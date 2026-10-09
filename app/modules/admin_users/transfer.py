"""CSV import (dry-run preview, then commit) and CSV export of users.

Security stance: passwords are never imported (sign-in belongs to the identity provider; a
``Password`` column is ignored and reported once, never stored or echoed), exports contain no
secrets/phone/notes, and every cell is neutralized against spreadsheet formula injection.
Imports are bounded (rows and bytes) and run inside the request; larger loads belong to a job
queue and are listed as deferred in the feature matrix.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.db.enums import AccessLevel, CreationSource, MembershipStatus
from app.db.models import Group, GroupMembership, Membership, User
from app.modules.admin_users import service as svc
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.reports.service import _safe_cell
from app.modules.users import service as members
from app.schemas.admin_users import ImportPreviewOut, ImportResultOut, ImportRowOut

MAX_ROWS = 1000
MAX_BYTES = 1_000_000
TEMPLATE_HEADER = ["UserName", "EmailID", "DisplayName", "Status", "ExpirationDate", "Groups"]
TEMPLATE_EXAMPLE = [
    "jdoe",
    "jdoe@example.com",
    "Jane Doe",
    "Full",
    "2027-12-31",
    "Finance;Legal",
]
_ALIASES = {
    "username": "username",
    "emailid": "email",
    "email": "email",
    "displayname": "display_name",
    "status": "access_level",
    "accesslevel": "access_level",
    "expirationdate": "expires",
    "accountexpireson": "expires",
    "groups": "groups",
    "password": "password",
    "emailverified": "email_verified",
}
_LEVELS = {"full": "full", "fullaccess": "full", "guest": "guest", "external": "external"}


def template_csv() -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(TEMPLATE_HEADER)
    w.writerow(TEMPLATE_EXAMPLE)
    return buf.getvalue()


class _Parsed:
    def __init__(self, line: int) -> None:
        self.line = line
        self.email: str | None = None
        self.username: str | None = None
        self.display_name: str | None = None
        self.access_level = AccessLevel.FULL.value
        self.expires: datetime | None = None
        self.groups: list[Group] = []
        self.problems: list[str] = []
        self.exists = False


def _read(text: str) -> tuple[list[str], list[dict[str, str]]]:
    if len(text.encode("utf-8", errors="ignore")) > MAX_BYTES:
        raise ValidationFailed("The CSV is larger than 1 MB.", code="csv_too_large")
    text = text.lstrip("﻿")
    reader = csv.reader(io.StringIO(text))
    try:
        header = next(reader)
    except StopIteration:
        raise ValidationFailed("The CSV is empty.", code="csv_empty") from None
    keys = [_ALIASES.get(re.sub(r"[^a-z]", "", h.lower()), "") for h in header]
    if "email" not in keys:
        raise ValidationFailed("The CSV needs an EmailID column.", code="csv_missing_email")
    rows: list[dict[str, str]] = []
    for raw in reader:
        if not any(c.strip() for c in raw):
            continue
        if len(rows) >= MAX_ROWS:
            raise ValidationFailed(f"At most {MAX_ROWS} rows per import.", code="csv_too_many_rows")
        rows.append({k: v for k, v in zip(keys, raw, strict=False) if k})
    return [h.strip() for h in header if h.strip()], rows


def _validate(db: Session, p: Principal, rows: list[dict[str, str]]) -> tuple[list[_Parsed], bool]:
    groups_by_name = {
        g.name.lower(): g
        for g in db.scalars(select(Group).where(Group.organization_id == p.organization_id))
    }
    existing_emails = {
        email
        for (email,) in db.execute(
            select(User.email)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == p.organization_id,
                Membership.status != MembershipStatus.REMOVED.value,
            )
        )
    }
    taken_usernames = {
        n.lower()
        for n in db.scalars(
            select(Membership.username).where(
                Membership.organization_id == p.organization_id, Membership.username.is_not(None)
            )
        )
        if n
    }
    seen_emails: set[str] = set()
    seen_usernames: set[str] = set()
    out: list[_Parsed] = []
    saw_password = any("password" in r for r in rows)
    for i, row in enumerate(rows, start=2):  # line 1 is the header
        r = _Parsed(i)
        out.append(r)
        try:
            r.email = svc.clean_email(row.get("email"))
            if r.email is None:
                r.problems.append("EmailID is required.")
        except ValidationFailed as e:
            r.problems.append(e.message)
        if r.email:
            if r.email in seen_emails:
                r.problems.append("Duplicate email in this file.")
            seen_emails.add(r.email)
            r.exists = r.email in existing_emails
        try:
            r.username = svc.clean_username(row.get("username"))
        except ValidationFailed as e:
            r.problems.append(e.message)
        if r.username:
            low = r.username.lower()
            if low in seen_usernames or (low in taken_usernames and not r.exists):
                r.problems.append("User name is already in use.")
            seen_usernames.add(low)
        r.display_name = (row.get("display_name") or "").strip()[:200] or None
        level = _LEVELS.get(re.sub(r"[^a-z]", "", (row.get("access_level") or "full").lower()))
        if level is None:
            r.problems.append("Status must be Full, Guest or External.")
        else:
            r.access_level = level
        raw_date = (row.get("expires") or "").strip()
        if raw_date:
            try:
                r.expires = datetime.fromisoformat(raw_date).replace(tzinfo=UTC)
            except ValueError:
                r.problems.append("ExpirationDate must be YYYY-MM-DD.")
        for name in [g.strip() for g in re.split(r"[;|]", row.get("groups") or "") if g.strip()]:
            g = groups_by_name.get(name.lower())
            if g is None:
                r.problems.append(f"Group '{name}' does not exist.")
            elif g.external_id:
                r.problems.append(f"Group '{name}' is managed by the directory.")
            else:
                r.groups.append(g)
    return out, saw_password


def _row_out(r: _Parsed) -> ImportRowOut:
    outcome = "invalid" if r.problems else ("skip_existing" if r.exists else "create")
    return ImportRowOut(
        line=r.line,
        email=r.email,
        outcome=outcome,
        problems=r.problems,  # type: ignore[arg-type]
    )


def preview(db: Session, p: Principal, csv_text: str) -> ImportPreviewOut:
    members.require_admin(p)
    header, rows = _read(csv_text)
    parsed, saw_password = _validate(db, p, rows)
    outs = [_row_out(r) for r in parsed]
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="member.import_previewed",
        resource_type="user",
        metadata={"rows": len(outs)},
    )
    db.commit()
    columns = header + (
        ["(Password is ignored: sign-in is handled by the identity provider)"]
        if saw_password
        else []
    )
    return ImportPreviewOut(
        total=len(outs),
        creates=sum(o.outcome == "create" for o in outs),
        existing=sum(o.outcome == "skip_existing" for o in outs),
        invalid=sum(o.outcome == "invalid" for o in outs),
        rows=outs[:200],
        columns_seen=columns,
    )


def commit(db: Session, p: Principal, csv_text: str) -> ImportResultOut:
    """Re-validates from scratch (never trusts a previous preview), then creates valid rows.

    Existing accounts are skipped, never overwritten; invalid rows are reported and do not block
    valid ones."""
    members.require_admin(p)
    _, rows = _read(csv_text)
    parsed, _ = _validate(db, p, rows)
    created = 0
    for r in parsed:
        if r.problems or r.exists or r.email is None:
            continue
        user, _m = members.add_invited_member(
            db,
            p,
            email=r.email,
            display_name=r.display_name,
            role="member",
            source=CreationSource.CSV_IMPORT.value,
            profile={
                "username": r.username,
                "access_level": r.access_level,
                "account_expires_at": r.expires,
            },
        )
        for g in r.groups:
            db.add(
                GroupMembership(group_id=g.id, user_id=user.id, organization_id=p.organization_id)
            )
        created += 1
    outs = [_row_out(r) for r in parsed]
    result = ImportResultOut(
        created=created,
        skipped_existing=sum(o.outcome == "skip_existing" for o in outs),
        invalid=sum(o.outcome == "invalid" for o in outs),
        errors=[o for o in outs if o.outcome == "invalid"][:200],
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="member.imported",
        resource_type="user",
        metadata={
            "created": created,
            "skipped_existing": result.skipped_existing,
            "invalid": result.invalid,
        },
    )
    db.commit()
    return result


def export_csv(
    db: Session, p: Principal, *, q: str | None, status: str, source: str | None
) -> bytes:
    members.require_admin(p)
    stmt = svc.filtered(p, q, status, source).order_by(User.email).limit(20_001)
    rows = db.execute(stmt).all()
    truncated = len(rows) > 20_000
    rows = rows[:20_000]
    group_names = dict(
        db.execute(
            select(Group.id, Group.name).where(Group.organization_id == p.organization_id)
        ).all()
    )
    groups = svc.groups_for(db, p.organization_id, [u.id for _, u in rows])
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "UserName",
            "EmailID",
            "DisplayName",
            "SecondaryEmail",
            "AccessLevel",
            "State",
            "Role",
            "Authentication",
            "CreationSource",
            "LastLoginUtc",
            "AccountExpiresUtc",
            "Groups",
        ]
    )
    for m, u in rows:
        w.writerow(
            [
                _safe_cell(v)
                for v in (
                    m.username,
                    u.email,
                    u.display_name,
                    m.secondary_email,
                    m.access_level,
                    svc.state_of(m, u),
                    m.role,
                    u.identity_provider or "default",
                    m.creation_source,
                    u.last_login_at.isoformat() if u.last_login_at else "",
                    m.account_expires_at.isoformat() if m.account_expires_at else "",
                    ";".join(sorted(group_names.get(g, "") for g in groups.get(u.id, []))),
                )
            ]
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="member.exported",
        resource_type="user",
        metadata={"rows": len(rows), "truncated": truncated, "status": status, "q_used": bool(q)},
    )
    db.commit()
    return buf.getvalue().encode("utf-8-sig")
