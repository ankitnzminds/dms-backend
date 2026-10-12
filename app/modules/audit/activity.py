"""Administrator activity monitoring on top of the append-only audit log.

Reads only. Tenant scope is part of every query (``organization_id = principal.organization_id``);
no client-supplied organization id exists. Paging is keyset-based (stable while new events arrive).
Network details (IP, user agent) are personal data and are shown only to the owner and auditors.
Viewing and exporting activity is itself audited.
"""

from __future__ import annotations

import base64
import csv
import io
import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import AuditOutcome, Role
from app.db.models import AuditEvent, Document, Folder, User
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.reports.service import _safe_cell
from app.schemas.admin_users import ActivityEventOut, ActivityPage, AuditPolicyOut

# category -> action prefixes (before the first dot)
CATEGORIES: dict[str, tuple[str, ...]] = {
    "authentication": ("auth",),
    "users": ("member",),
    "files": ("document", "folder", "upload", "comment"),
    "sharing": ("share", "access_request"),
    "permissions": ("permission", "authz"),
    "groups": ("group",),
    "policies": ("policy", "retention_policy", "metadata_definition"),
    "admin": ("org", "audit"),
    "workflow": ("workflow", "automation", "integrity"),
    "signatures": ("signature",),
    "integrations": ("directory", "directory_source"),
    "retention": ("legal_hold",),
    "assistant": ("chat", "ai"),
}
_PREFIX_TO_CATEGORY = {prefix: cat for cat, prefixes in CATEGORIES.items() for prefix in prefixes}
MAX_EXPORT_ROWS = 50_000
NEVER_RECORDED = [
    "passwords, tokens, cookies, MFA codes or keys",
    "document contents or chat message bodies",
    "search query text",
]


def category_of(action: str) -> str:
    return _PREFIX_TO_CATEGORY.get(action.split(".", 1)[0], "other")


def require_reader(p: Principal) -> None:
    if not p.can_read_audit:
        raise ForbiddenError("Activity access is restricted to administrators and auditors.")


def _may_see_network(p: Principal) -> bool:
    return p.role in (Role.OWNER.value, Role.AUDITOR.value)


def _encode(created_at: datetime, event_id: uuid.UUID) -> str:
    raw = f"{created_at.astimezone(UTC).isoformat()}|{event_id}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def _decode(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, ident = raw.split("|", 1)
        return datetime.fromisoformat(ts), uuid.UUID(ident)
    except (ValueError, UnicodeDecodeError):
        raise ValidationFailed("Invalid cursor.", code="invalid_cursor") from None


def _query(
    p: Principal,
    *,
    user_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    category: str | None,
    action: str | None,
    outcome: str | None,
    resource_type: str | None,
    resource_id: uuid.UUID | None,
    since: datetime | None,
    until: datetime | None,
):  # type: ignore[no-untyped-def]
    stmt = select(AuditEvent).where(AuditEvent.organization_id == p.organization_id)
    if user_id:  # everything the user did, plus what was done to the account
        stmt = stmt.where(
            or_(
                AuditEvent.actor_user_id == user_id,
                and_(AuditEvent.resource_type == "user", AuditEvent.resource_id == user_id),
            )
        )
    if actor_user_id:
        stmt = stmt.where(AuditEvent.actor_user_id == actor_user_id)
    if category:
        prefixes = CATEGORIES.get(category)
        if prefixes is None:
            raise ValidationFailed(f"Unknown category '{category}'.", code="unknown_category")
        stmt = stmt.where(or_(*[AuditEvent.action.like(f"{pre}.%") for pre in prefixes]))
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if since:
        stmt = stmt.where(AuditEvent.created_at >= since)
    if until:
        stmt = stmt.where(AuditEvent.created_at <= until)
    return stmt


def _present(db: Session, p: Principal, events: list[AuditEvent]) -> list[ActivityEventOut]:
    ids = {e.actor_user_id for e in events if e.actor_user_id} | {
        e.resource_id for e in events if e.resource_type == "user" and e.resource_id
    }
    emails = (
        dict(db.execute(select(User.id, User.email).where(User.id.in_(ids))).all()) if ids else {}
    )
    # Current names of the documents / folders the events are about (administrators and auditors see
    # the whole organization's activity, so naming the items adds nothing they could not already open).
    doc_ids = {e.resource_id for e in events if e.resource_type == "document" and e.resource_id}
    folder_ids = {e.resource_id for e in events if e.resource_type == "folder" and e.resource_id}
    item_names: dict[uuid.UUID, str] = {}
    if doc_ids:
        item_names.update(
            dict(
                db.execute(
                    select(Document.id, Document.name).where(
                        Document.organization_id == p.organization_id, Document.id.in_(doc_ids)
                    )
                ).all()
            )
        )
    if folder_ids:
        item_names.update(
            dict(
                db.execute(
                    select(Folder.id, Folder.name).where(
                        Folder.organization_id == p.organization_id, Folder.id.in_(folder_ids)
                    )
                ).all()
            )
        )
    network = _may_see_network(p)
    return [
        ActivityEventOut(
            id=e.id,
            occurred_at=e.created_at,
            category=category_of(e.action),
            action=e.action,
            outcome=e.outcome,  # type: ignore[arg-type]
            actor_user_id=e.actor_user_id,
            actor_email=emails.get(e.actor_user_id) if e.actor_user_id else None,
            target_type=e.resource_type,
            target_id=e.resource_id,
            target_label=emails.get(e.resource_id)
            if e.resource_type == "user" and e.resource_id
            else item_names.get(e.resource_id)
            if e.resource_id
            else None,
            request_id=e.request_id,
            ip_address=e.ip_address if network else None,
            user_agent=e.user_agent if network else None,
            metadata=e.event_metadata or {},
        )
        for e in events
    ]


def search(
    db: Session,
    p: Principal,
    *,
    user_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    category: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> ActivityPage:
    require_reader(p)
    stmt = _query(
        p,
        user_id=user_id,
        actor_user_id=actor_user_id,
        category=category,
        action=action,
        outcome=outcome,
        resource_type=resource_type,
        resource_id=resource_id,
        since=since,
        until=until,
    )
    if cursor:
        ts, ident = _decode(cursor)
        stmt = stmt.where(
            or_(
                AuditEvent.created_at < ts,
                and_(AuditEvent.created_at == ts, AuditEvent.id < ident),
            )
        )
    rows = list(
        db.scalars(
            stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit + 1)
        )
    )
    more = len(rows) > limit
    rows = rows[:limit]
    if cursor is None:  # opening a view is audited once; paging through it is not
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="audit.viewed",
            resource_type="user" if user_id else "audit",
            resource_id=user_id,
            metadata={
                "category": category,
                "action": action,
                "outcome": outcome,
                "scope": "user" if user_id else "organization",
            },
        )
        db.commit()
    return ActivityPage(
        items=_present(db, p, rows),
        next_cursor=_encode(rows[-1].created_at, rows[-1].id) if more and rows else None,
    )


def get_event(db: Session, p: Principal, event_id: uuid.UUID) -> ActivityEventOut:
    require_reader(p)
    event = db.scalar(
        select(AuditEvent).where(
            AuditEvent.id == event_id, AuditEvent.organization_id == p.organization_id
        )
    )
    if event is None:
        raise NotFoundError("Event not found.")
    return _present(db, p, [event])[0]


def export_csv(
    db: Session,
    p: Principal,
    *,
    user_id: uuid.UUID | None,
    category: str | None,
    action: str | None,
    outcome: str | None,
    since: datetime | None,
    until: datetime | None,
) -> bytes:
    require_reader(p)
    stmt = _query(
        p,
        user_id=user_id,
        actor_user_id=None,
        category=category,
        action=action,
        outcome=outcome,
        resource_type=None,
        resource_id=None,
        since=since,
        until=until,
    )
    events = list(
        db.scalars(
            stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(
                MAX_EXPORT_ROWS + 1
            )
        )
    )
    truncated = len(events) > MAX_EXPORT_ROWS
    out = _present(db, p, events[:MAX_EXPORT_ROWS])
    network = _may_see_network(p)
    buf = io.StringIO()
    w = csv.writer(buf)
    header = [
        "time_utc",
        "category",
        "action",
        "outcome",
        "actor_email",
        "target_type",
        "target",
        "request_id",
    ]
    w.writerow(header + (["ip_address"] if network else []) + ["metadata"])
    for e in out:
        row = [
            e.occurred_at.astimezone(UTC).isoformat(),
            e.category,
            e.action,
            e.outcome,
            e.actor_email,
            e.target_type,
            e.target_label or (str(e.target_id) if e.target_id else ""),
            e.request_id,
        ]
        if network:
            row.append(e.ip_address)
        row.append(str(e.metadata))
        w.writerow([_safe_cell(c) for c in row])
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="audit.exported",
        resource_type="user" if user_id else "audit",
        resource_id=user_id,
        outcome=AuditOutcome.SUCCESS,
        metadata={"rows": len(out), "truncated": truncated, "category": category, "format": "csv"},
    )
    db.commit()
    return buf.getvalue().encode("utf-8-sig")


def audit_policy(p: Principal) -> AuditPolicyOut:
    require_reader(p)
    return AuditPolicyOut(
        append_only=True,
        retention_days=None,
        categories=sorted(CATEGORIES),
        never_recorded=NEVER_RECORDED,
        coverage_note=(
            "Events are written by the server when an action is performed or refused. Actions the "
            "application does not observe (for example sign-in at the identity provider, or file "
            "opens inside an external office server) are not in this log."
        ),
    )
