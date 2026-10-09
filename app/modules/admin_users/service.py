"""Users as an administrator sees them: profile, access level, lifecycle and usage.

Everything is scoped to ``p.organization_id`` in the query itself; ids from the client are never
trusted as tenant authority. Accounts are never hard-deleted: removal is a soft state that keeps
files, history and audit intact (see ``delete_user``).
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import MembershipStatus, Role, UserStatus
from app.db.models import (
    Document,
    DocumentVersion,
    Group,
    GroupMembership,
    Membership,
    Organization,
    ShareGrant,
    User,
)
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.policies import service as policies
from app.modules.users import service as members
from app.schemas.admin_users import (
    AdminOut,
    AdminUserCreate,
    AdminUserOut,
    AdminUserUpdate,
    DeleteImpact,
    QuotaOut,
)

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,99}$")
_PHONE = re.compile(r"^\+[1-9][0-9]{6,14}$")
_SORTS = {
    "email": User.email,
    "display_name": func.lower(func.coalesce(User.display_name, "")),
    "last_login_at": User.last_login_at,
    "created_at": Membership.created_at,
    "username": func.lower(func.coalesce(Membership.username, "")),
}


# ---- validation helpers (shared with CSV import)
def clean_email(value: str | None, field: str = "Email") -> str | None:
    if value is None or not value.strip():
        return None
    email = value.strip().lower()
    if len(email) > 320 or not _EMAIL.match(email):
        raise ValidationFailed(f"{field} is not a valid email address.", code="invalid_email")
    return email


def clean_username(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    name = value.strip()
    if not _USERNAME.match(name):
        raise ValidationFailed(
            "User name may use letters, digits and . _ @ - (2-100 characters).",
            code="invalid_username",
        )
    return name


def clean_phone(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    digits = re.sub(r"[\s().-]", "", value.strip())
    if not _PHONE.match(digits):
        raise ValidationFailed(
            "Phone must be in international format, e.g. +14155550123.", code="invalid_phone"
        )
    return digits


def _aware(value: datetime | None, field: str) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        raise ValidationFailed(f"{field} must include a timezone (UTC is stored).")
    return value.astimezone(UTC)


# ---- views
def state_of(m: Membership, u: User, now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    if m.status in (MembershipStatus.SUSPENDED.value, MembershipStatus.REMOVED.value) or (
        u.status == UserStatus.DISABLED.value
    ):
        return "disabled"
    if m.account_locked:
        return "locked"
    if m.account_expires_at is not None and m.account_expires_at <= now:
        return "expired"
    return "invited" if m.status == MembershipStatus.INVITED.value else "active"


def groups_for(
    db: Session, org_id: uuid.UUID, user_ids: list[uuid.UUID]
) -> dict[uuid.UUID, list[uuid.UUID]]:
    out: dict[uuid.UUID, list[uuid.UUID]] = {}
    if not user_ids:
        return out
    for uid, gid in db.execute(
        select(GroupMembership.user_id, GroupMembership.group_id).where(
            GroupMembership.organization_id == org_id, GroupMembership.user_id.in_(user_ids)
        )
    ):
        out.setdefault(uid, []).append(gid)
    return out


def to_out(m: Membership, u: User, groups: dict[uuid.UUID, list[uuid.UUID]]) -> AdminUserOut:
    return AdminUserOut(
        user_id=u.id,
        username=m.username,
        email=u.email,
        display_name=u.display_name,
        secondary_email=m.secondary_email,
        phone=m.phone,
        notes=m.notes,
        role=m.role,  # type: ignore[arg-type]
        access_level=m.access_level,  # type: ignore[arg-type]
        membership_status=m.status,  # type: ignore[arg-type]
        state=state_of(m, u),  # type: ignore[arg-type]
        account_locked=m.account_locked,
        account_expires_at=m.account_expires_at,
        email_verified=u.email_verified,
        last_login_at=u.last_login_at,
        created_at=m.created_at,
        creation_source=m.creation_source,  # type: ignore[arg-type]
        authentication=u.identity_provider or "default",
        group_ids=groups.get(u.id, []),
    )


def _row(
    db: Session, p: Principal, user_id: uuid.UUID, *, lock: bool = False
) -> tuple[Membership, User]:
    members.require_admin(p)
    stmt = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.organization_id == p.organization_id,
            Membership.user_id == user_id,
            Membership.status != MembershipStatus.REMOVED.value,
        )
    )
    if lock:
        stmt = stmt.with_for_update(of=Membership).execution_options(populate_existing=True)
    row = db.execute(stmt).first()
    if row is None:
        raise NotFoundError("User not found.")
    return row[0], row[1]


def filtered(p: Principal, q: str | None, status: str, source: str | None) -> Any:
    stmt = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.organization_id == p.organization_id,
            Membership.status != MembershipStatus.REMOVED.value,
        )
    )
    if q and q.strip():
        like = "%" + re.sub(r"[%_\\]", "", q.strip().lower()) + "%"
        stmt = stmt.where(
            or_(
                func.lower(User.email).like(like),
                func.lower(func.coalesce(User.display_name, "")).like(like),
                func.lower(func.coalesce(Membership.username, "")).like(like),
                func.lower(func.coalesce(Membership.secondary_email, "")).like(like),
                func.lower(func.coalesce(Membership.notes, "")).like(like),
            )
        )
    if status == "disabled":
        stmt = stmt.where(Membership.status == MembershipStatus.SUSPENDED.value)
    elif status in {"full", "guest", "external"}:
        stmt = stmt.where(Membership.access_level == status)
    if source:
        stmt = stmt.where(Membership.creation_source == source)
    return stmt


def list_users(
    db: Session,
    p: Principal,
    *,
    q: str | None,
    status: str,
    source: str | None,
    sort: str,
    descending: bool,
    limit: int,
    offset: int,
) -> tuple[list[AdminUserOut], int]:
    members.require_admin(p)
    if sort not in _SORTS:
        raise ValidationFailed(f"Sort must be one of: {', '.join(sorted(_SORTS))}.")
    stmt = filtered(p, q, status, source)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    column = _SORTS[sort]
    order = column.desc().nullslast() if descending else column.asc().nullsfirst()
    rows = db.execute(stmt.order_by(order, User.id).limit(limit).offset(offset)).all()
    groups = groups_for(db, p.organization_id, [u.id for _, u in rows])
    return [to_out(m, u, groups) for m, u in rows], int(total)


def get_user(db: Session, p: Principal, user_id: uuid.UUID) -> AdminUserOut:
    m, u = _row(db, p, user_id)
    return to_out(m, u, groups_for(db, p.organization_id, [u.id]))


# ---- create / update
def username_taken(
    db: Session, org_id: uuid.UUID, username: str, except_user: uuid.UUID | None
) -> bool:
    stmt = select(Membership.user_id).where(
        Membership.organization_id == org_id, func.lower(Membership.username) == username.lower()
    )
    if except_user:
        stmt = stmt.where(Membership.user_id != except_user)
    return db.scalar(stmt) is not None


def local_groups(db: Session, p: Principal, ids: list[uuid.UUID]) -> list[Group]:
    if not ids:
        return []
    found = list(
        db.scalars(
            select(Group).where(Group.organization_id == p.organization_id, Group.id.in_(ids))
        )
    )
    if len(found) != len(set(ids)):
        raise ValidationFailed("One or more groups do not exist.", code="unknown_group")
    if any(g.external_id for g in found):
        raise ConflictError(
            "Directory-synchronized groups are managed by the directory.", code="group_synced"
        )
    return found


def create_user(db: Session, p: Principal, body: AdminUserCreate) -> AdminUserOut:
    members.require_admin(p)
    email = clean_email(body.email)
    assert email is not None
    username = clean_username(body.username)
    if username and username_taken(db, p.organization_id, username, None):
        raise ConflictError("That user name is already in use.", code="username_taken")
    profile: dict[str, Any] = {
        "username": username,
        "access_level": body.access_level,
        "secondary_email": clean_email(body.secondary_email, "Secondary email"),
        "phone": clean_phone(body.phone),
        "notes": (body.notes or "").strip() or None,
        "account_expires_at": _aware(body.account_expires_at, "Account expiry"),
    }
    groups = local_groups(db, p, body.group_ids)
    user, membership = members.add_invited_member(
        db,
        p,
        email=email,
        display_name=(body.display_name or "").strip() or None,
        role=body.role,
        source="default",
        profile=profile,
    )
    for g in groups:
        db.add(GroupMembership(group_id=g.id, user_id=user.id, organization_id=p.organization_id))
    db.commit()
    return to_out(membership, user, groups_for(db, p.organization_id, [user.id]))


def update_user(
    db: Session, p: Principal, user_id: uuid.UUID, body: AdminUserUpdate
) -> AdminUserOut:
    m, u = _row(db, p, user_id, lock=True)
    members.assert_can_manage(p, m)
    sent = body.model_fields_set
    changed: list[str] = []

    def set_if(name: str, value: Any, target: Any, attr: str) -> None:
        if getattr(target, attr) != value:
            setattr(target, attr, value)
            changed.append(name)

    if "display_name" in sent:
        set_if("display_name", (body.display_name or "").strip() or None, u, "display_name")
    if "username" in sent:
        username = clean_username(body.username)
        if username and username_taken(db, p.organization_id, username, u.id):
            raise ConflictError("That user name is already in use.", code="username_taken")
        set_if("username", username, m, "username")
    if "secondary_email" in sent:
        set_if(
            "secondary_email",
            clean_email(body.secondary_email, "Secondary email"),
            m,
            "secondary_email",
        )
    if "phone" in sent:
        set_if("phone", clean_phone(body.phone), m, "phone")
    if "notes" in sent:
        set_if("notes", (body.notes or "").strip() or None, m, "notes")
    if body.clear_account_expiry:
        set_if("account_expires_at", None, m, "account_expires_at")
    elif body.account_expires_at is not None:
        set_if(
            "account_expires_at",
            _aware(body.account_expires_at, "Account expiry"),
            m,
            "account_expires_at",
        )
    if body.access_level is not None:
        set_if("access_level", body.access_level, m, "access_level")
    if body.account_locked is not None and body.account_locked != m.account_locked:
        if u.id == p.user_id:
            raise ForbiddenError("You cannot lock your own account.")
        m.account_locked = body.account_locked
        changed.append("account_locked")
        if body.account_locked:
            u.sessions_valid_after = datetime.now(UTC)
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="member.locked" if body.account_locked else "member.unlocked",
            resource_type="user",
            resource_id=u.id,
        )
    if changed:
        # field NAMES only: notes/phone values are personal data and stay out of the audit trail
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="member.profile_updated",
            resource_type="user",
            resource_id=u.id,
            metadata={"fields": sorted(changed)},
        )
    db.commit()
    return to_out(m, u, groups_for(db, p.organization_id, [u.id]))


def set_enabled(db: Session, p: Principal, user_id: uuid.UUID, enabled: bool) -> AdminUserOut:
    """Deactivate (suspend + end sessions) or reactivate. Reuses the member rules (last owner, rank)."""
    _row(db, p, user_id)
    members.update_member(
        db,
        p,
        user_id,
        role=None,
        status=MembershipStatus.ACTIVE.value if enabled else MembershipStatus.SUSPENDED.value,
        display_name=None,
    )
    if not enabled:
        members.revoke_sessions(db, p, user_id)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="member.reactivated" if enabled else "member.deactivated",
        resource_type="user",
        resource_id=user_id,
    )
    db.commit()
    return get_user(db, p, user_id)


# ---- deletion (soft, retention-first)
def delete_impact(db: Session, p: Principal, user_id: uuid.UUID) -> DeleteImpact:
    _row(db, p, user_id)
    docs = db.scalar(
        select(func.count()).where(
            Document.organization_id == p.organization_id, Document.owner_id == user_id
        )
    )
    size = db.scalar(
        select(func.coalesce(func.sum(DocumentVersion.size_bytes), 0))
        .join(Document, Document.id == DocumentVersion.document_id)
        .where(Document.organization_id == p.organization_id, Document.owner_id == user_id)
    )
    shares = db.scalar(
        select(func.count()).where(
            ShareGrant.organization_id == p.organization_id,
            ShareGrant.created_by == user_id,
            ShareGrant.revoked_at.is_(None),
        )
    )
    group_count = db.scalar(
        select(func.count()).where(
            GroupMembership.organization_id == p.organization_id, GroupMembership.user_id == user_id
        )
    )
    return DeleteImpact(
        owned_documents=int(docs or 0),
        owned_bytes=int(size or 0),
        active_shares_created=int(shares or 0),
        group_memberships=int(group_count or 0),
        summary=(
            "The account is removed from this organization, signed out everywhere and taken out of "
            "its groups. Files and folders are NOT deleted: they stay in the organization with their "
            "history, under its retention rules, and administrators can reassign them."
        ),
    )


def delete_user(
    db: Session, p: Principal, user_id: uuid.UUID, *, confirm: bool, confirm_email: str
) -> None:
    m, u = _row(db, p, user_id, lock=True)
    members.assert_can_manage(p, m)
    if u.id == p.user_id:
        raise ForbiddenError("You cannot delete your own account.")
    if not confirm or confirm_email.strip().lower() != u.email:
        raise ValidationFailed(
            "Confirm the deletion and type the account email.", code="confirmation_required"
        )
    if m.role == Role.OWNER.value:
        other_owners = db.scalar(
            select(func.count()).where(
                Membership.organization_id == p.organization_id,
                Membership.role == Role.OWNER.value,
                Membership.status == MembershipStatus.ACTIVE.value,
                Membership.user_id != u.id,
            )
        )
        if not other_owners:
            raise ConflictError(
                "The organization must keep at least one active owner.", code="last_owner"
            )
    impact = delete_impact(db, p, user_id)
    m.status = MembershipStatus.REMOVED.value
    u.sessions_valid_after = datetime.now(UTC)
    db.execute(
        delete(GroupMembership).where(
            GroupMembership.organization_id == p.organization_id, GroupMembership.user_id == u.id
        )
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="member.deleted",
        resource_type="user",
        resource_id=u.id,
        metadata={
            "owned_documents": impact.owned_documents,
            "owned_bytes": impact.owned_bytes,
            "files_deleted": False,
        },
    )
    db.commit()


# ---- usage
def used_bytes_by(db: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> int:
    """Bytes of every stored version this user uploaded (trash counts until purged: ADR-0007)."""
    return int(
        db.scalar(
            select(func.coalesce(func.sum(DocumentVersion.size_bytes), 0)).where(
                DocumentVersion.organization_id == org_id, DocumentVersion.created_by == user_id
            )
        )
        or 0
    )


def quota(db: Session, p: Principal, user_id: uuid.UUID) -> QuotaOut:
    _row(db, p, user_id)
    org = db.get(Organization, p.organization_id)
    assert org is not None
    eff = policies.effective(db, p.organization_id, user_id)
    limit = int(eff.values["general"]["user_storage_quota_bytes"]) or None
    used = used_bytes_by(db, p.organization_id, user_id)
    return QuotaOut(
        quota_bytes=limit,
        used_bytes=used,
        available_bytes=None if limit is None else max(0, limit - used),
        organization_quota_bytes=org.quota_bytes,
        organization_used_bytes=org.quota_used_bytes,
        quota_source=eff.provenance["general.user_storage_quota_bytes"],
        calculated_at=datetime.now(UTC),
    )


# ---- group membership of one user
def replace_groups(
    db: Session, p: Principal, user_id: uuid.UUID, group_ids: list[uuid.UUID]
) -> AdminUserOut:
    m, u = _row(db, p, user_id)
    members.assert_can_manage(p, m)
    wanted = {g.id for g in local_groups(db, p, group_ids)}
    current = set(
        db.scalars(
            select(GroupMembership.group_id)
            .join(Group, Group.id == GroupMembership.group_id)
            .where(
                GroupMembership.organization_id == p.organization_id,
                GroupMembership.user_id == user_id,
                Group.external_id.is_(None),  # synced memberships are not editable here
            )
        )
    )
    added, removed = wanted - current, current - wanted
    for gid in added:
        db.add(GroupMembership(group_id=gid, user_id=user_id, organization_id=p.organization_id))
    if removed:
        db.execute(
            delete(GroupMembership).where(
                GroupMembership.organization_id == p.organization_id,
                GroupMembership.user_id == user_id,
                GroupMembership.group_id.in_(removed),
            )
        )
    if added or removed:
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="member.groups_replaced",
            resource_type="user",
            resource_id=user_id,
            metadata={"added": sorted(map(str, added)), "removed": sorted(map(str, removed))},
        )
    db.commit()
    return to_out(m, u, groups_for(db, p.organization_id, [user_id]))


# ---- administrators
def list_admins(db: Session, p: Principal) -> list[AdminOut]:
    members.require_admin(p)
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(
            Membership.organization_id == p.organization_id,
            Membership.role.in_([Role.OWNER.value, Role.ADMIN.value, Role.AUDITOR.value]),
            Membership.status != MembershipStatus.REMOVED.value,
        )
        .order_by(Membership.role, User.email)
    ).all()
    return [
        AdminOut(
            user_id=u.id,
            email=u.email,
            display_name=u.display_name,
            role=m.role,  # type: ignore[arg-type]
            membership_status=m.status,  # type: ignore[arg-type]
            authentication=u.identity_provider or "default",
            last_login_at=u.last_login_at,
        )
        for m, u in rows
    ]
