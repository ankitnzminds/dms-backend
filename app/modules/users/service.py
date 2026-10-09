"""Members, invitations and role administration (organization scoped)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import MembershipStatus, OrgStatus, Role, UserStatus
from app.db.models import GroupMembership, Membership, Organization, User
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.schemas.admin import MemberOut, MembershipOut

_ROLE_RANK = {Role.AUDITOR.value: 0, Role.MEMBER.value: 0, Role.ADMIN.value: 1, Role.OWNER.value: 2}


def _normalize_email(email: str) -> str:
    email = email.strip().lower()
    if "@" not in email or len(email) > 320 or email.startswith("@") or email.endswith("@"):
        raise ValidationFailed("A valid email address is required.")
    return email


def require_admin(p: Principal) -> None:
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required.")


def assert_can_manage(p: Principal, membership: Membership) -> None:
    """An administrator may only manage members at or below their own rank."""
    if _ROLE_RANK[membership.role] > _ROLE_RANK[p.role] or (
        membership.role == Role.OWNER.value and p.role != Role.OWNER.value
    ):
        raise ForbiddenError("You cannot modify a member with a higher role.")


def list_members(
    db: Session,
    p: Principal,
    *,
    q: str | None,
    status: str | None,
    role: str | None,
    limit: int,
    offset: int,
) -> tuple[list[MemberOut], int]:
    require_admin(p)
    stmt = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == p.organization_id)
    )
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(User.email).like(like),
                func.lower(func.coalesce(User.display_name, "")).like(like),
            )
        )
    if status:
        stmt = stmt.where(Membership.status == status)
    if role:
        stmt = stmt.where(Membership.role == role)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(stmt.order_by(User.email).limit(limit).offset(offset)).all()
    gm = db.execute(
        select(GroupMembership.user_id, GroupMembership.group_id).where(
            GroupMembership.organization_id == p.organization_id,
            GroupMembership.user_id.in_([u.id for _, u in rows] or [uuid.UUID(int=0)]),
        )
    ).all()
    groups: dict[uuid.UUID, list[uuid.UUID]] = {}
    for uid, gid in gm:
        groups.setdefault(uid, []).append(gid)
    return (
        [
            MemberOut(
                user_id=u.id,
                email=u.email,
                display_name=u.display_name,
                role=m.role,  # type: ignore[arg-type]
                membership_status=m.status,  # type: ignore[arg-type]
                user_status=u.status,  # type: ignore[arg-type]
                last_login_at=u.last_login_at,
                group_ids=groups.get(u.id, []),
            )
            for m, u in rows
        ],
        int(total),
    )


def _member_out(user: User, membership: Membership) -> MemberOut:
    return MemberOut(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=membership.role,  # type: ignore[arg-type]
        membership_status=membership.status,  # type: ignore[arg-type]
        user_status=user.status,  # type: ignore[arg-type]
        last_login_at=user.last_login_at,
    )


def add_invited_member(
    db: Session,
    p: Principal,
    *,
    email: str,
    display_name: str | None,
    role: str,
    source: str = "invitation",
    profile: dict[str, object] | None = None,
) -> tuple[User, Membership]:
    """Create (or re-invite) a member inside the caller's transaction; the caller commits."""
    require_admin(p)
    if role == Role.OWNER.value and p.role != Role.OWNER.value:
        raise ForbiddenError("Only an owner can invite another owner.")
    email = _normalize_email(email)
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        user = User(
            id=uuid.uuid4(), email=email, display_name=display_name, status=UserStatus.INVITED.value
        )
        db.add(user)
        db.flush()
    elif user.status == UserStatus.DISABLED.value:
        raise ConflictError(
            "This account is disabled and cannot be invited.", code="account_disabled"
        )
    membership = db.scalar(
        select(Membership).where(
            Membership.organization_id == p.organization_id, Membership.user_id == user.id
        )
    )
    if membership is not None and membership.status in (
        MembershipStatus.ACTIVE.value,
        MembershipStatus.INVITED.value,
        MembershipStatus.SUSPENDED.value,
    ):
        raise ConflictError(
            "This user is already a member or has a pending invitation.", code="already_member"
        )
    if membership is None:
        membership = Membership(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            user_id=user.id,
            invited_by=p.user_id,
        )
        db.add(membership)
    membership.role = role
    membership.status = MembershipStatus.INVITED.value
    membership.invited_by = p.user_id
    membership.creation_source = source
    for key, value in (profile or {}).items():
        setattr(membership, key, value)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="member.invited",
        resource_type="user",
        resource_id=user.id,
        metadata={"role": role, "source": source},
    )
    return user, membership


def invite(
    db: Session, p: Principal, *, email: str, display_name: str | None, role: str
) -> MemberOut:
    user, membership = add_invited_member(db, p, email=email, display_name=display_name, role=role)
    db.commit()
    return _member_out(user, membership)


def update_member(
    db: Session,
    p: Principal,
    user_id: uuid.UUID,
    *,
    role: str | None,
    status: str | None,
    display_name: str | None,
) -> MemberOut:
    require_admin(p)
    row = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == p.organization_id, Membership.user_id == user_id)
        .with_for_update(of=Membership)
        .execution_options(populate_existing=True)
    ).first()
    if row is None:
        raise NotFoundError("Member not found.")
    membership, user = row
    if user_id == p.user_id and (role is not None or status is not None):
        raise ForbiddenError("You cannot change your own role or status.")
    target_rank, my_rank = _ROLE_RANK[membership.role], _ROLE_RANK[p.role]
    if target_rank > my_rank or (
        membership.role == Role.OWNER.value and p.role != Role.OWNER.value
    ):
        raise ForbiddenError("You cannot modify a member with a higher role.")
    if role is not None and role == Role.OWNER.value and p.role != Role.OWNER.value:
        raise ForbiddenError("Only an owner can grant the owner role.")

    changes: dict[str, str] = {}
    if role is not None and role != membership.role:
        changes["role"] = f"{membership.role}->{role}"
        membership.role = role
    if status is not None and status != membership.status:
        changes["status"] = f"{membership.status}->{status}"
        membership.status = status
    if display_name is not None:
        user.display_name = display_name.strip() or None
        changes["display_name"] = "updated"

    # An organization must always keep at least one active owner.
    db.flush()
    owners = db.scalar(
        select(func.count()).where(
            Membership.organization_id == p.organization_id,
            Membership.role == Role.OWNER.value,
            Membership.status == MembershipStatus.ACTIVE.value,
        )
    )
    if not owners:
        db.rollback()
        raise ConflictError(
            "The organization must keep at least one active owner.", code="last_owner"
        )

    if changes:
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="member.updated",
            resource_type="user",
            resource_id=user.id,
            metadata=changes,
        )
    db.commit()
    return MemberOut(
        user_id=user.id,
        email=user.email,
        display_name=user.display_name,
        role=membership.role,  # type: ignore[arg-type]
        membership_status=membership.status,  # type: ignore[arg-type]
        user_status=user.status,  # type: ignore[arg-type]
        last_login_at=user.last_login_at,
    )


def revoke_sessions(db: Session, p: Principal, user_id: uuid.UUID) -> None:
    """Invalidate every token issued so far for a member (e.g. suspected compromise)."""
    require_admin(p)
    member = db.scalar(
        select(Membership).where(
            Membership.organization_id == p.organization_id, Membership.user_id == user_id
        )
    )
    if member is None:
        raise NotFoundError("Member not found.")
    user = db.get(User, user_id)
    assert user is not None
    user.sessions_valid_after = datetime.now(UTC)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="member.sessions_revoked",
        resource_type="user",
        resource_id=user_id,
    )
    db.commit()


def membership_views(db: Session, user: User) -> tuple[list[MembershipOut], list[MembershipOut]]:
    rows = db.execute(
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(Membership.user_id == user.id, Organization.status == OrgStatus.ACTIVE.value)
    ).all()
    active, pending = [], []
    for m, o in rows:
        view = MembershipOut(
            organization_id=o.id,
            organization_name=o.name,
            role=m.role,
            status=m.status,  # type: ignore[arg-type]
        )
        if m.status == MembershipStatus.ACTIVE.value:
            active.append(view)
        elif m.status == MembershipStatus.INVITED.value:
            pending.append(view)
    return active, pending


def accept_invitation(db: Session, user: User, organization_id: uuid.UUID) -> None:
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user.id,
            Membership.organization_id == organization_id,
            Membership.status == MembershipStatus.INVITED.value,
        )
    )
    if membership is None:
        raise NotFoundError("Invitation not found.")
    membership.status = MembershipStatus.ACTIVE.value
    audit.record(
        db,
        organization_id=organization_id,
        actor_user_id=user.id,
        action="member.invitation_accepted",
        resource_type="user",
        resource_id=user.id,
    )
    db.commit()
