"""Groups / departments / teams and their memberships (organization scoped)."""

from __future__ import annotations

import uuid

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import MembershipStatus
from app.db.models import Group, GroupMembership, Membership, User
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.users.service import require_admin
from app.schemas.admin import GroupOut, MemberOut


def _group_or_404(db: Session, p: Principal, group_id: uuid.UUID) -> Group:
    group = db.scalar(
        select(Group).where(Group.id == group_id, Group.organization_id == p.organization_id)
    )
    if group is None:
        raise NotFoundError("Group not found.")
    return group


def _to_out(group: Group, count: int) -> GroupOut:
    return GroupOut(
        id=group.id,
        name=group.name,
        kind=group.kind,  # type: ignore[arg-type]
        description=group.description,
        member_count=count,
        created_at=group.created_at,
    )


def list_groups(
    db: Session, p: Principal, *, q: str | None, limit: int, offset: int
) -> tuple[list[GroupOut], int]:
    # Any member may list groups (needed to pick share recipients); only names/counts are exposed.
    stmt = select(Group).where(Group.organization_id == p.organization_id)
    if q:
        stmt = stmt.where(func.lower(Group.name).like(f"%{q.strip().lower()}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    groups = list(db.scalars(stmt.order_by(Group.name).limit(limit).offset(offset)))
    counts = dict(
        db.execute(
            select(GroupMembership.group_id, func.count())
            .where(GroupMembership.group_id.in_([g.id for g in groups] or [uuid.UUID(int=0)]))
            .group_by(GroupMembership.group_id)
        ).all()
    )
    return [_to_out(g, counts.get(g.id, 0)) for g in groups], int(total)


def create_group(
    db: Session, p: Principal, *, name: str, kind: str, description: str | None
) -> GroupOut:
    require_admin(p)
    name = name.strip()
    if not name:
        raise ValidationFailed("Group name is required.")
    group = Group(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=name,
        kind=kind,
        description=description,
    )
    db.add(group)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("A group with this name already exists.", code="name_conflict") from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="group.created",
        resource_type="group",
        resource_id=group.id,
        metadata={"name": name},
    )
    db.commit()
    return _to_out(group, 0)


def update_group(
    db: Session, p: Principal, group_id: uuid.UUID, *, name: str | None, description: str | None
) -> GroupOut:
    require_admin(p)
    group = _group_or_404(db, p, group_id)
    if name is not None:
        group.name = name.strip()
    if description is not None:
        group.description = description
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("A group with this name already exists.", code="name_conflict") from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="group.updated",
        resource_type="group",
        resource_id=group.id,
    )
    db.commit()
    count = db.scalar(select(func.count()).where(GroupMembership.group_id == group.id)) or 0
    return _to_out(group, count)


def delete_group(db: Session, p: Principal, group_id: uuid.UUID) -> None:
    require_admin(p)
    group = _group_or_404(db, p, group_id)
    db.execute(delete(GroupMembership).where(GroupMembership.group_id == group.id))
    # Grants/shares addressed to the group stop working because the group no longer resolves.
    from app.db.models import PermissionGrant, ShareRecipient  # local import to avoid cycles

    db.execute(
        update(PermissionGrant)
        .where(
            PermissionGrant.subject_type == "group",
            PermissionGrant.subject_id == group.id,
            PermissionGrant.revoked_at.is_(None),
        )
        .values(revoked_at=func.now(), revoked_by=p.user_id)
    )
    db.execute(
        delete(ShareRecipient).where(
            ShareRecipient.recipient_type == "group", ShareRecipient.recipient_id == group.id
        )
    )
    db.delete(group)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="group.deleted",
        resource_type="group",
        resource_id=group_id,
        metadata={"name": group.name},
    )
    db.commit()


def list_group_members(db: Session, p: Principal, group_id: uuid.UUID) -> list[MemberOut]:
    require_admin(p)
    _group_or_404(db, p, group_id)
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .join(
            GroupMembership,
            (GroupMembership.user_id == User.id)
            & (GroupMembership.organization_id == Membership.organization_id),
        )
        .where(
            GroupMembership.group_id == group_id, Membership.organization_id == p.organization_id
        )
        .order_by(User.email)
    ).all()
    return [
        MemberOut(
            user_id=u.id,
            email=u.email,
            display_name=u.display_name,
            role=m.role,  # type: ignore[arg-type]
            membership_status=m.status,
            user_status=u.status,
            last_login_at=u.last_login_at,  # type: ignore[arg-type]
        )
        for m, u in rows
    ]


def add_member(db: Session, p: Principal, group_id: uuid.UUID, user_id: uuid.UUID) -> None:
    require_admin(p)
    group = _group_or_404(db, p, group_id)
    member = db.scalar(
        select(Membership.id).where(
            Membership.organization_id == p.organization_id,
            Membership.user_id == user_id,
            Membership.status.in_([MembershipStatus.ACTIVE.value, MembershipStatus.INVITED.value]),
        )
    )
    if member is None:
        raise ValidationFailed("User is not a member of this organization.", code="unknown_subject")
    exists = db.scalar(
        select(GroupMembership.user_id).where(
            GroupMembership.group_id == group.id, GroupMembership.user_id == user_id
        )
    )
    if exists is None:
        db.add(
            GroupMembership(group_id=group.id, user_id=user_id, organization_id=p.organization_id)
        )
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="group.member_added",
            resource_type="group",
            resource_id=group.id,
            metadata={"user_id": str(user_id)},
        )
        db.commit()


def remove_member(db: Session, p: Principal, group_id: uuid.UUID, user_id: uuid.UUID) -> None:
    require_admin(p)
    group = _group_or_404(db, p, group_id)
    result = db.execute(
        delete(GroupMembership).where(
            GroupMembership.group_id == group.id,
            GroupMembership.user_id == user_id,
            GroupMembership.organization_id == p.organization_id,
        )
    )
    if getattr(result, "rowcount", 0):
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="group.member_removed",
            resource_type="group",
            resource_id=group.id,
            metadata={"user_id": str(user_id)},
        )
    db.commit()
