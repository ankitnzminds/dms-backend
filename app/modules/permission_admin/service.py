"""Read models behind the Admin and User permission dashboards.

Nothing here decides access: it only *lists* grants and shares that the single AuthorizationService
already enforces, scoped to the caller's organization. Administrators see the whole organization; an
ordinary user only ever sees entries that are addressed to them or that sit on resources they may
manage (never confidential access information about resources they cannot inspect).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from sqlalchemy import and_, false, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, NotFoundError
from app.db.enums import ResourceType
from app.db.models import (
    AuditEvent,
    Document,
    Folder,
    Group,
    PermissionGrant,
    ShareGrant,
    ShareRecipient,
    User,
)
from app.modules.authorization import access_check
from app.modules.authorization.matrix import ACL_LABELS, to_labels
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.schemas.admin import AuditEventOut
from app.schemas.common import ApiModel

PERMISSION_EVENT_PREFIXES = ("permission.", "share.", "access_request.", "access.")


class AccessEntry(ApiModel):
    id: uuid.UUID
    source: Literal["grant", "share"]
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    resource_name: str
    subject_type: Literal["user", "group", "organization", "link"]
    subject_id: uuid.UUID | None = None
    subject_label: str
    actions: list[str]
    permissions: list[str]
    inherited: bool = False
    expires_at: datetime | None = None
    expiring_soon: bool = False
    granted_by_id: uuid.UUID | None = None
    granted_by: str | None = None
    created_at: datetime


def _now() -> datetime:
    return datetime.now(UTC)


def _names(db: Session, org: uuid.UUID, rows: list[tuple[str, uuid.UUID]]) -> dict[uuid.UUID, str]:
    out: dict[uuid.UUID, str] = {}
    fids = {i for t, i in rows if t == ResourceType.FOLDER.value}
    dids = {i for t, i in rows if t == ResourceType.DOCUMENT.value}
    if fids:
        out.update(
            db.execute(
                select(Folder.id, Folder.name).where(
                    Folder.organization_id == org, Folder.id.in_(fids)
                )
            ).all()
        )
    if dids:
        out.update(
            db.execute(
                select(Document.id, Document.name).where(
                    Document.organization_id == org, Document.id.in_(dids)
                )
            ).all()
        )
    return out


def _people(db: Session, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, str]:
    real = {i for i in ids if i}
    if not real:
        return {}
    return {
        u.id: (u.display_name or u.email) for u in db.scalars(select(User).where(User.id.in_(real)))
    }


def _groups(db: Session, org: uuid.UUID, ids: set[uuid.UUID]) -> dict[uuid.UUID, str]:
    if not ids:
        return {}
    return dict(
        db.execute(
            select(Group.id, Group.name).where(Group.organization_id == org, Group.id.in_(ids))
        ).all()
    )


def _live(model: type[PermissionGrant] | type[ShareGrant]):  # type: ignore[no-untyped-def]
    return and_(
        model.revoked_at.is_(None),
        or_(model.expires_at.is_(None), model.expires_at > _now()),
    )


def _build(
    db: Session,
    org: uuid.UUID,
    grants: list[PermissionGrant],
    shares: list[tuple[ShareGrant, ShareRecipient | None]],
    soon: datetime,
) -> list[AccessEntry]:
    res = [(g.resource_type, g.resource_id) for g in grants] + [
        (s.resource_type, s.resource_id) for s, _ in shares
    ]
    names = _names(db, org, res)
    people = _people(
        db,
        {g.created_by for g in grants}
        | {s.created_by for s, _ in shares}
        | {g.subject_id for g in grants if g.subject_type == "user"}
        | {r.recipient_id for _, r in shares if r is not None and r.recipient_type == "user"},
    )
    gids = {g.subject_id for g in grants if g.subject_type == "group" and g.subject_id} | {
        r.recipient_id for _, r in shares if r is not None and r.recipient_type == "group"
    }
    groups = _groups(db, org, gids)  # type: ignore[arg-type]
    out: list[AccessEntry] = []
    for g in grants:
        label = (
            people.get(g.subject_id, "Unknown user")
            if g.subject_type == "user" and g.subject_id
            else groups.get(g.subject_id, "Unknown group")
            if g.subject_type == "group" and g.subject_id
            else "Everyone in the organization"
        )
        out.append(
            AccessEntry(
                id=g.id,
                source="grant",
                resource_type=g.resource_type,  # type: ignore[arg-type]
                resource_id=g.resource_id,
                resource_name=names.get(g.resource_id, "(unavailable)"),
                subject_type=g.subject_type,  # type: ignore[arg-type]
                subject_id=g.subject_id,
                subject_label=label,
                actions=list(g.actions),
                permissions=to_labels(g.actions, ACL_LABELS),
                inherited=bool(g.inherit and g.resource_type == "folder"),
                expires_at=g.expires_at,
                expiring_soon=bool(g.expires_at and g.expires_at <= soon),
                granted_by_id=g.created_by,
                granted_by=people.get(g.created_by) if g.created_by else None,
                created_at=g.created_at,
            )
        )
    for s, r in shares:
        actions = list(r.actions) if r is not None and r.actions else list(s.actions)
        if r is None:
            stype, sid, label = "link", None, s.name or "Share link"
        elif r.recipient_type == "user":
            stype, sid, label = "user", r.recipient_id, people.get(r.recipient_id, "Unknown user")
        elif r.recipient_type == "group":
            stype, sid, label = "group", r.recipient_id, groups.get(r.recipient_id, "Unknown group")
        else:
            stype, sid, label = "organization", None, "Everyone in the organization"
        out.append(
            AccessEntry(
                id=s.id,
                source="share",
                resource_type=s.resource_type,  # type: ignore[arg-type]
                resource_id=s.resource_id,
                resource_name=names.get(s.resource_id, "(unavailable)"),
                subject_type=stype,  # type: ignore[arg-type]
                subject_id=sid,
                subject_label=label,
                actions=actions,
                permissions=to_labels(actions, ACL_LABELS),
                expires_at=s.expires_at,
                expiring_soon=bool(s.expires_at and s.expires_at <= soon),
                granted_by_id=s.created_by,
                granted_by=people.get(s.created_by),
                created_at=s.created_at,
            )
        )
    out.sort(key=lambda e: e.created_at, reverse=True)
    return out


def _fetch(
    db: Session,
    org: uuid.UUID,
    *,
    source: str,
    expiring_within_days: int | None,
    subject_user: uuid.UUID | None = None,
    subject_groups: frozenset[uuid.UUID] | None = None,
    include_org: bool = False,
    group_id: uuid.UUID | None = None,
    resource_id: uuid.UUID | None = None,
) -> list[AccessEntry]:
    soon = _now() + timedelta(days=expiring_within_days or 7)
    grants: list[PermissionGrant] = []
    shares: list[tuple[ShareGrant, ShareRecipient | None]] = []
    if source in ("all", "grant"):
        gs = select(PermissionGrant).where(
            PermissionGrant.organization_id == org, _live(PermissionGrant)
        )
        subj = []
        if subject_user:
            subj.append(
                and_(
                    PermissionGrant.subject_type == "user",
                    PermissionGrant.subject_id == subject_user,
                )
            )
        gids = set(subject_groups or ())
        if group_id:
            gids.add(group_id)
        if gids:
            subj.append(
                and_(PermissionGrant.subject_type == "group", PermissionGrant.subject_id.in_(gids))
            )
        if include_org:
            subj.append(PermissionGrant.subject_type == "organization")
        if subj:
            gs = gs.where(or_(*subj))
        elif subject_user or group_id:
            gs = gs.where(false())
        if resource_id:
            gs = gs.where(PermissionGrant.resource_id == resource_id)
        if expiring_within_days:
            gs = gs.where(
                PermissionGrant.expires_at.is_not(None), PermissionGrant.expires_at <= soon
            )
        grants = list(db.scalars(gs.limit(1000)))
    if source in ("all", "share"):
        q = (
            select(ShareGrant, ShareRecipient)
            .outerjoin(ShareRecipient, ShareRecipient.share_grant_id == ShareGrant.id)
            .where(ShareGrant.organization_id == org, _live(ShareGrant))
        )
        subj = []
        if subject_user:
            subj.append(
                and_(
                    ShareRecipient.recipient_type == "user",
                    ShareRecipient.recipient_id == subject_user,
                )
            )
        gids = set(subject_groups or ())
        if group_id:
            gids.add(group_id)
        if gids:
            subj.append(
                and_(
                    ShareRecipient.recipient_type == "group", ShareRecipient.recipient_id.in_(gids)
                )
            )
        if include_org:
            subj.append(ShareRecipient.recipient_type == "organization")
        if subj:
            q = q.where(or_(*subj))
        elif subject_user or group_id:
            q = q.where(false())
        if resource_id:
            q = q.where(ShareGrant.resource_id == resource_id)
        if expiring_within_days:
            q = q.where(ShareGrant.expires_at.is_not(None), ShareGrant.expires_at <= soon)
        shares = [(s, r) for s, r in db.execute(q.limit(1000)).all()]
    return _build(db, org, grants, shares, soon)


def _page(items: list[AccessEntry], limit: int, offset: int) -> tuple[list[AccessEntry], int]:
    return items[offset : offset + limit], len(items)


def _require_admin(p: Principal) -> None:
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required.")


def org_access(
    db: Session,
    p: Principal,
    *,
    source: str,
    expiring_within_days: int | None,
    user_id: uuid.UUID | None,
    group_id: uuid.UUID | None,
    q: str | None,
    limit: int,
    offset: int,
) -> tuple[list[AccessEntry], int]:
    """Admin: every live grant/share in the organization, optionally for one user or group."""
    _require_admin(p)
    groups_of_user: frozenset[uuid.UUID] | None = None
    if user_id:
        from app.db.models import GroupMembership

        groups_of_user = frozenset(
            db.scalars(
                select(GroupMembership.group_id).where(
                    GroupMembership.organization_id == p.organization_id,
                    GroupMembership.user_id == user_id,
                )
            )
        )
    items = _fetch(
        db,
        p.organization_id,
        source=source,
        expiring_within_days=expiring_within_days,
        subject_user=user_id,
        subject_groups=groups_of_user,
        include_org=bool(user_id),
        group_id=group_id,
    )
    if q:
        needle = q.strip().lower()
        items = [
            e
            for e in items
            if needle in e.resource_name.lower() or needle in e.subject_label.lower()
        ]
    return _page(items, limit, offset)


def my_access(
    db: Session, p: Principal, *, expiring_within_days: int | None, limit: int, offset: int
) -> tuple[list[AccessEntry], int]:
    """What has been granted to the caller (directly, via their groups, or to the whole org)."""
    items = _fetch(
        db,
        p.organization_id,
        source="all",
        expiring_within_days=expiring_within_days,
        subject_user=p.user_id,
        subject_groups=p.group_ids,
        include_org=True,
    )
    return _page(items, limit, offset)


def resource_history(
    db: Session,
    p: Principal,
    rtype: ResourceType,
    rid: uuid.UUID,
    *,
    limit: int,
    offset: int,
) -> tuple[list[AuditEventOut], int]:
    """Permission/share/request events for ONE resource; managers of that resource and admins only."""
    model = Document if rtype == ResourceType.DOCUMENT else Folder
    if (
        db.scalar(
            select(model.id).where(model.id == rid, model.organization_id == p.organization_id)
        )
        is None
    ):
        raise NotFoundError("Resource not found.")
    access_check._require_manager(db, p, rtype, rid)  # noqa: SLF001
    cond = or_(*[AuditEvent.action.like(pre + "%") for pre in PERMISSION_EVENT_PREFIXES])
    stmt = select(AuditEvent).where(
        AuditEvent.organization_id == p.organization_id,
        AuditEvent.resource_id == rid,
        cond,
    )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    events = list(
        db.scalars(
            stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id).limit(limit).offset(offset)
        )
    )
    emails = _people(db, {e.actor_user_id for e in events})
    return (
        [
            AuditEventOut(
                id=e.id,
                created_at=e.created_at,
                actor_user_id=e.actor_user_id,
                actor_email=emails.get(e.actor_user_id) if e.actor_user_id else None,
                action=e.action,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                outcome=e.outcome,  # type: ignore[arg-type]
                request_id=e.request_id,
                metadata=e.event_metadata or {},
            )
            for e in events
        ],
        int(total),
    )


def effective_for_me(
    db: Session, p: Principal, rtype: ResourceType, rid: uuid.UUID
) -> dict[str, object]:
    """The caller's own effective actions on a resource (same engine as enforcement).

    A resource the caller cannot even discover answers 404, exactly like every other endpoint.
    """
    authz = AuthorizationService(db, p)
    org = p.organization_id
    if rtype == ResourceType.DOCUMENT:
        doc = db.scalar(select(Document).where(Document.id == rid, Document.organization_id == org))
        held = authz.document_actions([doc]).get(rid, frozenset()) if doc else frozenset()
    else:
        found = db.scalar(select(Folder.id).where(Folder.id == rid, Folder.organization_id == org))
        held = authz.folder_actions([rid]).get(rid, frozenset()) if found else frozenset()
    if not held:
        raise NotFoundError("Resource not found.")
    return {"resource_type": rtype.value, "resource_id": rid, "actions": sorted(held)}
