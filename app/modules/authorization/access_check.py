"""Administrator "Check Access" and ACL impact preview.

The effective actions are computed by the **same** ``AuthorizationService`` every API call uses,
run as the target user (rebuilt from current state, so a suspended or removed account has none).
The provenance list explains *why*, from the underlying grants, shares and ownership; it is
informational and cannot disagree with the enforcement result because it never decides anything.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, NotFoundError
from app.db.enums import Action, MembershipStatus, RecipientType, ResourceType, SubjectType
from app.db.models import (
    Document,
    Folder,
    Group,
    GroupMembership,
    Membership,
    PermissionGrant,
    ShareGrant,
    ShareRecipient,
    User,
)
from app.modules.audit import service as audit
from app.modules.authorization.actions import ALL_ACTIONS
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import subtree_folder_ids
from app.modules.identity.principal import Principal
from app.modules.identity.service import principal_for
from app.schemas.common import ApiModel


class AccessSource(ApiModel):
    kind: Literal["role", "owner", "direct", "group", "organization", "share"]
    via: str
    inherited_from: str | None = None
    actions: list[str]
    expires_at: datetime | None = None


class AccessCheckOut(ApiModel):
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    resource_name: str
    user_id: uuid.UUID
    user_email: str
    account_state: Literal["active", "inactive"]
    actions: list[str]
    not_held: list[str]
    sources: list[AccessSource]
    note: str | None = None


class ImpactOut(ApiModel):
    folders_affected: int
    documents_affected: int
    inherits: bool
    subject_label: str
    note: str


def _require_admin(p: Principal) -> None:
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required.")


def _chain(db: Session, org: uuid.UUID, folder_id: uuid.UUID) -> list[tuple[uuid.UUID, str, int]]:
    """Folder and ancestors: [(id, name, depth)], depth 0 = the folder itself."""
    out: list[tuple[uuid.UUID, str, int]] = []
    cur: uuid.UUID | None = folder_id
    depth = 0
    while cur is not None and depth < 100:
        f = db.scalar(select(Folder).where(Folder.id == cur, Folder.organization_id == org))
        if f is None:
            break
        out.append((f.id, f.name, depth))
        cur, depth = f.parent_folder_id, depth + 1
    return out


def check(
    db: Session, p: Principal, rtype: ResourceType, rid: uuid.UUID, user_id: uuid.UUID
) -> AccessCheckOut:
    _require_admin(p)
    org = p.organization_id
    doc: Document | None = None
    folder: Folder | None = None
    if rtype == ResourceType.DOCUMENT:
        doc = db.scalar(select(Document).where(Document.id == rid, Document.organization_id == org))
        if doc is None:
            raise NotFoundError("Resource not found.")
        name, start = doc.name, doc.folder_id
        extra_depth = 1
    else:
        folder = db.scalar(select(Folder).where(Folder.id == rid, Folder.organization_id == org))
        if folder is None:
            raise NotFoundError("Resource not found.")
        name, start = folder.name, folder.id
        extra_depth = 0
    member = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.organization_id == org, Membership.user_id == user_id)
    ).first()
    if member is None:
        raise NotFoundError("User not found.")
    membership, user = member

    base = {
        "resource_type": rtype.value,
        "resource_id": rid,
        "resource_name": name,
        "user_id": user.id,
        "user_email": user.email,
    }
    try:
        target = principal_for(db, user_id, org)
    except ForbiddenError:
        audit.record(
            db,
            organization_id=org,
            actor_user_id=p.user_id,
            action="access.checked",
            resource_type=rtype.value,
            resource_id=rid,
            metadata={"user_id": str(user_id), "state": "inactive"},
        )
        db.commit()
        return AccessCheckOut(
            **base,
            account_state="inactive",
            actions=[],
            not_held=sorted(ALL_ACTIONS),
            sources=[],
            note="The account is not active in this organization, so it holds no access (membership: "
            f"{membership.status}).",
        )

    authz = AuthorizationService(db, target)
    if doc is not None:
        held = authz.document_actions([doc])[doc.id]
    else:
        assert folder is not None
        held = authz.folder_actions([folder.id])[folder.id]

    sources: list[AccessSource] = []
    if target.is_admin:
        sources.append(
            AccessSource(
                kind="role", via=f"Organization {target.role}", actions=sorted(ALL_ACTIONS)
            )
        )
    now = datetime.now(UTC)
    chain = _chain(db, org, start)
    chain_ids = [c[0] for c in chain]
    names = {c[0]: c[1] for c in chain}
    depth = {c[0]: c[2] + extra_depth for c in chain}
    group_names = dict(
        db.execute(
            select(Group.id, Group.name).where(
                Group.id.in_(list(target.group_ids) or [uuid.UUID(int=0)])
            )
        ).all()
    )
    grants = db.scalars(
        select(PermissionGrant).where(
            PermissionGrant.organization_id == org,
            PermissionGrant.revoked_at.is_(None),
            or_(PermissionGrant.expires_at.is_(None), PermissionGrant.expires_at > now),
            or_(
                and_(
                    PermissionGrant.subject_type == SubjectType.USER.value,
                    PermissionGrant.subject_id == user_id,
                ),
                and_(
                    PermissionGrant.subject_type == SubjectType.GROUP.value,
                    PermissionGrant.subject_id.in_(list(target.group_ids) or [uuid.UUID(int=0)]),
                ),
                PermissionGrant.subject_type == SubjectType.ORGANIZATION.value,
            ),
            or_(
                and_(
                    PermissionGrant.resource_type == ResourceType.FOLDER.value,
                    PermissionGrant.resource_id.in_(chain_ids),
                ),
                and_(
                    PermissionGrant.resource_type == ResourceType.DOCUMENT.value,
                    PermissionGrant.resource_id == (doc.id if doc else uuid.UUID(int=0)),
                ),
            ),
        )
    ).all()
    for g in grants:
        on_doc = g.resource_type == ResourceType.DOCUMENT.value
        d = 0 if on_doc else depth.get(g.resource_id, 99)
        if not on_doc and d != 0 and not g.inherit:
            continue  # a non-inheriting grant on an ancestor does not reach this resource
        kind: Any = (
            "direct"
            if g.subject_type == SubjectType.USER.value
            else ("group" if g.subject_type == SubjectType.GROUP.value else "organization")
        )
        via = (
            user.email
            if kind == "direct"
            else f"Group “{group_names.get(g.subject_id or uuid.UUID(int=0), '?')}”"
            if kind == "group"
            else "Everyone in the organization"
        )
        sources.append(
            AccessSource(
                kind=kind,
                via=via,
                actions=sorted(g.actions),
                expires_at=g.expires_at,
                inherited_from=None if (on_doc or d == extra_depth) else names.get(g.resource_id),
            )
        )
    share_rows = db.execute(
        select(
            ShareGrant.actions,
            ShareGrant.resource_type,
            ShareGrant.resource_id,
            ShareGrant.expires_at,
        )
        .join(
            ShareRecipient,
            and_(
                ShareRecipient.share_grant_id == ShareGrant.id,
                ShareRecipient.organization_id == ShareGrant.organization_id,
            ),
        )
        .where(
            ShareGrant.organization_id == org,
            ShareGrant.revoked_at.is_(None),
            or_(ShareGrant.expires_at.is_(None), ShareGrant.expires_at > now),
            or_(
                and_(
                    ShareRecipient.recipient_type == RecipientType.USER.value,
                    ShareRecipient.recipient_id == user_id,
                ),
                and_(
                    ShareRecipient.recipient_type == RecipientType.GROUP.value,
                    ShareRecipient.recipient_id.in_(list(target.group_ids) or [uuid.UUID(int=0)]),
                ),
            ),
            or_(
                and_(
                    ShareGrant.resource_type == ResourceType.FOLDER.value,
                    ShareGrant.resource_id.in_(chain_ids),
                ),
                and_(
                    ShareGrant.resource_type == ResourceType.DOCUMENT.value,
                    ShareGrant.resource_id == (doc.id if doc else uuid.UUID(int=0)),
                ),
            ),
        )
    ).all()
    for actions, r_type, r_id, exp in share_rows:
        sources.append(
            AccessSource(
                kind="share",
                via="Shared with them",
                actions=sorted(actions),
                expires_at=exp,
                inherited_from=names.get(r_id)
                if r_type == ResourceType.FOLDER.value and depth.get(r_id, 0) != extra_depth
                else None,
            )
        )
    if doc is not None and doc.owner_id == user_id:
        sources.append(
            AccessSource(kind="owner", via="Owner of this file", actions=[Action.VIEW.value])
        )
    created = db.scalars(
        select(Folder.id).where(Folder.id.in_(chain_ids), Folder.created_by == user_id)
    ).all()
    for fid in created:
        sources.append(
            AccessSource(
                kind="owner",
                via="Created this folder",
                actions=[],
                inherited_from=names.get(fid) if depth.get(fid, 0) != extra_depth else None,
            )
        )

    note = None
    if doc is not None and not held and doc.status != "available":
        note = "The file is not available yet (still processing or quarantined); only its owner can reach it."
    audit.record(
        db,
        organization_id=org,
        actor_user_id=p.user_id,
        action="access.checked",
        resource_type=rtype.value,
        resource_id=rid,
        metadata={"user_id": str(user_id), "actions": len(held)},
    )
    db.commit()
    return AccessCheckOut(
        **base,
        account_state="active",
        actions=sorted(held),
        not_held=sorted(ALL_ACTIONS - held),
        sources=sources,
        note=note,
    )


def impact(
    db: Session,
    p: Principal,
    rtype: ResourceType,
    rid: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID | None,
    inherit: bool,
) -> ImpactOut:
    """What a grant on this resource would reach, before it is made."""
    _require_admin(p)
    org = p.organization_id
    if rtype == ResourceType.DOCUMENT:
        if (
            db.scalar(
                select(Document.id).where(Document.id == rid, Document.organization_id == org)
            )
            is None
        ):
            raise NotFoundError("Resource not found.")
        folders, docs = 0, 1
    else:
        if (
            db.scalar(select(Folder.id).where(Folder.id == rid, Folder.organization_id == org))
            is None
        ):
            raise NotFoundError("Resource not found.")
        ids = subtree_folder_ids(db, org, rid) if inherit else [rid]
        folders = len(ids)
        docs = int(
            db.scalar(
                select(func.count()).where(
                    Document.organization_id == org,
                    Document.deleted_at.is_(None),
                    Document.folder_id.in_(ids),
                )
            )
            or 0
        )
    label = "Everyone in the organization"
    if subject_type == "user" and subject_id:
        u = db.get(User, subject_id)
        label = u.email if u else "Unknown user"
    elif subject_type == "group" and subject_id:
        g = db.get(Group, subject_id)
        members = int(
            db.scalar(
                select(func.count()).where(
                    GroupMembership.group_id == subject_id, GroupMembership.organization_id == org
                )
            )
            or 0
        )
        label = f"Group “{g.name}” ({members} members)" if g else "Unknown group"
    elif subject_type == "organization":
        members = int(
            db.scalar(
                select(func.count()).where(
                    Membership.organization_id == org,
                    Membership.status == MembershipStatus.ACTIVE.value,
                )
            )
            or 0
        )
        label = f"Everyone in the organization ({members} people)"
    return ImpactOut(
        folders_affected=folders,
        documents_affected=docs,
        inherits=inherit,
        subject_label=label,
        note=(
            f"The grant would reach {folders} folder(s) and {docs} file(s) now, plus anything added later."
            if inherit and rtype == ResourceType.FOLDER
            else "The grant applies to this item only."
        ),
    )
