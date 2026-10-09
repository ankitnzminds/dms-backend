"""Manage Folder Permissions: direct vs inherited ACL, per-principal Read/Write/Share/Delete/Manage,
and the "Inherit Folder Level Security" switch with a preview.

Everything here reads and writes the same ``permission_grants`` the authorization service enforces.
Disabling inheritance never silently erases anyone's access: the caller sees a preview and either
converts the inherited grants into direct ones or explicitly confirms the loss.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import Action, ResourceType, SubjectType
from app.db.models import Document, Folder, Group, PermissionGrant, User
from app.modules.audit import service as audit
from app.modules.authorization import acl
from app.modules.authorization.actions import expand_actions
from app.modules.authorization.matrix import ACL_LABELS, to_actions, to_labels
from app.modules.authorization.service import AuthorizationService
from app.schemas.common import ApiModel
from app.schemas.sharing import PermissionGrantOut

A = Action


class InheritedGrant(ApiModel):
    grant_id: uuid.UUID
    source_folder_id: uuid.UUID
    source_folder_name: str
    subject_type: Literal["user", "group", "organization"]
    subject_id: uuid.UUID | None
    subject_name: str | None
    actions: list[str]
    permissions: list[str]
    expires_at: datetime | None


class AclOut(ApiModel):
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    resource_name: str
    path: str
    inherit_enabled: bool | None = None  # folders only
    direct: list[PermissionGrantOut]
    inherited: list[InheritedGrant]
    note: str | None = None


class InheritancePreview(ApiModel):
    inherit_now: bool
    inherit_after: bool
    affected: list[InheritedGrant]
    note: str


def _resource(
    db: Session, authz: AuthorizationService, rtype: ResourceType, rid: uuid.UUID
) -> tuple[str, uuid.UUID | None, Folder | None, Document | None]:
    acl._held(authz, rtype, rid)  # requires manage_access (admins pass)
    org = authz.principal.organization_id
    if rtype == ResourceType.DOCUMENT:
        d = db.scalar(select(Document).where(Document.id == rid, Document.organization_id == org))
        if d is None:
            raise NotFoundError("Resource not found.")
        return d.name, d.folder_id, None, d
    f = db.scalar(select(Folder).where(Folder.id == rid, Folder.organization_id == org))
    if f is None:
        raise NotFoundError("Resource not found.")
    return f.name, f.parent_folder_id, f, None


def _path(db: Session, org: uuid.UUID, folder_id: uuid.UUID | None, leaf: str | None) -> str:
    names: list[str] = []
    cur = folder_id
    for _ in range(100):
        if cur is None:
            break
        f = db.scalar(select(Folder).where(Folder.id == cur, Folder.organization_id == org))
        if f is None:
            break
        names.append(f.name)
        cur = f.parent_folder_id
    names.reverse()
    parts = names[1:]  # drop the root folder's own name
    if leaf:
        parts.append(leaf)
    return "/" + "/".join(parts)


def _subject_names(db: Session, grants: list[PermissionGrant]) -> dict[uuid.UUID, str]:
    out: dict[uuid.UUID, str] = {}
    uids = [
        g.subject_id for g in grants if g.subject_type == SubjectType.USER.value and g.subject_id
    ]
    gids = [
        g.subject_id for g in grants if g.subject_type == SubjectType.GROUP.value and g.subject_id
    ]
    if uids:
        for u in db.scalars(select(User).where(User.id.in_(uids))):
            out[u.id] = u.display_name or u.email
    if gids:
        for g in db.scalars(select(Group).where(Group.id.in_(gids))):
            out[g.id] = g.name
    return out


def _ancestor_grants(
    db: Session, org: uuid.UUID, start_folder_id: uuid.UUID | None, *, ignore_cut: bool = False
) -> list[InheritedGrant]:
    """Grants on ancestors that currently reach ``start_folder_id`` (or would, with ``ignore_cut``)."""
    now = datetime.now(UTC)
    chain: list[Folder] = []
    cur = start_folder_id
    for _ in range(100):
        if cur is None:
            break
        f = db.scalar(select(Folder).where(Folder.id == cur, Folder.organization_id == org))
        if f is None:
            break
        chain.append(f)
        cur = f.parent_folder_id
    # chain[0] is the nearest ancestor-or-self: grants must be inherit=True to reach below
    out: list[InheritedGrant] = []
    reach: list[Folder] = []
    for f in chain:
        reach.append(f)
        if not f.inherit_acl and not ignore_cut:
            break
    ids = [f.id for f in reach]
    if not ids:
        return out
    grants = list(
        db.scalars(
            select(PermissionGrant).where(
                PermissionGrant.organization_id == org,
                PermissionGrant.resource_type == ResourceType.FOLDER.value,
                PermissionGrant.resource_id.in_(ids),
                PermissionGrant.revoked_at.is_(None),
                PermissionGrant.inherit.is_(True),
            )
        )
    )
    names = _subject_names(db, grants)
    folder_names = {f.id: f.name for f in reach}
    for g in grants:
        if g.expires_at is not None and g.expires_at <= now:
            continue
        out.append(
            InheritedGrant(
                grant_id=g.id,
                source_folder_id=g.resource_id,
                source_folder_name=folder_names.get(g.resource_id, "?"),
                subject_type=g.subject_type,  # type: ignore[arg-type]
                subject_id=g.subject_id,
                subject_name=names.get(g.subject_id)
                if g.subject_id
                else "Everyone in the organization",
                actions=list(g.actions),
                permissions=to_labels(g.actions, ACL_LABELS),
                expires_at=g.expires_at,
            )
        )
    return out


def get_acl(
    db: Session, authz: AuthorizationService, rtype: ResourceType, rid: uuid.UUID
) -> AclOut:
    p = authz.principal
    name, parent_id, folder, doc = _resource(db, authz, rtype, rid)
    direct = acl.list_grants(db, authz, rtype, rid)
    for g in direct:
        g.permissions = to_labels(g.actions, ACL_LABELS)
    if folder is not None:
        # ancestors reach this folder through its PARENT chain, unless this folder cuts inheritance
        inherited = (
            [] if not folder.inherit_acl else _ancestor_grants(db, p.organization_id, parent_id)
        )
        path = _path(db, p.organization_id, parent_id, name)
        note = (
            None
            if folder.inherit_acl
            else "Inheritance is off: permissions set on parent folders do not apply here."
        )
    else:
        assert doc is not None
        inherited = _ancestor_grants(db, p.organization_id, doc.folder_id)
        path = _path(db, p.organization_id, doc.folder_id, name)
        note = None
    return AclOut(
        resource_type=rtype.value,  # type: ignore[arg-type]
        resource_id=rid,
        resource_name=name,
        path=path,
        inherit_enabled=folder.inherit_acl if folder is not None else None,
        direct=direct,
        inherited=inherited,
        note=note,
    )


def set_principal_permissions(
    db: Session,
    authz: AuthorizationService,
    rtype: ResourceType,
    rid: uuid.UUID,
    subject_type: str,
    subject_id: uuid.UUID | None,
    permissions: list[str],
    inherit: bool,
    expires_at: datetime | None,
) -> PermissionGrantOut:
    """Create or update the DIRECT grant of one person/group with Read/Write/Share/Delete/Manage."""
    p = authz.principal
    _resource(db, authz, rtype, rid)
    if not permissions:
        raise ValidationFailed(
            "Choose at least one permission, or remove the person.", code="empty_permissions"
        )
    try:
        actions = set(to_actions(permissions, ACL_LABELS))
    except ValueError as e:
        raise ValidationFailed(str(e)) from e
    expanded = set(expand_actions(actions) - {A.DISCOVER.value})
    existing = db.scalar(
        select(PermissionGrant).where(
            PermissionGrant.organization_id == p.organization_id,
            PermissionGrant.resource_type == rtype.value,
            PermissionGrant.resource_id == rid,
            PermissionGrant.subject_type == subject_type,
            PermissionGrant.subject_id == subject_id
            if subject_id
            else PermissionGrant.subject_id.is_(None),
            PermissionGrant.revoked_at.is_(None),
        )
    )
    from app.schemas.sharing import PermissionGrantIn

    if existing is None:
        return acl.add_grant(
            db,
            authz,
            rtype,
            rid,
            PermissionGrantIn(
                subject_type=subject_type,  # type: ignore[arg-type]
                subject_id=subject_id,
                actions=sorted(expanded),  # type: ignore[arg-type]
                inherit=inherit,
                expires_at=expires_at,
            ),
        )
    held = acl._held(authz, rtype, rid)
    if not expanded <= set(held):
        raise ForbiddenError("You cannot grant actions you do not hold.")
    if expires_at is not None and expires_at <= datetime.now(UTC):
        raise ValidationFailed("expires_at must be in the future.")
    before = to_labels(existing.actions, ACL_LABELS)
    existing.actions = sorted(expanded)
    if rtype == ResourceType.FOLDER:
        existing.inherit = inherit
    existing.expires_at = expires_at
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="permission.updated",
        resource_type=rtype.value,
        resource_id=rid,
        metadata={
            "grant_id": str(existing.id),
            "subject_type": subject_type,
            "subject_id": str(subject_id) if subject_id else None,
            "from": before,
            "to": [x for x in ACL_LABELS if x in permissions],
            "inherit": existing.inherit,
        },
    )
    db.commit()
    out = acl._out(db, [existing])[0]
    out.permissions = to_labels(out.actions, ACL_LABELS)
    return out


def preview_inheritance(
    db: Session, authz: AuthorizationService, folder_id: uuid.UUID, inherit: bool
) -> InheritancePreview:
    p = authz.principal
    _, parent_id, folder, _ = _resource(db, authz, ResourceType.FOLDER, folder_id)
    assert folder is not None
    affected = _ancestor_grants(db, p.organization_id, parent_id, ignore_cut=True)
    if inherit == folder.inherit_acl:
        note = "No change."
    elif inherit:
        note = (
            f"Turning inheritance on adds {len(affected)} permission entr{'y' if len(affected) == 1 else 'ies'} from parent folders. "
            "Nothing that is set directly on this folder is removed."
        )
    else:
        note = (
            f"Turning inheritance off stops {len(affected)} permission entr{'y' if len(affected) == 1 else 'ies'} from parent folders "
            "from applying here. Choose to copy them as direct permissions first, or confirm the loss of access."
        )
    return InheritancePreview(
        inherit_now=folder.inherit_acl, inherit_after=inherit, affected=affected, note=note
    )


def set_inheritance(
    db: Session,
    authz: AuthorizationService,
    folder_id: uuid.UUID,
    inherit: bool,
    *,
    convert_inherited: bool,
    confirm: bool,
) -> AclOut:
    p = authz.principal
    _, parent_id, folder, _ = _resource(db, authz, ResourceType.FOLDER, folder_id)
    assert folder is not None
    if folder.parent_folder_id is None:
        raise ConflictError("The root folder has nothing to inherit from.", code="root_folder")
    if inherit != folder.inherit_acl:
        affected = _ancestor_grants(db, p.organization_id, parent_id, ignore_cut=True)
        if not inherit:
            if affected and not (convert_inherited or confirm):
                raise ValidationFailed(
                    "Turning inheritance off removes access that comes from parent folders. "
                    "Copy it as direct permissions, or confirm.",
                    code="inheritance_confirmation",
                    details={"affected": [a.model_dump(mode="json") for a in affected]},
                )
            if convert_inherited:
                held = acl._held(authz, ResourceType.FOLDER, folder_id)
                for a in affected:
                    if not set(a.actions) <= set(held):
                        raise ForbiddenError("You cannot copy permissions you do not hold.")
                have = {
                    (g.subject_type, g.subject_id)
                    for g in db.scalars(
                        select(PermissionGrant).where(
                            PermissionGrant.organization_id == p.organization_id,
                            PermissionGrant.resource_type == ResourceType.FOLDER.value,
                            PermissionGrant.resource_id == folder_id,
                            PermissionGrant.revoked_at.is_(None),
                        )
                    )
                }
                for a in affected:
                    if (a.subject_type, a.subject_id) in have:
                        continue
                    db.add(
                        PermissionGrant(
                            id=uuid.uuid4(),
                            organization_id=p.organization_id,
                            resource_type=ResourceType.FOLDER.value,
                            resource_id=folder_id,
                            subject_type=a.subject_type,
                            subject_id=a.subject_id,
                            actions=a.actions,
                            inherit=True,
                            expires_at=a.expires_at,
                            created_by=p.user_id,
                        )
                    )
                    have.add((a.subject_type, a.subject_id))
        folder.inherit_acl = inherit
        folder.row_version += 1
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="permission.inheritance_changed",
            resource_type="folder",
            resource_id=folder_id,
            metadata={
                "inherit": inherit,
                "converted": bool(convert_inherited and not inherit),
                "affected": 0
                if inherit
                else len(_ancestor_grants(db, p.organization_id, parent_id, ignore_cut=True)),
            },
        )
        db.commit()
    return get_acl(db, authz, ResourceType.FOLDER, folder_id)


def labels_of(actions: list[str]) -> list[str]:
    return to_labels(actions, ACL_LABELS)


__all__ = ["AclOut", "InheritedGrant", "InheritancePreview", "Any"]
