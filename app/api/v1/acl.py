"""Resource ACLs for the Manage Folder Permissions dialog and the hover toolbar's action hints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Body
from sqlalchemy import select

from app.api.deps import Authz, DbSession, limited
from app.core.errors import NotFoundError, ValidationFailed
from app.db.enums import Action, ResourceType
from app.db.models import Membership, User
from app.modules.authorization import access_check, acl_view
from app.modules.authorization.actions import expand_actions
from app.schemas.common import ApiModel
from app.schemas.sharing import PermissionGrantOut

router = APIRouter(tags=["acl"])
Kind = Literal["document", "folder"]


class PrincipalPermissionsPut(ApiModel):
    subject_type: Literal["user", "group", "organization"]
    subject_id: uuid.UUID | None = None
    permissions: list[Literal["read", "write", "share", "delete", "manage"]]
    inherit: bool = True
    expires_at: datetime | None = None


class InheritancePut(ApiModel):
    inherit: bool
    convert_inherited: bool = False
    confirm: bool = False


class CheckAccessIn(ApiModel):
    user_id: uuid.UUID | None = None
    email: str | None = None


class ActionHints(ApiModel):
    """Presentation hints only. Every endpoint authorizes independently."""

    can_share: bool
    can_download: bool
    can_rename: bool
    can_copy: bool
    can_move: bool
    can_delete: bool
    can_manage_permissions: bool


@router.get(
    "/resources/{kind}/{resource_id}/acl",
    response_model=acl_view.AclOut,
    summary="Direct and inherited permissions of a file or folder",
)
def get_acl(kind: Kind, resource_id: uuid.UUID, db: DbSession, authz: Authz) -> acl_view.AclOut:
    return acl_view.get_acl(db, authz, ResourceType(kind), resource_id)


@router.put(
    "/resources/{kind}/{resource_id}/acl/principals",
    response_model=PermissionGrantOut,
    summary="Set Read/Write/Share/Delete/Manage for one person or group",
)
def put_principal(
    kind: Kind, resource_id: uuid.UUID, body: PrincipalPermissionsPut, db: DbSession, authz: Authz
) -> PermissionGrantOut:
    if (body.subject_type == "organization") != (body.subject_id is None):
        raise ValidationFailed("subject_id is required unless subject_type is 'organization'.")
    return acl_view.set_principal_permissions(
        db,
        authz,
        ResourceType(kind),
        resource_id,
        body.subject_type,
        body.subject_id,
        list(body.permissions),
        body.inherit,
        body.expires_at,
    )


@router.post(
    "/resources/folder/{folder_id}/inheritance/preview",
    response_model=acl_view.InheritancePreview,
    summary="What turning folder-level inheritance on/off would change",
)
def inheritance_preview(
    folder_id: uuid.UUID, db: DbSession, authz: Authz, inherit: bool = Body(embed=True)
) -> acl_view.InheritancePreview:
    return acl_view.preview_inheritance(db, authz, folder_id, inherit)


@router.put(
    "/resources/folder/{folder_id}/inheritance",
    response_model=acl_view.AclOut,
    summary="Turn Inherit Folder Level Security on/off (never silently erases access)",
)
def put_inheritance(
    folder_id: uuid.UUID, body: InheritancePut, db: DbSession, authz: Authz
) -> acl_view.AclOut:
    return acl_view.set_inheritance(
        db,
        authz,
        folder_id,
        body.inherit,
        convert_inherited=body.convert_inherited,
        confirm=body.confirm,
    )


@router.post(
    "/resources/{kind}/{resource_id}/check-access",
    response_model=access_check.AccessCheckOut,
    summary="Effective access of a person for this item (diagnostic; grants nothing)",
    dependencies=[limited("access_check")],
)
def check_access(
    kind: Kind, resource_id: uuid.UUID, body: CheckAccessIn, db: DbSession, authz: Authz
) -> access_check.AccessCheckOut:
    p = authz.principal
    uid = body.user_id
    if uid is None:
        if not body.email:
            raise ValidationFailed("Enter the person's email.")
        uid = db.scalar(
            select(User.id)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == p.organization_id,
                User.email == body.email.strip().lower(),
            )
        )
        if uid is None:
            raise NotFoundError("User not found.")
    return access_check.check(db, p, ResourceType(kind), resource_id, uid)


@router.get(
    "/folders/{folder_id}/actions",
    response_model=ActionHints,
    summary="Which hover-toolbar actions to offer (a hint; each action is still authorized)",
)
def folder_action_hints(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> ActionHints:
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    held = expand_actions(authz.folder_actions([folder.id])[folder.id])
    return ActionHints(
        can_share="share" in held,
        can_download="download" in held,
        can_rename="rename" in held,
        can_copy="copy" in held,
        can_move="move" in held,
        can_delete="delete" in held,
        can_manage_permissions="manage_access" in held,
    )
