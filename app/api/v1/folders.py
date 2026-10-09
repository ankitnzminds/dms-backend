"""Canonical folder tree endpoints."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query, Response

from app.api.deps import Authz, DbSession, limited
from app.core.errors import ErrorResponse
from app.db.enums import ResourceType
from app.modules.authorization import acl
from app.modules.folders import service as folders
from app.modules.sharing import service as sharing
from app.schemas.common import BreadcrumbSegmentOut, Page
from app.schemas.sharing import (
    PermissionGrantIn,
    PermissionGrantOut,
    ShareCreate,
    ShareOut,
)
from app.schemas.tree import (
    EnsurePathIn,
    EnsurePathOut,
    FolderCreate,
    FolderOut,
    FolderUpdate,
    RestoreRequest,
    TreeItem,
)

router = APIRouter(prefix="/folders", tags=["folders"], responses={404: {"model": ErrorResponse}})


@router.get("/root", response_model=FolderOut, summary="The organization's root folder")
def get_root(db: DbSession, authz: Authz) -> FolderOut:
    return folders.get_root(db, authz)


@router.post("", response_model=FolderOut, status_code=201, summary="Create a folder")
def create_folder(body: FolderCreate, db: DbSession, authz: Authz) -> FolderOut:
    return folders.create_folder(db, authz, body.parent_folder_id, body.name)


@router.post(
    "/{folder_id}/ensure-path",
    response_model=EnsurePathOut,
    summary="Find or create a nested folder path (used by folder upload / drag & drop)",
)
def ensure_path(
    folder_id: uuid.UUID, body: EnsurePathIn, db: DbSession, authz: Authz
) -> EnsurePathOut:
    leaf, created = folders.ensure_path(db, authz, folder_id, body.path)
    return EnsurePathOut(folder=leaf, created=created)


@router.get("/{folder_id}", response_model=FolderOut, summary="Folder details")
def get_folder(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> FolderOut:
    return folders.get_folder(db, authz, folder_id)


@router.get(
    "/{folder_id}/children", response_model=Page[TreeItem], summary="List the folder's children"
)
def list_children(
    folder_id: uuid.UUID,
    db: DbSession,
    authz: Authz,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    sort: Literal["name", "updated_at", "size", "type", "modified_by"] = "name",
    order: Literal["asc", "desc"] = "asc",
    kind: Literal["folder", "document"] | None = None,
) -> Page[TreeItem]:
    items, total = folders.list_children(
        db,
        authz,
        folder_id,
        limit=limit,
        offset=offset,
        sort=sort,
        descending=order == "desc",
        kind=kind,
    )
    return Page[TreeItem](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/{folder_id}/breadcrumb",
    response_model=list[BreadcrumbSegmentOut],
    summary="Canonical path of the folder (names are context; `navigable` reflects real access)",
)
def get_breadcrumb(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> list[BreadcrumbSegmentOut]:
    return folders.breadcrumb(db, authz, folder_id)


@router.patch("/{folder_id}", response_model=FolderOut, summary="Rename and/or move a folder")
def update_folder(
    folder_id: uuid.UUID, body: FolderUpdate, db: DbSession, authz: Authz
) -> FolderOut:
    return folders.update_folder(
        db,
        authz,
        folder_id,
        name=body.name,
        parent_folder_id=body.parent_folder_id,
        expected_row_version=body.expected_row_version,
    )


@router.delete(
    "/{folder_id}", status_code=204, summary="Move a folder (and its contents) to the trash"
)
def delete_folder(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    folders.delete_folder(db, authz, folder_id)
    return Response(status_code=204)


@router.post("/{folder_id}/restore", response_model=FolderOut, summary="Restore a trashed folder")
def restore_folder(
    folder_id: uuid.UUID, db: DbSession, authz: Authz, body: RestoreRequest | None = None
) -> FolderOut:
    return folders.restore_folder(db, authz, folder_id, body.new_name if body else None)


# ---- sharing & ACL on folders
@router.post(
    "/{folder_id}/shares",
    response_model=ShareOut,
    status_code=201,
    summary="Share a folder (recipients get access to the folder and its contents only)",
    dependencies=[limited("share_create", sensitive=True)],
)
def share_folder(folder_id: uuid.UUID, body: ShareCreate, db: DbSession, authz: Authz) -> ShareOut:
    return sharing.create_share(db, authz, ResourceType.FOLDER, folder_id, body)


@router.get("/{folder_id}/shares", response_model=list[ShareOut], summary="Shares of this folder")
def folder_shares(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> list[ShareOut]:
    return sharing.list_for_resource(db, authz, ResourceType.FOLDER, folder_id)


@router.get(
    "/{folder_id}/permissions",
    response_model=list[PermissionGrantOut],
    summary="ACL entries (requires manage_access)",
)
def folder_permissions(
    folder_id: uuid.UUID, db: DbSession, authz: Authz
) -> list[PermissionGrantOut]:
    return acl.list_grants(db, authz, ResourceType.FOLDER, folder_id)


@router.post(
    "/{folder_id}/permissions",
    response_model=PermissionGrantOut,
    status_code=201,
    summary="Add an ACL entry",
)
def add_folder_permission(
    folder_id: uuid.UUID, body: PermissionGrantIn, db: DbSession, authz: Authz
) -> PermissionGrantOut:
    return acl.add_grant(db, authz, ResourceType.FOLDER, folder_id, body)


@router.delete(
    "/{folder_id}/permissions/{grant_id}", status_code=204, summary="Revoke an ACL entry"
)
def revoke_folder_permission(
    folder_id: uuid.UUID, grant_id: uuid.UUID, db: DbSession, authz: Authz
) -> Response:
    acl.revoke_grant(db, authz, ResourceType.FOLDER, folder_id, grant_id)
    return Response(status_code=204)
