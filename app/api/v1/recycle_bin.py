"""Administrators' Recycle Bin (organization-wide deleted items)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Query

from app.api.deps import Authz, DbSession
from app.modules.recycle import service
from app.schemas.common import Page
from app.schemas.recycle import PurgeIn, RecycleBulkOut, RecycleDetail, RecycleItem, RestoreIn

router = APIRouter(prefix="/admin/recycle-bin", tags=["recycle-bin"])


@router.get(
    "", response_model=Page[RecycleItem], summary="Deleted files and folders (administrators)"
)
def list_recycle_bin(
    db: DbSession,
    authz: Authz,
    q: str | None = Query(None, max_length=200, description="Name contains."),
    deleted_by: uuid.UUID | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    file_type: str | None = Query(None, max_length=20, description="Extension, or 'folder'."),
    source: Literal["trash", "user_permanent"] | None = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[RecycleItem]:
    items, total = service.list_items(
        db,
        authz,
        q=q,
        deleted_by=deleted_by,
        date_from=date_from,
        date_to=date_to,
        file_type=file_type,
        source=source,
        limit=limit,
        offset=offset,
    )
    return Page[RecycleItem](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/{kind}/{resource_id}", response_model=RecycleDetail, summary="Deletion details of one item"
)
def recycle_detail(
    kind: Literal["document", "folder"], resource_id: uuid.UUID, db: DbSession, authz: Authz
) -> RecycleDetail:
    return service.detail(db, authz, kind, resource_id)


@router.post(
    "/restore",
    response_model=RecycleBulkOut,
    summary="Restore items (original location, or a chosen folder / new name)",
)
def restore_items(body: RestoreIn, db: DbSession, authz: Authz) -> RecycleBulkOut:
    return service.restore(db, authz, body)


@router.post(
    "/purge",
    response_model=RecycleBulkOut,
    summary="Permanently delete items (irreversible; blocked by legal holds and retention)",
)
def purge_items(body: PurgeIn, db: DbSession, authz: Authz) -> RecycleBulkOut:
    return service.purge(db, authz, body)
