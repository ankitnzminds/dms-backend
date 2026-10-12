"""File-manager endpoints: bulk operations, folder copy, Quick Access, properties, locks, prefs."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Path, Query, Response

from app.api.deps import Authz, CurrentPrincipal, DbSession, limited
from app.core.errors import ErrorResponse
from app.modules.documents import locks
from app.modules.items import service as items
from app.schemas.common import Page
from app.schemas.items import (
    BulkDeleteIn,
    BulkMoveCopyIn,
    BulkResult,
    ColorTagIn,
    FolderCopyIn,
    FolderCopyOut,
    ItemProperties,
    LockIn,
    PreferenceValue,
)
from app.schemas.tree import LockOut, TreeItem

router = APIRouter(tags=["file manager"], responses={404: {"model": ErrorResponse}})

PrefKey = Annotated[str, Path(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")]


@router.post(
    "/items/bulk/move",
    response_model=BulkResult,
    summary="Move many items (cut/paste, drag & drop); every item is authorized and reported separately",
    dependencies=[limited("bulk_items", sensitive=True)],
)
def bulk_move(body: BulkMoveCopyIn, db: DbSession, authz: Authz) -> BulkResult:
    return items.bulk_move(db, authz, body.items, body.target_folder_id, body.on_conflict)


@router.post(
    "/items/bulk/copy",
    response_model=BulkResult,
    summary="Copy many items as NEW items (copy/paste); folders are copied recursively",
    dependencies=[limited("bulk_items", sensitive=True)],
)
def bulk_copy(body: BulkMoveCopyIn, db: DbSession, authz: Authz) -> BulkResult:
    return items.bulk_copy(db, authz, body.items, body.target_folder_id, body.on_conflict)


@router.post(
    "/items/bulk/delete",
    response_model=BulkResult,
    summary="Move many items to the trash with a per-item result",
    dependencies=[limited("bulk_items", sensitive=True)],
)
def bulk_delete(body: BulkDeleteIn, db: DbSession, authz: Authz) -> BulkResult:
    return items.bulk_delete(db, authz, body.items)


@router.post(
    "/folders/{folder_id}/copy",
    response_model=FolderCopyOut,
    status_code=201,
    summary="Copy a folder (recursively, as new items) into another folder",
    dependencies=[limited("bulk_items", sensitive=True)],
)
def copy_folder(
    folder_id: uuid.UUID, body: FolderCopyIn, db: DbSession, authz: Authz
) -> FolderCopyOut:
    return items.copy_folder(db, authz, folder_id, body.target_folder_id, body.name)


@router.put(
    "/folders/{folder_id}/favorite", status_code=204, summary="Pin a folder to Quick Access"
)
def pin_folder(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    items.set_folder_favorite(db, authz, folder_id, True)
    return Response(status_code=204)


@router.delete("/folders/{folder_id}/favorite", status_code=204, summary="Unpin a folder")
def unpin_folder(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    items.set_folder_favorite(db, authz, folder_id, False)
    return Response(status_code=204)


@router.get(
    "/favorites",
    response_model=Page[TreeItem],
    summary="Quick Access: pinned folders and starred documents",
)
def favorites(
    db: DbSession, authz: Authz, limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)
) -> Page[TreeItem]:
    found, total = items.list_favorites(db, authz, limit, offset)
    return Page[TreeItem](items=found, total=total, limit=limit, offset=offset)


@router.get(
    "/documents/{document_id}/properties",
    response_model=ItemProperties,
    summary="Properties panel for a document",
)
def document_properties(document_id: uuid.UUID, db: DbSession, authz: Authz) -> ItemProperties:
    return items.properties(db, authz, "document", document_id)


@router.get(
    "/folders/{folder_id}/properties",
    response_model=ItemProperties,
    summary="Properties panel for a folder (counts cover only what you may see)",
)
def folder_properties(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> ItemProperties:
    return items.properties(db, authz, "folder", folder_id)


@router.post(
    "/documents/{document_id}/lock",
    response_model=LockOut,
    status_code=201,
    summary="Check out (lock) a document",
)
def lock_document(
    document_id: uuid.UUID, db: DbSession, authz: Authz, body: LockIn | None = None
) -> LockOut:
    return locks.lock_document(db, authz, document_id, body)


@router.delete(
    "/documents/{document_id}/lock",
    status_code=204,
    summary="Check in (unlock); administrators may break a lock",
)
def unlock_document(document_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    locks.unlock_document(db, authz, document_id)
    return Response(status_code=204)


@router.post(
    "/folders/{folder_id}/lock",
    response_model=LockOut,
    status_code=201,
    summary="Lock a folder (others cannot rename, move or delete it)",
)
def lock_folder(
    folder_id: uuid.UUID, db: DbSession, authz: Authz, body: LockIn | None = None
) -> LockOut:
    return locks.lock_folder(db, authz, folder_id, body)


@router.delete(
    "/folders/{folder_id}/lock",
    status_code=204,
    summary="Unlock a folder; administrators may break a lock",
)
def unlock_folder(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    locks.unlock_folder(db, authz, folder_id)
    return Response(status_code=204)


@router.get(
    "/me/preferences/{key}",
    response_model=PreferenceValue,
    summary="Read a stored UI preference (e.g. file-manager layout)",
)
def get_pref(key: PrefKey, db: DbSession, principal: CurrentPrincipal) -> PreferenceValue:
    return PreferenceValue(value=items.get_preference(db, principal, key))


@router.put(
    "/me/preferences/{key}",
    response_model=PreferenceValue,
    summary="Store a UI preference (<= 16 KB JSON)",
)
def put_pref(
    key: PrefKey, body: PreferenceValue, db: DbSession, principal: CurrentPrincipal
) -> PreferenceValue:
    return PreferenceValue(value=items.set_preference(db, principal, key, body.value))


@router.put(
    "/documents/{document_id}/color-tag",
    status_code=204,
    summary="Set or clear a document's color tag",
)
def set_document_color(
    document_id: uuid.UUID, body: ColorTagIn, db: DbSession, authz: Authz
) -> Response:
    items.set_color_tag(db, authz, "document", document_id, body.color)
    return Response(status_code=204)


@router.put(
    "/folders/{folder_id}/color-tag",
    status_code=204,
    summary="Set or clear a folder's color tag",
)
def set_folder_color(
    folder_id: uuid.UUID, body: ColorTagIn, db: DbSession, authz: Authz
) -> Response:
    items.set_color_tag(db, authz, "folder", folder_id, body.color)
    return Response(status_code=204)
