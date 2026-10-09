"""Directory provisioning (admin): sources, snapshot upload, sync runs."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import CurrentPrincipal, DbSession
from app.core.errors import ErrorResponse
from app.modules.directory import service as directory
from app.schemas.directory import (
    DirectorySourceIn,
    DirectorySourceOut,
    DirectorySourceUpdate,
    SnapshotIn,
    SyncRequestIn,
    SyncRunOut,
)

router = APIRouter(
    prefix="/admin/directory", tags=["directory"], responses={404: {"model": ErrorResponse}}
)


@router.get(
    "/sources", response_model=list[DirectorySourceOut], summary="Provisioning sources (admin)"
)
def list_sources(db: DbSession, principal: CurrentPrincipal) -> list[DirectorySourceOut]:
    return directory.list_sources(db, principal)


@router.post(
    "/sources",
    response_model=DirectorySourceOut,
    status_code=201,
    summary="Add a provisioning source",
)
def create_source(
    body: DirectorySourceIn, db: DbSession, principal: CurrentPrincipal
) -> DirectorySourceOut:
    return directory.create_source(db, principal, body)


@router.patch("/sources/{source_id}", response_model=DirectorySourceOut, summary="Edit a source")
def update_source(
    source_id: uuid.UUID, body: DirectorySourceUpdate, db: DbSession, principal: CurrentPrincipal
) -> DirectorySourceOut:
    return directory.update_source(db, principal, source_id, body)


@router.delete(
    "/sources/{source_id}",
    status_code=204,
    summary="Remove a source (provisioned users/groups are kept)",
)
def delete_source(source_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> Response:
    directory.delete_source(db, principal, source_id)
    return Response(status_code=204)


@router.put(
    "/sources/{source_id}/snapshot",
    response_model=DirectorySourceOut,
    summary="Upload users/groups for a 'static' source",
)
def upload_snapshot(
    source_id: uuid.UUID, body: SnapshotIn, db: DbSession, principal: CurrentPrincipal
) -> DirectorySourceOut:
    return directory.upload_snapshot(db, principal, source_id, body)


@router.post(
    "/sources/{source_id}/sync",
    response_model=SyncRunOut,
    status_code=202,
    summary="Start a sync (preview with dry_run=true)",
)
def start_sync(
    source_id: uuid.UUID, body: SyncRequestIn, db: DbSession, principal: CurrentPrincipal
) -> SyncRunOut:
    return directory.request_sync(db, principal, source_id, dry_run=body.dry_run)


@router.get(
    "/sources/{source_id}/runs", response_model=list[SyncRunOut], summary="Recent sync runs"
)
def list_runs(source_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> list[SyncRunOut]:
    return directory.list_runs(db, principal, source_id)


@router.get(
    "/runs/{run_id}",
    response_model=SyncRunOut,
    summary="A sync run (poll until it leaves 'running')",
)
def get_run(run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> SyncRunOut:
    return directory.get_run(db, principal, run_id)
