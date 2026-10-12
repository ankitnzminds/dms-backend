"""Operations for administrators: dead background events and storage consistency."""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Query

from app.api.deps import CurrentPrincipal, DbSession
from app.modules.storage import reconcile
from app.schemas.common import ApiModel

router = APIRouter(prefix="/admin/ops", tags=["operations"])


class DeadEventOut(ApiModel):
    id: uuid.UUID
    event_type: str
    attempts: int
    last_error: str | None
    created_at: datetime


class MissingObject(ApiModel):
    document_id: uuid.UUID
    document_name: str
    version_number: int
    version_id: uuid.UUID


class StorageCheckOut(ApiModel):
    checked: int
    missing: list[MissingObject]
    errors: int
    next_offset: int


@router.get(
    "/dead-events", response_model=list[DeadEventOut], summary="Background events that gave up"
)
def dead_events(
    db: DbSession, principal: CurrentPrincipal, limit: int = Query(50, ge=1, le=200)
) -> list[DeadEventOut]:
    return [DeadEventOut.model_validate(e) for e in reconcile.list_dead(db, principal, limit=limit)]


@router.post(
    "/dead-events/{event_id}/replay",
    response_model=DeadEventOut,
    summary="Make a dead event claimable again (handlers are idempotent)",
)
def replay_dead_event(
    event_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> DeadEventOut:
    return DeadEventOut.model_validate(reconcile.replay(db, principal, event_id))


@router.get(
    "/storage-check",
    response_model=StorageCheckOut,
    summary="Check that stored versions still have their objects (read-only, bounded batch)",
)
def storage_check(
    db: DbSession,
    principal: CurrentPrincipal,
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> StorageCheckOut:
    return StorageCheckOut(
        **reconcile.find_missing_objects(db, principal, limit=limit, offset=offset)
    )
