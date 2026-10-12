"""Workflows for everyone: start a workflow on a file or folder, and follow its progress."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query

from app.api.deps import Authz, CurrentPrincipal, DbSession
from app.modules.automations import manual
from app.schemas.automations import (
    AutomationRunOut,
    RunSummaryOut,
    StartableOut,
    StartedOut,
    StartRequest,
)
from app.schemas.common import Page

router = APIRouter(tags=["workflows"])


@router.get(
    "/automations/startable",
    response_model=list[StartableOut],
    summary="Workflows I can start on this item",
)
def startable(
    db: DbSession,
    authz: Authz,
    resource_type: Literal["document", "folder"],
    resource_id: uuid.UUID,
) -> list[StartableOut]:
    return manual.startable(db, authz, resource_type, resource_id)


@router.post(
    "/automations/{automation_id}/start",
    response_model=StartedOut,
    status_code=202,
    summary="Start a workflow on a file or folder",
)
def start(automation_id: uuid.UUID, body: StartRequest, db: DbSession, authz: Authz) -> StartedOut:
    return manual.start(db, authz, automation_id, body)


@router.get(
    "/automation-runs/mine",
    response_model=Page[RunSummaryOut],
    summary="Workflows I started",
)
def my_runs(
    db: DbSession,
    principal: CurrentPrincipal,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[RunSummaryOut]:
    items, total = manual.my_runs(db, principal, limit=limit, offset=offset)
    return Page[RunSummaryOut](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/automation-runs/mine/{run_id}",
    response_model=RunSummaryOut,
    summary="One workflow run I started",
)
def my_run(run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> RunSummaryOut:
    return manual.get_my_run(db, principal, run_id)


@router.get(
    "/documents/{document_id}/automation-runs",
    response_model=list[RunSummaryOut],
    summary="Workflows that ran on this file",
)
def document_runs(
    document_id: uuid.UUID, db: DbSession, authz: Authz, limit: int = Query(10, ge=1, le=50)
) -> list[RunSummaryOut]:
    return manual.document_runs(db, authz, document_id, limit=limit)


admin_router = APIRouter(prefix="/admin", tags=["admin-automations"])


@admin_router.get(
    "/automation-runs",
    response_model=Page[AutomationRunOut],
    summary="Every workflow run in the organization",
)
def admin_runs(
    db: DbSession,
    principal: CurrentPrincipal,
    status: Literal["queued", "running", "waiting", "succeeded", "failed", "cancelled", "skipped"]
    | None = None,
    automation_id: uuid.UUID | None = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[AutomationRunOut]:
    items, total = manual.admin_runs(
        db, principal, status=status, automation_id=automation_id, limit=limit, offset=offset
    )
    return Page[AutomationRunOut](items=items, total=total, limit=limit, offset=offset)
