"""Administration: automation workflows (IF this THEN that + visual canvas), runs and catalogue."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Query

from app.api.deps import CurrentPrincipal, DbSession, limited
from app.db.session import get_sessionmaker
from app.modules.automations import runs, service
from app.schemas.automations import (
    AutomationCreate,
    AutomationOut,
    AutomationUpdate,
    CatalogueOut,
    PublishRequest,
    AutomationRunOut,
    TestRequest,
    ValidationReport,
)
from app.schemas.common import Page

router = APIRouter(prefix="/admin", tags=["admin-automations"])


@router.get(
    "/automations/catalogue", response_model=CatalogueOut, summary="Conditions, actions and schemas"
)
def catalogue(principal: CurrentPrincipal) -> CatalogueOut:
    service.require_admin(principal)
    return service.catalogue()


@router.get("/automations", response_model=Page[AutomationOut], summary="Manage workflows")
def list_automations(
    db: DbSession,
    principal: CurrentPrincipal,
    q: str | None = Query(None, max_length=200),
    status: Literal["draft", "published", "archived"] | None = None,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[AutomationOut]:
    items, total = service.list_automations(
        db, principal, q=q, status=status, limit=limit, offset=offset
    )
    return Page[AutomationOut](items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/automations", response_model=AutomationOut, status_code=201, summary="Create a workflow"
)
def create_automation(
    body: AutomationCreate, db: DbSession, principal: CurrentPrincipal
) -> AutomationOut:
    return service.create(db, principal, body)


@router.post(
    "/automations/validate",
    response_model=ValidationReport,
    summary="Validate a definition without saving it",
)
def validate_definition(
    body: AutomationCreate, db: DbSession, principal: CurrentPrincipal
) -> ValidationReport:
    service.require_admin(principal)
    return service.validate_definition(db, principal, body.trigger, body.graph)


@router.get(
    "/automations/{automation_id}", response_model=AutomationOut, summary="Workflow details"
)
def get_automation(
    automation_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> AutomationOut:
    return service.to_out(db, service.get_or_404(db, principal, automation_id))


@router.patch(
    "/automations/{automation_id}", response_model=AutomationOut, summary="Edit the draft"
)
def update_automation(
    automation_id: uuid.UUID, body: AutomationUpdate, db: DbSession, principal: CurrentPrincipal
) -> AutomationOut:
    return service.update(db, principal, automation_id, body)


@router.post(
    "/automations/{automation_id}/validate",
    response_model=ValidationReport,
    summary="Validate the saved draft",
)
def validate_saved(
    automation_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> ValidationReport:
    return service.validate_saved(db, principal, automation_id)


@router.post(
    "/automations/{automation_id}/publish",
    response_model=AutomationOut,
    summary="Publish the draft",
)
def publish(
    automation_id: uuid.UUID, body: PublishRequest, db: DbSession, principal: CurrentPrincipal
) -> AutomationOut:
    return service.publish(db, principal, automation_id, confirm_high_risk=body.confirm_high_risk)


@router.post("/automations/{automation_id}/enable", response_model=AutomationOut, summary="Enable")
def enable(automation_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AutomationOut:
    return service.set_enabled(db, principal, automation_id, True)


@router.post(
    "/automations/{automation_id}/disable", response_model=AutomationOut, summary="Disable"
)
def disable(automation_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AutomationOut:
    return service.set_enabled(db, principal, automation_id, False)


@router.post(
    "/automations/{automation_id}/archive", response_model=AutomationOut, summary="Archive"
)
def archive(automation_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AutomationOut:
    return service.archive(db, principal, automation_id)


@router.post(
    "/automations/{automation_id}/duplicate",
    response_model=AutomationOut,
    status_code=201,
    summary="Duplicate",
)
def duplicate(
    automation_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> AutomationOut:
    return service.duplicate(db, principal, automation_id)


@router.post(
    "/automations/{automation_id}/test",
    summary="Dry run against one item: nothing is sent, copied, moved, deleted or granted",
    dependencies=[limited("automation_test", sensitive=True)],
)
def test_automation(
    automation_id: uuid.UUID, body: TestRequest, db: DbSession, principal: CurrentPrincipal
) -> dict[str, Any]:
    out = runs.dry_run(db, get_sessionmaker(), principal, automation_id, body.resource_id)
    return {
        "would_trigger": out["would_trigger"],
        "status": out["status"],
        "run": out["run"].model_dump(mode="json"),
    }


@router.get(
    "/automations/{automation_id}/runs",
    response_model=Page[AutomationRunOut],
    summary="Run history",
)
def list_runs(
    automation_id: uuid.UUID,
    db: DbSession,
    principal: CurrentPrincipal,
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
) -> Page[AutomationRunOut]:
    items, total = runs.list_runs(db, principal, automation_id, limit=limit, offset=offset)
    return Page[AutomationRunOut](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/automation-runs/{run_id}", response_model=AutomationRunOut, summary="Run with node outcomes"
)
def get_run(run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AutomationRunOut:
    return runs.get_run(db, principal, run_id)


@router.post(
    "/automation-runs/{run_id}/retry", response_model=AutomationRunOut, summary="Retry failed steps"
)
def retry_run(run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AutomationRunOut:
    return runs.retry(db, principal, run_id)


@router.post(
    "/automation-runs/{run_id}/cancel", response_model=AutomationRunOut, summary="Cancel a run"
)
def cancel_run(run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> AutomationRunOut:
    return runs.cancel(db, principal, run_id)
