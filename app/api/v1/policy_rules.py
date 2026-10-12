"""Policy engine management API (rule policies: draft -> validate -> publish, history, rollback)."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query

from app.api.deps import CurrentPrincipal, DbSession
from app.core.errors import ForbiddenError
from app.modules.policy_engine import service, simulator, templates
from app.schemas.common import Page
from app.schemas.policy_rules import (
    ModeIn,
    PolicyCreate,
    PolicyDetail,
    PolicyOut,
    PolicyUpdate,
    PolicyValidationReport,
    PublishIn,
    RevisionDiff,
    RollbackIn,
)

router = APIRouter(prefix="/admin/policy-rules", tags=["policy-engine"])


@router.get("", response_model=Page[PolicyOut], summary="Rule policies of the organization")
def list_policies(
    db: DbSession,
    principal: CurrentPrincipal,
    status: Literal["draft", "published", "disabled", "archived"] | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[PolicyOut]:
    items, total = service.list_policies(
        db, principal, status=status, q=q, limit=limit, offset=offset
    )
    return Page[PolicyOut](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/grammar",
    response_model=templates.Grammar,
    summary="The attributes, operators, actions and effects a policy may use (single source of truth)",
)
def policy_grammar(principal: CurrentPrincipal) -> templates.Grammar:
    if not principal.can_read_audit:
        raise ForbiddenError("Policy access is restricted to administrators and auditors.")
    return templates.grammar()


@router.get(
    "/templates",
    response_model=list[templates.PolicyTemplate],
    summary="Predefined policy library (instantiate as a DRAFT; nothing auto-publishes)",
)
def policy_templates(principal: CurrentPrincipal) -> list[templates.PolicyTemplate]:
    if not principal.can_read_audit:
        raise ForbiddenError("Policy access is restricted to administrators and auditors.")
    return templates.catalogue()


@router.post("", response_model=PolicyDetail, status_code=201, summary="Create a draft policy")
def create_policy(body: PolicyCreate, db: DbSession, principal: CurrentPrincipal) -> PolicyDetail:
    return service.create(
        db,
        principal,
        name=body.name,
        description=body.description,
        category=body.category,
        document=body.document,
        change_reason=body.change_reason,
        template_key=body.template_key,
    )


@router.get("/{policy_id}", response_model=PolicyDetail, summary="A policy with all its revisions")
def get_policy(policy_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> PolicyDetail:
    return service.get_policy(db, principal, policy_id)


@router.patch(
    "/{policy_id}", response_model=PolicyDetail, summary="Edit the draft (or open a new one)"
)
def update_policy(
    policy_id: uuid.UUID, body: PolicyUpdate, db: DbSession, principal: CurrentPrincipal
) -> PolicyDetail:
    return service.update_draft(
        db,
        principal,
        policy_id,
        name=body.name,
        description=body.description,
        document=body.document,
        change_reason=body.change_reason,
    )


@router.post(
    "/{policy_id}/validate", response_model=PolicyValidationReport, summary="Validate the draft"
)
def validate_policy(
    policy_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> PolicyValidationReport:
    return service.validate(db, principal, policy_id)


@router.post(
    "/{policy_id}/publish", response_model=PolicyDetail, summary="Publish the validated draft"
)
def publish_policy(
    policy_id: uuid.UUID, body: PublishIn, db: DbSession, principal: CurrentPrincipal
) -> PolicyDetail:
    return service.publish(
        db, principal, policy_id, mode=body.mode, change_reason=body.change_reason
    )


@router.put("/{policy_id}/mode", response_model=PolicyDetail, summary="Enforce or only observe")
def set_mode(
    policy_id: uuid.UUID, body: ModeIn, db: DbSession, principal: CurrentPrincipal
) -> PolicyDetail:
    return service.set_mode(db, principal, policy_id, body.mode)


@router.post("/{policy_id}/disable", response_model=PolicyDetail, summary="Stop enforcing")
def disable_policy(
    policy_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal, reason: str | None = None
) -> PolicyDetail:
    return service.disable(db, principal, policy_id, reason)


@router.post(
    "/{policy_id}/enable", response_model=PolicyDetail, summary="Re-enable a disabled policy"
)
def enable_policy(policy_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal) -> PolicyDetail:
    return service.enable(db, principal, policy_id)


@router.post(
    "/{policy_id}/archive", response_model=PolicyDetail, summary="Archive an unused policy"
)
def archive_policy(
    policy_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> PolicyDetail:
    return service.archive(db, principal, policy_id)


@router.post(
    "/{policy_id}/rollback",
    response_model=PolicyDetail,
    summary="New draft copied from an old revision",
)
def rollback_policy(
    policy_id: uuid.UUID, body: RollbackIn, db: DbSession, principal: CurrentPrincipal
) -> PolicyDetail:
    return service.rollback(
        db, principal, policy_id, to_revision=body.to_revision, reason=body.change_reason
    )


@router.get("/{policy_id}/compare", response_model=RevisionDiff, summary="Compare two revisions")
def compare_revisions(
    policy_id: uuid.UUID,
    db: DbSession,
    principal: CurrentPrincipal,
    a: int = Query(ge=1),
    b: int = Query(ge=1),
) -> RevisionDiff:
    return service.compare(db, principal, policy_id, a, b)


@router.post(
    "/simulate",
    response_model=simulator.SimulationOut,
    summary="Simulate a decision for a user, resource and action (never executes anything)",
)
def simulate_decision(
    body: simulator.SimulationIn, db: DbSession, principal: CurrentPrincipal
) -> simulator.SimulationOut:
    return simulator.simulate(db, principal, body)
