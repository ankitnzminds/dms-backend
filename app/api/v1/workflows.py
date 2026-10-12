"""Approval workflows: definitions (admin), runs on documents, my tasks, decisions."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query, Response

from app.api.deps import Authz, CurrentPrincipal, DbSession
from app.core.errors import ErrorResponse
from app.modules.workflows import approval_chain
from app.modules.workflows import service as wf
from app.schemas.common import Page
from app.schemas.workflows import (
    ApprovalChainIn,
    ApprovalChainOut,
    CancelRunIn,
    DecisionIn,
    DelegateIn,
    RunOut,
    StartRunIn,
    SubmitForApprovalIn,
    TaskOut,
    WorkflowDefinitionIn,
    WorkflowDefinitionOut,
    WorkflowDefinitionUpdate,
    WorkflowVersionIn,
)

router = APIRouter(tags=["workflows"], responses={404: {"model": ErrorResponse}})


# ---- definitions
@router.get(
    "/workflows",
    response_model=list[WorkflowDefinitionOut],
    summary="Approval workflows available to start",
)
def list_workflows(
    db: DbSession, principal: CurrentPrincipal, include_archived: bool = False
) -> list[WorkflowDefinitionOut]:
    return wf.list_definitions(db, principal, include_archived=include_archived)


@router.post(
    "/admin/workflows",
    response_model=WorkflowDefinitionOut,
    status_code=201,
    summary="Create a workflow (admin)",
)
def create_workflow(
    body: WorkflowDefinitionIn, db: DbSession, principal: CurrentPrincipal
) -> WorkflowDefinitionOut:
    return wf.create_definition(db, principal, body)


@router.post(
    "/admin/workflows/{definition_id}/versions",
    response_model=WorkflowDefinitionOut,
    status_code=201,
    summary="Publish new steps as a new version (running approvals keep their version)",
)
def add_workflow_version(
    definition_id: uuid.UUID, body: WorkflowVersionIn, db: DbSession, principal: CurrentPrincipal
) -> WorkflowDefinitionOut:
    return wf.add_version(db, principal, definition_id, body.steps)


@router.patch(
    "/admin/workflows/{definition_id}",
    response_model=WorkflowDefinitionOut,
    summary="Rename / archive a workflow (admin)",
)
def update_workflow(
    definition_id: uuid.UUID,
    body: WorkflowDefinitionUpdate,
    db: DbSession,
    principal: CurrentPrincipal,
) -> WorkflowDefinitionOut:
    return wf.update_definition(
        db,
        principal,
        definition_id,
        name=body.name,
        description=body.description,
        archived=body.archived,
    )


# ---- runs
@router.get(
    "/folders/{folder_id}/approval-chain",
    response_model=ApprovalChainOut,
    summary="The folder's approval chain (levels of approvers); empty = pick a workflow manually",
)
def get_approval_chain(folder_id: uuid.UUID, db: DbSession, authz: Authz) -> ApprovalChainOut:
    return approval_chain.get_chain(db, authz, folder_id)


@router.put(
    "/folders/{folder_id}/approval-chain",
    response_model=ApprovalChainOut,
    summary="Replace the folder's approval chain (administrators); an empty chain removes it",
)
def set_approval_chain(
    folder_id: uuid.UUID, body: ApprovalChainIn, db: DbSession, principal: CurrentPrincipal
) -> ApprovalChainOut:
    return approval_chain.set_chain(db, principal, folder_id, body)


@router.post(
    "/documents/{document_id}/submit-for-approval",
    response_model=RunOut,
    status_code=201,
    summary="Submit the file to its folder's approval chain (no approver to choose)",
)
def submit_for_approval(
    document_id: uuid.UUID, body: SubmitForApprovalIn, db: DbSession, authz: Authz
) -> RunOut:
    return approval_chain.submit(db, authz, document_id, body.note)


@router.post(
    "/documents/{document_id}/workflow-runs",
    response_model=RunOut,
    status_code=201,
    summary="Submit the current version for approval",
)
def start_run(document_id: uuid.UUID, body: StartRunIn, db: DbSession, authz: Authz) -> RunOut:
    return wf.start_run(db, authz, document_id, body.definition_id, body.note)


@router.get(
    "/documents/{document_id}/workflow-runs",
    response_model=list[RunOut],
    summary="Approval history of a document",
)
def document_runs(document_id: uuid.UUID, db: DbSession, authz: Authz) -> list[RunOut]:
    return wf.list_runs_for_document(db, authz, document_id)


@router.get(
    "/workflow-runs/{run_id}",
    response_model=RunOut,
    summary="Approval details (participants, submitter, admins, viewers)",
)
def get_run(run_id: uuid.UUID, db: DbSession, authz: Authz) -> RunOut:
    return wf.get_run(db, authz, run_id)


@router.post(
    "/workflow-runs/{run_id}/cancel",
    status_code=204,
    summary="Cancel an approval in progress (submitter or admin)",
)
def cancel_run(
    run_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal, body: CancelRunIn | None = None
) -> Response:
    wf.cancel_run(db, principal, run_id, body.comment if body else None)
    return Response(status_code=204)


@router.post(
    "/workflow-runs/{run_id}/resubmit",
    response_model=RunOut,
    status_code=201,
    summary="Resubmit a rejected approval",
)
def resubmit_run(
    run_id: uuid.UUID, db: DbSession, authz: Authz, body: CancelRunIn | None = None
) -> RunOut:
    return wf.resubmit(db, authz, run_id, body.comment if body else None)


# ---- tasks
@router.get("/workflow-tasks/mine", response_model=Page[TaskOut], summary="My approval tasks")
def my_tasks(
    db: DbSession,
    principal: CurrentPrincipal,
    status: Literal["pending", "approved", "rejected", "cancelled", "skipped", "all"]
    | None = "pending",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[TaskOut]:
    items, total = wf.list_my_tasks(
        db, principal, status=None if status == "all" else status, limit=limit, offset=offset
    )
    return Page[TaskOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/workflow-tasks/{task_id}", response_model=TaskOut, summary="One task I may see")
def get_task(task_id: uuid.UUID, db: DbSession, authz: Authz) -> TaskOut:
    return wf.get_task(db, authz, task_id)


@router.post(
    "/workflow-tasks/{task_id}/decision",
    response_model=TaskOut,
    summary="Approve or reject (idempotent)",
)
def decide(
    task_id: uuid.UUID, body: DecisionIn, db: DbSession, principal: CurrentPrincipal
) -> TaskOut:
    return wf.decide(db, principal, task_id, body.decision, body.comment)


@router.post(
    "/workflow-tasks/{task_id}/delegate",
    response_model=TaskOut,
    summary="Delegate my pending task to another member",
)
def delegate(
    task_id: uuid.UUID, body: DelegateIn, db: DbSession, principal: CurrentPrincipal
) -> TaskOut:
    return wf.delegate(
        db, principal, task_id, user_id=body.user_id, email=body.email, comment=body.comment
    )
