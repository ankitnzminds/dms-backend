"""Approval workflows as an explicit, tested state machine (ADR-0008).

Run:   in_progress -> approved | rejected | cancelled          (terminal states)
Task:  pending -> approved | rejected | cancelled | skipped    (terminal states)

* Definitions are versioned; a run snapshots the exact definition version AND the exact
  document version under review.
* Steps run sequentially. Inside a step, ``rule=all`` is a parallel approval (everyone must
  approve; one rejection fails the run) and ``rule=any`` is first-approval-wins.
* Steps can be conditional on document attributes; skipped steps are logged, never silent.
* The initiator can never approve their own request; a step with no eligible approver fails
  closed (the run is rejected) instead of being skipped.
* Decisions are idempotent and take row locks, so double clicks / concurrent decisions cannot
  advance a run twice. Authorization is checked at task display and at decision time.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import Action, AuditOutcome, DocumentStatus, MembershipStatus, UserStatus
from app.db.models import (
    ApprovalAction,
    Document,
    DocumentVersion,
    Group,
    GroupMembership,
    Membership,
    User,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
    WorkflowRun,
    WorkflowTask,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.modules.outbox import service as outbox
from app.modules.users.service import require_admin
from app.schemas.common import UserRef
from app.schemas.workflows import (
    ActionOut,
    RunOut,
    StepSpec,
    StepStatusOut,
    TaskOut,
    WorkflowDefinitionIn,
    WorkflowDefinitionOut,
)

TERMINAL_RUN = ("approved", "rejected", "cancelled")


# ------------------------------------------------------------------ definitions
def _validate_references(db: Session, org_id: uuid.UUID, steps: list[StepSpec]) -> None:
    user_ids: set[uuid.UUID] = set()
    group_ids: set[uuid.UUID] = set()
    for step in steps:
        if step.escalate_to_user_id:
            user_ids.add(step.escalate_to_user_id)
        for a in step.assignees:
            if a.type == "user" and a.id:
                user_ids.add(a.id)
            elif a.type == "group" and a.id:
                group_ids.add(a.id)
    if user_ids:
        found = set(
            db.scalars(
                select(Membership.user_id).where(
                    Membership.organization_id == org_id,
                    Membership.user_id.in_(user_ids),
                    Membership.status.in_(
                        [MembershipStatus.ACTIVE.value, MembershipStatus.INVITED.value]
                    ),
                )
            )
        )
        if found != user_ids:
            raise ValidationFailed(
                "A referenced user is not a member of this organization.", code="unknown_assignee"
            )
    if group_ids:
        found_g = set(
            db.scalars(
                select(Group.id).where(Group.organization_id == org_id, Group.id.in_(group_ids))
            )
        )
        if found_g != group_ids:
            raise ValidationFailed("A referenced group does not exist.", code="unknown_assignee")


def _steps_json(steps: list[StepSpec]) -> list[dict[str, Any]]:
    return [s.model_dump(mode="json", exclude_none=True) for s in steps]


def _latest_version(db: Session, definition_id: uuid.UUID) -> WorkflowDefinitionVersion:
    v = db.scalar(
        select(WorkflowDefinitionVersion)
        .where(WorkflowDefinitionVersion.definition_id == definition_id)
        .order_by(WorkflowDefinitionVersion.version_number.desc())
        .limit(1)
    )
    assert v is not None
    return v


def _definition_out(d: WorkflowDefinition, v: WorkflowDefinitionVersion) -> WorkflowDefinitionOut:
    return WorkflowDefinitionOut(
        id=d.id,
        name=d.name,
        description=d.description,
        archived=d.archived_at is not None,
        latest_version=v.version_number,
        steps=[StepSpec.model_validate(s) for s in v.steps],
        created_at=d.created_at,
    )


def create_definition(
    db: Session, p: Principal, body: WorkflowDefinitionIn
) -> WorkflowDefinitionOut:
    require_admin(p)
    _validate_references(db, p.organization_id, body.steps)
    d = WorkflowDefinition(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=body.name.strip(),
        description=body.description,
        created_by=p.user_id,
    )
    db.add(d)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError(
            "A workflow with this name already exists.", code="name_conflict"
        ) from exc
    v = WorkflowDefinitionVersion(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        definition_id=d.id,
        version_number=1,
        steps=_steps_json(body.steps),
        created_by=p.user_id,
    )
    db.add(v)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="workflow_definition.created",
        resource_type="workflow_definition",
        resource_id=d.id,
        metadata={"name": d.name, "steps": len(body.steps)},
    )
    db.commit()
    return _definition_out(d, v)


def _def_or_404(db: Session, p: Principal, definition_id: uuid.UUID) -> WorkflowDefinition:
    d = db.scalar(
        select(WorkflowDefinition).where(
            WorkflowDefinition.id == definition_id,
            WorkflowDefinition.organization_id == p.organization_id,
        )
    )
    if d is None:
        raise NotFoundError("Workflow not found.")
    return d


def add_version(
    db: Session, p: Principal, definition_id: uuid.UUID, steps: list[StepSpec]
) -> WorkflowDefinitionOut:
    """New steps = new immutable version. Runs already in flight keep the version they started with."""
    require_admin(p)
    d = db.scalar(
        select(WorkflowDefinition)
        .where(
            WorkflowDefinition.id == definition_id,
            WorkflowDefinition.organization_id == p.organization_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if d is None:
        raise NotFoundError("Workflow not found.")
    _validate_references(db, p.organization_id, steps)
    latest = _latest_version(db, d.id)
    v = WorkflowDefinitionVersion(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        definition_id=d.id,
        version_number=latest.version_number + 1,
        steps=_steps_json(steps),
        created_by=p.user_id,
    )
    db.add(v)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="workflow_definition.versioned",
        resource_type="workflow_definition",
        resource_id=d.id,
        metadata={"version": v.version_number},
    )
    db.commit()
    return _definition_out(d, v)


def update_definition(
    db: Session,
    p: Principal,
    definition_id: uuid.UUID,
    *,
    name: str | None,
    description: str | None,
    archived: bool | None,
) -> WorkflowDefinitionOut:
    require_admin(p)
    d = _def_or_404(db, p, definition_id)
    if name is not None:
        d.name = name.strip()
    if description is not None:
        d.description = description
    if archived is not None:
        d.archived_at = datetime.now(UTC) if archived else None
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError(
            "A workflow with this name already exists.", code="name_conflict"
        ) from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="workflow_definition.updated",
        resource_type="workflow_definition",
        resource_id=d.id,
    )
    db.commit()
    return _definition_out(d, _latest_version(db, d.id))


def list_definitions(
    db: Session, p: Principal, *, include_archived: bool
) -> list[WorkflowDefinitionOut]:
    stmt = select(WorkflowDefinition).where(WorkflowDefinition.organization_id == p.organization_id)
    if not (include_archived and p.is_admin):
        stmt = stmt.where(WorkflowDefinition.archived_at.is_(None))
    return [
        _definition_out(d, _latest_version(db, d.id))
        for d in db.scalars(stmt.order_by(WorkflowDefinition.name))
    ]


# ------------------------------------------------------------------ internals
def _log(
    db: Session,
    run: WorkflowRun,
    action: str,
    actor_id: uuid.UUID | None,
    *,
    task_id: uuid.UUID | None = None,
    comment: str | None = None,
    **meta: Any,
) -> None:
    db.add(
        ApprovalAction(
            id=uuid.uuid4(),
            organization_id=run.organization_id,
            run_id=run.id,
            task_id=task_id,
            action=action,
            actor_id=actor_id,
            comment=comment,
            action_metadata=meta,
        )
    )


def _active_user_ids(db: Session, org_id: uuid.UUID, ids: set[uuid.UUID]) -> set[uuid.UUID]:
    if not ids:
        return set()
    return set(
        db.scalars(
            select(Membership.user_id)
            .join(User, User.id == Membership.user_id)
            .where(
                Membership.organization_id == org_id,
                Membership.user_id.in_(ids),
                Membership.status == MembershipStatus.ACTIVE.value,
                User.status == UserStatus.ACTIVE.value,
            )
        )
    )


def _resolve_assignees(
    db: Session, org_id: uuid.UUID, step: dict[str, Any], exclude: uuid.UUID
) -> list[tuple[uuid.UUID, bool, bool]]:
    """(user, optional, super approver) for everyone the step resolves to. A person matched by several
    assignee entries is optional/super if ANY entry says so (same merge rule as signature chains)."""
    flags: dict[uuid.UUID, list[bool]] = {}

    def add(users: Iterable[uuid.UUID], a: dict[str, Any]) -> None:
        for uid in users:
            cur = flags.setdefault(uid, [False, False])
            cur[0] = cur[0] or bool(a.get("optional"))
            cur[1] = cur[1] or bool(a.get("is_super_approver"))

    for a in step["assignees"]:
        if a["type"] == "user":
            add([uuid.UUID(a["id"])], a)
        elif a["type"] == "group":
            add(
                db.scalars(
                    select(GroupMembership.user_id).where(
                        GroupMembership.group_id == uuid.UUID(a["id"]),
                        GroupMembership.organization_id == org_id,
                    )
                ),
                a,
            )
        else:
            add(
                db.scalars(
                    select(Membership.user_id).where(
                        Membership.organization_id == org_id,
                        Membership.role == a["role"],
                        Membership.status == MembershipStatus.ACTIVE.value,
                    )
                ),
                a,
            )
    eligible = _active_user_ids(db, org_id, set(flags)) - {exclude}
    return [(uid, flags[uid][0], flags[uid][1]) for uid in sorted(eligible, key=str)]


def _condition_true(cond: dict[str, Any] | None, doc: Document, version: DocumentVersion) -> bool:
    if not cond:
        return True
    f, op, expected = cond["field"], cond["op"], cond["value"]
    actual: Any
    if f == "classification":
        actual = doc.classification
    elif f == "size_bytes":
        actual = version.size_bytes
    elif f == "content_type":
        actual = version.content_type
    else:
        actual = (doc.custom_metadata or {}).get(cond["key"])
    try:
        return {
            "eq": lambda: actual == expected,
            "neq": lambda: actual != expected,
            "gt": lambda: actual > expected,
            "gte": lambda: actual >= expected,
            "lt": lambda: actual < expected,
            "lte": lambda: actual <= expected,
            "in": lambda: actual in expected,
        }[op]()
    except TypeError:
        return False  # incomparable (e.g. missing metadata) -> condition not met


def _steps_of(db: Session, run: WorkflowRun) -> list[dict[str, Any]]:
    v = db.get(WorkflowDefinitionVersion, run.definition_version_id)
    assert v is not None
    return v.steps


def _finish(
    db: Session, run: WorkflowRun, state: str, comment: str | None, actor_id: uuid.UUID | None
) -> None:
    run.state = state
    run.completed_at = datetime.now(UTC)
    run.outcome_comment = comment
    for t in db.scalars(
        select(WorkflowTask).where(WorkflowTask.run_id == run.id, WorkflowTask.status == "pending")
    ):
        t.status = "cancelled"
    _log(db, run, f"run_{state}", actor_id, comment=comment)
    audit.record(
        db,
        organization_id=run.organization_id,
        actor_user_id=actor_id,
        action=f"workflow.{state}",
        resource_type="document",
        resource_id=run.document_id,
        outcome=AuditOutcome.SUCCESS,
        metadata={"run_id": str(run.id)},
    )
    outbox.enqueue(
        db,
        organization_id=run.organization_id,
        event_type="workflow.finished",
        aggregate_type="workflow_run",
        aggregate_id=run.id,
        payload={"state": state},
    )


def _activate_from(db: Session, run: WorkflowRun, start: int) -> None:
    """Activate the first applicable step at or after ``start`` or complete the run."""
    steps = _steps_of(db, run)
    doc = db.get(Document, run.document_id)
    version = db.get(DocumentVersion, run.document_version_id)
    assert doc is not None and version is not None
    for idx in range(start, len(steps)):
        step = steps[idx]
        if not _condition_true(step.get("condition"), doc, version):
            _log(
                db,
                run,
                "step_skipped",
                None,
                step=idx,
                name=step["name"],
                reason="condition_not_met",
            )
            continue
        assignees = _resolve_assignees(db, run.organization_id, step, run.started_by)
        run.current_step = idx
        if not assignees:
            _log(
                db,
                run,
                "step_failed",
                None,
                step=idx,
                name=step["name"],
                reason="no_eligible_approvers",
            )
            _finish(db, run, "rejected", f"No eligible approver for step '{step['name']}'.", None)
            return
        due = datetime.now(UTC) + timedelta(days=step["due_days"]) if step.get("due_days") else None
        for uid, optional, super_approver in assignees:
            task = WorkflowTask(
                id=uuid.uuid4(),
                organization_id=run.organization_id,
                run_id=run.id,
                document_id=run.document_id,
                step_index=idx,
                step_name=step["name"],
                rule=step.get("rule", "all"),
                assignee_id=uid,
                optional=optional,
                is_super_approver=super_approver,
                due_at=due,
                escalate_to_id=uuid.UUID(step["escalate_to_user_id"])
                if step.get("escalate_to_user_id")
                else None,
            )
            db.add(task)
            db.flush()
            outbox.enqueue(
                db,
                organization_id=run.organization_id,
                event_type="workflow.task_assigned",
                aggregate_type="workflow_task",
                aggregate_id=task.id,
                payload={"run_id": str(run.id)},
            )
        _log(db, run, "step_started", None, step=idx, name=step["name"], assignees=len(assignees))
        return
    run.current_step = len(steps)
    _finish(db, run, "approved", None, None)


# --------------------------------------------------------------------- runs
def start_run(
    db: Session,
    authz: AuthorizationService,
    document_id: uuid.UUID,
    definition_id: uuid.UUID,
    note: str | None,
) -> RunOut:
    p = authz.principal
    doc = authz.require_document(document_id, Action.EDIT_METADATA)
    if doc.status != DocumentStatus.AVAILABLE.value or doc.current_version_id is None:
        raise ConflictError(
            "Only available documents can be submitted for approval.", code="not_available"
        )
    d = db.scalar(
        select(WorkflowDefinition).where(
            WorkflowDefinition.id == definition_id,
            WorkflowDefinition.organization_id == p.organization_id,
            WorkflowDefinition.archived_at.is_(None),
        )
    )
    if d is None:
        raise NotFoundError("Workflow not found.")
    dv = _latest_version(db, d.id)
    run = WorkflowRun(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        definition_version_id=dv.id,
        document_id=doc.id,
        document_version_id=doc.current_version_id,
        started_by=p.user_id,
        note=note,
    )
    db.add(run)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError(
            "This document already has an approval in progress.", code="run_in_progress"
        ) from exc
    _log(
        db,
        run,
        "submitted",
        p.user_id,
        comment=note,
        definition=d.name,
        definition_version=dv.version_number,
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="workflow.started",
        resource_type="document",
        resource_id=doc.id,
        metadata={
            "run_id": str(run.id),
            "definition": d.name,
            "version": dv.version_number,
            "document_version_id": str(run.document_version_id),
        },
    )
    _activate_from(db, run, 0)
    if run.state == "rejected" and not db.scalar(
        select(WorkflowTask.id).where(WorkflowTask.run_id == run.id)
    ):
        # fail closed at submission time: tell the submitter instead of creating a dead run
        db.rollback()
        raise ValidationFailed("The first step has no eligible approvers.", code="no_approvers")
    db.commit()
    return get_run(db, authz, run.id)


def cancel_run(db: Session, p: Principal, run_id: uuid.UUID, comment: str | None) -> None:
    run = db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == run_id, WorkflowRun.organization_id == p.organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if run is None or not (run.started_by == p.user_id or p.is_admin):
        raise NotFoundError("Approval not found.")
    if run.state != "in_progress":
        raise ConflictError(f"The approval is already {run.state}.", code="run_closed")
    _finish(db, run, "cancelled", comment, p.user_id)
    db.commit()


def cancel_runs_for_document(
    db: Session, document_id: uuid.UUID, org_id: uuid.UUID, actor_id: uuid.UUID | None
) -> None:
    """System hook: a document sent to the trash cannot stay under approval."""
    for run in db.scalars(
        select(WorkflowRun)
        .where(
            WorkflowRun.document_id == document_id,
            WorkflowRun.organization_id == org_id,
            WorkflowRun.state == "in_progress",
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ):
        _finish(db, run, "cancelled", "Document was deleted.", actor_id)


def resubmit(
    db: Session, authz: AuthorizationService, run_id: uuid.UUID, note: str | None
) -> RunOut:
    p = authz.principal
    old = db.scalar(
        select(WorkflowRun).where(
            WorkflowRun.id == run_id, WorkflowRun.organization_id == p.organization_id
        )
    )
    if old is None or not (old.started_by == p.user_id or p.is_admin):
        raise NotFoundError("Approval not found.")
    if old.state != "rejected":
        raise ConflictError("Only rejected approvals can be resubmitted.", code="invalid_state")
    dv = db.get(WorkflowDefinitionVersion, old.definition_version_id)
    assert dv is not None
    definition = db.get(WorkflowDefinition, dv.definition_id)
    if definition is None or definition.archived_at is not None:
        raise ConflictError("The workflow is no longer available.", code="workflow_archived")
    new = start_run(db, authz, old.document_id, definition.id, note or old.note)
    db_run = db.get(WorkflowRun, new.id)
    assert db_run is not None
    db_run.resubmitted_from_run_id = old.id
    _log(db, db_run, "resubmitted", p.user_id, previous_run=str(old.id))
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="workflow.resubmitted",
        resource_type="document",
        resource_id=old.document_id,
        metadata={"run_id": str(db_run.id), "previous": str(old.id)},
    )
    db.commit()
    return get_run(db, authz, new.id)


# -------------------------------------------------------------------- tasks
def _lock_task_and_run(
    db: Session, p: Principal, task_id: uuid.UUID
) -> tuple[WorkflowTask, WorkflowRun]:
    """Lock order is always run -> task so concurrent decisions in one step cannot deadlock.
    Only the assignee may touch a task; everyone else gets the same 404 as for a missing task."""
    probe = db.scalar(
        select(WorkflowTask).where(
            WorkflowTask.id == task_id, WorkflowTask.organization_id == p.organization_id
        )
    )
    if probe is None or probe.assignee_id != p.user_id:
        raise NotFoundError("Task not found.")
    run = db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == probe.run_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    task = db.scalar(
        select(WorkflowTask)
        .where(WorkflowTask.id == task_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    assert run is not None and task is not None
    if task.assignee_id != p.user_id:  # re-checked under the lock (e.g. delegated meanwhile)
        raise NotFoundError("Task not found.")
    return task, run


def decide(
    db: Session, p: Principal, task_id: uuid.UUID, decision: str, comment: str | None
) -> TaskOut:
    task, run = _lock_task_and_run(db, p, task_id)
    target = "approved" if decision == "approve" else "rejected"
    if task.status != "pending":
        if task.status == target and task.decided_by == p.user_id:
            return _task_out(db, [task])[0]  # idempotent repeat (double click / retry)
        raise ConflictError(f"This task is already {task.status}.", code="task_closed")
    if run.state != "in_progress":
        raise ConflictError("This approval is no longer active.", code="run_closed")
    doc = db.scalar(
        select(Document).where(
            Document.id == run.document_id, Document.organization_id == p.organization_id
        )
    )
    if doc is None or doc.deleted_at is not None:
        raise ConflictError("The document is no longer available.", code="not_available")

    task.status, task.decided_by, task.decided_at, task.comment = (
        target,
        p.user_id,
        datetime.now(UTC),
        comment,
    )
    _log(
        db, run, f"task_{target}", p.user_id, task_id=task.id, comment=comment, step=task.step_index
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=f"workflow.task_{target}",
        resource_type="document",
        resource_id=run.document_id,
        metadata={"run_id": str(run.id), "task_id": str(task.id), "step": task.step_index},
    )
    db.flush()
    siblings = list(
        db.scalars(
            select(WorkflowTask).where(
                WorkflowTask.run_id == run.id, WorkflowTask.step_index == task.step_index
            )
        )
    )
    pending = [t for t in siblings if t.status == "pending"]
    approved = [t for t in siblings if t.status == "approved"]

    step_done = step_failed = False
    if target == "approved" and task.is_super_approver:
        # A super approver fast-forwards: everyone still pending (this step and later ones) is skipped
        # and the document is approved at once.
        bypassed = list(
            db.scalars(
                select(WorkflowTask).where(
                    WorkflowTask.run_id == run.id, WorkflowTask.status == "pending"
                )
            )
        )
        for t in bypassed:
            t.status, t.comment = (
                "skipped",
                "Bypassed - a super-approver approved and fast-forwarded the remaining chain",
            )
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="workflow.chain_override",
            resource_type="document",
            resource_id=run.document_id,
            metadata={"run_id": str(run.id), "step": task.step_index, "bypassed": len(bypassed)},
        )
        _log(db, run, "chain_override", p.user_id, step=task.step_index, bypassed=len(bypassed))
        run.current_step = len(_steps_of(db, run))
        _finish(db, run, "approved", comment, p.user_id)
        db.commit()
        return _task_out(db, [task])[0]
    if task.rule == "any":
        if target == "approved":
            step_done = True
            for t in pending:
                t.status = "skipped"
        elif not pending and not approved:
            step_failed = True
    else:
        required = [t for t in siblings if not t.optional]
        if target == "rejected" and not task.optional:
            step_failed = True  # a required approver rejected: the chain halts
        elif not pending and not approved:
            step_failed = True  # nobody is left who could approve
        elif required:
            step_done = not any(t.status == "pending" for t in required)
        else:  # a step of optional approvers only needs one approval
            step_done = bool(approved)
        if step_done:
            for t in pending:  # optional approvers still pending are no longer needed
                t.status = "skipped"

    if step_failed:
        _finish(db, run, "rejected", comment, p.user_id)
    elif step_done:
        _log(db, run, "step_completed", None, step=task.step_index)
        _activate_from(db, run, task.step_index + 1)
    db.commit()
    return _task_out(db, [task])[0]


def delegate(
    db: Session,
    p: Principal,
    task_id: uuid.UUID,
    *,
    user_id: uuid.UUID | None,
    email: str | None,
    comment: str | None,
) -> TaskOut:
    task, run = _lock_task_and_run(db, p, task_id)
    if task.status != "pending":
        raise ConflictError(f"This task is already {task.status}.", code="task_closed")
    stmt = (
        select(User.id)
        .join(Membership, Membership.user_id == User.id)
        .where(
            Membership.organization_id == p.organization_id,
            Membership.status == MembershipStatus.ACTIVE.value,
            User.status == UserStatus.ACTIVE.value,
        )
    )
    stmt = (
        stmt.where(User.id == user_id)
        if user_id
        else stmt.where(User.email == (email or "").strip().lower())
    )
    target = db.scalar(stmt)
    if target is None:
        raise ValidationFailed(
            "The delegate must be an active member of this organization.", code="unknown_recipient"
        )
    if target in (p.user_id, run.started_by):
        raise ValidationFailed(
            "You cannot delegate to yourself or to the person who submitted the document.",
            code="invalid_delegate",
        )
    already = db.scalar(
        select(WorkflowTask.id).where(
            WorkflowTask.run_id == run.id,
            WorkflowTask.step_index == task.step_index,
            WorkflowTask.assignee_id == target,
            WorkflowTask.status == "pending",
        )
    )
    if already:
        raise ConflictError(
            "That person already has a pending task in this step.", code="duplicate_assignee"
        )
    task.delegated_from_id, task.assignee_id = p.user_id, target
    _log(db, run, "delegated", p.user_id, task_id=task.id, comment=comment, to=str(target))
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="workflow.task_delegated",
        resource_type="document",
        resource_id=run.document_id,
        metadata={"run_id": str(run.id), "task_id": str(task.id), "to": str(target)},
    )
    outbox.enqueue(
        db,
        organization_id=p.organization_id,
        event_type="workflow.task_assigned",
        aggregate_type="workflow_task",
        aggregate_id=task.id,
        payload={"run_id": str(run.id), "delegated": True},
    )
    db.commit()
    return _task_out(db, [task])[0]


# ----------------------------------------------------------------- read models
def _users(db: Session, ids: Iterable[uuid.UUID | None]) -> dict[uuid.UUID, User]:
    real = {i for i in ids if i}
    return {u.id: u for u in db.scalars(select(User).where(User.id.in_(real)))} if real else {}


def _ref(users: dict[uuid.UUID, User], uid: uuid.UUID | None) -> UserRef | None:
    if uid is None:
        return None
    u = users.get(uid)
    return UserRef(id=uid, display_name=u.display_name if u else None, email=u.email if u else None)


def _task_out(
    db: Session, tasks: list[WorkflowTask], *, with_context: bool = False
) -> list[TaskOut]:
    users = _users(db, [*(t.assignee_id for t in tasks), *(t.delegated_from_id for t in tasks)])
    docs = {
        d.id: d
        for d in db.scalars(
            select(Document).where(
                Document.id.in_({t.document_id for t in tasks} or {uuid.UUID(int=0)})
            )
        )
    }
    runs: dict[uuid.UUID, WorkflowRun] = {}
    versions: dict[uuid.UUID, DocumentVersion] = {}
    if with_context:
        runs = {
            r.id: r
            for r in db.scalars(
                select(WorkflowRun).where(
                    WorkflowRun.id.in_({t.run_id for t in tasks} or {uuid.UUID(int=0)})
                )
            )
        }
        versions = {
            v.id: v
            for v in db.scalars(
                select(DocumentVersion).where(
                    DocumentVersion.id.in_(
                        {r.document_version_id for r in runs.values()} or {uuid.UUID(int=0)}
                    )
                )
            )
        }
        users.update(_users(db, {r.started_by for r in runs.values()}))
    now = datetime.now(UTC)
    out: list[TaskOut] = []
    for t in tasks:
        run = runs.get(t.run_id)
        out.append(
            TaskOut(
                id=t.id,
                run_id=t.run_id,
                document_id=t.document_id,
                document_name=docs[t.document_id].name if t.document_id in docs else None,
                step_index=t.step_index,
                step_name=t.step_name,
                rule=t.rule,  # type: ignore[arg-type]
                assignee=_ref(users, t.assignee_id),  # type: ignore[arg-type]
                delegated_from=_ref(users, t.delegated_from_id),
                status=t.status,  # type: ignore[arg-type]
                due_at=t.due_at,
                overdue=bool(t.status == "pending" and t.due_at and t.due_at < now),
                decided_at=t.decided_at,
                comment=t.comment,
                run_state=run.state if run else None,  # type: ignore[arg-type]
                document_version_number=versions[run.document_version_id].version_number
                if run and run.document_version_id in versions
                else None,
                started_by=_ref(users, run.started_by) if run else None,
                note=run.note if run else None,
                optional=t.optional,
                is_super_approver=t.is_super_approver,
            )
        )
    return out


def list_my_tasks(
    db: Session, p: Principal, *, status: str | None, limit: int, offset: int
) -> tuple[list[TaskOut], int]:
    stmt = select(WorkflowTask).where(
        WorkflowTask.organization_id == p.organization_id, WorkflowTask.assignee_id == p.user_id
    )
    if status:
        stmt = stmt.where(WorkflowTask.status == status)
    tasks = list(db.scalars(stmt.order_by(WorkflowTask.created_at.desc())))
    # hide tasks whose document no longer exists / is trashed (cannot be reviewed)
    live = set(
        db.scalars(
            select(Document.id).where(
                Document.id.in_({t.document_id for t in tasks} or {uuid.UUID(int=0)}),
                Document.deleted_at.is_(None),
            )
        )
    )
    tasks = [t for t in tasks if t.document_id in live or t.status != "pending"]
    return _task_out(db, tasks[offset : offset + limit], with_context=True), len(tasks)


def get_task(db: Session, authz: AuthorizationService, task_id: uuid.UUID) -> TaskOut:
    p = authz.principal
    task = db.scalar(
        select(WorkflowTask).where(
            WorkflowTask.id == task_id, WorkflowTask.organization_id == p.organization_id
        )
    )
    run = db.get(WorkflowRun, task.run_id) if task else None
    if (
        task is None
        or run is None
        or not (task.assignee_id == p.user_id or _can_see_run(db, authz, run))
    ):
        raise NotFoundError("Task not found.")  # same answer for 'missing' and 'not yours'
    return _task_out(db, [task], with_context=True)[0]


def _can_see_run(db: Session, authz: AuthorizationService, run: WorkflowRun) -> bool:
    p = authz.principal
    if p.is_admin or run.started_by == p.user_id:
        return True
    if db.scalar(
        select(WorkflowTask.id)
        .where(WorkflowTask.run_id == run.id, WorkflowTask.assignee_id == p.user_id)
        .limit(1)
    ):
        return True
    doc = authz.load_document(run.document_id, include_deleted=True)
    return doc is not None and Action.VIEW.value in authz.document_actions([doc])[doc.id]


def get_run(db: Session, authz: AuthorizationService, run_id: uuid.UUID) -> RunOut:
    p = authz.principal
    run = db.scalar(
        select(WorkflowRun).where(
            WorkflowRun.id == run_id, WorkflowRun.organization_id == p.organization_id
        )
    )
    if run is None or not _can_see_run(db, authz, run):
        raise NotFoundError("Approval not found.")
    return _run_out(db, run)


def _run_out(db: Session, run: WorkflowRun) -> RunOut:
    dv = db.get(WorkflowDefinitionVersion, run.definition_version_id)
    assert dv is not None
    definition = db.get(WorkflowDefinition, dv.definition_id)
    doc = db.get(Document, run.document_id)
    version = db.get(DocumentVersion, run.document_version_id)
    tasks = list(
        db.scalars(
            select(WorkflowTask)
            .where(WorkflowTask.run_id == run.id)
            .order_by(WorkflowTask.step_index, WorkflowTask.created_at)
        )
    )
    actions = list(
        db.scalars(
            select(ApprovalAction)
            .where(ApprovalAction.run_id == run.id)
            .order_by(ApprovalAction.created_at)
        )
    )
    users = _users(db, [run.started_by, *(a.actor_id for a in actions)])
    by_step: dict[int, list[WorkflowTask]] = {}
    for t in tasks:
        by_step.setdefault(t.step_index, []).append(t)
    skipped_steps = {a.action_metadata.get("step") for a in actions if a.action == "step_skipped"}
    steps_out: list[StepStatusOut] = []
    for i, s in enumerate(dv.steps):
        ts = by_step.get(i, [])
        if i in skipped_steps:
            status = "skipped"
        elif not ts:
            status = "upcoming"
        elif any(t.status == "pending" for t in ts):
            status = "active"
        elif any(t.status == "rejected" for t in ts) and not any(
            t.status == "approved" for t in ts
        ):
            status = "rejected"
        elif any(t.status == "approved" for t in ts):
            status = "approved"
        else:
            status = "upcoming" if run.state == "in_progress" else "skipped"
        steps_out.append(
            StepStatusOut(index=i, name=s["name"], rule=s.get("rule", "all"), status=status)
        )  # type: ignore[arg-type]
    return RunOut(
        id=run.id,
        document_id=run.document_id,
        document_name=doc.name if doc else None,
        document_version_id=run.document_version_id,
        document_version_number=version.version_number if version else 0,
        definition_name=definition.name if definition else None,
        definition_version=dv.version_number,
        state=run.state,
        current_step=run.current_step,
        started_by=_ref(users, run.started_by),  # type: ignore[arg-type]
        note=run.note,
        outcome_comment=run.outcome_comment,
        created_at=run.created_at,
        completed_at=run.completed_at,
        resubmitted_from_run_id=run.resubmitted_from_run_id,
        steps=steps_out,
        tasks=_task_out(db, tasks),
        actions=[
            ActionOut(
                id=a.id,
                action=a.action,
                actor=_ref(users, a.actor_id),
                comment=a.comment,
                task_id=a.task_id,
                created_at=a.created_at,
                metadata=a.action_metadata or {},
            )
            for a in actions
        ],
    )


def list_runs_for_document(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID
) -> list[RunOut]:
    doc = authz.require_document(document_id, Action.VIEW)
    runs = db.scalars(
        select(WorkflowRun)
        .where(
            WorkflowRun.document_id == doc.id, WorkflowRun.organization_id == doc.organization_id
        )
        .order_by(WorkflowRun.created_at.desc())
    )
    return [_run_out(db, r) for r in runs]


# ----------------------------------------------------------------- maintenance
def process_overdue_tasks(db: Session, limit: int = 200) -> int:
    """Notify (once) about overdue tasks, including the configured escalation contact."""
    now = datetime.now(UTC)
    tasks = list(
        db.scalars(
            select(WorkflowTask)
            .where(
                and_(
                    WorkflowTask.status == "pending",
                    WorkflowTask.due_at.is_not(None),
                    WorkflowTask.due_at < now,
                    WorkflowTask.overdue_notified_at.is_(None),
                )
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
    )
    for t in tasks:
        t.overdue_notified_at = now
        audit.record(
            db,
            organization_id=t.organization_id,
            actor_user_id=None,
            action="workflow.task_overdue",
            resource_type="document",
            resource_id=t.document_id,
            metadata={"task_id": str(t.id), "run_id": str(t.run_id)},
        )
        outbox.enqueue(
            db,
            organization_id=t.organization_id,
            event_type="workflow.task_overdue",
            aggregate_type="workflow_task",
            aggregate_id=t.id,
            payload={"run_id": str(t.run_id)},
        )
    db.commit()
    return len(tasks)
