"""Run history, dry-run test, retry and cancel (administrators only, tenant scoped)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.models import (
    Automation,
    AutomationNodeRun,
    AutomationRun,
    AutomationVersion,
    Document,
    DocumentVersion,
    Folder,
)
from app.modules.audit import service as audit
from app.modules.automations import engine, triggers
from app.modules.automations.registry import ACTIONS, CONDITIONS
from app.modules.automations.service import get_or_404, require_admin
from app.modules.identity.principal import Principal
from app.schemas.automations import AutomationRunOut, NodeRunOut


def _run_out(db: Session, run: AutomationRun, *, with_nodes: bool) -> AutomationRunOut:
    version = db.get(AutomationVersion, run.version_id)
    a = db.get(Automation, run.automation_id)
    nodes: list[NodeRunOut] = []
    if with_nodes:
        for nr in db.scalars(
            select(AutomationNodeRun)
            .where(AutomationNodeRun.run_id == run.id)
            .order_by(AutomationNodeRun.started_at.nulls_last())
        ):
            spec = ACTIONS.get(nr.node_type)
            nodes.append(
                NodeRunOut(
                    node_id=nr.node_id,
                    node_type=nr.node_type,
                    label=spec.label if spec else nr.node_type,
                    status=nr.status,  # type: ignore[arg-type]
                    attempts=nr.attempts,
                    output=nr.output or {},
                    error=nr.error,
                    started_at=nr.started_at,
                    finished_at=nr.finished_at,
                )
            )
    return AutomationRunOut(
        id=run.id,
        automation_id=run.automation_id,
        automation_name=a.name if a else None,
        version_number=version.version_number if version else None,
        status=run.status,  # type: ignore[arg-type]
        mode=run.mode,  # type: ignore[arg-type]
        event_key=run.event_key,
        trigger_context=run.trigger_context or {},
        error=run.error,
        correlation_id=run.correlation_id,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        nodes=nodes,
    )


def list_runs(
    db: Session, p: Principal, automation_id: uuid.UUID, *, limit: int, offset: int
) -> tuple[list[AutomationRunOut], int]:
    get_or_404(db, p, automation_id)
    stmt = select(AutomationRun).where(
        AutomationRun.automation_id == automation_id,
        AutomationRun.organization_id == p.organization_id,
    )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(AutomationRun.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return [_run_out(db, r, with_nodes=False) for r in rows], int(total)


def get_run(db: Session, p: Principal, run_id: uuid.UUID) -> AutomationRunOut:
    require_admin(p)
    run = db.scalar(
        select(AutomationRun).where(
            AutomationRun.id == run_id, AutomationRun.organization_id == p.organization_id
        )
    )
    if run is None:
        raise NotFoundError("Run not found.")
    return _run_out(db, run, with_nodes=True)


def retry(db: Session, p: Principal, run_id: uuid.UUID) -> AutomationRunOut:
    require_admin(p)
    run = db.scalar(
        select(AutomationRun)
        .where(AutomationRun.id == run_id, AutomationRun.organization_id == p.organization_id)
        .with_for_update()
    )
    if run is None:
        raise NotFoundError("Run not found.")
    if run.status != "failed" or run.mode != "live":
        raise ConflictError("Only failed live runs can be retried.", code="not_retryable")
    engine.retry_run(db, run)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.run_retried",
        resource_type="automation",
        resource_id=run.automation_id,
        metadata={"run_id": str(run.id)},
    )
    from app.modules.outbox import service as outbox

    outbox.enqueue(
        db,
        organization_id=p.organization_id,
        event_type="automation.run",
        aggregate_type="automation_run",
        aggregate_id=run.id,
    )
    db.commit()
    return _run_out(db, run, with_nodes=True)


def cancel(db: Session, p: Principal, run_id: uuid.UUID) -> AutomationRunOut:
    require_admin(p)
    run = db.scalar(
        select(AutomationRun)
        .where(AutomationRun.id == run_id, AutomationRun.organization_id == p.organization_id)
        .with_for_update()
    )
    if run is None:
        raise NotFoundError("Run not found.")
    if run.status not in ("queued", "waiting", "running"):
        raise ConflictError("This run has already finished.", code="not_cancellable")
    run.status = "cancelled"
    run.error = "Cancelled by an administrator."
    from datetime import UTC, datetime

    run.finished_at = datetime.now(UTC)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.run_cancelled",
        resource_type="automation",
        resource_id=run.automation_id,
        metadata={"run_id": str(run.id)},
    )
    db.commit()
    return _run_out(db, run, with_nodes=True)


def dry_run(
    db: Session,
    factory: sessionmaker[Session],
    p: Principal,
    automation_id: uuid.UUID,
    resource_id: uuid.UUID | None,
) -> dict[str, Any]:
    """Evaluate the DRAFT against one real item and walk the graph without side effects.

    Conditions and variable assignments really evaluate; every other step reports what it
    would do. Nothing is sent, copied, moved, deleted or granted."""
    a = get_or_404(db, p, automation_id)
    spec = CONDITIONS.get(a.draft_trigger.get("key", ""))
    if spec is None or not spec.supported:
        raise ValidationFailed("The condition of this workflow is not supported.")
    from app.modules.automations.service import validate_saved

    report = validate_saved(db, p, a.id)
    if not report.valid:
        raise ValidationFailed(
            report.issues[0].message,
            code="invalid_workflow",
            details={"issues": [i.model_dump() for i in report.issues]},
        )
    org = p.organization_id
    ctx_stored: tuple[dict[str, Any], dict[str, Any]] | None
    if spec.kind == "timer":
        ctx_stored = ({"event": {"action": "timer"}}, {"event": "timer"})
    else:
        if resource_id is None:
            raise ValidationFailed(
                "Pick a file, folder or user to test against.", code="resource_required"
            )
        ctx_stored = _resolve(db, org, resource_id)
        if ctx_stored is None:
            raise NotFoundError("That item was not found.")
    ctx, stored = ctx_stored
    params = a.draft_trigger.get("params") or {}
    matches = triggers.condition_matches(spec, params, ctx) if spec.kind != "timer" else True
    # A dry run executes an in-memory copy of the DRAFT stored on the run row; no version is created.
    with factory() as s2:
        a2 = s2.get(Automation, a.id)
        assert a2 is not None
        run_id = uuid.uuid4()
        s2.add(
            AutomationRun(
                id=run_id,
                organization_id=org,
                automation_id=a.id,
                version_id=a.published_version_id or uuid.uuid4(),
                event_key=f"dry:{run_id}",
                status="queued",
                mode="dry",
                trigger_context=stored,
                variables={},
                snapshot={
                    "trigger": a.draft_trigger,
                    "graph": a.draft_graph,
                    "as_user": str(p.user_id),
                },
                correlation_id=uuid.uuid4().hex[:16],
            )
        )
        s2.commit()
    status = engine.execute_run(factory, run_id)
    result = get_run(db, p, run_id)
    return {"would_trigger": matches, "status": status, "run": result}


def _resolve(
    db: Session, org: uuid.UUID, rid: uuid.UUID
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    doc = db.scalar(select(Document).where(Document.id == rid, Document.organization_id == org))
    if doc is not None:
        ver = db.get(DocumentVersion, doc.current_version_id) if doc.current_version_id else None
        ctx = {
            "event": {"action": "test"},
            "actor": {"email": ""},
            **triggers.file_context(db, org, doc, ver),
        }
        return ctx, {
            "event": "test",
            "resource": {"type": "document", "id": str(doc.id), "name": doc.name},
        }
    folder = db.scalar(select(Folder).where(Folder.id == rid, Folder.organization_id == org))
    if folder is not None:
        ctx = {
            "event": {"action": "test"},
            "actor": {"email": ""},
            "folder": {"name": folder.name, "path": triggers._path_of(db, org, folder.id)},
        }
        return ctx, {
            "event": "test",
            "resource": {"type": "folder", "id": str(folder.id), "name": folder.name},
        }
    return triggers.user_context(db, org, rid)
