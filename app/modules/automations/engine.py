"""Durable execution of one run.

Properties the design relies on (and the tests exercise):
  * **Re-authorization at every step.** Before each node the publisher's principal is rebuilt from
    current database state (``principal_for`` fails closed): a suspended/removed publisher, a
    revoked ACL or a disabled workflow stops the *next* side effect.
  * **Idempotent nodes.** A node already ``succeeded``/``skipped`` is never executed again; a
    redelivered or retried run resumes after the last finished node.
  * **Bounded retries.** An unexpected error is re-raised so the outbox retries with backoff; after
    ``MAX_ATTEMPTS`` the node and run fail visibly. A deliberate refusal (``ActionFailed``) fails
    the node immediately and is not retried.
  * **Waiting.** ``wait_for_approval`` parks the run; ``resume_waiting`` (maintenance) wakes it when
    the approval is decided.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.errors import AppError, ForbiddenError
from app.core.logging import get_logger
from app.db.enums import AuditOutcome
from app.db.models import Automation, AutomationNodeRun, AutomationRun, AutomationVersion
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.automations import actions
from app.modules.automations.registry import ACTIONS
from app.modules.identity.service import principal_for

log = get_logger("app.automations")

MAX_ATTEMPTS = 3
MAX_STEPS = 60


def _finish(
    db: Session, run: AutomationRun, a: Automation, status: str, error: str | None = None
) -> None:
    now = datetime.now(UTC)
    run.status = status
    run.error = (error or None) and error[:500]
    run.finished_at = now
    if run.mode == "live":
        a.last_run_at = now
        a.last_run_status = status
        a.last_run_summary = (error or f"Run {status}")[:300]
        audit.record(
            db,
            organization_id=run.organization_id,
            actor_user_id=None,
            action="automation.run_finished",
            resource_type="automation",
            resource_id=a.id,
            outcome=AuditOutcome.SUCCESS
            if status in ("succeeded", "skipped")
            else AuditOutcome.FAILURE,
            metadata={"run_id": str(run.id), "status": status},
        )


def _edges(graph: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for e in graph.get("edges", []):
        out.setdefault(e["from"], []).append(e)
    return out


def execute_run(factory: sessionmaker[Session], run_id: uuid.UUID) -> str:
    """Run (or resume) one run to completion, failure, or a waiting state. Returns its status."""
    with factory() as db:
        run = db.scalar(
            select(AutomationRun)
            .where(AutomationRun.id == run_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if run is None or run.status in ("succeeded", "failed", "cancelled", "skipped"):
            return run.status if run else "missing"
        a = db.get(Automation, run.automation_id)
        dry = run.mode == "dry"
        version: AutomationVersion | None
        if dry and run.snapshot:
            version = AutomationVersion(
                id=run.version_id,
                organization_id=run.organization_id,
                automation_id=run.automation_id,
                version_number=0,
                trigger=run.snapshot["trigger"],
                graph=run.snapshot["graph"],
                published_by=uuid.UUID(run.snapshot["as_user"]),
            )
        else:
            version = db.get(AutomationVersion, run.version_id)
        assert a is not None and version is not None
        if run.started_at is None:
            run.started_at = datetime.now(UTC)
        run.status = "running"
        db.commit()

        graph = version.graph
        nodes = {n["id"]: n for n in graph["nodes"]}
        edges = _edges(graph)
        current = next((e["to"] for e in edges.get(_start(graph), [])), None)
        steps = 0
        ctx_stored = run.trigger_context or {}
        expr_ctx = _rebuild_context(db, run, ctx_stored)

        while current is not None and steps < MAX_STEPS:
            steps += 1
            node = nodes[current]
            if node["type"] == "end":
                break
            db.refresh(a)
            if not dry and not a.enabled:
                _finish(
                    db,
                    run,
                    a,
                    "cancelled",
                    "The workflow was disabled while this run was in progress.",
                )
                db.commit()
                return "cancelled"

            nr = db.scalar(
                select(AutomationNodeRun).where(
                    AutomationNodeRun.run_id == run.id, AutomationNodeRun.node_id == node["id"]
                )
            )
            if nr is None:
                nr = AutomationNodeRun(
                    id=uuid.uuid4(),
                    organization_id=run.organization_id,
                    run_id=run.id,
                    node_id=node["id"],
                    node_type=node["type"],
                    status="pending",
                    output={},
                )
                db.add(nr)
                db.flush()
            if nr.status in ("succeeded", "skipped"):
                current = _next(nr.output.get("branch"), edges.get(current, []))
                continue

            # ---- re-authorize as the publisher against CURRENT state
            try:
                principal = principal_for(db, version.published_by, run.organization_id)  # type: ignore[arg-type]
                authz = AuthorizationService(db, principal)
            except (ForbiddenError, AttributeError):
                nr.status, nr.error = (
                    "failed",
                    "The person who published this workflow no longer has access.",
                )
                nr.finished_at = datetime.now(UTC)
                _finish(db, run, a, "failed", nr.error)
                db.commit()
                return "failed"

            nr.attempts += 1
            nr.status = "running"
            nr.started_at = nr.started_at or datetime.now(UTC)
            db.commit()

            c = actions.Ctx(
                db=db,
                run_id=run.id,
                node_id=node["id"],
                org=run.organization_id,
                principal=principal,
                authz=authz,
                expr_ctx=expr_ctx,
                variables=dict(run.variables or {}),
                resource=ctx_stored.get("resource"),
                actor_id=uuid.UUID(ctx_stored["actor_id"]) if ctx_stored.get("actor_id") else None,
                prior_output=dict(nr.output or {}),
                trigger=dict(ctx_stored),
                approvals=dict(getattr(version, "approval_definitions", None) or {}),
            )
            try:
                if dry and node["type"] not in actions.PURE:
                    spec = ACTIONS[node["type"]]
                    # a branching step previews its first exit (the happy path) so the dry run
                    # shows what comes next; nothing really happens
                    first = spec.outputs[0] if spec.outputs else None
                    result = actions.NodeResult(
                        output={"dry_run": True, "would": spec.label}
                        | ({"simulated_exit": first} if first else {}),
                        branch=first,
                    )
                else:
                    result = actions.HANDLERS[node["type"]](c, node.get("params") or {})
            except actions.ActionFailed as e:
                db.rollback()
                nr = _reload(db, run.id, node["id"])
                nr.status, nr.error, nr.finished_at = "failed", str(e)[:500], datetime.now(UTC)
                _finish(
                    db,
                    run,
                    _auto(db, run),
                    "failed",
                    f"{ACTIONS[node['type']].label}: {e}",
                )  # type: ignore[arg-type]
                db.commit()
                return "failed"
            except Exception as exc:
                db.rollback()
                nr = _reload(db, run.id, node["id"])
                nr.error = _safe(exc)
                if nr.attempts >= MAX_ATTEMPTS:
                    nr.status, nr.finished_at = "failed", datetime.now(UTC)
                    _finish(
                        db,
                        run,
                        _auto(db, run),
                        "failed",  # type: ignore[arg-type]
                        f"{ACTIONS[node['type']].label} failed after {nr.attempts} attempts.",
                    )
                    db.commit()
                    return "failed"
                db.commit()
                raise  # outbox retries with backoff; the node resumes, finished nodes are skipped

            nr = _reload(db, run.id, node["id"])
            run = db.get(AutomationRun, run_id)  # type: ignore[assignment]
            assert run is not None
            run.variables = dict(c.variables)
            nr.output = {**result.output, **({"branch": result.branch} if result.branch else {})}
            nr.error = None
            if result.status == "waiting":
                nr.status = "waiting"
                nr.attempts = 1  # polling for a decision is not a failure
                run.status = "waiting"
                db.commit()
                return "waiting"
            nr.status = result.status
            nr.finished_at = datetime.now(UTC)
            db.commit()
            current = _next(result.branch, edges.get(current, []))

        run = db.get(AutomationRun, run_id)  # type: ignore[assignment]
        a = db.get(Automation, run.automation_id)  # type: ignore[union-attr]
        statuses = {
            s
            for (s,) in db.execute(
                select(AutomationNodeRun.status).where(AutomationNodeRun.run_id == run_id)
            )  # type: ignore[union-attr]
        }
        final = "skipped" if statuses and statuses <= {"skipped"} else "succeeded"
        _finish(db, run, a, final)  # type: ignore[arg-type]
        db.commit()
        return final


def _auto(db: Session, run: AutomationRun) -> Automation:
    a = db.get(Automation, run.automation_id)
    assert a is not None
    return a


def _start(graph: dict[str, Any]) -> str:
    return next(n["id"] for n in graph["nodes"] if n["type"] == "start")


def _next(branch: str | None, outs: list[dict[str, Any]]) -> str | None:
    if not outs:
        return None
    if branch is None:
        return outs[0]["to"]
    for e in outs:
        if e.get("branch") == branch:
            return e["to"]
    return None  # a missing branch means "stop here"


def _reload(db: Session, run_id: uuid.UUID, node_id: str) -> AutomationNodeRun:
    nr = db.scalar(
        select(AutomationNodeRun)
        .where(AutomationNodeRun.run_id == run_id, AutomationNodeRun.node_id == node_id)
        .execution_options(populate_existing=True)
    )
    assert nr is not None
    return nr


def _safe(exc: Exception) -> str:
    """Error text for the run log: type and message of *our* errors, never raw driver text."""
    if isinstance(exc, AppError):
        return exc.message[:300]
    return f"{type(exc).__name__}: an unexpected error occurred."


def _rebuild_context(db: Session, run: AutomationRun, stored: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the expression context from the stored resource reference and CURRENT state."""
    from app.modules.automations import triggers

    res = stored.get("resource")
    ctx: dict[str, Any] = {"event": {"action": stored.get("event", "")}, "actor": {"email": ""}}
    if stored.get("actor_id"):
        ctx["actor"]["email"] = triggers._actor_email(db, uuid.UUID(stored["actor_id"]))
    if res:
        rid = uuid.UUID(res["id"])
        if res["type"] == "document":
            from app.db.models import Document, DocumentVersion

            doc = db.get(Document, rid)
            if doc is not None and doc.organization_id == run.organization_id:
                ver = (
                    db.get(DocumentVersion, doc.current_version_id)
                    if doc.current_version_id
                    else None
                )
                ctx.update(triggers.file_context(db, run.organization_id, doc, ver))
        elif res["type"] == "folder":
            from app.db.models import Folder

            f = db.get(Folder, rid)
            if f is not None and f.organization_id == run.organization_id:
                ctx["folder"] = {
                    "name": f.name,
                    "path": triggers._path_of(db, run.organization_id, f.id),
                }
        elif res["type"] == "user":
            pair = triggers.user_context(db, run.organization_id, rid, ctx, None)
            if pair:
                ctx = pair[0]
    if stored.get("request_id"):
        ctx["request"] = {
            "id": stored["request_id"],
            "actions": stored.get("request_actions", ""),
        }
    for k, v in (run.variables or {}).items():
        ctx.setdefault("vars", {})[k] = v
    return ctx


def resume_waiting(factory: sessionmaker[Session]) -> list[uuid.UUID]:
    """Re-queue runs parked on an approval so ``wait_for_approval`` can re-check the decision."""
    from app.modules.automations.triggers import queue_runs

    with factory() as db:
        ids = list(
            db.scalars(select(AutomationRun.id).where(AutomationRun.status == "waiting").limit(100))
        )
    queue_runs(factory, ids)
    return ids


def wake_for_approval(db: Session, workflow_run_id: uuid.UUID) -> int:
    """An approval just finished: re-queue the automation runs parked on it right away, instead
    of waiting for the next maintenance pass."""
    from app.modules.outbox import service as outbox

    ids = set(
        db.scalars(
            select(AutomationNodeRun.run_id).where(
                AutomationNodeRun.status == "waiting",
                AutomationNodeRun.output["approval_run_id"].astext == str(workflow_run_id),
            )
        )
    )
    for rid in ids:
        run = db.get(AutomationRun, rid)
        if run is not None and run.status == "waiting":
            outbox.enqueue(
                db,
                organization_id=run.organization_id,
                event_type="automation.run",
                aggregate_type="automation_run",
                aggregate_id=rid,
            )
    return len(ids)


def retry_run(db: Session, run: AutomationRun) -> None:
    """Operator retry: failed nodes go back to pending; finished nodes are never redone."""
    for nr in db.scalars(
        select(AutomationNodeRun).where(
            AutomationNodeRun.run_id == run.id, AutomationNodeRun.status == "failed"
        )
    ):
        nr.status, nr.attempts, nr.error, nr.finished_at = "pending", 0, None, None
    run.status, run.error, run.finished_at = "queued", None, None
