"""The people side of workflows: start one on an item, and follow what it is doing.

Administrators design and publish a workflow; this module is what everyone else touches.

* A *manual* workflow ("Started by a user on a file/folder") is offered on the items its scope covers
  to the people it allows (anyone who can edit the item, or administrators only).
* Starting it creates an ordinary live run. Like every run it executes AS the person who published
  the workflow and re-checks that person's rights at each step, so starting a workflow never gives
  the starter more power than the administrator chose to hand out. The starter must hold the edit
  right on the item, and the start is audited.
* Non-administrators see a *summary* of a run (step names and outcomes), never step parameters or raw
  output.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import Action
from app.db.models import (
    Automation,
    AutomationNodeRun,
    AutomationRun,
    AutomationVersion,
    DocumentVersion,
    User,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.automations import triggers
from app.modules.automations.registry import ACTIONS, CONDITIONS
from app.modules.identity.principal import Principal
from app.schemas.automations import (
    AutomationRunOut,
    RunStepOut,
    RunSummaryOut,
    StartableOut,
    StartedOut,
    StartRequest,
)

MANUAL_KEYS = {"manual_file": "document", "manual_folder": "folder"}


def _live_manual(db: Session, org: uuid.UUID) -> list[tuple[Automation, AutomationVersion]]:
    return [
        (a, v)
        for a, v in triggers._live_automations(db, org)  # noqa: SLF001
        if v.trigger.get("key") in MANUAL_KEYS
    ]


def _item_context(
    db: Session, authz: AuthorizationService, rtype: str, rid: uuid.UUID
) -> tuple[dict[str, Any], dict[str, Any]]:
    """(expression context, stored resource) for an item the caller may start workflows on."""
    p = authz.principal
    base = {"actor": {"email": triggers._actor_email(db, p.user_id)}, "event": {"action": "manual"}}  # noqa: SLF001
    if rtype == "document":
        doc = authz.require_document(rid, Action.EDIT_METADATA)
        version = (
            db.get(DocumentVersion, doc.current_version_id) if doc.current_version_id else None
        )
        ctx = {**base, **triggers.file_context(db, p.organization_id, doc, version)}
        return ctx, {"type": "document", "id": str(doc.id), "name": doc.name}
    folder = authz.require_folder(rid, Action.CREATE_CHILD)
    path = triggers._path_of(db, p.organization_id, folder.id)  # noqa: SLF001
    ctx = {**base, "folder": {"name": folder.name, "path": path}}
    return ctx, {"type": "folder", "id": str(folder.id), "name": folder.name}


def _allowed(p: Principal, params: dict[str, Any]) -> bool:
    return params.get("who_can_start", "editors") != "admins" or p.is_admin


def startable(
    db: Session, authz: AuthorizationService, rtype: str, rid: uuid.UUID
) -> list[StartableOut]:
    """The manual workflows this person may start on this item right now."""
    p = authz.principal
    try:
        ctx, _ = _item_context(db, authz, rtype, rid)
    except (ForbiddenError, NotFoundError):
        return []  # no edit right (or not visible): nothing to offer, and nothing disclosed
    out: list[StartableOut] = []
    for a, v in _live_manual(db, p.organization_id):
        key = v.trigger.get("key", "")
        params = v.trigger.get("params") or {}
        spec = CONDITIONS[key]
        if MANUAL_KEYS[key] != rtype or not _allowed(p, params):
            continue
        if not triggers.condition_matches(spec, params, ctx):
            continue
        out.append(
            StartableOut(
                id=a.id,
                name=a.name,
                description=a.description,
                instructions=params.get("instructions"),
                who_can_start=params.get("who_can_start", "editors"),
            )
        )
    return sorted(out, key=lambda s: s.name.lower())


def start(
    db: Session, authz: AuthorizationService, automation_id: uuid.UUID, body: StartRequest
) -> StartedOut:
    p = authz.principal
    row = db.execute(
        select(Automation, AutomationVersion)
        .join(AutomationVersion, AutomationVersion.id == Automation.published_version_id)
        .where(
            Automation.id == automation_id,
            Automation.organization_id == p.organization_id,
            Automation.enabled.is_(True),
            Automation.status == "published",
        )
    ).first()
    if row is None or row[1].trigger.get("key") not in MANUAL_KEYS:
        raise NotFoundError("Workflow not found.")
    a, v = row
    key = v.trigger["key"]
    params = v.trigger.get("params") or {}
    if MANUAL_KEYS[key] != body.resource_type:
        raise ValidationFailed(
            f"This workflow is started on a {MANUAL_KEYS[key]}.", code="wrong_item_type"
        )
    if not _allowed(p, params):
        raise ForbiddenError("Only administrators can start this workflow.", code="admins_only")
    ctx, resource = _item_context(db, authz, body.resource_type, body.resource_id)
    if not triggers.condition_matches(CONDITIONS[key], params, ctx):
        raise ValidationFailed(
            "This workflow does not apply to that item (outside its folder or file-type scope).",
            code="out_of_scope",
        )
    stored: dict[str, Any] = {
        "event": "manual",
        "actor_id": str(p.user_id),
        "resource": resource,
        "started_by": str(p.user_id),
        "note": (body.note or "").strip() or None,
    }
    run_id = triggers.create_run(
        db, a, v, event_key=f"manual:{uuid.uuid4()}", trigger_context=stored
    )
    if run_id is None:  # the circuit breaker tripped
        db.commit()
        raise ValidationFailed(
            "This workflow was paused because it started too many runs.", code="paused"
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="automation.manual_started",
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        metadata={"automation_id": str(a.id), "run_id": str(run_id), "workflow": a.name},
    )
    db.commit()
    return StartedOut(run_id=run_id, status="queued")


# ------------------------------------------------------------------------------ summaries
def summarize(db: Session, runs: list[AutomationRun]) -> list[RunSummaryOut]:
    if not runs:
        return []
    names = dict(
        db.execute(
            select(Automation.id, Automation.name).where(
                Automation.id.in_({r.automation_id for r in runs})
            )
        ).all()
    )
    starters = {
        uuid.UUID(r.trigger_context["actor_id"])
        for r in runs
        if (r.trigger_context or {}).get("actor_id")
    }
    emails = (
        dict(db.execute(select(User.id, User.email).where(User.id.in_(starters))).all())
        if starters
        else {}
    )
    steps: dict[uuid.UUID, list[RunStepOut]] = {}
    for nr in db.scalars(
        select(AutomationNodeRun)
        .where(AutomationNodeRun.run_id.in_([r.id for r in runs]))
        .order_by(AutomationNodeRun.started_at.nulls_last())
    ):
        spec = ACTIONS.get(nr.node_type)
        steps.setdefault(nr.run_id, []).append(
            RunStepOut(
                label=spec.label if spec else nr.node_type,
                status=nr.status,  # type: ignore[arg-type]
                branch=(nr.output or {}).get("branch"),
                error=nr.error,
                finished_at=nr.finished_at,
            )
        )
    out = []
    for r in runs:
        tc = r.trigger_context or {}
        res = tc.get("resource") or {}
        starter = tc.get("actor_id")
        out.append(
            RunSummaryOut(
                id=r.id,
                automation_name=names.get(r.automation_id, "Workflow"),
                status=r.status,  # type: ignore[arg-type]
                started_by_email=emails.get(uuid.UUID(starter)) if starter else None,
                resource_name=res.get("name"),
                resource_type=res.get("type"),
                resource_id=uuid.UUID(res["id"]) if res.get("id") else None,
                note=tc.get("note"),
                error=r.error,
                created_at=r.created_at,
                finished_at=r.finished_at,
                steps=steps.get(r.id, []),
            )
        )
    return out


def my_runs(
    db: Session, p: Principal, *, limit: int, offset: int
) -> tuple[list[RunSummaryOut], int]:
    """Workflows I started by hand, newest first."""
    stmt = select(AutomationRun).where(
        AutomationRun.organization_id == p.organization_id,
        AutomationRun.mode == "live",
        AutomationRun.event_key.like("manual:%"),
        AutomationRun.trigger_context["actor_id"].astext == str(p.user_id),
    )
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(AutomationRun.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return summarize(db, list(rows)), int(total)


def get_my_run(db: Session, p: Principal, run_id: uuid.UUID) -> RunSummaryOut:
    run = db.scalar(
        select(AutomationRun).where(
            AutomationRun.id == run_id,
            AutomationRun.organization_id == p.organization_id,
            AutomationRun.mode == "live",
        )
    )
    starter = ((run.trigger_context or {}).get("actor_id") if run else None) or ""
    if run is None or not (starter == str(p.user_id) or p.is_admin):
        raise NotFoundError("Run not found.")
    return summarize(db, [run])[0]


def document_runs(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, *, limit: int
) -> list[RunSummaryOut]:
    """Workflows that ran on this file (anyone who can see the file may follow them)."""
    p = authz.principal
    doc = authz.require_document(document_id, Action.VIEW)
    rows = db.scalars(
        select(AutomationRun)
        .where(
            AutomationRun.organization_id == p.organization_id,
            AutomationRun.mode == "live",
            AutomationRun.trigger_context["resource"]["id"].astext == str(doc.id),
        )
        .order_by(AutomationRun.created_at.desc())
        .limit(limit)
    ).all()
    return summarize(db, list(rows))


def admin_runs(
    db: Session,
    p: Principal,
    *,
    status: str | None,
    automation_id: uuid.UUID | None,
    limit: int,
    offset: int,
) -> tuple[list[AutomationRunOut], int]:
    from app.modules.automations.runs import _run_out
    from app.modules.automations.service import require_admin

    require_admin(p)
    stmt = select(AutomationRun).where(
        AutomationRun.organization_id == p.organization_id, AutomationRun.mode == "live"
    )
    if status:
        stmt = stmt.where(AutomationRun.status == status)
    if automation_id:
        stmt = stmt.where(AutomationRun.automation_id == automation_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(AutomationRun.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return [_run_out(db, r, with_nodes=False) for r in rows], int(total)
