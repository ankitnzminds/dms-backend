"""Turning things that happened into runs.

Three sources, one idempotent ``create_run``:
  * audit events (``dispatch`` is called from the audit writer, inside the business transaction,
    and enqueues an outbox event; the worker then matches automations),
  * the scheduler (timers and daily scans), called from worker maintenance,
  * manual dry-run tests (never side-effecting).

A run is keyed by ``(automation, event_key)``: a redelivered event, a retried scan or a second
scheduler instance can never start a second run for the same occurrence.
"""

from __future__ import annotations

import fnmatch
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.core.context import get_request_id
from app.core.logging import get_logger
from app.db.enums import DocumentStatus, MembershipStatus
from app.db.models import (
    AuditEvent,
    Automation,
    AutomationRun,
    AutomationVersion,
    Document,
    DocumentVersion,
    Folder,
    Membership,
    User,
)
from app.modules.audit import service as audit
from app.modules.automations import expr
from app.modules.automations.registry import CONDITIONS, ConditionSpec
from app.modules.automations.schedule import fire_key, next_fire
from app.modules.folders.common import plain_path
from app.modules.outbox import service as outbox

log = get_logger("app.automations")

EVENT_ACTIONS = frozenset(a for c in CONDITIONS.values() for a in c.audit_actions)
RUNS_PER_10_MIN_LIMIT = 200  # circuit breaker against self-triggering loops


# ------------------------------------------------------------------------ dispatch
def dispatch(db: Session, event: AuditEvent) -> None:
    """Called inside the transaction that records ``event``. Cheap: one indexed existence check."""
    if event.action not in EVENT_ACTIONS or event.organization_id is None:
        return
    exists = db.scalar(
        select(Automation.id)
        .where(
            Automation.organization_id == event.organization_id,
            Automation.enabled.is_(True),
            Automation.status == "published",
        )
        .limit(1)
    )
    if exists is None:
        return
    outbox.enqueue(
        db,
        organization_id=event.organization_id,
        event_type="automation.event",
        aggregate_type="audit_event",
        aggregate_id=event.id,
    )


# ------------------------------------------------------------------------ context
def _path_of(db: Session, org: uuid.UUID, folder_id: uuid.UUID) -> str:
    segments = plain_path(db, org, folder_id).split("/")[1:]  # drop the root folder's own name
    return "/" + "/".join(s for s in segments if s)


def file_context(
    db: Session, org: uuid.UUID, doc: Document, version: DocumentVersion | None
) -> dict[str, Any]:
    folder_path = _path_of(db, org, doc.folder_id)
    name = doc.name
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return {
        "file": {
            "name": name,
            "path": (folder_path.rstrip("/") + "/" + name),
            "extension": ext,
            "size_bytes": version.size_bytes if version else 0,
            "classification": doc.classification,
            "version_number": version.version_number if version else 0,
        }
    }


def _actor_email(db: Session, actor_id: uuid.UUID | None) -> str:
    if actor_id is None:
        return ""
    u = db.get(User, actor_id)
    return u.email if u else ""


def event_context(db: Session, ev: AuditEvent) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """(expression context, stored trigger_context). None if the subject cannot be resolved."""
    org = ev.organization_id
    assert org is not None
    base = {"actor": {"email": _actor_email(db, ev.actor_user_id)}, "event": {"action": ev.action}}
    stored: dict[str, Any] = {
        "event": ev.action,
        "audit_event_id": str(ev.id),
        "actor_id": str(ev.actor_user_id) if ev.actor_user_id else None,
    }
    if ev.resource_type == "document" and ev.resource_id:
        doc = db.scalar(
            select(Document).where(Document.id == ev.resource_id, Document.organization_id == org)
        )
        if doc is None:
            return None
        meta_version = (ev.event_metadata or {}).get("version_number")
        version = None
        if meta_version is not None:
            version = db.scalar(
                select(DocumentVersion).where(
                    DocumentVersion.document_id == doc.id,
                    DocumentVersion.version_number == int(meta_version),
                )
            )
        if version is None and doc.current_version_id:
            version = db.get(DocumentVersion, doc.current_version_id)
        # Scan results are written by the system; for those the "actor" is whoever uploaded the version.
        actor_id = ev.actor_user_id or (version.created_by if version else None)
        base["actor"] = {"email": _actor_email(db, actor_id)}
        stored["actor_id"] = str(actor_id) if actor_id else None
        ctx = {**base, **file_context(db, org, doc, version)}
        stored["resource"] = {"type": "document", "id": str(doc.id), "name": doc.name}
        return ctx, stored
    if ev.resource_type == "folder" and ev.resource_id:
        folder = db.scalar(
            select(Folder).where(Folder.id == ev.resource_id, Folder.organization_id == org)
        )
        if folder is None:
            return None
        ctx = {
            **base,
            "folder": {"name": folder.name, "path": _path_of(db, org, folder.id)},
        }
        stored["resource"] = {"type": "folder", "id": str(folder.id), "name": folder.name}
        return ctx, stored
    if ev.resource_type == "user" and ev.resource_id:
        return user_context(db, org, ev.resource_id, base, stored)
    return None


def user_context(
    db: Session,
    org: uuid.UUID,
    user_id: uuid.UUID,
    base: dict[str, Any] | None = None,
    stored: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    row = db.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(User.id == user_id, Membership.organization_id == org)
    ).first()
    if row is None:
        return None
    user, m = row
    now = datetime.now(UTC)
    ctx = {
        **(base or {"event": {"action": "scan"}}),
        "user": {
            "email": user.email,
            "display_name": user.display_name or "",
            "role": m.role,
            "age_days": (now - m.created_at).days,
            "days_since_login": (now - user.last_login_at).days if user.last_login_at else None,
            "days_to_expiry": (m.account_expires_at - now).days if m.account_expires_at else None,
        },
    }
    st = dict(stored or {})
    st["resource"] = {"type": "user", "id": str(user.id), "name": user.email}
    return ctx, st


# ------------------------------------------------------------------------ matching
def _in_scope(params: dict[str, Any], ctx: dict[str, Any]) -> bool:
    item = ctx.get("file") or ctx.get("folder") or {}
    path = (item.get("path") or "").lower()
    scope = (params.get("path") or "").lower()
    if scope:
        if params.get("recursive", True):
            if not (path == scope or path.startswith(scope + "/")):
                return False
        else:
            parent = path.rsplit("/", 1)[0] if "/" in path else ""
            if parent != scope and path != scope:
                return False
    name = (item.get("name") or "").lower()
    for pat in params.get("exclude") or []:
        if fnmatch.fnmatch(name, pat.lower()) or fnmatch.fnmatch(path, pat.lower()):
            return False
    exts = [e.lower() for e in params.get("extensions") or []]
    return not (exts and (ctx.get("file") or {}).get("extension") not in exts)


def condition_matches(spec: ConditionSpec, params: dict[str, Any], ctx: dict[str, Any]) -> bool:
    """Static filters for event triggers: version semantics, size thresholds, scope, expression."""
    f = ctx.get("file") or {}
    if spec.key == "file_created" and f.get("version_number") != 1:
        return False
    if spec.key == "file_updated" and (f.get("version_number") or 0) < 2:
        return False
    if spec.key in ("upload_size_threshold", "download_size_threshold") and not (
        (f.get("size_bytes") or 0) > params["greater_than_bytes"]
    ):
        return False
    if (ctx.get("file") or ctx.get("folder")) and not _in_scope(params, ctx):
        return False
    expression = params.get("expression")
    if expression:
        try:
            return bool(expr.evaluate(expression, ctx, frozenset(spec.variables)))
        except expr.ExprError:
            return False
    return True


# -------------------------------------------------------------------------- runs
def create_run(
    db: Session,
    a: Automation,
    version: AutomationVersion,
    *,
    event_key: str,
    trigger_context: dict[str, Any],
    mode: str = "live",
) -> uuid.UUID | None:
    """Insert a queued run; returns None when this occurrence already has one (idempotent)."""
    if mode == "live":
        since = datetime.now(UTC) - timedelta(minutes=10)
        recent = db.scalar(
            select(AutomationRun.id)
            .where(AutomationRun.automation_id == a.id, AutomationRun.created_at >= since)
            .offset(RUNS_PER_10_MIN_LIMIT)
            .limit(1)
        )
        if recent is not None:
            a.enabled = False
            a.next_check_at = None
            a.attention_reason = "Disabled automatically: it started more than 200 runs in 10 minutes (possible loop)."
            audit.record(
                db,
                organization_id=a.organization_id,
                actor_user_id=None,
                action="automation.circuit_open",
                resource_type="automation",
                resource_id=a.id,
            )
            return None
    run_id = uuid.uuid4()
    stmt = (
        pg_insert(AutomationRun)
        .values(
            id=run_id,
            organization_id=a.organization_id,
            automation_id=a.id,
            version_id=version.id,
            event_key=event_key[:200],
            status="queued",
            mode=mode,
            trigger_context=trigger_context,
            variables={},
            correlation_id=get_request_id() or uuid.uuid4().hex[:16],
        )
        .on_conflict_do_nothing(constraint="uq_automation_runs_event")
        .returning(AutomationRun.id)
    )
    new_id = db.execute(stmt).scalar()
    if new_id is not None and mode == "live":
        # same transaction as the run row: a crash can never leave a run that nothing will execute
        outbox.enqueue(
            db,
            organization_id=a.organization_id,
            event_type="automation.run",
            aggregate_type="automation_run",
            aggregate_id=new_id,
        )
    return new_id


def _live_automations(
    db: Session, org: uuid.UUID | None = None
) -> list[tuple[Automation, AutomationVersion]]:
    stmt = (
        select(Automation, AutomationVersion)
        .join(AutomationVersion, AutomationVersion.id == Automation.published_version_id)
        .where(Automation.enabled.is_(True), Automation.status == "published")
    )
    if org:
        stmt = stmt.where(Automation.organization_id == org)
    return [(a, v) for a, v in db.execute(stmt).all()]


def handle_event(factory: sessionmaker[Session], audit_event_id: uuid.UUID) -> list[uuid.UUID]:
    """Worker side of ``dispatch``: create (idempotently) the runs this event triggers."""
    created: list[uuid.UUID] = []
    with factory() as db:
        ev = db.get(AuditEvent, audit_event_id)
        if ev is None or ev.organization_id is None:
            return created
        resolved = event_context(db, ev)
        for a, v in _live_automations(db, ev.organization_id):
            spec = CONDITIONS.get(v.trigger.get("key", ""))
            if spec is None or ev.action not in spec.audit_actions or not spec.supported:
                continue
            a.last_checked_at = datetime.now(UTC)
            if resolved is None:
                continue
            ctx, stored = resolved
            if not condition_matches(spec, v.trigger.get("params") or {}, ctx):
                continue
            run_id = create_run(db, a, v, event_key=f"audit:{ev.id}", trigger_context=stored)
            if run_id:
                created.append(run_id)
        db.commit()
    return created


# ---------------------------------------------------------------------- scheduler
def _scan_resources(
    db: Session, spec: ConditionSpec, a: Automation, params: dict[str, Any], now: datetime
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], bool]:
    """Resources currently matching a scan condition: [(ctx, stored)], truncated?"""
    org = a.organization_id
    limit = 200
    out: list[tuple[dict[str, Any], dict[str, Any]]] = []
    base = {"event": {"action": "scan"}}
    if spec.key == "file_stale":
        cutoff = now - timedelta(days=int(params["days"]))
        rows = db.execute(
            select(Document, DocumentVersion)
            .join(DocumentVersion, DocumentVersion.id == Document.current_version_id)
            .where(
                Document.organization_id == org,
                Document.deleted_at.is_(None),
                Document.status == DocumentStatus.AVAILABLE.value,
                DocumentVersion.created_at < cutoff,
            )
            .order_by(DocumentVersion.created_at)
            .limit(limit * 5)
        ).all()
        for doc, ver in rows:
            ctx = {**base, "actor": {"email": ""}, **file_context(db, org, doc, ver)}
            if _in_scope(params, ctx) and _expr_ok(spec, params, ctx):
                out.append(
                    (
                        ctx,
                        {
                            "event": "scan",
                            "resource": {"type": "document", "id": str(doc.id), "name": doc.name},
                        },
                    )
                )
            if len(out) >= limit:
                return out, True
        return out, False
    now_date = now
    members = db.execute(
        select(User, Membership)
        .join(Membership, Membership.user_id == User.id)
        .where(
            Membership.organization_id == org, Membership.status != MembershipStatus.REMOVED.value
        )
        .limit(5000)
    ).all()
    for user, m in members:
        ctx_stored = user_context(db, org, user.id)
        if ctx_stored is None:
            continue
        ctx, stored = ctx_stored
        u = ctx["user"]
        if spec.key == "account_age":
            ok = u["age_days"] >= int(params["days"]) and not (
                params.get("exclude_disabled", True)
                and m.status == MembershipStatus.SUSPENDED.value
            )
        elif spec.key == "last_login_age":
            days = u["days_since_login"]
            ok = (days is not None and days >= int(params["days"])) or (
                days is None
                and params.get("include_never_logged_in")
                and u["age_days"] >= int(params["days"])
            )
            if (
                params.get("exclude_disabled", True)
                and m.status == MembershipStatus.SUSPENDED.value
            ):
                ok = False
        else:  # account_expiring
            d = u["days_to_expiry"]
            ok = d is not None and 0 <= d <= int(params["within_days"])
        if ok and _expr_ok(spec, params, ctx):
            out.append((ctx, stored))
        if len(out) >= limit:
            return out, True
    _ = now_date
    return out, False


def _expr_ok(spec: ConditionSpec, params: dict[str, Any], ctx: dict[str, Any]) -> bool:
    e = params.get("expression")
    if not e:
        return True
    try:
        return bool(expr.evaluate(e, ctx, frozenset(spec.variables)))
    except expr.ExprError:
        return False


def schedule_due(factory: sessionmaker[Session], now: datetime | None = None) -> list[uuid.UUID]:
    """Evaluate timers and daily scans that are due. Safe to run on several workers at once:
    rows are claimed with SKIP LOCKED and runs are idempotent by (automation, event_key)."""
    now = now or datetime.now(UTC)
    created: list[uuid.UUID] = []
    with factory() as db:
        due = db.execute(
            select(Automation, AutomationVersion)
            .join(AutomationVersion, AutomationVersion.id == Automation.published_version_id)
            .where(
                Automation.enabled.is_(True),
                Automation.status == "published",
                Automation.next_check_at.is_not(None),
                Automation.next_check_at <= now,
            )
            .limit(25)
            .with_for_update(of=Automation, skip_locked=True)
        ).all()
        for a, v in due:
            spec = CONDITIONS.get(v.trigger.get("key", ""))
            if spec is None or not spec.supported:
                a.enabled = False
                a.attention_reason = "Its condition is no longer supported."
                continue
            params = v.trigger.get("params") or {}
            fired_at = a.next_check_at or now
            a.last_checked_at = now
            if spec.kind == "timer":
                rid = create_run(
                    db,
                    a,
                    v,
                    event_key=fire_key(v.trigger, fired_at),
                    trigger_context={"event": "timer", "fired_at": fired_at.isoformat()},
                )
                if rid:
                    created.append(rid)
            else:
                matches, truncated = _scan_resources(db, spec, a, params, now)
                for _ctx, stored in matches:
                    rid = create_run(
                        db,
                        a,
                        v,
                        event_key=f"{fire_key(v.trigger, now)}:{stored['resource']['id']}",
                        trigger_context={**stored, "scan_truncated": truncated},
                    )
                    if rid:
                        created.append(rid)
                if truncated:
                    a.attention_reason = (
                        "More than 200 items matched; only the first 200 were processed today."
                    )
            a.next_check_at = next_fire(v.trigger, now)
            if a.next_check_at is None and spec.kind == "timer":
                a.last_run_summary = "Scheduled run completed; no further runs are scheduled."
        db.commit()
    return created


def queue_runs(factory: sessionmaker[Session], run_ids: list[uuid.UUID]) -> None:
    """Hand runs to the outbox consumer (durable, retried, dead-lettered like everything else)."""
    if not run_ids:
        return
    with factory() as db:
        for rid in run_ids:
            run = db.get(AutomationRun, rid)
            if run is None:
                continue
            outbox.enqueue(
                db,
                organization_id=run.organization_id,
                event_type="automation.run",
                aggregate_type="automation_run",
                aggregate_id=rid,
            )
        db.commit()
