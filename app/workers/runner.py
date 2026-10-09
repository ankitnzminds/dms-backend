"""Outbox consumer: claim -> handle -> mark done, with retry/backoff and dead-lettering.

Delivery is at-least-once. Safety under duplicate delivery and worker restarts comes from
(1) claiming with FOR UPDATE SKIP LOCKED + a lock lease that expires, and (2) handlers being
idempotent by construction (state checks / unique constraints), never from "exactly once".
"""

from __future__ import annotations

import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.adapters.email.base import EmailSender, LogEmailSender
from app.adapters.malware.base import MalwareScanner
from app.adapters.malware.factory import build_scanner
from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.metrics import OUTBOX_BACKLOG, OUTBOX_OLDEST_AGE, OUTBOX_PROCESSED
from app.db.enums import OutboxStatus
from app.db.models import OutboxEvent
from app.db.session import get_sessionmaker

log = get_logger("app.worker")

_CLAIM_SQL = text(
    """
    UPDATE dms.outbox_events o
       SET status = 'processing',
           attempts = o.attempts + 1,
           locked_until = now() + make_interval(secs => :lease)
     WHERE o.id IN (
             SELECT id FROM dms.outbox_events
              WHERE status IN ('pending', 'processing')
                AND next_attempt_at <= now()
                AND (locked_until IS NULL OR locked_until < now())
              ORDER BY next_attempt_at, created_at
              LIMIT :n
              FOR UPDATE SKIP LOCKED)
    RETURNING o.id
    """
)


@dataclass
class WorkerContext:
    settings: Settings
    scanner: MalwareScanner
    email: EmailSender


Handler = Callable[[Session, OutboxEvent, WorkerContext], None]


def build_context(settings: Settings | None = None) -> WorkerContext:
    settings = settings or get_settings()
    return WorkerContext(settings=settings, scanner=build_scanner(settings), email=LogEmailSender())


def backoff_seconds(attempts: int) -> float:
    base = min(5 * 2 ** max(attempts - 1, 0), 3600)
    return base * random.uniform(0.8, 1.2)  # noqa: S311  (jitter, not security)


def claim(factory: sessionmaker[Session], limit: int, lease_seconds: int) -> list[uuid.UUID]:
    with factory() as db:
        ids = [r[0] for r in db.execute(_CLAIM_SQL, {"n": limit, "lease": lease_seconds})]
        db.commit()
    return ids


def _sanitize_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {str(exc)[:300]}"


def process_event(
    factory: sessionmaker[Session],
    event_id: uuid.UUID,
    handlers: dict[str, Handler],
    ctx: WorkerContext,
) -> str:
    """Returns 'done' | 'retry' | 'dead' | 'skipped'."""
    event_type = "unknown"
    try:
        with factory() as db:
            event = db.get(OutboxEvent, event_id)
            if event is None or event.status == OutboxStatus.DONE.value:
                return "skipped"
            event_type = event.event_type
            handler = handlers.get(event.event_type)
            if handler is None:
                event.status = OutboxStatus.DONE.value
                event.processed_at = datetime.now(UTC)
                event.last_error = "no handler registered"
                db.commit()
                OUTBOX_PROCESSED.labels(event_type, "no_handler").inc()
                return "done"
            handler(db, event, ctx)
            # the handler commits its own work; mark done in a fresh transaction scope
            event = db.get(OutboxEvent, event_id)
            assert event is not None
            event.status = OutboxStatus.DONE.value
            event.processed_at = datetime.now(UTC)
            event.locked_until = None
            event.last_error = None
            db.commit()
        OUTBOX_PROCESSED.labels(event_type, "done").inc()
        return "done"
    except Exception as exc:
        log.warning(
            "outbox_handler_failed",
            extra={
                "event_id": str(event_id),
                "event_type": event_type,
                "error": _sanitize_error(exc),
            },
        )
        return _record_failure(factory, event_id, exc, event_type)


def _record_failure(
    factory: sessionmaker[Session], event_id: uuid.UUID, exc: Exception, event_type: str
) -> str:
    with factory() as db:
        event = db.get(OutboxEvent, event_id)
        if event is None:
            return "skipped"
        event.last_error = _sanitize_error(exc)
        event.locked_until = None
        if event.attempts >= event.max_attempts:
            event.status = OutboxStatus.DEAD.value
            result = "dead"
        else:
            event.status = OutboxStatus.PENDING.value
            event.next_attempt_at = datetime.now(UTC) + timedelta(
                seconds=backoff_seconds(event.attempts)
            )
            result = "retry"
        db.commit()
    OUTBOX_PROCESSED.labels(event_type, result).inc()
    if result == "dead":
        log.error("outbox_event_dead", extra={"event_id": str(event_id), "event_type": event_type})
    return result


def update_gauges(factory: sessionmaker[Session]) -> None:
    with factory() as db:
        backlog = (
            db.scalar(select(func.count()).where(OutboxEvent.status.in_(["pending", "processing"])))
            or 0
        )
        oldest = db.scalar(
            select(func.min(OutboxEvent.created_at)).where(
                OutboxEvent.status.in_(["pending", "processing"])
            )
        )
    OUTBOX_BACKLOG.set(backlog)
    OUTBOX_OLDEST_AGE.set((datetime.now(UTC) - oldest).total_seconds() if oldest else 0)


def run_once(
    handlers: dict[str, Handler] | None = None,
    ctx: WorkerContext | None = None,
    factory: sessionmaker[Session] | None = None,
) -> int:
    """Claim and process one batch. Returns the number of events handled."""
    from app.workers.handlers import HANDLERS

    handlers = handlers if handlers is not None else HANDLERS
    ctx = ctx or build_context()
    factory = factory or get_sessionmaker()
    ids = claim(factory, ctx.settings.worker_batch_size, ctx.settings.outbox_lock_seconds)
    for event_id in ids:
        process_event(factory, event_id, handlers, ctx)
    return len(ids)


def run_forever() -> None:  # pragma: no cover - process entry point
    from app.workers.maintenance import run_maintenance

    ctx = build_context()
    factory = get_sessionmaker()
    last_maintenance = 0.0
    log.info("worker_started", extra={"scanner": ctx.scanner.name})
    while True:
        try:
            handled = run_once(ctx=ctx, factory=factory)
            now = time.monotonic()
            if now - last_maintenance > 60:
                run_maintenance(factory)
                update_gauges(factory)
                last_maintenance = now
            if handled == 0:
                time.sleep(ctx.settings.worker_poll_interval_seconds)
        except KeyboardInterrupt:
            log.info("worker_stopping")
            return
        except Exception:
            log.exception("worker_loop_error")
            time.sleep(5)


__all__ = [
    "WorkerContext",
    "build_context",
    "claim",
    "process_event",
    "run_forever",
    "run_once",
    "update",
]
