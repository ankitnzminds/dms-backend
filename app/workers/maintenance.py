"""Periodic housekeeping (idempotent and safe to run on several workers)."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.logging import get_logger
from app.db.enums import AuditOutcome
from app.db.models import ShareGrant
from app.modules.audit import service as audit
from app.modules.outbox import service as outbox
from app.modules.uploads.service import expire_stale_sessions

log = get_logger("app.worker.maintenance")


def record_expired_shares(db: Session, limit: int = 200) -> int:
    """Audit + notify each expired share exactly once (guarded by expiry_recorded_at)."""
    now = datetime.now(UTC)
    shares = list(
        db.scalars(
            select(ShareGrant)
            .where(
                ShareGrant.revoked_at.is_(None),
                ShareGrant.expires_at.is_not(None),
                ShareGrant.expires_at <= now,
                ShareGrant.expiry_recorded_at.is_(None),
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
    )
    for share in shares:
        share.expiry_recorded_at = now
        audit.record(
            db,
            organization_id=share.organization_id,
            actor_user_id=None,
            action="share.expired",
            resource_type=share.resource_type,
            resource_id=share.resource_id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"share_id": str(share.id)},
        )
        outbox.enqueue(
            db,
            organization_id=share.organization_id,
            event_type="share.expired",
            aggregate_type="share",
            aggregate_id=share.id,
        )
    db.commit()
    return len(shares)


def run_maintenance(factory: sessionmaker[Session]) -> dict[str, int]:
    summary = {}
    with factory() as db:
        summary["expired_upload_sessions"] = expire_stale_sessions(db)
    with factory() as db:
        summary["expired_shares_recorded"] = record_expired_shares(db)
    from app.modules.governance.service import purge_expired_trash
    from app.modules.workflows.service import process_overdue_tasks

    with factory() as db:
        summary["overdue_tasks_notified"] = process_overdue_tasks(db)

    with factory() as db:
        summary.update({f"trash_{k}": v for k, v in purge_expired_trash(db).items()})
    if any(summary.values()):
        log.info("maintenance_ran", extra=summary)
    return summary
