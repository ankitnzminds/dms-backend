"""Compliance reporting built from real records: audit CSV export and an activity summary."""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError
from app.db.enums import AuditOutcome
from app.db.models import (
    AuditEvent,
    Document,
    LegalHold,
    RetentionPolicy,
    ShareGrant,
    SignatureRequest,
    User,
    WorkflowRun,
)
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal

MAX_EXPORT_ROWS = 100_000
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value: object) -> str:
    """Neutralize spreadsheet formula injection (CSV is opened in Excel by auditors)."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def export_audit_csv(
    db: Session,
    p: Principal,
    *,
    action: str | None,
    actor_user_id: uuid.UUID | None,
    resource_type: str | None,
    outcome: str | None,
    since: datetime | None,
    until: datetime | None,
) -> Iterator[bytes]:
    if not p.can_read_audit:
        raise ForbiddenError("Audit access is restricted to administrators and auditors.")
    stmt = select(AuditEvent).where(AuditEvent.organization_id == p.organization_id)
    if action:
        stmt = stmt.where(AuditEvent.action.like(action.replace("%", "") + "%"))
    if actor_user_id:
        stmt = stmt.where(AuditEvent.actor_user_id == actor_user_id)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if since:
        stmt = stmt.where(AuditEvent.created_at >= since)
    if until:
        stmt = stmt.where(AuditEvent.created_at <= until)
    rows = list(db.scalars(stmt.order_by(AuditEvent.created_at.desc()).limit(MAX_EXPORT_ROWS + 1)))
    truncated = len(rows) > MAX_EXPORT_ROWS
    rows = rows[:MAX_EXPORT_ROWS]
    emails = dict(
        db.execute(
            select(User.id, User.email).where(
                User.id.in_(
                    {r.actor_user_id for r in rows if r.actor_user_id} or {uuid.UUID(int=0)}
                )
            )
        ).all()
    )
    # The export itself is an auditable event (who exported what, how many rows).
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="audit.exported",
        resource_type="audit",
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "rows": len(rows),
            "truncated": truncated,
            "filters": {"action": action, "outcome": outcome, "resource_type": resource_type},
        },
    )
    db.commit()

    def generate() -> Iterator[bytes]:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "time_utc",
                "actor_user_id",
                "actor_email",
                "action",
                "outcome",
                "resource_type",
                "resource_id",
                "request_id",
                "metadata",
            ]
        )
        yield buf.getvalue().encode("utf-8-sig")
        for r in rows:
            buf.seek(0)
            buf.truncate()
            writer.writerow(
                [
                    r.created_at.astimezone(UTC).isoformat(),
                    r.actor_user_id or "",
                    _safe_cell(emails.get(r.actor_user_id, "")) if r.actor_user_id else "",
                    _safe_cell(r.action),
                    r.outcome,
                    _safe_cell(r.resource_type),
                    r.resource_id or "",
                    _safe_cell(r.request_id),
                    _safe_cell(str(r.event_metadata or {})),
                ]
            )
            yield buf.getvalue().encode("utf-8")
        if truncated:
            yield f"# truncated at {MAX_EXPORT_ROWS} rows - narrow the filters\n".encode()

    return generate()


def activity_summary(db: Session, p: Principal, days: int = 30) -> dict[str, Any]:
    if not p.can_read_audit:
        raise ForbiddenError("Compliance access is restricted to administrators and auditors.")
    org = p.organization_id
    since = datetime.now(UTC) - timedelta(days=days)

    def grouped(model: Any, column: Any, *where: Any) -> dict[str, int]:
        rows = db.execute(
            select(column, func.count())
            .where(model.organization_id == org, *where)
            .group_by(column)
        ).all()
        return {str(k): int(v) for k, v in rows}

    now = datetime.now(UTC)
    shares_total = int(
        db.scalar(select(func.count()).where(ShareGrant.organization_id == org)) or 0
    )
    shares_revoked = int(
        db.scalar(
            select(func.count()).where(
                ShareGrant.organization_id == org, ShareGrant.revoked_at.is_not(None)
            )
        )
        or 0
    )
    shares_expired = int(
        db.scalar(
            select(func.count()).where(
                ShareGrant.organization_id == org,
                ShareGrant.revoked_at.is_(None),
                ShareGrant.expires_at.is_not(None),
                ShareGrant.expires_at <= now,
            )
        )
        or 0
    )
    return {
        "period_days": days,
        "documents_by_classification": grouped(
            Document, Document.classification, Document.deleted_at.is_(None)
        ),
        "documents_by_status": grouped(Document, Document.status, Document.deleted_at.is_(None)),
        "shares": {
            "total": shares_total,
            "revoked": shares_revoked,
            "expired": shares_expired,
            "active": shares_total - shares_revoked - shares_expired,
        },
        "legal_holds": grouped(LegalHold, LegalHold.status),
        "retention_policies_enabled": int(
            db.scalar(
                select(func.count()).where(
                    RetentionPolicy.organization_id == org, RetentionPolicy.enabled.is_(True)
                )
            )
            or 0
        ),
        "workflow_runs": grouped(WorkflowRun, WorkflowRun.state),
        "signature_requests": grouped(SignatureRequest, SignatureRequest.state),
        "audit_events_by_outcome": grouped(
            AuditEvent, AuditEvent.outcome, AuditEvent.created_at >= since
        ),
        "top_actions": [
            {"action": a, "count": int(c)}
            for a, c in db.execute(
                select(AuditEvent.action, func.count().label("c"))
                .where(AuditEvent.organization_id == org, AuditEvent.created_at >= since)
                .group_by(AuditEvent.action)
                .order_by(func.count().desc())
                .limit(10)
            ).all()
        ],
        "denied_attempts": int(
            db.scalar(
                select(func.count()).where(
                    AuditEvent.organization_id == org,
                    AuditEvent.outcome == "denied",
                    AuditEvent.created_at >= since,
                )
            )
            or 0
        ),
    }
