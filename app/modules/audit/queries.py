"""Reading audit events (administrators and auditors only; tenant scoped)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError
from app.db.models import AuditEvent, User
from app.modules.identity.principal import Principal
from app.schemas.admin import AuditEventOut


def list_events(
    db: Session,
    p: Principal,
    *,
    action: str | None,
    actor_user_id: uuid.UUID | None,
    resource_type: str | None,
    resource_id: uuid.UUID | None,
    outcome: str | None,
    since: datetime | None,
    until: datetime | None,
    limit: int,
    offset: int,
) -> tuple[list[AuditEventOut], int]:
    if not p.can_read_audit:
        raise ForbiddenError("Audit access is restricted to administrators and auditors.")
    stmt = select(AuditEvent).where(AuditEvent.organization_id == p.organization_id)
    if action:
        stmt = stmt.where(AuditEvent.action.like(action.replace("%", "") + "%"))
    if actor_user_id:
        stmt = stmt.where(AuditEvent.actor_user_id == actor_user_id)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if since:
        stmt = stmt.where(AuditEvent.created_at >= since)
    if until:
        stmt = stmt.where(AuditEvent.created_at <= until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    events = list(
        db.scalars(
            stmt.order_by(AuditEvent.created_at.desc(), AuditEvent.id).limit(limit).offset(offset)
        )
    )
    actor_ids = {e.actor_user_id for e in events if e.actor_user_id}
    emails = (
        dict(db.execute(select(User.id, User.email).where(User.id.in_(actor_ids))).all())
        if actor_ids
        else {}
    )
    return (
        [
            AuditEventOut(
                id=e.id,
                created_at=e.created_at,
                actor_user_id=e.actor_user_id,
                actor_email=emails.get(e.actor_user_id) if e.actor_user_id else None,
                action=e.action,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                outcome=e.outcome,  # type: ignore[arg-type]
                request_id=e.request_id,
                metadata=e.event_metadata or {},
            )
            for e in events
        ],
        int(total),
    )
