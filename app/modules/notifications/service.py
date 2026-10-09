"""In-app notifications. Creation is idempotent per (user, source event, type)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.db.models import Notification
from app.modules.identity.principal import Principal
from app.schemas.admin import NotificationOut


def create(
    db: Session,
    *,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    type_: str,
    title: str,
    body: str | None = None,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    source_event_id: uuid.UUID | None = None,
) -> bool:
    """Returns False if this (user, event, type) notification already exists (duplicate delivery)."""
    stmt = (
        pg_insert(Notification)
        .values(
            id=uuid.uuid4(),
            organization_id=organization_id,
            user_id=user_id,
            type=type_,
            title=title[:300],
            body=body,
            resource_type=resource_type,
            resource_id=resource_id,
            source_event_id=source_event_id,
        )
        .on_conflict_do_nothing(constraint="uq_notifications_event")
        .returning(Notification.id)
    )
    return db.execute(stmt).first() is not None


def list_for(
    db: Session, p: Principal, *, unread_only: bool, limit: int, offset: int
) -> tuple[list[NotificationOut], int, int]:
    base = select(Notification).where(
        Notification.user_id == p.user_id, Notification.organization_id == p.organization_id
    )
    unread = (
        db.scalar(
            select(func.count()).select_from(base.where(Notification.read_at.is_(None)).subquery())
        )
        or 0
    )
    stmt = base.where(Notification.read_at.is_(None)) if unread_only else base
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(
        stmt.order_by(Notification.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return [NotificationOut.model_validate(r) for r in rows], int(total), int(unread)


def mark_read(db: Session, p: Principal, notification_id: uuid.UUID) -> bool:
    result = db.execute(
        update(Notification)
        .where(
            Notification.id == notification_id,
            Notification.user_id == p.user_id,
            Notification.read_at.is_(None),
        )
        .values(read_at=datetime.now(UTC))
    )
    db.commit()
    return bool(getattr(result, "rowcount", 0))


def mark_all_read(db: Session, p: Principal) -> int:
    result = db.execute(
        update(Notification)
        .where(
            Notification.user_id == p.user_id,
            Notification.organization_id == p.organization_id,
            Notification.read_at.is_(None),
        )
        .values(read_at=datetime.now(UTC))
    )
    db.commit()
    return int(getattr(result, "rowcount", 0) or 0)
