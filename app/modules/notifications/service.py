"""In-app notifications. Creation is idempotent per (user, source event, type)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import Notification, NotificationPreference
from app.modules.identity.principal import Principal
from app.modules.outbox import service as outbox
from app.schemas.admin import NotificationOut

GROUPS = ("sharing", "workflow", "signature", "document", "other")


def group_of(type_: str) -> str:
    head = type_.split(".", 1)[0]
    return {
        "share": "sharing",
        "access_request": "sharing",
        "comment": "document",
        "workflow": "workflow",
        "signature": "signature",
        "document": "document",
    }.get(head, "other")


def preference(db: Session, org_id: uuid.UUID, user_id: uuid.UUID, group: str) -> tuple[bool, bool]:
    row = db.get(NotificationPreference, (user_id, org_id, group))
    return (row.in_app, row.email) if row else (True, True)


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
    """Returns False if this (user, event, type) notification already exists (duplicate delivery).

    Honors the user's preferences: with in-app disabled the record is kept but pre-read; an
    e-mail is queued (through the outbox, never inline) only if enabled and a sender exists."""
    in_app, email = preference(db, organization_id, user_id, group_of(type_))
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
            read_at=None if in_app else datetime.now(UTC),
        )
        .on_conflict_do_nothing(constraint="uq_notifications_event")
        .returning(Notification.id)
    )
    new_id = db.execute(stmt).scalar()
    if new_id is None:
        return False
    if email and get_settings().email_provider != "none":
        outbox.enqueue(
            db,
            organization_id=organization_id,
            event_type="notification.email",
            aggregate_type="notification",
            aggregate_id=new_id,
            payload={},
        )
    return True


def get_preferences(db: Session, p: Principal) -> list[dict[str, object]]:
    rows = {
        r.group: r
        for r in db.scalars(
            select(NotificationPreference).where(
                NotificationPreference.user_id == p.user_id,
                NotificationPreference.organization_id == p.organization_id,
            )
        )
    }
    return [
        {
            "group": g,
            "in_app": rows[g].in_app if g in rows else True,
            "email": rows[g].email if g in rows else True,
        }
        for g in GROUPS
    ]


def set_preferences(
    db: Session, p: Principal, items: list[dict[str, object]]
) -> list[dict[str, object]]:
    for item in items:
        group = str(item["group"])
        if group not in GROUPS:
            continue
        stmt = pg_insert(NotificationPreference).values(
            user_id=p.user_id,
            organization_id=p.organization_id,
            group=group,
            in_app=bool(item["in_app"]),
            email=bool(item["email"]),
        )
        db.execute(
            stmt.on_conflict_do_update(
                index_elements=["user_id", "organization_id", "group"],
                set_={"in_app": stmt.excluded.in_app, "email": stmt.excluded.email},
            )
        )
    db.commit()
    return get_preferences(db, p)


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
