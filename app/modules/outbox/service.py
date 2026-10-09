"""Transactional outbox: events are inserted in the same transaction as the business change."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models import OutboxEvent


def enqueue(
    db: Session,
    *,
    organization_id: uuid.UUID | None,
    event_type: str,
    aggregate_type: str,
    aggregate_id: uuid.UUID,
    payload: dict[str, Any] | None = None,
) -> OutboxEvent:
    event = OutboxEvent(
        id=uuid.uuid4(),
        organization_id=organization_id,
        event_type=event_type,
        aggregate_type=aggregate_type,
        aggregate_id=aggregate_id,
        payload=payload or {},
        max_attempts=get_settings().outbox_max_attempts,
    )
    db.add(event)
    return event
