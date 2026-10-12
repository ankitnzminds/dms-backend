"""Storage consistency checks (read-only) and dead-event replay.

* ``find_missing_objects``: versions the database says exist whose object is gone from storage
  (bounded batch, newest first, tenant scoped). Orphan objects (stored but unknown to the database)
  cannot be found because the storage adapter interface has no listing operation; that stays a
  documented limitation. Dead delete events are the usual source of leaked objects, so they can be
  listed and replayed (``list_dead`` / ``replay``).
* Nothing here deletes data. Replay only makes a dead event claimable again (handlers are idempotent).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.storage.registry import get_storage_provider
from app.core.errors import ConflictError, ForbiddenError, NotFoundError
from app.db.enums import OutboxStatus
from app.db.models import Document, DocumentVersion, OutboxEvent, StorageLocation
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal


def _require_admin(p: Principal) -> None:
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required.")


def find_missing_objects(db: Session, p: Principal, *, limit: int, offset: int) -> dict[str, Any]:
    _require_admin(p)
    rows = db.execute(
        select(DocumentVersion, StorageLocation, Document.name)
        .join(StorageLocation, StorageLocation.id == DocumentVersion.storage_location_id)
        .join(Document, Document.id == DocumentVersion.document_id)
        .where(DocumentVersion.organization_id == p.organization_id)
        .order_by(DocumentVersion.created_at.desc(), DocumentVersion.id)
        .limit(limit)
        .offset(offset)
    ).all()
    missing: list[dict[str, Any]] = []
    errors = 0
    for version, location, name in rows:
        try:
            meta = get_storage_provider(location.provider_type).head_object(
                location.bucket, version.object_key
            )
        except Exception:  # the check must not fail the whole batch; report and count
            errors += 1
            continue
        if meta is None:
            missing.append(
                {
                    "document_id": str(version.document_id),
                    "document_name": name,
                    "version_number": version.version_number,
                    "version_id": str(version.id),
                }
            )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="storage.consistency_checked",
        resource_type="organization",
        resource_id=p.organization_id,
        metadata={"checked": len(rows), "missing": len(missing), "errors": errors},
    )
    db.commit()
    return {
        "checked": len(rows),
        "missing": missing,
        "errors": errors,
        "next_offset": offset + len(rows),
    }


def list_dead(db: Session, p: Principal, *, limit: int) -> list[OutboxEvent]:
    _require_admin(p)
    return list(
        db.scalars(
            select(OutboxEvent)
            .where(
                OutboxEvent.organization_id == p.organization_id,
                OutboxEvent.status == OutboxStatus.DEAD.value,
            )
            .order_by(OutboxEvent.created_at.desc())
            .limit(limit)
        )
    )


def replay(db: Session, p: Principal, event_id: uuid.UUID) -> OutboxEvent:
    _require_admin(p)
    event = db.scalar(
        select(OutboxEvent)
        .where(OutboxEvent.id == event_id, OutboxEvent.organization_id == p.organization_id)
        .with_for_update()
    )
    if event is None:
        raise NotFoundError("Event not found.")
    if event.status != OutboxStatus.DEAD.value:
        raise ConflictError("Only a dead event can be replayed.", code="not_dead")
    event.status = OutboxStatus.PENDING.value
    event.attempts = 0
    event.next_attempt_at = datetime.now(UTC)
    event.locked_until = None
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="outbox.event_replayed",
        resource_type="outbox_event",
        resource_id=event.id,
        metadata={"event_type": event.event_type},
    )
    db.commit()
    return event
