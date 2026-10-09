"""Outbox event handlers. Each is idempotent: replaying an event never double-applies it."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.adapters.malware.base import ScanResult
from app.adapters.storage.registry import get_storage_provider
from app.core.logging import get_logger
from app.core.metrics import SCANS
from app.db.enums import AuditOutcome, DocumentStatus, Role, ScanStatus
from app.db.models import (
    Document,
    DocumentVersion,
    Membership,
    OutboxEvent,
    ProcessedEvent,
    ShareGrant,
    StorageLocation,
    User,
)
from app.modules.audit import service as audit
from app.modules.notifications import service as notifications
from app.modules.outbox import service as outbox
from app.modules.sharing.service import expand_group_members
from app.workers.runner import Handler, WorkerContext

log = get_logger("app.worker.handlers")


def mark_processed(db: Session, consumer: str, event_id: uuid.UUID) -> bool:
    """True the first time, False on duplicate delivery (for side effects without a natural key)."""
    stmt = (
        pg_insert(ProcessedEvent)
        .values(consumer=consumer, event_id=event_id)
        .on_conflict_do_nothing()
        .returning(ProcessedEvent.event_id)
    )
    return db.execute(stmt).first() is not None


# --------------------------------------------------------------------- scanning
class _HashingStream:
    """Feed the scanner while computing the SHA-256 of exactly the bytes that were scanned."""

    def __init__(self, source: Iterator[bytes]) -> None:
        self._source = source
        self.hasher = hashlib.sha256()
        self.size = 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._source:
            self.hasher.update(chunk)
            self.size += len(chunk)
            yield chunk


def handle_version_uploaded(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    version_id = event.aggregate_id
    org_id = event.organization_id
    version = db.get(DocumentVersion, version_id)
    if version is None or version.organization_id != org_id:
        return  # purged / foreign - nothing to do
    if version.scan_status != ScanStatus.PENDING.value:
        return  # duplicate delivery: already decided
    location = db.get(StorageLocation, version.storage_location_id)
    assert location is not None
    provider = get_storage_provider(location.provider_type)
    bucket, key, expected_sha, expected_size = (
        location.bucket,
        version.object_key,
        version.sha256,
        version.size_bytes,
    )
    db.rollback()  # no transaction held while streaming + scanning

    stream = _HashingStream(provider.stream_object(bucket, key))
    result: ScanResult = ctx.scanner.scan(iter(stream))  # ScannerUnavailableError -> retry
    if result.status == ScanStatus.CLEAN and (
        stream.hasher.hexdigest() != expected_sha or stream.size != expected_size
    ):
        # Stored bytes differ from what was recorded at upload: never release them.
        result = ScanResult(
            ScanStatus.ERROR, result.engine, "integrity check failed (checksum/size mismatch)"
        )

    _apply_scan_result(db, version_id, org_id, result)


def _apply_scan_result(
    db: Session, version_id: uuid.UUID, org_id: uuid.UUID | None, result: ScanResult
) -> None:
    version = db.get(DocumentVersion, version_id)
    assert version is not None
    # Lock order: document, then version (matches the upload/restore paths).
    doc = db.scalar(select(Document).where(Document.id == version.document_id).with_for_update())
    assert doc is not None
    version = db.scalar(
        select(DocumentVersion).where(DocumentVersion.id == version_id).with_for_update()
    )
    assert version is not None
    if version.scan_status != ScanStatus.PENDING.value:
        db.rollback()
        return

    version.scan_status = result.status.value
    version.scan_engine = result.engine
    version.scan_detail = (result.detail or "")[:500] or None
    version.scanned_at = datetime.now(UTC)
    SCANS.labels(result.status.value).inc()

    if result.status == ScanStatus.CLEAN:
        current = (
            db.get(DocumentVersion, doc.current_version_id) if doc.current_version_id else None
        )
        # Promote only forward: a slow scan of v2 must never replace an already-released v3.
        if current is None or version.version_number > current.version_number:
            doc.current_version_id = version.id
        doc.status = DocumentStatus.AVAILABLE.value
        doc.row_version += 1
        audit.record(
            db,
            organization_id=org_id,
            actor_user_id=None,
            action="document.scan_clean",
            resource_type="document",
            resource_id=doc.id,
            metadata={"version_number": version.version_number, "engine": result.engine},
        )
        outbox.enqueue(
            db,
            organization_id=org_id,
            event_type="document.available",
            aggregate_type="document",
            aggregate_id=doc.id,
            payload={"version_id": str(version.id), "version_number": version.version_number},
        )
    else:
        if doc.current_version_id is None:
            doc.status = (
                DocumentStatus.QUARANTINED.value
                if result.status == ScanStatus.INFECTED
                else DocumentStatus.FAILED.value
            )
        doc.row_version += 1
        audit.record(
            db,
            organization_id=org_id,
            actor_user_id=None,
            action="document.quarantined"
            if result.status == ScanStatus.INFECTED
            else "document.scan_failed",
            resource_type="document",
            resource_id=doc.id,
            outcome=AuditOutcome.FAILURE,
            metadata={
                "version_number": version.version_number,
                "engine": result.engine,
                "detail": result.detail,
            },
        )
        outbox.enqueue(
            db,
            organization_id=org_id,
            event_type="document.quarantined",
            aggregate_type="document",
            aggregate_id=doc.id,
            payload={"version_id": str(version.id), "status": result.status.value},
        )
    db.commit()


# ---------------------------------------------------------------- notifications
def _display(db: Session, user_id: uuid.UUID | None) -> str:
    if user_id is None:
        return "Someone"
    u = db.get(User, user_id)
    return (u.display_name or u.email) if u else "Someone"


def handle_share_created(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    share = db.get(ShareGrant, event.aggregate_id)
    if (
        share is None
        or share.organization_id != event.organization_id
        or share.revoked_at is not None
    ):
        return
    name = event.payload.get("name", "an item")
    sharer = _display(db, share.created_by)
    for uid in expand_group_members(db, share.organization_id, share.id) - {share.created_by}:
        notifications.create(
            db,
            organization_id=share.organization_id,
            user_id=uid,
            type_="share.received",
            title=f'{sharer} shared "{name}" with you',
            body="Open Shared with me to view it.",
            resource_type=share.resource_type,
            resource_id=share.resource_id,
            source_event_id=event.id,
        )
    db.commit()


def handle_share_revoked(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    share = db.get(ShareGrant, event.aggregate_id)
    if share is None or share.organization_id != event.organization_id:
        return
    for uid in expand_group_members(db, share.organization_id, share.id) - {share.revoked_by}:
        notifications.create(
            db,
            organization_id=share.organization_id,
            user_id=uid,
            type_="share.revoked",
            title="Access to a shared item was removed",
            resource_type=share.resource_type,
            resource_id=None,
            source_event_id=event.id,
        )
    db.commit()


def handle_share_expired(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    share = db.get(ShareGrant, event.aggregate_id)
    if share is None or share.organization_id != event.organization_id:
        return
    for uid in expand_group_members(db, share.organization_id, share.id) | {share.created_by}:
        notifications.create(
            db,
            organization_id=share.organization_id,
            user_id=uid,
            type_="share.expired",
            title="A shared item has expired",
            resource_type=share.resource_type,
            resource_id=None,
            source_event_id=event.id,
        )
    db.commit()


def handle_document_available(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    doc = db.get(Document, event.aggregate_id)
    version = (
        db.get(DocumentVersion, uuid.UUID(event.payload["version_id"]))
        if event.payload.get("version_id")
        else None
    )
    if (
        doc is None
        or version is None
        or version.created_by is None
        or event.organization_id is None
    ):
        return
    notifications.create(
        db,
        organization_id=event.organization_id,
        user_id=version.created_by,
        type_="document.available",
        title=f'"{doc.name}" is ready',
        body=f"Version {version.version_number} passed all checks.",
        resource_type="document",
        resource_id=doc.id,
        source_event_id=event.id,
    )
    db.commit()


def handle_document_quarantined(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    doc = db.get(Document, event.aggregate_id)
    if doc is None or event.organization_id is None:
        return
    admins = db.scalars(
        select(Membership.user_id).where(
            Membership.organization_id == event.organization_id,
            Membership.role.in_([Role.OWNER.value, Role.ADMIN.value]),
            Membership.status == "active",
        )
    ).all()
    version_id = event.payload.get("version_id")
    uploader = None
    if version_id:
        v = db.get(DocumentVersion, uuid.UUID(version_id))
        uploader = v.created_by if v else None
    for uid in {*admins, *([uploader] if uploader else [])}:
        notifications.create(
            db,
            organization_id=event.organization_id,
            user_id=uid,
            type_="document.quarantined",
            title=f'A file was blocked by security checks: "{doc.name}"',
            resource_type="document",
            resource_id=doc.id,
            source_event_id=event.id,
        )
    db.commit()


HANDLERS: dict[str, Handler] = {
    "document_version.uploaded": handle_version_uploaded,
    "share.created": handle_share_created,
    "share.revoked": handle_share_revoked,
    "share.expired": handle_share_expired,
    "document.available": handle_document_available,
    "document.quarantined": handle_document_quarantined,
}
