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
    doc = db.scalar(
        select(Document)
        .where(Document.id == version.document_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    assert doc is not None
    version = db.scalar(
        select(DocumentVersion)
        .where(DocumentVersion.id == version_id)
        .with_for_update()
        .execution_options(populate_existing=True)
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
            doc.updated_by = version.created_by or doc.updated_by
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
            event_type="document_version.extract",
            aggregate_type="document_version",
            aggregate_id=version.id,
            payload={"document_id": str(doc.id)},
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


def handle_delete_objects(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.modules.governance.service import handle_delete_objects as run

    run(db, event.payload, get_storage_provider)


def handle_workflow_task_assigned(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.db.models import WorkflowRun, WorkflowTask

    task = db.get(WorkflowTask, event.aggregate_id)
    if task is None or task.status != "pending" or task.organization_id != event.organization_id:
        return
    run = db.get(WorkflowRun, task.run_id)
    doc = db.get(Document, task.document_id)
    if run is None or doc is None:
        return
    notifications.create(
        db,
        organization_id=task.organization_id,
        user_id=task.assignee_id,
        type_="workflow.task_assigned",
        title=f'Approval requested: "{doc.name}"',
        body=f'{_display(db, run.started_by)} asked you to review step "{task.step_name}".',
        resource_type="workflow_task",
        resource_id=task.id,
        source_event_id=event.id,
    )
    db.commit()


def handle_workflow_finished(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.db.models import WorkflowRun

    run = db.get(WorkflowRun, event.aggregate_id)
    if run is None or run.organization_id != event.organization_id:
        return
    doc = db.get(Document, run.document_id)
    state = event.payload.get("state", run.state)
    notifications.create(
        db,
        organization_id=run.organization_id,
        user_id=run.started_by,
        type_=f"workflow.{state}",
        title=f'Approval {state}: "{doc.name if doc else "document"}"',
        body=run.outcome_comment,
        resource_type="workflow_run",
        resource_id=run.id,
        source_event_id=event.id,
    )
    db.commit()


def handle_workflow_task_overdue(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.db.models import WorkflowRun, WorkflowTask

    task = db.get(WorkflowTask, event.aggregate_id)
    if task is None or task.status != "pending":
        return
    run = db.get(WorkflowRun, task.run_id)
    recipients = {task.assignee_id}
    if task.escalate_to_id:
        recipients.add(task.escalate_to_id)
    if run:
        recipients.add(run.started_by)
    for uid in recipients:
        notifications.create(
            db,
            organization_id=task.organization_id,
            user_id=uid,
            type_="workflow.task_overdue",
            title=f'Approval overdue: step "{task.step_name}"',
            resource_type="workflow_task",
            resource_id=task.id,
            source_event_id=event.id,
        )
    db.commit()


def handle_signature_event(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.db.session import get_sessionmaker
    from app.modules.signatures.service import process_event

    process_event(get_sessionmaker(), event.aggregate_id)


def handle_signature_finished(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.db.models import SignatureRequest

    req = db.get(SignatureRequest, event.aggregate_id)
    if req is None or req.organization_id != event.organization_id:
        return
    state = event.payload.get("state", req.state)
    titles = {
        "completed": "Signing completed",
        "declined": "A signer declined",
        "expired": "Signature request expired",
    }
    notifications.create(
        db,
        organization_id=req.organization_id,
        user_id=req.requested_by,
        type_=f"signature.{state}",
        title=f'{titles.get(state, "Signature update")}: "{req.title}"',
        resource_type="signature_request",
        resource_id=req.id,
        source_event_id=event.id,
    )
    db.commit()


def handle_directory_sync(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.db.session import get_sessionmaker
    from app.modules.directory.service import execute_run

    execute_run(get_sessionmaker(), event.aggregate_id)


def handle_notification_email(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    """Deliver a notification by e-mail. Content is deliberately minimal and carries no token:
    e-mail is a pointer to the app, not an authorization (the link requires a normal sign-in)."""
    from app.adapters.email.base import EmailMessage
    from app.db.models import Notification, Organization

    if not mark_processed(db, "notification.email", event.id):
        db.rollback()
        return  # duplicate delivery
    notification = db.get(Notification, event.aggregate_id)
    user = db.get(User, notification.user_id) if notification else None
    if notification is None or user is None or user.status != "active":
        db.commit()
        return
    org = db.get(Organization, notification.organization_id)
    include_titles = bool(((org.settings if org else {}) or {}).get("email_include_titles", False))
    settings = ctx.settings
    subject = f"[{settings.app_name}] New notification"
    lines = ["You have a new notification."]
    if include_titles:
        lines.append(f"\n{notification.title}")
    lines.append(
        f"\nOpen {settings.web_base_url.rstrip('/')}/notifications to view it (sign-in required)."
    )
    ctx.email.send(
        EmailMessage(
            to=user.email,
            subject=subject,
            body_text="\n".join(lines),
            idempotency_key=str(event.id),
        )
    )
    db.commit()


def handle_extract(db: Session, event: OutboxEvent, ctx: WorkerContext) -> None:
    from app.modules.processing.service import process_version

    process_version(db, event.aggregate_id, ctx.settings)


HANDLERS: dict[str, Handler] = {
    "notification.email": handle_notification_email,
    "directory.sync": handle_directory_sync,
    "signature.event": handle_signature_event,
    "signature.finished": handle_signature_finished,
    "workflow.task_assigned": handle_workflow_task_assigned,
    "workflow.finished": handle_workflow_finished,
    "workflow.task_overdue": handle_workflow_task_overdue,
    "document_version.extract": handle_extract,
    "storage.delete_objects": handle_delete_objects,
    "document_version.uploaded": handle_version_uploaded,
    "share.created": handle_share_created,
    "share.revoked": handle_share_revoked,
    "share.expired": handle_share_expired,
    "document.available": handle_document_available,
    "document.quarantined": handle_document_quarantined,
}
