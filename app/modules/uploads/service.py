"""Upload sessions: initiate -> receive bytes (private staging) -> finalize -> (worker) scan -> available.

State machine:  initiated -> uploaded -> finalized      (terminal: failed | cancelled | expired)

* Quota is *reserved* at initiate, *committed* at finalize and *released* on any failure,
  cancellation or expiry (idempotent ledger, see app.modules.quota).
* Bytes are written to a private object under an opaque key. They are not downloadable until
  the malware scan marks the version ``clean`` (done by the worker); the document stays
  ``processing`` until then.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import BinaryIO

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters.storage.base import StorageError, new_object_key
from app.adapters.storage.registry import get_storage_provider
from app.core.config import get_settings
from app.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    PayloadTooLargeError,
    QuotaExceededError,
    ValidationFailed,
)
from app.core.logging import get_logger
from app.core.metrics import UPLOADS
from app.core.naming import split_extension, validate_name
from app.db.enums import Action, AuditOutcome, DocumentStatus, ScanStatus, UploadState
from app.db.models import Document, DocumentVersion, Membership, StorageLocation, UploadSession
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import ensure_name_free, plain_path
from app.modules.identity.principal import Principal
from app.modules.outbox import service as outbox
from app.modules.quota import service as quota
from app.modules.sharing import quota as share_quota

log = get_logger(__name__)

MAX_ACTIVE_SESSIONS_PER_USER = 25
_CONTENT_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+$")
_ACTIVE = (UploadState.INITIATED.value, UploadState.UPLOADED.value)
# Executable containers are refused regardless of the claimed extension/type.
_EXECUTABLE_MAGIC = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)


def normalize_content_type(value: str | None) -> str:
    value = (value or "").split(";")[0].strip().lower()
    return (
        value
        if value and len(value) <= 127 and _CONTENT_TYPE_RE.match(value)
        else "application/octet-stream"
    )


_TEXT_CLAIMS = {"text/plain", "text/csv", "text/markdown", "application/json"}
_PREVIEWABLE_CLAIMS = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    *_TEXT_CLAIMS,
}


def sniff_content_type(head: bytes, claimed: str) -> str:
    """The client-claimed type is untrusted. Known binary formats are identified from magic
    bytes; a claim of a *previewable* type that the content does not back is downgraded to
    ``application/octet-stream`` so it can never be rendered inline."""
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if claimed in _TEXT_CLAIMS and not any(b < 9 or 13 < b < 32 for b in head):
        return claimed
    if claimed in _PREVIEWABLE_CLAIMS:
        return "application/octet-stream"
    return claimed


def _validate_filename(raw: str) -> str:
    name = validate_name(raw, what="Filename")
    ext = split_extension(name)
    if ext and ext in get_settings().blocked_extension_set:
        raise ValidationFailed(f"Files of type .{ext} are not allowed.", code="blocked_file_type")
    return name


def _default_location(db: Session, organization_id: uuid.UUID) -> StorageLocation:
    location = db.scalar(
        select(StorageLocation).where(
            StorageLocation.organization_id == organization_id,
            StorageLocation.is_default.is_(True),
            StorageLocation.status == "active",
        )
    )
    if location is None:
        raise DependencyUnavailableError("No active storage location is configured.")
    return location


def _existing_for_key(db: Session, p, key: str) -> UploadSession | None:  # noqa: ANN001
    return db.scalar(
        select(UploadSession).where(
            UploadSession.organization_id == p.organization_id,
            UploadSession.created_by == p.user_id,
            UploadSession.idempotency_key == key,
        )
    )


def _enforce_account_limits(db: Session, p: Principal, size_bytes: int) -> None:
    """Access level and per-user policy limits (guest/external accounts have no storage)."""
    from app.modules.admin_users.service import used_bytes_by
    from app.modules.policies import service as policies

    level = db.scalar(
        select(Membership.access_level).where(
            Membership.organization_id == p.organization_id, Membership.user_id == p.user_id
        )
    )
    if level and level != "full":
        raise ForbiddenError(
            f"{level.capitalize()} accounts have no storage and cannot upload.",
            code="no_storage_access",
        )
    values = policies.effective(db, p.organization_id, p.user_id).values
    max_upload = int(values["user_policy"]["max_upload_bytes"])
    if max_upload and size_bytes > max_upload:
        raise PayloadTooLargeError(
            f"Your policy limits uploads to {max_upload} bytes.", code="policy_upload_limit"
        )
    quota = int(values["general"]["user_storage_quota_bytes"])
    if quota and used_bytes_by(db, p.organization_id, p.user_id) + size_bytes > quota:
        raise QuotaExceededError(
            "Your personal storage quota would be exceeded.", code="user_quota"
        )


def _folder_right(intent: str) -> Action:
    """What a folder must allow for a NEW file: Create File for "create a file", Upload otherwise."""
    return Action.CREATE_FILE if intent == "create_file" else Action.UPLOAD


def initiate(
    db: Session,
    authz: AuthorizationService,
    *,
    folder_id: uuid.UUID | None,
    document_id: uuid.UUID | None,
    filename: str,
    size_bytes: int,
    content_type: str | None,
    sha256: str | None,
    expected_latest_version: int | None,
    idempotency_key: str | None,
    intent: str = "upload",
) -> UploadSession:
    p = authz.principal
    settings = get_settings()
    name = _validate_filename(filename)
    if size_bytes <= 0:
        raise ValidationFailed("File must not be empty.")
    if size_bytes > settings.max_upload_bytes:
        raise PayloadTooLargeError(
            f"File exceeds the maximum size of {settings.max_upload_bytes} bytes."
        )
    if sha256 is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValidationFailed("sha256 must be 64 hexadecimal characters.")
    _enforce_account_limits(db, p, size_bytes)

    if idempotency_key:
        existing = _existing_for_key(db, p, idempotency_key)
        if existing is not None:
            same = (
                existing.filename == name
                and existing.declared_size == size_bytes
                and existing.folder_id == (folder_id or existing.folder_id)
                and existing.document_id == document_id
            )
            if not same:
                raise ConflictError(
                    "Idempotency-Key was already used for a different request.",
                    code="idempotency_mismatch",
                )
            return existing

    if document_id is not None:
        doc = authz.require_document(document_id, Action.UPLOAD_VERSION)
        from app.modules.documents.locks import assert_unlocked_for

        assert_unlocked_for(db, doc, p)
        if expected_latest_version is None:
            raise ValidationFailed(
                "expected_latest_version is required when uploading a new version."
            )
        if expected_latest_version != doc.latest_version_number:
            raise ConflictError(
                "The document has a newer version. Reload and try again.", code="stale_version"
            )
        target_folder = doc.folder_id
    else:
        assert folder_id is not None
        folder = authz.require_folder(folder_id, _folder_right(intent))
        ensure_name_free(db, p.organization_id, folder.id, name)
        target_folder = folder.id
    share_quota.check(db, p, target_folder, size_bytes)

    active = db.scalar(
        select(func.count()).where(
            UploadSession.organization_id == p.organization_id,
            UploadSession.created_by == p.user_id,
            UploadSession.state.in_(_ACTIVE),
            UploadSession.expires_at > datetime.now(UTC),
        )
    )
    if (active or 0) >= MAX_ACTIVE_SESSIONS_PER_USER:
        raise ConflictError(
            "Too many uploads in progress. Finish or cancel some first.", code="too_many_uploads"
        )

    location = _default_location(db, p.organization_id)
    session = UploadSession(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        folder_id=target_folder,
        document_id=document_id,
        expected_latest_version=expected_latest_version,
        intent=intent if intent in ("upload", "create_file") else "upload",
        created_by=p.user_id,
        filename=name,
        content_type=normalize_content_type(content_type),
        declared_size=size_bytes,
        declared_sha256=sha256.lower() if sha256 else None,
        storage_location_id=location.id,
        object_key=new_object_key(p.organization_id),
        reserved_bytes=size_bytes,
        idempotency_key=idempotency_key,
        expires_at=datetime.now(UTC) + timedelta(seconds=settings.upload_session_ttl_seconds),
    )
    db.add(session)
    try:
        db.flush()
        quota.reserve(
            db,
            organization_id=p.organization_id,
            upload_session_id=session.id,
            size_bytes=size_bytes,
        )
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("Duplicate upload request.", code="duplicate_request") from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="upload.initiated",
        resource_type="upload_session",
        resource_id=session.id,
        metadata={"size_bytes": size_bytes, "new_version": document_id is not None},
    )
    db.commit()
    UPLOADS.labels("initiated").inc()
    return session


def get_session(db: Session, authz: AuthorizationService, session_id: uuid.UUID) -> UploadSession:
    p = authz.principal
    session = db.scalar(
        select(UploadSession).where(
            UploadSession.id == session_id, UploadSession.organization_id == p.organization_id
        )
    )
    # Upload sessions are private to their creator (even admins cannot push bytes into them).
    if session is None or session.created_by != p.user_id:
        raise NotFoundError("Upload session not found.")
    return session


def _fail(
    db: Session, session: UploadSession, reason: str, *, state: UploadState = UploadState.FAILED
) -> None:
    """Terminal transition + quota release + staged object cleanup (best effort, reconciled later)."""
    if session.state in (UploadState.FINALIZED.value,):
        return
    was_active = session.state in _ACTIVE
    session.state = state.value
    session.failure_reason = reason[:500]
    if was_active:
        quota.release(
            db,
            organization_id=session.organization_id,
            upload_session_id=session.id,
            reserved_bytes=session.reserved_bytes,
            reason=reason,
        )
    audit.record(
        db,
        organization_id=session.organization_id,
        actor_user_id=session.created_by,
        action=f"upload.{state.value}",
        resource_type="upload_session",
        resource_id=session.id,
        outcome=AuditOutcome.FAILURE if state == UploadState.FAILED else AuditOutcome.SUCCESS,
        metadata={"reason": reason[:200]},
    )
    db.commit()
    UPLOADS.labels(state.value).inc()
    _delete_object_quietly(db, session)


def _delete_object_quietly(db: Session, session: UploadSession) -> None:
    location = db.get(StorageLocation, session.storage_location_id)
    if location is None:
        return
    try:
        get_storage_provider(location.provider_type).delete_object(
            location.bucket, session.object_key
        )
    except Exception:
        # Best effort: the object is unreferenced and will be reconciled by the cleanup sweep.
        log.warning("staged_object_cleanup_failed", extra={"upload_session_id": str(session.id)})


def prepare_content(
    db: Session, authz: AuthorizationService, session_id: uuid.UUID
) -> UploadSession:
    """Checks that must pass *before* any bytes are read from the client."""
    session = get_session(db, authz, session_id)
    if session.state != UploadState.INITIATED.value:
        raise ConflictError(f"Upload session is {session.state}.", code="invalid_state")
    if session.expires_at <= datetime.now(UTC):
        _fail(db, session, "expired", state=UploadState.EXPIRED)
        raise ConflictError("Upload session has expired.", code="session_expired")
    # Permission is re-checked at the moment bytes arrive (it may have changed since initiate).
    if session.document_id:
        authz.require_document(session.document_id, Action.UPLOAD_VERSION)
    else:
        authz.require_folder(session.folder_id, _folder_right(session.intent))
    db.rollback()  # release the connection while the (possibly slow) body is streamed
    return session


def store_content(
    db: Session,
    authz: AuthorizationService,
    session_id: uuid.UUID,
    data: BinaryIO,
    received_size: int,
    received_sha256: str,
    head: bytes,
) -> UploadSession:
    session = get_session(db, authz, session_id)
    if session.state != UploadState.INITIATED.value:
        raise ConflictError(f"Upload session is {session.state}.", code="invalid_state")

    if received_size != session.declared_size:
        _fail(db, session, "size_mismatch")
        raise ValidationFailed(
            "Uploaded size does not match the declared size.", code="size_mismatch"
        )
    if session.declared_sha256 and session.declared_sha256 != received_sha256:
        _fail(db, session, "checksum_mismatch")
        raise ValidationFailed(
            "Uploaded content does not match the declared SHA-256.", code="checksum_mismatch"
        )
    if head.startswith(_EXECUTABLE_MAGIC):
        _fail(db, session, "executable_content")
        raise ValidationFailed("Executable content is not allowed.", code="blocked_file_type")

    location = db.get(StorageLocation, session.storage_location_id)
    assert location is not None
    provider = get_storage_provider(location.provider_type)
    object_key, bucket, size = session.object_key, location.bucket, session.declared_size
    db.rollback()  # no DB locks while talking to storage
    try:
        data.seek(0)
        provider.put_object(bucket, object_key, data, size, session.content_type)
        meta = provider.head_object(bucket, object_key)
        if meta is None or meta.size != size:
            raise StorageError("stored size mismatch")
    except StorageError as exc:
        log.warning(
            "upload_storage_failed", extra={"error": str(exc), "upload_id": str(session_id)}
        )
        session = get_session(db, authz, session_id)
        _fail(db, session, "storage_error")
        raise DependencyUnavailableError("Storage rejected the upload. Please retry.") from exc

    locked = db.scalar(
        select(UploadSession)
        .where(UploadSession.id == session_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    assert locked is not None
    if locked.state != UploadState.INITIATED.value:  # cancelled/expired concurrently
        _delete_object_quietly(db, locked)
        raise ConflictError(f"Upload session is {locked.state}.", code="invalid_state")
    locked.state = UploadState.UPLOADED.value
    locked.content_type = sniff_content_type(head, locked.content_type)
    locked.received_size = received_size
    locked.received_sha256 = received_sha256
    db.commit()
    return locked


def finalize(
    db: Session, authz: AuthorizationService, session_id: uuid.UUID
) -> tuple[Document, DocumentVersion]:
    p = authz.principal
    session = db.scalar(
        select(UploadSession)
        .where(UploadSession.id == session_id, UploadSession.organization_id == p.organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if session is None or session.created_by != p.user_id:
        raise NotFoundError("Upload session not found.")

    if session.state == UploadState.FINALIZED.value:  # idempotent retry
        version = db.get(DocumentVersion, session.result_version_id)
        assert version is not None
        return db.get(Document, version.document_id), version  # type: ignore[return-value]
    if session.state != UploadState.UPLOADED.value:
        raise ConflictError(
            f"Upload session is {session.state}; upload the content first.", code="invalid_state"
        )

    # Re-authorize at the commit point.
    if session.document_id:
        authz.require_document(session.document_id, Action.UPLOAD_VERSION)
    else:
        authz.require_folder(session.folder_id, _folder_right(session.intent))

    try:
        if session.document_id:
            doc = db.scalar(
                select(Document)
                .where(
                    Document.id == session.document_id,
                    Document.organization_id == p.organization_id,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
            if doc is None or doc.deleted_at is not None:
                raise NotFoundError("Document not found.")
            # Optimistic concurrency: a concurrent new version since initiate wins; we do not
            # silently overwrite it.
            if doc.latest_version_number != session.expected_latest_version:
                _fail(db, session, "stale_version")
                raise ConflictError(
                    "The document has a newer version. Reload and try again.", code="stale_version"
                )
            doc.latest_version_number += 1
            doc.row_version += 1
            doc.updated_by = p.user_id
            version_number = doc.latest_version_number
            action = "document.version_created"
        else:
            ensure_name_free(db, p.organization_id, session.folder_id, session.filename)
            doc = Document(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                folder_id=session.folder_id,
                name=session.filename,
                owner_id=p.user_id,
                updated_by=p.user_id,
                status=DocumentStatus.PROCESSING.value,
                latest_version_number=1,
            )
            db.add(doc)
            db.flush()
            version_number = 1
            action = "document.created"

        version = DocumentVersion(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            document_id=doc.id,
            version_number=version_number,
            storage_location_id=session.storage_location_id,
            object_key=session.object_key,
            size_bytes=session.received_size or session.declared_size,
            sha256=session.received_sha256 or "",
            content_type=session.content_type,
            original_filename=session.filename,
            created_by=p.user_id,
            scan_status=ScanStatus.PENDING.value,
        )
        db.add(version)
        db.flush()
        quota.commit(
            db,
            organization_id=p.organization_id,
            upload_session_id=session.id,
            reserved_bytes=session.reserved_bytes,
            actual_bytes=version.size_bytes,
            document_version_id=version.id,
        )
        share_quota.charge(db, p, session.folder_id, version.size_bytes)
        session.state = UploadState.FINALIZED.value
        session.result_version_id = version.id
        outbox.enqueue(
            db,
            organization_id=p.organization_id,
            event_type="document_version.uploaded",
            aggregate_type="document_version",
            aggregate_id=version.id,
            payload={"document_id": str(doc.id), "version_number": version_number},
        )
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action=action,
            resource_type="document",
            resource_id=doc.id,
            metadata={
                "version_number": version_number,
                "size_bytes": version.size_bytes,
                "sha256": version.sha256,
                "path": f"{plain_path(db, p.organization_id, doc.folder_id)}/{doc.name}",
            },
        )
        from app.modules.documents.service import touch_recent

        touch_recent(db, p.user_id, doc, "uploaded")
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError(
            "A file or folder with this name already exists here.", code="name_conflict"
        ) from exc
    UPLOADS.labels("finalized").inc()
    return doc, version


def cancel(db: Session, authz: AuthorizationService, session_id: uuid.UUID) -> None:
    session = get_session(db, authz, session_id)
    if session.state == UploadState.FINALIZED.value:
        raise ConflictError("Upload already finalized.", code="invalid_state")
    if session.state in _ACTIVE:
        _fail(db, session, "cancelled_by_user", state=UploadState.CANCELLED)


def expire_stale_sessions(db: Session, *, limit: int = 100) -> int:
    """Maintenance: release reservations of abandoned uploads and clean their staged objects."""
    stale = list(
        db.scalars(
            select(UploadSession)
            .where(UploadSession.state.in_(_ACTIVE), UploadSession.expires_at <= datetime.now(UTC))
            .order_by(UploadSession.expires_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
            .execution_options(populate_existing=True)
        )
    )
    for session in stale:
        _fail(db, session, "expired", state=UploadState.EXPIRED)
    return len(stale)


__all__ = ["ForbiddenError"]
