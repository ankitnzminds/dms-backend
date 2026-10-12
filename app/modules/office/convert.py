"""Download as PDF: server-side conversion by the office engine (Collabora ``/cool/convert-to``).

The caller needs DOWNLOAD on the document; the bytes of the *current, scan-clean* version are
sent to the office server over the private network and the PDF comes straight back. Nothing is
stored (the conversion is an on-demand export, not a new version), nothing is public, and the
result is returned with ``Cache-Control: no-store``.

The conversion runs inside the request with a hard timeout and a size cap: it is bounded and
synchronous. A queued conversion for very large files is listed as deferred in the status matrix.
"""

from __future__ import annotations

import uuid

import httpx
from sqlalchemy.orm import Session

from app.adapters.storage.base import StorageError
from app.adapters.storage.registry import get_storage_provider
from app.core.config import get_settings
from app.core.errors import ConflictError, DependencyUnavailableError, ValidationFailed
from app.db.enums import Action
from app.db.models import DocumentVersion, StorageLocation
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.documents.downloads import _servable_version
from app.modules.documents.locks import assert_download_allowed
from app.modules.office import formats

CONVERTIBLE = formats.SUPPORTED | {"txt", "csv", "md"}
TIMEOUT_SECONDS = 90


def _base_url() -> str:
    s = get_settings()
    if s.effective_office_provider != "collabora":
        raise DependencyUnavailableError(
            "PDF export is not available: no office server is configured.",
            code="office_unavailable",
        )
    return (
        (s.collabora_discovery_url or s.collabora_url)
        .rstrip("/")
        .removesuffix("/hosting/discovery")
    )


def _bytes(db: Session, version: DocumentVersion) -> bytes:
    location = db.get(StorageLocation, version.storage_location_id)
    if location is None:
        raise ConflictError("The stored file could not be found.", code="storage_unavailable")
    try:
        return b"".join(
            get_storage_provider(location.provider_type).stream_object(
                location.bucket, version.object_key
            )
        )
    except StorageError as e:
        raise ConflictError("The stored file could not be read.", code="storage_unavailable") from e


def to_pdf(db: Session, authz: AuthorizationService, document_id: uuid.UUID) -> tuple[bytes, str]:
    p = authz.principal
    doc = authz.require_document(document_id, Action.DOWNLOAD)
    assert_download_allowed(doc, p)
    ext = formats.extension(doc.name)
    if ext == "pdf":
        raise ValidationFailed(
            "This file is already a PDF. Download it directly.", code="already_pdf"
        )
    if ext not in CONVERTIBLE:
        raise ValidationFailed("This file type cannot be converted to PDF.", code="not_convertible")
    version = _servable_version(db, p.organization_id, doc, None)  # scan gate + quarantine
    if version.size_bytes > get_settings().office_max_bytes:
        raise ConflictError("This file is too large to convert.", code="office_too_large")
    data = _bytes(db, version)
    base = _base_url()
    try:
        resp = httpx.post(
            f"{base}/cool/convert-to/pdf",
            files={"data": (f"document.{ext}", data)},
            timeout=TIMEOUT_SECONDS,
        )
    except httpx.HTTPError as e:
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="document.exported_pdf",
            resource_type="document",
            resource_id=doc.id,
            outcome=_failure(),
            metadata={"reason": "unreachable"},
        )
        db.commit()
        raise DependencyUnavailableError(
            "The office server could not be reached.", code="office_unavailable"
        ) from e
    if resp.status_code != 200 or not resp.content.startswith(b"%PDF"):
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="document.exported_pdf",
            resource_type="document",
            resource_id=doc.id,
            outcome=_failure(),
            metadata={"status": resp.status_code},
        )
        db.commit()
        raise ConflictError(
            "The office server could not convert this file.", code="conversion_failed"
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.exported_pdf",
        resource_type="document",
        resource_id=doc.id,
        metadata={"version_number": version.version_number, "pdf_bytes": len(resp.content)},
    )
    db.commit()
    stem = doc.name.rsplit(".", 1)[0] or "document"
    return resp.content, f"{stem}.pdf"


def _failure():  # noqa: ANN202
    from app.db.enums import AuditOutcome

    return AuditOutcome.FAILURE
