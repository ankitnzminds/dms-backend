"""Compare two immutable versions of a document, by file format.

Authorization: the caller needs DOWNLOAD on the document (a comparison reveals content), and both
versions must be scan-clean. Results are cached per (from, to, parser version); versions never
change, so a cached result is always valid. Failures are recorded and shown, never reported as
"no differences".
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.adapters.storage.base import StorageError
from app.adapters.storage.registry import get_storage_provider
from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import Action, ScanStatus
from app.db.models import DocumentVersion, StorageLocation, VersionDiff
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.diffs import ooxml, textual
from app.modules.diffs.core import PARSER_VERSION, Counts, Section
from app.schemas.versions import DiffOut, VersionRef

MAX_COMPARE_BYTES = 25 * 1024 * 1024
OOXML = {"docx": "docx", "xlsx": "xlsx", "pptx": "pptx"}


def _kind(name: str, content_type: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext in OOXML:
        return OOXML[ext]
    if ext == "pdf" or content_type == "application/pdf":
        return "pdf"
    if ext == "json" or content_type == "application/json":
        return "json"
    if ext in ("csv", "tsv") or content_type == "text/csv":
        return "csv"
    if ext in textual.TEXT_EXTENSIONS or content_type.startswith("text/"):
        return "text"
    if content_type.startswith("image/"):
        return "image"
    return "binary"


def _load(db: Session, v: DocumentVersion) -> bytes:
    location = db.get(StorageLocation, v.storage_location_id)
    if location is None:
        raise NotFoundError("Storage location not found.")
    chunks: list[bytes] = []
    size = 0
    try:
        for chunk in get_storage_provider(location.provider_type).stream_object(
            location.bucket, v.object_key
        ):
            size += len(chunk)
            if size > MAX_COMPARE_BYTES:
                raise ValidationFailed("too_large")
            chunks.append(chunk)
    except StorageError as e:
        raise ConflictError("The stored file could not be read.", code="storage_unavailable") from e
    return b"".join(chunks)


def _ref(v: DocumentVersion, current_id: uuid.UUID | None) -> VersionRef:
    return VersionRef(
        version_number=v.version_number,
        size_bytes=v.size_bytes,
        sha256=v.sha256,
        content_type=v.content_type,
        created_by=v.created_by,
        created_at=v.created_at,
        is_current=v.id == current_id,
    )


def _version(db: Session, doc_id: uuid.UUID, org: uuid.UUID, number: int) -> DocumentVersion:
    v = db.scalar(
        select(DocumentVersion).where(
            DocumentVersion.document_id == doc_id,
            DocumentVersion.organization_id == org,
            DocumentVersion.version_number == number,
        )
    )
    if v is None:
        raise NotFoundError("Version not found.")
    if v.scan_status != ScanStatus.CLEAN.value:
        raise ConflictError("This version has not passed required checks.", code="not_released")
    return v


def _run(
    kind: str, old: bytes, new: bytes, counts: Counts
) -> tuple[list[Section], list[str], bool]:
    if kind == "docx":
        return ooxml.diff_docx(old, new, counts)
    if kind == "xlsx":
        return ooxml.diff_xlsx(old, new, counts)
    if kind == "pptx":
        return ooxml.diff_pptx(old, new, counts)
    if kind == "pdf":
        return textual.diff_pdf(old, new, counts)
    if kind == "json":
        return textual.diff_json(old, new, counts)
    if kind == "csv":
        return textual.diff_csv(old, new, counts)
    return textual.diff_text(old, new, counts)


def compare(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, from_n: int, to_n: int
) -> DiffOut:
    p = authz.principal
    if from_n == to_n:
        raise ValidationFailed("Pick two different versions.", code="same_version")
    doc = authz.require_document(document_id, Action.DOWNLOAD)
    authz.require_document(document_id, Action.VIEW_VERSIONS)  # comparing reads two versions
    a = _version(db, doc.id, p.organization_id, from_n)
    b = _version(db, doc.id, p.organization_id, to_n)
    kind = _kind(doc.name, b.content_type)
    base: dict[str, Any] = {
        "document_id": doc.id,
        "from_version": _ref(a, doc.current_version_id),
        "to_version": _ref(b, doc.current_version_id),
        "kind": kind,
        "parser_version": PARSER_VERSION,
    }

    cached = db.scalar(
        select(VersionDiff).where(
            VersionDiff.from_version_id == a.id,
            VersionDiff.to_version_id == b.id,
            VersionDiff.parser_version == PARSER_VERSION,
            VersionDiff.status != "failed",
        )
    )
    if cached is not None and cached.result is not None:
        _audit(db, authz, doc.id, a, b, kind, "cached")
        return DiffOut(**base, **cached.result, cached=True)

    result = _compute(db, a, b, kind)
    db.execute(
        pg_insert(VersionDiff)
        .values(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            document_id=doc.id,
            from_version_id=a.id,
            to_version_id=b.id,
            parser_version=PARSER_VERSION,
            status=result["status"],
            result=result,
            error=(result.get("message") or None) if result["status"] == "failed" else None,
        )
        .on_conflict_do_nothing(constraint="uq_version_diffs_pair")
    )
    _audit(db, authz, doc.id, a, b, kind, result["status"])
    return DiffOut(**base, **result)


def _fail(status: str, message: str) -> dict[str, Any]:
    return {
        "status": status,
        "summary": None,
        "sections": [],
        "notes": [],
        "truncated": False,
        "message": message,
    }


def _compute(db: Session, a: DocumentVersion, b: DocumentVersion, kind: str) -> dict[str, Any]:
    if a.sha256 == b.sha256:
        return {
            "status": "ready",
            "identical": True,
            "summary": {"added": 0, "removed": 0, "changed": 0, "unchanged": 0},
            "sections": [],
            "notes": ["The two versions are byte-for-byte identical (same checksum)."],
            "truncated": False,
        }
    if kind in ("image", "binary"):
        section = Section(
            "Properties",
            [
                {
                    "op": "change",
                    "loc": "size",
                    "old": f"{a.size_bytes} bytes",
                    "new": f"{b.size_bytes} bytes",
                },
                {"op": "change", "loc": "sha256", "old": a.sha256, "new": b.sha256},
                {
                    "op": "change",
                    "loc": "content type",
                    "old": a.content_type,
                    "new": b.content_type,
                },
            ],
        )
        out = _fail("unsupported", "No content comparison exists for this file type.")
        out["sections"] = [section.out()]
        out["notes"] = ["Only the recorded properties are compared."]
        return out
    try:
        old, new = _load(db, a), _load(db, b)
    except ValidationFailed:
        return _fail(
            "too_large",
            f"A version is larger than {MAX_COMPARE_BYTES // (1024 * 1024)} MB; it is not compared inline.",
        )
    counts = Counts()
    try:
        sections, notes, truncated = _run(kind, old, new, counts)
    except ooxml.PackageError as e:
        return _fail("failed", str(e))
    except ValueError:
        return _fail(
            "unsupported", "One of the files is binary or encrypted, so it cannot be compared."
        )
    except Exception:  # a parser bug must never be reported as "no differences"
        return _fail("failed", "The comparison could not be completed for this file.")
    changed = counts.added + counts.removed + counts.changed
    return {
        "status": "ready",
        "identical": changed == 0 and all(s.status == "unchanged" for s in sections),
        "summary": {
            "added": counts.added,
            "removed": counts.removed,
            "changed": counts.changed,
            "unchanged": counts.unchanged,
        },
        "sections": [s.out() for s in sections],
        "notes": notes,
        "truncated": truncated,
    }


def _audit(
    db: Session,
    authz: AuthorizationService,
    doc_id: uuid.UUID,
    a: DocumentVersion,
    b: DocumentVersion,
    kind: str,
    outcome: str,
) -> None:
    p = authz.principal
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.versions_compared",
        resource_type="document",
        resource_id=doc_id,
        metadata={
            "from": a.version_number,
            "to": b.version_number,
            "kind": kind,
            "result": outcome,
        },
    )
    db.commit()
