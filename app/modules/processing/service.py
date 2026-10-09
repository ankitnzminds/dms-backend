"""Text extraction + thumbnail pipeline (worker side) and processing status (API side).

Derived data (text, thumbnails) is only produced for versions that passed the malware scan,
carries the same ACL as its source (checked on every read) and is removed with the source.
"""

from __future__ import annotations

import json
import os
import subprocess  # noqa: S404  (fixed argv, no shell)
import sys
import tempfile
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.storage.base import new_object_key
from app.adapters.storage.registry import get_storage_provider
from app.core.config import Settings
from app.core.logging import get_logger
from app.db.enums import ScanStatus
from app.db.models import DocumentDerivative, DocumentText, DocumentVersion, StorageLocation

log = get_logger(__name__)

_MAX_CHILD_OUTPUT = 8 * 1024 * 1024
_MIN_ENV = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "LANG", "LC_ALL")


class ExtractionChildError(Exception):
    pass


def _posix_limits(timeout: int) -> Callable[[], None] | None:  # type: ignore[return] # pragma: no cover
    if os.name != "posix":
        return None

    def apply() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout + 5))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))

    return apply


def run_child(request: dict[str, Any], timeout: int) -> dict[str, Any]:
    """Run the extractor in a separate, minimally-privileged process."""
    env = {k: os.environ[k] for k in _MIN_ENV if k in os.environ}
    try:
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-I", "-m", "app.workers.extract_child"],
            input=json.dumps(request).encode(),
            capture_output=True,
            timeout=timeout,
            env=env,
            cwd=request["out_dir"],
            preexec_fn=_posix_limits(timeout),  # noqa: PLW1509
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ExtractionChildError("extraction timed out") from exc
    if proc.returncode != 0 or len(proc.stdout) > _MAX_CHILD_OUTPUT:
        raise ExtractionChildError(f"extractor exited with code {proc.returncode}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ExtractionChildError("extractor returned invalid output") from exc


def process_version(db: Session, version_id: uuid.UUID, settings: Settings) -> str:
    """Idempotent: a version that already has a text record is skipped. Returns the status."""
    version = db.get(DocumentVersion, version_id)
    if version is None or version.scan_status != ScanStatus.CLEAN.value:
        return "skipped"
    if db.get(DocumentText, version_id) is not None:
        return "exists"
    location = db.get(StorageLocation, version.storage_location_id)
    assert location is not None
    provider = get_storage_provider(location.provider_type)
    org_id, doc_id = version.organization_id, version.document_id
    size: int = version.size_bytes
    content_type: str = version.content_type
    filename: str = version.original_filename
    bucket: str = location.bucket
    key: str = version.object_key
    loc_id: uuid.UUID = location.id
    db.rollback()  # nothing is held while the (slow) parser runs

    status, text, truncated, engine, error = "unsupported", "", False, None, None
    thumb_bytes: bytes | None = None
    if size > settings.extract_max_bytes:
        status, error = "unsupported", "file too large for content extraction"
    else:
        with tempfile.TemporaryDirectory(prefix="dms-extract-") as tmp:
            src = Path(tmp) / "input.bin"
            with src.open("wb") as out:
                for chunk in provider.stream_object(bucket, key):
                    out.write(chunk)
            try:
                result = run_child(
                    {
                        "path": str(src),
                        "content_type": content_type,
                        "filename": filename,
                        "max_chars": settings.extract_max_chars,
                        "max_pages": settings.extract_max_pages,
                        "out_dir": tmp,
                        "ocr_command": settings.ocr_command,
                    },
                    settings.extract_timeout_seconds,
                )
                status, text = result["status"], result.get("text") or ""
                truncated, engine, error = (
                    result["truncated"],
                    result.get("engine"),
                    result.get("error"),
                )
                if result.get("thumbnail"):
                    thumb_bytes = Path(result["thumbnail"]).read_bytes()
            except ExtractionChildError as exc:
                status, error = "failed", str(exc)[:300]

    derivative_key: str | None = None
    if thumb_bytes:
        import io

        derivative_key = new_object_key(org_id)
        provider.put_object(
            bucket, derivative_key, io.BytesIO(thumb_bytes), len(thumb_bytes), "image/png"
        )

    if db.get(DocumentText, version_id) is None:
        db.add(
            DocumentText(
                version_id=version_id,
                organization_id=org_id,
                document_id=doc_id,
                status=status,
                engine=engine,
                char_count=len(text),
                truncated=truncated,
                content=text or None,
                error=(error or None) and error[:300],
            )
        )
        if derivative_key and thumb_bytes:
            db.add(
                DocumentDerivative(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    version_id=version_id,
                    kind="thumbnail",
                    storage_location_id=loc_id,
                    object_key=derivative_key,
                    content_type="image/png",
                    size_bytes=len(thumb_bytes),
                )
            )
        db.commit()
    elif derivative_key:  # concurrent worker won: drop our orphan
        provider.delete_object(bucket, derivative_key)
    return status


def derivative_for(
    db: Session, version_id: uuid.UUID, kind: str = "thumbnail"
) -> DocumentDerivative | None:
    return db.scalar(
        select(DocumentDerivative).where(
            DocumentDerivative.version_id == version_id, DocumentDerivative.kind == kind
        )
    )
