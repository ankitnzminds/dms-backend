"""Download a folder as a ZIP archive.

Authorization is per item, not per archive: the caller needs DOWNLOAD on the folder, and every
file is included only if they may download *that file* (anything else is skipped and counted, not
revealed). Only available, scan-clean, non-deleted current versions are included. Entry names are
sanitized (no absolute paths, no ``..``, no control characters) and de-duplicated, and the archive
is bounded (files, total bytes) so it cannot be used to exhaust the server.
"""

from __future__ import annotations

import re
import tempfile
import uuid
import zipfile
from collections import defaultdict
from dataclasses import dataclass
from typing import IO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.storage.base import StorageError
from app.adapters.storage.registry import get_storage_provider
from app.core.errors import ConflictError
from app.db.enums import Action, DocumentStatus, ScanStatus
from app.db.models import Document, DocumentVersion, Folder, StorageLocation
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.documents.locks import assert_download_allowed, download_blocked
from app.modules.folders.common import subtree_folder_ids

MAX_FILES = 2000
MAX_BYTES = 500 * 1024 * 1024
_BAD = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*]')


@dataclass
class Archive:
    file: IO[bytes]
    filename: str
    files: int
    skipped: int
    size: int


def _clean(name: str) -> str:
    cleaned = _BAD.sub("_", name).strip().strip(".")
    return cleaned[:150] or "item"


def build(db: Session, authz: AuthorizationService, folder_id: uuid.UUID) -> Archive:
    p = authz.principal
    root = authz.require_folder(folder_id, Action.DOWNLOAD)
    assert_download_allowed(root, p)
    ids = subtree_folder_ids(db, p.organization_id, root.id)
    folders = {
        f.id: f
        for f in db.scalars(
            select(Folder).where(
                Folder.organization_id == p.organization_id,
                Folder.id.in_(ids),
                Folder.deleted_at.is_(None),
            )
        )
    }
    perms = authz.folder_actions(list(folders))
    visible = {fid for fid in folders if Action.DISCOVER.value in perms.get(fid, ())}

    def rel_path(fid: uuid.UUID) -> list[str] | None:
        parts: list[str] = []
        cur: uuid.UUID | None = fid
        for _ in range(100):
            if cur is None or cur not in folders or cur not in visible:
                return None
            if cur == root.id:
                return list(reversed(parts))
            parts.append(_clean(folders[cur].name))
            cur = folders[cur].parent_folder_id
        return None

    docs = list(
        db.scalars(
            select(Document).where(
                Document.organization_id == p.organization_id,
                Document.folder_id.in_(list(folders) or [uuid.UUID(int=0)]),
                Document.deleted_at.is_(None),
                Document.status == DocumentStatus.AVAILABLE.value,
            )
        )
    )
    doc_perms = authz.document_actions(docs)
    versions = {
        v.id: v
        for v in db.scalars(
            select(DocumentVersion).where(
                DocumentVersion.id.in_(
                    [d.current_version_id for d in docs if d.current_version_id]
                    or [uuid.UUID(int=0)]
                )
            )
        )
    }
    entries: list[tuple[list[str], str, Document, DocumentVersion]] = []
    skipped = 0
    seen: dict[tuple[str, ...], int] = defaultdict(int)
    total = 0
    for d in sorted(docs, key=lambda x: x.name.lower()):
        v = versions.get(d.current_version_id) if d.current_version_id else None
        path = rel_path(d.folder_id)
        if (
            v is None
            or v.scan_status != ScanStatus.CLEAN.value
            or path is None
            or Action.DOWNLOAD.value not in doc_perms.get(d.id, ())
            or download_blocked(d, p)
        ):
            skipped += 1
            continue
        key = (*path, _clean(d.name).lower())
        seen[key] += 1
        name = _clean(d.name)
        if seen[key] > 1:
            stem, dot, ext = name.rpartition(".")
            name = f"{stem or name} ({seen[key]}){dot}{ext}" if dot else f"{name} ({seen[key]})"
        total += v.size_bytes
        entries.append((path, name, d, v))
    if len(entries) > MAX_FILES or total > MAX_BYTES:
        raise ConflictError(
            f"This folder is too large to download as one archive (limit {MAX_FILES} files / {MAX_BYTES // (1024 * 1024)} MB). Download a smaller part.",
            code="archive_too_large",
        )

    tmp = tempfile.SpooledTemporaryFile(max_size=32 * 1024 * 1024)  # noqa: SIM115 - closed by the response
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            for path, name, _doc, v in entries:
                location = db.get(StorageLocation, v.storage_location_id)
                if location is None:
                    skipped += 1
                    continue
                info = zipfile.ZipInfo(
                    "/".join([*path, name]),
                    date_time=(
                        v.created_at.year if v.created_at.year >= 1980 else 1980,
                        v.created_at.month,
                        v.created_at.day,
                        v.created_at.hour,
                        v.created_at.minute,
                        v.created_at.second,
                    ),
                )
                info.compress_type = zipfile.ZIP_DEFLATED
                try:
                    with zf.open(info, "w") as out:
                        for chunk in get_storage_provider(location.provider_type).stream_object(
                            location.bucket, v.object_key
                        ):
                            out.write(chunk)
                except StorageError:
                    skipped += 1
    except Exception:
        tmp.close()
        raise
    size = tmp.seek(0, 2)
    tmp.seek(0)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="folder.downloaded",
        resource_type="folder",
        resource_id=root.id,
        metadata={"files": len(entries), "skipped": skipped, "archive_bytes": size},
    )
    db.commit()
    return Archive(
        file=tmp,
        filename=f"{_clean(root.name)}.zip",
        files=len(entries),
        skipped=skipped,
        size=size,
    )
