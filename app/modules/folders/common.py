"""Shared tree helpers (name collisions, plain paths for audit, subtree traversal)."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.errors import ConflictError
from app.db.models import Document, Folder

_SUBTREE_SQL = text(
    """
    WITH RECURSIVE sub(id, depth) AS (
      SELECT f.id, 0 FROM dms.folders f WHERE f.id = :root AND f.organization_id = :org
      UNION ALL
      SELECT c.id, s.depth + 1
        FROM sub s JOIN dms.folders c ON c.parent_folder_id = s.id AND c.organization_id = :org
       WHERE s.depth < 100
    )
    SELECT id FROM sub
    """
)

_LIVE_SUBTREE_SQL = text(
    """
    WITH RECURSIVE sub(id, depth) AS (
      SELECT f.id, 0 FROM dms.folders f
       WHERE f.id = :root AND f.organization_id = :org AND f.deleted_at IS NULL
      UNION ALL
      SELECT c.id, s.depth + 1
        FROM sub s JOIN dms.folders c
          ON c.parent_folder_id = s.id AND c.organization_id = :org AND c.deleted_at IS NULL
       WHERE s.depth < 100
    )
    SELECT id FROM sub
    """
)

_PATH_SQL = text(
    """
    WITH RECURSIVE up(id, parent_id, name, depth) AS (
      SELECT f.id, f.parent_folder_id, f.name, 0 FROM dms.folders f
       WHERE f.id = :fid AND f.organization_id = :org
      UNION ALL
      SELECT p.id, p.parent_folder_id, p.name, u.depth + 1
        FROM up u JOIN dms.folders p ON p.id = u.parent_id AND p.organization_id = :org
       WHERE u.depth < 100
    )
    SELECT name FROM up ORDER BY depth DESC
    """
)


def subtree_folder_ids(
    db: Session, organization_id: uuid.UUID, root_id: uuid.UUID
) -> list[uuid.UUID]:
    """The folder and all its descendants (including already-deleted ones)."""
    return list(db.scalars(_SUBTREE_SQL, {"root": root_id, "org": organization_id}))


def live_subtree_folder_ids(
    db: Session, organization_id: uuid.UUID, root_id: uuid.UUID
) -> list[uuid.UUID]:
    """The folder and its descendants that are not in the recycle bin."""
    return list(db.scalars(_LIVE_SUBTREE_SQL, {"root": root_id, "org": organization_id}))


def plain_path(db: Session, organization_id: uuid.UUID, folder_id: uuid.UUID) -> str:
    """Unfiltered canonical path for audit records (never returned to unauthorized callers)."""
    names = list(db.scalars(_PATH_SQL, {"fid": folder_id, "org": organization_id}))
    return "/".join(names)


def name_taken(
    db: Session,
    organization_id: uuid.UUID,
    folder_id: uuid.UUID,
    name: str,
    *,
    exclude_folder_id: uuid.UUID | None = None,
    exclude_document_id: uuid.UUID | None = None,
) -> bool:
    lowered = name.lower()
    folder_q = select(func.count()).where(
        Folder.organization_id == organization_id,
        Folder.parent_folder_id == folder_id,
        func.lower(Folder.name) == lowered,
        Folder.deleted_at.is_(None),
    )
    if exclude_folder_id:
        folder_q = folder_q.where(Folder.id != exclude_folder_id)
    doc_q = select(func.count()).where(
        Document.organization_id == organization_id,
        Document.folder_id == folder_id,
        func.lower(Document.name) == lowered,
        Document.deleted_at.is_(None),
    )
    if exclude_document_id:
        doc_q = doc_q.where(Document.id != exclude_document_id)
    return bool(db.scalar(folder_q) or db.scalar(doc_q))


def ensure_name_free(
    db: Session,
    organization_id: uuid.UUID,
    folder_id: uuid.UUID,
    name: str,
    **exclude: uuid.UUID | None,
) -> None:
    if name_taken(db, organization_id, folder_id, name, **exclude):
        raise ConflictError(
            "A file or folder with this name already exists here.", code="name_conflict"
        )
