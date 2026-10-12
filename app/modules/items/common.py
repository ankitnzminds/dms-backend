"""Helpers shared by the file-manager style listings (who modified, favorites, locks)."""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Document, DocumentStar, Folder, FolderFavorite, User
from app.schemas.common import UserRef
from app.schemas.tree import LockOut


def user_refs(db: Session, ids: Iterable[uuid.UUID | None]) -> dict[uuid.UUID, UserRef]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return {
        u.id: UserRef(id=u.id, display_name=u.display_name, email=u.email)
        for u in db.scalars(select(User).where(User.id.in_(wanted)))
    }


def folder_favorites(
    db: Session, user_id: uuid.UUID, folder_ids: Iterable[uuid.UUID]
) -> set[uuid.UUID]:
    ids = list(folder_ids)
    if not ids:
        return set()
    return set(
        db.scalars(
            select(FolderFavorite.folder_id).where(
                FolderFavorite.user_id == user_id, FolderFavorite.folder_id.in_(ids)
            )
        )
    )


def document_stars(db: Session, user_id: uuid.UUID, doc_ids: Iterable[uuid.UUID]) -> set[uuid.UUID]:
    ids = list(doc_ids)
    if not ids:
        return set()
    return set(
        db.scalars(
            select(DocumentStar.document_id).where(
                DocumentStar.user_id == user_id, DocumentStar.document_id.in_(ids)
            )
        )
    )


def lock_active(doc: Document | Folder, now: datetime | None = None) -> bool:
    if doc.locked_by is None:
        return False
    now = now or datetime.now(UTC)
    return doc.lock_expires_at is None or doc.lock_expires_at > now


def lock_out(
    doc: Document | Folder, viewer_id: uuid.UUID, refs: dict[uuid.UUID, UserRef]
) -> LockOut | None:
    if not lock_active(doc) or doc.locked_by is None or doc.locked_at is None:
        return None
    return LockOut(
        locked_by=refs.get(doc.locked_by, UserRef(id=doc.locked_by)),
        locked_at=doc.locked_at,
        expires_at=doc.lock_expires_at,
        is_mine=doc.locked_by == viewer_id,
        prevent_download=bool(doc.lock_prevents_download),
    )
