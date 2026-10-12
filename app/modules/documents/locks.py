"""Cooperative check-out (lock) of documents and folders.

A lock stops *other users* from changing, moving, renaming, deleting or versioning the item until it is
released or expires (default 8 h; the holder may instead pick an end time or "never"). It is a
coordination aid, not an access grant: it never gives anyone access, reading stays governed by
permissions, and administrators can break a lock (audited). Optionally the holder can also stop *other
people downloading* the item while the lock is held.

A folder lock covers the folder itself (rename, move, delete); it does not cascade to its contents.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, ValidationFailed
from app.db.enums import Action
from app.db.models import Document, Folder
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.modules.items.common import lock_active, lock_out, user_refs
from app.schemas.items import LockIn
from app.schemas.tree import LockOut

DEFAULT_LOCK_MINUTES = 8 * 60
MAX_LOCK_MINUTES = 7 * 24 * 60
MAX_EXPIRES_DAYS = 365


def _held_by_other(obj: Document | Folder, p: Principal) -> bool:
    return lock_active(obj) and obj.locked_by != p.user_id


def assert_unlocked_for(db: Session, doc: Document, p: Principal) -> None:
    """Raise 409 `document_locked` if somebody else holds an active lock."""
    if _held_by_other(doc, p):
        refs = user_refs(db, [doc.locked_by])
        who = refs.get(doc.locked_by) if doc.locked_by else None
        raise ConflictError(
            "This document is checked out by another user.",
            code="document_locked",
            details={
                "locked_by": who.display_name or who.email if who else None,
                "expires_at": doc.lock_expires_at.isoformat() if doc.lock_expires_at else None,
            },
        )


def assert_folder_unlocked_for(db: Session, folder: Folder, p: Principal) -> None:
    """Raise 409 `folder_locked` if somebody else holds an active lock on this folder."""
    if _held_by_other(folder, p):
        refs = user_refs(db, [folder.locked_by])
        who = refs.get(folder.locked_by) if folder.locked_by else None
        raise ConflictError(
            "This folder is locked by another user.",
            code="folder_locked",
            details={
                "locked_by": who.display_name or who.email if who else None,
                "expires_at": folder.lock_expires_at.isoformat()
                if folder.lock_expires_at
                else None,
            },
        )


def download_blocked(obj: Document | Folder, p: Principal | None) -> bool:
    """True while a lock that forbids downloads is held by somebody else (``p`` None: anonymous)."""
    if not (lock_active(obj) and obj.lock_prevents_download):
        return False
    return p is None or obj.locked_by != p.user_id


def assert_download_allowed(obj: Document | Folder, p: Principal | None) -> None:
    if download_blocked(obj, p):
        raise ForbiddenError(
            "Downloading is turned off while this item is locked by someone else.",
            code="download_blocked_by_lock",
        )


def _expiry(body: LockIn | None, now: datetime) -> datetime | None:
    if body is None:
        return now + timedelta(minutes=DEFAULT_LOCK_MINUTES)
    if body.no_expiry:
        return None
    if body.expires_at is not None:
        at = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=UTC)
        if at <= now + timedelta(minutes=1):
            raise ValidationFailed("The lock must end in the future.", code="lock_in_the_past")
        if at > now + timedelta(days=MAX_EXPIRES_DAYS):
            raise ValidationFailed(
                f"A lock can last at most {MAX_EXPIRES_DAYS} days.", code="lock_too_long"
            )
        return at
    return now + timedelta(minutes=min(body.minutes or DEFAULT_LOCK_MINUTES, MAX_LOCK_MINUTES))


def lock_document(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, body: LockIn | None
) -> LockOut:
    p = authz.principal
    visible = authz.require_document(document_id, Action.LOCK)
    doc = db.scalar(
        select(Document)
        .where(Document.id == visible.id, Document.organization_id == p.organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    assert doc is not None
    assert_unlocked_for(db, doc, p)
    now = datetime.now(UTC)
    doc.locked_by, doc.locked_at = p.user_id, now
    doc.lock_expires_at = _expiry(body, now)
    doc.lock_prevents_download = bool(body and body.prevent_download)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.locked",
        resource_type="document",
        resource_id=doc.id,
        metadata={
            "expires_at": doc.lock_expires_at.isoformat() if doc.lock_expires_at else None,
            "prevent_download": doc.lock_prevents_download,
        },
    )
    db.commit()
    result = lock_out(doc, p.user_id, user_refs(db, [p.user_id]))
    assert result is not None
    return result


def lock_folder(
    db: Session, authz: AuthorizationService, folder_id: uuid.UUID, body: LockIn | None
) -> LockOut:
    p = authz.principal
    visible = authz.require_folder(folder_id, Action.LOCK)
    if visible.parent_folder_id is None:
        raise ForbiddenError("The root folder cannot be locked.")
    folder = db.scalar(
        select(Folder)
        .where(Folder.id == visible.id, Folder.organization_id == p.organization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    assert folder is not None
    assert_folder_unlocked_for(db, folder, p)
    now = datetime.now(UTC)
    folder.locked_by, folder.locked_at = p.user_id, now
    folder.lock_expires_at = _expiry(body, now)
    folder.lock_prevents_download = bool(body and body.prevent_download)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="folder.locked",
        resource_type="folder",
        resource_id=folder.id,
        metadata={
            "expires_at": folder.lock_expires_at.isoformat() if folder.lock_expires_at else None,
            "prevent_download": folder.lock_prevents_download,
        },
    )
    db.commit()
    result = lock_out(folder, p.user_id, user_refs(db, [p.user_id]))
    assert result is not None
    return result


def _release(db: Session, p: Principal, obj: Document | Folder, kind: str) -> None:
    if not lock_active(obj):
        obj.locked_by = obj.locked_at = obj.lock_expires_at = None  # type: ignore[assignment]
        obj.lock_prevents_download = False
        db.commit()
        return
    broke = obj.locked_by != p.user_id
    if broke and not p.is_admin:
        if kind == "document":
            assert_unlocked_for(db, obj, p)  # type: ignore[arg-type]
        else:
            assert_folder_unlocked_for(db, obj, p)  # type: ignore[arg-type]
    previous, was_download_blocked = obj.locked_by, obj.lock_prevents_download
    obj.locked_by = obj.locked_at = obj.lock_expires_at = None  # type: ignore[assignment]
    obj.lock_prevents_download = False
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=f"{kind}.lock_broken" if broke else f"{kind}.unlocked",
        resource_type=kind,
        resource_id=obj.id,
        metadata={
            "previous_holder": str(previous),
            "prevent_download_was_on": was_download_blocked,
        },
    )
    db.commit()


def unlock_document(db: Session, authz: AuthorizationService, document_id: uuid.UUID) -> None:
    doc = authz.require_document(document_id, Action.VIEW)
    _release(db, authz.principal, doc, "document")


def unlock_folder(db: Session, authz: AuthorizationService, folder_id: uuid.UUID) -> None:
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    _release(db, authz.principal, folder, "folder")
