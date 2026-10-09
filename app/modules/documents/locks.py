"""Cooperative document check-out (lock).

A lock stops *other users* from changing, moving, deleting or versioning the document until it is
released or expires (default 8 h). It is a coordination aid, not a security boundary: reading and
downloading stay governed by permissions, and administrators can break a lock (audited).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError
from app.db.enums import Action
from app.db.models import Document
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.modules.items.common import lock_active, lock_out, user_refs
from app.schemas.tree import LockOut

DEFAULT_LOCK_MINUTES = 8 * 60
MAX_LOCK_MINUTES = 7 * 24 * 60


def assert_unlocked_for(db: Session, doc: Document, p: Principal) -> None:
    """Raise 409 `document_locked` if somebody else holds an active lock."""
    if lock_active(doc) and doc.locked_by != p.user_id:
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


def lock_document(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, minutes: int | None
) -> LockOut:
    p = authz.principal
    visible = authz.require_document(document_id, Action.UPLOAD_VERSION)
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
    doc.lock_expires_at = now + timedelta(
        minutes=min(minutes or DEFAULT_LOCK_MINUTES, MAX_LOCK_MINUTES)
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.locked",
        resource_type="document",
        resource_id=doc.id,
        metadata={"expires_at": doc.lock_expires_at.isoformat()},
    )
    db.commit()
    result = lock_out(doc, p.user_id, user_refs(db, [p.user_id]))
    assert result is not None
    return result


def unlock_document(db: Session, authz: AuthorizationService, document_id: uuid.UUID) -> None:
    p = authz.principal
    doc = authz.require_document(document_id, Action.VIEW)
    if not lock_active(doc):
        doc.locked_by = doc.locked_at = doc.lock_expires_at = None
        db.commit()
        return
    if doc.locked_by != p.user_id:
        if not p.is_admin:
            assert_unlocked_for(db, doc, p)  # raises document_locked
        action = "document.lock_broken"
    else:
        action = "document.unlocked"
    previous = doc.locked_by
    doc.locked_by = doc.locked_at = doc.lock_expires_at = None
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=action,
        resource_type="document",
        resource_id=doc.id,
        metadata={"previous_holder": str(previous)},
    )
    db.commit()
