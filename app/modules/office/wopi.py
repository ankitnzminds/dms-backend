"""WOPI host operations (CheckFileInfo, GetFile, PutFile, locks) for Collabora Online.

Rules enforced on EVERY call (not just at session creation):
* the token must be valid and bound to this document;
* the principal is rebuilt from the database (inactive user/membership/org => denied);
* the document permission is re-evaluated: PREVIEW to read, UPLOAD_VERSION (+ token mode 'edit',
  editable format, not checked out by someone else) to write;
* only a scan-clean current version is ever served;
* a save becomes a NEW immutable version through the normal upload pipeline (quota, scan,
  virus gate, audit, version numbering); the previous version stays untouched.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import (
    AppError,
    ForbiddenError,
    NotFoundError,
    PayloadTooLargeError,
    UnauthorizedError,
)
from app.db.enums import Action
from app.db.models import Document, DocumentVersion, OfficeLock
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.documents.downloads import Servable, servable_current
from app.modules.documents.locks import assert_unlocked_for
from app.modules.identity.principal import Principal
from app.modules.identity.service import principal_for
from app.modules.office import formats, service
from app.modules.uploads import service as uploads


class WopiConflict(AppError):
    """409 carrying the lock that is currently held (WOPI requires it in X-WOPI-Lock)."""

    status_code = 409
    code = "lock_mismatch"

    def __init__(self, current_lock: str) -> None:
        super().__init__("Lock mismatch.")
        self.current_lock = current_lock


@dataclass
class Ctx:
    principal: Principal
    authz: AuthorizationService
    doc: Document
    mode: str


def authenticate(db: Session, token: str | None, file_id: uuid.UUID, *, write: bool = False) -> Ctx:
    if not token:
        raise UnauthorizedError("Missing access token.", code="invalid_token")
    claims = service.decode_token(token)
    if claims.get("doc") != str(file_id):
        raise NotFoundError("File not found.")  # a token is valid for exactly one document
    try:
        principal = principal_for(db, uuid.UUID(claims["sub"]), uuid.UUID(claims["org"]))
    except (ForbiddenError, KeyError, ValueError) as exc:
        raise UnauthorizedError("Invalid or expired access token.", code="invalid_token") from exc
    authz = AuthorizationService(db, principal)
    doc = authz.require_document(file_id, Action.PREVIEW)
    mode = str(claims.get("mode", "view"))
    if write:
        if mode != "edit":
            raise ForbiddenError("This session is read-only.")
        authz.require_document(file_id, Action.UPLOAD_VERSION)
        assert_unlocked_for(db, doc, principal)
        if not formats.is_editable(doc.name):
            raise ForbiddenError("This format cannot be edited.")
    return Ctx(principal, authz, doc, mode)


def _can_write(ctx: Ctx, db: Session) -> bool:
    if ctx.mode != "edit" or not formats.is_editable(ctx.doc.name):
        return False
    held = ctx.authz.document_actions([ctx.doc])[ctx.doc.id]
    if Action.UPLOAD_VERSION.value not in held:
        return False
    try:
        assert_unlocked_for(db, ctx.doc, ctx.principal)
    except AppError:
        return False
    return True


def check_file_info(db: Session, token: str | None, file_id: uuid.UUID) -> dict[str, object]:
    ctx = authenticate(db, token, file_id)
    servable, version = servable_current(db, ctx.authz, file_id, Action.PREVIEW)
    held = ctx.authz.document_actions([ctx.doc])[ctx.doc.id]
    can_download = Action.DOWNLOAD.value in held
    can_write = _can_write(ctx, db)
    web = get_settings().web_base_url.rstrip("/")
    return {
        "BaseFileName": ctx.doc.name,
        "OwnerId": str(ctx.doc.owner_id or ""),
        "UserId": str(ctx.principal.user_id),
        "UserFriendlyName": ctx.principal.display_name or ctx.principal.email,
        "Size": servable.size,
        "Version": f"{version.version_number}",
        "SHA256": base64.b64encode(bytes.fromhex(version.sha256)).decode()
        if version.sha256
        else "",
        "LastModifiedTime": version.created_at.astimezone(UTC).isoformat(),
        "UserCanWrite": can_write,
        "ReadOnly": not can_write,
        "SupportsUpdate": True,
        "SupportsLocks": True,
        "SupportsGetLock": True,
        "UserCanNotWriteRelative": True,  # no "Save As" copies: a save is a new VERSION
        "PostMessageOrigin": web,
        # Without download rights the editor must not become an exfiltration path.
        "DisablePrint": not can_download,
        "DisableExport": not can_download,
        "DisableCopy": not can_download,
        "HidePrintOption": not can_download,
        "HideExportOption": not can_download,
        "EnableShare": False,
    }


def get_contents(db: Session, token: str | None, file_id: uuid.UUID) -> Servable:
    ctx = authenticate(db, token, file_id)
    servable, _ = servable_current(db, ctx.authz, file_id, Action.PREVIEW)
    return servable


# ---------------------------------------------------------------- locks
def _active_lock(
    db: Session, org: uuid.UUID, file_id: uuid.UUID, *, for_update: bool
) -> OfficeLock | None:
    stmt = select(OfficeLock).where(
        OfficeLock.document_id == file_id, OfficeLock.organization_id == org
    )
    if for_update:
        stmt = stmt.with_for_update().execution_options(populate_existing=True)
    row = db.scalar(stmt)
    if row is not None and row.expires_at <= datetime.now(UTC):
        db.delete(row)
        db.flush()
        return None
    return row


def lock_op(
    db: Session, token: str | None, file_id: uuid.UUID, op: str, lock_id: str, old_lock: str | None
) -> str:
    """Returns the lock to echo in X-WOPI-Lock ('' when none). Raises WopiConflict on mismatch."""
    ctx = authenticate(db, token, file_id, write=op != "GET_LOCK")
    org = ctx.principal.organization_id
    expires = datetime.now(UTC) + timedelta(seconds=get_settings().wopi_lock_seconds)
    cur = _active_lock(db, org, file_id, for_update=True)
    if op == "GET_LOCK":
        return cur.lock_id if cur else ""
    if op == "LOCK":
        if cur is not None and cur.lock_id != lock_id:
            raise WopiConflict(cur.lock_id)
        if cur is None:
            db.add(
                OfficeLock(
                    document_id=file_id,
                    organization_id=org,
                    lock_id=lock_id,
                    locked_by=ctx.principal.user_id,
                    expires_at=expires,
                )
            )
        else:
            cur.expires_at = expires
    elif op == "REFRESH_LOCK":
        if cur is None or cur.lock_id != lock_id:
            raise WopiConflict(cur.lock_id if cur else "")
        cur.expires_at = expires
    elif op == "UNLOCK":
        if cur is None or cur.lock_id != lock_id:
            raise WopiConflict(cur.lock_id if cur else "")
        db.delete(cur)
    elif op == "UNLOCK_AND_RELOCK":
        if cur is None or cur.lock_id != (old_lock or ""):
            raise WopiConflict(cur.lock_id if cur else "")
        cur.lock_id, cur.expires_at = lock_id, expires
    db.commit()
    return lock_id if op != "UNLOCK" else ""


# ---------------------------------------------------------------- save
def put_contents(
    db: Session,
    token: str | None,
    file_id: uuid.UUID,
    lock_id: str | None,
    body: BinaryIO,
    size: int,
    sha256: str,
    head: bytes,
) -> DocumentVersion:
    """Save = a new version (never an overwrite). Requires the matching WOPI lock."""
    ctx = authenticate(db, token, file_id, write=True)
    s = get_settings()
    if size <= 0 or size > s.office_max_bytes:
        raise PayloadTooLargeError("The saved file is empty or too large.")
    cur = _active_lock(db, ctx.principal.organization_id, file_id, for_update=False)
    if cur is None or cur.lock_id != (lock_id or ""):
        raise WopiConflict(cur.lock_id if cur else "")
    doc = ctx.doc
    current = db.get(DocumentVersion, doc.current_version_id) if doc.current_version_id else None
    content_type = current.content_type if current else "application/octet-stream"
    session = uploads.initiate(
        db,
        ctx.authz,
        folder_id=None,
        document_id=doc.id,
        filename=doc.name,
        size_bytes=size,
        content_type=content_type,
        sha256=sha256,
        expected_latest_version=doc.latest_version_number,
        idempotency_key=None,
    )
    stored = uploads.store_content(db, ctx.authz, session.id, body, size, sha256, head)
    _, version = uploads.finalize(db, ctx.authz, stored.id)
    audit.record(
        db,
        organization_id=ctx.principal.organization_id,
        actor_user_id=ctx.principal.user_id,
        action="document.office_saved",
        resource_type="document",
        resource_id=doc.id,
        metadata={"version_number": version.version_number, "size_bytes": size},
    )
    db.commit()
    return version
