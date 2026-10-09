"""Office sessions: decide view/edit from CURRENT permissions and mint a scoped WOPI token.

The WOPI token only identifies (user, organization, document, requested mode). It carries no
authority of its own: every WOPI call rebuilds the principal from the database and re-checks the
document permissions, so revoking a share or the right to edit stops an open editor at its next
call, even though the token has not expired.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import jwt
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import ConflictError, DependencyUnavailableError, ValidationFailed
from app.db.enums import Action
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.documents.downloads import _servable_version
from app.modules.items.common import lock_active
from app.modules.office import discovery, formats
from app.schemas.office import OfficeSessionOut, OfficeStatus

_TOKEN_TYPE = "dms-wopi"  # noqa: S105


def _key() -> str:
    s = get_settings()
    secret = s.download_signing_secret or s.local_jwt_secret
    if secret is None:
        raise RuntimeError("DOWNLOAD_SIGNING_SECRET is not configured")
    return secret.get_secret_value()


def status() -> OfficeStatus:
    s = get_settings()
    on = s.effective_office_provider == "collabora"
    return OfficeStatus(
        available=on,
        provider="collabora" if on else None,
        viewable_extensions=sorted(formats.SUPPORTED) if on else [],
        editable_extensions=sorted(formats.EDITABLE) if on else [],
    )


def issue_token(
    user_id: uuid.UUID, org_id: uuid.UUID, document_id: uuid.UUID, mode: str
) -> tuple[str, datetime]:
    expires = datetime.now(UTC) + timedelta(seconds=get_settings().wopi_token_ttl_seconds)
    token = jwt.encode(
        {
            "typ": _TOKEN_TYPE,
            "sub": str(user_id),
            "org": str(org_id),
            "doc": str(document_id),
            "mode": mode,
            "jti": uuid.uuid4().hex,
            "exp": int(expires.timestamp()),
        },
        _key(),
        algorithm="HS256",
    )
    return token, expires


def decode_token(token: str) -> dict:  # type: ignore[type-arg]
    from app.core.errors import UnauthorizedError

    try:
        claims = jwt.decode(token, _key(), algorithms=["HS256"], options={"require": ["exp"]})
    except jwt.PyJWTError as exc:
        raise UnauthorizedError("Invalid or expired access token.", code="invalid_token") from exc
    if claims.get("typ") != _TOKEN_TYPE:
        raise UnauthorizedError("Invalid or expired access token.", code="invalid_token")
    return claims  # type: ignore[no-any-return]


def wopi_src(document_id: uuid.UUID) -> str:
    s = get_settings()
    base = (s.wopi_host_url or s.public_api_base_url).rstrip("/")
    return f"{base}/api/v1/wopi/files/{document_id}"


def create_session(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, mode: str
) -> OfficeSessionOut:
    s = get_settings()
    p = authz.principal
    if s.effective_office_provider != "collabora":
        raise DependencyUnavailableError(
            "No office server is configured.", code="office_unavailable"
        )
    doc = authz.require_document(document_id, Action.PREVIEW)
    ext = formats.extension(doc.name)
    if not formats.is_supported(doc.name):
        raise ValidationFailed(
            "This file type cannot be opened in the office viewer.", code="office_unsupported_type"
        )
    version = _servable_version(db, doc.organization_id, doc, None)  # quarantine / scan gate
    if version.size_bytes > s.office_max_bytes:
        raise ConflictError(
            "This file is too large for the office viewer.", code="office_too_large"
        )

    held = authz.document_actions([doc])[doc.id]
    granted, reason = "view", None
    if mode == "edit":
        if not formats.is_editable(doc.name):
            reason = "This format opens read-only. Edit an OOXML/ODF copy instead."
        elif Action.UPLOAD_VERSION.value not in held:
            reason = "You do not have permission to edit this file."
        elif lock_active(doc) and doc.locked_by != p.user_id:
            reason = "This file is checked out by someone else."
        else:
            granted = "edit"

    url = discovery.editor_url("edit" if granted == "edit" else "view", ext)
    if url is None:
        raise ValidationFailed(
            "The office server cannot open this type.", code="office_unsupported_type"
        )
    token, expires = issue_token(p.user_id, p.organization_id, doc.id, granted)
    sep = "" if url.endswith(("?", "&")) else ("&" if "?" in url else "?")
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.office_opened",
        resource_type="document",
        resource_id=doc.id,
        metadata={"mode": granted, "requested": mode, "version_number": version.version_number},
    )
    db.commit()
    return OfficeSessionOut(
        editor_url=f"{url}{sep}WOPISrc={quote(wopi_src(doc.id), safe='')}",
        access_token=token,
        access_token_ttl=int(expires.timestamp() * 1000),
        mode=granted,  # type: ignore[arg-type]
        can_edit=granted == "edit",
        reason=reason,
        can_download=Action.DOWNLOAD.value in held,
    )
