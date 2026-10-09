"""Authorized, short-lived download/preview tickets.

A ticket is a signed token (user, organization, document, version, disposition, expiry). It is
NOT a capability by itself: when it is redeemed, the user's membership and the document's
current permissions (shares, revocation, expiry, deletion, quarantine) are evaluated again, so a
revoked share stops working immediately even for a ticket that has not yet expired.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import quote

import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.adapters.storage.base import ObjectNotFoundError, StorageError
from app.adapters.storage.registry import get_storage_provider
from app.core.config import get_settings
from app.core.errors import (
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    UnauthorizedError,
)
from app.core.metrics import DOWNLOAD_URLS
from app.db.enums import (
    Action,
    AuditOutcome,
    DocumentStatus,
    MembershipStatus,
    OrgStatus,
    ScanStatus,
    UserStatus,
)
from app.db.models import (
    DocumentVersion,
    GroupMembership,
    Membership,
    Organization,
    StorageLocation,
    User,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.documents.service import touch_recent
from app.modules.identity.principal import Principal

_TOKEN_TYPE = "dms-download"  # noqa: S105
# Types a browser may render inline when previewing. Everything else is attachment-only.
PREVIEWABLE_TYPES = frozenset(
    {"application/pdf", "image/png", "image/jpeg", "image/gif", "image/webp", "text/plain"}
)


@dataclass(frozen=True)
class Servable:
    location: StorageLocation
    object_key: str
    size: int
    content_type: str
    disposition: str
    filename: str


def _signing_key() -> str:
    s = get_settings()
    secret = s.download_signing_secret or s.local_jwt_secret
    if secret is None:
        raise RuntimeError("DOWNLOAD_SIGNING_SECRET is not configured")
    return secret.get_secret_value()


def issue_ticket(
    principal: Principal,
    document_id: uuid.UUID,
    version_id: uuid.UUID,
    disposition: str,
    variant: str = "original",
) -> tuple[str, datetime]:
    ttl = get_settings().download_url_ttl_seconds
    expires = datetime.now(UTC) + timedelta(seconds=ttl)
    token = jwt.encode(
        {
            "typ": _TOKEN_TYPE,
            "sub": str(principal.user_id),
            "org": str(principal.organization_id),
            "doc": str(document_id),
            "ver": str(version_id),
            "disp": disposition,
            "var": variant,
            "jti": uuid.uuid4().hex,
            "exp": int(expires.timestamp()),
        },
        _signing_key(),
        algorithm="HS256",
    )
    return token, expires


def _decode(token: str) -> dict:
    try:
        claims = jwt.decode(
            token, _signing_key(), algorithms=["HS256"], options={"require": ["exp"]}
        )
    except jwt.PyJWTError as exc:
        raise UnauthorizedError(
            "Download link is invalid or has expired.", code="link_expired"
        ) from exc
    if claims.get("typ") != _TOKEN_TYPE:
        raise UnauthorizedError("Download link is invalid or has expired.", code="link_expired")
    return claims


def create_download_url(
    db: Session,
    authz: AuthorizationService,
    document_id: uuid.UUID,
    *,
    version_number: int | None,
    inline: bool,
    variant: str = "original",
) -> tuple[str, datetime]:
    """Authorize first; only then mint a ticket."""
    p = authz.principal
    thumbnail = variant == "thumbnail"
    inline = inline or thumbnail
    action = Action.PREVIEW if inline else Action.DOWNLOAD
    doc = authz.require_document(document_id, action)
    version = _servable_version(db, doc.organization_id, doc, version_number)
    if thumbnail:
        from app.modules.processing.service import derivative_for

        if derivative_for(db, version.id) is None:
            raise NotFoundError("No thumbnail is available for this document.")
    if inline and not thumbnail and version.content_type not in PREVIEWABLE_TYPES:
        raise ConflictError(
            "This file type cannot be previewed; download it instead.", code="not_previewable"
        )
    token, expires = issue_ticket(
        p, doc.id, version.id, "inline" if inline else "attachment", variant
    )
    DOWNLOAD_URLS.inc()
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.preview_url_issued" if inline else "document.download_url_issued",
        resource_type="document",
        resource_id=doc.id,
        metadata={"version_number": version.version_number},
    )
    touch_recent(db, p.user_id, doc, "previewed" if inline else "downloaded")
    db.commit()
    base = get_settings().public_api_base_url.rstrip("/")
    return f"{base}{get_settings().api_v1_prefix}/downloads/{token}", expires


def _servable_version(
    db: Session, organization_id: uuid.UUID, doc, version_number: int | None
) -> DocumentVersion:  # noqa: ANN001
    """A version is servable only if it is scan-clean; unscanned/quarantined bytes never leave."""
    if doc.status == DocumentStatus.QUARANTINED.value:
        raise ForbiddenError("This document is quarantined.", code="quarantined")
    if version_number is None:
        if doc.current_version_id is None:
            raise ConflictError("The document is still being processed.", code="processing")
        version = db.get(DocumentVersion, doc.current_version_id)
    else:
        version = db.scalar(
            select(DocumentVersion).where(
                DocumentVersion.document_id == doc.id,
                DocumentVersion.version_number == version_number,
            )
        )
    if version is None or version.organization_id != organization_id:
        raise NotFoundError("Version not found.")
    if version.scan_status != ScanStatus.CLEAN.value:
        raise ConflictError("This version has not passed required checks.", code="not_released")
    return version


def _principal_from_claims(db: Session, claims: dict) -> Principal:
    """Rebuild the caller from *current* DB state (never from the token's say-so)."""
    try:
        user_id, org_id = uuid.UUID(claims["sub"]), uuid.UUID(claims["org"])
    except (KeyError, ValueError) as exc:
        raise UnauthorizedError(
            "Download link is invalid or has expired.", code="link_expired"
        ) from exc
    user = db.get(User, user_id)
    org = db.get(Organization, org_id)
    membership = db.scalar(
        select(Membership).where(
            Membership.user_id == user_id, Membership.organization_id == org_id
        )
    )
    if (
        user is None
        or org is None
        or membership is None
        or user.status != UserStatus.ACTIVE.value
        or org.status != OrgStatus.ACTIVE.value
        or membership.status != MembershipStatus.ACTIVE.value
    ):
        raise ForbiddenError("Access denied.")
    groups = frozenset(
        db.scalars(
            select(GroupMembership.group_id).where(
                GroupMembership.user_id == user_id, GroupMembership.organization_id == org_id
            )
        )
    )
    return Principal(user.id, user.email, user.display_name, org_id, membership.role, groups)


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^\w.\- ]", "_", name, flags=re.ASCII).strip() or "download"
    return cleaned[:150]


def redeem_ticket(db: Session, token: str) -> Servable:
    """Validate + re-authorize, then describe exactly which stored object may be streamed."""
    claims = _decode(token)
    principal = _principal_from_claims(db, claims)
    authz = AuthorizationService(db, principal)
    inline = claims.get("disp") == "inline"
    doc = authz.require_document(
        uuid.UUID(claims["doc"]), Action.PREVIEW if inline else Action.DOWNLOAD
    )
    if doc.status == DocumentStatus.QUARANTINED.value:
        raise ForbiddenError("This document is quarantined.", code="quarantined")
    version = db.get(DocumentVersion, uuid.UUID(claims["ver"]))
    if (
        version is None
        or version.document_id != doc.id
        or version.organization_id != principal.organization_id
    ):
        raise NotFoundError("Version not found.")
    if version.scan_status != ScanStatus.CLEAN.value:
        raise ConflictError("This version has not passed required checks.", code="not_released")
    location = db.get(StorageLocation, version.storage_location_id)
    if location is None or location.organization_id != principal.organization_id:
        raise NotFoundError("Storage location not found.")
    servable = Servable(
        location=location,
        object_key=version.object_key,
        size=version.size_bytes,
        content_type=version.content_type,
        disposition="inline" if inline else "attachment",
        filename=doc.name,
    )
    if claims.get("var") == "thumbnail":
        from app.modules.processing.service import derivative_for

        derivative = derivative_for(db, version.id)
        if derivative is None:
            raise NotFoundError("No thumbnail is available for this document.")
        servable = Servable(
            location=location,
            object_key=derivative.object_key,
            size=derivative.size_bytes,
            content_type=derivative.content_type,
            disposition="inline",
            filename="thumbnail.png",
        )
    audit.record(
        db,
        organization_id=principal.organization_id,
        actor_user_id=principal.user_id,
        action="document.previewed" if inline else "document.downloaded",
        resource_type="document",
        resource_id=doc.id,
        outcome=AuditOutcome.SUCCESS,
        metadata={"version_number": version.version_number, "size_bytes": version.size_bytes},
    )
    db.commit()
    return servable


def content_disposition(disposition: str, filename: str) -> str:
    ascii_name = _safe_filename(filename)
    return f"{disposition}; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename, safe='')}"


def open_stream(servable: Servable):  # noqa: ANN201
    provider = get_storage_provider(servable.location.provider_type)
    try:
        return provider.stream_object(servable.location.bucket, servable.object_key)
    except ObjectNotFoundError as exc:
        raise NotFoundError("The stored file is missing. Contact an administrator.") from exc
    except StorageError as exc:
        raise DependencyUnavailableError("Storage is unavailable. Please retry.") from exc
