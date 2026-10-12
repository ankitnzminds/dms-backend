"""FastAPI dependencies: identity -> tenant-scoped Principal -> authorization service."""

from __future__ import annotations

import uuid
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header, Request
from sqlalchemy.orm import Session

from app.adapters.identity.base import IdentityProvider, InvalidTokenError, VerifiedIdentity
from app.adapters.identity.jwt_providers import build_identity_provider
from app.core.auth_audit import record_token_rejected
from app.core.config import get_settings
from app.core.context import set_principal_context
from app.core.errors import UnauthorizedError, ValidationFailed
from app.core.metrics import AUTH_FAILURES
from app.core.ratelimit import rate_limit
from app.db.session import get_db
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.modules.identity.service import resolve_principal

DbSession = Annotated[Session, Depends(get_db)]


@lru_cache
def get_identity_provider() -> IdentityProvider:
    return build_identity_provider(get_settings())


def reset_identity_provider() -> None:
    get_identity_provider.cache_clear()


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        AUTH_FAILURES.labels("missing_token").inc()
        raise UnauthorizedError("Authentication required.")
    token = authorization[7:].strip()
    if not token:
        AUTH_FAILURES.labels("missing_token").inc()
        raise UnauthorizedError("Authentication required.")
    return token


def get_verified_identity(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    provider: IdentityProvider = Depends(get_identity_provider),
) -> VerifiedIdentity:
    token = _bearer_token(authorization)
    try:
        return provider.verify_token(token)
    except InvalidTokenError as exc:
        AUTH_FAILURES.labels("invalid_token").inc()
        record_token_rejected("invalid_token", request.url.path)
        raise UnauthorizedError("Invalid or expired credentials.") from exc


def get_principal(
    request: Request,
    db: DbSession,
    identity: VerifiedIdentity = Depends(get_verified_identity),
    x_organization_id: Annotated[str | None, Header()] = None,
) -> Principal:
    requested: uuid.UUID | None = None
    if x_organization_id:
        try:
            requested = uuid.UUID(x_organization_id)
        except ValueError as exc:
            raise ValidationFailed("X-Organization-Id must be a UUID.") from exc
    principal = resolve_principal(db, identity, requested)
    set_principal_context(str(principal.user_id), str(principal.organization_id))
    request.state.rate_key = str(principal.user_id)
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def get_authz(db: DbSession, principal: CurrentPrincipal) -> AuthorizationService:
    return AuthorizationService(db, principal)


Authz = Annotated[AuthorizationService, Depends(get_authz)]


def limited(bucket: str, *, sensitive: bool = False):  # noqa: ANN201
    """Per-user rate limit dependency. Depends on the principal so the key is the user id."""
    inner = rate_limit(bucket, sensitive=sensitive)

    def dependency(request: Request, _principal: CurrentPrincipal) -> None:
        inner(request)

    return Depends(dependency)


__all__ = [
    "Authz",
    "CurrentPrincipal",
    "DbSession",
    "get_authz",
    "get_identity_provider",
    "get_principal",
    "get_settings",
    "limited",
    "reset_identity_provider",
]
