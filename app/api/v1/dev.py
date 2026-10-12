"""Development-only sign-in for the local stack (AUTH_PROVIDER=local, APP_ENV=development|test).

This router is NOT registered in staging/production (the settings validator also refuses
AUTH_PROVIDER=local there), so it cannot exist in a deployed environment.
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from sqlalchemy import select

from app.adapters.identity.jwt_providers import LocalJwtProvider
from app.api.deps import DbSession
from app.core.config import get_settings
from app.core.errors import NotFoundError, UnauthorizedError
from app.core.local_password import verify_password
from app.db.enums import UserStatus
from app.db.models import User
from app.schemas.common import ApiModel

router = APIRouter(prefix="/dev", tags=["dev (local only)"], include_in_schema=False)


class DevTokenRequest(ApiModel):
    email: str


class DevTokenResponse(ApiModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105


@router.post(
    "/token", response_model=DevTokenResponse, summary="Issue a token for a seeded local user"
)
def dev_token(body: DevTokenRequest, db: DbSession) -> DevTokenResponse:
    settings = get_settings()
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    if (
        user is None
        or user.status != UserStatus.ACTIVE.value
        or user.identity_provider != "local"
        or user.external_subject is None
    ):
        raise NotFoundError("Unknown local user.")
    token = LocalJwtProvider(settings).issue_token(
        subject=user.external_subject, email=user.email, ttl_seconds=8 * 3600
    )
    return DevTokenResponse(access_token=token)


class DevLoginRequest(ApiModel):
    email: str
    password: str


@router.post(
    "/login",
    response_model=DevTokenResponse,
    summary="Email + password sign-in for the LOCAL stack only (shared dev password)",
)
def dev_login(body: DevLoginRequest, db: DbSession) -> DevTokenResponse:
    """Gives the login form a real email/password flow in development. The password is
    ``LOCAL_DEV_PASSWORD`` for every seeded user; the router is not registered in staging or
    production, where Supabase Auth is the only sign-in."""
    settings = get_settings()
    user = db.scalar(select(User).where(User.email == body.email.strip().lower()))
    # A user with an individual password must use it; everyone else uses the shared development password.
    if user is not None and user.local_password_hash:
        password_ok = verify_password(body.password, user.local_password_hash)
    else:
        password_ok = hmac.compare_digest(
            body.password.encode(), settings.local_dev_password.get_secret_value().encode()
        )
    if (
        user is None
        or not password_ok
        or user.status != UserStatus.ACTIVE.value
        or user.identity_provider != "local"
        or user.external_subject is None
    ):
        raise UnauthorizedError("Invalid email or password.", code="invalid_credentials")
    issued = datetime.now(UTC)
    if user.sessions_valid_after is not None:
        # tokens issued in the same second as a revocation count as revoked: start just after it
        issued = max(issued, user.sessions_valid_after + timedelta(seconds=1))
    token = LocalJwtProvider(settings).issue_token(
        subject=user.external_subject, email=user.email, ttl_seconds=8 * 3600, issued_at=issued
    )
    return DevTokenResponse(access_token=token)
