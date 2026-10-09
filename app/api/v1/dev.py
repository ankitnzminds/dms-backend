"""Development-only sign-in for the local stack (AUTH_PROVIDER=local, APP_ENV=development|test).

This router is NOT registered in staging/production (the settings validator also refuses
AUTH_PROVIDER=local there), so it cannot exist in a deployed environment.
"""

from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import select

from app.adapters.identity.jwt_providers import LocalJwtProvider
from app.api.deps import DbSession
from app.core.config import get_settings
from app.core.errors import NotFoundError
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
