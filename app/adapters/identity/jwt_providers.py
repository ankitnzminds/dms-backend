"""JWT based identity providers: Supabase Auth (production) and a local HS256 one (dev/test)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import jwt
from jwt import PyJWKClient

from app.adapters.identity.base import IdentityProvider, InvalidTokenError, VerifiedIdentity
from app.core.config import Settings

_ASYMMETRIC = ["ES256", "RS256", "EdDSA"]


def _identity_from_claims(provider: str, claims: dict[str, Any]) -> VerifiedIdentity:
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise InvalidTokenError("missing subject")
    user_meta = claims.get("user_metadata") or {}
    email = claims.get("email")
    verified = bool(claims.get("email_verified") or user_meta.get("email_verified"))
    iat = claims.get("iat")
    return VerifiedIdentity(
        provider=provider,
        subject=sub,
        email=email.lower() if isinstance(email, str) else None,
        email_verified=verified,
        display_name=user_meta.get("full_name") or user_meta.get("name") or claims.get("name"),
        issued_at=datetime.fromtimestamp(iat, UTC) if isinstance(iat, (int, float)) else None,
    )


class SupabaseJwtProvider:
    """Validates Supabase Auth access tokens (JWKS for asymmetric keys, or legacy HS256 secret)."""

    name = "supabase"

    def __init__(self, settings: Settings) -> None:
        if not settings.supabase_url:
            raise RuntimeError("SUPABASE_URL is required for AUTH_PROVIDER=supabase")
        base = settings.supabase_url.rstrip("/")
        self._issuer = f"{base}/auth/v1"
        self._audience = settings.supabase_jwt_audience
        self._leeway = settings.auth_clock_skew_seconds
        self._hs_secret = (
            settings.supabase_jwt_secret.get_secret_value()
            if settings.supabase_jwt_secret
            else None
        )
        self._jwks = PyJWKClient(
            f"{self._issuer}/.well-known/jwks.json", cache_keys=True, lifespan=600
        )

    def verify_token(self, token: str) -> VerifiedIdentity:
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get("alg")
            if alg == "HS256":
                if not self._hs_secret:
                    raise InvalidTokenError("HS256 tokens are not accepted by this deployment")
                key: Any = self._hs_secret
                algorithms = ["HS256"]
            elif alg in _ASYMMETRIC:
                key = self._jwks.get_signing_key_from_jwt(token).key
                algorithms = _ASYMMETRIC
            else:
                raise InvalidTokenError("unsupported algorithm")
            claims = jwt.decode(
                token,
                key,
                algorithms=algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={"require": ["exp", "sub", "iat"]},
            )
        except InvalidTokenError:
            raise
        except Exception as exc:  # PyJWTError, JWKS fetch errors, ...
            raise InvalidTokenError("invalid token") from exc
        return _identity_from_claims(self.name, claims)


class LocalJwtProvider:
    """HS256 tokens signed with LOCAL_JWT_SECRET. Development and automated tests only."""

    name = "local"

    def __init__(self, settings: Settings) -> None:
        if settings.is_production_like:
            raise RuntimeError("Local identity provider cannot be used in staging/production")
        if settings.local_jwt_secret is None:
            raise RuntimeError("LOCAL_JWT_SECRET is required for AUTH_PROVIDER=local")
        self._secret = settings.local_jwt_secret.get_secret_value()
        self._leeway = settings.auth_clock_skew_seconds

    def verify_token(self, token: str) -> VerifiedIdentity:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=["HS256"],
                audience="dms-local",
                leeway=self._leeway,
                options={"require": ["exp", "sub", "iat"]},
            )
        except Exception as exc:
            raise InvalidTokenError("invalid token") from exc
        return _identity_from_claims(self.name, claims)

    def issue_token(
        self,
        *,
        subject: str,
        email: str,
        email_verified: bool = True,
        ttl_seconds: int = 3600,
        issued_at: datetime | None = None,
    ) -> str:
        now = issued_at or datetime.now(UTC)
        return jwt.encode(
            {
                "sub": subject,
                "email": email,
                "email_verified": email_verified,
                "aud": "dms-local",
                "iat": int(now.timestamp()),
                "exp": int(now.timestamp()) + ttl_seconds,
            },
            self._secret,
            algorithm="HS256",
        )


def build_identity_provider(settings: Settings) -> IdentityProvider:
    if settings.auth_provider == "local":
        return LocalJwtProvider(settings)
    return SupabaseJwtProvider(settings)
