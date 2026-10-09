"""Provider-neutral identity interface: a provider only *authenticates* (who is this?).

Authorization (what may they do) is DMS-owned and lives in app.modules.authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


class InvalidTokenError(Exception):
    """Token is missing, malformed, expired, or fails signature/claim validation."""


@dataclass(frozen=True)
class VerifiedIdentity:
    provider: str
    subject: str
    email: str | None
    email_verified: bool
    display_name: str | None
    issued_at: datetime | None


class IdentityProvider(Protocol):
    name: str

    def verify_token(self, token: str) -> VerifiedIdentity: ...
