"""Share-link tokens: opaque, high entropy, revocable.

Lookup uses only the SHA-256 of the token (a database read cannot be replayed as a link). The token
is also kept encrypted (Fernet, key derived from the server signing secret) so a *manager* can copy
the link again; the plain token is never logged, never put in audit metadata, never in e-mail.
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings


def _fernet() -> Fernet:
    s = get_settings()
    secret = s.download_signing_secret or s.local_jwt_secret
    if secret is None:
        raise RuntimeError("DOWNLOAD_SIGNING_SECRET is not configured")
    raw = hashlib.sha256(b"dms-share-link:" + secret.get_secret_value().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def encrypt(token: str) -> str:
    return _fernet().encrypt(token.encode()).decode()


def decrypt(blob: str | None) -> str | None:
    if not blob:
        return None
    try:
        return _fernet().decrypt(blob.encode()).decode()
    except InvalidToken:
        return None


def url_for(token: str) -> str:
    return f"{get_settings().web_base_url.rstrip('/')}/s/{token}"
