"""Signing URLs are secret-equivalent (they carry the signer's token), so they are stored encrypted.

Fernet with a key derived from the server signing secret and a purpose-specific prefix (a share-link
key cannot decrypt these). Rows written before this change hold the plain URL; ``read`` accepts them
and the caller re-encrypts on first use, so no key-dependent data migration is needed.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings

_PREFIX = "gAAAA"  # every Fernet token starts like this


def _fernet() -> Fernet:
    s = get_settings()
    secret = s.download_signing_secret or s.local_jwt_secret
    if secret is None:
        raise RuntimeError("DOWNLOAD_SIGNING_SECRET is not configured")
    raw = hashlib.sha256(b"dms-signing-url:" + secret.get_secret_value().encode()).digest()
    return Fernet(base64.urlsafe_b64encode(raw))


def encrypt(url: str) -> str:
    return _fernet().encrypt(url.encode()).decode()


def is_encrypted(stored: str | None) -> bool:
    return bool(stored) and stored.startswith(_PREFIX)  # type: ignore[union-attr]


def read(stored: str | None) -> str | None:
    """The plain URL, or None when it cannot be recovered (wrong key / corrupt value)."""
    if not stored:
        return None
    if not is_encrypted(stored):
        return stored  # legacy plaintext row
    try:
        return _fernet().decrypt(stored.encode()).decode()
    except InvalidToken:
        return None
