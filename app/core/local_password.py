"""Password hashing for the LOCAL development sign-in (stdlib scrypt; no extra dependency).

Production passwords are owned by the identity provider (Supabase Auth); this module is only used by the
development-only ``/dev/login`` route to give each seeded user an individual password.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N, _R, _P = 2**14, 8, 1


def _derive(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=64 * 1024 * 1024
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    key = _derive(password, salt, _N, _R, _P)
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return f"scrypt${_N}${_R}${_P}${b64(salt)}${b64(key)}"


def verify_password(password: str, stored: str | None) -> bool:
    if not stored:
        return False
    try:
        scheme, n, r, p, salt, key = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = base64.b64decode(key)
        actual = _derive(password, base64.b64decode(salt), int(n), int(r), int(p))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)
