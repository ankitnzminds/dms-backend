"""Throttled audit of rejected credentials (security monitoring).

A rejected bearer token has no trustworthy tenant or user, so the event is written with a NULL
organization (visible to platform operators / SIEM export, not to tenant administrators) and carries
only the coarse failure reason, the route and the client address recorded by the request context.
Never the token itself. One event per (client address, reason) per window keeps a flood of bad
tokens from filling the append-only table; every failure is still counted by ``AUTH_FAILURES``.
"""

from __future__ import annotations

import threading
import time

from app.core.context import get_client_ip
from app.core.logging import get_logger
from app.db.enums import AuditOutcome
from app.modules.audit import service as audit

log = get_logger(__name__)

WINDOW_SECONDS = 60.0
MAX_TRACKED = 5000

_lock = threading.Lock()
_last: dict[tuple[str, str], float] = {}


def _due(key: tuple[str, str], now: float) -> bool:
    with _lock:
        last = _last.get(key)
        if last is not None and now - last < WINDOW_SECONDS:
            return False
        if len(_last) >= MAX_TRACKED:  # bounded memory: drop expired entries, then the oldest
            for k in [k for k, t in _last.items() if now - t >= WINDOW_SECONDS]:
                del _last[k]
            if len(_last) >= MAX_TRACKED:
                del _last[min(_last, key=_last.__getitem__)]
        _last[key] = now
        return True


def record_token_rejected(reason: str, path: str) -> bool:
    """Audit (at most once per window per client+reason). Returns True when an event was written."""
    ip = get_client_ip() or "unknown"
    if not _due((ip, reason), time.monotonic()):
        return False
    log.warning("auth_token_rejected", extra={"reason": reason, "path": path})
    audit.record_independent(
        organization_id=None,
        actor_user_id=None,
        action="auth.token_rejected",
        resource_type=None,
        resource_id=None,
        outcome=AuditOutcome.DENIED,
        metadata={"reason": reason, "path": path},
    )
    return True


def reset_for_tests() -> None:
    with _lock:
        _last.clear()
