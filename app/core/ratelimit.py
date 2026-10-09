"""Small in-process sliding-window rate limiter.

Limits are per process (each API replica counts independently). That is an accepted
trade-off for the first release (see docs/security/rate-limiting.md); a shared store can
be added behind the same interface when horizontally scaling.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from fastapi import Request

from app.core.config import get_settings
from app.core.errors import RateLimitedError


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, bucket: str, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._hits[(bucket, key)]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            if len(self._hits) > 50_000:  # bound memory under key-flooding
                self._gc(now, window)
            return True

    def _gc(self, now: float, window: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or now - q[-1] > window]:
            self._hits.pop(k, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def rate_limit(bucket: str, *, sensitive: bool = False):  # noqa: ANN201
    """Dependency factory. Keyed by authenticated user when known, else client IP."""

    def dependency(request: Request) -> None:
        settings = get_settings()
        if not settings.rate_limit_enabled:
            return
        limit = (
            settings.rate_limit_sensitive_per_minute
            if sensitive
            else settings.rate_limit_default_per_minute
        )
        principal = getattr(request.state, "rate_key", None)
        key = principal or (request.client.host if request.client else "unknown")
        if not limiter.check(bucket, key, limit):
            raise RateLimitedError("Too many requests. Please retry shortly.")

    return dependency
