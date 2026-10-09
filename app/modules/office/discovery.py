"""Collabora Online WOPI discovery: which URL opens which extension (cached)."""

from __future__ import annotations

import threading
import time
import xml.etree.ElementTree as ET  # noqa: S405 - XML comes from the configured office server only
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.core.config import get_settings
from app.core.errors import DependencyUnavailableError

_TTL_SECONDS = 3600
_lock = threading.Lock()
_cache: tuple[float, dict[tuple[str, str], str]] | None = None


def reset_discovery_cache() -> None:
    global _cache
    with _lock:
        _cache = None


def _load() -> dict[tuple[str, str], str]:
    s = get_settings()
    base = (s.collabora_discovery_url or s.collabora_url).rstrip("/")
    try:
        resp = httpx.get(f"{base}/hosting/discovery", timeout=10)
        resp.raise_for_status()
        root = ET.fromstring(resp.text)  # noqa: S314
    except (httpx.HTTPError, ET.ParseError) as exc:
        raise DependencyUnavailableError(
            "The office server is not reachable.", code="office_unavailable"
        ) from exc
    public = urlsplit(s.collabora_url)
    table: dict[tuple[str, str], str] = {}
    for action in root.iter("action"):
        name, ext, url = action.get("name"), action.get("ext"), action.get("urlsrc")
        if not (name and ext and url):
            continue
        parts = urlsplit(url)
        # The server may advertise its internal address; the browser must use the public one.
        table[(name, ext.lower())] = urlunsplit(
            (
                public.scheme or parts.scheme,
                public.netloc or parts.netloc,
                parts.path,
                parts.query,
                "",
            )
        )
    return table


def editor_url(action: str, ext: str) -> str | None:
    """urlsrc for ``action`` ('view' | 'edit') and extension; None if the server lacks it."""
    global _cache
    with _lock:
        if _cache is None or time.monotonic() - _cache[0] > _TTL_SECONDS:
            _cache = (time.monotonic(), _load())
        table = _cache[1]
    return table.get((action, ext)) or (table.get(("edit", ext)) if action == "view" else None)
