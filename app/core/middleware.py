"""Pure-ASGI middleware: request id/context, security headers, body-size limits, metrics."""

from __future__ import annotations

import json
import re
import time
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import get_settings
from app.core.context import get_request_id, set_request_context
from app.core.logging import get_logger
from app.core.metrics import HTTP_LATENCY, HTTP_REQUESTS

log = get_logger("app.access")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_UPLOAD_PATH_RE = re.compile(r"^/api/v1/uploads/[0-9a-fA-F-]{36}/content$")
MAX_JSON_BODY_BYTES = 2 * 1024 * 1024

SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    b"referrer-policy": b"no-referrer",
    b"cache-control": b"no-store",
    b"content-security-policy": b"default-src 'none'; frame-ancestors 'none'",
    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
}
# Interactive API docs need to load their own assets.
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class _BodyTooLarge(Exception):
    pass


def _route_template(scope: Scope) -> str:
    route = scope.get("route")
    return getattr(route, "path", None) or "unmatched"


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.settings = get_settings()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        incoming = headers.get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if _REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        client = scope.get("client")
        set_request_context(
            request_id,
            client[0] if client else None,
            headers.get(b"user-agent", b"").decode("latin-1") or None,
        )

        path: str = scope.get("path", "")
        is_upload = bool(_UPLOAD_PATH_RE.match(path))
        limit = self.settings.max_upload_bytes if is_upload else MAX_JSON_BODY_BYTES
        started = time.perf_counter()
        status_holder = {"status": 500}

        declared = headers.get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > limit:
            await self._reject_413(scope, send, request_id)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise _BodyTooLarge
            return message

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
                response_headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                present = {k.lower() for k, _ in response_headers}
                docs = path in _DOCS_PATHS
                for key, value in SECURITY_HEADERS.items():
                    if key in present or (docs and key == b"content-security-policy"):
                        continue
                    response_headers.append((key, value))
                response_headers.append((b"x-request-id", request_id.encode()))
                if self.settings.is_production_like:
                    response_headers.append(
                        (b"strict-transport-security", b"max-age=63072000; includeSubDomains")
                    )
                message = {**message, "headers": response_headers}
            await send(message)

        try:
            await self.app(scope, limited_receive, send_wrapper)
        except _BodyTooLarge:
            await self._reject_413(scope, send_wrapper, request_id)
        finally:
            elapsed = time.perf_counter() - started
            template = _route_template(scope)
            method = scope.get("method", "")
            HTTP_REQUESTS.labels(method, template, str(status_holder["status"])).inc()
            HTTP_LATENCY.labels(method, template).observe(elapsed)
            log.info(
                "request",
                extra={
                    "method": method,
                    "route": template,
                    "status": status_holder["status"],
                    "duration_ms": round(elapsed * 1000, 1),
                },
            )

    @staticmethod
    async def _reject_413(scope: Scope, send: Any, request_id: str) -> None:
        body = json.dumps(
            {
                "error": {
                    "code": "payload_too_large",
                    "message": "Request body is too large.",
                    "request_id": request_id,
                    "details": None,
                }
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"x-request-id", request_id.encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


__all__ = ["RequestContextMiddleware", "get_request_id"]
