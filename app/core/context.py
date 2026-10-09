"""Per-request context (request id, principal ids) for logging and audit."""

from __future__ import annotations

from contextvars import ContextVar

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_client_ip: ContextVar[str | None] = ContextVar("client_ip", default=None)
_user_agent: ContextVar[str | None] = ContextVar("user_agent", default=None)
_user_id: ContextVar[str | None] = ContextVar("user_id", default=None)
_org_id: ContextVar[str | None] = ContextVar("org_id", default=None)


def get_request_id() -> str | None:
    return _request_id.get()


def set_request_context(request_id: str, ip: str | None, user_agent: str | None) -> None:
    _request_id.set(request_id)
    _client_ip.set(ip)
    _user_agent.set(user_agent[:300] if user_agent else None)


def set_principal_context(user_id: str | None, org_id: str | None) -> None:
    _user_id.set(user_id)
    _org_id.set(org_id)


def get_client_ip() -> str | None:
    return _client_ip.get()


def get_user_agent() -> str | None:
    return _user_agent.get()


def get_log_context() -> dict[str, str | None]:
    return {
        "request_id": _request_id.get(),
        "user_id": _user_id.get(),
        "org_id": _org_id.get(),
    }
