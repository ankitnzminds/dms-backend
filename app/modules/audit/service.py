"""Audit recording.

``record`` joins the caller's transaction (business change + audit commit atomically).
``record_independent`` uses its own short transaction so *denials* and failures are retained
even though the request transaction is rolled back.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.context import get_client_ip, get_request_id, get_user_agent
from app.core.logging import get_logger
from app.db.enums import AuditOutcome
from app.db.models import AuditEvent
from app.db.session import get_sessionmaker

log = get_logger(__name__)

_MAX_META_BYTES = 8_000
_FORBIDDEN_META_KEYS = ("token", "secret", "password", "authorization", "url", "signature")


def _safe_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not metadata:
        return {}
    clean: dict[str, Any] = {}
    for key, value in metadata.items():
        if any(bad in key.lower() for bad in _FORBIDDEN_META_KEYS):
            continue
        clean[key] = (
            value if isinstance(value, (int, float, bool, type(None), list, dict)) else str(value)
        )
    if len(str(clean)) > _MAX_META_BYTES:
        return {"truncated": True}
    return clean


def build_event(
    *,
    organization_id: uuid.UUID | None,
    actor_user_id: uuid.UUID | None,
    action: str,
    resource_type: str | None = None,
    resource_id: uuid.UUID | None = None,
    outcome: AuditOutcome = AuditOutcome.SUCCESS,
    metadata: dict[str, Any] | None = None,
) -> AuditEvent:
    return AuditEvent(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome.value,
        request_id=get_request_id(),
        ip_address=get_client_ip(),
        user_agent=get_user_agent(),
        event_metadata=_safe_metadata(metadata),
    )


def record(db: Session, **kwargs: Any) -> AuditEvent:
    event = build_event(**kwargs)
    db.add(event)
    return event


def record_independent(**kwargs: Any) -> None:
    """Persist an audit event in its own transaction. Failures are logged, never raised."""
    try:
        session = get_sessionmaker()()
        try:
            session.add(build_event(**kwargs))
            session.commit()
        finally:
            session.close()
    except Exception:
        log.exception("audit_write_failed", extra={"audit_action": kwargs.get("action")})
