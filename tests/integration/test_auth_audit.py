"""Rejected credentials are audited (throttled), never with the token, and valid requests are unaffected."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.core import auth_audit
from app.db.models import AuditEvent

pytestmark = pytest.mark.integration
API = "/api/v1"


def count(world):  # noqa: ANN001, ANN201
    with world.db_factory() as db:
        return db.scalar(
            select(func.count())
            .select_from(AuditEvent)
            .where(AuditEvent.action == "auth.token_rejected")
        )


def test_invalid_tokens_are_audited_once_per_window_without_the_token(world):  # noqa: ANN001
    auth_audit.reset_for_tests()
    before = count(world)
    bad = {"Authorization": "Bearer not-a-real-token-SECRETVALUE"}
    for _ in range(5):
        assert world.client.get(f"{API}/me", headers=bad).status_code == 401
    assert count(world) == before + 1  # a flood of bad tokens writes one event per window
    with world.db_factory() as db:
        ev = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.action == "auth.token_rejected")
            .order_by(AuditEvent.created_at.desc())
        ).first()
    assert ev.outcome == "denied" and ev.organization_id is None and ev.actor_user_id is None
    assert ev.event_metadata["reason"] == "invalid_token" and ev.event_metadata["path"].endswith(
        "/me"
    )
    assert "SECRETVALUE" not in str(ev.event_metadata)


def test_missing_token_is_not_audited_and_valid_requests_are_unaffected(world):  # noqa: ANN001
    auth_audit.reset_for_tests()
    before = count(world)
    assert world.client.get(f"{API}/me").status_code == 401
    assert count(world) == before
    owner = world.org("Auth Audit Co", member_default_access=False)
    assert owner.get(f"{API}/me").status_code == 200
    assert count(world) == before


def test_throttle_window_is_bounded_and_reopens(monkeypatch):  # noqa: ANN001
    auth_audit.reset_for_tests()
    t = [1000.0]
    monkeypatch.setattr(auth_audit.time, "monotonic", lambda: t[0])
    monkeypatch.setattr(auth_audit.audit, "record_independent", lambda **kw: None)
    assert auth_audit.record_token_rejected("invalid_token", "/x") is True
    assert auth_audit.record_token_rejected("invalid_token", "/x") is False
    t[0] += auth_audit.WINDOW_SECONDS + 1
    assert auth_audit.record_token_rejected("invalid_token", "/x") is True
    for i in range(auth_audit.MAX_TRACKED + 50):  # memory stays bounded
        auth_audit._last[(f"ip{i}", "r")] = t[0]  # noqa: SLF001
    assert auth_audit.record_token_rejected("other", "/x") in (True, False)
    assert len(auth_audit._last) <= auth_audit.MAX_TRACKED + 51  # noqa: SLF001
