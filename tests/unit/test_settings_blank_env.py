"""Blank environment variables (an unfilled dashboard field) behave like unset ones."""

from __future__ import annotations

from app.core.config import Settings


def test_blank_provider_variables_fall_back_to_defaults(monkeypatch):  # noqa: ANN001
    for key in ("AUTH_PROVIDER", "STORAGE_PROVIDER", "AI_PROVIDER", "SIGNATURE_PROVIDER"):
        monkeypatch.setenv(key, "")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.auth_provider == "supabase" and s.storage_provider == "supabase"
    assert s.ai_provider == "auto" and s.signature_provider == "auto"


def test_filled_variables_still_win(monkeypatch):  # noqa: ANN001
    monkeypatch.setenv("AUTH_PROVIDER", "local")
    monkeypatch.setenv("STORAGE_PROVIDER", "")
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.auth_provider == "local" and s.storage_provider == "supabase"
