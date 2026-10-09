"""Unit tests for pure logic: config safety, naming, action closure, rate limiting, logging."""

from __future__ import annotations

import json
import logging

import pytest
from pydantic import SecretStr

from app.core.config import Settings
from app.core.errors import ValidationFailed
from app.core.logging import JsonFormatter
from app.core.naming import split_extension, validate_name
from app.core.ratelimit import SlidingWindowLimiter
from app.modules.authorization.actions import (
    ALL_ACTIONS,
    OWNER_ACTIONS,
    SHAREABLE_ACTIONS,
    expand_actions,
    validate_known_actions,
)
from app.modules.uploads.service import normalize_content_type, sniff_content_type


def make_settings(**kw):  # noqa: ANN003, ANN201
    return Settings(_env_file=None, **kw)


class TestConfigSafety:
    def test_production_rejects_local_providers_and_weak_scanner(self):
        with pytest.raises(ValueError) as exc:
            make_settings(
                app_env="production",
                auth_provider="local",
                storage_provider="local",
                malware_scanner="eicar",
                cors_allowed_origins="*",
                download_signing_secret=None,
            )
        msg = str(exc.value)
        for needle in (
            "AUTH_PROVIDER=local",
            "STORAGE_PROVIDER=local",
            "MALWARE_SCANNER",
            "CORS",
            "DOWNLOAD_SIGNING_SECRET",
        ):
            assert needle in msg

    def test_production_accepts_safe_configuration(self):
        s = make_settings(
            app_env="production",
            auth_provider="supabase",
            storage_provider="supabase",
            malware_scanner="clamd",
            cors_allowed_origins="https://dms.example.com",
            download_signing_secret=SecretStr("x" * 40),
        )
        assert s.is_production_like and s.cors_origins == ["https://dms.example.com"]

    def test_development_allows_local(self):
        assert make_settings(app_env="development", auth_provider="local").auth_provider == "local"

    def test_secrets_are_not_in_repr(self):
        s = make_settings(supabase_service_role_key=SecretStr("super-secret-value"))
        assert "super-secret-value" not in repr(s) and "super-secret-value" not in str(s)

    def test_blocked_extensions_parsed(self):
        assert "exe" in make_settings().blocked_extension_set


class TestNaming:
    @pytest.mark.parametrize(
        "name", ["report.pdf", "Q3 results (final).xlsx", "ünïcode.txt", "a" * 255]
    )
    def test_valid(self, name):  # noqa: ANN001
        assert validate_name(name) == name

    @pytest.mark.parametrize(
        "name",
        [
            "",
            "   ",
            ".",
            "..",
            "a/b",
            "a\\b",
            "../etc/passwd",
            "name.",
            "tab\tname",
            "nul",
            "COM1.txt",
            "x" * 256,
            "bell\x07",
        ],
    )
    def test_invalid(self, name):  # noqa: ANN001
        with pytest.raises(ValidationFailed):
            validate_name(name)

    def test_nfc_normalization_and_strip(self):
        assert validate_name("  é.txt ") == "é.txt"

    def test_extension(self):
        assert split_extension("a.TAR.GZ") == "gz"
        assert split_extension("noext") == ""
        assert split_extension(".hidden") == ""


class TestActions:
    def test_operational_actions_imply_view_and_discover(self):
        assert expand_actions({"download"}) == {"download", "view", "discover"}
        assert expand_actions({"view"}) == {"view", "discover"}
        assert expand_actions({"discover"}) == {"discover"}
        assert expand_actions(set()) == frozenset()

    def test_unknown_actions_are_dropped_by_expand_and_rejected_by_validate(self):
        assert expand_actions({"hack"}) == frozenset()
        with pytest.raises(ValueError):
            validate_known_actions(["view", "hack"])

    def test_shares_can_never_delegate_dangerous_actions(self):
        for dangerous in (
            "share",
            "manage_access",
            "delete",
            "move",
            "copy",
            "export",
            "administer",
            "restore",
        ):
            assert dangerous not in SHAREABLE_ACTIONS
        assert "administer" not in OWNER_ACTIONS and OWNER_ACTIONS < ALL_ACTIONS


class TestRateLimiter:
    def test_blocks_after_limit_and_is_keyed(self):
        lim = SlidingWindowLimiter()
        assert all(lim.check("b", "k", 3) for _ in range(3))
        assert not lim.check("b", "k", 3)
        assert lim.check("b", "other", 3)  # different key unaffected
        assert lim.check("b2", "k", 3)  # different bucket unaffected

    def test_window_expires(self):
        lim = SlidingWindowLimiter()
        assert lim.check("b", "k", 1, window=0.05)
        assert not lim.check("b", "k", 1, window=0.05)
        import time

        time.sleep(0.07)
        assert lim.check("b", "k", 1, window=0.05)


class TestLogging:
    def _format(self, **extra):  # noqa: ANN003, ANN202
        rec = logging.LogRecord("t", logging.INFO, __file__, 1, "hello token=abc123 end", (), None)
        for k, v in extra.items():
            setattr(rec, k, v)
        return json.loads(JsonFormatter().format(rec))

    def test_redacts_sensitive_keys_and_url_tokens(self):
        out = self._format(
            authorization="Bearer abc", password="pw", api_key="k", note="visit /d?token=zzz&x=1"
        )
        assert out["authorization"] == out["password"] == out["api_key"] == "[REDACTED]"
        assert "zzz" not in json.dumps(out) and "abc123" not in json.dumps(out)
        assert out["note"].startswith("visit /d?token=[REDACTED]")


class TestContentSniffing:
    @pytest.mark.parametrize(
        ("head", "claimed", "expected"),
        [
            (b"%PDF-1.7 xx", "application/octet-stream", "application/pdf"),
            (b"\x89PNG\r\n\x1a\n....", "application/pdf", "image/png"),
            (b"\xff\xd8\xff\xe0 jfif", "text/html", "image/jpeg"),
            (b"GIF89a....", "x/y", "image/gif"),
            (b"RIFF\x00\x00\x00\x00WEBPVP8", "x/y", "image/webp"),
            (b"<html><script>", "application/pdf", "application/octet-stream"),  # claim not backed
            (b"<html>", "text/html", "text/html"),  # never previewable anyway
            (b"hello world", "text/plain", "text/plain"),
            (b"\x00\x01binary", "text/plain", "application/octet-stream"),
            (b"PK\x03\x04", "application/zip", "application/zip"),
        ],
    )
    def test_sniff(self, head, claimed, expected):  # noqa: ANN001
        assert sniff_content_type(head, claimed) == expected

    @pytest.mark.parametrize(
        "value", [None, "", "no-slash", "a/b; charset=utf-8", "x" * 200 + "/y", "a b/c"]
    )
    def test_claimed_type_is_normalized(self, value):  # noqa: ANN001
        out = normalize_content_type(value)
        assert out == "application/octet-stream" or out == "a/b"
