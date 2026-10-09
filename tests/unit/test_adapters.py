"""Adapter tests: identity (JWT), storage (local + Supabase over a mock transport), malware."""

from __future__ import annotations

import io
import socket
import struct
import threading
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from pydantic import SecretStr

from app.adapters.identity.base import InvalidTokenError
from app.adapters.identity.jwt_providers import LocalJwtProvider, SupabaseJwtProvider
from app.adapters.malware.base import ScannerUnavailableError
from app.adapters.malware.clamd import ClamdScanner
from app.adapters.malware.eicar import EICAR, EicarScanner
from app.adapters.storage.base import ObjectNotFoundError, StorageError, new_object_key
from app.adapters.storage.local import LocalStorageProvider
from app.adapters.storage.supabase import SupabaseStorageProvider
from app.core.config import Settings
from app.db.enums import ScanStatus

SECRET = "unit-test-hs256-secret-0123456789abcdef-0123"


def settings(**kw):  # noqa: ANN003, ANN201
    base = dict(
        _env_file=None,
        supabase_url="https://abc.supabase.co",
        supabase_jwt_secret=SecretStr(SECRET),
        local_jwt_secret=SecretStr(SECRET),
        auth_provider="local",
    )
    base.update(kw)
    return Settings(**base)


def supa_token(**over):  # noqa: ANN003, ANN202
    now = datetime.now(UTC)
    claims = {
        "sub": "user-1",
        "email": "A@Example.com",
        "aud": "authenticated",
        "iss": "https://abc.supabase.co/auth/v1",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "user_metadata": {"email_verified": True, "full_name": "Ann"},
    }
    claims.update(over)
    return jwt.encode({k: v for k, v in claims.items() if v is not None}, SECRET, algorithm="HS256")


class TestSupabaseJwt:
    def provider(self):  # noqa: ANN202
        return SupabaseJwtProvider(settings(auth_provider="supabase"))

    def test_valid_token(self):
        ident = self.provider().verify_token(supa_token())
        assert ident.subject == "user-1" and ident.email == "a@example.com"
        assert ident.email_verified and ident.display_name == "Ann" and ident.provider == "supabase"

    @pytest.mark.parametrize(
        "over",
        [
            {"exp": int((datetime.now(UTC) - timedelta(hours=2)).timestamp())},
            {"aud": "someone-else"},
            {"iss": "https://evil.example/auth/v1"},
            {"sub": None},
            {"iat": None},
        ],
    )
    def test_rejects_bad_claims(self, over):  # noqa: ANN001
        with pytest.raises(InvalidTokenError):
            self.provider().verify_token(supa_token(**over))

    def test_rejects_wrong_signature(self):
        bad = jwt.encode(
            {
                "sub": "x",
                "aud": "authenticated",
                "iss": "https://abc.supabase.co/auth/v1",
                "iat": int(datetime.now(UTC).timestamp()),
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            },
            "another-secret-another-secret-another-secret",
            algorithm="HS256",
        )
        with pytest.raises(InvalidTokenError):
            self.provider().verify_token(bad)

    def test_rejects_alg_none_and_garbage(self):
        unsigned = jwt.encode({"sub": "x"}, None, algorithm="none")
        for token in (unsigned, "not.a.jwt", ""):
            with pytest.raises(InvalidTokenError):
                self.provider().verify_token(token)

    def test_hs256_refused_when_no_secret_configured(self):
        p = SupabaseJwtProvider(settings(auth_provider="supabase", supabase_jwt_secret=None))
        with pytest.raises(InvalidTokenError):
            p.verify_token(supa_token())


class TestLocalJwt:
    def test_roundtrip_and_audience_separation(self):
        p = LocalJwtProvider(settings())
        ident = p.verify_token(p.issue_token(subject="s", email="x@y.z"))
        assert ident.subject == "s" and ident.provider == "local"
        with pytest.raises(InvalidTokenError):  # a Supabase-style token is not a local token
            p.verify_token(supa_token())

    def test_refused_in_production(self):
        with pytest.raises(RuntimeError):
            LocalJwtProvider(
                Settings.model_construct(
                    app_env="production",
                    local_jwt_secret=SecretStr(SECRET),
                    auth_clock_skew_seconds=30,
                )
            )


class TestLocalStorage:
    def test_put_stream_head_copy_delete(self, tmp_path):  # noqa: ANN001
        s = LocalStorageProvider(str(tmp_path))
        s.put_object("b", "k/1", io.BytesIO(b"hello"), 5, "text/plain")
        assert b"".join(s.stream_object("b", "k/1")) == b"hello"
        assert s.head_object("b", "k/1").size == 5
        assert s.head_object("b", "missing") is None
        s.copy_object("b", "k/1", "k/2")
        assert b"".join(s.stream_object("b", "k/2")) == b"hello"
        s.delete_object("b", "k/1")
        s.delete_object("b", "k/1")  # idempotent
        with pytest.raises(ObjectNotFoundError):
            s.stream_object("b", "k/1")

    def test_never_overwrites_and_checks_size(self, tmp_path):  # noqa: ANN001
        s = LocalStorageProvider(str(tmp_path))
        s.put_object("b", "k", io.BytesIO(b"abc"), 3, "x/y")
        with pytest.raises(StorageError):
            s.put_object("b", "k", io.BytesIO(b"zzz"), 3, "x/y")
        assert b"".join(s.stream_object("b", "k")) == b"abc"
        with pytest.raises(StorageError):
            s.put_object("b", "short", io.BytesIO(b"ab"), 3, "x/y")
        assert s.head_object("b", "short") is None  # partial object removed

    @pytest.mark.parametrize("key", ["../escape", "a/../../escape", "/abs/path"])
    def test_path_traversal_blocked(self, tmp_path, key):  # noqa: ANN001
        s = LocalStorageProvider(str(tmp_path / "root"))
        with pytest.raises(StorageError):
            s.put_object("b", key, io.BytesIO(b"x"), 1, "x/y")

    def test_object_keys_are_opaque(self):
        import uuid

        org = uuid.uuid4()
        key = new_object_key(org)
        assert key.startswith(str(org)) and ".." not in key and len(key.split("/")[-1]) == 32


class TestSupabaseStorage:
    def make(self, handler):  # noqa: ANN001, ANN202
        client = httpx.Client(transport=httpx.MockTransport(handler))
        s = Settings(
            _env_file=None,
            supabase_url="https://abc.supabase.co",
            supabase_service_role_key=SecretStr("service-key"),
        )
        return SupabaseStorageProvider(s, client=client)

    def test_put_sends_auth_no_upsert_and_streams_body(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"], seen["headers"], seen["body"] = (
                str(request.url),
                request.headers,
                request.read(),
            )
            return httpx.Response(200, json={"Key": "ok"})

        self.make(handler).put_object(
            "dms", "org/2026/abc", io.BytesIO(b"payload"), 7, "application/pdf"
        )
        assert seen["url"] == "https://abc.supabase.co/storage/v1/object/dms/org/2026/abc"
        assert seen["headers"]["authorization"] == "Bearer service-key"
        assert seen["headers"]["x-upsert"] == "false" and seen["headers"]["content-length"] == "7"
        assert seen["body"] == b"payload"

    def test_errors_do_not_leak_response_bodies(self):
        provider = self.make(lambda r: httpx.Response(500, text="secret-internal-detail"))
        with pytest.raises(StorageError) as exc:
            provider.put_object("b", "k", io.BytesIO(b"x"), 1, "a/b")
        assert "secret-internal-detail" not in str(exc.value) and "500" in str(exc.value)

    def test_head_parses_size_and_missing(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/gone"):
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"size": 42, "content_type": "application/pdf"})

        p = self.make(handler)
        assert p.head_object("b", "here").size == 42
        assert p.head_object("b", "gone") is None

    def test_stream_download_and_not_found(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if "/object/info/" in request.url.path:
                return httpx.Response(200, json={"size": 5})
            return httpx.Response(200, content=b"hello")

        assert b"".join(self.make(handler).stream_object("b", "k")) == b"hello"
        with pytest.raises(ObjectNotFoundError):
            self.make(lambda r: httpx.Response(404, json={})).stream_object("b", "k")

    def test_copy_and_delete_and_health(self):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append((request.method, request.url.path))
            if request.url.path.endswith("/bucket/dms"):
                return httpx.Response(200, json={"public": False})
            return httpx.Response(404 if request.method == "DELETE" else 200, json={})

        p = self.make(handler)
        p.copy_object("dms", "a", "b")
        p.delete_object("dms", "gone")  # 404 tolerated
        assert p.health_check("dms") is True
        assert ("POST", "/storage/v1/object/copy") in calls

    def test_public_bucket_is_unhealthy(self):
        p = self.make(lambda r: httpx.Response(200, json={"public": True}))
        assert p.health_check("dms") is False

    def test_service_key_required(self):
        with pytest.raises(RuntimeError):
            SupabaseStorageProvider(
                Settings(_env_file=None, supabase_url="https://abc.supabase.co")
            )


class TestMalware:
    def test_eicar_detected_across_chunk_boundary(self):
        data = b"A" * 100 + EICAR + b"B" * 100
        chunks = iter([data[:150], data[150:]])  # split in the middle of the signature
        assert EicarScanner().scan(chunks).status == ScanStatus.INFECTED

    def test_project_marker_detected(self):
        from app.adapters.malware.eicar import TEST_MARKER

        assert (
            EicarScanner().scan(iter([b"pre", TEST_MARKER[:5], TEST_MARKER[5:]])).status
            == ScanStatus.INFECTED
        )

    def test_eicar_clean(self):
        assert EicarScanner().scan(iter([b"hello", b"world"])).status == ScanStatus.CLEAN

    def _fake_clamd(self, reply: bytes):  # noqa: ANN202
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        received = bytearray()

        def serve() -> None:
            conn, _ = srv.accept()
            with conn:
                buf = b""
                while not buf.endswith(b"\x00\x00\x00\x00") or len(buf) < 14:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                received.extend(buf)
                conn.sendall(reply)
            srv.close()

        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1], received

    def test_clamd_ok(self):
        port, received = self._fake_clamd(b"stream: OK\x00")
        result = ClamdScanner("127.0.0.1", port, 5).scan(iter([b"data"]))
        assert result.status == ScanStatus.CLEAN
        assert bytes(received).startswith(b"zINSTREAM\x00") and struct.pack(
            "!I", 4
        ) + b"data" in bytes(received)

    def test_clamd_found(self):
        port, _ = self._fake_clamd(b"stream: Win.Test.EICAR_HDB-1 FOUND\x00")
        result = ClamdScanner("127.0.0.1", port, 5).scan(iter([b"x"]))
        assert result.status == ScanStatus.INFECTED and "EICAR" in (result.detail or "")

    def test_clamd_error_is_never_clean(self):
        port, _ = self._fake_clamd(b"INSTREAM size limit exceeded. ERROR\x00")
        with pytest.raises(ScannerUnavailableError):
            ClamdScanner("127.0.0.1", port, 5).scan(iter([b"x"]))

    def test_clamd_unreachable_fails_closed(self):
        with pytest.raises(ScannerUnavailableError):
            ClamdScanner("127.0.0.1", 1, 0.5).scan(iter([b"x"]))
