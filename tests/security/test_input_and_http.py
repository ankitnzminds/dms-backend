"""HTTP-level security: headers, error contract, injection inputs, CORS, tickets, rate limits."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.security]

PDF = b"%PDF-1.4 http"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Http")
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "docs")
    doc = world.available_doc(admin, folder, "h.pdf", PDF + b" doc")
    return dict(world=world, admin=admin, root=root, folder=folder, doc=doc)


def test_security_headers_and_request_id(env):  # noqa: ANN001
    r = env["admin"].get("/api/v1/me")
    h = r.headers
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
    assert h["cache-control"] == "no-store" and h["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert len(h["x-request-id"]) >= 8
    # client-supplied ids are accepted only when safe
    ok = env["world"].client.get("/health/live", headers={"X-Request-ID": "trace-abc-12345"})
    assert ok.headers["x-request-id"] == "trace-abc-12345"
    bad = env["world"].client.get("/health/live", headers={"X-Request-ID": "x\r\ninjected: 1"})
    assert "injected" not in bad.headers and bad.headers["x-request-id"] != "x"


def test_error_contract_is_uniform_and_leaks_nothing(env):  # noqa: ANN001
    admin, world = env["admin"], env["world"]
    r = admin.get(f"/api/v1/documents/{uuid.uuid4()}")
    body = r.json()
    assert r.status_code == 404 and set(body["error"]) == {
        "code",
        "message",
        "request_id",
        "details",
    }
    assert body["error"]["request_id"] == r.headers["x-request-id"]
    r = admin.post("/api/v1/folders", json={"parent_folder_id": "nope", "name": ""})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    assert "nope" not in r.text  # input values are not echoed back
    assert world.client.get("/api/v1/does-not-exist").json()["error"]["code"] == "not_found"
    assert world.client.delete("/api/v1/me").json()["error"]["code"] == "method_not_allowed"
    r = admin.get(f"/api/v1/documents/{env['doc']}/versions/abc")
    assert r.status_code in (404, 405, 422)


def test_unhandled_errors_return_safe_500(env, monkeypatch):  # noqa: ANN001
    from app.modules.folders import service

    def explode(*a, **k):  # noqa: ANN002, ANN003, ANN202
        raise RuntimeError("db password is hunter2")

    monkeypatch.setattr(service, "get_root", explode)
    r = env["admin"].get("/api/v1/folders/root")
    assert r.status_code == 500 and "hunter2" not in r.text
    assert r.json()["error"]["code"] == "internal_error" and r.json()["error"]["request_id"]


def test_body_size_limits(env):  # noqa: ANN001
    admin = env["admin"]
    big = {"name": "x" * (3 * 1024 * 1024), "parent_folder_id": env["root"]}
    r = admin.post("/api/v1/folders", json=big)
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"


@pytest.mark.parametrize(
    "payload",
    [
        "'; DROP TABLE dms.documents; --",
        '" OR 1=1 --',
        "%' OR '1'='1",
        "${jndi:ldap://x}",
        "<script>alert(1)</script>",
        "‮.exe",
        "a" * 1000,
    ],
)
def test_hostile_strings_are_inert(env, payload):  # noqa: ANN001
    admin = env["admin"]
    assert admin.get("/api/v1/search", params={"q": payload[:200]}).status_code in (200, 422)
    r = admin.post("/api/v1/folders", json={"parent_folder_id": env["root"], "name": payload})
    assert r.status_code in (201, 422)
    if r.status_code == 201:  # stored verbatim as text and returned as data, never interpreted
        assert r.json()["name"] == payload.strip()
    assert admin.get(f"/api/v1/documents/{env['doc']}").status_code == 200  # table still there


def test_search_treats_like_wildcards_literally(env):  # noqa: ANN001
    w, admin = env["world"], env["admin"]
    w.available_doc(admin, env["folder"], "report_final.pdf", PDF + b" 1")
    w.available_doc(admin, env["folder"], "reportXfinal.pdf", PDF + b" 2")
    names = {
        i["name"] for i in admin.get("/api/v1/search", params={"q": "report_final"}).json()["items"]
    }
    assert "report_final.pdf" in names and "reportXfinal.pdf" not in names
    assert admin.get("/api/v1/search", params={"q": "%"}).json()["total"] == 0


def test_cors_allows_only_configured_origins(env):  # noqa: ANN001
    c = env["world"].client
    ok = c.options(
        "/api/v1/me",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,x-organization-id",
        },
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:3000"
    assert "access-control-allow-credentials" not in ok.headers
    evil = c.options(
        "/api/v1/me",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "access-control-allow-origin" not in evil.headers
    simple = c.get("/health/live", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in simple.headers


class TestDownloadTickets:
    def _url(self, env):  # noqa: ANN001, ANN202
        r = env["admin"].post(f"/api/v1/documents/{env['doc']}/download-url", json={})
        assert r.status_code == 200
        return r.json()["url"].replace("http://testserver", ""), r.json()["expires_at"]

    def test_ticket_is_short_lived_and_signed(self, env):  # noqa: ANN001
        url, expires = self._url(env)
        c = env["world"].client
        assert c.get(url).status_code == 200
        exp = datetime.fromisoformat(expires)
        assert timedelta(seconds=0) < exp - datetime.now(UTC) <= timedelta(seconds=61)
        token = url.rsplit("/", 1)[1]
        for bad in (token[:-2] + "xx", "garbage", token + "a", ""):
            r = c.get(f"/api/v1/downloads/{bad}")
            assert r.status_code in (401, 404, 405), bad

    def test_expired_ticket_and_wrong_type_are_rejected(self, env):  # noqa: ANN001
        from app.core.config import get_settings

        secret = get_settings().download_signing_secret.get_secret_value()
        a = env["admin"]
        claims = {
            "typ": "dms-download",
            "sub": str(a.user_id),
            "org": str(a.org_id),
            "doc": env["doc"],
            "ver": str(uuid.uuid4()),
            "disp": "attachment",
            "exp": int((datetime.now(UTC) - timedelta(seconds=5)).timestamp()),
        }
        c = env["world"].client
        expired = jwt.encode(claims, secret, algorithm="HS256")
        assert c.get(f"/api/v1/downloads/{expired}").status_code == 401
        wrong_type = jwt.encode(
            {
                **claims,
                "typ": "something-else",
                "exp": int((datetime.now(UTC) + timedelta(minutes=1)).timestamp()),
            },
            secret,
            algorithm="HS256",
        )
        assert c.get(f"/api/v1/downloads/{wrong_type}").status_code == 401
        # a login token can never be redeemed as a download ticket (different secret/type)
        assert c.get(f"/api/v1/downloads/{a.token}").status_code == 401

    def test_ticket_cannot_be_used_after_the_user_is_deactivated(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        m = w.user(admin, "admin", label="temp")
        url = (
            m.post(f"/api/v1/documents/{env['doc']}/download-url", json={})
            .json()["url"]
            .replace("http://testserver", "")
        )
        assert w.client.get(url).status_code == 200
        assert (
            admin.patch(
                f"/api/v1/admin/members/{m.user_id}", json={"status": "suspended"}
            ).status_code
            == 200
        )
        assert w.client.get(url).status_code == 403

    def test_downloads_are_attachment_by_default_and_previews_are_restricted(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        html = w.available_doc(
            admin, env["folder"], "page.html", b"<html><script>alert(1)</script></html>"
        )
        url = (
            admin.post(f"/api/v1/documents/{html}/download-url", json={})
            .json()["url"]
            .replace("http://testserver", "")
        )
        r = w.client.get(url)
        assert (
            "attachment" in r.headers["content-disposition"]
            and r.headers["content-type"] == "application/octet-stream"
        )
        assert "sandbox" in r.headers["content-security-policy"]
        # html can never be previewed inline
        assert (
            admin.post(f"/api/v1/documents/{html}/download-url", json={"inline": True}).status_code
            == 409
        )
        pdf_url = (
            admin.post(f"/api/v1/documents/{env['doc']}/download-url", json={"inline": True})
            .json()["url"]
            .replace("http://testserver", "")
        )
        inline = w.client.get(pdf_url)
        assert inline.status_code == 200 and inline.headers["content-disposition"].startswith(
            "inline"
        )
        assert (
            inline.headers["content-type"] == "application/pdf"
            and "default-src 'none'" in inline.headers["content-security-policy"]
        )

    def test_filename_header_injection_is_neutralised(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        evil = w.available_doc(admin, env["folder"], 'a";b=cé ü.pdf', PDF + b" evil")
        url = (
            admin.post(f"/api/v1/documents/{evil}/download-url", json={})
            .json()["url"]
            .replace("http://testserver", "")
        )
        cd = w.client.get(url).headers["content-disposition"]
        assert "\n" not in cd and '";' not in cd.split("filename=")[1].split(";")[0][1:-1]


def test_rate_limits_apply_per_user(world, monkeypatch):  # noqa: ANN001
    from app.core.config import get_settings

    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_SENSITIVE_PER_MINUTE", "3")
    from app.core.config import reset_settings_cache

    reset_settings_cache()
    try:
        assert get_settings().rate_limit_enabled
        admin = world.org("Limits")
        doc = world.available_doc(
            admin, world.mkdir(admin, world.root_id(admin), "f"), "r.pdf", PDF + b" rl"
        )
        other = world.user(admin, "admin", label="o")
        codes = [
            admin.post(f"/api/v1/documents/{doc}/download-url", json={}).status_code
            for _ in range(5)
        ]
        assert codes[:3] == [200, 200, 200] and codes[3:] == [429, 429]
        r = admin.post(f"/api/v1/documents/{doc}/download-url", json={})
        assert r.json()["error"]["code"] == "rate_limited" and "retry-after" in r.headers
        assert (
            other.post(f"/api/v1/documents/{doc}/download-url", json={}).status_code == 200
        )  # per-user keys
    finally:
        monkeypatch.undo()
        reset_settings_cache()


def test_dev_endpoints_exist_only_with_local_auth_in_dev(env):  # noqa: ANN001
    # In this test process AUTH_PROVIDER=local/APP_ENV=test -> available (and hidden from OpenAPI).
    c = env["world"].client
    spec = c.get("/openapi.json").json()
    assert not any("/dev/" in p for p in spec["paths"])
    import os

    from app.main import create_app

    old = os.environ.get("AUTH_PROVIDER")
    os.environ["AUTH_PROVIDER"] = "supabase"
    os.environ["SUPABASE_URL"] = "https://abc.supabase.co"
    from app.core.config import reset_settings_cache

    reset_settings_cache()
    try:
        paths = {getattr(r, "path", "") for r in create_app().routes}
        assert not any("/dev/" in p for p in paths)
    finally:
        os.environ["AUTH_PROVIDER"] = old or "local"
        os.environ.pop("SUPABASE_URL", None)
        reset_settings_cache()


def test_metrics_endpoint_is_off_unless_token_configured(env):  # noqa: ANN001
    assert env["world"].client.get("/metrics").status_code == 404
    assert (
        env["world"].client.get("/metrics", headers={"Authorization": "Bearer guess"}).status_code
        == 404
    )
