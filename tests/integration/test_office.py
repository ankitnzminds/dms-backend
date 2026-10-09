"""Office (WOPI) integration: sessions, scoped tokens, per-call re-authorization, locks, saves as new
versions, view-only restrictions and audit. The office server itself is simulated by calling the WOPI
endpoints exactly as Collabora does; a real-server check lives in the frontend E2E/documentation."""

from __future__ import annotations

import io
import zipfile

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


_STAMP = (2026, 1, 1, 0, 0, 0)


def make_docx(text: str = "hello") -> bytes:
    """Deterministic bytes (fixed zip timestamps) so content can be compared exactly."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            zipfile.ZipInfo("[Content_Types].xml", _STAMP),
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        z.writestr(
            zipfile.ZipInfo("word/document.xml", _STAMP),
            f"<w:document xmlns:w='x'><w:body>{text}</w:body></w:document>",
        )
    return buf.getvalue()


@pytest.fixture()
def office(monkeypatch):  # noqa: ANN001, ANN201
    from app.core.config import reset_settings_cache
    from app.modules.office import discovery

    monkeypatch.setenv("COLLABORA_URL", "http://office.test:9980")
    monkeypatch.setenv("WOPI_HOST_URL", "http://backend.test:8000")
    reset_settings_cache()
    discovery.reset_discovery_cache()
    table = {
        ("view", "docx"): "http://office.test:9980/browser/abc/cool.html?",
        ("edit", "docx"): "http://office.test:9980/browser/abc/cool.html?",
        ("view", "doc"): "http://office.test:9980/browser/abc/cool.html?",
        ("view", "xlsx"): "http://office.test:9980/browser/abc/cool.html?",
    }
    monkeypatch.setattr(discovery, "_load", lambda: table)
    yield
    discovery.reset_discovery_cache()
    monkeypatch.undo()
    reset_settings_cache()


@pytest.fixture()
def env(world, office):  # noqa: ANN001, ANN201
    admin = world.org("Off", member_default_access=False)
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "docs")
    doc = world.available_doc(admin, folder, "report.docx", make_docx("original"))
    return dict(world=world, admin=admin, folder=folder, doc=doc)


def session(actor, doc, mode="view"):  # noqa: ANN001, ANN201
    r = actor.post(f"{API}/documents/{doc}/office-session", json={"mode": mode})
    return r


def wopi(client, method, doc, token, path="", headers=None, content=None):  # noqa: ANN001, ANN201
    return client.request(
        method,
        f"{API}/wopi/files/{doc}{path}",
        params={"access_token": token},
        headers=headers or {},
        content=content,
    )


class TestSession:
    def test_status_and_session_urls(self, env):  # noqa: ANN001
        a = env["admin"]
        assert a.get(f"{API}/office/status").json()["available"] is True
        s = session(a, env["doc"], "edit").json()
        assert s["mode"] == "edit" and s["can_edit"] and s["can_download"]
        assert s["editor_url"].startswith("http://office.test:9980/browser/abc/cool.html?WOPISrc=")
        assert f"backend.test%3A8000%2Fapi%2Fv1%2Fwopi%2Ffiles%2F{env['doc']}" in s["editor_url"]
        assert "access_token" not in s["editor_url"]  # the token is never part of a URL

    def test_unavailable_when_not_configured_and_unsupported_types(self, env, monkeypatch):  # noqa: ANN001
        a, w = env["admin"], env["world"]
        txt = w.available_doc(a, env["folder"], "n.txt", b"plain")
        r = session(a, txt)
        assert r.status_code == 422 and r.json()["error"]["code"] == "office_unsupported_type"
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("COLLABORA_URL", "")
        reset_settings_cache()
        r = session(a, env["doc"])
        assert r.status_code == 503 and r.json()["error"]["code"] == "office_unavailable"
        assert a.get(f"{API}/office/status").json()["available"] is False

    def test_permissions_decide_the_mode(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        viewer = w.user(a, "member", label="viewer")
        editor = w.user(a, "member", label="editor")
        stranger = w.user(a, "member", label="stranger")
        a.post(
            f"{API}/documents/{env['doc']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(viewer.user_id),
                "actions": ["view", "preview"],
            },
        )
        a.post(
            f"{API}/documents/{env['doc']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(editor.user_id),
                "actions": ["view", "preview", "upload_version", "download"],
            },
        )
        v = session(viewer, env["doc"], "edit").json()
        assert (
            v["mode"] == "view"
            and not v["can_edit"]
            and "permission" in v["reason"]
            and not v["can_download"]
        )
        e = session(editor, env["doc"], "edit").json()
        assert e["mode"] == "edit" and e["can_download"]
        assert (
            session(stranger, env["doc"]).status_code == 404
        )  # not visible: indistinguishable from missing
        assert (
            w.org("OffOther")
            .post(f"{API}/documents/{env['doc']}/office-session", json={})
            .status_code
            == 404
        )

    def test_checked_out_by_someone_else_downgrades_to_view(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        bob = w.user(a, "member", label="bob")
        a.post(
            f"{API}/documents/{env['doc']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(bob.user_id),
                "actions": ["view", "preview", "upload_version"],
            },
        )
        assert a.post(f"{API}/documents/{env['doc']}/lock", json={}).status_code == 201
        r = session(bob, env["doc"], "edit").json()
        assert r["mode"] == "view" and "checked out" in r["reason"]

    def test_legacy_formats_are_view_only_and_audited(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        legacy = w.available_doc(
            a, env["folder"], "old.doc", b"\xd0\xcf\x11\xe0" + b"legacy-doc-body" * 8
        )
        r = session(a, legacy, "edit").json()
        assert r["mode"] == "view" and "read-only" in r["reason"]
        events = a.get(f"{API}/admin/audit-events", params={"limit": 100}).json()["items"]
        assert "document.office_opened" in {e["action"] for e in events}


class TestWopiHost:
    def test_check_file_info_and_contents(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        tok = session(a, env["doc"], "edit").json()["access_token"]
        info = wopi(w.client, "GET", env["doc"], tok).json()
        assert (
            info["BaseFileName"] == "report.docx" and info["UserCanWrite"] and not info["ReadOnly"]
        )
        assert info["UserCanNotWriteRelative"] is True and info["DisablePrint"] is False
        assert info["Version"] == "1" and info["Size"] > 0
        body = wopi(w.client, "GET", env["doc"], tok, "/contents")
        assert body.status_code == 200 and body.content == make_docx("original")

    def test_view_token_cannot_write_and_view_only_users_cannot_export(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        viewer = w.user(a, "member", label="v")
        a.post(
            f"{API}/documents/{env['doc']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(viewer.user_id),
                "actions": ["view", "preview"],
            },
        )
        tok = session(viewer, env["doc"], "edit").json()["access_token"]
        info = wopi(w.client, "GET", env["doc"], tok).json()
        assert (
            info["ReadOnly"]
            and info["DisablePrint"]
            and info["DisableExport"]
            and info["DisableCopy"]
        )
        lock = wopi(
            w.client,
            "POST",
            env["doc"],
            tok,
            headers={"X-WOPI-Override": "LOCK", "X-WOPI-Lock": "L1"},
        )
        assert lock.status_code == 403
        put = wopi(
            w.client,
            "POST",
            env["doc"],
            tok,
            "/contents",
            headers={"X-WOPI-Override": "PUT", "X-WOPI-Lock": "L1"},
            content=make_docx("hack"),
        )
        assert put.status_code == 403

    def test_token_is_bound_to_one_document_and_must_be_valid(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        other = w.available_doc(a, env["folder"], "other.docx", make_docx("other"))
        tok = session(a, env["doc"]).json()["access_token"]
        assert wopi(w.client, "GET", other, tok).status_code == 404
        assert wopi(w.client, "GET", env["doc"], "garbage").status_code == 401
        assert wopi(w.client, "GET", env["doc"], "").status_code == 401
        dl = a.post(f"{API}/documents/{env['doc']}/download-url", json={}).json()["url"]
        ticket = dl.split("token=")[-1].split("&")[0]
        assert (
            wopi(w.client, "GET", env["doc"], ticket).status_code == 401
        )  # a download ticket is not a WOPI token

    def test_lock_save_creates_a_new_version_and_keeps_history(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        tok = session(a, env["doc"], "edit").json()["access_token"]
        c = w.client
        no_lock = wopi(
            c,
            "POST",
            env["doc"],
            tok,
            "/contents",
            headers={"X-WOPI-Override": "PUT"},
            content=make_docx("v2"),
        )
        assert no_lock.status_code == 409  # saving needs the lock
        assert (
            wopi(
                c, "POST", env["doc"], tok, headers={"X-WOPI-Override": "LOCK", "X-WOPI-Lock": "L1"}
            ).status_code
            == 200
        )
        clash = wopi(
            c, "POST", env["doc"], tok, headers={"X-WOPI-Override": "LOCK", "X-WOPI-Lock": "L2"}
        )
        assert clash.status_code == 409 and clash.headers["x-wopi-lock"] == "L1"
        assert (
            wopi(c, "POST", env["doc"], tok, headers={"X-WOPI-Override": "GET_LOCK"}).headers[
                "x-wopi-lock"
            ]
            == "L1"
        )
        wrong = wopi(
            c,
            "POST",
            env["doc"],
            tok,
            "/contents",
            headers={"X-WOPI-Override": "PUT", "X-WOPI-Lock": "NOPE"},
            content=make_docx("v2"),
        )
        assert wrong.status_code == 409 and wrong.headers["x-wopi-lock"] == "L1"
        saved = wopi(
            c,
            "POST",
            env["doc"],
            tok,
            "/contents",
            headers={"X-WOPI-Override": "PUT", "X-WOPI-Lock": "L1"},
            content=make_docx("v2"),
        )
        assert saved.status_code == 200 and saved.headers["x-wopi-itemversion"] == "2"
        versions = a.get(f"{API}/documents/{env['doc']}/versions").json()
        assert [v["version_number"] for v in versions] == [2, 1]
        w.process_jobs()  # scan -> the new version becomes current
        assert wopi(c, "GET", env["doc"], tok, "/contents").content == make_docx("v2")
        assert a.get(f"{API}/documents/{env['doc']}").json()["latest_version_number"] == 2
        old = a.post(
            f"{API}/documents/{env['doc']}/download-url", json={"version_number": 1}
        ).json()["url"]
        assert c.get(old.replace("http://testserver", "")).content == make_docx(
            "original"
        )  # v1 untouched
        assert (
            wopi(
                c,
                "POST",
                env["doc"],
                tok,
                headers={"X-WOPI-Override": "UNLOCK", "X-WOPI-Lock": "L1"},
            ).status_code
            == 200
        )
        assert (
            wopi(c, "POST", env["doc"], tok, headers={"X-WOPI-Override": "GET_LOCK"}).headers[
                "x-wopi-lock"
            ]
            == ""
        )
        actions = {
            e["action"]
            for e in a.get(f"{API}/admin/audit-events", params={"limit": 100}).json()["items"]
        }
        assert {"document.office_saved", "document.version_created"} <= actions

    def test_access_is_rechecked_on_every_call_not_just_at_session_start(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        bob = w.user(a, "member", label="bob")
        g = a.post(
            f"{API}/documents/{env['doc']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(bob.user_id),
                "actions": ["view", "preview", "upload_version"],
            },
        ).json()
        tok = session(bob, env["doc"], "edit").json()["access_token"]
        assert wopi(w.client, "GET", env["doc"], tok).json()["UserCanWrite"] is True
        # edit right revoked mid-session -> read-only at the next call, writes denied
        assert a.delete(f"{API}/documents/{env['doc']}/permissions/{g['id']}").status_code in (
            200,
            204,
        )
        a.post(
            f"{API}/documents/{env['doc']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(bob.user_id),
                "actions": ["view", "preview"],
            },
        )
        assert wopi(w.client, "GET", env["doc"], tok).json()["UserCanWrite"] is False
        assert (
            wopi(
                w.client,
                "POST",
                env["doc"],
                tok,
                headers={"X-WOPI-Override": "LOCK", "X-WOPI-Lock": "x"},
            ).status_code
            == 403
        )
        # all access revoked -> even reading is gone
        g2 = a.get(f"{API}/documents/{env['doc']}/permissions").json()
        for grant in g2:
            if grant["subject_id"] == str(bob.user_id):
                a.delete(f"{API}/documents/{env['doc']}/permissions/{grant['id']}")
        assert wopi(w.client, "GET", env["doc"], tok).status_code == 404
        assert wopi(w.client, "GET", env["doc"], tok, "/contents").status_code == 404

    def test_unsupported_operations_and_oversize_saves(self, env, monkeypatch):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        tok = session(a, env["doc"], "edit").json()["access_token"]
        for op in ("PUT_RELATIVE", "RENAME_FILE", "DELETE"):
            assert (
                wopi(w.client, "POST", env["doc"], tok, headers={"X-WOPI-Override": op}).status_code
                == 501
            )
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("OFFICE_MAX_BYTES", "100")
        reset_settings_cache()
        wopi(
            w.client,
            "POST",
            env["doc"],
            tok,
            headers={"X-WOPI-Override": "LOCK", "X-WOPI-Lock": "L1"},
        )
        big = wopi(
            w.client,
            "POST",
            env["doc"],
            tok,
            "/contents",
            headers={"X-WOPI-Override": "PUT", "X-WOPI-Lock": "L1"},
            content=b"x" * 500,
        )
        assert big.status_code == 413

    def test_quarantined_documents_are_never_served(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        tok = session(a, env["doc"]).json()["access_token"]
        from sqlalchemy import text

        with w.db_factory() as db:
            db.execute(
                text("UPDATE dms.documents SET status='quarantined' WHERE id = :d"),
                {"d": env["doc"]},
            )
            db.commit()
        assert wopi(w.client, "GET", env["doc"], tok, "/contents").status_code in (403, 409)
        assert session(a, env["doc"]).status_code in (403, 409)


class TestInlineTextTypes:
    def test_csv_markdown_json_preview_inline_but_binary_claims_are_downgraded(self, world):  # noqa: ANN001
        a = world.org("InlineT")
        folder = world.mkdir(a, world.root_id(a), "t")
        for name, ct, body in (
            ("data.csv", "text/csv", b"a,b\n1,2\n"),
            ("notes.md", "text/markdown", b"# Title\ntext\n"),
            ("conf.json", "application/json", b'{"k": 1}'),
        ):
            doc = world.upload(a, folder, name, body, content_type=ct)["document_id"]
            world.process_jobs()
            r = a.post(f"{API}/documents/{doc}/download-url", json={"inline": True})
            assert r.status_code == 200, (name, r.text)
            served = world.client.get(r.json()["url"].replace("http://testserver", ""))
            assert served.headers["content-type"].startswith(ct) and served.content == body
            assert "attachment" not in served.headers["content-disposition"]
        evil = world.upload(a, folder, "fake.csv", b"\x00\x01\x02binary", content_type="text/csv")[
            "document_id"
        ]
        world.process_jobs()
        r = a.post(f"{API}/documents/{evil}/download-url", json={"inline": True})
        assert r.status_code == 409 and r.json()["error"]["code"] == "not_previewable"
