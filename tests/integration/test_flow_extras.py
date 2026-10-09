"""Admin access check / ACL impact, color tags and PDF export."""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"
A = f"{API}/admin"


@pytest.fixture()
def closed(world):  # noqa: ANN001, ANN201
    owner = world.org("Closed Co", member_default_access=False)
    root = world.root_id(owner)
    parent = world.mkdir(owner, root, "Projects")
    child = world.mkdir(owner, parent, "Alpha")
    doc = world.available_doc(owner, child, "plan.pdf")
    member = world.user(owner, "member", label="mem")
    return dict(
        world=world, owner=owner, root=root, parent=parent, child=child, doc=doc, member=member
    )


def check(actor, rtype, rid, uid):  # noqa: ANN001, ANN201
    return actor.post(
        f"{A}/access-check", json={"resource_type": rtype, "resource_id": rid, "user_id": str(uid)}
    )


class TestAccessCheck:
    def test_no_grants_no_access_then_inherited_grant_is_explained(self, closed):  # noqa: ANN001
        o, m = closed["owner"], closed["member"]
        r = check(o, "document", closed["doc"], m.user_id)
        assert r.status_code == 200, r.text
        assert r.json()["actions"] == [] and r.json()["sources"] == []
        g = o.post(
            f"{API}/folders/{closed['parent']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(m.user_id),
                "actions": ["view", "preview"],
                "inherit": True,
            },
        )
        assert g.status_code == 201, g.text
        r = check(o, "document", closed["doc"], m.user_id).json()
        assert {"view", "preview"} <= set(r["actions"])
        src = r["sources"][0]
        assert (
            src["kind"] == "direct"
            and src["inherited_from"] == "Projects"
            and src["actions"] == ["preview", "view"]
        )
        # the explanation matches what enforcement actually does
        assert m.get(f"{API}/documents/{closed['doc']}").status_code == 200
        assert m.post(f"{API}/documents/{closed['doc']}/download-url", json={}).status_code == 403

    def test_non_inheriting_grant_does_not_reach_children(self, closed):  # noqa: ANN001
        o, m = closed["owner"], closed["member"]
        o.post(
            f"{API}/folders/{closed['parent']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(m.user_id),
                "actions": ["view"],
                "inherit": False,
            },
        )
        assert check(o, "folder", closed["parent"], m.user_id).json()["actions"]
        assert check(o, "folder", closed["child"], m.user_id).json()["actions"] == []

    def test_group_grants_and_revocation_take_effect_next_check(self, closed):  # noqa: ANN001
        o, m = closed["owner"], closed["member"]
        gid = o.post(f"{A}/groups", json={"name": "Readers"}).json()["id"]
        o.put(f"{A}/users/{m.user_id}/groups", json={"group_ids": [gid]})
        grant = o.post(
            f"{API}/folders/{closed['child']}/permissions",
            json={"subject_type": "group", "subject_id": gid, "actions": ["view"]},
        ).json()
        r = check(o, "document", closed["doc"], m.user_id).json()
        assert r["sources"][0]["kind"] == "group" and "Readers" in r["sources"][0]["via"]
        assert (
            o.delete(f"{API}/folders/{closed['child']}/permissions/{grant['id']}").status_code
            == 204
        )
        assert check(o, "document", closed["doc"], m.user_id).json()["actions"] == []
        assert m.get(f"{API}/documents/{closed['doc']}").status_code in (403, 404)

    def test_admins_hold_everything_and_suspended_accounts_nothing(self, closed):  # noqa: ANN001
        w, o = closed["world"], closed["owner"]
        adm = w.user(o, "admin", label="adm")
        r = check(o, "document", closed["doc"], adm.user_id).json()
        assert r["sources"][0]["kind"] == "role" and "administer" in r["actions"]
        assert (
            o.patch(f"{API}/admin/members/{adm.user_id}", json={"status": "suspended"}).status_code
            == 200
        )
        r = check(o, "document", closed["doc"], adm.user_id).json()
        assert r["account_state"] == "inactive" and r["actions"] == []

    def test_only_admins_and_tenant_scoped(self, closed):  # noqa: ANN001
        w, o, m = closed["world"], closed["owner"], closed["member"]
        assert check(m, "document", closed["doc"], m.user_id).status_code == 403
        other = w.org("Other")
        assert check(other, "document", closed["doc"], other.user_id).status_code == 404
        assert check(o, "document", closed["doc"], other.user_id).status_code == 404
        assert check(o, "document", str(uuid.uuid4()), m.user_id).status_code == 404
        assert check(o, "document", closed["doc"], m.user_id).status_code == 200
        events = o.get(f"{A}/activity", params={"action": "access.checked"}).json()["items"]
        assert events

    def test_acl_impact_preview(self, closed):  # noqa: ANN001
        o = closed["owner"]
        body = {
            "resource_type": "folder",
            "resource_id": closed["parent"],
            "subject_type": "organization",
            "inherit": True,
        }
        r = o.post(f"{A}/acl-impact", json=body).json()
        assert (
            r["folders_affected"] == 2
            and r["documents_affected"] == 1
            and "Everyone" in r["subject_label"]
        )
        r2 = o.post(f"{A}/acl-impact", json={**body, "inherit": False}).json()
        assert r2["folders_affected"] == 1 and r2["documents_affected"] == 0
        assert closed["member"].post(f"{A}/acl-impact", json=body).status_code == 403


class TestColorTags:
    def test_set_clear_list_and_search(self, closed):  # noqa: ANN001
        o = closed["owner"]
        assert (
            o.put(f"{API}/documents/{closed['doc']}/color-tag", json={"color": "red"}).status_code
            == 204
        )
        assert (
            o.put(f"{API}/folders/{closed['child']}/color-tag", json={"color": "blue"}).status_code
            == 204
        )
        items = {
            i["name"]: i for i in o.get(f"{API}/folders/{closed['child']}/children").json()["items"]
        }
        assert items["plan.pdf"]["color_tag"] == "red"
        parent_items = {
            i["name"]: i
            for i in o.get(f"{API}/folders/{closed['parent']}/children").json()["items"]
        }
        assert parent_items["Alpha"]["color_tag"] == "blue"
        hit = o.get(f"{API}/search", params={"q": "plan", "color_tag": "red"}).json()
        assert [i["name"] for i in hit["items"]] == ["plan.pdf"]
        assert (
            o.get(f"{API}/search", params={"q": "plan", "color_tag": "green"}).json()["total"] == 0
        )
        assert (
            o.put(f"{API}/documents/{closed['doc']}/color-tag", json={"color": None}).status_code
            == 204
        )
        assert o.get(f"{API}/search", params={"q": "plan", "color_tag": "red"}).json()["total"] == 0
        assert (
            o.put(
                f"{API}/documents/{closed['doc']}/color-tag", json={"color": "chartreuse"}
            ).status_code
            == 422
        )

    def test_needs_edit_rights_and_is_audited(self, closed):  # noqa: ANN001
        o, m = closed["owner"], closed["member"]
        o.post(
            f"{API}/folders/{closed['child']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(m.user_id),
                "actions": ["view", "preview"],
            },
        )
        assert (
            m.put(f"{API}/documents/{closed['doc']}/color-tag", json={"color": "red"}).status_code
            == 403
        )
        o.put(f"{API}/documents/{closed['doc']}/color-tag", json={"color": "green"})
        ev = o.get(f"{A}/activity", params={"action": "document.color_tagged"}).json()["items"]
        assert ev and ev[0]["metadata"]["to"] == "green"


class _Resp:
    def __init__(self, status: int, content: bytes) -> None:
        self.status_code, self.content = status, content


@pytest.fixture()
def office(monkeypatch):  # noqa: ANN001, ANN201
    from app.core.config import reset_settings_cache

    monkeypatch.setenv("COLLABORA_URL", "http://office.test:9980")
    reset_settings_cache()
    yield monkeypatch
    monkeypatch.undo()
    reset_settings_cache()


class TestExportPdf:
    def make(self, world, owner, name="memo.docx"):  # noqa: ANN001, ANN201
        folder = world.mkdir(owner, world.root_id(owner), f"f{uuid.uuid4().hex[:4]}")
        return world.available_doc(owner, folder, name, b"PK\x03\x04 fake docx bytes")

    def test_converts_via_the_office_server_and_audits(self, world, office):  # noqa: ANN001
        from app.modules.office import convert

        o = world.org("Pdf Inc")
        doc = self.make(world, o)
        seen = {}

        def fake_post(url, files, timeout):  # noqa: ANN001, ANN202
            seen["url"], seen["name"] = url, files["data"][0]
            return _Resp(200, b"%PDF-1.7 converted")

        office.setattr(convert.httpx, "post", fake_post)
        r = o.post(f"{API}/documents/{doc}/export-pdf")
        assert r.status_code == 200 and r.content.startswith(b"%PDF")
        assert (
            r.headers["content-type"] == "application/pdf"
            and r.headers["cache-control"] == "no-store"
        )
        assert "memo.pdf" in r.headers["content-disposition"]
        assert (
            seen["url"] == "http://office.test:9980/cool/convert-to/pdf"
            and seen["name"] == "document.docx"
        )
        ev = o.get(f"{A}/activity", params={"action": "document.exported_pdf"}).json()["items"]
        assert ev and ev[0]["outcome"] == "success"

    def test_needs_download_right_and_a_convertible_type(self, world, office):  # noqa: ANN001
        from app.modules.office import convert

        office.setattr(convert.httpx, "post", lambda *a, **k: _Resp(200, b"%PDF-1"))
        o = world.org("Closed Pdf", member_default_access=False)
        doc = self.make(world, o)
        stranger = world.user(o, "member", label="s")
        assert stranger.post(f"{API}/documents/{doc}/export-pdf").status_code == 404
        folder = world.mkdir(o, world.root_id(o), "pdfs")
        pdf = world.available_doc(o, folder, "a.pdf")
        assert o.post(f"{API}/documents/{pdf}/export-pdf").json()["error"]["code"] == "already_pdf"
        png = world.upload(
            o, folder, "x.png", b"\x89PNG\r\n\x1a\n" + b"0" * 30, content_type="image/png"
        )["document_id"]
        world.process_jobs()
        assert (
            o.post(f"{API}/documents/{png}/export-pdf").json()["error"]["code"] == "not_convertible"
        )

    def test_failures_are_honest(self, world, office):  # noqa: ANN001
        import httpx

        from app.modules.office import convert

        o = world.org("Fail Pdf")
        doc = self.make(world, o)

        def boom(*a, **k):  # noqa: ANN002, ANN003, ANN202
            raise httpx.ConnectError("down")

        office.setattr(convert.httpx, "post", boom)
        r = o.post(f"{API}/documents/{doc}/export-pdf")
        assert r.status_code == 503 and r.json()["error"]["code"] == "office_unavailable"
        office.setattr(convert.httpx, "post", lambda *a, **k: _Resp(500, b"oops"))
        assert (
            o.post(f"{API}/documents/{doc}/export-pdf").json()["error"]["code"]
            == "conversion_failed"
        )
        office.setattr(convert.httpx, "post", lambda *a, **k: _Resp(200, b"<html>not a pdf"))
        assert (
            o.post(f"{API}/documents/{doc}/export-pdf").json()["error"]["code"]
            == "conversion_failed"
        )

    def test_unavailable_without_an_office_server(self, world, monkeypatch):  # noqa: ANN001
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("COLLABORA_URL", "")
        monkeypatch.setenv("OFFICE_PROVIDER", "none")
        reset_settings_cache()
        try:
            o = world.org("No Office")
            doc = self.make(world, o)
            r = o.post(f"{API}/documents/{doc}/export-pdf")
            assert r.status_code == 503 and r.json()["error"]["code"] == "office_unavailable"
        finally:
            monkeypatch.undo()
            reset_settings_cache()
