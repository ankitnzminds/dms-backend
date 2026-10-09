"""Administrator user management: profile, lifecycle, access level, policies (and what they
enforce), CSV import/export, and activity monitoring with its privacy and tenant guarantees."""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1/admin"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    owner = world.org("Users Inc")
    admin = world.user(owner, "admin", label="adm")
    member = world.user(owner, "member", label="mem")
    auditor = world.user(owner, "auditor", label="aud")
    return dict(world=world, owner=owner, admin=admin, member=member, auditor=auditor)


def created(actor, **body):  # noqa: ANN001, ANN201, ANN003
    body.setdefault("email", f"new-{uuid.uuid4().hex[:8]}@example.test")
    r = actor.post(f"{API}/users", json=body)
    assert r.status_code == 201, r.text
    return r.json()["user"]


class TestListing:
    def test_filters_search_sort_and_pagination(self, env):  # noqa: ANN001
        o = env["owner"]
        created(o, username="alice.w", display_name="Alice Wong", access_level="guest")
        created(o, username="bob.e", display_name="Bob Ext", access_level="external")
        r = o.get(f"{API}/users", params={"status": "guest"})
        assert [u["username"] for u in r.json()["items"]] == ["alice.w"]
        r = o.get(f"{API}/users", params={"q": "ext"})
        assert [u["username"] for u in r.json()["items"]] == ["bob.e"]
        r = o.get(f"{API}/users", params={"sort": "email", "limit": 2, "offset": 0})
        body = r.json()
        assert len(body["items"]) == 2 and body["total"] >= 5
        assert o.get(f"{API}/users", params={"sort": "password"}).status_code == 422

    def test_disabled_filter_is_separate_from_access_level(self, env):  # noqa: ANN001
        o = env["owner"]
        u = created(o, access_level="full")
        assert o.post(f"{API}/users/{u['user_id']}/deactivate").status_code == 200
        r = o.get(f"{API}/users", params={"status": "disabled"}).json()["items"]
        assert [x["user_id"] for x in r] == [u["user_id"]]
        assert r[0]["state"] == "disabled" and r[0]["access_level"] == "full"

    def test_only_admins_and_never_other_tenants(self, env):  # noqa: ANN001
        assert env["member"].get(f"{API}/users").status_code == 403
        assert env["auditor"].get(f"{API}/users").status_code == 403
        other = env["world"].org("Other Org")
        mine = created(env["owner"])
        for method, path in (
            ("get", f"/users/{mine['user_id']}"),
            ("get", f"/users/{mine['user_id']}/quota"),
            ("get", f"/users/{mine['user_id']}/activity"),
            ("get", f"/users/{mine['user_id']}/policy"),
        ):
            assert getattr(other, method)(f"{API}{path}").status_code == 404
        assert other.patch(f"{API}/users/{mine['user_id']}", json={"notes": "x"}).status_code == 404
        assert other.get(f"{API}/users", params={"q": mine["email"]}).json()["total"] == 0


class TestCreateAndUpdate:
    def test_create_persists_profile_and_reports_no_email(self, env):  # noqa: ANN001
        o = env["owner"]
        r = o.post(
            f"{API}/users",
            json={
                "email": "Jane@Example.test",
                "username": "jane",
                "display_name": "Jane",
                "secondary_email": "jane2@example.test",
                "phone": "+1 (415) 555-0123",
                "notes": "VIP",
                "access_level": "guest",
            },
        )
        assert r.status_code == 201
        assert r.json()["invitation_email"] == "not_configured"  # no provider: nothing is faked
        u = r.json()["user"]
        assert u["email"] == "jane@example.test" and u["phone"] == "+14155550123"
        assert u["state"] == "invited" and u["access_level"] == "guest"
        assert u["authentication"] == "default" and u["tos_accepted_at"] is None

    def test_validation_and_uniqueness(self, env):  # noqa: ANN001
        o = env["owner"]
        created(o, username="dupe")
        assert (
            o.post(f"{API}/users", json={"email": "x@y.test", "username": "DUPE"}).status_code
            == 409
        )
        assert o.post(f"{API}/users", json={"email": "bad"}).status_code in (400, 422)
        r = o.post(f"{API}/users", json={"email": "p@y.test", "phone": "12345"})
        assert r.status_code in (400, 422)
        assert o.post(f"{API}/users", json={"email": env["member"].email}).status_code == 409

    def test_update_lock_unlock_and_sessions(self, env):  # noqa: ANN001
        o, m = env["owner"], env["member"]
        assert m.get("/api/v1/me").status_code == 200
        r = o.patch(f"{API}/users/{m.user_id}", json={"account_locked": True, "notes": "review"})
        assert r.status_code == 200 and r.json()["state"] == "locked"
        assert m.get("/api/v1/me").status_code in (401, 403)  # tokens issued before are rejected
        r = o.patch(f"{API}/users/{m.user_id}", json={"account_locked": False})
        assert r.json()["state"] == "active"
        assert o.patch(f"{API}/users/{o.user_id}", json={"account_locked": True}).status_code == 403

    def test_admin_cannot_touch_owner(self, env):  # noqa: ANN001
        a, o = env["admin"], env["owner"]
        assert a.patch(f"{API}/users/{o.user_id}", json={"notes": "x"}).status_code == 403
        assert a.post(f"{API}/users/{o.user_id}/deactivate").status_code == 403

    def test_expired_account_cannot_use_the_organization(self, env):  # noqa: ANN001
        o, m = env["owner"], env["member"]
        past = "2020-01-01T00:00:00+00:00"
        assert (
            o.patch(f"{API}/users/{m.user_id}", json={"account_expires_at": past}).status_code
            == 200
        )
        r = m.get("/api/v1/folders/root")
        assert r.status_code == 403 and r.json()["error"]["code"] == "account_locked"
        r = o.patch(f"{API}/users/{m.user_id}", json={"clear_account_expiry": True})
        assert r.status_code == 200
        assert m.get("/api/v1/folders/root").status_code == 200

    def test_audit_has_field_names_not_personal_values(self, env):  # noqa: ANN001
        o = env["owner"]
        u = created(o)
        o.patch(
            f"{API}/users/{u['user_id']}", json={"phone": "+14155550000", "notes": "secret note"}
        )
        page = o.get(
            f"{API}/users/{u['user_id']}/activity", params={"action": "member.profile_updated"}
        ).json()
        assert page["items"], page
        meta = str(page["items"][0]["metadata"])
        assert "phone" in meta and "notes" in meta
        assert "secret note" not in meta and "+14155550000" not in meta


class TestDeletion:
    def test_needs_confirmation_and_keeps_files(self, env):  # noqa: ANN001
        w, o, m = env["world"], env["owner"], env["member"]
        folder = w.mkdir(o, w.root_id(o), "f")
        w.available_doc(o, folder, "a.pdf")
        impact = o.get(f"{API}/users/{o.user_id}/delete-impact").json()
        assert impact["files_are_deleted"] is False and impact["owned_documents"] >= 1
        assert (
            o.post(
                f"{API}/users/{m.user_id}/delete", json={"confirm": False, "confirm_email": m.email}
            ).status_code
            == 422
        )
        assert (
            o.post(
                f"{API}/users/{m.user_id}/delete",
                json={"confirm": True, "confirm_email": "x@x.test"},
            ).status_code
            == 422
        )
        r = o.post(
            f"{API}/users/{m.user_id}/delete", json={"confirm": True, "confirm_email": m.email}
        )
        assert r.status_code == 204
        assert o.get(f"{API}/users/{m.user_id}").status_code == 404
        assert m.get("/api/v1/me").status_code in (401, 403)
        # history stays readable after removal
        assert o.get(f"{API}/users/{m.user_id}/activity").status_code == 200
        ev = o.get(f"{API}/activity", params={"action": "member.deleted"}).json()["items"]
        assert ev and ev[0]["metadata"]["files_deleted"] is False

    def test_self_and_last_owner_protected(self, env):  # noqa: ANN001
        o = env["owner"]
        r = o.post(
            f"{API}/users/{o.user_id}/delete", json={"confirm": True, "confirm_email": o.email}
        )
        assert r.status_code == 403
        r = o.post(f"{API}/users/{o.user_id}/deactivate")
        assert r.status_code == 403


class TestPolicies:
    def put_org(self, actor, overrides, version=None):  # noqa: ANN001, ANN201
        return actor.put(
            f"{API}/policies/organization",
            json={"overrides": overrides, "expected_version": version},
        )

    def test_validation_and_versioning(self, env):  # noqa: ANN001
        o = env["owner"]
        assert self.put_org(o, {"nope": {}}).status_code == 422
        assert self.put_org(o, {"general": {"share_mode": "bogus"}}).status_code == 422
        assert self.put_org(o, {"general": {"default_share_expiry_days": -1}}).status_code == 422
        assert self.put_org(o, {"general": {"surprise": 1}}).status_code == 422
        bad = self.put_org(o, {"device_config": {"client_configuration_xml": "<a><b></a>"}})
        assert bad.status_code == 422 and "line" in bad.json()["error"]["message"]
        evil = '<!DOCTYPE x [<!ENTITY a "b">]><x>&a;</x>'
        assert (
            self.put_org(o, {"device_config": {"client_configuration_xml": evil}}).status_code
            == 422
        )
        ok = self.put_org(o, {"device_config": {"client_configuration_xml": "<c><k>1</k></c>"}}, 0)
        assert ok.status_code == 200 and ok.json()["version"] == 1
        stale = self.put_org(o, {"general": {"recycle_bin_enabled": False}}, 0)
        assert stale.status_code == 409
        assert (
            env["member"].put(f"{API}/policies/organization", json={"overrides": {}}).status_code
            == 403
        )

    def test_precedence_and_provenance(self, env):  # noqa: ANN001
        o, m = env["owner"], env["member"]
        gid = o.post(f"{API}/groups", json={"name": "Finance"}).json()["id"]
        assert (
            o.put(f"{API}/users/{m.user_id}/groups", json={"group_ids": [gid]}).status_code == 200
        )
        self.put_org(o, {"general": {"default_share_expiry_days": 30, "default_max_downloads": 5}})
        o.put(
            f"{API}/groups/{gid}/policy",
            json={"overrides": {"general": {"default_share_expiry_days": 14}}},
        )
        o.put(
            f"{API}/users/{m.user_id}/policy",
            json={"overrides": {"user_policy": {"max_upload_bytes": 1000}}},
        )
        eff = o.get(f"{API}/users/{m.user_id}/policy/effective").json()
        assert eff["values"]["general"]["default_share_expiry_days"] == 14
        assert eff["provenance"]["general.default_share_expiry_days"] == "group:Finance"
        assert eff["provenance"]["general.default_max_downloads"] == "organization"
        assert eff["provenance"]["user_policy.max_upload_bytes"] == "user"
        assert eff["provenance"]["mfa.require_mfa"] == "default"
        assert eff["applied_from"] == "user"
        assert eff["inherited"]["user_policy"]["max_upload_bytes"] == 0  # without the user override
        assert eff["inherited_provenance"]["general.default_share_expiry_days"] == "group:Finance"
        assert "user_policy.max_upload_bytes" in eff["enforced"]
        assert "mfa.require_mfa" not in eff["enforced"]  # stored, honestly not enforced
        reset = o.post(f"{API}/users/{m.user_id}/policy/reset")
        assert reset.json()["overrides"] == {}

    def test_policy_enforcement_upload_limits_and_storage(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        folder = w.mkdir(o, w.root_id(o), "up")

        def initiate(actor, size=100):  # noqa: ANN001, ANN202
            return actor.post(
                f"/api/v1/folders/{folder}/uploads",
                json={"filename": "a.pdf", "size_bytes": size, "content_type": "application/pdf"},
            )

        r = o.put(
            f"{API}/users/{o.user_id}/policy",
            json={"overrides": {"user_policy": {"max_upload_bytes": 50}}},
        )
        assert r.status_code == 200
        assert initiate(o, 100).status_code == 413
        assert initiate(o, 40).status_code == 201
        o.put(
            f"{API}/users/{o.user_id}/policy",
            json={"overrides": {"general": {"user_storage_quota_bytes": 10}}},
        )
        over = initiate(o, 40)
        assert over.status_code == 409 and over.json()["error"]["code"] == "user_quota", over.text
        q = o.get(f"{API}/users/{o.user_id}/quota").json()
        assert q["quota_bytes"] == 10 and q["quota_source"] == "user"

    def test_guest_and_external_have_no_storage(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        folder = w.mkdir(o, w.root_id(o), "g")
        assert (
            o.patch(f"{API}/users/{o.user_id}", json={"access_level": "guest"}).status_code == 200
        )
        r = o.post(
            f"/api/v1/folders/{folder}/uploads",
            json={"filename": "a.pdf", "size_bytes": 10, "content_type": "application/pdf"},
        )
        assert r.status_code == 403 and r.json()["error"]["code"] == "no_storage_access"

    def test_share_policy(self, env):  # noqa: ANN001
        w, o, m = env["world"], env["owner"], env["member"]
        folder = w.mkdir(o, w.root_id(o), "s")
        doc = w.available_doc(o, folder, "s.pdf")
        body = {"recipients": [{"type": "user", "id": str(m.user_id)}], "actions": ["view"]}
        o.put(
            f"{API}/users/{o.user_id}/policy",
            json={"overrides": {"general": {"default_share_expiry_days": 7}}},
        )
        r = o.post(f"/api/v1/documents/{doc}/shares", json=body)
        assert r.status_code == 201, r.text
        assert r.json()["expires_at"] is not None  # default expiry applied
        o.put(
            f"{API}/users/{o.user_id}/policy",
            json={"overrides": {"general": {"share_mode": "no_shares"}}},
        )
        assert o.post(f"/api/v1/documents/{doc}/shares", json=body).status_code == 403


class TestImportExport:
    CSV = (
        "UserName,EmailID,Password,DisplayName,Status,ExpirationDate,Groups\n"
        "ann,ann@x.test,Sup3rSecret!,Ann,Full,2030-01-01,Finance\n"
        "bad,not-an-email,,Bad,Full,,\n"
        "dup,ann@x.test,,Dup,Full,,\n"
        "gst,gst@x.test,,Gst,Guest,,Missing\n"
        "ext,ext@x.test,,=cmd|' /C calc'!A0,External,,\n"
    )

    def test_preview_changes_nothing_then_commit(self, env):  # noqa: ANN001
        o = env["owner"]
        o.post(f"{API}/groups", json={"name": "Finance"})
        before = o.get(f"{API}/users").json()["total"]
        p = o.post(f"{API}/users/import/preview", json={"csv": self.CSV})
        assert p.status_code == 200, p.text
        pv = p.json()
        assert (pv["total"], pv["creates"], pv["invalid"]) == (5, 2, 3)
        assert "Sup3rSecret!" not in p.text
        assert any("Password is ignored" in c for c in pv["columns_seen"])
        assert o.get(f"{API}/users").json()["total"] == before
        r = o.post(f"{API}/users/import", json={"csv": self.CSV})
        assert r.status_code == 200 and r.json()["created"] == 2
        assert "Sup3rSecret!" not in r.text
        again = o.post(f"{API}/users/import", json={"csv": self.CSV}).json()
        assert again["created"] == 0 and again["skipped_existing"] == 2  # never overwritten
        ann = o.get(f"{API}/users", params={"q": "ann@x.test"}).json()["items"][0]
        assert ann["creation_source"] == "csv_import" and ann["group_ids"]

    def test_limits_and_permissions(self, env):  # noqa: ANN001
        o = env["owner"]
        assert (
            env["member"].post(f"{API}/users/import/preview", json={"csv": self.CSV}).status_code
            == 403
        )
        assert o.post(f"{API}/users/import/preview", json={"csv": ""}).status_code == 422
        assert o.post(f"{API}/users/import/preview", json={"csv": "Foo\nbar\n"}).status_code == 422
        many = "EmailID\n" + "\n".join(f"u{i}@x.test" for i in range(1001))
        assert o.post(f"{API}/users/import/preview", json={"csv": many}).status_code == 422
        assert "EmailID" in o.get(f"{API}/users/import/template").text

    def test_export_is_formula_safe_and_secret_free(self, env):  # noqa: ANN001
        o = env["owner"]
        created(o, display_name='=HYPERLINK("http://evil")', phone="+14155550123", notes="private")
        r = o.get(f"{API}/users/export")
        assert r.status_code == 200 and "text/csv" in r.headers["content-type"]
        assert "'=HYPERLINK" in r.text
        assert "+14155550123" not in r.text and "private" not in r.text
        ev = o.get(f"{API}/activity", params={"action": "member.exported"}).json()["items"]
        assert ev


class TestActivity:
    def test_roles_scope_and_privacy(self, env):  # noqa: ANN001
        o, a, aud, m = env["owner"], env["admin"], env["auditor"], env["member"]
        created(o)
        assert m.get(f"{API}/activity").status_code == 403
        assert m.get(f"{API}/audit-policy").status_code == 403
        assert aud.get(f"{API}/activity").status_code == 200  # read-only auditor
        assert aud.post(f"{API}/users", json={"email": "z@z.test"}).status_code == 403
        owner_view = o.get(f"{API}/activity", params={"limit": 200}).json()["items"]
        admin_view = a.get(f"{API}/activity", params={"limit": 200}).json()["items"]
        assert owner_view  # the owner may see network details; the admin may not
        assert all(e["ip_address"] is None and e["user_agent"] is None for e in admin_view)

    def test_cursor_pagination_is_stable(self, env):  # noqa: ANN001
        o = env["owner"]
        for _ in range(6):
            created(o)
        seen: list[str] = []
        cursor = None
        for _ in range(20):
            page = o.get(
                f"{API}/activity", params={"limit": 4, "cursor": cursor, "action": "member.invited"}
            ).json()
            seen += [e["id"] for e in page["items"]]
            cursor = page["next_cursor"]
            if not cursor:
                break
        assert len(seen) == len(set(seen)) >= 6
        assert o.get(f"{API}/activity", params={"cursor": "garbage"}).status_code == 422

    def test_user_timeline_includes_actions_by_and_on_the_user(self, env):  # noqa: ANN001
        o, m = env["owner"], env["member"]
        o.patch(f"{API}/users/{m.user_id}", json={"notes": "n"})
        items = o.get(f"{API}/users/{m.user_id}/activity").json()["items"]
        assert any(
            e["action"] == "member.profile_updated" and e["target_label"] == m.email for e in items
        )
        assert all(e["category"] for e in items)

    def test_viewing_and_exporting_are_audited(self, env):  # noqa: ANN001
        o, aud = env["owner"], env["auditor"]
        aud.get(f"{API}/activity")
        aud.get(f"{API}/activity/export")
        actions = {
            e["action"] for e in o.get(f"{API}/activity", params={"limit": 200}).json()["items"]
        }
        assert {"audit.viewed", "audit.exported"} <= actions

    def test_cross_tenant_event_ids_are_not_readable(self, env):  # noqa: ANN001
        o = env["owner"]
        other = env["world"].org("Elsewhere")
        created(o)
        eid = o.get(f"{API}/activity").json()["items"][0]["id"]
        assert o.get(f"{API}/activity/{eid}").status_code == 200
        assert other.get(f"{API}/activity/{eid}").status_code == 404
        leak = other.get(f"{API}/activity", params={"user_id": str(env["member"].user_id)})
        assert leak.json()["items"] == []
        ids = {e["id"] for e in other.get(f"{API}/activity", params={"limit": 200}).json()["items"]}
        assert eid not in ids

    def test_audit_events_are_immutable_for_everyone(self, env, db):  # noqa: ANN001
        from sqlalchemy import text
        from sqlalchemy.exc import DBAPIError

        created(env["owner"])
        with pytest.raises(DBAPIError):
            db.execute(text("UPDATE dms.audit_events SET action = 'x'"))
        db.rollback()
        with pytest.raises(DBAPIError):
            db.execute(text("DELETE FROM dms.audit_events"))
        db.rollback()

    def test_policy_and_coverage_endpoint(self, env):  # noqa: ANN001
        p = env["owner"].get(f"{API}/audit-policy").json()
        assert p["append_only"] is True and "files" in p["categories"]
        assert any("password" in n for n in p["never_recorded"])

    def test_no_secrets_in_recorded_metadata(self, env):  # noqa: ANN001
        o = env["owner"]
        o.post(f"{API}/users/import", json={"csv": TestImportExport.CSV})
        blob = str(o.get(f"{API}/activity", params={"limit": 200}).json())
        assert "Sup3rSecret!" not in blob


class TestAdmins:
    def test_lists_privileged_roles_only(self, env):  # noqa: ANN001
        r = env["owner"].get(f"{API}/admins").json()
        assert {x["role"] for x in r} == {"owner", "admin", "auditor"}
        assert env["member"].get(f"{API}/admins").status_code == 403


class TestGroups:
    def test_replace_memberships_and_directory_groups_are_read_only(self, env, db):  # noqa: ANN001
        from app.db.models import Group

        o, m = env["owner"], env["member"]
        g1 = o.post(f"{API}/groups", json={"name": "A"}).json()["id"]
        g2 = o.post(f"{API}/groups", json={"name": "B"}).json()["id"]
        r = o.put(f"{API}/users/{m.user_id}/groups", json={"group_ids": [g1, g2]})
        assert sorted(r.json()["group_ids"]) == sorted([g1, g2])
        r = o.put(f"{API}/users/{m.user_id}/groups", json={"group_ids": [g2]})
        assert r.json()["group_ids"] == [g2]
        db.add(Group(id=uuid.uuid4(), organization_id=o.org_id, name="Synced", external_id="ext-1"))
        db.commit()
        synced = str(db.query(Group).filter_by(name="Synced", organization_id=o.org_id).one().id)
        assert (
            o.put(f"{API}/users/{m.user_id}/groups", json={"group_ids": [synced]}).status_code
            == 409
        )
        assert (
            o.put(
                f"{API}/users/{m.user_id}/groups", json={"group_ids": [str(uuid.uuid4())]}
            ).status_code
            == 422
        )
