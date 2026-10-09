"""Directory provisioning: static sync engine, guards, deprovisioning, adapters (mocked)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text

from app.adapters.directory.base import DirectoryError, resolve_secret
from app.adapters.directory.providers import EntraDirectory, LdapDirectory

pytestmark = pytest.mark.integration

_DOMAIN = {"value": "corp.test"}


def D() -> str:  # noqa: N802
    """Per-test e-mail domain: users are global by e-mail, so tests must not share addresses."""
    return _DOMAIN["value"]


@pytest.fixture(autouse=True)
def _unique_domain():  # noqa: ANN202
    import uuid

    _DOMAIN["value"] = f"c{uuid.uuid4().hex[:10]}.test"
    yield


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Dir", member_default_access=False)
    src = admin.post(
        "/api/v1/admin/directory/sources", json={"name": "HR export", "kind": "static"}
    )
    assert src.status_code == 201, src.text
    return dict(world=world, admin=admin, source=src.json())


def users(*emails, active=True):  # noqa: ANN002, ANN202
    return [
        {
            "external_id": f"id-{e.split('@')[0]}",
            "email": e,
            "display_name": e.split("@")[0].title(),
            "active": active,
        }
        for e in emails
    ]


def upload(env, user_list, groups=None):  # noqa: ANN001, ANN202
    r = env["admin"].put(
        f"/api/v1/admin/directory/sources/{env['source']['id']}/snapshot",
        json={"users": user_list, "groups": groups or []},
    )
    assert r.status_code == 200, r.text
    return r.json()


def sync(env, dry_run=False):  # noqa: ANN001, ANN202
    r = env["admin"].post(
        f"/api/v1/admin/directory/sources/{env['source']['id']}/sync", json={"dry_run": dry_run}
    )
    assert r.status_code == 202, r.text
    env["world"].process_jobs()
    return env["admin"].get(f"/api/v1/admin/directory/runs/{r.json()['id']}").json()


def members(env):  # noqa: ANN001, ANN202
    items = env["admin"].get("/api/v1/admin/members", params={"limit": 200}).json()["items"]
    return {m["email"]: m for m in items}


class TestProvisioning:
    def test_creates_invited_accounts_groups_and_memberships_idempotently(self, env):  # noqa: ANN001
        upload(
            env,
            users(f"ann@{D()}", f"ben@{D()}", f"cat@{D()}"),
            [{"external_id": "g-fin", "name": "Finance", "member_ids": ["id-ann", "id-ben"]}],
        )
        run = sync(env)
        assert run["state"] == "succeeded", run
        assert (
            run["stats"]["users_created"] == 3
            and run["stats"]["groups_created"] == 1
            and run["stats"]["group_members_added"] == 2
        )
        m = members(env)
        assert (
            m[f"ann@{D()}"]["membership_status"] == "invited"
            and m[f"ann@{D()}"]["role"] == "member"
        )
        groups = {g["name"]: g for g in env["admin"].get("/api/v1/admin/groups").json()["items"]}
        assert groups["Finance"]["member_count"] == 2
        again = sync(env)  # second run changes nothing
        assert again["state"] == "succeeded" and not any(
            k
            for k in again["stats"]
            if k.endswith(("_created", "_added", "_removed", "_deprovisioned"))
            and again["stats"][k]
        )

    def test_dry_run_reports_without_changing_anything(self, env):  # noqa: ANN001
        upload(env, users(f"ann@{D()}", f"ben@{D()}"))
        run = sync(env, dry_run=True)
        assert (
            run["state"] == "succeeded"
            and run["dry_run"] is True
            and run["stats"]["users_created"] == 2
        )
        assert f"ann@{D()}" not in members(env)

    def test_existing_users_are_linked_not_duplicated_and_login_binds_by_verified_email(self, env):  # noqa: ANN001
        w = env["world"]
        existing = w.user(env["admin"], "member", label="zoe")
        upload(env, users(existing.email, f"new@{D()}"))
        run = sync(env)
        assert run["stats"]["users_linked"] == 1 and run["stats"]["users_created"] == 1
        assert members(env)[existing.email]["membership_status"] == "active"  # untouched
        # a provisioned (invited) person signs in with a verified e-mail -> account binds and activates
        token = w.token_for("sub-new-person", f"new@{D()}")
        r = w.client.get(
            "/api/v1/folders/root",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Organization-Id": str(env["admin"].org_id),
            },
        )
        assert r.status_code in (
            200,
            404,
        )  # authenticated and a member (root is not visible without grants)
        assert members(env)[f"new@{D()}"]["membership_status"] == "active"


class TestDeprovisioning:
    def test_removed_and_disabled_users_lose_access_and_sessions_at_once(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        a, b = w.user(admin, "member", label="a"), w.user(admin, "member", label="b")
        upload(env, users(a.email, b.email, f"keep1@{D()}", f"keep2@{D()}"))
        sync(env)
        assert a.get("/api/v1/folders/root").status_code in (200, 404)  # a is a working member
        # b disabled in the directory, a removed from it entirely
        upload(env, [*users(b.email, active=False), *users(f"keep1@{D()}", f"keep2@{D()}")])
        run = sync(env)
        assert run["state"] == "succeeded" and run["stats"]["users_deprovisioned"] == 2, run
        for gone in (a, b):
            r = gone.get("/api/v1/folders/root")
            assert r.status_code in (401, 403), r.text  # session revoked / no membership
        assert members(admin and env)[a.email]["membership_status"] == "removed"
        actions = {
            e["action"]
            for e in admin.get("/api/v1/admin/audit-events", params={"limit": 200}).json()["items"]
        }
        assert {"member.deprovisioned", "directory.sync_succeeded"} <= actions

    def test_returning_users_are_reactivated_only_if_sync_removed_them(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        a = w.user(admin, "member", label="back")
        keepers = users(f"k1@{D()}", f"k2@{D()}", f"k3@{D()}")
        upload(env, [*users(a.email), *keepers])
        sync(env)
        upload(env, keepers)
        sync(env)
        assert members(env)[a.email]["membership_status"] == "removed"
        upload(env, [*users(a.email), *keepers])
        assert sync(env)["stats"]["memberships_reactivated"] == 1
        assert members(env)[a.email]["membership_status"] == "active"
        # a membership suspended manually by an admin is NOT reactivated by sync
        admin.patch(f"/api/v1/admin/members/{a.user_id}", json={"status": "suspended"})
        sync(env)
        assert members(env)[a.email]["membership_status"] == "suspended"

    def test_administrators_are_not_removed_automatically(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        boss = w.user(admin, "admin", label="boss")
        upload(env, users(boss.email, f"k1@{D()}", f"k2@{D()}"))
        sync(env)
        upload(env, users(f"k1@{D()}", f"k2@{D()}"))
        run = sync(env)
        assert (
            run["stats"]["protected_admins_skipped"] == 1
            and "users_deprovisioned" not in run["stats"]
        )
        assert members(env)[boss.email]["membership_status"] == "active"
        # explicit opt-in allows it
        admin.patch(
            f"/api/v1/admin/directory/sources/{env['source']['id']}",
            json={"config": {"allow_admin_deprovision": True}},
        )
        assert sync(env)["stats"]["users_deprovisioned"] == 1

    def test_group_changes_apply_and_removed_groups_end_access(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        upload(
            env,
            users(f"ann@{D()}", f"ben@{D()}", f"k1@{D()}"),
            [
                {"external_id": "g1", "name": "Legal", "member_ids": ["id-ann", "id-ben"]},
                {"external_id": "g2", "name": "Ops", "member_ids": ["id-k1"]},
            ],
        )
        sync(env)
        legal = next(
            g for g in admin.get("/api/v1/admin/groups").json()["items"] if g["name"] == "Legal"
        )
        folder = w.mkdir(admin, w.root_id(admin), "legal-docs")
        admin.post(
            f"/api/v1/folders/{folder}/permissions",
            json={"subject_type": "group", "subject_id": legal["id"], "actions": ["view"]},
        )
        upload(
            env,
            users(f"ann@{D()}", f"ben@{D()}", f"k1@{D()}"),
            [
                {"external_id": "g1", "name": "Legal Dept", "member_ids": ["id-ann"]},
                {"external_id": "g2", "name": "Ops", "member_ids": ["id-k1"]},
            ],
        )
        run = sync(env)
        assert run["stats"]["groups_renamed"] == 1 and run["stats"]["group_members_removed"] == 1
        assert (
            admin.get(f"/api/v1/admin/groups/{legal['id']}/members").json()[0]["email"]
            == f"ann@{D()}"
        )
        upload(
            env,
            users(f"ann@{D()}", f"ben@{D()}", f"k1@{D()}"),
            [{"external_id": "g2", "name": "Ops", "member_ids": ["id-k1"]}],
        )
        assert sync(env)["stats"]["groups_deleted"] == 1
        assert legal["id"] not in {
            g["id"] for g in admin.get("/api/v1/admin/groups").json()["items"]
        }
        assert all(
            g["subject_id"] != legal["id"]
            for g in admin.get(f"/api/v1/folders/{folder}/permissions").json()
        )

    def test_manually_created_groups_are_never_touched(self, env):  # noqa: ANN001
        admin = env["admin"]
        manual = admin.post("/api/v1/admin/groups", json={"name": "Handmade"}).json()
        upload(
            env,
            users(f"a@{D()}"),
            [{"external_id": "gx", "name": "Handmade", "member_ids": ["id-a"]}],
        )
        sync(env)
        names = {g["name"] for g in admin.get("/api/v1/admin/groups").json()["items"]}
        assert {"Handmade", "Handmade (directory)"} <= names  # conflict resolved without hijacking
        assert admin.get(f"/api/v1/admin/groups/{manual['id']}/members").json() == []


class TestSafetyGuards:
    def test_empty_directory_response_aborts(self, env):  # noqa: ANN001
        upload(env, users(f"a@{D()}", f"b@{D()}"))
        sync(env)
        upload(env, [])
        run = sync(env)
        assert run["state"] == "aborted" and "no users" in run["error"]
        assert members(env)[f"a@{D()}"]["membership_status"] == "invited"

    def test_mass_deprovisioning_is_blocked(self, env):  # noqa: ANN001
        emails = [f"u{i}@{D()}" for i in range(20)]
        upload(env, users(*emails))
        sync(env)
        upload(env, users(*emails[:5]))  # 15 of 20 vanish
        run = sync(env)
        assert run["state"] == "aborted" and "Would deprovision 15" in run["error"]
        assert members(env)[f"u19@{D()}"]["membership_status"] == "invited"

    def test_invalid_records_are_skipped_and_counted(self, env):  # noqa: ANN001
        upload(
            env,
            [
                *users(f"ok@{D()}"),
                {"external_id": "bad1", "email": "not-an-email"},
                {"external_id": "dup", "email": f"ok@{D()}"},
            ],
        )
        run = sync(env)
        assert run["stats"]["users_created"] == 1 and run["stats"]["invalid_records"] == 2

    def test_concurrent_syncs_are_refused_and_interval_scheduling_queues_runs(self, env):  # noqa: ANN001
        admin, w = env["admin"], env["world"]
        upload(env, users(f"a@{D()}"))
        r1 = admin.post(
            f"/api/v1/admin/directory/sources/{env['source']['id']}/sync", json={"dry_run": True}
        )
        assert r1.status_code == 202
        assert (
            admin.post(
                f"/api/v1/admin/directory/sources/{env['source']['id']}/sync", json={}
            ).status_code
            == 409
        )
        w.process_jobs()
        admin.patch(
            f"/api/v1/admin/directory/sources/{env['source']['id']}",
            json={"sync_interval_minutes": 60},
        )
        with w.db_factory() as db:
            db.execute(
                text("UPDATE dms.directory_sync_runs SET started_at = :t"),
                {"t": datetime.now(UTC) - timedelta(hours=2)},
            )
            db.commit()
        from app.modules.directory.service import schedule_due

        with w.db_factory() as db:
            assert schedule_due(db) == 1
        with w.db_factory() as db:
            assert schedule_due(db) == 0  # already queued


class TestAccessAndSecrets:
    def test_admin_only_and_tenant_scoped(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        m = w.user(admin, "member", label="m")
        sid = env["source"]["id"]
        for call in (
            m.get("/api/v1/admin/directory/sources"),
            m.post(f"/api/v1/admin/directory/sources/{sid}/sync", json={}),
            m.put(f"/api/v1/admin/directory/sources/{sid}/snapshot", json={"users": []}),
        ):
            assert call.status_code == 403
        other = w.org("Other")
        assert other.get("/api/v1/admin/directory/sources").json() == []
        assert other.post(f"/api/v1/admin/directory/sources/{sid}/sync", json={}).status_code == 404

    def test_secret_references_are_restricted_to_the_dedicated_prefix(self, env, monkeypatch):  # noqa: ANN001
        admin = env["admin"]
        for bad in (
            "env:DATABASE_URL",
            "env:SUPABASE_SERVICE_ROLE_KEY",
            "file:/etc/passwd",
            "DMS_DIR_X",
        ):
            r = admin.post(
                "/api/v1/admin/directory/sources",
                json={
                    "name": f"s-{bad}",
                    "kind": "entra",
                    "config": {"tenant_id": "t", "client_id": "c"},
                    "secret_ref": bad,
                },
            )
            assert r.status_code == 422, bad
        monkeypatch.setenv("DMS_DIR_TEST", "s3cret")
        assert resolve_secret("env:DMS_DIR_TEST") == "s3cret"
        with pytest.raises(DirectoryError):
            resolve_secret("env:HOME")

    def test_insecure_ldap_is_rejected_and_responses_never_expose_the_snapshot(self, env):  # noqa: ANN001
        admin = env["admin"]
        r = admin.post(
            "/api/v1/admin/directory/sources",
            json={
                "name": "ldap",
                "kind": "ldap",
                "config": {
                    "server_uri": "ldap://dc.corp",
                    "bind_dn": "cn=x",
                    "base_dn_users": "dc=corp",
                },
            },
        )
        assert r.status_code == 422 and r.json()["error"]["code"] == "insecure_ldap"
        upload(env, users(f"a@{D()}"))
        src = admin.get("/api/v1/admin/directory/sources").json()[0]
        assert "users" not in src["config"] and src["has_snapshot"] is True


class TestAdapters:
    def test_entra_graph_paging_and_ssrf_guard(self, monkeypatch):  # noqa: ANN001
        monkeypatch.setenv("DMS_DIR_ENTRA", "client-secret")
        calls = []

        def handler(req: httpx.Request) -> httpx.Response:
            calls.append(str(req.url))
            if "login.microsoftonline.com" in str(req.url):
                assert b"client_secret=client-secret" in req.read()
                return httpx.Response(200, json={"access_token": "tok"})
            assert req.headers["authorization"] == "Bearer tok"
            if req.url.path.endswith("/users") and "skip" not in str(req.url):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {
                                "id": "u1",
                                "mail": f"A@{D()}",
                                "displayName": "A",
                                "accountEnabled": True,
                            }
                        ],
                        "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?skip=1",
                    },
                )
            if req.url.path.endswith("/users"):
                return httpx.Response(
                    200,
                    json={
                        "value": [
                            {"id": "u2", "userPrincipalName": f"b@{D()}", "accountEnabled": False}
                        ]
                    },
                )
            if req.url.path.endswith("/groups"):
                return httpx.Response(200, json={"value": [{"id": "g1", "displayName": "All"}]})
            return httpx.Response(
                200,
                json={
                    "value": [
                        {"id": "u1", "@odata.type": "#microsoft.graph.user"},
                        {"id": "gx", "@odata.type": "#microsoft.graph.group"},
                    ]
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        snap = EntraDirectory(
            {"tenant_id": "t1", "client_id": "c1"}, "env:DMS_DIR_ENTRA", client=client
        ).fetch()
        assert [(u.email, u.active) for u in snap.users] == [
            (f"a@{D()}", True),
            (f"b@{D()}", False),
        ]
        assert snap.groups[0].member_ids == frozenset({"u1"}) and len(calls) >= 5

        def evil(req: httpx.Request) -> httpx.Response:
            if "login" in str(req.url):
                return httpx.Response(200, json={"access_token": "tok"})
            return httpx.Response(
                200,
                json={"value": [], "@odata.nextLink": "https://169.254.169.254/latest/meta-data"},
            )

        with pytest.raises(DirectoryError):
            EntraDirectory(
                {"tenant_id": "t1", "client_id": "c1"},
                "env:DMS_DIR_ENTRA",
                client=httpx.Client(transport=httpx.MockTransport(evil)),
            ).fetch()

    def test_ldap_mapping_with_fake_connection(self, monkeypatch):  # noqa: ANN001
        monkeypatch.setenv("DMS_DIR_LDAP", "bindpw")

        class FakeExtend:
            class standard:  # noqa: N801
                @staticmethod
                def paged_search(base, flt, attributes, paged_size, generator):  # noqa: ANN001, ANN205
                    if "users" in base:
                        yield {
                            "type": "searchResEntry",
                            "attributes": {
                                "entryUUID": ["e1"],
                                "mail": ["Ann@Corp.test"],
                                "displayName": ["Ann"],
                                "userAccountControl": 512,
                                "distinguishedName": "CN=Ann,OU=users,DC=corp",
                            },
                        }
                        yield {
                            "type": "searchResEntry",
                            "attributes": {
                                "entryUUID": ["e2"],
                                "mail": ["ben@corp.test"],
                                "userAccountControl": 514,
                                "distinguishedName": "CN=Ben,OU=users,DC=corp",
                            },
                        }
                        yield {"type": "searchResRe", "attributes": {}}
                    else:
                        yield {
                            "type": "searchResEntry",
                            "attributes": {
                                "entryUUID": ["g1"],
                                "cn": ["Staff"],
                                "member": ["cn=ann,ou=users,dc=corp", "CN=Nobody,DC=x"],
                            },
                        }

        class FakeConn:
            extend = FakeExtend()

            def unbind(self):  # noqa: ANN202
                pass

        cfg = {
            "server_uri": "ldaps://dc.corp",
            "bind_dn": "cn=svc",
            "base_dn_users": "ou=users,dc=corp",
            "base_dn_groups": "ou=groups,dc=corp",
        }
        snap = LdapDirectory(cfg, "env:DMS_DIR_LDAP", connection_factory=lambda: FakeConn()).fetch()
        assert [(u.email, u.active) for u in snap.users] == [
            ("ann@corp.test", True),
            ("ben@corp.test", False),
        ]
        assert snap.groups[0].member_ids == frozenset({"e1"})
        with pytest.raises(DirectoryError):
            LdapDirectory({**cfg, "server_uri": "ldap://dc.corp"}, "env:DMS_DIR_LDAP")
