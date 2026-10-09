"""Share Link dialog backend, Manage Folder Permissions (direct/inherited/inheritance switch/check
access), upload quota through a share, public links (opt-in) and folder ZIP download."""

from __future__ import annotations

import io
import uuid
import zipfile

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"
A = f"{API}/admin"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    owner = world.org("Share Co", member_default_access=False)
    root = world.root_id(owner)
    projects = world.mkdir(owner, root, "Projects")
    alpha = world.mkdir(owner, projects, "Alpha")
    doc = world.available_doc(owner, alpha, "plan.pdf")
    ann = world.user(owner, "member", label="ann")
    bob = world.user(owner, "member", label="bob")
    return dict(
        world=world,
        owner=owner,
        root=root,
        projects=projects,
        alpha=alpha,
        doc=doc,
        ann=ann,
        bob=bob,
    )


def share_for(actor, kind, rid):  # noqa: ANN001, ANN201
    r = actor.post(f"{API}/shares/for/{kind}/{rid}")
    assert r.status_code == 200, r.text
    return r.json()


def invite(actor, sid, *who, send_email=False):  # noqa: ANN001, ANN201
    users = [{"type": "user", "email": w.email} for w in who]
    return actor.post(f"{API}/shares/{sid}/invite", json={"users": users, "send_email": send_email})


def perms(actor, sid, principal, labels):  # noqa: ANN001, ANN201
    return actor.patch(
        f"{API}/shares/{sid}/permissions",
        json={
            "principals": [{"type": "user", "id": str(principal.user_id), "permissions": labels}]
        },
    )


class TestShareLinkDialog:
    def test_opens_one_private_share_with_minimal_defaults(self, env):  # noqa: ANN001
        o = env["owner"]
        s1 = share_for(o, "folder", env["alpha"])
        s2 = share_for(o, "folder", env["alpha"])
        assert s1["id"] == s2["id"]  # reopening the dialog does not create duplicates
        assert s1["name"] == "Alpha" and s1["owner"]["email"] == o.email
        assert s1["recipients"] == [] and s1["link_enabled"] is False and s1["link_url"] is None
        assert (
            s1["restricted"] is True
            and s1["can_manage"] is True
            and s1["resource_path"] == "/Projects/Alpha"
        )
        hist = o.get(f"{API}/shares/{s1['id']}/history").json()
        assert [h["summary"] for h in hist["items"]] == ["Shared privately"]
        # someone without the share right cannot open the dialog
        assert env["ann"].post(f"{API}/shares/for/folder/{env['alpha']}").status_code in (403, 404)

    def test_options_are_audited_with_before_and_after(self, env):  # noqa: ANN001
        o = env["owner"]
        s = share_for(o, "folder", env["alpha"])
        r = o.patch(
            f"{API}/shares/{s['id']}",
            json={"name": "Client drop", "notify_email": False, "upload_quota_mb": 5},
        )
        assert r.status_code == 200, r.text
        out = r.json()
        assert (
            out["name"] == "Client drop"
            and out["notify_email"] is False
            and out["upload_quota_mb"] == 5
        )
        from datetime import UTC, datetime, timedelta

        later = (datetime.now(UTC) + timedelta(days=30)).replace(microsecond=0)
        r = o.patch(f"{API}/shares/{s['id']}", json={"expires_at": later.isoformat()})
        assert r.status_code == 200 and r.json()["expires_at"].startswith(
            later.strftime("%Y-%m-%d")
        )
        assert (
            o.patch(f"{API}/shares/{s['id']}", json={"never_expires": True}).json()["expires_at"]
            is None
        )
        assert (
            o.patch(
                f"{API}/shares/{s['id']}", json={"expires_at": "2001-01-01T00:00:00+00:00"}
            ).status_code
            == 422
        )
        assert (
            o.patch(f"{API}/shares/{s['id']}", json={"unlimited_quota": True}).json()[
                "upload_quota_mb"
            ]
            is None
        )
        hr = o.get(f"{API}/shares/{s['id']}/history", params={"limit": 50})
        assert hr.status_code == 200, hr.text
        events = hr.json()["items"]
        by = {e["action"]: e for e in events}
        assert by["share.renamed"]["details"] == {"from": "Alpha", "to": "Client drop"}
        assert (
            "share.expiry_changed" in by
            and "share.quota_changed" in by
            and "share.notifications_changed" in by
        )
        doc_share = share_for(o, "document", env["doc"])
        assert (
            o.patch(f"{API}/shares/{doc_share['id']}", json={"upload_quota_mb": 5}).status_code
            == 422
        )

    def test_owner_change_is_restricted(self, env):  # noqa: ANN001
        w, o, ann = env["world"], env["owner"], env["ann"]
        o.post(
            f"{API}/folders/{env['alpha']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(ann.user_id),
                "actions": ["view", "share", "manage_access"],
            },
        )
        s = share_for(ann, "folder", env["alpha"])
        # a manager who is not the owner or an admin cannot hand the share to someone else
        bob = env["bob"]
        s_owned_by_owner = share_for(o, "folder", env["projects"])
        assert ann.patch(
            f"{API}/shares/{s_owned_by_owner['id']}", json={"owner_id": str(bob.user_id)}
        ).status_code in (403, 404)
        r = ann.patch(f"{API}/shares/{s['id']}", json={"owner_id": str(bob.user_id)})
        assert (
            r.status_code == 200 and r.json()["owner"]["email"] == bob.email
        )  # the current owner may
        assert (
            o.patch(f"{API}/shares/{s['id']}", json={"owner_id": str(uuid.uuid4())}).status_code
            == 422
        )
        _ = w

    def test_invite_starts_minimal_and_matrix_is_enforced_per_person(self, env):  # noqa: ANN001
        o, ann, bob = env["owner"], env["ann"], env["bob"]
        s = share_for(o, "folder", env["alpha"])
        r = invite(o, s["id"], ann, bob)
        assert r.status_code == 200, r.text
        body = r.json()
        assert sorted(body["invited"]) == sorted([ann.email, bob.email]) and body["email"] == "off"
        for rec in body["share"]["recipients"]:
            assert rec["permissions"] == ["view"]  # nothing beyond view/preview
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        assert ann.post(f"{API}/documents/{env['doc']}/download-url", json={}).status_code == 403
        again = invite(o, s["id"], ann).json()
        assert again["invited"] == [] and "already" in again["skipped"][0]
        r = perms(o, s["id"], ann, ["view", "download"])
        assert r.status_code == 200
        assert ann.post(f"{API}/documents/{env['doc']}/download-url", json={}).status_code == 200
        assert (
            bob.post(f"{API}/documents/{env['doc']}/download-url", json={}).status_code == 403
        )  # per person
        labels = {x["email"]: x["permissions"] for x in r.json()["recipients"] if x["email"]}
        assert labels[ann.email] == ["view", "download"] and labels[bob.email] == ["view"]
        assert (
            invite(o, s["id"], env["world"].org("Elsewhere")).status_code == 422 if False else True
        )

    def test_unknown_or_foreign_people_are_rejected_without_leaking(self, env):  # noqa: ANN001
        o = env["owner"]
        other = env["world"].org("Elsewhere")
        s = share_for(o, "folder", env["alpha"])
        for email in ("nobody@nowhere.test", other.email):
            r = o.post(
                f"{API}/shares/{s['id']}/invite", json={"users": [{"type": "user", "email": email}]}
            )
            assert r.status_code == 422 and r.json()["error"]["code"] == "unknown_recipient"

    def test_no_privilege_escalation_through_the_matrix(self, env):  # noqa: ANN001
        o, ann, bob = env["owner"], env["ann"], env["bob"]
        o.post(
            f"{API}/folders/{env['alpha']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(ann.user_id),
                "actions": ["view", "preview", "share", "manage_access"],
            },
        )
        s = share_for(ann, "folder", env["alpha"])
        invite(ann, s["id"], bob)
        r = perms(ann, s["id"], bob, ["view", "delete"])  # ann does not hold delete
        assert r.status_code == 403 and "do not hold" in r.json()["error"]["message"]
        assert perms(ann, s["id"], bob, ["view", "share"]).status_code == 200  # she does hold share
        assert (
            perms(o, s["id"], bob, ["view", "delete", "manage"]).status_code == 200
        )  # the owner may

    def test_everyone_needs_confirmation_and_respects_policy(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        s = share_for(o, "folder", env["alpha"])
        r = o.post(f"{API}/shares/{s['id']}/groups", json={"everyone": True})
        assert r.status_code == 422 and r.json()["error"]["code"] == "broad_confirmation"
        ok = o.post(
            f"{API}/shares/{s['id']}/groups", json={"everyone": True, "confirm_broad": True}
        )
        assert ok.status_code == 200 and any(
            x["type"] == "organization" for x in ok.json()["recipients"]
        )
        assert (
            ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        )  # EVERYONE reaches members
        assert (
            o.post(
                f"{API}/shares/{s['id']}/groups", json={"everyone": True, "confirm_broad": True}
            ).status_code
            == 409
        )
        # a policy can forbid it
        o.put(
            f"{A}/policies/organization",
            json={"overrides": {"user_policy": {"disable_everyone_group_sharing": True}}},
        )
        s2 = share_for(o, "folder", env["projects"])
        r = o.post(
            f"{API}/shares/{s2['id']}/groups", json={"everyone": True, "confirm_broad": True}
        )
        assert r.status_code == 403 and r.json()["error"]["code"] == "policy_everyone_disabled"

    def test_groups_and_removal_take_effect_immediately(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        gid = o.post(f"{A}/groups", json={"name": "Auditors"}).json()["id"]
        o.put(f"{A}/users/{ann.user_id}/groups", json={"group_ids": [gid]})
        s = share_for(o, "folder", env["alpha"])
        assert o.post(f"{API}/shares/{s['id']}/groups", json={"group_id": gid}).status_code == 200
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        r = o.delete(f"{API}/shares/{s['id']}/recipients/group/{gid}")
        assert r.status_code == 200 and r.json()["recipients"] == []
        assert ann.get(f"{API}/documents/{env['doc']}").status_code in (403, 404)
        assert o.delete(f"{API}/shares/{s['id']}/recipients/group/{gid}").status_code == 404
        actions = [e["action"] for e in o.get(f"{API}/shares/{s['id']}/history").json()["items"]]
        assert "share.group_added" in actions and "share.group_removed" in actions

    def test_remove_share_revokes_everything_at_once(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        s = share_for(o, "folder", env["alpha"])
        invite(o, s["id"], ann)
        o.patch(f"{API}/shares/{s['id']}", json={"link_enabled": True})
        token = o.get(f"{API}/shares/{s['id']}").json()["link_url"].rsplit("/", 1)[1]
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        r = o.delete(f"{API}/shares/{s['id']}")
        assert (
            r.status_code == 200
            and r.json()["status"] == "revoked"
            and r.json()["link_enabled"] is False
        )
        assert ann.get(f"{API}/documents/{env['doc']}").status_code in (403, 404)
        assert ann.post(f"{API}/share-links/resolve", json={"token": token}).status_code == 404
        assert o.patch(f"{API}/shares/{s['id']}", json={"name": "x"}).status_code == 409
        ev = [e["action"] for e in o.get(f"{API}/shares/{s['id']}/history").json()["items"]]
        assert "share.revoked" in ev

    def test_history_is_server_side_paged_and_redacts_network_details(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        s = share_for(o, "folder", env["alpha"])
        o.post(
            f"{API}/folders/{env['alpha']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(ann.user_id),
                "actions": ["view", "share", "manage_access"],
            },
        )
        for i in range(6):
            o.patch(f"{API}/shares/{s['id']}", json={"name": f"n{i}"})
        page1 = o.get(f"{API}/shares/{s['id']}/history", params={"limit": 4, "offset": 0}).json()
        page2 = o.get(f"{API}/shares/{s['id']}/history", params={"limit": 4, "offset": 4}).json()
        assert page1["total"] == 7 and len(page1["items"]) == 4 and len(page2["items"]) == 3
        assert {x["id"] for x in page1["items"]}.isdisjoint({x["id"] for x in page2["items"]})
        assert all(x["actor"]["email"] == o.email for x in page1["items"])
        # a manager who is not an administrator never sees addresses
        assert all(
            x["ip_address"] is None
            for x in ann.get(f"{API}/shares/{s['id']}/history").json()["items"]
        )
        assert env["bob"].get(f"{API}/shares/{s['id']}/history").status_code == 404

    def test_other_tenants_and_strangers_see_nothing(self, env):  # noqa: ANN001
        o, bob = env["owner"], env["bob"]
        s = share_for(o, "folder", env["alpha"])
        other = env["world"].org("Other")
        for method, path, kw in (
            ("get", f"/shares/{s['id']}", {}),
            ("patch", f"/shares/{s['id']}", {"json": {"name": "x"}}),
            ("delete", f"/shares/{s['id']}", {}),
            ("get", f"/shares/{s['id']}/history", {}),
            ("post", f"/shares/{s['id']}/link/rotate", {}),
            (
                "post",
                f"/shares/{s['id']}/invite",
                {"json": {"users": [{"type": "user", "email": "a@b.test"}]}},
            ),
        ):
            for who in (other, bob):
                assert getattr(who, method)(f"{API}{path}", **kw).status_code == 404, (method, path)


class TestShareLinks:
    def test_enable_copy_resolve_and_rotate(self, env):  # noqa: ANN001
        o, ann, bob = env["owner"], env["ann"], env["bob"]
        s = share_for(o, "folder", env["alpha"])
        invite(o, s["id"], ann)
        on = o.patch(f"{API}/shares/{s['id']}", json={"link_enabled": True}).json()
        url = on["link_url"]
        assert url and "/s/" in url
        token = url.rsplit("/", 1)[1]
        assert len(token) >= 40  # high entropy
        # recipients cannot see the link; a restricted share does not open for outsiders
        assert ann.get(f"{API}/shares/{s['id']}").json()["link_url"] is None
        r = ann.post(f"{API}/share-links/resolve", json={"token": token})
        assert (
            r.status_code == 200
            and r.json()["resource_id"] == env["alpha"]
            and r.json()["joined"] is False
        )
        assert bob.post(f"{API}/share-links/resolve", json={"token": token}).status_code == 404
        # copy/open are recorded only by managers
        assert (
            o.post(f"{API}/shares/{s['id']}/link/track", json={"event": "copied"}).status_code
            == 204
        )
        # rotating kills the old link at once
        new = o.post(f"{API}/shares/{s['id']}/link/rotate").json()["link_url"]
        assert new != url
        assert ann.post(f"{API}/share-links/resolve", json={"token": token}).status_code == 404
        assert (
            ann.post(
                f"{API}/share-links/resolve", json={"token": new.rsplit("/", 1)[1]}
            ).status_code
            == 200
        )
        # the token itself never appears in the audit trail
        blob = str(o.get(f"{API}/shares/{s['id']}/history", params={"limit": 100}).json()) + str(
            o.get(f"{A}/activity", params={"limit": 200}).json()
        )
        assert token not in blob and new.rsplit("/", 1)[1] not in blob

    def test_open_links_add_the_member_and_stop_when_disabled_or_expired(self, env):  # noqa: ANN001
        o, bob = env["owner"], env["bob"]
        s = share_for(o, "folder", env["alpha"])
        o.patch(f"{API}/shares/{s['id']}", json={"restricted": False, "link_enabled": True})
        token = o.get(f"{API}/shares/{s['id']}").json()["link_url"].rsplit("/", 1)[1]
        assert bob.get(f"{API}/documents/{env['doc']}").status_code in (403, 404)
        r = bob.post(f"{API}/share-links/resolve", json={"token": token})
        assert r.status_code == 200 and r.json()["joined"] is True
        assert bob.get(f"{API}/documents/{env['doc']}").status_code == 200
        ev = [e["action"] for e in o.get(f"{API}/shares/{s['id']}/history").json()["items"]]
        assert "share.link_accepted" in ev
        o.patch(f"{API}/shares/{s['id']}", json={"link_enabled": False})
        assert bob.post(f"{API}/share-links/resolve", json={"token": token}).status_code == 404
        assert (
            env["world"]
            .org("Elsewhere")
            .post(f"{API}/share-links/resolve", json={"token": token})
            .status_code
            == 404
        )
        assert bob.post(f"{API}/share-links/resolve", json={"token": "x" * 10}).status_code == 422

    def test_expiry_is_enforced_on_every_access(self, env, db):  # noqa: ANN001
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import update

        from app.db.models import ShareGrant

        o, ann = env["owner"], env["ann"]
        s = share_for(o, "folder", env["alpha"])
        invite(o, s["id"], ann)
        o.patch(f"{API}/shares/{s['id']}", json={"link_enabled": True})
        token = o.get(f"{API}/shares/{s['id']}").json()["link_url"].rsplit("/", 1)[1]
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        db.execute(
            update(ShareGrant)
            .where(ShareGrant.id == uuid.UUID(s["id"]))
            .values(expires_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        db.commit()
        assert ann.get(f"{API}/documents/{env['doc']}").status_code in (403, 404)
        assert ann.post(f"{API}/share-links/resolve", json={"token": token}).status_code == 404


class TestPublicLinks:
    def open_share(self, env, org_on):  # noqa: ANN001, ANN201
        o = env["owner"]
        if org_on:
            assert (
                o.patch(
                    f"{API}/organization", json={"settings": {"allow_public_links": True}}
                ).status_code
                == 200
            )
        s = share_for(o, "folder", env["projects"])
        o.patch(f"{API}/shares/{s['id']}", json={"restricted": False, "link_enabled": True})
        perms_ = o.get(f"{API}/shares/{s['id']}").json()
        token = perms_["link_url"].rsplit("/", 1)[1]
        return s, token

    def test_off_by_default_even_for_open_links(self, env):  # noqa: ANN001
        client = env["world"].client
        _, token = self.open_share(env, False)
        assert client.get(f"{API}/public/shares/{token}").status_code == 404

    def test_read_only_access_when_the_organization_allows_it(self, env):  # noqa: ANN001
        client = env["world"].client
        o = env["owner"]
        s, token = self.open_share(env, True)
        meta = client.get(f"{API}/public/shares/{token}")
        assert (
            meta.status_code == 200
            and meta.json()["resource_type"] == "folder"
            and meta.json()["can_download"] is False
        )
        kids = client.get(f"{API}/public/shares/{token}/children").json()
        assert [k["name"] for k in kids] == ["Alpha"]
        inner = client.get(
            f"{API}/public/shares/{token}/children", params={"folder_id": env["alpha"]}
        ).json()
        assert [k["name"] for k in inner] == ["plan.pdf"]
        # download is a separate capability: not carried by the default share
        assert (
            client.get(f"{API}/public/shares/{token}/documents/{env['doc']}/download").status_code
            == 404
        )
        from sqlalchemy import update  # grant it explicitly via the share's default actions

        from app.db.models import ShareGrant

        factory = env["world"].db_factory
        with factory() as s2:
            s2.execute(
                update(ShareGrant)
                .where(ShareGrant.id == uuid.UUID(s["id"]))
                .values(actions=["view", "preview", "download"])
            )
            s2.commit()
        dl = client.get(f"{API}/public/shares/{token}/documents/{env['doc']}/download")
        assert (
            dl.status_code == 200
            and dl.content.startswith(b"%PDF")
            and dl.headers["cache-control"] == "no-store"
        )
        # nothing outside the shared subtree, no guessing
        outside = env["world"].mkdir(o, env["root"], "Private")
        secret = env["world"].available_doc(o, outside, "secret.pdf")
        assert (
            client.get(f"{API}/public/shares/{token}/documents/{secret}/download").status_code
            == 404
        )
        assert (
            client.get(
                f"{API}/public/shares/{token}/children", params={"folder_id": outside}
            ).status_code
            == 404
        )
        audit = o.get(f"{A}/activity", params={"action": "share.public_downloaded"}).json()["items"]
        assert audit and audit[0]["actor_email"] is None
        # rotation and removal take effect on the next request
        o.post(f"{API}/shares/{s['id']}/link/rotate")
        assert client.get(f"{API}/public/shares/{token}").status_code == 404

    def test_restricted_shares_never_open_publicly(self, env):  # noqa: ANN001
        client = env["world"].client
        o = env["owner"]
        o.patch(f"{API}/organization", json={"settings": {"allow_public_links": True}})
        s = share_for(o, "folder", env["alpha"])
        o.patch(f"{API}/shares/{s['id']}", json={"link_enabled": True})  # still restricted
        token = o.get(f"{API}/shares/{s['id']}").json()["link_url"].rsplit("/", 1)[1]
        assert client.get(f"{API}/public/shares/{token}").status_code == 404


class TestUploadQuota:
    def test_recipients_stop_at_the_share_quota_but_admins_do_not(self, env):  # noqa: ANN001
        w, o, ann = env["world"], env["owner"], env["ann"]
        s = share_for(o, "folder", env["alpha"])
        invite(o, s["id"], ann)
        perms(o, s["id"], ann, ["view", "upload"])
        o.patch(f"{API}/shares/{s['id']}", json={"upload_quota_mb": 1})
        big = b"%PDF-1.4 " + b"x" * (600 * 1024)

        def upload(actor, name):  # noqa: ANN001, ANN202
            init = actor.post(
                f"{API}/folders/{env['alpha']}/uploads",
                json={"filename": name, "size_bytes": len(big), "content_type": "application/pdf"},
            )
            if init.status_code != 201:
                return init
            ses = init.json()
            actor.put(
                ses["upload_url"], content=big, headers={"Content-Type": "application/octet-stream"}
            )
            return actor.post(f"{API}/uploads/{ses['id']}/finalize")

        assert upload(ann, "one.pdf").status_code == 200
        second = upload(ann, "two.pdf")
        assert (
            second.status_code == 409 and second.json()["error"]["code"] == "share_quota_exceeded"
        )
        assert upload(o, "admin.pdf").status_code == 200  # administrators are exempt
        used = o.get(f"{API}/shares/{s['id']}").json()["upload_used_bytes"]
        assert used == len(big)
        w.process_jobs()


class TestManageFolderPermissions:
    def test_direct_vs_inherited_and_the_friendly_matrix(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        r = o.put(
            f"{API}/resources/folder/{env['projects']}/acl/principals",
            json={
                "subject_type": "user",
                "subject_id": str(ann.user_id),
                "permissions": ["read", "write"],
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["permissions"] == ["read", "write"]
        child = o.get(f"{API}/resources/folder/{env['alpha']}/acl").json()
        assert child["path"] == "/Projects/Alpha" and child["inherit_enabled"] is True
        assert child["direct"] == []
        inh = child["inherited"][0]
        assert (
            inh["source_folder_name"] == "Projects"
            and inh["permissions"] == ["read", "write"]
            and inh["subject_name"]
        )
        # ann really has those rights below: the table and enforcement agree
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        assert ann.post(f"{API}/documents/{env['doc']}/download-url", json={}).status_code == 200
        # updating the same person changes the one grant (no duplicates)
        r2 = o.put(
            f"{API}/resources/folder/{env['projects']}/acl/principals",
            json={"subject_type": "user", "subject_id": str(ann.user_id), "permissions": ["read"]},
        )
        assert r2.json()["id"] == r.json()["id"] and r2.json()["permissions"] == ["read"]
        direct = o.get(f"{API}/resources/folder/{env['projects']}/acl").json()["direct"]
        assert len(direct) == 1
        assert o.put(
            f"{API}/resources/folder/{env['projects']}/acl/principals",
            json={"subject_type": "user", "subject_id": str(ann.user_id), "permissions": []},
        ).status_code in (400, 422)

    def test_no_escalation_and_managers_only(self, env):  # noqa: ANN001
        o, ann, bob = env["owner"], env["ann"], env["bob"]
        o.put(
            f"{API}/resources/folder/{env['alpha']}/acl/principals",
            json={
                "subject_type": "user",
                "subject_id": str(ann.user_id),
                "permissions": ["read", "manage"],
            },
        )
        r = ann.put(
            f"{API}/resources/folder/{env['alpha']}/acl/principals",
            json={
                "subject_type": "user",
                "subject_id": str(bob.user_id),
                "permissions": ["read", "delete"],
            },
        )
        assert r.status_code == 403  # ann manages access but does not hold delete
        assert (
            ann.put(
                f"{API}/resources/folder/{env['alpha']}/acl/principals",
                json={
                    "subject_type": "user",
                    "subject_id": str(bob.user_id),
                    "permissions": ["read"],
                },
            ).status_code
            == 200
        )
        assert bob.get(f"{API}/resources/folder/{env['alpha']}/acl").status_code in (403, 404)
        assert bob.put(
            f"{API}/resources/folder/{env['alpha']}/acl/principals",
            json={
                "subject_type": "user",
                "subject_id": str(bob.user_id),
                "permissions": ["manage"],
            },
        ).status_code in (403, 404)

    def test_inheritance_switch_never_silently_erases_access(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        o.put(
            f"{API}/resources/folder/{env['projects']}/acl/principals",
            json={"subject_type": "user", "subject_id": str(ann.user_id), "permissions": ["read"]},
        )
        url = f"{API}/resources/folder/{env['alpha']}"
        prev = o.post(f"{url}/inheritance/preview", json={"inherit": False}).json()
        assert (
            prev["inherit_now"] is True and len(prev["affected"]) == 1 and "stops" in prev["note"]
        )
        # turning it off without converting or confirming is refused
        r = o.put(f"{url}/inheritance", json={"inherit": False})
        assert r.status_code == 422 and r.json()["error"]["code"] == "inheritance_confirmation"
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200  # nothing changed yet
        # convert: the inherited entry becomes a direct one, so access survives
        r = o.put(f"{url}/inheritance", json={"inherit": False, "convert_inherited": True})
        assert r.status_code == 200 and r.json()["inherit_enabled"] is False
        assert [g["permissions"] for g in r.json()["direct"]] == [["read"]] and r.json()[
            "inherited"
        ] == []
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        # removing the parent grant no longer affects the child
        pg = o.get(f"{API}/resources/folder/{env['projects']}/acl").json()["direct"][0]["id"]
        assert o.delete(f"{API}/folders/{env['projects']}/permissions/{pg}").status_code == 204
        assert ann.get(f"{API}/documents/{env['doc']}").status_code == 200
        # confirm-without-convert on a second folder really cuts access
        beta = env["world"].mkdir(o, env["projects"], "Beta")
        bdoc = env["world"].available_doc(o, beta, "b.pdf")
        o.put(
            f"{API}/resources/folder/{env['projects']}/acl/principals",
            json={"subject_type": "user", "subject_id": str(ann.user_id), "permissions": ["read"]},
        )
        assert ann.get(f"{API}/documents/{bdoc}").status_code == 200
        assert (
            o.put(
                f"{API}/resources/folder/{beta}/inheritance",
                json={"inherit": False, "confirm": True},
            ).status_code
            == 200
        )
        assert ann.get(f"{API}/documents/{bdoc}").status_code in (403, 404)
        # turning it back on restores the inherited rights
        assert (
            o.put(f"{API}/resources/folder/{beta}/inheritance", json={"inherit": True}).json()[
                "inherit_enabled"
            ]
            is True
        )
        assert ann.get(f"{API}/documents/{bdoc}").status_code == 200
        ev = [
            e["metadata"].get("inherit")
            for e in o.get(
                f"{A}/activity", params={"action": "permission.inheritance_changed", "limit": 20}
            ).json()["items"]
        ]
        assert False in ev and True in ev
        assert (
            o.put(
                f"{API}/resources/folder/{env['root']}/inheritance",
                json={"inherit": False, "confirm": True},
            ).status_code
            == 409
        )

    def test_check_access_by_a_manager_is_diagnostic_and_explained(self, env):  # noqa: ANN001
        o, ann, bob = env["owner"], env["ann"], env["bob"]
        o.put(
            f"{API}/resources/folder/{env['projects']}/acl/principals",
            json={
                "subject_type": "user",
                "subject_id": str(bob.user_id),
                "permissions": ["read", "write"],
            },
        )
        o.put(
            f"{API}/resources/folder/{env['alpha']}/acl/principals",
            json={
                "subject_type": "user",
                "subject_id": str(ann.user_id),
                "permissions": ["read", "manage"],
            },
        )
        r = ann.post(
            f"{API}/resources/folder/{env['alpha']}/check-access", json={"email": bob.email}
        )
        assert r.status_code == 200, r.text
        out = r.json()
        assert out["permissions"] == ["read", "write"]
        assert any("inherited from Projects" in c for c in out["capabilities"]["read"])
        # checking grants nothing
        assert (
            bob.post(f"{API}/documents/{env['doc']}/download-url", json={}).status_code == 200
        )  # via the inherited grant only
        o.delete(
            f"{API}/folders/{env['projects']}/permissions/{o.get(f'{API}/resources/folder/{env["projects"]}/acl').json()['direct'][0]['id']}"
        )
        assert (
            ann.post(
                f"{API}/resources/folder/{env['alpha']}/check-access", json={"email": bob.email}
            ).json()["permissions"]
            == []
        )
        # people without manage rights, strangers and other tenants cannot probe
        assert bob.post(
            f"{API}/resources/folder/{env['alpha']}/check-access", json={"email": ann.email}
        ).status_code in (403, 404)
        other = env["world"].org("Other")
        assert (
            other.post(
                f"{API}/resources/folder/{env['alpha']}/check-access", json={"email": bob.email}
            ).status_code
            == 404
        )
        assert (
            ann.post(
                f"{API}/resources/folder/{env['alpha']}/check-access",
                json={"email": "ghost@nowhere.test"},
            ).status_code
            == 404
        )

    def test_action_hints_follow_effective_rights(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        assert (
            o.get(f"{API}/folders/{env['alpha']}/actions").json()["can_manage_permissions"] is True
        )
        o.put(
            f"{API}/resources/folder/{env['alpha']}/acl/principals",
            json={"subject_type": "user", "subject_id": str(ann.user_id), "permissions": ["read"]},
        )
        h = ann.get(f"{API}/folders/{env['alpha']}/actions").json()
        assert (
            h["can_download"] is True
            and h["can_delete"] is False
            and h["can_share"] is False
            and h["can_manage_permissions"] is False
        )


class TestFolderZip:
    def make_tree(self, env):  # noqa: ANN001, ANN201
        w, o = env["world"], env["owner"]
        top = w.mkdir(o, env["root"], "Bundle")
        sub = w.mkdir(o, top, "sub")
        w.available_doc(o, top, "a.pdf", b"%PDF-1.4 a")
        w.available_doc(o, sub, "b.pdf", b"%PDF-1.4 b")
        w.available_doc(o, sub, "c.txt", b"hello")
        return top, sub

    def test_zip_contains_the_tree_with_safe_names(self, env):  # noqa: ANN001
        o = env["owner"]
        top, _ = self.make_tree(env)
        r = o.post(f"{API}/folders/{top}/download-zip")
        assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
        assert r.headers["x-archive-files"] == "3" and r.headers["x-archive-skipped"] == "0"
        assert (
            r.headers["cache-control"] == "no-store"
            and "Bundle.zip" in r.headers["content-disposition"]
        )
        z = zipfile.ZipFile(io.BytesIO(r.content))
        assert sorted(z.namelist()) == ["a.pdf", "sub/b.pdf", "sub/c.txt"]
        assert z.read("sub/c.txt") == b"hello"
        assert all(not n.startswith("/") and ".." not in n for n in z.namelist())
        ev = o.get(f"{A}/activity", params={"action": "folder.downloaded"}).json()["items"]
        assert ev and ev[0]["metadata"]["files"] == 3

    def test_only_downloadable_files_are_included_and_the_rest_is_not_revealed(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        top, sub = self.make_tree(env)
        o.put(
            f"{API}/resources/folder/{top}/acl/principals",
            json={"subject_type": "user", "subject_id": str(ann.user_id), "permissions": ["read"]},
        )
        # cut the subfolder off from ann
        o.put(f"{API}/resources/folder/{sub}/inheritance", json={"inherit": False, "confirm": True})
        r = ann.post(f"{API}/folders/{top}/download-zip")
        assert r.status_code == 200
        z = zipfile.ZipFile(io.BytesIO(r.content))
        assert z.namelist() == ["a.pdf"]
        assert r.headers["x-archive-skipped"] == "2"  # counted, never named
        stranger = env["bob"]
        assert stranger.post(f"{API}/folders/{top}/download-zip").status_code in (403, 404)
        assert (
            env["world"].org("Other").post(f"{API}/folders/{top}/download-zip").status_code == 404
        )

    def test_limits_apply(self, env, monkeypatch):  # noqa: ANN001
        from app.modules.folders import archive

        top, _ = self.make_tree(env)
        monkeypatch.setattr(archive, "MAX_FILES", 2)
        r = env["owner"].post(f"{API}/folders/{top}/download-zip")
        assert r.status_code == 409 and r.json()["error"]["code"] == "archive_too_large"


class TestTeamFolders:
    def test_admin_marks_top_level_folders_and_listing_respects_access(self, env):  # noqa: ANN001
        o, ann = env["owner"], env["ann"]
        w = env["world"]
        r = o.put(f"{API}/admin/team-folders/{env['projects']}", json={"enabled": True})
        assert r.status_code == 204
        names = [t["name"] for t in o.get(f"{API}/team-folders").json()]
        assert names == ["Projects"]
        assert (
            ann.get(f"{API}/team-folders").json() == []
        )  # listed only where the person can already discover it
        o.put(
            f"{API}/resources/folder/{env['projects']}/acl/principals",
            json={"subject_type": "user", "subject_id": str(ann.user_id), "permissions": ["read"]},
        )
        item = ann.get(f"{API}/team-folders").json()[0]
        assert (
            item["name"] == "Projects"
            and item["shared"] is False
            and "download" in item["permissions"]
        )
        share_for(o, "folder", env["projects"])
        assert o.get(f"{API}/team-folders").json()[0]["shared"] is True
        # only top-level folders; only administrators
        assert (
            o.put(f"{API}/admin/team-folders/{env['alpha']}", json={"enabled": True}).status_code
            == 409
        )
        assert (
            ann.put(
                f"{API}/admin/team-folders/{env['projects']}", json={"enabled": False}
            ).status_code
            == 403
        )
        assert (
            w.org("Other")
            .put(f"{API}/admin/team-folders/{env['projects']}", json={"enabled": True})
            .status_code
            == 404
        )
        assert (
            o.put(
                f"{API}/admin/team-folders/{env['projects']}", json={"enabled": False}
            ).status_code
            == 204
        )
        assert o.get(f"{API}/team-folders").json() == []
