"""Cross-tenant, IDOR and account-state negative tests (release blockers)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import text

pytestmark = [pytest.mark.integration, pytest.mark.security]

PDF = b"%PDF-1.4 tenant isolation"


@pytest.fixture()
def two_tenants(world):  # noqa: ANN001, ANN201
    a = world.org("Tenant A")
    b = world.org("Tenant B")
    a_root, b_root = world.root_id(a), world.root_id(b)
    a_folder = world.mkdir(a, a_root, "a-folder")
    b_folder = world.mkdir(b, b_root, "b-secret-folder")
    a_doc = world.available_doc(a, a_folder, "a-doc.pdf", PDF + b"A")
    b_doc = world.available_doc(b, b_folder, "b-secret.pdf", PDF + b"B")
    b_member = world.user(b, "member", label="bmember")
    b_share = b.post(
        f"/api/v1/documents/{b_doc}/shares",
        json={
            "recipients": [{"type": "user", "id": str(b_member.user_id)}],
            "actions": ["view", "download"],
        },
    ).json()
    b_grant = b.post(
        f"/api/v1/folders/{b_folder}/permissions",
        json={"subject_type": "user", "subject_id": str(b_member.user_id), "actions": ["view"]},
    ).json()
    b_group = b.post("/api/v1/admin/groups", json={"name": "B-Finance"}).json()
    b_upload = b.post(
        f"/api/v1/folders/{b_folder}/uploads", json={"filename": "pending.pdf", "size_bytes": 10}
    ).json()
    return dict(
        world=world,
        a=a,
        b=b,
        a_root=a_root,
        b_root=b_root,
        a_folder=a_folder,
        b_folder=b_folder,
        a_doc=a_doc,
        b_doc=b_doc,
        b_member=b_member,
        b_share=b_share,
        b_grant=b_grant,
        b_group=b_group,
        b_upload=b_upload,
    )


def _snapshot(world, ids):  # noqa: ANN001, ANN202
    with world.db_factory() as db:
        return {
            "docs": db.execute(
                text(
                    "SELECT id, name, folder_id, deleted_at, row_version FROM dms.documents WHERE id = ANY(:i) ORDER BY id"
                ),
                {"i": [uuid.UUID(i) for i in ids["docs"]]},
            ).all(),
            "folders": db.execute(
                text(
                    "SELECT id, name, parent_folder_id, deleted_at, row_version FROM dms.folders WHERE id = ANY(:i) ORDER BY id"
                ),
                {"i": [uuid.UUID(i) for i in ids["folders"]]},
            ).all(),
            "shares": db.execute(text("SELECT id, revoked_at FROM dms.share_grants")).all(),
            "grants": db.execute(text("SELECT id, revoked_at FROM dms.permission_grants")).all(),
            "groups": db.execute(text("SELECT id, name FROM dms.groups ORDER BY id")).all(),
            "members": db.execute(
                text("SELECT user_id, role, status FROM dms.memberships ORDER BY id")
            ).all(),
        }


def test_tenant_a_cannot_touch_any_tenant_b_resource(two_tenants):  # noqa: ANN001
    t = two_tenants
    a, bd, bf = t["a"], t["b_doc"], t["b_folder"]
    before = _snapshot(t["world"], {"docs": [bd], "folders": [bf]})

    attempts = [
        ("get", f"/api/v1/folders/{bf}", None),
        ("get", f"/api/v1/folders/{bf}/children", None),
        ("get", f"/api/v1/folders/{bf}/breadcrumb", None),
        ("patch", f"/api/v1/folders/{bf}", {"name": "pwned"}),
        ("patch", f"/api/v1/folders/{bf}", {"parent_folder_id": t["a_folder"]}),
        ("delete", f"/api/v1/folders/{bf}", None),
        ("post", f"/api/v1/folders/{bf}/restore", {}),
        ("post", "/api/v1/folders", {"parent_folder_id": bf, "name": "intruder"}),
        ("post", f"/api/v1/folders/{bf}/uploads", {"filename": "x.pdf", "size_bytes": 5}),
        (
            "post",
            f"/api/v1/folders/{bf}/shares",
            {"recipients": [{"type": "user", "id": str(a.user_id)}], "actions": ["view"]},
        ),
        ("get", f"/api/v1/folders/{bf}/shares", None),
        ("get", f"/api/v1/folders/{bf}/permissions", None),
        (
            "post",
            f"/api/v1/folders/{bf}/permissions",
            {"subject_type": "organization", "actions": ["view"]},
        ),
        ("delete", f"/api/v1/folders/{bf}/permissions/{t['b_grant']['id']}", None),
        ("get", f"/api/v1/documents/{bd}", None),
        ("patch", f"/api/v1/documents/{bd}", {"name": "pwned.pdf"}),
        ("patch", f"/api/v1/documents/{bd}", {"folder_id": t["a_folder"]}),
        ("delete", f"/api/v1/documents/{bd}", None),
        ("post", f"/api/v1/documents/{bd}/restore", {}),
        ("post", f"/api/v1/documents/{bd}/copy", {"target_folder_id": t["a_folder"]}),
        ("post", f"/api/v1/documents/{t['a_doc']}/copy", {"target_folder_id": bf}),
        ("put", f"/api/v1/documents/{bd}/star", None),
        ("get", f"/api/v1/documents/{bd}/versions", None),
        ("post", f"/api/v1/documents/{bd}/versions/1/restore", None),
        (
            "post",
            f"/api/v1/documents/{bd}/uploads",
            {"filename": "v2.pdf", "size_bytes": 5, "expected_latest_version": 1},
        ),
        ("post", f"/api/v1/documents/{bd}/download-url", {}),
        ("post", f"/api/v1/documents/{bd}/download-url", {"inline": True}),
        (
            "post",
            f"/api/v1/documents/{bd}/shares",
            {"recipients": [{"type": "user", "id": str(a.user_id)}], "actions": ["view"]},
        ),
        ("get", f"/api/v1/documents/{bd}/shares", None),
        ("get", f"/api/v1/documents/{bd}/permissions", None),
        (
            "post",
            f"/api/v1/documents/{bd}/permissions",
            {"subject_type": "user", "subject_id": str(a.user_id), "actions": ["view"]},
        ),
        ("get", f"/api/v1/shares/{t['b_share']['id']}", None),
        ("post", f"/api/v1/shares/{t['b_share']['id']}/revoke", None),
        ("get", f"/api/v1/uploads/{t['b_upload']['id']}", None),
        ("put", f"/api/v1/uploads/{t['b_upload']['id']}/content", None),
        ("post", f"/api/v1/uploads/{t['b_upload']['id']}/finalize", None),
        ("delete", f"/api/v1/uploads/{t['b_upload']['id']}", None),
        ("patch", f"/api/v1/admin/members/{t['b_member'].user_id}", {"role": "admin"}),
        ("post", f"/api/v1/admin/members/{t['b_member'].user_id}/revoke-sessions", None),
        ("patch", f"/api/v1/admin/groups/{t['b_group']['id']}", {"name": "pwned"}),
        ("delete", f"/api/v1/admin/groups/{t['b_group']['id']}", None),
        ("get", f"/api/v1/admin/groups/{t['b_group']['id']}/members", None),
        ("post", f"/api/v1/admin/groups/{t['b_group']['id']}/members", {"user_id": str(a.user_id)}),
    ]
    for method, url, body in attempts:
        kw = {"json": body} if body is not None else {}
        r = getattr(a, method)(url, **kw)
        assert r.status_code in (403, 404, 422), (
            f"{method.upper()} {url} -> {r.status_code} {r.text[:200]}"
        )
        assert (
            "b-secret" not in r.text and "Tenant B" not in r.text and "B-Finance" not in r.text
        ), f"{method.upper()} {url} leaked tenant B data"

    assert _snapshot(t["world"], {"docs": [bd], "folders": [bf]}) == before  # nothing mutated


def test_search_and_listings_never_reveal_other_tenant(two_tenants):  # noqa: ANN001
    t = two_tenants
    a = t["a"]
    for q in ("b-secret", "secret", "pdf", "B-Finance"):
        body = a.get("/api/v1/search", params={"q": q}).json()
        assert all("b-secret" not in i["name"] for i in body["items"])
    assert all(
        i["id"] != t["b_doc"]
        for i in a.get("/api/v1/recent").json()["items"] + a.get("/api/v1/starred").json()["items"]
    )
    assert a.get("/api/v1/shares/sent", params={"scope": "all"}).json()["total"] == 0
    groups = a.get("/api/v1/admin/groups").json()["items"]
    assert all(g["name"] != "B-Finance" for g in groups)
    events = a.get("/api/v1/admin/audit-events", params={"limit": 200}).json()["items"]
    assert all(e["resource_id"] not in (t["b_doc"], t["b_folder"]) for e in events)
    members = {m["email"] for m in a.get("/api/v1/admin/members").json()["items"]}
    assert t["b_member"].email not in members


def test_org_header_is_only_a_selector_over_server_side_memberships(two_tenants):  # noqa: ANN001
    t = two_tenants
    a, b = t["a"], t["b"]
    # A's user cannot select B's organization.
    r = a.get("/api/v1/folders/root", headers={"X-Organization-Id": str(b.org_id)})
    assert r.status_code == 403 and r.json()["error"]["code"] == "no_membership"
    # Nonexistent org gives the SAME answer (no tenant enumeration).
    r2 = a.get("/api/v1/folders/root", headers={"X-Organization-Id": str(uuid.uuid4())})
    assert (r2.status_code, r2.json()["error"]["code"]) == (403, "no_membership")
    r3 = a.get("/api/v1/folders/root", headers={"X-Organization-Id": "not-a-uuid"})
    assert r3.status_code == 422


def test_user_in_two_orgs_sees_only_the_selected_org(two_tenants):  # noqa: ANN001
    t = two_tenants
    world, a, b = t["world"], t["a"], t["b"]
    from app.db.models import Membership

    with world.db_factory() as db:  # alice (owner of A) is also a plain member of B
        db.add(
            Membership(
                id=uuid.uuid4(),
                organization_id=b.org_id,
                user_id=a.user_id,
                role="member",
                status="active",
            )
        )
        db.commit()
    # Without a selector the org is ambiguous.
    r = world.client.get("/api/v1/folders/root", headers={"Authorization": f"Bearer {a.token}"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "organization_required"
    # Under A she is owner; B's document is invisible under A's context and A's under B's.
    assert a.get(f"/api/v1/documents/{t['b_doc']}").status_code == 404
    as_b = {"X-Organization-Id": str(b.org_id)}
    assert a.get(f"/api/v1/documents/{t['a_doc']}", headers=as_b).status_code == 404
    # Under B she is a plain member: no admin rights bleed across tenants.
    assert a.get("/api/v1/admin/members", headers=as_b).status_code == 403
    assert (
        a.get(f"/api/v1/documents/{t['b_doc']}", headers=as_b).status_code == 404
    )  # no grant in B


@pytest.fixture()
def fresh(world):  # noqa: ANN001, ANN201
    org = world.org("State")
    user = world.user(org, "member", label="m")
    return world, org, user


def _me(world, token, org_id=None):  # noqa: ANN001, ANN202
    headers = {"Authorization": f"Bearer {token}"}
    if org_id:
        headers["X-Organization-Id"] = str(org_id)
    return world.client.get("/api/v1/folders/root", headers=headers)


class TestAuthentication:
    def test_no_token_and_garbage_tokens(self, fresh):  # noqa: ANN001
        world, org, _ = fresh
        assert world.client.get("/api/v1/folders/root").status_code == 401
        for bad in ("", "Bearer", "Bearer x.y.z", "Basic abc", "bearer"):
            r = world.client.get("/api/v1/folders/root", headers={"Authorization": bad})
            assert r.status_code == 401, bad
            assert r.json()["error"]["code"] == "unauthenticated"

    def test_forged_and_expired_tokens(self, fresh):  # noqa: ANN001
        world, org, user = fresh
        forged = jwt.encode(
            {
                "sub": user.subject,
                "email": user.email,
                "aud": "dms-local",
                "iat": int(datetime.now(UTC).timestamp()),
                "exp": int((datetime.now(UTC) + timedelta(hours=1)).timestamp()),
            },
            "attacker-secret-attacker-secret-attacker-secret",
            algorithm="HS256",
        )
        assert _me(world, forged, org.org_id).status_code == 401
        expired = world.token_for(
            user.subject, user.email, issued_at=datetime.now(UTC) - timedelta(hours=3)
        )
        assert _me(world, expired, org.org_id).status_code == 401
        none_alg = jwt.encode({"sub": user.subject, "aud": "dms-local"}, None, algorithm="none")
        assert _me(world, none_alg, org.org_id).status_code == 401

    def test_valid_identity_without_a_dms_account_is_refused(self, fresh):  # noqa: ANN001
        world, org, _ = fresh
        stranger = world.token_for(f"sub-{uuid.uuid4().hex}", "stranger@nowhere.test")
        r = _me(world, stranger, org.org_id)
        assert r.status_code == 403 and r.json()["error"]["code"] == "not_provisioned"

    def test_unverified_email_cannot_claim_an_invitation(self, fresh):  # noqa: ANN001
        world, org, _ = fresh
        r = org.post(
            "/api/v1/admin/members", json={"email": "newbie@invite.test", "role": "member"}
        )
        assert r.status_code == 201, r.text
        token = world.token_for("sub-new", "newbie@invite.test", verified=False)
        assert _me(world, token, org.org_id).json()["error"]["code"] == "not_provisioned"
        ok = world.token_for("sub-new", "newbie@invite.test", verified=True)
        assert _me(world, ok, org.org_id).status_code == 200  # verified email binds the invitation

    def test_disabled_user_suspended_membership_and_revoked_sessions(self, fresh):  # noqa: ANN001
        world, org, user = fresh
        assert _me(world, user.token, org.org_id).status_code == 200

        # session revocation: tokens issued before the cut-off stop working at once
        r = org.post(f"/api/v1/admin/members/{user.user_id}/revoke-sessions")
        assert r.status_code == 204
        old = world.token_for(
            user.subject, user.email, issued_at=datetime.now(UTC) - timedelta(minutes=5)
        )
        r = _me(world, old, org.org_id)
        assert r.status_code == 401 and r.json()["error"]["code"] == "session_revoked"
        import time

        time.sleep(1.1)  # a token issued after the cut-off (different second) is fine
        new_token = world.token_for(user.subject, user.email)
        assert _me(world, new_token, org.org_id).status_code == 200

        # membership suspension applies on the very next request
        assert (
            org.patch(
                f"/api/v1/admin/members/{user.user_id}", json={"status": "suspended"}
            ).status_code
            == 200
        )
        r = _me(world, new_token, org.org_id)
        assert r.status_code == 403 and r.json()["error"]["code"] == "no_membership"
        assert (
            org.patch(
                f"/api/v1/admin/members/{user.user_id}", json={"status": "active"}
            ).status_code
            == 200
        )
        assert _me(world, new_token, org.org_id).status_code == 200

        with world.db_factory() as db:
            db.execute(
                text("UPDATE dms.users SET status = 'disabled' WHERE id = :i"), {"i": user.user_id}
            )
            db.commit()
        r = _me(world, new_token, org.org_id)
        assert r.status_code == 403 and r.json()["error"]["code"] == "account_inactive"

    def test_suspended_organization_blocks_everyone(self, fresh):  # noqa: ANN001
        world, org, user = fresh
        with world.db_factory() as db:
            db.execute(
                text("UPDATE dms.organizations SET status = 'suspended' WHERE id = :i"),
                {"i": org.org_id},
            )
            db.commit()
        assert _me(world, user.token, org.org_id).status_code == 403
        assert _me(world, org.token, org.org_id).status_code == 403


class TestAdminBoundaries:
    def test_members_cannot_use_admin_endpoints(self, fresh):  # noqa: ANN001
        world, org, user = fresh
        for method, url, body in [
            ("get", "/api/v1/admin/members", None),
            ("post", "/api/v1/admin/members", {"email": "x@y.test"}),
            ("patch", f"/api/v1/admin/members/{org.user_id}", {"role": "member"}),
            ("post", "/api/v1/admin/groups", {"name": "g"}),
            ("get", "/api/v1/admin/audit-events", None),
            ("get", "/api/v1/admin/quarantine", None),
            ("patch", "/api/v1/organization", {"name": "Hijacked"}),
        ]:
            kw = {"json": body} if body is not None else {}
            assert getattr(user, method)(url, **kw).status_code == 403, url

    def test_admin_cannot_escalate_or_lock_out(self, fresh):  # noqa: ANN001
        world, org, _ = fresh
        admin = world.user(org, "admin", label="adm")
        # admin cannot create/modify owners or themselves
        assert (
            admin.post(
                "/api/v1/admin/members", json={"email": "o@x.test", "role": "owner"}
            ).status_code
            == 403
        )
        assert (
            admin.patch(
                f"/api/v1/admin/members/{org.user_id}", json={"status": "suspended"}
            ).status_code
            == 403
        )
        assert (
            admin.patch(
                f"/api/v1/admin/members/{admin.user_id}", json={"role": "owner"}
            ).status_code
            == 403
        )
        # the last owner cannot be demoted by themselves nor removed
        assert (
            org.patch(f"/api/v1/admin/members/{org.user_id}", json={"role": "member"}).status_code
            == 403
        )
        owner2 = world.user(org, "owner", label="own2")
        assert (
            owner2.patch(
                f"/api/v1/admin/members/{org.user_id}", json={"status": "removed"}
            ).status_code
            == 200
        )
        assert (
            owner2.patch(
                f"/api/v1/admin/members/{owner2.user_id}", json={"status": "removed"}
            ).status_code
            == 403
        )

    def test_auditor_reads_audit_only(self, fresh):  # noqa: ANN001
        world, org, _ = fresh
        auditor = world.user(org, "auditor", label="aud")
        root = world.root_id(org)
        doc = world.available_doc(org, world.mkdir(org, root, "docs"), "x.pdf")
        assert auditor.get("/api/v1/admin/audit-events").status_code == 200
        assert auditor.get(f"/api/v1/documents/{doc}").status_code == 404  # no content access
        assert auditor.get("/api/v1/admin/members").status_code == 403
