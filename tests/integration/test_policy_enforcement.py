"""Published policies are enforced by the real backend operations (and drafts / disabled / observe are not)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration
API = "/api/v1"
URL = f"{API}/admin/policy-rules"

CONF = {"attribute": "resource.classification", "operator": "EQUALS", "value": "confidential"}


def doc(**over):  # noqa: ANN003, ANN201
    base = {
        "schema_version": 1,
        "effect": "DENY",
        "scope": {"type": "organization"},
        "resource_types": ["document"],
        "actions": ["download"],
        "condition": CONF,
    }
    base.update(over)
    return base


def publish(admin, name, document, mode="enforce"):  # noqa: ANN001, ANN201
    r = admin.post(URL, json={"name": name, "document": document})
    assert r.status_code == 201, r.text
    pid = r.json()["id"]
    assert admin.post(f"{URL}/{pid}/validate").json()["valid"] is True
    r = admin.post(f"{URL}/{pid}/publish", json={"mode": mode})
    assert r.status_code == 200, r.text
    return pid


def grant(owner, folder, user, actions):  # noqa: ANN001, ANN201
    r = owner.post(
        f"{API}/folders/{folder}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(user.user_id),
            "actions": actions,
            "inherit": True,
        },
    )
    assert r.status_code == 201, r.text


def download(actor, doc_id):  # noqa: ANN001, ANN201
    return actor.post(f"{API}/documents/{doc_id}/download-url", json={})


def set_level(world, user, level):  # noqa: ANN001, ANN201
    with world.db_factory() as db:
        db.execute(
            text("UPDATE dms.memberships SET access_level = :l WHERE user_id = :u"),
            {"l": level, "u": str(user.user_id)},
        )
        db.commit()


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    owner = world.org("Enforce Co", member_default_access=False)
    root = world.root_id(owner)
    folder = world.mkdir(owner, root, "Shared")
    secret = world.available_doc(owner, folder, "secret.pdf")
    plain = world.available_doc(owner, folder, "plain.pdf")
    assert (
        owner.patch(
            f"{API}/documents/{secret}", json={"classification": "confidential"}
        ).status_code
        == 200
    )
    admin = world.user(owner, "admin", label="eadmin")
    alice = world.user(owner, "member", label="alice")
    ext = world.user(owner, "member", label="ext")
    set_level(world, ext, "external")
    for u in (alice, ext):
        grant(owner, folder, u, ["view", "preview", "download"])
    return dict(
        world=world,
        owner=owner,
        admin=admin,
        alice=alice,
        ext=ext,
        folder=folder,
        secret=secret,
        plain=plain,
        root=root,
    )


def test_baseline_without_policies_is_unchanged(env):  # noqa: ANN001
    assert download(env["ext"], env["secret"]).status_code == 200
    assert download(env["alice"], env["secret"]).status_code == 200


def test_published_deny_blocks_the_matching_users_and_documents_only(env):  # noqa: ANN001
    publish(
        env["admin"],
        "No external confidential downloads",
        doc(subjects={"access_levels": ["external"]}),
    )
    r = download(env["ext"], env["secret"])
    assert r.status_code == 403 and r.json()["error"]["code"] == "policy_denied"
    assert download(env["ext"], env["plain"]).status_code == 200  # other classification
    assert download(env["alice"], env["secret"]).status_code == 200  # other subject
    # the denial is audited with the policy revision, but the user is told nothing about the rule
    ev = (
        env["owner"]
        .get(f"{API}/admin/audit-events", params={"action": "authz.denied"})
        .json()["items"]
    )
    mine = [e for e in ev if e["metadata"].get("reason") == "POLICY_DENY"]
    assert mine and mine[0]["metadata"]["policies"][0]["revision"] == 1
    assert "classification" not in r.text


def test_draft_disabled_and_observe_do_not_block(env):  # noqa: ANN001
    admin = env["admin"]
    r = admin.post(URL, json={"name": "draft only", "document": doc()})
    assert r.status_code == 201
    assert download(env["alice"], env["secret"]).status_code == 200  # draft: not enforced
    pid = publish(admin, "will be disabled", doc())
    assert download(env["alice"], env["secret"]).status_code == 403
    admin.post(f"{URL}/{pid}/disable")
    assert download(env["alice"], env["secret"]).status_code == 200  # disabled: not enforced
    admin.post(f"{URL}/{pid}/enable")
    assert admin.put(f"{URL}/{pid}/mode", json={"mode": "observe"}).status_code == 200
    assert download(env["alice"], env["secret"]).status_code == 200  # observe: allowed ...
    ev = (
        env["owner"]
        .get(f"{API}/admin/audit-events", params={"action": "policy.observed"})
        .json()["items"]
    )
    assert ev and ev[0]["metadata"]["would_be"] == "deny" and ev[0]["metadata"]["enforced"] is False


def test_a_policy_never_grants_access(env):  # noqa: ANN001
    stranger = env["world"].user(env["owner"], "member", label="stranger")  # no grant at all
    publish(env["admin"], "allow everything", doc(effect="ALLOW", condition=None))
    assert download(stranger, env["plain"]).status_code in (403, 404)


def test_group_policy_applies_to_members_and_follows_membership_changes(env):  # noqa: ANN001
    world = env["world"]
    gid = uuid.uuid4()
    with world.db_factory() as db:
        from app.db.models import Group, GroupMembership

        db.add(Group(id=gid, organization_id=env["owner"].org_id, name="Contractors", kind="group"))
        db.flush()
        db.add(
            GroupMembership(
                group_id=gid, user_id=env["alice"].user_id, organization_id=env["owner"].org_id
            )
        )
        db.commit()
    publish(
        env["admin"],
        "Contractors cannot download confidential",
        doc(subjects={"groups": [str(gid)]}),
    )
    assert download(env["alice"], env["secret"]).status_code == 403
    assert download(env["ext"], env["secret"]).status_code == 200  # not in the group
    with world.db_factory() as db:  # removed from the group -> the very next request is allowed
        db.execute(
            text("DELETE FROM dms.group_memberships WHERE user_id = :u"),
            {"u": str(env["alice"].user_id)},
        )
        db.commit()
    assert download(env["alice"], env["secret"]).status_code == 200


def test_unlisted_group_ids_from_other_tenants_are_rejected_at_validation(env):  # noqa: ANN001
    r = env["admin"].post(
        URL, json={"name": "x-tenant", "document": doc(subjects={"groups": [str(uuid.uuid4())]})}
    )
    pid = r.json()["id"]
    assert env["admin"].post(f"{URL}/{pid}/validate").json()["valid"] is False


def test_administrators_are_exempt_from_ordinary_but_not_mandatory_policies(env):  # noqa: ANN001
    publish(env["admin"], "ordinary", doc(resource_types=["document"], actions=["download"]))
    assert download(env["admin"], env["secret"]).status_code == 200  # ordinary DENY: admins exempt
    assert download(env["alice"], env["secret"]).status_code == 403
    # a mandatory DENY (owner-managed) binds administrators and owners too
    mand = env["owner"].post(URL, json={"name": "mandatory", "document": doc(mandatory=True)})
    pid = mand.json()["id"]
    env["owner"].post(f"{URL}/{pid}/validate")
    assert env["owner"].post(f"{URL}/{pid}/publish", json={}).status_code == 200
    assert download(env["admin"], env["secret"]).status_code == 403
    assert download(env["owner"], env["secret"]).status_code == 403
    assert download(env["owner"], env["plain"]).status_code == 200


def test_folder_scoped_policy_covers_the_subtree_only(env):  # noqa: ANN001
    world, owner = env["world"], env["owner"]
    other = world.mkdir(owner, env["root"], "Elsewhere")
    elsewhere = world.available_doc(owner, other, "e.pdf")
    grant(owner, other, env["alice"], ["view", "preview", "download"])
    publish(
        env["admin"],
        "Shared folder: no downloads",
        doc(scope={"type": "folder", "id": env["folder"]}, condition=None),
    )
    assert download(env["alice"], env["plain"]).status_code == 403
    assert download(env["alice"], elsewhere).status_code == 200


def test_policy_changes_apply_to_the_next_request(env):  # noqa: ANN001
    admin = env["admin"]
    pid = publish(admin, "toggle", doc())
    assert download(env["alice"], env["secret"]).status_code == 403
    admin.post(f"{URL}/{pid}/disable")
    assert download(env["alice"], env["secret"]).status_code == 200
    admin.post(f"{URL}/{pid}/enable")
    assert download(env["alice"], env["secret"]).status_code == 403


def test_other_tenants_policies_do_not_apply(env):  # noqa: ANN001
    world = env["world"]
    publish(env["admin"], "tenant A deny", doc())
    other = world.org("Unaffected Co", member_default_access=False)
    root = world.root_id(other)
    d = world.available_doc(other, root, "o.pdf")
    assert (
        other.patch(f"{API}/documents/{d}", json={"classification": "confidential"}).status_code
        == 200
    )
    assert download(other, d).status_code == 200


def test_require_approval_cannot_be_enforced_yet(env):  # noqa: ANN001
    admin = env["admin"]
    r = admin.post(
        URL,
        json={
            "name": "needs approval",
            "document": doc(effect="REQUIRE_APPROVAL", actions=["share"]),
        },
    )
    pid = r.json()["id"]
    admin.post(f"{URL}/{pid}/validate")
    blocked = admin.post(f"{URL}/{pid}/publish", json={"mode": "enforce"})
    assert (
        blocked.status_code == 409 and blocked.json()["error"]["code"] == "approval_not_available"
    )
    assert admin.post(f"{URL}/{pid}/publish", json={"mode": "observe"}).status_code == 200


def test_list_and_hints_reflect_the_policy(env):  # noqa: ANN001
    publish(env["admin"], "no download", doc(condition=None))
    listing = env["alice"].get(f"{API}/folders/{env['folder']}/children").json()
    names = {i["name"] for i in listing.get("items", [])}
    assert {"secret.pdf", "plain.pdf"} <= names  # still visible: only download is removed


def _open_link(env):  # noqa: ANN001, ANN202
    """An anonymous, download-capable public link over the shared folder."""
    from sqlalchemy import update

    from app.db.models import ShareGrant

    o = env["owner"]
    assert (
        o.patch(f"{API}/organization", json={"settings": {"allow_public_links": True}}).status_code
        == 200
    )
    s = o.post(f"{API}/shares/for/folder/{env['folder']}").json()
    o.patch(f"{API}/shares/{s['id']}", json={"restricted": False, "link_enabled": True})
    token = o.get(f"{API}/shares/{s['id']}").json()["link_url"].rsplit("/", 1)[1]
    with env["world"].db_factory() as db:
        db.execute(
            update(ShareGrant)
            .where(ShareGrant.id == uuid.UUID(s["id"]))
            .values(actions=["view", "preview", "download"])
        )
        db.commit()
    return token


def test_public_link_applies_dlp_classification_block(env):  # noqa: ANN001
    """Regression: an anonymous folder link used to serve 'restricted' files that named recipients cannot get."""
    c = env["world"].client
    token = _open_link(env)
    assert (
        env["owner"]
        .patch(f"{API}/documents/{env['secret']}", json={"classification": "restricted"})
        .status_code
        == 200
    )
    assert (
        c.get(f"{API}/public/shares/{token}/documents/{env['plain']}/download").status_code == 200
    )
    assert (
        c.get(f"{API}/public/shares/{token}/documents/{env['secret']}/download").status_code == 404
    )
    names = {k["name"] for k in c.get(f"{API}/public/shares/{token}/children").json()}
    assert "secret.pdf" not in names and "plain.pdf" in names


def test_public_link_is_covered_by_policies_aimed_at_external_users(env):  # noqa: ANN001
    c = env["world"].client
    token = _open_link(env)
    assert (
        c.get(f"{API}/public/shares/{token}/documents/{env['secret']}/download").status_code == 200
    )
    publish(
        env["admin"], "externals: no confidential", doc(subjects={"access_levels": ["external"]})
    )
    assert (
        c.get(f"{API}/public/shares/{token}/documents/{env['secret']}/download").status_code == 404
    )
    assert (
        c.get(f"{API}/public/shares/{token}/documents/{env['plain']}/download").status_code == 200
    )


# ---- simulator -----------------------------------------------------------------------------------
def sim(admin, env, user, action="download", doc_id=None, draft=None):  # noqa: ANN001, ANN201
    body = {
        "user_id": str(user.user_id),
        "resource_type": "document",
        "resource_id": doc_id or env["secret"],
        "action": action,
    }
    if draft:
        body["draft_policy_id"] = draft
    return admin.post(f"{URL}/simulate", json=body)


def test_simulator_explains_without_changing_anything(env):  # noqa: ANN001
    admin = env["admin"]
    r = sim(admin, env, env["alice"]).json()
    assert r["simulated"] is True and r["outcome"] == "allow" and r["holds_permission"] is True
    # a DRAFT is simulated as if enforcing, but is NOT enforced for real
    d = admin.post(URL, json={"name": "sim draft", "document": doc()}).json()["id"]
    r = sim(admin, env, env["alice"], draft=d).json()
    assert r["outcome"] == "deny" and r["matched"][0]["source"] == "draft"
    assert download(env["alice"], env["secret"]).status_code == 200  # simulation changed nothing
    # missing ACL permission is reported as such; a policy never grants
    stranger = env["world"].user(env["owner"], "member", label="sim-stranger")
    r = sim(admin, env, stranger).json()
    assert r["outcome"] == "deny" and r["reason"] == "ACL_PERMISSION_MISSING"
    ev_ = (
        env["owner"].get(f"{API}/admin/audit-events", params={"action": "policy.simulated"}).json()
    )
    assert ev_["total"] >= 3


def test_simulator_is_admin_only_and_tenant_scoped(env):  # noqa: ANN001
    assert sim(env["alice"], env, env["alice"]).status_code == 403
    other = env["world"].org("Sim Other Co", member_default_access=False)
    assert sim(other, env, env["alice"]).status_code in (403, 404)


def test_simulator_shows_published_and_observe_only_matches(env):  # noqa: ANN001
    admin = env["admin"]
    publish(admin, "published deny", doc(subjects={"access_levels": ["external"]}))
    r = sim(admin, env, env["ext"]).json()
    assert r["outcome"] == "deny" and r["matched"][0]["source"] == "published"
    publish(
        admin, "observed deny", doc(subjects={"roles": ["member"]}, condition=CONF), mode="observe"
    )
    r = sim(admin, env, env["alice"]).json()
    assert r["outcome"] == "allow" and r["observed_only"]  # would match, but only observed
