"""Admin/User permission dashboards: listings are scoped, explained by audit, and never leak."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


def grant(owner, folder, user, actions, expires_at=None):  # noqa: ANN001, ANN201
    body = {
        "subject_type": "user",
        "subject_id": str(user.user_id),
        "actions": actions,
        "inherit": True,
    }
    if expires_at:
        body["expires_at"] = expires_at.isoformat()
    r = owner.post(f"{API}/folders/{folder}/permissions", json=body)
    assert r.status_code == 201, r.text


@pytest.fixture()
def space(world):  # noqa: ANN001, ANN201
    owner = world.org("Perm Co", member_default_access=False)
    root = world.root_id(owner)
    folder = world.mkdir(owner, root, "Finance")
    alice = world.user(owner, "member", label="alice")
    bob = world.user(owner, "member", label="bob")
    return dict(world=world, owner=owner, root=root, folder=folder, alice=alice, bob=bob)


def test_admin_overview_lists_org_grants_and_filters_by_user(space):  # noqa: ANN001
    o, alice, bob = space["owner"], space["alice"], space["bob"]
    grant(o, space["folder"], alice, ["view", "download"])
    grant(o, space["folder"], bob, ["view"])
    allr = o.get(f"{API}/admin/permissions/access").json()
    subjects = {e["subject_id"] for e in allr["items"]}
    assert {str(alice.user_id), str(bob.user_id)} <= subjects
    one = o.get(f"{API}/admin/permissions/access", params={"user_id": str(alice.user_id)}).json()
    assert one["total"] >= 1
    assert all(e["subject_id"] in (str(alice.user_id), None) for e in one["items"])
    assert any(e["resource_name"] == "Finance" for e in one["items"])


def test_overview_is_admin_only(space):  # noqa: ANN001
    assert space["alice"].get(f"{API}/admin/permissions/access").status_code == 403


def test_expiring_filter_only_returns_near_expiry(space):  # noqa: ANN001
    o, alice, bob = space["owner"], space["alice"], space["bob"]
    soon = datetime.now(UTC) + timedelta(days=2)
    later = datetime.now(UTC) + timedelta(days=60)
    grant(o, space["folder"], alice, ["view"], expires_at=soon)
    grant(o, space["folder"], bob, ["view"], expires_at=later)
    r = o.get(f"{API}/admin/permissions/access", params={"expiring_within_days": 7}).json()
    ids = {e["subject_id"] for e in r["items"]}
    assert str(alice.user_id) in ids and str(bob.user_id) not in ids
    assert all(e["expiring_soon"] for e in r["items"])


def test_revoked_grants_disappear_from_dashboards(space):  # noqa: ANN001
    o, alice = space["owner"], space["alice"]
    grant(o, space["folder"], alice, ["view"])
    perms = o.get(f"{API}/resources/folder/{space['folder']}/acl").json()
    assert alice.get(f"{API}/me/access").json()["total"] >= 1
    gid = next(
        p["id"]
        for p in o.get(f"{API}/folders/{space['folder']}/permissions").json()
        if p.get("subject_id") == str(alice.user_id)
    )
    assert o.delete(f"{API}/folders/{space['folder']}/permissions/{gid}").status_code in (200, 204)
    assert perms is not None
    assert alice.get(f"{API}/me/access").json()["total"] == 0


def test_my_access_only_shows_what_is_addressed_to_me(space):  # noqa: ANN001
    o, alice, bob = space["owner"], space["alice"], space["bob"]
    grant(o, space["folder"], alice, ["view"])
    mine = alice.get(f"{API}/me/access").json()
    assert mine["total"] == 1 and mine["items"][0]["subject_id"] == str(alice.user_id)
    assert bob.get(f"{API}/me/access").json()["total"] == 0


def test_effective_access_matches_enforcement_and_hides_undiscoverable(space):  # noqa: ANN001
    o, alice, bob = space["owner"], space["alice"], space["bob"]
    grant(o, space["folder"], alice, ["view", "download"])
    r = alice.get(f"{API}/resources/folder/{space['folder']}/effective-access")
    assert r.status_code == 200 and {"view", "download"} <= set(r.json()["actions"])
    assert "delete" not in r.json()["actions"]
    # no access at all -> same 404 as a missing item (non-disclosure)
    assert bob.get(f"{API}/resources/folder/{space['folder']}/effective-access").status_code == 404


def test_permission_history_is_for_managers_and_records_changes(space):  # noqa: ANN001
    o, alice = space["owner"], space["alice"]
    grant(o, space["folder"], alice, ["view"])
    h = o.get(f"{API}/resources/folder/{space['folder']}/permission-history").json()
    assert any(e["action"] == "permission.granted" for e in h["items"])
    assert alice.get(
        f"{API}/resources/folder/{space['folder']}/permission-history"
    ).status_code in (
        403,
        404,
    )


def test_cross_tenant_resources_are_invisible(space):  # noqa: ANN001
    other = space["world"].org("Other Co", member_default_access=False)
    assert other.get(f"{API}/admin/permissions/access").json()["total"] == 0
    assert (
        other.get(f"{API}/resources/folder/{space['folder']}/effective-access").status_code == 404
    )
    assert (
        other.get(f"{API}/resources/folder/{space['folder']}/permission-history").status_code == 404
    )
