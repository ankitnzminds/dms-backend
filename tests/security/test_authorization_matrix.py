"""Permission matrix: roles, ownership, grants, inheritance, groups, expiry, no escalation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

pytestmark = [pytest.mark.integration, pytest.mark.security]

PDF = b"%PDF-1.4 matrix"


@pytest.fixture()
def tree(world):  # noqa: ANN001, ANN201
    """root > team > sub > doc.pdf ; root > other > other.pdf  (no default member access)."""
    admin = world.org("Matrix", member_default_access=False)
    root = world.root_id(admin)
    team = world.mkdir(admin, root, "team")
    sub = world.mkdir(admin, team, "sub")
    other = world.mkdir(admin, root, "other")
    doc = world.available_doc(admin, sub, "doc.pdf", PDF)
    other_doc = world.available_doc(admin, other, "other.pdf", PDF + b"2")
    return dict(
        world=world,
        admin=admin,
        root=root,
        team=team,
        sub=sub,
        other=other,
        doc=doc,
        other_doc=other_doc,
    )


def grant(admin, folder, user, actions, **kw):  # noqa: ANN001, ANN202
    body = {"subject_type": "user", "subject_id": str(user.user_id), "actions": actions, **kw}
    r = admin.post(f"/api/v1/folders/{folder}/permissions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_default_deny_for_plain_members(tree):  # noqa: ANN001
    t = tree
    m = t["world"].user(t["admin"], "member")
    for url in (
        f"/api/v1/folders/{t['root']}",
        f"/api/v1/folders/{t['team']}",
        f"/api/v1/documents/{t['doc']}",
    ):
        assert m.get(url).status_code == 404
    assert m.get("/api/v1/search", params={"q": "pdf"}).json()["total"] == 0


def test_inherited_folder_grant_reaches_descendants_but_not_ancestors_or_siblings(tree):  # noqa: ANN001
    t = tree
    m = t["world"].user(t["admin"], "member")
    grant(t["admin"], t["team"], m, ["view", "download"])
    assert m.get(f"/api/v1/folders/{t['team']}").status_code == 200
    assert m.get(f"/api/v1/folders/{t['sub']}/children").status_code == 200  # inherited downwards
    assert m.get(f"/api/v1/documents/{t['doc']}").status_code == 200
    assert m.post(f"/api/v1/documents/{t['doc']}/download-url", json={}).status_code == 200
    # but never upwards or sideways
    assert m.get(f"/api/v1/folders/{t['root']}").status_code == 404
    assert m.get(f"/api/v1/folders/{t['other']}").status_code == 404
    assert m.get(f"/api/v1/documents/{t['other_doc']}").status_code == 404
    # only granted actions
    assert m.patch(f"/api/v1/documents/{t['doc']}", json={"name": "x.pdf"}).status_code == 403
    assert m.delete(f"/api/v1/documents/{t['doc']}").status_code == 403
    assert (
        m.post("/api/v1/folders", json={"parent_folder_id": t["sub"], "name": "n"}).status_code
        == 403
    )
    # the breadcrumb shows the path but only navigable where authorized
    crumbs = m.get(f"/api/v1/documents/{t['doc']}").json()["breadcrumb"]
    assert [(c["name"], c["navigable"]) for c in crumbs] == [
        ("Organization Files", False),
        ("team", True),
        ("sub", True),
    ]


def test_non_inheriting_grant_applies_to_that_folder_only(tree):  # noqa: ANN001
    t = tree
    m = t["world"].user(t["admin"], "member")
    grant(t["admin"], t["team"], m, ["view"], inherit=False)
    assert m.get(f"/api/v1/folders/{t['team']}/children").status_code == 200
    # child folder is NOT visible (and therefore not listed) although the parent is
    assert m.get(f"/api/v1/folders/{t['sub']}").status_code == 404
    assert m.get(f"/api/v1/folders/{t['team']}/children").json()["items"] == []
    assert m.get(f"/api/v1/documents/{t['doc']}").status_code == 404


def test_listing_hides_children_the_user_cannot_see(tree):  # noqa: ANN001
    t = tree
    m = t["world"].user(t["admin"], "member")
    grant(t["admin"], t["root"], m, ["discover"], inherit=False)  # may list root, nothing else
    r = m.get(f"/api/v1/folders/{t['root']}/children")
    assert r.status_code == 200 and r.json()["items"] == [] and r.json()["total"] == 0
    grant(t["admin"], t["other"], m, ["view"])
    items = m.get(f"/api/v1/folders/{t['root']}/children").json()
    assert [i["name"] for i in items["items"]] == ["other"] and items["total"] == 1


def test_group_grants_follow_membership_changes(tree):  # noqa: ANN001
    t = tree
    admin, world = t["admin"], t["world"]
    g = admin.post("/api/v1/admin/groups", json={"name": "Readers"}).json()
    m = world.user(admin, "member")
    r = admin.post(
        f"/api/v1/folders/{t['team']}/permissions",
        json={"subject_type": "group", "subject_id": g["id"], "actions": ["view"]},
    )
    assert r.status_code == 201
    assert m.get(f"/api/v1/documents/{t['doc']}").status_code == 404
    admin.post(f"/api/v1/admin/groups/{g['id']}/members", json={"user_id": str(m.user_id)})
    assert m.get(f"/api/v1/documents/{t['doc']}").status_code == 200
    admin.delete(f"/api/v1/admin/groups/{g['id']}/members/{m.user_id}")
    assert m.get(f"/api/v1/documents/{t['doc']}").status_code == 404
    admin.post(f"/api/v1/admin/groups/{g['id']}/members", json={"user_id": str(m.user_id)})
    assert m.get(f"/api/v1/documents/{t['doc']}").status_code == 200
    assert (
        admin.delete(f"/api/v1/admin/groups/{g['id']}").status_code == 204
    )  # deleting the group ends access
    assert m.get(f"/api/v1/documents/{t['doc']}").status_code == 404


def test_org_wide_grant_and_revocation_and_expiry(tree):  # noqa: ANN001
    t = tree
    admin, world = t["admin"], t["world"]
    m = world.user(admin, "member")
    g = admin.post(
        f"/api/v1/folders/{t['other']}/permissions",
        json={"subject_type": "organization", "actions": ["view"]},
    ).json()
    assert m.get(f"/api/v1/documents/{t['other_doc']}").status_code == 200
    assert admin.delete(f"/api/v1/folders/{t['other']}/permissions/{g['id']}").status_code == 204
    assert m.get(f"/api/v1/documents/{t['other_doc']}").status_code == 404

    g2 = grant(
        admin,
        t["other"],
        m,
        ["view"],
        expires_at=(datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    assert m.get(f"/api/v1/documents/{t['other_doc']}").status_code == 200
    with world.db_factory() as db:
        db.execute(
            text("UPDATE dms.permission_grants SET expires_at = :t WHERE id = :i"),
            {"t": datetime.now(UTC) - timedelta(seconds=5), "i": g2["id"]},
        )
        db.commit()
    assert m.get(f"/api/v1/documents/{t['other_doc']}").status_code == 404


def test_no_privilege_escalation_through_grants_or_shares(tree):  # noqa: ANN001
    t = tree
    admin, world = t["admin"], t["world"]
    mgr = world.user(admin, "member", label="mgr")
    peer = world.user(admin, "member", label="peer")
    grant(admin, t["team"], mgr, ["view", "manage_access", "share"])  # no delete / download
    # mgr cannot hand out rights they do not hold
    r = mgr.post(
        f"/api/v1/folders/{t['team']}/permissions",
        json={"subject_type": "user", "subject_id": str(peer.user_id), "actions": ["delete"]},
    )
    assert r.status_code == 403
    r = mgr.post(
        f"/api/v1/documents/{t['doc']}/shares",
        json={"recipients": [{"type": "user", "id": str(peer.user_id)}], "actions": ["download"]},
    )
    assert r.status_code == 403
    # ... but may delegate what they hold, and nothing more
    assert (
        mgr.post(
            f"/api/v1/folders/{t['team']}/permissions",
            json={"subject_type": "user", "subject_id": str(peer.user_id), "actions": ["view"]},
        ).status_code
        == 201
    )
    assert peer.get(f"/api/v1/documents/{t['doc']}").status_code == 200
    assert peer.post(f"/api/v1/documents/{t['doc']}/download-url", json={}).status_code == 403
    # 'administer' can never be granted on a resource
    r = admin.post(
        f"/api/v1/folders/{t['team']}/permissions",
        json={"subject_type": "user", "subject_id": str(peer.user_id), "actions": ["administer"]},
    )
    assert r.status_code == 422


def test_folder_share_covers_subtree_only(tree):  # noqa: ANN001
    t = tree
    admin, world = t["admin"], t["world"]
    bob = world.user(admin, "member", label="bob")
    r = admin.post(
        f"/api/v1/folders/{t['sub']}/shares",
        json={
            "recipients": [{"type": "user", "id": str(bob.user_id)}],
            "actions": ["view", "download"],
        },
    )
    assert r.status_code == 201, r.text
    assert bob.get(f"/api/v1/folders/{t['sub']}/children").status_code == 200
    assert bob.get(f"/api/v1/documents/{t['doc']}").status_code == 200
    assert bob.get(f"/api/v1/folders/{t['team']}").status_code == 404  # parent: no
    assert bob.get(f"/api/v1/documents/{t['other_doc']}").status_code == 404  # unrelated: no
    row = bob.get("/api/v1/shares/received").json()["items"][0]
    assert row["resource_type"] == "folder" and row["resource_id"] == t["sub"]
    assert [(c["name"], c["navigable"]) for c in row["breadcrumb"]] == [
        ("Organization Files", False),
        ("team", False),
    ]


def test_uploader_gets_no_rights_beyond_the_grant_and_none_on_the_folder(tree):  # noqa: ANN001
    t = tree
    admin, world = t["admin"], t["world"]
    m = world.user(admin, "member", label="uploader")
    grant(admin, t["team"], m, ["create_child", "upload_version"])
    doc = world.available_doc(m, t["team"], "mine.pdf", PDF + b"mine")
    assert m.get(f"/api/v1/documents/{doc}").status_code == 200
    # uploading a file does not escalate: renaming and deleting need their own rights
    assert m.patch(f"/api/v1/documents/{doc}", json={"name": "renamed.pdf"}).status_code == 403
    assert m.delete(f"/api/v1/documents/{doc}").status_code == 403
    assert m.patch(f"/api/v1/folders/{t['team']}", json={"name": "hacked"}).status_code == 403
    assert m.delete(f"/api/v1/folders/{t['team']}").status_code == 403
    grant(admin, t["team"], m, ["rename", "delete"])
    assert m.patch(f"/api/v1/documents/{doc}", json={"name": "renamed.pdf"}).status_code == 200
    assert m.delete(f"/api/v1/documents/{doc}").status_code == 204


def test_deleting_a_folder_requires_rights_on_everything_inside(tree):  # noqa: ANN001
    t = tree
    admin, world = t["admin"], t["world"]
    m = world.user(admin, "member", label="mgr")
    grant(admin, t["team"], m, ["delete", "view"], inherit=False)  # may delete team itself only
    r = m.delete(f"/api/v1/folders/{t['team']}")
    assert r.status_code == 403  # children (sub/doc) are not deletable by m
    assert admin.get(f"/api/v1/folders/{t['sub']}").json()["deleted_at"] is None


def test_processing_and_quarantined_documents_are_owner_and_admin_only(tree):  # noqa: ANN001
    t = tree
    admin, world = t["admin"], t["world"]
    m = world.user(admin, "member", label="reader")
    grant(admin, t["team"], m, ["view", "download", "create_child"])
    pending = world.upload(admin, t["sub"], "pending.pdf", PDF + b"pending")  # not yet scanned
    assert m.get(f"/api/v1/documents/{pending['document_id']}").status_code == 404
    assert [i["name"] for i in m.get(f"/api/v1/folders/{t['sub']}/children").json()["items"]] == [
        "doc.pdf"
    ]
    assert (
        admin.post(f"/api/v1/documents/{pending['document_id']}/download-url", json={}).status_code
        == 409
    )
    world.process_jobs()
    assert m.get(f"/api/v1/documents/{pending['document_id']}").status_code == 200
