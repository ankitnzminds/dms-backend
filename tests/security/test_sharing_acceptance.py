"""RELEASE-BLOCKING acceptance scenario (docs: Mandatory share acceptance test + section 13).

Organization Files / dir1 / dirB / file.pdf is shared with a user who has NO access to dir1,
dirB or file2.pdf. Covers listing, breadcrumb, parent/sibling isolation, download,
revocation, expiry, identity preservation (no duplicate), moves and audit.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text

pytestmark = [pytest.mark.integration, pytest.mark.security]

PDF = b"%PDF-1.4 acceptance test document"


@pytest.fixture()
def scenario(world):  # noqa: ANN001, ANN201
    admin = world.org("Acme", member_default_access=False)
    root = world.root_id(admin)
    dir1 = world.mkdir(admin, root, "dir1")
    dirb = world.mkdir(admin, dir1, "dirB")
    file_id = world.available_doc(admin, dirb, "file.pdf", PDF)
    sibling_id = world.available_doc(admin, dirb, "sibling.pdf", PDF + b" sibling")
    other_dir = world.mkdir(admin, dir1, "dirC")
    bob = world.user(admin, "member", label="bob")
    return dict(
        world=world,
        admin=admin,
        bob=bob,
        root=root,
        dir1=dir1,
        dirb=dirb,
        file_id=file_id,
        sibling_id=sibling_id,
        other_dir=other_dir,
    )


def _share(s, actions=("view", "download"), expires_in_days=7):  # noqa: ANN001, ANN202
    body = {
        "recipients": [{"type": "user", "id": str(s["bob"].user_id)}],
        "actions": list(actions),
        "expires_at": (datetime.now(UTC) + timedelta(days=expires_in_days)).isoformat(),
    }
    r = s["admin"].post(f"/api/v1/documents/{s['file_id']}/shares", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_full_acceptance_scenario(scenario):  # noqa: ANN001
    s = scenario
    bob, admin = s["bob"], s["admin"]

    # Before sharing: bob sees nothing of dir1 / dirB / the file.
    assert bob.get(f"/api/v1/documents/{s['file_id']}").status_code == 404
    assert bob.get(f"/api/v1/folders/{s['dirb']}/children").status_code == 404

    share = _share(s)

    # 1-2. Shared with Me shows the ORIGINAL document with the canonical breadcrumb.
    r = bob.get("/api/v1/shares/received")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    row = items[0]
    assert row["resource_id"] == s["file_id"]  # same document identity - no copy
    assert row["name"] == "file.pdf"
    assert [seg["name"] for seg in row["breadcrumb"]] == ["Organization Files", "dir1", "dirB"]
    # breadcrumb is context only: bob cannot navigate to ANY of those folders
    assert all(seg["navigable"] is False and seg["folder_id"] is None for seg in row["breadcrumb"])
    assert set(row["actions"]) >= {"view", "download"}
    assert row["shared_by"]["id"] == str(admin.user_id)

    # 3. Only granted actions: view + download yes; rename/delete/share no.
    assert bob.get(f"/api/v1/documents/{s['file_id']}").status_code == 200
    assert (
        bob.patch(f"/api/v1/documents/{s['file_id']}", json={"name": "hacked.pdf"}).status_code
        == 403
    )
    assert bob.delete(f"/api/v1/documents/{s['file_id']}").status_code == 403
    assert (
        bob.post(
            f"/api/v1/documents/{s['file_id']}/shares",
            json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["view"]},
        ).status_code
        == 403
    )

    # 4. Parent folder listing, sibling access and folder navigation remain DENIED.
    for folder in (s["dirb"], s["dir1"], s["root"]):
        listing = bob.get(f"/api/v1/folders/{folder}/children")
        assert listing.status_code in (403, 404), (folder, listing.text)
        assert bob.get(f"/api/v1/folders/{folder}").status_code in (403, 404)
        assert bob.get(f"/api/v1/folders/{folder}/breadcrumb").status_code in (403, 404)
    assert bob.get(f"/api/v1/documents/{s['sibling_id']}").status_code == 404
    assert bob.post(f"/api/v1/documents/{s['sibling_id']}/download-url", json={}).status_code == 404
    # cannot upload/create into the parent either
    assert bob.post(
        "/api/v1/folders", json={"parent_folder_id": s["dirb"], "name": "x"}
    ).status_code in (403, 404)

    # 5. Search must not leak siblings / folders.
    names = {i["name"] for i in bob.get("/api/v1/search", params={"q": "pdf"}).json()["items"]}
    assert names == {"file.pdf"}
    assert bob.get("/api/v1/search", params={"q": "dir"}).json()["total"] == 0

    # 6. Authorized download with an active grant.
    r = bob.post(f"/api/v1/documents/{s['file_id']}/download-url", json={})
    assert r.status_code == 200, r.text
    url = r.json()["url"].replace("http://testserver", "")
    got = world_get(s, url)
    assert got.status_code == 200
    assert got.content == PDF
    assert "attachment" in got.headers["content-disposition"]

    # 7. Revocation: new URL issuance fails; the old ticket stops working immediately.
    ticket = (
        bob.post(f"/api/v1/documents/{s['file_id']}/download-url", json={})
        .json()["url"]
        .replace("http://testserver", "")
    )
    assert admin.post(f"/api/v1/shares/{share['id']}/revoke").status_code == 200
    assert bob.post(f"/api/v1/documents/{s['file_id']}/download-url", json={}).status_code == 404
    assert world_get(s, ticket).status_code in (403, 404)
    assert bob.get(f"/api/v1/documents/{s['file_id']}").status_code == 404
    assert bob.get("/api/v1/shares/received").json()["total"] == 0
    inactive = bob.get("/api/v1/shares/received", params={"include_inactive": True}).json()["items"]
    assert (
        [i["status"] for i in inactive] == ["revoked"]
        and inactive[0]["breadcrumb"] == []
        and inactive[0]["actions"] == []
    )

    # 8. Audit trail exists for the whole story.
    events = admin.get("/api/v1/admin/audit-events", params={"limit": 200}).json()["items"]
    actions = {e["action"] for e in events}
    assert {
        "folder.created",
        "document.created",
        "share.created",
        "share.revoked",
        "document.download_url_issued",
        "document.downloaded",
        "authz.denied",
    } <= actions
    denied = [
        e
        for e in events
        if e["action"] == "authz.denied" and e["actor_user_id"] == str(bob.user_id)
    ]
    assert denied, "denials must be audited"


def world_get(s, url):  # noqa: ANN001, ANN202
    # Ticket redemption needs no Authorization header (the ticket is re-authorized server-side).
    return s["world"].client.get(url)


def test_expiry_blocks_access_and_url_issuance(scenario):  # noqa: ANN001
    s = scenario
    share = _share(s)
    bob = s["bob"]
    ticket = (
        bob.post(f"/api/v1/documents/{s['file_id']}/download-url", json={})
        .json()["url"]
        .replace("http://testserver", "")
    )
    assert world_get(s, ticket).status_code == 200

    with s["world"].db_factory() as db:  # time travel: expire the grant
        db.execute(
            text("UPDATE dms.share_grants SET expires_at = :t WHERE id = :id"),
            {"t": datetime.now(UTC) - timedelta(minutes=1), "id": share["id"]},
        )
        db.commit()

    assert bob.post(f"/api/v1/documents/{s['file_id']}/download-url", json={}).status_code == 404
    assert world_get(s, ticket).status_code in (403, 404)
    assert bob.get(f"/api/v1/documents/{s['file_id']}").status_code == 404
    expired = bob.get("/api/v1/shares/received", params={"include_inactive": True}).json()["items"]
    assert [i["status"] for i in expired] == ["expired"]


def test_share_is_not_a_copy_and_identity_survives_move_and_rename(scenario):  # noqa: ANN001
    s = scenario
    admin, bob = s["admin"], s["bob"]
    _share(s)
    with s["world"].db_factory() as db:
        before = db.execute(text("SELECT count(*) FROM dms.documents")).scalar()
        versions_before = db.execute(text("SELECT count(*) FROM dms.document_versions")).scalar()

    # Move + rename the original: the SAME document id, the recipient's breadcrumb follows.
    r = admin.patch(
        f"/api/v1/documents/{s['file_id']}",
        json={"folder_id": s["other_dir"], "name": "renamed.pdf"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["id"] == s["file_id"]
    row = bob.get("/api/v1/shares/received").json()["items"][0]
    assert row["resource_id"] == s["file_id"]
    assert row["name"] == "renamed.pdf"
    assert [seg["name"] for seg in row["breadcrumb"]] == ["Organization Files", "dir1", "dirC"]
    assert bob.get(f"/api/v1/folders/{s['other_dir']}/children").status_code in (403, 404)

    with s["world"].db_factory() as db:  # sharing/moving created no new document/version/object
        assert db.execute(text("SELECT count(*) FROM dms.documents")).scalar() == before
        assert (
            db.execute(text("SELECT count(*) FROM dms.document_versions")).scalar()
            == versions_before
        )


def test_copy_creates_new_identity(scenario):  # noqa: ANN001
    s = scenario
    r = s["admin"].post(
        f"/api/v1/documents/{s['file_id']}/copy",
        json={"target_folder_id": s["other_dir"], "name": "copy.pdf"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["id"] != s["file_id"]


def test_shared_with_group_follows_membership(scenario):  # noqa: ANN001
    s = scenario
    admin, world = s["admin"], s["world"]
    g = admin.post("/api/v1/admin/groups", json={"name": "Finance"}).json()
    carol = world.user(admin, "member", label="carol")
    r = admin.post(
        f"/api/v1/documents/{s['file_id']}/shares",
        json={"recipients": [{"type": "group", "id": g["id"]}], "actions": ["view"]},
    )
    assert r.status_code == 201, r.text
    assert carol.get(f"/api/v1/documents/{s['file_id']}").status_code == 404  # not in group yet
    assert (
        admin.post(
            f"/api/v1/admin/groups/{g['id']}/members", json={"user_id": str(carol.user_id)}
        ).status_code
        == 204
    )
    assert carol.get(f"/api/v1/documents/{s['file_id']}").status_code == 200
    assert (
        admin.delete(f"/api/v1/admin/groups/{g['id']}/members/{carol.user_id}").status_code == 204
    )
    assert (
        carol.get(f"/api/v1/documents/{s['file_id']}").status_code == 404
    )  # removal applies at once


def test_cannot_share_beyond_own_rights_or_outside_tenant(scenario):  # noqa: ANN001
    s = scenario
    admin, world = s["admin"], s["world"]
    other_org = world.org("Other")
    outsider = world.user(other_org, "member", label="eve")
    r = admin.post(
        f"/api/v1/documents/{s['file_id']}/shares",
        json={"recipients": [{"type": "user", "id": str(outsider.user_id)}], "actions": ["view"]},
    )
    assert r.status_code == 422 and r.json()["error"]["code"] == "unknown_recipient"
    r = admin.post(
        f"/api/v1/documents/{s['file_id']}/shares",
        json={"recipients": [{"type": "user", "id": str(s["bob"].user_id)}], "actions": ["delete"]},
    )
    assert r.status_code == 422  # delete cannot be delegated through a share
    with world.db_factory() as db:
        assert db.scalar(select(text("count(*)")).select_from(text("dms.share_grants"))) is not None


def test_default_root_access_lists_only_what_the_user_may_see(world):  # noqa: ANN001
    """With the default member access on the root, the listing is still filtered per item."""
    admin = world.org("Acme")  # default: members may discover root + create in it
    root = world.root_id(admin)
    dir1 = world.mkdir(admin, root, "dir1")
    dirb = world.mkdir(admin, dir1, "dirB")
    file_id = world.available_doc(admin, dirb, "file.pdf", PDF)
    bob = world.user(admin, "member", label="bob")
    r = admin.post(
        f"/api/v1/documents/{file_id}/shares",
        json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["view"]},
    )
    assert r.status_code == 201

    listing = bob.get(f"/api/v1/folders/{root}/children")
    assert listing.status_code == 200
    assert (
        listing.json()["items"] == [] and listing.json()["total"] == 0
    )  # dir1 is hidden, not counted
    assert bob.get(f"/api/v1/folders/{dir1}/children").status_code == 404
    row = bob.get("/api/v1/shares/received").json()["items"][0]
    assert [seg["navigable"] for seg in row["breadcrumb"]] == [True, False, False]
    assert [seg["folder_id"] is None for seg in row["breadcrumb"]] == [False, True, True]
