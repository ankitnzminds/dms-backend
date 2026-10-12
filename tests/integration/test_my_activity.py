"""The signed-in user's own activity feed (GET /me/activity) and named admin activity."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


@pytest.fixture()
def team(world):  # noqa: ANN001, ANN201
    owner = world.org("Feed Co", member_default_access=False)
    root = world.root_id(owner)
    folder = world.mkdir(owner, root, "Docs")
    doc = world.available_doc(owner, folder, "report.pdf")
    member = world.user(owner, "member", label="mem")
    return dict(world=world, owner=owner, folder=folder, doc=doc, member=member)


def test_my_activity_lists_only_my_own_actions_with_names(team):  # noqa: ANN001
    o, m = team["owner"], team["member"]
    grant = o.post(
        f"{API}/folders/{team['folder']}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(m.user_id),
            "actions": ["view", "preview", "download"],
            "inherit": True,
        },
    )
    assert grant.status_code == 201, grant.text
    assert o.post(f"{API}/documents/{team['doc']}/download-url", json={}).status_code == 200
    assert m.post(f"{API}/documents/{team['doc']}/download-url", json={}).status_code == 200

    mine = m.get(f"{API}/me/activity")
    assert mine.status_code == 200, mine.text
    items = mine.json()
    assert items, "the member downloaded a file, so there is something to show"
    assert all(i["verb"] for i in items)
    dl = [i for i in items if i["action"] == "document.download_url_issued"]
    assert dl and dl[0]["target_name"] == "report.pdf" and dl[0]["target_id"] == team["doc"]
    # nothing from the owner's own actions (the folder/document creation) leaks into the member's feed
    assert not [i for i in items if i["action"] in ("document.created", "folder.created")]

    theirs = o.get(f"{API}/me/activity").json()
    assert any(i["action"] == "document.created" for i in theirs)


def test_my_activity_hides_names_of_items_i_can_no_longer_see(team):  # noqa: ANN001
    o, m = team["owner"], team["member"]
    g = o.post(
        f"{API}/folders/{team['folder']}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(m.user_id),
            "actions": ["view", "preview", "download"],
            "inherit": True,
        },
    ).json()
    assert m.post(f"{API}/documents/{team['doc']}/download-url", json={}).status_code == 200
    assert o.delete(f"{API}/folders/{team['folder']}/permissions/{g['id']}").status_code == 204
    items = m.get(f"{API}/me/activity").json()
    dl = [i for i in items if i["action"] == "document.download_url_issued"]
    assert dl and dl[0]["target_name"] is None


def test_admin_activity_names_the_item(team):  # noqa: ANN001
    o = team["owner"]
    assert o.post(f"{API}/documents/{team['doc']}/download-url", json={}).status_code == 200
    page = o.get(f"{API}/admin/activity", params={"category": "files", "limit": 50}).json()
    named = [e for e in page["items"] if e["target_id"] == team["doc"]]
    assert named and named[0]["target_label"] == "report.pdf"
