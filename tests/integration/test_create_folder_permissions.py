"""Creating folders in Team Folders: the Create Folder right is enforced by the API itself."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


def grant(owner, folder, user, actions, inherit=True):  # noqa: ANN001, ANN201
    r = owner.post(
        f"{API}/folders/{folder}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(user.user_id),
            "actions": actions,
            "inherit": inherit,
        },
    )
    assert r.status_code == 201, r.text


def mkdir(actor, parent, name):  # noqa: ANN001, ANN201
    return actor.post(f"{API}/folders", json={"parent_folder_id": parent, "name": name})


@pytest.fixture()
def team(world):  # noqa: ANN001, ANN201
    owner = world.org("Team Co", member_default_access=False)
    root = world.root_id(owner)
    folder = world.mkdir(owner, root, "Engineering")
    assert (
        owner.put(f"{API}/admin/team-folders/{folder}", json={"enabled": True}).status_code == 204
    )
    return dict(
        world=world,
        owner=owner,
        root=root,
        folder=folder,
        creator=world.user(owner, "member", label="creator"),
        reader=world.user(owner, "member", label="reader"),
        uploader=world.user(owner, "member", label="uploader"),
    )


class TestAdmin:
    def test_admin_creates_a_team_folder_and_nested_folders(self, team):  # noqa: ANN001
        o = team["owner"]
        top = mkdir(o, team["root"], "Design")
        assert top.status_code == 201, top.text
        assert top.json()["name"] == "Design" and top.json()["parent_folder_id"] == team["root"]
        assert (
            o.put(
                f"{API}/admin/team-folders/{top.json()['id']}", json={"enabled": True}
            ).status_code
            == 204
        )
        listed = {t["name"] for t in o.get(f"{API}/team-folders").json()}
        assert {"Engineering", "Design"} <= listed
        nested = mkdir(o, team["folder"], "Backend")
        assert nested.status_code == 201, nested.text
        kids = o.get(f"{API}/folders/{team['folder']}/children").json()["items"]
        assert "Backend" in {k["name"] for k in kids}

    def test_creation_is_audited(self, team):  # noqa: ANN001
        o = team["owner"]
        assert mkdir(o, team["folder"], "Audited").status_code == 201
        acts = [i for i in o.get(f"{API}/me/activity").json() if i["action"] == "folder.created"]
        assert any(i["target_name"] == "Audited" for i in acts)


class TestCreateFolderRight:
    def test_user_with_create_folder_can_create_and_nest(self, team):  # noqa: ANN001
        c = team["creator"]
        grant(team["owner"], team["folder"], c, ["view", "create_folder"])
        a = mkdir(c, team["folder"], "Sprint 1")
        assert a.status_code == 201, a.text
        # inheritance: the right applies to the whole permitted subtree
        assert mkdir(c, a.json()["id"], "Notes").status_code == 201

    def test_view_only_is_denied(self, team):  # noqa: ANN001
        r = team["reader"]
        grant(team["owner"], team["folder"], r, ["view"])
        assert mkdir(r, team["folder"], "Nope").status_code == 403

    def test_upload_right_does_not_allow_creating_folders(self, team):  # noqa: ANN001
        u = team["uploader"]
        grant(team["owner"], team["folder"], u, ["view", "upload"])
        assert mkdir(u, team["folder"], "Nope").status_code == 403

    def test_create_folder_does_not_grant_other_rights(self, team):  # noqa: ANN001
        c, o = team["creator"], team["owner"]
        grant(o, team["folder"], c, ["view", "create_folder"])
        made = mkdir(c, team["folder"], "Mine").json()["id"]
        # no delete / share / manage / upload implied by being able to create folders
        assert c.delete(f"{API}/folders/{team['folder']}").status_code in (403, 404)
        up = c.post(
            f"{API}/folders/{team['folder']}/uploads",
            json={"filename": "a.txt", "size_bytes": 1},
            headers={"Idempotency-Key": "k1"},
        )
        assert up.status_code == 403
        perms = c.get(f"{API}/folders/{made}").json()["permissions"]
        assert "create_folder" in perms and "manage_access" not in perms and "share" not in perms

    def test_no_access_at_all_is_not_disclosed(self, team):  # noqa: ANN001
        assert mkdir(team["reader"], team["folder"], "X").status_code == 404

    def test_not_inherited_below_a_non_inheriting_grant(self, team):  # noqa: ANN001
        c, o = team["creator"], team["owner"]
        sub = o.post(
            f"{API}/folders", json={"parent_folder_id": team["folder"], "name": "Sub"}
        ).json()["id"]
        grant(o, team["folder"], c, ["view", "create_folder"], inherit=False)
        assert mkdir(c, team["folder"], "Direct").status_code == 201
        assert mkdir(c, sub, "Below").status_code in (403, 404)

    def test_revoked_right_stops_working(self, team):  # noqa: ANN001
        c, o = team["creator"], team["owner"]
        grant(o, team["folder"], c, ["view", "create_folder"])
        assert mkdir(c, team["folder"], "One").status_code == 201
        perms = o.get(f"{API}/folders/{team['folder']}/permissions").json()
        gid = next(p["id"] for p in perms if p.get("subject_id") == str(c.user_id))
        assert o.delete(f"{API}/folders/{team['folder']}/permissions/{gid}").status_code in (
            200,
            204,
        )
        assert mkdir(c, team["folder"], "Two").status_code in (403, 404)


class TestNamesAndTenancy:
    def test_duplicate_sibling_is_rejected(self, team):  # noqa: ANN001
        o = team["owner"]
        assert mkdir(o, team["folder"], "Same").status_code == 201
        dup = mkdir(o, team["folder"], "same")
        assert dup.status_code == 409 and dup.json()["error"]["code"] == "name_conflict"

    @pytest.mark.parametrize("name", ["", "   ", "a/b", "a\\b", "..", "x" * 300])
    def test_invalid_names_are_rejected(self, team, name):  # noqa: ANN001
        assert mkdir(team["owner"], team["folder"], name).status_code in (400, 422)

    def test_other_organization_cannot_create_here(self, team):  # noqa: ANN001
        other = team["world"].org("Other Co", member_default_access=False)
        assert mkdir(other, team["folder"], "Intruder").status_code == 404
        kids = team["owner"].get(f"{API}/folders/{team['folder']}/children").json()["items"]
        assert "Intruder" not in {k["name"] for k in kids}

    def test_unknown_parent_is_not_found(self, team):  # noqa: ANN001
        r = mkdir(team["owner"], "00000000-0000-0000-0000-000000000000", "X")
        assert r.status_code == 404
