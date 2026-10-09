"""Prefix/any-term content search, per-item activity feed, dev password login and logout."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Srch", member_default_access=False)
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "docs")
    return dict(world=world, admin=admin, root=root, folder=folder)


def search(actor, q, **params):  # noqa: ANN001, ANN201, ANN003
    r = actor.get(f"{API}/search", params={"q": q, **params})
    assert r.status_code == 200, r.text
    return r.json()["items"]


class TestAdvancedSearch:
    def test_content_prefix_and_any_term_matching(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        d = w.available_doc(
            a, env["folder"], "memo1.txt", b"The approved marketing budget for 2026 is final."
        )
        w.available_doc(a, env["folder"], "memo2.txt", b"Office plants watering schedule.")
        hit = search(a, "budg")  # as-you-type prefix of a word that only occurs inside the file
        assert [i["id"] for i in hit] == [d] and hit[0]["match"] == "content"
        assert "[[budget]]" in hit[0]["snippet"].lower()
        assert [i["id"] for i in search(a, "market 2026")] == [d]  # every term as a prefix
        fallback = search(
            a, "approved zebra"
        )  # no file has both: any-term fallback finds the real match
        assert [i["id"] for i in fallback] == [d]
        assert search(a, "zebra giraffe") == []
        assert [i["id"] for i in search(a, '"approved marketing"')] == [
            d
        ]  # phrase syntax still works
        assert search(a, "budget -2026") == []  # exclusion still works

    def test_content_search_still_requires_the_preview_right(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        m = w.user(a, "member", label="reader")
        doc = w.available_doc(a, env["folder"], "secret.txt", b"quarterly layoffs planning")
        a.post(
            f"{API}/documents/{doc}/permissions",
            json={"subject_type": "user", "subject_id": str(m.user_id), "actions": ["view"]},
        )
        assert search(m, "layoffs") == []  # may see the name, not the content
        assert [i["id"] for i in search(m, "secret")] == [doc]
        a.post(
            f"{API}/documents/{doc}/permissions",
            json={"subject_type": "user", "subject_id": str(m.user_id), "actions": ["preview"]},
        )
        assert [i["id"] for i in search(m, "layoff")][:1] == [doc]

    def test_query_with_tsquery_syntax_cannot_break_or_inject(self, env):  # noqa: ANN001
        a = env["admin"]
        for q in [
            "a & | ! ( ) ' :* <->",
            "'; drop table dms.documents; --",
            "\\",
            "(((",
            "!!",
            "é€%_",
        ]:
            assert a.get(f"{API}/search", params={"q": q}).status_code == 200


class TestActivity:
    def test_feed_lists_item_events_and_hides_access_events_from_viewers(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        viewer = w.user(a, "member", label="v")
        doc = w.available_doc(a, env["folder"], "act.txt", b"activity text here")
        a.patch(f"{API}/documents/{doc}", json={"name": "act-renamed.txt"})
        a.post(
            f"{API}/documents/{doc}/shares",
            json={
                "recipients": [{"type": "user", "id": str(viewer.user_id)}],
                "actions": ["view", "comment"],
            },
        )
        viewer.post(f"{API}/documents/{doc}/comments", json={"body": "hi"})
        mine = a.get(f"{API}/documents/{doc}/activity").json()
        labels = [x["label"] for x in mine]
        assert (
            "created this file" in labels and "renamed this" in labels and "shared this" in labels
        )
        assert "commented" in labels and mine[0]["at"] >= mine[-1]["at"]  # newest first
        assert all(x["actor"]["email"] for x in mine if x["actor"])  # system events have no actor
        theirs = viewer.get(f"{API}/documents/{doc}/activity").json()
        tl = [x["label"] for x in theirs]
        assert "renamed this" in tl and "commented" in tl and "shared this" not in tl
        assert any(x["you"] for x in theirs if x["label"] == "commented")
        stranger = w.user(a, "member", label="s")
        assert stranger.get(f"{API}/documents/{doc}/activity").status_code == 404
        assert w.org("SrchOther").get(f"{API}/documents/{doc}/activity").status_code == 404

    def test_folder_activity(self, env):  # noqa: ANN001
        a = env["admin"]
        feed = a.get(f"{API}/folders/{env['folder']}/activity").json()
        assert "created this folder" in [x["label"] for x in feed]


class TestAuth:
    def test_dev_password_login_and_logout_everywhere(self, world):  # noqa: ANN001
        a = world.org("AuthT")
        email = a.email
        client = world.client
        bad = client.post(f"{API}/dev/login", json={"email": email, "password": "wrong"})
        assert bad.status_code == 401 and bad.json()["error"]["code"] == "invalid_credentials"
        assert (
            client.post(
                f"{API}/dev/login", json={"email": "nobody@x.test", "password": "dev-password-123"}
            ).status_code
            == 401
        )
        # The conftest users are provisioned by the dev token path; password login works for them too.
        ok = client.post(f"{API}/dev/login", json={"email": email, "password": "dev-password-123"})
        assert ok.status_code == 200
        h = {"Authorization": f"Bearer {ok.json()['access_token']}"}
        assert client.get(f"{API}/me", headers=h).status_code == 200
        assert (
            client.post(f"{API}/me/logout", headers=h, json={}).status_code == 204
        )  # plain sign-out
        assert client.get(f"{API}/me", headers=h).status_code == 200  # stateless token still valid
        assert (
            client.post(f"{API}/me/logout", headers=h, json={"everywhere": True}).status_code == 204
        )
        assert client.get(f"{API}/me", headers=h).status_code == 401  # revoked
        again = client.post(
            f"{API}/dev/login", json={"email": email, "password": "dev-password-123"}
        )
        h2 = {"Authorization": f"Bearer {again.json()['access_token']}"}
        assert client.get(f"{API}/me", headers=h2).status_code == 200  # can sign in again at once
