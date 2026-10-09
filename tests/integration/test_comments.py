"""Comments on files and folders: who may read, write, edit and moderate; shared recipients;
threads; notifications; tenant and trash edges."""

from __future__ import annotations

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration
API = "/api/v1"
PDF = b"%PDF-1.4 comments"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Cmt", member_default_access=False)
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "team")
    doc = world.available_doc(admin, folder, "plan.pdf", PDF + b" plan")
    return dict(world=world, admin=admin, root=root, folder=folder, doc=doc)


def share(admin, kind, rid, user, actions):  # noqa: ANN001, ANN202
    r = admin.post(
        f"{API}/{kind}s/{rid}/shares",
        json={"recipients": [{"type": "user", "id": str(user.user_id)}], "actions": actions},
    )
    assert r.status_code == 201, r.text


def test_shared_recipient_with_comment_access_can_comment_on_file_and_folder(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    bob = w.user(a, "member", label="bob")
    share(a, "document", env["doc"], bob, ["view", "comment"])
    share(a, "folder", env["folder"], bob, ["view", "comment"])
    listing = bob.get(f"{API}/documents/{env['doc']}/comments").json()
    assert listing["can_comment"] is True and listing["items"] == []
    c = bob.post(f"{API}/documents/{env['doc']}/comments", json={"body": "Looks good to me"})
    assert c.status_code == 201 and c.json()["can_edit"] and c.json()["can_delete"]
    f = bob.post(f"{API}/folders/{env['folder']}/comments", json={"body": "Folder note"})
    assert f.status_code == 201
    # the owner sees both, and was notified without the text leaking into the notification
    items = a.get(f"{API}/documents/{env['doc']}/comments").json()["items"]
    assert [i["body"] for i in items] == ["Looks good to me"] and items[0]["author"][
        "email"
    ] == bob.email
    assert items[0]["can_edit"] is False and items[0]["can_delete"] is True  # admin may moderate
    notes = a.get(f"{API}/notifications").json()["items"]
    assert any(n["type"] == "comment.created" for n in notes)
    assert "Looks good" not in str(notes)


def test_view_only_recipient_can_read_but_not_comment(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    eve = w.user(a, "member", label="eve")
    share(a, "document", env["doc"], eve, ["view"])
    a.post(f"{API}/documents/{env['doc']}/comments", json={"body": "Owner remark"})
    got = eve.get(f"{API}/documents/{env['doc']}/comments").json()
    assert got["can_comment"] is False and len(got["items"]) == 1
    r = eve.post(f"{API}/documents/{env['doc']}/comments", json={"body": "hi"})
    assert r.status_code == 403


def test_no_access_means_no_comments_and_no_existence_leak(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    stranger = w.user(a, "member", label="stranger")
    for url in (
        f"{API}/documents/{env['doc']}/comments",
        f"{API}/folders/{env['folder']}/comments",
    ):
        assert stranger.get(url).status_code == 404
        assert stranger.post(url, json={"body": "x"}).status_code == 404
    other = w.org("CmtOther")
    assert other.get(f"{API}/documents/{env['doc']}/comments").status_code == 404
    revoked = w.user(a, "member", label="rev")
    share(a, "document", env["doc"], revoked, ["view", "comment"])
    sh = a.get(f"{API}/documents/{env['doc']}/shares").json()[0]
    assert a.post(f"{API}/shares/{sh['id']}/revoke").status_code == 200
    assert (
        revoked.get(f"{API}/documents/{env['doc']}/comments").status_code == 404
    )  # revocation is immediate


def test_threads_edit_delete_and_moderation(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    bob = w.user(a, "member", label="bob")
    cara = w.user(a, "member", label="cara")
    for u in (bob, cara):
        share(a, "document", env["doc"], u, ["view", "comment"])
    top = bob.post(f"{API}/documents/{env['doc']}/comments", json={"body": "Question?"}).json()
    reply = cara.post(
        f"{API}/documents/{env['doc']}/comments", json={"body": "Answer.", "parent_id": top["id"]}
    )
    assert reply.status_code == 201 and reply.json()["parent_id"] == top["id"]
    nested = cara.post(
        f"{API}/documents/{env['doc']}/comments",
        json={"body": "deeper", "parent_id": reply.json()["id"]},
    )
    assert nested.status_code == 422  # one level only
    assert (
        cara.post(f"{API}/documents/{env['doc']}/comments", json={"body": "  "}).status_code == 422
    )
    # edit: author only
    assert cara.patch(f"{API}/comments/{top['id']}", json={"body": "hijack"}).status_code == 403
    edited = bob.patch(f"{API}/comments/{top['id']}", json={"body": "Question (edited)?"})
    assert edited.status_code == 200 and edited.json()["edited_at"]
    # delete: peers cannot, author can, admin can (moderation)
    assert cara.delete(f"{API}/comments/{top['id']}").status_code == 403
    assert a.delete(f"{API}/comments/{reply.json()['id']}").status_code == 204
    assert bob.delete(f"{API}/comments/{top['id']}").status_code == 204
    items = {i["id"]: i for i in a.get(f"{API}/documents/{env['doc']}/comments").json()["items"]}
    assert (
        items[top["id"]]["deleted"] and items[top["id"]]["body"] == ""
    )  # text scrubbed, thread shape kept
    assert bob.patch(f"{API}/comments/{top['id']}", json={"body": "again"}).status_code == 409
    assert (
        a.post(
            f"{API}/documents/{env['doc']}/comments", json={"body": "r", "parent_id": top["id"]}
        ).status_code
        == 409
    )
    with w.db_factory() as db:
        body = db.execute(
            text("SELECT body FROM dms.comments WHERE id = :i"), {"i": top["id"]}
        ).scalar()
    assert body == "[deleted]"
    actions = {
        e["action"]
        for e in a.get(f"{API}/admin/audit-events", params={"limit": 100}).json()["items"]
    }
    assert {"comment.created", "comment.edited", "comment.deleted"} <= actions


def test_trashed_items_and_cross_resource_parents_are_unreachable(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    other_doc = w.available_doc(a, env["folder"], "other.pdf", PDF + b" other")
    c = a.post(f"{API}/documents/{env['doc']}/comments", json={"body": "x"}).json()
    r = a.post(f"{API}/documents/{other_doc}/comments", json={"body": "y", "parent_id": c["id"]})
    assert r.status_code == 404  # a parent from another resource does not exist here
    assert a.delete(f"{API}/documents/{env['doc']}").status_code in (200, 204)
    assert a.get(f"{API}/documents/{env['doc']}/comments").status_code == 404
    assert a.patch(f"{API}/comments/{c['id']}", json={"body": "z"}).status_code == 404


def test_comment_text_is_stored_as_plain_text(env):  # noqa: ANN001
    a = env["admin"]
    payload = "<script>alert(1)</script> & more"
    c = a.post(f"{API}/folders/{env['folder']}/comments", json={"body": payload}).json()
    assert c["body"] == payload  # returned verbatim; the UI must render it as text
    assert (
        a.post(f"{API}/folders/{env['folder']}/comments", json={"body": "x" * 4001}).status_code
        == 422
    )
