"""Legal hold / retention also protect an item's NAME, LOCATION and CURRENT VERSION (not only deletion)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"
PDF = b"%PDF-1.4 hold-move"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Hold Move Co", quota_bytes=5_000_000)
    root = world.root_id(admin)
    return dict(
        world=world,
        admin=admin,
        root=root,
        src=world.mkdir(admin, root, "src"),
        dst=world.mkdir(admin, root, "dst"),
    )


def hold(admin, rtype, rid):  # noqa: ANN001, ANN201
    h = admin.post(f"{API}/admin/legal-holds", json={"name": f"hold-{rid[:6]}"}).json()
    r = admin.post(
        f"{API}/admin/legal-holds/{h['id']}/items",
        json={"resource_type": rtype, "resource_id": rid},
    )
    assert r.status_code == 201, r.text
    return h["id"]


def err(r):  # noqa: ANN001, ANN201
    assert r.status_code == 409, r.text
    return r.json()["error"]["code"]


def test_held_document_cannot_be_renamed_moved_or_version_restored_until_released(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    doc = w.available_doc(a, env["src"], "held.pdf", PDF + b"1")
    hid = hold(a, "document", doc)
    assert err(a.patch(f"{API}/documents/{doc}", json={"name": "renamed.pdf"})) == "legal_hold"
    assert err(a.patch(f"{API}/documents/{doc}", json={"folder_id": env["dst"]})) == "legal_hold"
    assert err(a.post(f"{API}/documents/{doc}/versions/1/restore")) == "legal_hold"
    # nothing changed
    d = a.get(f"{API}/documents/{doc}").json()
    assert d["name"] == "held.pdf" and d["folder_id"] == env["src"]
    # the denial is audited with the reason
    ev = a.get(f"{API}/admin/audit-events", params={"action": "governance.blocked"}).json()["items"]
    assert {e["metadata"]["operation"] for e in ev} >= {"rename", "move", "restore_version"}
    assert (
        a.post(f"{API}/admin/legal-holds/{hid}/release", json={"reason": "case closed"}).status_code
        == 200
    )
    assert a.patch(f"{API}/documents/{doc}", json={"name": "renamed.pdf"}).status_code == 200
    assert a.patch(f"{API}/documents/{doc}", json={"folder_id": env["dst"]}).status_code == 200


def test_folder_hold_covers_children_for_move_and_the_folder_itself(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    doc = w.available_doc(a, env["src"], "inside.pdf", PDF + b"2")
    hold(a, "folder", env["src"])
    assert err(a.patch(f"{API}/documents/{doc}", json={"folder_id": env["dst"]})) == "legal_hold"
    assert err(a.patch(f"{API}/folders/{env['src']}", json={"name": "src2"})) == "legal_hold"
    assert (
        err(a.patch(f"{API}/folders/{env['src']}", json={"parent_folder_id": env["dst"]}))
        == "legal_hold"
    )
    # bulk move reports the per-item reason instead of moving it
    r = a.post(
        f"{API}/items/bulk/move",
        json={
            "items": [{"kind": "document", "id": doc}],
            "target_folder_id": env["dst"],
            "on_conflict": "fail",
        },
    ).json()
    assert r["results"][0]["status"] == "error" and r["results"][0]["code"] == "legal_hold"
    # unrelated items are unaffected
    free = w.available_doc(a, env["dst"], "free.pdf", PDF + b"3")
    assert a.patch(f"{API}/documents/{free}", json={"name": "free2.pdf"}).status_code == 200


def test_scoped_retention_blocks_leaving_the_scope_but_not_moves_inside_it(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    inner = w.mkdir(a, env["src"], "inner")
    doc = w.available_doc(a, env["src"], "kept.pdf", PDF + b"4")
    pol = a.post(
        f"{API}/admin/retention-policies",
        json={"name": "keep", "min_retention_days": 3650, "scope_folder_id": env["src"]},
    )
    assert pol.status_code == 201, pol.text
    assert (
        err(a.patch(f"{API}/documents/{doc}", json={"folder_id": env["dst"]})) == "retention_active"
    )
    assert (
        a.patch(f"{API}/documents/{doc}", json={"folder_id": inner}).status_code == 200
    )  # still in scope
    assert (
        a.patch(f"{API}/documents/{doc}", json={"name": "kept2.pdf"}).status_code == 200
    )  # rename is fine
    # moving the whole scope folder carries the policy with it; moving a parent of docs out of scope is refused
    child = w.mkdir(a, env["src"], "child")
    w.available_doc(a, child, "c.pdf", PDF + b"5")
    assert (
        err(a.patch(f"{API}/folders/{child}", json={"parent_folder_id": env["dst"]}))
        == "retention_active"
    )
    assert (
        a.patch(f"{API}/folders/{env['src']}", json={"parent_folder_id": env["dst"]}).status_code
        == 200
    )
    a.delete(f"{API}/admin/retention-policies/{pol.json()['id']}")


def test_org_wide_retention_never_blocks_moves(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    doc = w.available_doc(a, env["src"], "any.pdf", PDF + b"6")
    assert (
        a.post(
            f"{API}/admin/retention-policies", json={"name": "all", "min_retention_days": 3650}
        ).status_code
        == 201
    )
    assert a.patch(f"{API}/documents/{doc}", json={"folder_id": env["dst"]}).status_code == 200


def test_unprotected_items_behave_exactly_as_before(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    doc = w.available_doc(a, env["src"], "plain.pdf", PDF + b"7")
    assert (
        a.patch(
            f"{API}/documents/{doc}", json={"name": "plain2.pdf", "folder_id": env["dst"]}
        ).status_code
        == 200
    )
    assert a.post(f"{API}/documents/{doc}/versions/1/restore").status_code in (200, 201)
