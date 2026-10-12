"""Administrator-controlled Recycle Bin: users cannot erase content, admins recover or delete it."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"
BIN = f"{API}/admin/recycle-bin"
PDF = b"%PDF-1.4 recycle"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Bin Co", member_default_access=False)
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "Projects")
    member = world.user(admin, "member", label="mem")
    stranger = world.user(admin, "member", label="out")
    r = admin.post(
        f"{API}/folders/{folder}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(member.user_id),
            "actions": [
                "view",
                "preview",
                "download",
                "delete",
                "restore",
                "rename",
                "move",
                "upload_version",
                "create_folder",
                "upload",
            ],
            "inherit": True,
        },
    )
    assert r.status_code == 201, r.text
    return dict(
        world=world, admin=admin, member=member, stranger=stranger, root=root, folder=folder
    )


def names(actor, **params):  # noqa: ANN001, ANN201
    r = actor.get(BIN, params=params)
    assert r.status_code == 200, r.text
    return {i["name"]: i for i in r.json()["items"]}


def audit_actions(admin):  # noqa: ANN001, ANN201
    return {
        e["action"]
        for e in admin.get(f"{API}/admin/audit-events", params={"limit": 200}).json()["items"]
    }


class TestDeleteAndPermanentDelete:
    def test_user_delete_lands_in_the_admin_recycle_bin_with_details(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        doc = w.available_doc(m, env["folder"], "plan.pdf", PDF)
        assert m.delete(f"{API}/documents/{doc}").status_code == 204
        item = names(a)["plan.pdf"]
        assert item["kind"] == "document" and item["id"] == doc
        assert item["original_path"].endswith("Projects")
        assert item["deleted_by"]["email"] == m.email if hasattr(m, "email") else True
        assert item["deleted_by"]["id"] == str(m.user_id)
        assert item["owner"]["id"] == str(m.user_id)
        assert item["deletion_source"] == "trash" and item["recovery_status"] == "recoverable"
        assert item["size_bytes"] == len(PDF) and item["original_location_available"] is True
        d = a.get(f"{BIN}/document/{doc}").json()
        assert d["versions"] == 1 and d["documents"] == 1 and d["protections"] == []

    def test_delete_permanently_by_a_user_keeps_it_recoverable(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        doc = w.available_doc(m, env["folder"], "secret.pdf", PDF)
        assert m.delete(f"{API}/documents/{doc}").status_code == 204
        r = m.delete(f"{API}/trash/documents/{doc}")
        assert r.status_code == 200 and r.json()["retained"] is True
        # gone from the user's trash, and the user cannot bring it back
        assert "secret.pdf" not in {i["name"] for i in m.get(f"{API}/trash").json()["items"]}
        assert m.post(f"{API}/documents/{doc}/restore", json={}).status_code == 404
        # but the administrator still sees it, flagged, with the underlying data intact
        item = names(a)["secret.pdf"]
        assert item["deletion_source"] == "user_permanent" and item["permanent_requested_at"]
        assert a.get(f"{BIN}/document/{doc}").json()["versions"] == 1
        assert names(a, source="user_permanent").keys() == {"secret.pdf"}
        assert "secret.pdf" not in names(a, source="trash")
        # restoring clears the flag and brings the same document (id, versions) back
        res = a.post(f"{BIN}/restore", json={"items": [{"kind": "document", "id": doc}]}).json()
        assert res["succeeded"] == 1, res
        back = a.get(f"{API}/documents/{doc}")
        assert back.status_code == 200 and back.json()["latest_version_number"] == 1
        assert "secret.pdf" not in names(a)
        acts = audit_actions(a)
        assert {
            "document.permanent_delete_requested",
            "document.restore_requested",
            "document.restored",
        } <= acts

    def test_an_admin_using_the_old_endpoint_still_purges(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "gone.pdf", PDF)
        assert a.delete(f"{API}/documents/{doc}").status_code == 204
        r = a.delete(f"{API}/trash/documents/{doc}")
        assert r.status_code == 200 and r.json()["retained"] is False and r.json()["documents"] == 1
        assert "gone.pdf" not in names(a)


class TestRestore:
    def test_folder_with_nested_files_restores_whole_hierarchy(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        top = w.mkdir(m, env["folder"], "Archive")
        sub = w.mkdir(m, top, "2024")
        d1 = w.available_doc(m, top, "a.pdf", PDF + b"1")
        d2 = w.available_doc(m, sub, "b.pdf", PDF + b"2")
        assert m.delete(f"{API}/folders/{top}").status_code == 204
        bin_ = names(a)
        assert list(bin_) == ["Archive"] and bin_["Archive"]["item_count"] == 2
        assert bin_["Archive"]["size_bytes"] == len(PDF) * 2 + 2
        res = a.post(f"{BIN}/restore", json={"items": [{"kind": "folder", "id": top}]}).json()
        assert res["succeeded"] == 1, res
        assert a.get(f"{API}/documents/{d1}").status_code == 200
        assert a.get(f"{API}/documents/{d2}").status_code == 200
        kids = a.get(f"{API}/folders/{top}/children").json()["items"]
        assert {k["name"] for k in kids} == {"2024", "a.pdf"}
        assert "folder.restored" in audit_actions(a)

    def test_name_conflict_can_be_resolved_by_renaming(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        doc = w.available_doc(m, env["folder"], "report.pdf", PDF)
        assert m.delete(f"{API}/documents/{doc}").status_code == 204
        w.available_doc(m, env["folder"], "report.pdf", PDF + b"new")
        first = a.post(f"{BIN}/restore", json={"items": [{"kind": "document", "id": doc}]}).json()
        assert first["failed"] == 1 and first["results"][0]["code"] == "name_conflict"
        assert "report.pdf" in names(a)  # still waiting in the bin
        again = a.post(
            f"{BIN}/restore",
            json={"items": [{"kind": "document", "id": doc, "new_name": "report (recovered).pdf"}]},
        ).json()
        assert again["succeeded"] == 1, again
        assert a.get(f"{API}/documents/{doc}").json()["name"] == "report (recovered).pdf"

    def test_missing_parent_needs_an_alternative_location(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        box = w.mkdir(a, env["root"], "Box")
        doc = w.available_doc(a, box, "inside.pdf", PDF)
        assert a.delete(f"{API}/documents/{doc}").status_code == 204
        assert a.delete(f"{API}/folders/{box}").status_code == 204
        bin_ = names(a)
        assert bin_["inside.pdf"]["original_location_available"] is False
        plain = a.post(f"{BIN}/restore", json={"items": [{"kind": "document", "id": doc}]}).json()
        assert plain["results"][0]["code"] == "parent_deleted"
        moved = a.post(
            f"{BIN}/restore",
            json={"items": [{"kind": "document", "id": doc, "target_folder_id": env["folder"]}]},
        ).json()
        assert moved["succeeded"] == 1, moved
        assert a.get(f"{API}/documents/{doc}").json()["folder_id"] == env["folder"]

    def test_filters(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        d1 = w.available_doc(m, env["folder"], "x.pdf", PDF)
        d2 = w.available_doc(a, env["folder"], "y.pdf", PDF + b"y")
        for d, who in ((d1, m), (d2, a)):
            assert who.delete(f"{API}/documents/{d}").status_code == 204
        assert set(names(a, deleted_by=str(m.user_id))) == {"x.pdf"}
        assert set(names(a, q="Y.P")) == {"y.pdf"}
        assert set(names(a, file_type="pdf")) == {"x.pdf", "y.pdf"}
        assert names(a, file_type="folder") == {}
        assert names(a, date_from="2999-01-01T00:00:00Z") == {}


class TestSecurity:
    def test_non_admins_cannot_use_the_recycle_bin(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        doc = w.available_doc(m, env["folder"], "mine.pdf", PDF)
        assert m.delete(f"{API}/documents/{doc}").status_code == 204
        ref = {"kind": "document", "id": doc}
        assert m.get(BIN).status_code == 403
        assert m.get(f"{BIN}/document/{doc}").status_code == 403
        assert m.post(f"{BIN}/restore", json={"items": [ref]}).status_code == 403
        assert m.post(f"{BIN}/purge", json={"items": [ref]}).status_code == 403
        assert env["stranger"].get(BIN).status_code == 403
        assert "mine.pdf" in names(a)  # nothing happened

    def test_other_organizations_are_isolated(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        doc = w.available_doc(m, env["folder"], "private.pdf", PDF)
        assert m.delete(f"{API}/documents/{doc}").status_code == 204
        other = w.org("Other Bin Co", member_default_access=False)
        assert names(other) == {}
        ref = {"kind": "document", "id": doc}
        assert other.get(f"{BIN}/document/{doc}").status_code == 404
        r = other.post(f"{BIN}/restore", json={"items": [ref]}).json()
        assert r["failed"] == 1 and r["results"][0]["code"] == "not_found"
        r = other.post(f"{BIN}/purge", json={"items": [ref]}).json()
        assert r["failed"] == 1
        assert "private.pdf" in names(a)


class TestPermanentDeletion:
    def test_admin_purge_is_irreversible_and_audited(self, env):  # noqa: ANN001
        w, a, m = env["world"], env["admin"], env["member"]
        doc = w.available_doc(m, env["folder"], "bye.pdf", PDF)
        assert m.delete(f"{API}/documents/{doc}").status_code == 204
        res = a.post(f"{BIN}/purge", json={"items": [{"kind": "document", "id": doc}]}).json()
        assert res["succeeded"] == 1, res
        assert "bye.pdf" not in names(a)
        assert a.get(f"{BIN}/document/{doc}").status_code == 404
        acts = audit_actions(a)
        assert {"document.permanently_deleted", "document.purged"} <= acts

    def test_legal_hold_blocks_purge_and_reports_why(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "held.pdf", PDF)
        assert a.delete(f"{API}/documents/{doc}").status_code == 204
        hold = a.post(
            f"{API}/admin/legal-holds", json={"name": "Case 1", "description": "x"}
        ).json()
        a.post(
            f"{API}/admin/legal-holds/{hold['id']}/items",
            json={"resource_type": "folder", "resource_id": env["folder"]},
        )
        assert names(a)["held.pdf"]["recovery_status"] == "protected"
        d = a.get(f"{BIN}/document/{doc}").json()
        assert d["protections"][0]["reason"] == "legal_hold"
        res = a.post(f"{BIN}/purge", json={"items": [{"kind": "document", "id": doc}]}).json()
        assert res["failed"] == 1 and res["results"][0]["code"] == "legal_hold"
        # still restorable
        ok = a.post(f"{BIN}/restore", json={"items": [{"kind": "document", "id": doc}]}).json()
        assert ok["succeeded"] == 1, ok

    def test_bulk_purge_reports_each_item(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        d1 = w.available_doc(a, env["folder"], "one.pdf", PDF + b"1")
        d2 = w.available_doc(a, env["folder"], "two.pdf", PDF + b"2")
        for d in (d1, d2):
            assert a.delete(f"{API}/documents/{d}").status_code == 204
        missing = "00000000-0000-0000-0000-000000000000"
        res = a.post(
            f"{BIN}/purge",
            json={
                "items": [
                    {"kind": "document", "id": d1},
                    {"kind": "document", "id": missing},
                    {"kind": "document", "id": d2},
                ]
            },
        ).json()
        assert res["succeeded"] == 2 and res["failed"] == 1
        assert names(a) == {}

    def test_storage_deletion_is_queued_so_failures_can_be_retried(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "obj.pdf", PDF)
        assert a.delete(f"{API}/documents/{doc}").status_code == 204
        res = a.post(f"{BIN}/purge", json={"items": [{"kind": "document", "id": doc}]}).json()
        assert res["succeeded"] == 1
        # object deletion is an outbox job (retried by the worker, idempotent), not part of the request
        with w.db_factory() as db:
            from sqlalchemy import select

            from app.db.models import OutboxEvent

            ev = list(
                db.scalars(
                    select(OutboxEvent).where(OutboxEvent.event_type == "storage.delete_objects")
                )
            )
            assert ev and ev[-1].payload["objects"]
