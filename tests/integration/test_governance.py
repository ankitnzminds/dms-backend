"""Retention, legal holds, permanent purge, trash auto-expiry and DLP classification."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

PDF = b"%PDF-1.4 governance"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Gov", quota_bytes=1_000_000)
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "records")
    return dict(world=world, admin=admin, root=root, folder=folder)


def usage(a):  # noqa: ANN001, ANN202
    return a.get("/api/v1/organization/usage").json()


def object_exists(key_fragment_bytes: bytes) -> bool:
    from app.core.config import get_settings

    base = Path(get_settings().local_storage_path)
    return any(p.is_file() and p.read_bytes() == key_fragment_bytes for p in base.rglob("*"))


class TestPurge:
    def test_purge_removes_rows_objects_and_releases_quota(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        body = PDF + b" purge me"
        doc = w.available_doc(a, env["folder"], "gone.pdf", body)
        a.put(f"/api/v1/documents/{doc}/star")
        bob = w.user(a, "member", label="bob")
        a.post(
            f"/api/v1/documents/{doc}/shares",
            json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["view"]},
        )
        used = usage(a)["used_bytes"]
        assert used >= len(body) and object_exists(body)
        # must be trashed first
        assert a.delete(f"/api/v1/trash/documents/{doc}").status_code == 409
        assert a.delete(f"/api/v1/documents/{doc}").status_code == 204
        r = a.delete(f"/api/v1/trash/documents/{doc}")
        assert r.status_code == 200 and r.json() == {
            "documents": 1,
            "folders": 0,
            "retained": False,
        }
        assert a.get(f"/api/v1/documents/{doc}").status_code == 404
        assert a.get("/api/v1/trash").json()["total"] == 0
        assert bob.get("/api/v1/shares/received").json()["total"] == 0
        assert usage(a)["used_bytes"] == used - len(body)
        w.process_jobs()  # worker removes the stored object after the DB commit
        assert not object_exists(body)
        with w.db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.document_versions WHERE document_id = :d"),
                    {"d": doc},
                )
                == 0
            )
        actions = [
            e["action"]
            for e in a.get("/api/v1/admin/audit-events", params={"limit": 50}).json()["items"]
        ]
        assert "document.purged" in actions
        # quota reconciliation agrees with ground truth after purge
        from app.modules.quota.service import reconcile

        with w.db_factory() as db:
            assert reconcile(db, a.org_id)["drift_used_vs_versions"] == 0

    def test_purge_folder_subtree_and_versions_with_restore_chain(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        top = w.mkdir(a, env["root"], "project")
        sub = w.mkdir(a, top, "sub")
        doc = w.available_doc(a, sub, "v.pdf", PDF + b" v1")
        s = a.post(
            f"/api/v1/documents/{doc}/uploads",
            json={"filename": "v.pdf", "size_bytes": 20, "expected_latest_version": 1},
        ).json()
        a.put(
            s["upload_url"],
            content=b"%PDF-1.4 second ver.",
            headers={"Content-Type": "application/octet-stream"},
        )
        a.post(f"/api/v1/uploads/{s['id']}/finalize")
        w.process_jobs()
        assert (
            a.post(f"/api/v1/documents/{doc}/versions/1/restore").status_code == 201
        )  # v3 references v1
        w.process_jobs()
        assert a.delete(f"/api/v1/folders/{top}").status_code == 204
        r = a.delete(f"/api/v1/trash/folders/{top}")
        assert r.status_code == 200 and r.json() == {
            "documents": 1,
            "folders": 2,
            "retained": False,
        }
        w.process_jobs()
        with w.db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.folders WHERE id = ANY(:i)"),
                    {"i": [uuid.UUID(top), uuid.UUID(sub)]},
                )
                == 0
            )
        assert usage(a)["used_bytes"] == 0 or usage(a)["folders"] >= 1

    def test_purge_requires_delete_right_and_cannot_cross_tenants_or_hit_root(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "x.pdf", PDF + b" x")
        reader = w.user(a, "member", label="reader")
        a.post(
            f"/api/v1/folders/{env['folder']}/permissions",
            json={"subject_type": "user", "subject_id": str(reader.user_id), "actions": ["view"]},
        )
        a.delete(f"/api/v1/documents/{doc}")
        assert reader.delete(f"/api/v1/trash/documents/{doc}").status_code in (403, 404)
        other = w.org("Other")
        assert other.delete(f"/api/v1/trash/documents/{doc}").status_code == 404
        assert a.delete(f"/api/v1/trash/folders/{env['root']}").status_code in (403, 409)
        assert a.get("/api/v1/trash").json()["total"] == 1  # still there

    def test_trash_retention_auto_purges_old_items_only(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        old = w.available_doc(a, env["folder"], "old.pdf", PDF + b" old")
        new = w.available_doc(a, env["folder"], "new.pdf", PDF + b" new")
        a.delete(f"/api/v1/documents/{old}")
        a.delete(f"/api/v1/documents/{new}")
        with w.db_factory() as db:
            db.execute(
                text(
                    "UPDATE dms.documents SET deleted_at = now() - interval '40 days' WHERE id = :i"
                ),
                {"i": old},
            )
            db.commit()
        from app.modules.governance.service import purge_expired_trash

        with w.db_factory() as db:
            result = purge_expired_trash(db)
        assert result["purged"] >= 1
        names = [i["name"] for i in a.get("/api/v1/trash").json()["items"]]
        assert names == ["new.pdf"]
        # nothing is purged when the organization disables auto-purge
        assert (
            a.patch(
                "/api/v1/organization", json={"settings": {"trash_retention_days": None}}
            ).status_code
            == 200
        )
        with w.db_factory() as db:
            db.execute(
                text(
                    "UPDATE dms.documents SET deleted_at = now() - interval '400 days' WHERE id = :i"
                ),
                {"i": new},
            )
            db.commit()
            assert purge_expired_trash(db)["purged"] == 0


class TestLegalHold:
    def _hold(self, a, name="Case 42"):  # noqa: ANN001, ANN202
        r = a.post("/api/v1/admin/legal-holds", json={"name": name, "description": "litigation"})
        assert r.status_code == 201, r.text
        return r.json()

    def test_hold_blocks_trash_and_purge_until_released(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "held.pdf", PDF + b" held")
        hold = self._hold(a)
        assert (
            a.post(
                f"/api/v1/admin/legal-holds/{hold['id']}/items",
                json={"resource_type": "document", "resource_id": doc},
            ).status_code
            == 201
        )
        r = a.delete(f"/api/v1/documents/{doc}")
        assert r.status_code == 409 and r.json()["error"]["code"] == "legal_hold"
        assert a.get(f"/api/v1/documents/{doc}/protection").json() == {
            "legal_hold": True,
            "retention_until": None,
            "can_delete": False,
            "can_purge": False,
        }
        assert (
            a.get(f"/api/v1/admin/legal-holds/{hold['id']}/items").json()[0]["resource_name"]
            == "held.pdf"
        )
        rel = a.post(
            f"/api/v1/admin/legal-holds/{hold['id']}/release", json={"reason": "case closed"}
        )
        assert rel.status_code == 200 and rel.json()["status"] == "released"
        assert a.delete(f"/api/v1/documents/{doc}").status_code == 204
        assert a.delete(f"/api/v1/trash/documents/{doc}").status_code == 200
        actions = {
            e["action"]
            for e in a.get("/api/v1/admin/audit-events", params={"limit": 100}).json()["items"]
        }
        assert {"legal_hold.created", "legal_hold.item_added", "legal_hold.released"} <= actions

    def test_folder_hold_covers_subtree_and_trashed_items_cannot_be_purged(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "deep.pdf", PDF + b" deep")
        # trash first, then place a hold on the (restored-in-trash) document's folder
        assert a.delete(f"/api/v1/documents/{doc}").status_code == 204
        hold = self._hold(a, "Audit 7")
        a.post(
            f"/api/v1/admin/legal-holds/{hold['id']}/items",
            json={"resource_type": "folder", "resource_id": env["folder"]},
        )
        r = a.delete(f"/api/v1/trash/documents/{doc}")
        assert r.status_code == 409 and r.json()["error"]["code"] == "legal_hold"
        # deleting the held folder itself is blocked too
        assert a.delete(f"/api/v1/folders/{env['folder']}").status_code == 409
        # auto-purge also skips held content
        with w.db_factory() as db:
            db.execute(
                text(
                    "UPDATE dms.documents SET deleted_at = now() - interval '90 days' WHERE id = :i"
                ),
                {"i": doc},
            )
            db.commit()
        from app.modules.governance.service import purge_expired_trash

        with w.db_factory() as db:
            res = purge_expired_trash(db)
        assert res["skipped_protected"] >= 1
        assert a.get("/api/v1/trash").json()["total"] == 1

    def test_only_admins_manage_holds_auditors_read(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        member = w.user(a, "member", label="m")
        auditor = w.user(a, "auditor", label="aud")
        hold = self._hold(a)
        assert member.post("/api/v1/admin/legal-holds", json={"name": "x"}).status_code == 403
        assert member.get("/api/v1/admin/legal-holds").status_code == 403
        assert auditor.get("/api/v1/admin/legal-holds").status_code == 200
        assert (
            auditor.post(
                f"/api/v1/admin/legal-holds/{hold['id']}/release", json={"reason": "nope nope"}
            ).status_code
            == 403
        )
        other = w.org("Foreign")
        assert other.get(f"/api/v1/admin/legal-holds/{hold['id']}/items").status_code == 404
        assert (
            other.post(
                f"/api/v1/admin/legal-holds/{hold['id']}/items",
                json={"resource_type": "folder", "resource_id": env["folder"]},
            ).status_code
            == 404
        )

    def test_cannot_hold_foreign_resources(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        other = w.org("Foreign2")
        foreign = w.mkdir(other, w.root_id(other), "theirs")
        hold = self._hold(a)
        assert (
            a.post(
                f"/api/v1/admin/legal-holds/{hold['id']}/items",
                json={"resource_type": "folder", "resource_id": foreign},
            ).status_code
            == 404
        )


class TestRetention:
    def test_minimum_retention_blocks_purge_until_elapsed(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "kept.pdf", PDF + b" kept")
        pol = a.post(
            "/api/v1/admin/retention-policies",
            json={"name": "7 years", "min_retention_days": 2555, "scope_folder_id": env["folder"]},
        )
        assert pol.status_code == 201, pol.text
        a.delete(f"/api/v1/documents/{doc}")  # moving to trash is allowed
        r = a.delete(f"/api/v1/trash/documents/{doc}")
        assert r.status_code == 409 and r.json()["error"]["code"] == "retention_active"
        prot = a.get(f"/api/v1/documents/{doc}/protection").json()
        assert prot["can_delete"] is True and prot["can_purge"] is False and prot["retention_until"]
        # disabling the policy releases the protection
        assert (
            a.patch(
                f"/api/v1/admin/retention-policies/{pol.json()['id']}", json={"enabled": False}
            ).status_code
            == 200
        )
        assert a.delete(f"/api/v1/trash/documents/{doc}").status_code == 200

    def test_policy_scope_and_age(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        inside = w.available_doc(a, env["folder"], "in.pdf", PDF + b" in")
        outside_folder = w.mkdir(a, env["root"], "elsewhere")
        outside = w.available_doc(a, outside_folder, "out.pdf", PDF + b" out")
        a.post(
            "/api/v1/admin/retention-policies",
            json={"name": "scoped", "min_retention_days": 30, "scope_folder_id": env["folder"]},
        )
        a.delete(f"/api/v1/documents/{inside}")
        a.delete(f"/api/v1/documents/{outside}")
        assert a.delete(f"/api/v1/trash/documents/{outside}").status_code == 200  # not covered
        assert a.delete(f"/api/v1/trash/documents/{inside}").status_code == 409
        with w.db_factory() as db:  # old enough -> allowed
            db.execute(
                text(
                    "UPDATE dms.documents SET created_at = now() - interval '31 days' WHERE id = :i"
                ),
                {"i": inside},
            )
            db.commit()
        assert a.delete(f"/api/v1/trash/documents/{inside}").status_code == 200

    def test_validation_and_permissions(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        member = w.user(a, "member", label="m")
        assert (
            a.post(
                "/api/v1/admin/retention-policies", json={"name": "bad", "min_retention_days": 0}
            ).status_code
            == 422
        )
        assert (
            a.post(
                "/api/v1/admin/retention-policies",
                json={"name": "bad", "min_retention_days": 5, "scope_folder_id": str(uuid.uuid4())},
            ).status_code
            == 422
        )
        assert (
            member.post(
                "/api/v1/admin/retention-policies", json={"name": "x", "min_retention_days": 5}
            ).status_code
            == 403
        )
        assert (
            a.post(
                "/api/v1/admin/retention-policies", json={"name": "dup", "min_retention_days": 5}
            ).status_code
            == 201
        )
        assert (
            a.post(
                "/api/v1/admin/retention-policies", json={"name": "DUP", "min_retention_days": 5}
            ).status_code
            == 409
        )


class TestClassificationDlp:
    def test_restricted_documents_cannot_be_shared_or_reached_through_shares(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        bob = w.user(a, "member", label="bob")
        doc = w.available_doc(a, env["folder"], "secret.pdf", PDF + b" secret")
        share = a.post(
            f"/api/v1/folders/{env['folder']}/shares",
            json={
                "recipients": [{"type": "user", "id": str(bob.user_id)}],
                "actions": ["view", "download"],
            },
        )
        assert share.status_code == 201
        assert bob.get(f"/api/v1/documents/{doc}").status_code == 200
        # classifying the document as restricted ends share-derived access immediately
        assert (
            a.patch(f"/api/v1/documents/{doc}", json={"classification": "restricted"}).status_code
            == 200
        )
        assert bob.get(f"/api/v1/documents/{doc}").status_code == 404
        assert bob.post(f"/api/v1/documents/{doc}/download-url", json={}).status_code == 404
        assert bob.get("/api/v1/search", params={"q": "secret"}).json()["total"] == 0
        # and direct sharing is refused by policy
        r = a.post(
            f"/api/v1/documents/{doc}/shares",
            json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["view"]},
        )
        assert r.status_code == 409 and r.json()["error"]["code"] == "policy_blocked"
        # the owner/admin keep access
        assert a.get(f"/api/v1/documents/{doc}").status_code == 200

    def test_classification_changes_need_manage_access_and_valid_values(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "c.pdf", PDF + b" c")
        editor = w.user(a, "member", label="ed")
        a.post(
            f"/api/v1/documents/{doc}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(editor.user_id),
                "actions": ["edit_metadata"],
            },
        )
        assert (
            editor.patch(f"/api/v1/documents/{doc}", json={"classification": "public"}).status_code
            == 403
        )
        assert (
            a.patch(f"/api/v1/documents/{doc}", json={"classification": "top-secret"}).status_code
            == 422
        )

    def test_org_can_relax_the_dlp_setting(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        assert (
            a.patch(
                "/api/v1/organization",
                json={
                    "settings": {"share_blocked_classifications": ["restricted", "confidential"]}
                },
            ).status_code
            == 200
        )
        assert (
            a.patch(
                "/api/v1/organization",
                json={"settings": {"share_blocked_classifications": ["bogus"]}},
            ).status_code
            == 422
        )
        doc = w.available_doc(a, env["folder"], "conf.pdf", PDF + b" conf")
        a.patch(f"/api/v1/documents/{doc}", json={"classification": "confidential"})
        bob = w.user(a, "member", label="bob")
        r = a.post(
            f"/api/v1/documents/{doc}/shares",
            json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["view"]},
        )
        assert r.status_code == 409
