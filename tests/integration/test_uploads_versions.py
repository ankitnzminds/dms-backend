"""Uploads (staging, checksum, size, quota), scanning/quarantine, versions, trash, tree rules."""

from __future__ import annotations

import hashlib
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

PDF = b"%PDF-1.4 content"
EICAR = b"%PDF-1.4 DMS-TEST-INFECTED-FILE-SIGNATURE"  # harmless marker; real EICAR trips host AV


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Uploads", quota_bytes=10_000)
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "docs")
    return dict(world=world, admin=admin, root=root, folder=folder)


def init(admin, folder, name, data, **kw):  # noqa: ANN001, ANN202
    body = {"filename": name, "size_bytes": len(data), **kw}
    return admin.post(f"/api/v1/folders/{folder}/uploads", json=body)


def put(admin, session, data):  # noqa: ANN001, ANN202
    return admin.put(
        session["upload_url"], content=data, headers={"Content-Type": "application/octet-stream"}
    )


def usage(admin):  # noqa: ANN001, ANN202
    return admin.get("/api/v1/organization/usage").json()


class TestUploadFlow:
    def test_happy_path_private_until_scanned(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        data = PDF + b" happy"
        digest = hashlib.sha256(data).hexdigest()
        s = init(admin, env["folder"], "happy.pdf", data, sha256=digest).json()
        assert usage(admin)["reserved_bytes"] == len(data) and usage(admin)["used_bytes"] == 0
        r = put(admin, s, data)
        assert r.status_code == 200 and r.json()["state"] == "uploaded"
        fin = admin.post(f"/api/v1/uploads/{s['id']}/finalize")
        assert fin.status_code == 200 and fin.json()["status"] == "pending_scan"
        assert fin.json()["version_number"] == 1
        # reservation became usage
        assert usage(admin)["reserved_bytes"] == 0 and usage(admin)["used_bytes"] == len(data)
        doc_id = fin.json()["document_id"]
        doc = admin.get(f"/api/v1/documents/{doc_id}").json()
        assert doc["status"] == "processing" and doc["current_version"] is None
        # not downloadable before the scan has passed
        assert admin.post(f"/api/v1/documents/{doc_id}/download-url", json={}).status_code == 409
        # finalize is idempotent
        assert (
            admin.post(f"/api/v1/uploads/{s['id']}/finalize").json()["version_id"]
            == fin.json()["version_id"]
        )
        w.process_jobs()
        doc = admin.get(f"/api/v1/documents/{doc_id}").json()
        assert doc["status"] == "available" and doc["current_version"]["scan_status"] == "clean"
        assert doc["current_version"]["sha256"] == digest
        # the staged bytes were verified against the recorded checksum by the scanner job
        url = admin.post(f"/api/v1/documents/{doc_id}/download-url", json={}).json()["url"]
        got = w.client.get(url.replace("http://testserver", ""))
        assert got.content == data and got.headers["x-content-type-options"] == "nosniff"
        assert "attachment" in got.headers["content-disposition"]
        # quota is the sum of stored versions
        assert usage(admin)["used_bytes"] == len(data)

    @pytest.mark.parametrize("name", ["evil.exe", "script.PS1", "x.bat"])
    def test_blocked_extensions(self, env, name):  # noqa: ANN001
        r = init(env["admin"], env["folder"], name, b"abc")
        assert r.status_code == 422 and r.json()["error"]["code"] == "blocked_file_type"
        assert usage(env["admin"])["reserved_bytes"] == 0

    def test_executable_content_is_rejected_even_with_innocent_name(self, env):  # noqa: ANN001
        admin = env["admin"]
        data = b"MZ\x90\x00" + b"\x00" * 100
        s = init(admin, env["folder"], "photo.jpg", data).json()
        r = put(admin, s, data)
        assert r.status_code == 422 and r.json()["error"]["code"] == "blocked_file_type"
        assert admin.get(f"/api/v1/uploads/{s['id']}").json()["state"] == "failed"
        assert usage(admin)["reserved_bytes"] == 0  # reservation released

    def test_checksum_and_size_mismatch_fail_and_release_quota(self, env):  # noqa: ANN001
        admin = env["admin"]
        s = init(admin, env["folder"], "a.pdf", PDF, sha256="0" * 64).json()
        r = put(admin, s, PDF)
        assert r.status_code == 422 and r.json()["error"]["code"] == "checksum_mismatch"
        assert usage(admin)["reserved_bytes"] == 0

        s = init(admin, env["folder"], "b.pdf", PDF).json()
        r = put(admin, s, PDF + b"extra")
        assert r.status_code == 422 and r.json()["error"]["code"] == "size_mismatch"
        s = init(admin, env["folder"], "c.pdf", PDF + b"xxxx").json()
        assert put(admin, s, PDF).status_code == 422
        assert usage(admin)["reserved_bytes"] == 0
        # failed sessions cannot be finalized
        assert admin.post(f"/api/v1/uploads/{s['id']}/finalize").status_code == 409

    def test_finalize_requires_content_and_cancel_releases(self, env):  # noqa: ANN001
        admin = env["admin"]
        s = init(admin, env["folder"], "n.pdf", PDF).json()
        assert admin.post(f"/api/v1/uploads/{s['id']}/finalize").status_code == 409
        assert usage(admin)["reserved_bytes"] == len(PDF)
        assert admin.delete(f"/api/v1/uploads/{s['id']}").status_code == 204
        assert usage(admin)["reserved_bytes"] == 0
        assert put(admin, s, PDF).status_code == 409  # cancelled

    def test_upload_sessions_are_private_to_their_creator(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        other = w.user(admin, "admin", label="otheradmin")
        s = init(admin, env["folder"], "p.pdf", PDF).json()
        assert other.get(f"/api/v1/uploads/{s['id']}").status_code == 404
        assert put(other, s, PDF).status_code == 404
        assert other.post(f"/api/v1/uploads/{s['id']}/finalize").status_code == 404

    def test_idempotency_key_returns_same_session(self, env):  # noqa: ANN001
        admin = env["admin"]
        h = {"Idempotency-Key": "key-123"}
        body = {"filename": "i.pdf", "size_bytes": 10}
        a = admin.post(f"/api/v1/folders/{env['folder']}/uploads", json=body, headers=h)
        b = admin.post(f"/api/v1/folders/{env['folder']}/uploads", json=body, headers=h)
        assert a.status_code == b.status_code == 201 and a.json()["id"] == b.json()["id"]
        assert usage(admin)["reserved_bytes"] == 10  # charged once
        c = admin.post(
            f"/api/v1/folders/{env['folder']}/uploads", json={**body, "size_bytes": 11}, headers=h
        )
        assert c.status_code == 409 and c.json()["error"]["code"] == "idempotency_mismatch"

    def test_name_conflicts_and_invalid_names(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        w.available_doc(admin, env["folder"], "dup.pdf")
        r = init(admin, env["folder"], "DUP.pdf", PDF)  # case-insensitive
        assert r.status_code == 409 and r.json()["error"]["code"] == "name_conflict"
        for bad in ("../x.pdf", "a/b.pdf", "..", "x" * 300):
            assert init(admin, env["folder"], bad, PDF).status_code == 422

    def test_expired_sessions_are_swept_and_quota_released(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        s = init(admin, env["folder"], "old.pdf", PDF).json()
        put(admin, s, PDF)
        with w.db_factory() as db:
            db.execute(
                text("UPDATE dms.upload_sessions SET expires_at = :t WHERE id = :i"),
                {"t": datetime.now(UTC) - timedelta(minutes=1), "i": s["id"]},
            )
            db.commit()
        from app.workers.maintenance import run_maintenance

        assert run_maintenance(w.db_factory)["expired_upload_sessions"] >= 1
        assert admin.get(f"/api/v1/uploads/{s['id']}").json()["state"] == "expired"
        assert usage(admin)["reserved_bytes"] == 0
        assert admin.post(f"/api/v1/uploads/{s['id']}/finalize").status_code == 409

    def test_oversized_declaration_and_body_are_rejected(self, env):  # noqa: ANN001
        admin = env["admin"]
        assert (
            admin.post(
                f"/api/v1/folders/{env['folder']}/uploads",
                json={"filename": "big.pdf", "size_bytes": 10**10},
            ).status_code
            == 413
        )
        assert admin.post(
            f"/api/v1/folders/{env['folder']}/uploads", json={"filename": "z.pdf", "size_bytes": 0}
        ).status_code in (422,)


class TestQuota:
    def test_quota_exceeded_and_no_leak(self, env):  # noqa: ANN001
        admin = env["admin"]
        assert init(admin, env["folder"], "a.pdf", b"x" * 6000).status_code == 201
        r = init(admin, env["folder"], "b.pdf", b"x" * 6000)
        assert r.status_code == 409 and r.json()["error"]["code"] == "quota_exceeded"
        assert usage(admin)["reserved_bytes"] == 6000

    def test_concurrent_reservations_cannot_oversubscribe(self, world):  # noqa: ANN001
        from sqlalchemy import select

        from app.core.errors import QuotaExceededError
        from app.db.models import Organization
        from app.modules.quota import service as quota

        owner = world.org("Race", quota_bytes=1000)
        results: list[str] = []
        barrier = threading.Barrier(8)

        def worker() -> None:
            with world.db_factory() as db:
                barrier.wait()
                try:
                    quota.reserve(
                        db,
                        organization_id=owner.org_id,
                        upload_session_id=uuid.uuid4(),
                        size_bytes=300,
                    )
                    db.commit()
                    results.append("ok")
                except QuotaExceededError:
                    db.rollback()
                    results.append("denied")

        threads = [threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert results.count("ok") == 3 and results.count("denied") == 5  # 3*300 <= 1000 < 4*300
        with world.db_factory() as db:
            org = db.scalar(select(Organization).where(Organization.id == owner.org_id))
            assert org.quota_reserved_bytes == 900

    def test_ledger_is_idempotent_and_reconciles(self, world):  # noqa: ANN001
        from sqlalchemy import select

        from app.db.models import Organization
        from app.modules.quota import service as quota

        owner = world.org("Ledger", quota_bytes=10_000)
        sid = uuid.uuid4()
        with world.db_factory() as db:
            quota.reserve(db, organization_id=owner.org_id, upload_session_id=sid, size_bytes=500)
            quota.reserve(
                db, organization_id=owner.org_id, upload_session_id=sid, size_bytes=500
            )  # replay
            quota.release(
                db,
                organization_id=owner.org_id,
                upload_session_id=sid,
                reserved_bytes=500,
                reason="t",
            )
            quota.release(
                db,
                organization_id=owner.org_id,
                upload_session_id=sid,
                reserved_bytes=500,
                reason="t",
            )
            db.commit()
            assert (
                db.scalar(
                    select(Organization.quota_reserved_bytes).where(Organization.id == owner.org_id)
                )
                == 0
            )

    def test_reconcile_detects_and_fixes_drift(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        w.available_doc(admin, env["folder"], "r.pdf", PDF + b"reconcile")
        from app.modules.quota.service import reconcile

        with w.db_factory() as db:
            assert reconcile(db, admin.org_id)["drift_used_vs_versions"] == 0
            db.execute(
                text(
                    "UPDATE dms.organizations SET quota_used_bytes = quota_used_bytes + 77 WHERE id = :i"
                ),
                {"i": admin.org_id},
            )
            db.commit()
            assert reconcile(db, admin.org_id, fix=True)["drift_used_vs_versions"] == 77
            db.commit()
            assert reconcile(db, admin.org_id)["drift_used_vs_versions"] == 0


class TestScanAndQuarantine:
    def test_infected_upload_is_quarantined_and_never_served(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        doc = w.upload(admin, env["folder"], "malware.pdf", EICAR)
        w.process_jobs()
        d = admin.get(f"/api/v1/documents/{doc['document_id']}").json()
        assert d["status"] == "quarantined" and d["current_version"] is None
        assert admin.post(
            f"/api/v1/documents/{doc['document_id']}/download-url", json={}
        ).status_code in (403, 409)
        q = admin.get("/api/v1/admin/quarantine").json()
        assert q["total"] == 1 and q["items"][0]["scan_status"] == "infected"
        actions = {
            e["action"]
            for e in admin.get("/api/v1/admin/audit-events", params={"limit": 100}).json()["items"]
        }
        assert "document.quarantined" in actions
        notes = admin.get("/api/v1/notifications").json()["items"]
        assert any(n["type"] == "document.quarantined" for n in notes)

    def test_infected_new_version_never_replaces_the_good_one(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        doc_id = w.available_doc(admin, env["folder"], "v.pdf", PDF + b" v1")
        s = admin.post(
            f"/api/v1/documents/{doc_id}/uploads",
            json={"filename": "v.pdf", "size_bytes": len(EICAR), "expected_latest_version": 1},
        ).json()
        put(admin, s, EICAR)
        assert admin.post(f"/api/v1/uploads/{s['id']}/finalize").json()["version_number"] == 2
        w.process_jobs()
        d = admin.get(f"/api/v1/documents/{doc_id}").json()
        assert d["status"] == "available" and d["current_version"]["version_number"] == 1
        versions = admin.get(f"/api/v1/documents/{doc_id}/versions").json()
        assert {v["version_number"]: v["scan_status"] for v in versions} == {
            1: "clean",
            2: "infected",
        }

    def test_scanner_outage_keeps_file_unavailable_and_retries(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        from app.adapters.malware.base import ScannerUnavailableError
        from app.workers.runner import WorkerContext, build_context, run_once

        class Down:
            name = "down"

            def scan(self, chunks):  # noqa: ANN001, ANN201
                raise ScannerUnavailableError("scanner offline")

        doc = w.upload(admin, env["folder"], "wait.pdf", PDF + b" wait")
        base = build_context()
        run_once(ctx=WorkerContext(base.settings, Down(), base.email), factory=w.db_factory)
        d = admin.get(f"/api/v1/documents/{doc['document_id']}").json()
        assert d["status"] == "processing"  # fail closed
        with w.db_factory() as db:
            row = db.execute(
                text(
                    "SELECT status, attempts, last_error, next_attempt_at FROM dms.outbox_events WHERE aggregate_id = :i AND event_type = 'document_version.uploaded'"
                ),
                {"i": doc["version_id"]},
            ).one()
            assert row.status == "pending" and row.attempts == 1 and "offline" in row.last_error
            assert row.next_attempt_at > datetime.now(UTC)  # backoff scheduled
            db.execute(
                text(
                    "UPDATE dms.outbox_events SET next_attempt_at = now() WHERE aggregate_id = :i"
                ),
                {"i": doc["version_id"]},
            )
            db.commit()
        w.process_jobs()  # scanner is back
        assert admin.get(f"/api/v1/documents/{doc['document_id']}").json()["status"] == "available"

    def test_tampered_object_is_not_released(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        doc = w.upload(admin, env["folder"], "t.pdf", PDF + b" original")
        from pathlib import Path

        from app.core.config import get_settings

        base = Path(get_settings().local_storage_path) / "dms-test"
        target = next(
            p for p in base.rglob("*") if p.is_file() and p.read_bytes() == PDF + b" original"
        )
        target.write_bytes(PDF + b" tampered!")  # same-ish size, different bytes
        w.process_jobs()
        d = admin.get(f"/api/v1/documents/{doc['document_id']}").json()
        assert d["status"] == "failed" and d["current_version"] is None


class TestVersions:
    def test_new_versions_are_immutable_history_and_restore_makes_a_new_version(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        doc_id = w.available_doc(admin, env["folder"], "h.pdf", PDF + b" one")
        for n, body in ((2, PDF + b" two"), (3, PDF + b" three")):
            s = admin.post(
                f"/api/v1/documents/{doc_id}/uploads",
                json={
                    "filename": "h.pdf",
                    "size_bytes": len(body),
                    "expected_latest_version": n - 1,
                },
            ).json()
            put(admin, s, body)
            assert admin.post(f"/api/v1/uploads/{s['id']}/finalize").json()["version_number"] == n
            w.process_jobs()
        versions = admin.get(f"/api/v1/documents/{doc_id}/versions").json()
        assert [v["version_number"] for v in versions] == [3, 2, 1] and versions[0]["is_current"]
        r = admin.post(f"/api/v1/documents/{doc_id}/versions/1/restore")
        assert (
            r.status_code == 201
            and r.json()["version_number"] == 4
            and r.json()["restored_from_version_number"] == 1
        )
        w.process_jobs()
        d = admin.get(f"/api/v1/documents/{doc_id}").json()
        assert d["current_version"]["version_number"] == 4 and d["latest_version_number"] == 4
        # old versions remain downloadable with their own bytes
        url = admin.post(
            f"/api/v1/documents/{doc_id}/download-url", json={"version_number": 1}
        ).json()["url"]
        assert w.client.get(url.replace("http://testserver", "")).content == PDF + b" one"
        # restored version has its own object but the same content hash
        with w.db_factory() as db:
            rows = db.execute(
                text(
                    "SELECT version_number, object_key, sha256 FROM dms.document_versions WHERE document_id = :d ORDER BY 1"
                ),
                {"d": doc_id},
            ).all()
            assert len({r.object_key for r in rows}) == 4 and rows[0].sha256 == rows[3].sha256

    def test_database_blocks_mutation_of_version_content(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        doc_id = w.available_doc(admin, env["folder"], "imm.pdf", PDF + b" imm")
        from sqlalchemy.exc import DBAPIError

        with w.db_factory() as db:
            for sql in (
                "UPDATE dms.document_versions SET sha256 = repeat('a', 64) WHERE document_id = :d",
                "UPDATE dms.document_versions SET object_key = 'other' WHERE document_id = :d",
                "UPDATE dms.document_versions SET size_bytes = 1 WHERE document_id = :d",
                "UPDATE dms.document_versions SET version_number = 9 WHERE document_id = :d",
            ):
                with pytest.raises(DBAPIError):
                    db.execute(text(sql), {"d": doc_id})
                db.rollback()
            db.execute(
                text("UPDATE dms.document_versions SET scan_detail = 'ok' WHERE document_id = :d"),
                {"d": doc_id},
            )
            db.commit()  # scan metadata remains updatable

    def test_concurrent_version_uploads_never_silently_overwrite(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        doc_id = w.available_doc(admin, env["folder"], "race.pdf", PDF + b" race")
        sessions = []
        for i in range(2):
            body = PDF + f" racer{i}".encode()
            s = admin.post(
                f"/api/v1/documents/{doc_id}/uploads",
                json={
                    "filename": "race.pdf",
                    "size_bytes": len(body),
                    "expected_latest_version": 1,
                },
            )
            if s.status_code == 201:
                put(admin, s.json(), body)
                sessions.append(s.json())
        codes = [admin.post(f"/api/v1/uploads/{s['id']}/finalize").status_code for s in sessions]
        assert sorted(codes) == [200, 409]  # exactly one wins; the other is told to reload
        assert admin.get(f"/api/v1/documents/{doc_id}").json()["latest_version_number"] == 2

    def test_stale_expected_version_is_rejected_up_front(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        doc_id = w.available_doc(admin, env["folder"], "stale.pdf", PDF + b" stale")
        r = admin.post(
            f"/api/v1/documents/{doc_id}/uploads",
            json={"filename": "s.pdf", "size_bytes": 5, "expected_latest_version": 7},
        )
        assert r.status_code == 409 and r.json()["error"]["code"] == "stale_version"
        assert (
            admin.post(
                f"/api/v1/documents/{doc_id}/uploads", json={"filename": "s.pdf", "size_bytes": 5}
            ).status_code
            == 422
        )


class TestTreeRules:
    def test_rename_move_keep_identity_and_enforce_uniqueness(self, env):  # noqa: ANN001
        w, admin, root = env["world"], env["admin"], env["root"]
        a, b = w.mkdir(admin, root, "A"), w.mkdir(admin, root, "B")
        doc = w.available_doc(admin, a, "f.pdf", PDF + b" f")
        w.available_doc(admin, b, "f.pdf", PDF + b" f2")
        assert (
            admin.patch(f"/api/v1/documents/{doc}", json={"folder_id": b}).status_code == 409
        )  # name clash
        assert (
            admin.patch(f"/api/v1/documents/{doc}", json={"folder_id": b, "name": "g.pdf"}).json()[
                "id"
            ]
            == doc
        )
        assert (
            w.mkdir(admin, root, "dup")
            and admin.post(
                "/api/v1/folders", json={"parent_folder_id": root, "name": "DUP"}
            ).status_code
            == 409
        )
        assert (
            admin.post("/api/v1/folders", json={"parent_folder_id": root, "name": "A"}).status_code
            == 409
        )

    def test_folder_cycles_and_root_protection(self, env):  # noqa: ANN001
        w, admin, root = env["world"], env["admin"], env["root"]
        a = w.mkdir(admin, root, "A")
        b = w.mkdir(admin, a, "B")
        c = w.mkdir(admin, b, "C")
        assert admin.patch(f"/api/v1/folders/{a}", json={"parent_folder_id": c}).status_code == 422
        assert admin.patch(f"/api/v1/folders/{a}", json={"parent_folder_id": a}).status_code == 422
        assert admin.patch(f"/api/v1/folders/{root}", json={"name": "x"}).status_code == 403
        assert admin.delete(f"/api/v1/folders/{root}").status_code == 403
        assert (
            admin.patch(f"/api/v1/folders/{c}", json={"parent_folder_id": root}).status_code == 200
        )

    def test_trash_and_restore_whole_subtree_in_one_batch(self, env):  # noqa: ANN001
        w, admin, root = env["world"], env["admin"], env["root"]
        a = w.mkdir(admin, root, "Tree")
        b = w.mkdir(admin, a, "Branch")
        doc = w.available_doc(admin, b, "leaf.pdf", PDF + b" leaf")
        assert admin.delete(f"/api/v1/folders/{a}").status_code == 204
        assert admin.get(f"/api/v1/folders/{a}").status_code == 404
        assert admin.get(f"/api/v1/documents/{doc}").status_code == 404
        assert admin.post(f"/api/v1/documents/{doc}/download-url", json={}).status_code == 404
        trash = admin.get("/api/v1/trash").json()
        assert [i["name"] for i in trash["items"]] == ["Tree"]  # only the batch root is listed
        assert admin.post(f"/api/v1/folders/{b}/restore", json={}).status_code in (
            409,
            404,
        )  # parent still deleted
        assert admin.post(f"/api/v1/folders/{a}/restore", json={}).status_code == 200
        assert admin.get(f"/api/v1/documents/{doc}").status_code == 200
        assert admin.get("/api/v1/trash").json()["total"] == 0

    def test_restore_conflicts_offer_rename(self, env):  # noqa: ANN001
        w, admin, root = env["world"], env["admin"], env["root"]
        doc = w.available_doc(admin, root, "clash.pdf", PDF + b" 1")
        assert admin.delete(f"/api/v1/documents/{doc}").status_code == 204
        w.available_doc(admin, root, "clash.pdf", PDF + b" 2")
        r = admin.post(f"/api/v1/documents/{doc}/restore", json={})
        assert r.status_code == 409 and r.json()["error"]["code"] == "name_conflict"
        assert (
            admin.post(
                f"/api/v1/documents/{doc}/restore", json={"new_name": "clash (restored).pdf"}
            ).status_code
            == 200
        )

    def test_stars_and_recents_are_per_user_and_server_side(self, env):  # noqa: ANN001
        w, admin, root = env["world"], env["admin"], env["root"]
        doc = w.available_doc(admin, root, "s.pdf", PDF + b" star")
        assert admin.put(f"/api/v1/documents/{doc}/star").status_code == 204
        assert [i["id"] for i in admin.get("/api/v1/starred").json()["items"]] == [doc]
        assert admin.get(f"/api/v1/documents/{doc}").json()["starred"] is True
        other = w.user(admin, "admin", label="o")
        assert other.get("/api/v1/starred").json()["items"] == []
        assert admin.delete(f"/api/v1/documents/{doc}/star").status_code == 204
        assert admin.get("/api/v1/starred").json()["total"] == 0
        assert doc in [i["id"] for i in admin.get("/api/v1/recent").json()["items"]]

    def test_optimistic_concurrency_on_metadata_updates(self, env):  # noqa: ANN001
        w, admin, root = env["world"], env["admin"], env["root"]
        doc = w.available_doc(admin, root, "m.pdf", PDF + b" meta")
        d = admin.get(f"/api/v1/documents/{doc}").json()
        ok = admin.patch(
            f"/api/v1/documents/{doc}",
            json={"metadata": {"k": "v"}, "expected_row_version": d["row_version"]},
        )
        assert ok.status_code == 200 and ok.json()["metadata"] == {"k": "v"}
        stale = admin.patch(
            f"/api/v1/documents/{doc}",
            json={"metadata": {"k": "x"}, "expected_row_version": d["row_version"]},
        )
        assert stale.status_code == 409 and stale.json()["error"]["code"] == "stale_version"


class TestUnreleasedVersions:
    def test_pending_and_infected_versions_cannot_be_downloaded_by_number_or_ticket(self, env):  # noqa: ANN001
        from app.modules.documents.downloads import issue_ticket
        from app.modules.identity.principal import Principal

        w, admin = env["world"], env["admin"]
        doc_id = w.available_doc(admin, env["folder"], "rel.pdf", PDF + b" v1")
        pending_body, bad_body = PDF + b" pending", EICAR
        sess = []
        for n, body in ((1, pending_body), (2, bad_body)):
            s = admin.post(
                f"/api/v1/documents/{doc_id}/uploads",
                json={"filename": "rel.pdf", "size_bytes": len(body), "expected_latest_version": n},
            ).json()
            put(admin, s, body)
            sess.append(admin.post(f"/api/v1/uploads/{s['id']}/finalize").json())
            if n == 1:  # scan v2 (pending_body) only after v3 exists? keep v2 pending, scan later
                pass
        # v2 (clean content) and v3 (marker) exist but are not scanned yet -> pending
        for number in (2, 3):
            r = admin.post(f"/api/v1/documents/{doc_id}/download-url", json={"version_number": number})
            assert r.status_code == 409 and r.json()["error"]["code"] == "not_released"
        # a hand-made ticket for an unreleased version is refused at redemption time as well
        principal = Principal(admin.user_id, admin.email, None, admin.org_id, "owner")
        ticket, _ = issue_ticket(principal, uuid.UUID(doc_id), uuid.UUID(sess[0]["version_id"]), "attachment")
        assert w.client.get(f"/api/v1/downloads/{ticket}").status_code == 409
        w.process_jobs()
        infected = admin.post(f"/api/v1/documents/{doc_id}/download-url", json={"version_number": 3})
        assert infected.status_code == 409  # infected: still never served
        ticket, _ = issue_ticket(principal, uuid.UUID(doc_id), uuid.UUID(sess[1]["version_id"]), "attachment")
        assert w.client.get(f"/api/v1/downloads/{ticket}").status_code == 409
        assert admin.post(f"/api/v1/documents/{doc_id}/download-url", json={"version_number": 2}).status_code == 200


def test_unconfigured_scanner_leaves_files_unavailable(env):  # noqa: ANN001
    from app.adapters.malware.factory import UnconfiguredScanner
    from app.workers.runner import WorkerContext, build_context, run_once

    w, admin = env["world"], env["admin"]
    doc = w.upload(admin, env["folder"], "noscan.pdf", PDF + b" noscan")
    base = build_context()
    run_once(ctx=WorkerContext(base.settings, UnconfiguredScanner(), base.email), factory=w.db_factory)
    d = admin.get(f"/api/v1/documents/{doc['document_id']}").json()
    assert d["status"] == "processing" and d["current_version"] is None
    assert admin.post(f"/api/v1/documents/{doc['document_id']}/download-url", json={}).status_code == 409
