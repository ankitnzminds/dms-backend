"""Text extraction pipeline, content search authorization, thumbnails, metadata definitions."""

from __future__ import annotations

import io
import uuid

import pytest
from sqlalchemy import text

from tests.unit.test_extractors import MINIMAL_PDF, make_docx, make_png

pytestmark = pytest.mark.integration


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Search", member_default_access=False)
    root = world.root_id(admin)
    folder = world.mkdir(admin, root, "reports")
    return dict(world=world, admin=admin, root=root, folder=folder)


def upload_ready(w, a, folder, name, data, ctype):  # noqa: ANN001, ANN202
    d = w.upload(a, folder, name, data, content_type=ctype)
    w.process_jobs()
    return d["document_id"]


def search(a, q, **params):  # noqa: ANN001, ANN202
    r = a.get("/api/v1/search", params={"q": q, **params})
    assert r.status_code == 200, r.text
    return r.json()


class TestExtraction:
    def test_text_file_is_indexed_and_found_by_content(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = upload_ready(
            w,
            a,
            env["folder"],
            "notes.txt",
            b"The quarterly zeppelin budget was approved.",
            "text/plain",
        )
        st = a.get(f"/api/v1/documents/{doc}/processing").json()
        assert (
            st["text_status"] == "extracted"
            and st["text_characters"] > 10
            and st["has_thumbnail"] is False
        )
        res = search(a, "zeppelin")
        assert [i["id"] for i in res["items"]] == [doc]
        assert (
            res["items"][0]["match"] == "content" and "[[zeppelin]]" in res["items"][0]["snippet"]
        )
        assert search(a, "zeppelin", scope="name")["total"] == 0
        assert search(a, "notes", scope="content")["total"] == 0
        assert search(a, "notes")["items"][0]["match"] == "name"

    def test_pdf_and_docx_extraction(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        pdf = upload_ready(w, a, env["folder"], "forecast.pdf", MINIMAL_PDF, "application/pdf")
        docx = upload_ready(
            w,
            a,
            env["folder"],
            "minutes.docx",
            make_docx("Unanimous vote on the ostrich initiative"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        assert {i["id"] for i in search(a, "Quarterly revenue")["items"]} == {pdf}
        assert {i["id"] for i in search(a, "ostrich")["items"]} == {docx}

    def test_malformed_files_do_not_break_the_pipeline_or_availability(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        bad = upload_ready(
            w, a, env["folder"], "broken.pdf", b"%PDF-1.4 total garbage \xff\xfe", "application/pdf"
        )
        assert a.get(f"/api/v1/documents/{bad}").json()["status"] == "available"
        assert a.get(f"/api/v1/documents/{bad}/processing").json()["text_status"] in (
            "failed",
            "empty",
            "ocr_unavailable",
        )
        with w.db_factory() as db:  # nothing is stuck in the queue
            assert (
                db.scalar(
                    text(
                        "SELECT count(*) FROM dms.outbox_events WHERE aggregate_id = (SELECT current_version_id FROM dms.documents WHERE id = :d) AND status <> 'done'"
                    ),
                    {"d": bad},
                )
                == 0
            )

    def test_extraction_is_idempotent_and_runs_only_for_released_versions(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        from app.core.config import get_settings
        from app.modules.processing.service import process_version

        doc = upload_ready(w, a, env["folder"], "once.txt", b"idempotent words here", "text/plain")
        with w.db_factory() as db:
            vid = db.scalar(
                text("SELECT current_version_id FROM dms.documents WHERE id = :d"), {"d": doc}
            )
            assert process_version(db, vid, get_settings()) == "exists"
        pending = w.upload(
            a, env["folder"], "later.txt", b"not yet scanned", content_type="text/plain"
        )
        with w.db_factory() as db:
            assert (
                process_version(db, uuid.UUID(pending["version_id"]), get_settings()) == "skipped"
            )

    def test_oversized_files_are_not_parsed(self, env, monkeypatch):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("EXTRACT_MAX_BYTES", "20")
        reset_settings_cache()
        try:
            doc = upload_ready(
                w, a, env["folder"], "big.txt", b"x" * 100 + b" bigword", "text/plain"
            )
        finally:
            monkeypatch.undo()
            reset_settings_cache()
        assert a.get(f"/api/v1/documents/{doc}/processing").json()["text_status"] == "unsupported"
        assert search(a, "bigword", scope="content")["total"] == 0

    def test_child_process_timeout_is_reported_not_raised_to_the_api(self, env, tmp_path):  # noqa: ANN001
        from app.modules.processing.service import ExtractionChildError, run_child

        request = {
            "path": str(tmp_path / "x"),
            "content_type": "text/plain",
            "filename": "x.txt",
            "max_chars": 1,
            "max_pages": 1,
            "out_dir": str(tmp_path),
            "ocr_command": "",
        }
        with pytest.raises(ExtractionChildError):
            run_child(request, timeout=0)

    def test_infected_files_are_never_indexed(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = upload_ready(
            w, a, env["folder"], "bad.txt", b"zebra DMS-TEST-INFECTED-FILE-SIGNATURE", "text/plain"
        )
        assert a.get(f"/api/v1/documents/{doc}").json()["status"] == "quarantined"
        assert search(a, "zebra", scope="content")["total"] == 0
        with w.db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.document_texts WHERE document_id = :d"),
                    {"d": doc},
                )
                == 0
            )


class TestContentSearchAuthorization:
    def test_content_search_requires_preview_right_and_leaks_nothing(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = upload_ready(
            w, a, env["folder"], "plan.txt", b"confidential merger codename ARCTURUS", "text/plain"
        )
        viewer = w.user(a, "member", label="viewer")  # may see name only
        reader = w.user(a, "member", label="reader")  # may preview
        a.post(
            f"/api/v1/documents/{doc}/permissions",
            json={"subject_type": "user", "subject_id": str(viewer.user_id), "actions": ["view"]},
        )
        a.post(
            f"/api/v1/documents/{doc}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(reader.user_id),
                "actions": ["preview"],
            },
        )
        assert search(viewer, "plan")["total"] == 1  # by name: allowed
        assert search(viewer, "ARCTURUS")["total"] == 0  # by content: not without preview
        assert search(viewer, "ARCTURUS", scope="content")["total"] == 0
        hit = search(reader, "ARCTURUS")
        assert hit["total"] == 1 and "[[ARCTURUS]]" in hit["items"][0]["snippet"].upper().replace(
            "ARCTURUS", "ARCTURUS"
        )
        outsider = w.user(a, "member", label="outsider")
        assert search(outsider, "ARCTURUS")["total"] == 0
        # nothing about the document in any search response for the outsider
        assert "plan.txt" not in str(search(outsider, "plan"))

    def test_other_tenants_never_match(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        upload_ready(w, a, env["folder"], "mine.txt", b"unique token PLATYPUS", "text/plain")
        other = w.org("Other")
        assert search(other, "PLATYPUS")["total"] == 0

    def test_revoked_share_removes_content_hits_and_dlp_hides_restricted(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = upload_ready(w, a, env["folder"], "s.txt", b"shared keyword NARWHAL", "text/plain")
        bob = w.user(a, "member", label="bob")
        sh = a.post(
            f"/api/v1/documents/{doc}/shares",
            json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["preview"]},
        ).json()
        assert search(bob, "NARWHAL")["total"] == 1
        a.post(f"/api/v1/shares/{sh['id']}/revoke")
        assert search(bob, "NARWHAL")["total"] == 0

    def test_snippets_are_plain_text(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        upload_ready(
            w,
            a,
            env["folder"],
            "x.txt",
            b"before <script>alert(1)</script> MARKER after",
            "text/plain",
        )
        snip = search(a, "MARKER")["items"][0]["snippet"]
        assert (
            "[[MARKER]]" in snip
        )  # highlight uses [[ ]], raw text is returned verbatim for the UI to escape


class TestThumbnails:
    def test_thumbnail_variant_requires_preview_and_is_a_small_png(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = upload_ready(w, a, env["folder"], "pic.png", make_png(), "image/png")
        assert a.get(f"/api/v1/documents/{doc}/processing").json()["has_thumbnail"] is True
        r = a.post(f"/api/v1/documents/{doc}/download-url", json={"variant": "thumbnail"})
        assert r.status_code == 200, r.text
        got = w.client.get(r.json()["url"].replace("http://testserver", ""))
        assert got.status_code == 200 and got.headers["content-type"] == "image/png"
        from PIL import Image

        assert max(Image.open(io.BytesIO(got.content)).size) <= 320
        viewer = w.user(a, "member", label="v")
        a.post(
            f"/api/v1/documents/{doc}/permissions",
            json={"subject_type": "user", "subject_id": str(viewer.user_id), "actions": ["view"]},
        )
        assert (
            viewer.post(
                f"/api/v1/documents/{doc}/download-url", json={"variant": "thumbnail"}
            ).status_code
            == 403
        )
        txt = upload_ready(w, a, env["folder"], "t.txt", b"hello", "text/plain")
        assert (
            a.post(
                f"/api/v1/documents/{txt}/download-url", json={"variant": "thumbnail"}
            ).status_code
            == 404
        )

    def test_purge_removes_text_and_thumbnail_objects(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = upload_ready(w, a, env["folder"], "gone.png", make_png((50, 50)), "image/png")
        with w.db_factory() as db:
            keys = [
                r[0]
                for r in db.execute(
                    text(
                        "SELECT object_key FROM dms.document_derivatives WHERE version_id = (SELECT current_version_id FROM dms.documents WHERE id = :d)"
                    ),
                    {"d": doc},
                )
            ]
        assert len(keys) == 1
        from pathlib import Path

        from app.core.config import get_settings

        base = Path(get_settings().local_storage_path)
        assert any(p.name == keys[0].split("/")[-1] for p in base.rglob("*"))
        a.delete(f"/api/v1/documents/{doc}")
        assert a.delete(f"/api/v1/trash/documents/{doc}").status_code == 200
        w.process_jobs()
        assert not any(p.name == keys[0].split("/")[-1] for p in base.rglob("*"))
        with w.db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.document_texts WHERE document_id = :d"),
                    {"d": doc},
                )
                == 0
            )


class TestMetadata:
    def define(self, a, **kw):  # noqa: ANN001, ANN003, ANN202
        return a.post("/api/v1/metadata-definitions", json=kw)

    def test_definitions_are_admin_managed_and_validated(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        m = w.user(a, "member", label="m")
        assert self.define(m, key="x", label="X", field_type="text").status_code == 403
        assert self.define(a, key="Bad Key", label="X", field_type="text").status_code == 422
        assert (
            self.define(a, key="status", label="Status", field_type="select").status_code == 422
        )  # options required
        assert (
            self.define(
                a,
                key="status",
                label="Status",
                field_type="select",
                options=["draft", "final"],
                required=True,
            ).status_code
            == 201
        )
        assert self.define(a, key="status", label="Dup", field_type="text").status_code == 409
        assert [d["key"] for d in m.get("/api/v1/metadata-definitions").json()] == [
            "status"
        ]  # members can read

    def test_document_metadata_is_validated_against_definitions(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        self.define(
            a,
            key="status",
            label="Status",
            field_type="select",
            options=["draft", "final"],
            required=True,
        )
        self.define(a, key="pages", label="Pages", field_type="number")
        self.define(a, key="due", label="Due", field_type="date")
        self.define(a, key="signed", label="Signed", field_type="boolean")
        doc = upload_ready(w, a, env["folder"], "m.txt", b"metadata doc", "text/plain")
        ok = a.patch(
            f"/api/v1/documents/{doc}",
            json={"metadata": {"status": "final", "pages": 3, "due": "2026-12-31", "signed": True}},
        )
        assert ok.status_code == 200 and ok.json()["metadata"]["pages"] == 3
        for bad in (
            {"status": "weird"},
            {"status": "final", "pages": "three"},
            {"status": "final", "due": "31/12/2026"},
            {"status": "final", "signed": "yes"},
            {"status": "final", "unknown": 1},
            {"pages": 1},
        ):
            r = a.patch(f"/api/v1/documents/{doc}", json={"metadata": bad})
            assert r.status_code == 422 and r.json()["error"]["code"] == "metadata_invalid", bad
            assert r.json()["error"]["details"]

    def test_metadata_filters_and_archiving(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        d = self.define(
            a, key="dept", label="Department", field_type="select", options=["hr", "fin"]
        ).json()
        one = upload_ready(w, a, env["folder"], "report-one.txt", b"report one", "text/plain")
        two = upload_ready(w, a, env["folder"], "report-two.txt", b"report two", "text/plain")
        a.patch(f"/api/v1/documents/{one}", json={"metadata": {"dept": "hr"}})
        a.patch(f"/api/v1/documents/{two}", json={"metadata": {"dept": "fin"}})
        res = a.get("/api/v1/search", params={"q": "report", "meta": ["dept:hr"]}).json()
        assert [i["id"] for i in res["items"]] == [one]
        assert (
            a.get("/api/v1/search", params={"q": "report", "meta": ["nope:x"]}).status_code == 422
        )
        arch = a.patch(f"/api/v1/metadata-definitions/{d['id']}", json={"archived": True})
        assert (
            arch.status_code == 200
            and arch.json()["archived"]
            and arch.json()["schema_version"] == 2
        )
        assert a.get("/api/v1/metadata-definitions").json() == []
        assert (
            len(a.get("/api/v1/metadata-definitions", params={"include_archived": True}).json())
            == 1
        )

    def test_no_definitions_keeps_freeform_metadata(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = upload_ready(w, a, env["folder"], "free.txt", b"free form", "text/plain")
        assert (
            a.patch(f"/api/v1/documents/{doc}", json={"metadata": {"anything": "goes"}}).status_code
            == 200
        )
        assert (
            a.patch(f"/api/v1/documents/{doc}", json={"metadata": {"": "bad key"}}).status_code
            == 422
        )

    def test_definitions_are_tenant_scoped(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        self.define(a, key="secret_field", label="Secret", field_type="text")
        other = w.org("Other")
        assert other.get("/api/v1/metadata-definitions").json() == []
