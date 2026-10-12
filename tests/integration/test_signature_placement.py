"""Choosing where the signature goes, the signing preview PDF, and conversion before signing."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from app.adapters.signatures.fake import FakeSignatureProvider
from app.db.models import SignatureRequest
from tests.integration import test_signatures as base

env = base.env
_fake_provider_state = base._fake_provider_state  # noqa: SLF001

pytestmark = pytest.mark.integration
API = "/api/v1"
BOX = {"page_number": 1, "page_x": 12.5, "page_y": 40.0, "page_width": 30.0, "page_height": 6.0}


def make_request(env, doc=None, **body):  # noqa: ANN001, ANN003, ANN202
    payload = {"signers": [{"email": env["carol"].email}], **body}
    return env["admin"].post(
        f"{API}/documents/{doc or env['doc']}/signature-requests", json=payload
    )


def provider_doc(env, request_id):  # noqa: ANN001, ANN202
    with env["world"].db_factory() as db:
        pid = db.scalar(
            select(SignatureRequest.provider_request_id).where(
                SignatureRequest.id == uuid.UUID(request_id)
            )
        )
    return FakeSignatureProvider._docs[pid]  # noqa: SLF001


# ---- preview ----------------------------------------------------------------------------------------
def test_preview_returns_the_exact_pdf_for_a_pdf_and_a_converted_pdf_for_text(env):  # noqa: ANN001
    a = env["admin"]
    r = a.get(f"{API}/documents/{env['doc']}/signature-preview-pdf")
    assert (
        r.status_code == 200
        and r.content.startswith(b"%PDF")
        and r.headers["cache-control"] == "no-store"
    )
    assert r.content == base.PDF + b" agreement"  # untouched
    txt = env["world"].available_doc(a, env["folder"], "notes.txt", b"hello signing world")
    t = a.get(f"{API}/documents/{txt}/signature-preview-pdf")
    assert (
        t.status_code == 200
        and t.content.startswith(b"%PDF")
        and b"hello signing world" not in t.content[:50]
    )
    # the original is not replaced by the signing copy
    orig = a.get(f"{API}/documents/{txt}").json()
    assert (
        orig["current_version"]["content_type"] != "application/pdf"
        and orig["latest_version_number"] == 1
    )


def test_preview_refuses_unsupported_files_without_creating_anything(env):  # noqa: ANN001
    a = env["admin"]
    weird = env["world"].available_doc(a, env["folder"], "data.xyz", b"\x00\x01 binary")
    r = a.get(f"{API}/documents/{weird}/signature-preview-pdf")
    assert r.status_code == 422 and r.json()["error"]["code"] == "conversion_failed"
    assert a.get(f"{API}/signature-requests").json()["total"] == 0


def test_preview_needs_the_same_rights_as_requesting_and_stays_in_the_tenant(env):  # noqa: ANN001
    assert (
        env["carol"].get(f"{API}/documents/{env['doc']}/signature-preview-pdf").status_code == 404
    )
    other = env["world"].org("Preview Other Co", member_default_access=False)
    assert other.get(f"{API}/documents/{env['doc']}/signature-preview-pdf").status_code == 404
    acts = {
        e["action"]
        for e in env["admin"].get(f"{API}/admin/audit-events", params={"limit": 50}).json()["items"]
    }
    env["admin"].get(f"{API}/documents/{env['doc']}/signature-preview-pdf")
    acts2 = {
        e["action"]
        for e in env["admin"].get(f"{API}/admin/audit-events", params={"limit": 50}).json()["items"]
    }
    assert "signature.preview_prepared" in acts2 and acts <= acts2


# ---- placement ----------------------------------------------------------------------------------------
def test_chosen_placement_is_stored_returned_and_given_to_the_provider(env):  # noqa: ANN001
    r = make_request(env, placement=BOX)
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["placement"] == BOX
    assert provider_doc(env, out["id"]).placement == BOX
    assert env["admin"].get(f"{API}/signature-requests/{out['id']}").json()["placement"] == BOX


def test_without_placement_the_default_spot_is_used_as_before(env):  # noqa: ANN001
    out = make_request(env).json()
    assert out["placement"] is None and provider_doc(env, out["id"]).placement is None


@pytest.mark.parametrize(
    "bad",
    [
        {**BOX, "page_number": 0},
        {**BOX, "page_x": -1},
        {**BOX, "page_width": 0},
        {**BOX, "page_x": 80, "page_width": 30},  # leaves the page
        {**BOX, "page_y": 99, "page_height": 5},
        {**BOX, "page_width": 150},
    ],
)
def test_invalid_boxes_are_rejected_before_anything_is_sent(env, bad):  # noqa: ANN001
    assert make_request(env, placement=bad).status_code == 422
    assert env["admin"].get(f"{API}/signature-requests").json()["total"] == 0


def test_a_page_that_does_not_exist_is_rejected(env):  # noqa: ANN001
    r = make_request(env, placement={**BOX, "page_number": 9})
    assert r.status_code == 422 and r.json()["error"]["code"] == "placement_invalid"


def test_placement_is_for_the_external_provider_only(env):  # noqa: ANN001
    r = make_request(env, placement=BOX, provider="builtin")
    assert r.status_code == 422 and r.json()["error"]["code"] == "placement_not_supported"


# ---- conversion before signing --------------------------------------------------------------------------
def test_a_text_file_is_signed_as_a_pdf_copy_and_the_signed_result_is_a_new_pdf_version(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    txt = w.available_doc(a, env["folder"], "contract.txt", b"Terms and conditions apply.")
    out = make_request(env, doc=txt, placement=BOX).json()
    d = provider_doc(env, out["id"])
    assert d.content.startswith(b"%PDF")  # the provider got the converted copy
    rid = next(k for k, v in FakeSignatureProvider._docs.items() if v is d)  # noqa: SLF001
    FakeSignatureProvider.sign(rid, env["carol"].email)
    base.deliver(env, rid, "DOCUMENT_COMPLETED")
    w.process_jobs()
    final = a.get(f"{API}/signature-requests/{out['id']}").json()
    assert final["state"] == "completed" and final["artifact"]["version_number"] == 2
    versions = a.get(f"{API}/documents/{txt}/versions").json()
    by = {
        v["version_number"]: v
        for v in (versions if isinstance(versions, list) else versions["items"])
    }
    assert (
        by[1]["content_type"] != "application/pdf" and by[1]["original_filename"] == "contract.txt"
    )
    assert (
        by[2]["content_type"] == "application/pdf"
        and by[2]["original_filename"] == "contract (signed).pdf"
    )


def test_image_documents_can_be_sent_for_signature(env):  # noqa: ANN001
    import io

    from PIL import Image

    out = io.BytesIO()
    Image.new("RGB", (80, 40), (20, 20, 200)).save(out, "PNG")
    up = env["world"].upload(
        env["admin"], env["folder"], "scan.png", out.getvalue(), content_type="image/png"
    )
    env["world"].process_jobs()
    r = make_request(env, doc=up["document_id"])
    assert r.status_code == 201, r.text
    assert provider_doc(env, r.json()["id"]).content.startswith(b"%PDF")
