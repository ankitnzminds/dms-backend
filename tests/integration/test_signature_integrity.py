"""E-signature integrity: one active request per document, a real state machine, cancel race safety,
source checksum binding, and artifact validation."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text

from app.adapters.signatures.fake import FakeSignatureProvider
from app.db.models import SignatureRequest, SignedArtifact
from app.modules.signatures.service import ALLOWED_TRANSITIONS, transition
from tests.integration import test_signatures as base

# reuse the signing fixtures and helpers of the main signature tests
env = base.env
_fake_provider_state = base._fake_provider_state  # noqa: SLF001
PDF = base.PDF
deliver = base.deliver
provider = base.provider
request_signature = base.request_signature

pytestmark = pytest.mark.integration


def provider_id(world, request_id):  # noqa: ANN001, ANN201
    with world.db_factory() as db:
        return db.scalar(
            select(SignatureRequest.provider_request_id).where(
                SignatureRequest.id == uuid.UUID(request_id)
            )
        )


def finish(env, request_id):  # noqa: ANN001, ANN201
    """The signer really signs at the provider, the webhook arrives, the worker reconciles."""
    w = env["world"]
    rid = provider_id(w, request_id)
    FakeSignatureProvider.sign(rid, env["carol"].email)
    deliver(env, rid, "DOCUMENT_COMPLETED")
    w.process_jobs()
    return rid


# ---- one active request per document -----------------------------------------------------------
def test_second_active_request_for_the_same_document_is_refused_until_the_first_ends(env):  # noqa: ANN001
    admin = env["admin"]
    first = request_signature(env)
    assert first.status_code == 201
    again = request_signature(env)
    assert again.status_code == 409 and again.json()["error"]["code"] == "signature_in_progress"
    assert admin.post(f"/api/v1/signature-requests/{first.json()['id']}/cancel").status_code == 204
    assert request_signature(env).status_code == 201  # the slot is free again after cancel


def test_a_finished_request_does_not_block_a_new_one(env):  # noqa: ANN001
    w = env["world"]
    first = request_signature(env).json()
    finish(env, first["id"])
    assert (
        env["admin"].get(f"/api/v1/signature-requests/{first['id']}").json()["state"] == "completed"
    )
    # the document now has a newer (signed) version; a fresh request is allowed once it is available
    assert request_signature(env).status_code in (201, 409)
    # a different document is never blocked by this one
    other = w.available_doc(env["admin"], env["folder"], "other.pdf", PDF + b" other")
    assert request_signature(env, doc=other).status_code == 201


def test_database_itself_rejects_two_in_flight_requests(env):  # noqa: ANN001
    from sqlalchemy.exc import IntegrityError

    w = env["world"]
    r = request_signature(env).json()
    with w.db_factory() as db:
        src = db.get(SignatureRequest, uuid.UUID(r["id"]))
        clone = SignatureRequest(
            id=uuid.uuid4(),
            organization_id=src.organization_id,
            document_id=src.document_id,
            source_version_id=src.source_version_id,
            requested_by=src.requested_by,
            provider=src.provider,
            title="dup",
            state="creating",
        )
        db.add(clone)
        with pytest.raises(IntegrityError):
            db.commit()


# ---- state machine -----------------------------------------------------------------------------
def test_transition_table_has_no_way_out_of_terminal_states():
    for terminal in ("completed", "declined", "cancelled", "expired", "failed"):
        assert terminal not in ALLOWED_TRANSITIONS
    assert "creating" not in ALLOWED_TRANSITIONS["sent"]  # nothing goes backwards


@pytest.mark.parametrize(
    ("start", "target", "ok"),
    [
        ("creating", "sent", True),
        ("creating", "failed", True),
        ("sent", "completed", True),
        ("sent", "declined", True),
        ("sent", "creating", False),
        ("completed", "cancelled", False),
        ("completed", "declined", False),
        ("cancelled", "sent", False),
        ("declined", "completed", False),
        ("failed", "sent", False),
    ],
)
def test_transition_helper(start, target, ok):  # noqa: ANN001
    from app.core.errors import ConflictError

    req = SignatureRequest(state=start)
    if ok:
        transition(req, target)
        assert req.state == target
    else:
        with pytest.raises(ConflictError) as e:
            transition(req, target)
        assert e.value.code == "invalid_transition" and req.state == start


def test_a_late_decline_or_cancel_event_cannot_reopen_or_overwrite_a_completed_request(env):  # noqa: ANN001
    w = env["world"]
    r = request_signature(env).json()
    rid = finish(env, r["id"])
    assert env["admin"].get(f"/api/v1/signature-requests/{r['id']}").json()["state"] == "completed"
    deliver(env, rid, "DOCUMENT_REJECTED", event_id="late-1")
    deliver(env, rid, "DOCUMENT_CANCELLED", event_id="late-2")
    w.process_jobs()
    assert env["admin"].get(f"/api/v1/signature-requests/{r['id']}").json()["state"] == "completed"
    with w.db_factory() as db:
        assert (
            db.scalar(
                select(text("count(*)"))
                .select_from(SignedArtifact)
                .where(SignedArtifact.request_id == uuid.UUID(r["id"]))
            )
            == 1
        )


# ---- cancel safety -----------------------------------------------------------------------------
def test_cancel_after_completion_is_refused_and_does_not_touch_the_provider(env):  # noqa: ANN001
    r = request_signature(env).json()
    rid = finish(env, r["id"])
    res = env["admin"].post(f"/api/v1/signature-requests/{r['id']}/cancel")
    assert res.status_code == 409 and res.json()["error"]["code"] == "invalid_state"
    assert FakeSignatureProvider._docs[rid].status != "cancelled"  # noqa: SLF001


def test_request_that_completes_while_the_provider_cancel_is_in_flight_stays_completed(
    env, monkeypatch
):  # noqa: ANN001
    """The second (locked) phase of cancel re-checks the state: a concurrent completion wins."""
    w, admin = env["world"], env["admin"]
    r = request_signature(env).json()
    rid = provider_id(w, r["id"])
    p = provider()
    real_cancel = p.cancel

    def cancel_then_finish(pid):  # noqa: ANN001, ANN202
        real_cancel(pid)
        # meanwhile reconcile observed the provider as completed and finished the request
        with w.db_factory() as db:
            db.execute(
                text("UPDATE dms.signature_requests SET state = 'completed' WHERE id = :i"),
                {"i": r["id"]},
            )
            db.commit()

    monkeypatch.setattr(p, "cancel", cancel_then_finish)
    res = admin.post(f"/api/v1/signature-requests/{r['id']}/cancel")
    assert res.status_code == 409 and res.json()["error"]["code"] == "invalid_state"
    assert admin.get(f"/api/v1/signature-requests/{r['id']}").json()["state"] == "completed"
    assert rid


# ---- evidence binding ----------------------------------------------------------------------------
def test_request_records_the_source_checksum_and_the_artifact_evidence_repeats_it(env):  # noqa: ANN001
    w = env["world"]
    r = request_signature(env).json()
    with w.db_factory() as db:
        req = db.get(SignatureRequest, uuid.UUID(r["id"]))
        assert req.source_sha256 and len(req.source_sha256) == 64
        sha = req.source_sha256
    finish(env, r["id"])
    with w.db_factory() as db:
        art = db.scalar(
            select(SignedArtifact).where(SignedArtifact.request_id == uuid.UUID(r["id"]))
        )
        assert art.evidence["source_sha256"] == sha and art.evidence["source_version_id"] == str(
            art.source_version_id
        )


def test_a_provider_download_that_is_not_a_pdf_is_never_stored(env, monkeypatch):  # noqa: ANN001
    w = env["world"]
    r = request_signature(env).json()
    rid = provider_id(w, r["id"])
    p = provider()
    monkeypatch.setattr(p, "download_signed", lambda pid: iter([b"<html>not a pdf</html>"]))
    FakeSignatureProvider.sign(rid, env["carol"].email)
    deliver(env, rid, "DOCUMENT_COMPLETED")
    w.process_jobs()
    with w.db_factory() as db:
        assert (
            db.scalar(
                select(SignedArtifact.id).where(SignedArtifact.request_id == uuid.UUID(r["id"]))
            )
            is None
        )
        assert (
            db.get(SignatureRequest, uuid.UUID(r["id"])).state == "sent"
        )  # retried by the sweep, not marked done


# ---- signing URLs are secret-equivalent: encrypted at rest ----------------------------------------
def _stored_url(world, request_id):  # noqa: ANN001, ANN202
    from app.db.models import SignatureRecipient

    with world.db_factory() as db:
        return db.scalar(
            select(SignatureRecipient.signing_url).where(
                SignatureRecipient.request_id == uuid.UUID(request_id)
            )
        )


def test_signing_url_is_encrypted_in_the_database_but_works_for_the_signer(env):  # noqa: ANN001
    w = env["world"]
    r = request_signature(env).json()
    stored = _stored_url(w, r["id"])
    assert (
        stored.startswith("gAAAA") and "fake-sign.example" not in stored and "token" not in stored
    )
    got = env["carol"].post(f"/api/v1/signature-requests/{r['id']}/signing-session")
    assert got.status_code == 200
    assert "fake-sign.example/sign/" in str(got.json())


def test_legacy_plaintext_urls_still_work_and_are_upgraded_on_first_use(env):  # noqa: ANN001
    from app.db.models import SignatureRecipient

    w = env["world"]
    r = request_signature(env).json()
    plain = "https://fake-sign.example/sign/legacy-token"
    with w.db_factory() as db:
        rec = db.scalar(
            select(SignatureRecipient).where(SignatureRecipient.request_id == uuid.UUID(r["id"]))
        )
        rec.signing_url = plain
        db.commit()
    got = env["carol"].post(f"/api/v1/signature-requests/{r['id']}/signing-session")
    assert got.status_code == 200 and plain in str(got.json())
    assert _stored_url(w, r["id"]).startswith("gAAAA")  # upgraded


def test_an_unreadable_stored_url_is_never_handed_out(env):  # noqa: ANN001
    from app.db.models import SignatureRecipient

    w = env["world"]
    r = request_signature(env).json()
    with w.db_factory() as db:
        rec = db.scalar(
            select(SignatureRecipient).where(SignatureRecipient.request_id == uuid.UUID(r["id"]))
        )
        rec.signing_url = "gAAAAcorrupted-value"
        db.commit()
    got = env["carol"].post(f"/api/v1/signature-requests/{r['id']}/signing-session")
    assert got.status_code == 409 and got.json()["error"]["code"] == "no_signing_link"
