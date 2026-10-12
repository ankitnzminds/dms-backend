"""Built-in signing: typed-name consent recorded in the DMS (no external provider)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text

from app.db.models import SignatureRecipient, SignatureRequest
from tests.integration import test_signatures as base

env = base.env
_fake_provider_state = base._fake_provider_state  # noqa: SLF001
PDF = base.PDF

pytestmark = pytest.mark.integration
API = "/api/v1"


def statement(actor):  # noqa: ANN001, ANN202
    return actor.get(f"{API}/signature-statement").json()


def request_builtin(env, signers=None, actor=None, doc=None):  # noqa: ANN001, ANN202
    signers = signers or [{"email": env["carol"].email, "name": "Carol"}]
    return (actor or env["admin"]).post(
        f"{API}/documents/{doc or env['doc']}/signature-requests",
        json={"signers": signers, "provider": "builtin", "message": "please sign"},
    )


def sign_body(actor, **over):  # noqa: ANN001, ANN003, ANN202
    st = statement(actor)
    body = {"agreed": True, "statement_version": st["version"], "typed_name": "Carol Example"}
    body.update(over)
    return body


def sign(actor, rid, **over):  # noqa: ANN001, ANN003, ANN202
    return actor.post(f"{API}/signature-requests/{rid}/sign", json=sign_body(actor, **over))


def state(env, rid):  # noqa: ANN001, ANN202
    return env["admin"].get(f"{API}/signature-requests/{rid}").json()["state"]


def test_capabilities_advertise_builtin_and_statement_is_versioned(env):  # noqa: ANN001
    caps = env["admin"].get(f"{API}/signature-capabilities").json()
    assert caps["builtin_available"] is True
    st = statement(env["carol"])
    assert (
        st["version"]
        and "electronic signature" in st["text"]
        and "not a cryptographic" in st["text"]
    )


def test_create_is_sent_immediately_binds_the_exact_version_and_notifies_the_signer(env):  # noqa: ANN001
    w = env["world"]
    r = request_builtin(env)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["provider"] == "builtin" and body["state"] == "sent"
    assert [s["status"] for s in body["signers"]] == ["pending"]
    with w.db_factory() as db:
        req = db.get(SignatureRequest, uuid.UUID(body["id"]))
        assert req.provider_request_id is None and req.source_sha256 and req.source_version_id
    assert (
        env["carol"].get(f"{API}/signature-requests/{body['id']}").json()["my_signing_available"]
        is True
    )
    w.process_jobs()
    notes = env["carol"].get(f"{API}/notifications").json()["items"]
    assert any(n["type"] == "signature.requested" for n in notes)


def test_builtin_is_internal_only_and_default_provider_behaviour_is_unchanged(env):  # noqa: ANN001
    r = request_builtin(env, [{"email": "outsider@example.org"}])
    assert r.status_code == 422 and r.json()["error"]["code"] == "builtin_internal_only"
    # no provider given -> the configured external provider, exactly as before
    assert base.request_signature(env).json()["provider"] == "fake"


def test_any_file_type_can_be_signed_built_in_not_only_pdf(env):  # noqa: ANN001
    w, admin = env["world"], env["admin"]
    up = w.upload(
        admin,
        env["folder"],
        "memo.docx",
        b"PK\x03\x04 pretend docx " + uuid.uuid4().bytes,
        content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    w.process_jobs()
    r = request_builtin(env, doc=up["document_id"])
    assert r.status_code == 201, r.text


def test_signing_requires_consent_current_statement_and_a_typed_name(env):  # noqa: ANN001
    rid = request_builtin(env).json()["id"]
    carol = env["carol"]
    r = sign(carol, rid, agreed=False)
    assert r.status_code == 422 and r.json()["error"]["code"] == "consent_required"
    r = sign(carol, rid, statement_version="old-version")
    assert r.status_code == 422 and r.json()["error"]["code"] == "statement_outdated"
    r = sign(carol, rid, typed_name="   ")
    assert r.status_code == 422
    assert state(env, rid) == "sent"  # nothing happened


def test_only_the_assigned_signer_can_sign_decline_or_read_the_document(env):  # noqa: ANN001
    w, admin = env["world"], env["admin"]
    rid = request_builtin(env).json()["id"]
    stranger = w.user(admin, "member", label="stranger")
    other_org = w.org("Other Sign Co", member_default_access=False)
    for actor in (
        stranger,
        admin,
        other_org,
    ):  # a stranger, the requester (not a signer), another tenant
        assert sign(actor, rid).status_code == 404
        assert actor.post(f"{API}/signature-requests/{rid}/decline", json={}).status_code == 404
        assert actor.get(f"{API}/signature-requests/{rid}/document").status_code == 404
    assert state(env, rid) == "sent"


def test_successful_signing_records_evidence_completes_and_is_final(env):  # noqa: ANN001
    w, carol = env["world"], env["carol"]
    rid = request_builtin(env).json()["id"]
    assert sign(carol, rid).status_code == 204
    assert state(env, rid) == "completed"
    with w.db_factory() as db:
        rec = db.scalar(
            select(SignatureRecipient).where(SignatureRecipient.request_id == uuid.UUID(rid))
        )
        req = db.get(SignatureRequest, uuid.UUID(rid))
        ev = rec.evidence
    assert rec.status == "signed" and rec.signed_at and req.completed_at
    assert ev["method"] == "builtin_typed_name_consent" and ev["typed_name"] == "Carol Example"
    assert (
        ev["source_version_id"] == str(req.source_version_id)
        and ev["source_sha256"] == req.source_sha256
    )
    assert (
        ev["statement_version"] == statement(carol)["version"] and len(ev["statement_sha256"]) == 64
    )
    assert ev["signer_email"] == carol.email and ev["client"]["ip"] is not None
    # final: no second signature, no decline, no cancel
    again = sign(carol, rid)
    assert again.status_code == 409
    assert carol.post(f"{API}/signature-requests/{rid}/decline", json={}).status_code == 409
    assert env["admin"].post(f"{API}/signature-requests/{rid}/cancel").status_code == 409
    actions = {
        e["action"]
        for e in env["admin"]
        .get(f"{API}/admin/audit-events", params={"limit": 100})
        .json()["items"]
    }
    assert {"signature.requested", "signature.recipient_signed", "signature.completed"} <= actions
    w.process_jobs()
    assert any(
        n["type"] == "signature.completed"
        for n in env["admin"].get(f"{API}/notifications").json()["items"]
    )


def test_client_info_can_be_switched_off(env, monkeypatch):  # noqa: ANN001
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "signature_record_client_info", False)
    w = env["world"]
    rid = request_builtin(env).json()["id"]
    assert sign(env["carol"], rid).status_code == 204
    with w.db_factory() as db:
        ev = db.scalar(
            select(SignatureRecipient.evidence).where(
                SignatureRecipient.request_id == uuid.UUID(rid)
            )
        )
    assert "client" not in ev


def test_request_completes_only_when_every_signer_has_signed(env):  # noqa: ANN001
    w, admin = env["world"], env["admin"]
    dave = w.user(admin, "member", label="dave")
    rid = request_builtin(env, [{"email": env["carol"].email}, {"email": dave.email}]).json()["id"]
    assert sign(env["carol"], rid).status_code == 204
    assert state(env, rid) == "sent"  # waiting for dave
    assert sign(dave, rid, typed_name="Dave").status_code == 204
    assert state(env, rid) == "completed"


def test_decline_is_separate_final_and_declines_the_request(env):  # noqa: ANN001
    w, admin, carol = env["world"], env["admin"], env["carol"]
    dave = w.user(admin, "member", label="dave2")
    rid = request_builtin(env, [{"email": carol.email}, {"email": dave.email}]).json()["id"]
    r = carol.post(f"{API}/signature-requests/{rid}/decline", json={"reason": "Wrong amount"})
    assert r.status_code == 204
    assert state(env, rid) == "declined"
    with w.db_factory() as db:
        rec = db.scalar(
            select(SignatureRecipient).where(
                SignatureRecipient.user_id == carol.user_id,
                SignatureRecipient.request_id == uuid.UUID(rid),
            )
        )
        assert rec.status == "declined" and rec.decline_reason == "Wrong amount"
    assert sign(dave, rid, typed_name="Dave").status_code == 409  # the request is over for everyone
    assert carol.post(f"{API}/signature-requests/{rid}/decline", json={}).status_code == 409
    w.process_jobs()
    assert any(
        n["type"] == "signature.declined" for n in admin.get(f"{API}/notifications").json()["items"]
    )


@pytest.mark.parametrize("final", ["cancelled", "expired", "failed"])
def test_a_finished_request_cannot_be_signed(env, final):  # noqa: ANN001
    w = env["world"]
    rid = request_builtin(env).json()["id"]
    if final == "cancelled":
        assert env["admin"].post(f"{API}/signature-requests/{rid}/cancel").status_code == 204
    else:
        with w.db_factory() as db:
            db.execute(
                text("UPDATE dms.signature_requests SET state = :s WHERE id = :i"),
                {"s": final, "i": rid},
            )
            db.commit()
    r = sign(env["carol"], rid)
    assert r.status_code == 409 and r.json()["error"]["code"] == "invalid_state"


def test_one_active_request_per_document_applies_to_builtin_too(env):  # noqa: ANN001
    assert request_builtin(env).status_code == 201
    again = request_builtin(env)
    assert again.status_code == 409 and again.json()["error"]["code"] == "signature_in_progress"


def test_signer_downloads_the_exact_version_and_it_is_audited(env):  # noqa: ANN001
    rid = request_builtin(env).json()["id"]
    r = env["carol"].get(f"{API}/signature-requests/{rid}/document")
    assert (
        r.status_code == 200
        and r.content.startswith(b"%PDF")
        and r.headers["cache-control"] == "no-store"
    )
    acts = {
        e["action"]
        for e in env["admin"]
        .get(f"{API}/admin/audit-events", params={"limit": 100})
        .json()["items"]
    }
    assert "signature.document_viewed" in acts
    env["admin"].post(f"{API}/signature-requests/{rid}/cancel")
    assert env["carol"].get(f"{API}/signature-requests/{rid}/document").status_code == 404


def test_a_tampered_source_checksum_blocks_signing(env):  # noqa: ANN001
    w = env["world"]
    rid = request_builtin(env).json()["id"]
    with w.db_factory() as db:
        db.execute(
            text("UPDATE dms.signature_requests SET source_sha256 = :h WHERE id = :i"),
            {"h": "0" * 64, "i": rid},
        )
        db.commit()
    r = sign(env["carol"], rid)
    assert r.status_code == 409 and r.json()["error"]["code"] == "integrity_error"
    assert state(env, rid) == "sent"


def test_builtin_requests_need_the_same_rights_as_any_signature_request(env):  # noqa: ANN001
    # the carol member has no access to the document: she cannot request a signature on it
    assert request_builtin(env, actor=env["carol"]).status_code == 404


def test_list_can_be_split_into_active_and_history(env):  # noqa: ANN001
    carol = env["carol"]
    rid = request_builtin(env).json()["id"]

    def lst(st):  # noqa: ANN001, ANN202
        return carol.get(
            f"{API}/signature-requests", params={"scope": "to_sign", "status": st}
        ).json()

    assert [r["id"] for r in lst("active")["items"]] == [rid] and lst("finished")["total"] == 0
    assert sign(carol, rid).status_code == 204
    assert lst("active")["total"] == 0 and [r["id"] for r in lst("finished")["items"]] == [rid]
    assert lst("any")["total"] == 1
    assert carol.get(f"{API}/signature-requests", params={"status": "bogus"}).status_code == 422


def test_signing_shows_up_in_the_signers_own_activity_feed(env):  # noqa: ANN001
    r = request_builtin(env)
    assert r.status_code == 201, r.text
    rid = r.json()["id"]
    assert sign(env["carol"], rid).status_code == 204
    items = env["carol"].get(f"{API}/me/activity").json()
    signed = [i for i in items if i["action"] == "signature.recipient_signed"]
    assert signed and signed[0]["verb"] == "signed" and signed[0]["target_id"] == str(env["doc"])
    # the requester's feed has their own request, not the signer's act
    mine = env["admin"].get(f"{API}/me/activity").json()
    assert not [i for i in mine if i["action"] == "signature.recipient_signed"]
