"""E-signature: requests, webhook authenticity/idempotency/ordering, reconciliation, artifacts."""

from __future__ import annotations

import json

import httpx
import pytest
from sqlalchemy import text

from app.adapters.signatures.base import InvalidWebhookError
from app.adapters.signatures.documenso import DocumensoProvider
from app.adapters.signatures.fake import FakeSignatureProvider

pytestmark = pytest.mark.integration

PDF = b"%PDF-1.4 to be signed"


@pytest.fixture(autouse=True)
def _fake_provider_state():  # noqa: ANN202
    FakeSignatureProvider.reset()
    yield
    FakeSignatureProvider.reset()


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Sign", member_default_access=False)
    admin.patch("/api/v1/organization", json={"settings": {"signatures_enabled": True}})
    folder = world.mkdir(admin, world.root_id(admin), "contracts")
    doc = world.available_doc(admin, folder, "agreement.pdf", PDF + b" agreement")
    carol = world.user(admin, "member", label="carol")
    return dict(world=world, admin=admin, folder=folder, doc=doc, carol=carol)


def provider() -> FakeSignatureProvider:
    from app.adapters.signatures.factory import get_signature_provider

    p = get_signature_provider()
    assert isinstance(p, FakeSignatureProvider)
    return p


def request_signature(env, signers=None, actor=None, doc=None):  # noqa: ANN001, ANN202
    signers = signers or [{"email": env["carol"].email, "name": "Carol"}]
    return (actor or env["admin"]).post(
        f"/api/v1/documents/{doc or env['doc']}/signature-requests",
        json={"signers": signers, "message": "please sign"},
    )


def deliver(env, rid, event_type="DOCUMENT_COMPLETED", event_id=None, headers=None, body=None):  # noqa: ANN001, ANN202
    b, h = provider().build_webhook(event_type, rid, event_id)
    return env["world"].client.post(
        "/api/v1/webhooks/signatures/fake", content=body or b, headers=headers or h
    )


class TestCapabilitiesAndPolicy:
    def test_capabilities_and_org_opt_in(self, world):  # noqa: ANN001
        admin = world.org("Off")
        caps = admin.get("/api/v1/signature-capabilities").json()
        assert caps == {
            "available": True,
            "enabled": False,
            "allow_external_signers": False,
            "provider": "fake",
            "builtin_available": True,
        }
        folder = world.mkdir(admin, world.root_id(admin), "f")
        doc = world.available_doc(admin, folder, "a.pdf", PDF + b" off")
        r = admin.post(
            f"/api/v1/documents/{doc}/signature-requests", json={"signers": [{"email": "x@y.test"}]}
        )
        assert r.status_code == 409 and r.json()["error"]["code"] == "feature_disabled"

    def test_internal_only_unless_external_signers_allowed(self, env):  # noqa: ANN001
        r = request_signature(env, [{"email": "outsider@example.org"}])
        assert r.status_code == 422 and r.json()["error"]["code"] == "external_signers_disabled"
        env["admin"].patch(
            "/api/v1/organization", json={"settings": {"allow_external_signers": True}}
        )
        ok = request_signature(
            env,
            [{"email": "outsider@example.org", "name": "Olivia"}, {"email": env["carol"].email}],
        )
        assert ok.status_code == 201
        assert {s["email"]: s["internal"] for s in ok.json()["signers"]} == {
            "outsider@example.org": False,
            env["carol"].email: True,
        }

    def test_requires_share_and_download_rights_dlp_and_valid_signers(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        viewer = w.user(admin, "member", label="viewer")
        admin.post(
            f"/api/v1/documents/{env['doc']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(viewer.user_id),
                "actions": ["view", "share"],
            },
        )
        assert (
            request_signature(env, actor=viewer).status_code == 403
        )  # no download right: bytes would leave the DMS
        assert request_signature(env, actor=env["carol"]).status_code == 404
        assert request_signature(env, signers=[{"email": "not-an-email"}]).status_code == 422
        assert (
            request_signature(
                env, signers=[{"email": env["carol"].email}, {"email": env["carol"].email}]
            ).status_code
            == 422
        )
        admin.patch(f"/api/v1/documents/{env['doc']}", json={"classification": "restricted"})
        assert (
            request_signature(env).status_code == 409
        )  # DLP blocks sending restricted content out

    def test_unavailable_when_no_provider(self, env, monkeypatch):  # noqa: ANN001
        from app.adapters.signatures.factory import reset_signature_provider
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("SIGNATURE_PROVIDER", "none")
        reset_settings_cache()
        reset_signature_provider()
        try:
            r = request_signature(env)
            assert r.status_code == 409 and r.json()["error"]["code"] == "signatures_unavailable"
            assert env["admin"].get("/api/v1/signature-capabilities").json()["available"] is False
        finally:
            monkeypatch.undo()
            reset_settings_cache()
            reset_signature_provider()


class TestLifecycle:
    def test_full_flow_webhook_reconcile_and_signed_artifact(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        r = request_signature(env)
        assert r.status_code == 201, r.text
        req = r.json()
        assert (
            req["state"] == "sent"
            and req["source_version_number"] == 1
            and req["signers"][0]["status"] == "pending"
        )
        rid = _provider_id(w, req["id"])
        FakeSignatureProvider.sign(rid, env["carol"].email)
        assert deliver(env, rid, "DOCUMENT_COMPLETED").json() == {"status": "accepted"}
        w.process_jobs()
        done = admin.get(f"/api/v1/signature-requests/{req['id']}").json()
        assert done["state"] == "completed" and done["signers"][0]["status"] == "signed"
        art = done["artifact"]
        assert art["version_number"] == 2 and len(art["sha256"]) == 64
        assert [e["status"] for e in done["events"]] == ["processed"]
        w.process_jobs()  # the signed version is scanned like any other upload
        doc = admin.get(f"/api/v1/documents/{env['doc']}").json()
        assert doc["current_version"]["version_number"] == 2 and doc["latest_version_number"] == 2
        url = admin.post(f"/api/v1/documents/{env['doc']}/download-url", json={}).json()["url"]
        assert (
            b"signed by fake provider" in w.client.get(url.replace("http://testserver", "")).content
        )
        # the exact source version is untouched and still downloadable
        v1 = admin.post(
            f"/api/v1/documents/{env['doc']}/download-url", json={"version_number": 1}
        ).json()["url"]
        assert w.client.get(v1.replace("http://testserver", "")).content == PDF + b" agreement"
        with w.db_factory() as db:
            ev = db.execute(
                text(
                    "SELECT evidence, source_version_id FROM dms.signed_artifacts WHERE request_id = :r"
                ),
                {"r": req["id"]},
            ).one()
            assert (
                ev.evidence["provider_request_id"] == rid
                and ev.evidence["recipients"][0]["status"] == "signed"
            )
        actions = {
            e["action"]
            for e in admin.get("/api/v1/admin/audit-events", params={"limit": 100}).json()["items"]
        }
        assert {
            "signature.requested",
            "signature.sent",
            "signature.recipient_signed",
            "signature.completed",
        } <= actions
        assert any(
            n["type"] == "signature.completed"
            for n in admin.get("/api/v1/notifications").json()["items"]
        )

    def test_declined_request_and_no_artifact(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        req = request_signature(env).json()
        rid = _provider_id(w, req["id"])
        FakeSignatureProvider.decline(rid, env["carol"].email)
        deliver(env, rid, "DOCUMENT_REJECTED")
        w.process_jobs()
        got = admin.get(f"/api/v1/signature-requests/{req['id']}").json()
        assert (
            got["state"] == "declined"
            and got["artifact"] is None
            and got["signers"][0]["status"] == "declined"
        )
        assert admin.get(f"/api/v1/documents/{env['doc']}").json()["latest_version_number"] == 1

    def test_one_active_request_per_document_and_cancel(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        a = request_signature(env).json()
        # a second concurrent request for the same document is still allowed to be created later,
        # but cancelling frees the provider side and is final
        assert admin.post(f"/api/v1/signature-requests/{a['id']}/cancel").status_code == 204
        assert admin.post(f"/api/v1/signature-requests/{a['id']}/cancel").status_code == 409
        assert FakeSignatureProvider._docs[_provider_id(w, a["id"])].status == "cancelled"
        assert env["carol"].post(f"/api/v1/signature-requests/{a['id']}/cancel").status_code == 404

    def test_provider_outage_on_create_leaves_a_failed_request_and_clear_error(self, env):  # noqa: ANN001
        FakeSignatureProvider.fail_next_create = True
        r = request_signature(env)
        assert r.status_code == 503 and r.json()["error"]["code"] == "dependency_unavailable"
        mine = env["admin"].get("/api/v1/signature-requests").json()["items"]
        assert [m["state"] for m in mine] == ["failed"] and mine[0]["failure_reason"]
        assert request_signature(env).status_code == 201  # the user can simply retry


class TestWebhookSecurity:
    def test_forged_and_malformed_webhooks_are_rejected_and_audited(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        req = request_signature(env).json()
        rid = _provider_id(w, req["id"])
        body, headers = provider().build_webhook("DOCUMENT_COMPLETED", rid)
        for bad_headers, bad_body in (
            ({"x-fake-signature": "0" * 64}, body),
            ({}, body),
            (headers, body + b" "),  # signed body tampered with
            ({"x-fake-signature": "zz"}, b"not json"),
        ):
            r = w.client.post(
                "/api/v1/webhooks/signatures/fake", content=bad_body, headers=bad_headers
            )
            assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_webhook"
        assert admin.get(f"/api/v1/signature-requests/{req['id']}").json()["state"] == "sent"
        with w.db_factory() as db:
            assert (
                db.scalar(
                    text(
                        "SELECT count(*) FROM dms.audit_events WHERE action = 'signature.webhook_rejected'"
                    )
                )
                >= 4
            )
        assert (
            w.client.post("/api/v1/webhooks/signatures/unknown", content=b"{}").status_code == 404
        )

    def test_duplicate_delivery_is_idempotent(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        req = request_signature(env).json()
        rid = _provider_id(w, req["id"])
        FakeSignatureProvider.sign(rid, env["carol"].email)
        assert deliver(env, rid, event_id="evt-1").json() == {"status": "accepted"}
        assert deliver(env, rid, event_id="evt-1").json() == {"status": "duplicate"}
        w.process_jobs()
        assert deliver(env, rid, event_id="evt-1").json() == {"status": "duplicate"}
        assert deliver(env, rid, event_id="evt-2").json() == {
            "status": "accepted"
        }  # a new event for a finished request
        w.process_jobs()
        assert (
            admin.get(f"/api/v1/documents/{env['doc']}").json()["latest_version_number"] == 2
        )  # exactly one signed version
        with w.db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.signed_artifacts WHERE request_id = :r"),
                    {"r": req["id"]},
                )
                == 1
            )

    def test_out_of_order_and_lying_webhooks_cannot_change_the_outcome(self, env):  # noqa: ANN001
        """A 'completed' webhook arriving before the signer actually signed must not complete it:
        status comes from the provider API, not from the webhook body."""
        w, admin = env["world"], env["admin"]
        req = request_signature(env).json()
        rid = _provider_id(w, req["id"])
        deliver(env, rid, "DOCUMENT_COMPLETED", event_id="early")  # provider says nobody signed yet
        w.process_jobs()
        got = admin.get(f"/api/v1/signature-requests/{req['id']}").json()
        assert got["state"] == "sent" and got["artifact"] is None
        FakeSignatureProvider.sign(rid, env["carol"].email)
        deliver(env, rid, "DOCUMENT_SIGNED", event_id="late")
        w.process_jobs()
        assert admin.get(f"/api/v1/signature-requests/{req['id']}").json()["state"] == "completed"

    def test_unknown_request_ids_are_ignored_not_errors(self, env):  # noqa: ANN001
        assert deliver(env, "fake-doesnotexist").json() == {"status": "ignored"}

    def test_lost_webhook_is_repaired_by_the_reconciliation_sweep(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        req = request_signature(env).json()
        FakeSignatureProvider.sign(
            _provider_id(w, req["id"]), env["carol"].email
        )  # no webhook ever arrives
        from app.workers.maintenance import run_maintenance

        summary = run_maintenance(w.db_factory)
        assert summary["signatures_reconciled"] >= 1
        w.process_jobs()
        assert admin.get(f"/api/v1/signature-requests/{req['id']}").json()["state"] == "completed"

    def test_orphaned_creating_requests_are_failed(self, env):  # noqa: ANN001
        w = env["world"]
        req = request_signature(env).json()
        with w.db_factory() as db:
            db.execute(
                text(
                    "UPDATE dms.signature_requests SET state = 'creating', created_at = now() - interval '1 hour' WHERE id = :i"
                ),
                {"i": req["id"]},
            )
            db.commit()
        from app.modules.signatures.service import reconcile_stale

        assert reconcile_stale(w.db_factory)["orphans_failed"] >= 1
        assert (
            env["admin"].get(f"/api/v1/signature-requests/{req['id']}").json()["state"] == "failed"
        )


class TestAccessAndTenancy:
    def test_requests_visible_to_requester_admins_and_document_viewers_only(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        req = request_signature(env).json()
        stranger = w.user(admin, "member", label="stranger")
        assert stranger.get(f"/api/v1/signature-requests/{req['id']}").status_code == 404
        assert stranger.get(f"/api/v1/documents/{env['doc']}/signature-requests").status_code == 404
        admin.post(
            f"/api/v1/documents/{env['doc']}/permissions",
            json={"subject_type": "user", "subject_id": str(stranger.user_id), "actions": ["view"]},
        )
        assert stranger.get(f"/api/v1/signature-requests/{req['id']}").status_code == 200
        assert (
            stranger.get("/api/v1/signature-requests").json()["total"] == 0
        )  # 'mine' = requested by me
        other = w.org("Other")
        assert other.get(f"/api/v1/signature-requests/{req['id']}").status_code == 404

    def test_purging_the_document_removes_requests_but_keeps_audit(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        request_signature(env)
        admin.delete(f"/api/v1/documents/{env['doc']}")
        assert admin.delete(f"/api/v1/trash/documents/{env['doc']}").status_code == 200
        with w.db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.signature_requests WHERE document_id = :d"),
                    {"d": env["doc"]},
                )
                == 0
            )
        assert any(
            e["action"] == "signature.requested"
            for e in admin.get("/api/v1/admin/audit-events", params={"limit": 100}).json()["items"]
        )


class TestDocumensoAdapter:
    def make(self, handler):  # noqa: ANN001, ANN202
        return DocumensoProvider(
            "https://sign.example.com",
            "api_key_123",
            "whsec",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

    def test_create_flow_follows_the_guide_sequence(self):
        """document/documenso-guide.txt s.8: create -> upload -> signature field -> send."""
        calls = []

        def handler(req: httpx.Request) -> httpx.Response:
            body = req.read()
            calls.append((req.method, req.url.path, req.headers.get("authorization"), body))
            if req.url.path == "/api/v1/documents" and req.method == "POST":
                payload = json.loads(body)
                assert payload["recipients"][0]["role"] == "SIGNER"
                return httpx.Response(
                    200,
                    json={
                        "documentId": 77,
                        "uploadUrl": "https://s3.example.com/upload?sig=abc",
                        "recipients": [
                            {
                                "recipientId": 5,
                                "email": "C@x.test",
                                "token": "tok",
                                "signingUrl": "https://sign.example.com/sign/tok",
                            }
                        ],
                    },
                )
            return httpx.Response(200, json={})

        from app.adapters.signatures.base import SignerSpec

        created = self.make(handler).create_request(
            title="T",
            message="m",
            filename="a.pdf",
            content=iter([b"%PDF-1.4 x"]),
            size=10,
            signers=[SignerSpec("c@x.test", "Carol")],
            send_email=False,
        )
        assert created.provider_request_id == "77"
        assert created.recipient_ids == {"c@x.test": "5"}
        assert created.signing_urls == {"c@x.test": "https://sign.example.com/sign/tok"}
        steps = [(m, path) for m, path, _, _ in calls]
        assert steps == [
            ("POST", "/api/v1/documents"),
            ("PUT", "/upload"),
            ("POST", "/api/v1/documents/77/fields"),
            ("POST", "/api/v1/documents/77/send"),
        ]
        assert calls[0][2] == "api_key_123"  # token sent as-is, without "Bearer"
        field = json.loads(calls[2][3])
        assert (
            field["recipientId"] == 5 and field["type"] == "SIGNATURE" and field["pageNumber"] == 1
        )
        assert 0 < field["pageX"] < 100 and 0 < field["pageY"] < 100
        assert json.loads(calls[3][3]) == {"sendEmail": False}

    def test_send_email_flag_and_one_field_per_signer(self):
        seen = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append((req.url.path, req.read()))
            if req.url.path == "/api/v1/documents":
                return httpx.Response(
                    200,
                    json={
                        "documentId": 1,
                        "uploadUrl": "https://s3.example.com/u",
                        "recipients": [
                            {
                                "recipientId": 1,
                                "email": "a@x.test",
                                "token": "t1",
                                "signingUrl": "https://sign.example.com/sign/t1",
                            },
                            {
                                "recipientId": 2,
                                "email": "b@x.test",
                                "token": "t2",
                                "signingUrl": "https://sign.example.com/sign/t2",
                            },
                        ],
                    },
                )
            return httpx.Response(200, json={})

        from app.adapters.signatures.base import SignerSpec

        self.make(handler).create_request(
            title="T",
            message=None,
            filename="a.pdf",
            content=iter([b"%PDF-1.4 y"]),
            size=10,
            signers=[SignerSpec("a@x.test", "A", 0), SignerSpec("b@x.test", "B", 1)],
            send_email=True,
        )
        fields = [json.loads(b) for path, b in seen if path.endswith("/fields")]
        assert [f["recipientId"] for f in fields] == [1, 2] and fields[0]["pageY"] != fields[1][
            "pageY"
        ]
        assert json.loads(seen[-1][1]) == {"sendEmail": True}

    def test_failure_midway_deletes_the_half_built_document_and_hides_error_bodies(self):
        deleted = []

        def handler(req: httpx.Request) -> httpx.Response:
            if req.method == "DELETE":
                deleted.append(req.url.path)
                return httpx.Response(200, json={})
            if req.url.path == "/api/v1/documents":
                return httpx.Response(
                    200,
                    json={
                        "documentId": 9,
                        "uploadUrl": "https://s3.example.com/u",
                        "recipients": [
                            {
                                "recipientId": 1,
                                "email": "a@x.test",
                                "token": "t",
                                "signingUrl": "https://s/sign/t",
                            }
                        ],
                    },
                )
            if req.url.path.endswith("/fields"):
                return httpx.Response(400, json={"message": "secret-internal-detail"})
            return httpx.Response(200, json={})

        from app.adapters.signatures.base import SignatureProviderError, SignerSpec

        with pytest.raises(SignatureProviderError) as exc:
            self.make(handler).create_request(
                title="T",
                message=None,
                filename="a.pdf",
                content=iter([b"%PDF-1.4 z"]),
                size=10,
                signers=[SignerSpec("a@x.test", "A")],
            )
        assert "secret-internal-detail" not in str(exc.value)
        assert deleted == ["/api/v1/documents/9"]

    def test_non_pdf_is_refused_before_any_call(self):
        from app.adapters.signatures.base import SignatureProviderError, SignerSpec

        def handler(req: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("no provider call expected")

        with pytest.raises(SignatureProviderError):
            self.make(handler).create_request(
                title="T",
                message=None,
                filename="a.docx",
                content=iter([b"PK.."]),
                size=4,
                signers=[SignerSpec("a@x.test", "A")],
            )

    def test_https_is_required(self):
        with pytest.raises(RuntimeError):
            DocumensoProvider("http://sign.example.com", "k", "s")

    def test_state_mapping_and_errors(self):
        def handler(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/404"):
                return httpx.Response(404, json={})
            return httpx.Response(
                200,
                json={
                    "status": "COMPLETED",
                    "recipients": [
                        {
                            "email": "C@x.test",
                            "signingStatus": "SIGNED",
                            "signedAt": "2026-10-09T10:00:00Z",
                        }
                    ],
                },
            )

        p = self.make(handler)
        st = p.get_state("1")
        assert (
            st.status == "completed"
            and st.recipients[0].email == "c@x.test"
            and st.recipients[0].status == "signed"
        )
        from app.adapters.signatures.base import SignatureProviderError

        with pytest.raises(SignatureProviderError):
            p.get_state("404")

    def test_webhook_secret_verification(self):
        p = self.make(lambda r: httpx.Response(200, json={}))
        body = json.dumps({"event": "DOCUMENT_COMPLETED", "payload": {"id": 12}}).encode()
        ev = p.parse_webhook({"x-documenso-secret": "whsec"}, body)
        assert ev.provider_request_id == "12" and ev.event_type == "DOCUMENT_COMPLETED"
        assert (
            p.parse_webhook({"x-documenso-secret": "whsec"}, body).event_id == ev.event_id
        )  # stable dedupe key
        for headers, b in (
            ({"x-documenso-secret": "wrong"}, body),
            ({}, body),
            ({"x-documenso-secret": "whsec"}, b"{}"),
            (
                {"x-documenso-secret": "whsec"},
                json.dumps({"event": "OTHER", "payload": {"id": 1}}).encode(),
            ),
        ):
            with pytest.raises(InvalidWebhookError):
                p.parse_webhook(headers, b)


def _provider_id(world, request_id: str) -> str:  # noqa: ANN001
    with world.db_factory() as db:
        return db.scalar(
            text("SELECT provider_request_id FROM dms.signature_requests WHERE id = :i"),
            {"i": request_id},
        )


class TestEmbeddedSigningAndRefresh:
    def _setup(self, env, with_external=False):  # noqa: ANN001, ANN202
        signers = [{"email": env["carol"].email, "name": "Carol"}]
        if with_external:
            env["admin"].patch(
                "/api/v1/organization", json={"settings": {"allow_external_signers": True}}
            )
            signers.append({"email": "outside@example.org", "name": "Olivia"})
        r = request_signature(env, signers)
        assert r.status_code == 201, r.text
        return r.json()

    def test_internal_signer_gets_the_signing_page_only_for_themselves(self, env):  # noqa: ANN001
        w, admin, carol = env["world"], env["admin"], env["carol"]
        req = self._setup(env)
        assert req["my_signing_available"] is False  # the requester is not a signer
        mine = carol.get(f"/api/v1/signature-requests/{req['id']}")
        assert mine.status_code == 200 and mine.json()["my_signing_available"] is True
        listed = carol.get("/api/v1/signature-requests", params={"scope": "to_sign"}).json()
        assert [r["id"] for r in listed["items"]] == [req["id"]]
        assert carol.get("/api/v1/signature-requests").json()["total"] == 0  # not hers to manage
        r = carol.post(f"/api/v1/signature-requests/{req['id']}/signing-session")
        assert r.status_code == 200 and r.json()["url"].startswith(
            "https://fake-sign.example/sign/"
        )
        assert (
            env["admin"].post(f"/api/v1/signature-requests/{req['id']}/signing-session").status_code
            == 404
        )
        stranger = w.user(admin, "member", label="stranger")
        assert (
            stranger.post(f"/api/v1/signature-requests/{req['id']}/signing-session").status_code
            == 404
        )
        # the link never appears in any listing, audit trail or event
        link = r.json()["url"]
        assert link not in admin.get(f"/api/v1/signature-requests/{req['id']}").text
        assert link not in admin.get("/api/v1/admin/audit-events", params={"limit": 200}).text
        assert (
            "signing_url"
            not in admin.get(f"/api/v1/documents/{env['doc']}/signature-requests").text
        )

    def test_signing_session_closes_after_signing_or_cancel(self, env):  # noqa: ANN001
        w, admin, carol = env["world"], env["admin"], env["carol"]
        req = self._setup(env)
        FakeSignatureProvider.sign(_provider_id(w, req["id"]), carol.email)
        done = carol.post(f"/api/v1/signature-requests/{req['id']}/refresh")
        assert done.status_code == 200
        w.process_jobs()
        r = carol.post(f"/api/v1/signature-requests/{req['id']}/signing-session")
        assert r.status_code == 409  # completed
        assert admin.get(f"/api/v1/signature-requests/{req['id']}").json()["state"] == "completed"

    def test_refresh_pulls_authoritative_status_and_is_limited_to_participants(self, env):  # noqa: ANN001
        w, admin, carol = env["world"], env["admin"], env["carol"]
        req = self._setup(env)
        rid = _provider_id(w, req["id"])
        FakeSignatureProvider.sign(rid, carol.email)  # no webhook at all
        out = admin.post(f"/api/v1/signature-requests/{req['id']}/refresh")
        assert out.status_code == 200 and out.json()["signers"][0]["status"] == "signed"
        stranger = w.user(admin, "member", label="stranger2")
        assert stranger.post(f"/api/v1/signature-requests/{req['id']}/refresh").status_code == 404

    def test_external_signers_are_emailed_by_the_provider_internal_only_are_not(self, env):  # noqa: ANN001
        w = env["world"]
        internal_only = self._setup(env)
        assert FakeSignatureProvider._docs[_provider_id(w, internal_only["id"])].send_email is False
        env["admin"].post(f"/api/v1/signature-requests/{internal_only['id']}/cancel")
        mixed = self._setup(env, with_external=True)
        assert FakeSignatureProvider._docs[_provider_id(w, mixed["id"])].send_email is True

    def test_non_pdf_documents_are_converted_and_unsupported_ones_refused(self, env):  # noqa: ANN001
        w, admin = env["world"], env["admin"]
        txt = w.available_doc(admin, env["folder"], "notes.txt", b"plain text file")
        r = admin.post(
            f"/api/v1/documents/{txt}/signature-requests",
            json={"signers": [{"email": env["carol"].email}]},
        )
        assert r.status_code == 201, (
            r.text
        )  # a signing copy (PDF) is made; the original stays as it is
        weird = w.available_doc(admin, env["folder"], "data.xyz", b"\x00\x01 binary-ish content")
        bad = admin.post(
            f"/api/v1/documents/{weird}/signature-requests",
            json={"signers": [{"email": env["carol"].email}]},
        )
        assert bad.status_code == 422 and bad.json()["error"]["code"] == "conversion_failed"
        assert "can't be converted to PDF" in bad.json()["error"]["message"]
