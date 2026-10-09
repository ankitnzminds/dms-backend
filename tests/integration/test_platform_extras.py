"""Notification preferences + e-mail, audit export, reports, member lookup, contract refinements."""

from __future__ import annotations

import csv
import io

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

PDF = b"%PDF-1.4 extras"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Extras", member_default_access=True)
    folder = world.mkdir(admin, world.root_id(admin), "docs")
    return dict(world=world, admin=admin, folder=folder)


class RecordingEmail:
    def __init__(self) -> None:
        self.sent = []

    def send(self, message):  # noqa: ANN001, ANN201
        self.sent.append(message)


def process_with_email(world, sender):  # noqa: ANN001, ANN201
    from app.workers.runner import WorkerContext, build_context, run_once

    base = build_context()
    ctx = WorkerContext(base.settings, base.scanner, sender)
    for _ in range(10):
        if run_once(ctx=ctx, factory=world.db_factory) == 0:
            break


class TestPreferencesAndEmail:
    def test_defaults_and_updates(self, env, monkeypatch):  # noqa: ANN001
        a = env["admin"]
        prefs = a.get("/api/v1/notification-preferences").json()
        assert prefs["email_available"] is False
        assert {p["group"] for p in prefs["preferences"]} == {
            "sharing",
            "workflow",
            "signature",
            "document",
            "other",
        }
        assert all(p["in_app"] and p["email"] for p in prefs["preferences"])
        r = a.put(
            "/api/v1/notification-preferences",
            json=[{"group": "sharing", "in_app": False, "email": False}],
        )
        assert r.status_code == 200
        got = {p["group"]: p for p in r.json()["preferences"]}
        assert got["sharing"]["in_app"] is False and got["workflow"]["in_app"] is True
        assert (
            a.put(
                "/api/v1/notification-preferences",
                json=[{"group": "bogus", "in_app": True, "email": True}],
            ).status_code
            == 422
        )

    def test_in_app_off_keeps_record_but_marks_it_read(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        bob = w.user(a, "member", label="bob")
        bob.put(
            "/api/v1/notification-preferences",
            json=[{"group": "sharing", "in_app": False, "email": False}],
        )
        doc = w.available_doc(a, env["folder"], "n.pdf", PDF + b" n")
        a.post(
            f"/api/v1/documents/{doc}/shares",
            json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["view"]},
        )
        w.process_jobs()
        assert bob.get("/api/v1/notifications").json()["unread_count"] == 0

    def test_email_is_queued_minimal_tokenless_and_deduplicated(self, env, monkeypatch):  # noqa: ANN001
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("EMAIL_PROVIDER", "log")
        reset_settings_cache()
        try:
            w, a = env["world"], env["admin"]
            bob = w.user(a, "member", label="bob")
            doc = w.available_doc(a, env["folder"], "secret-plan.pdf", PDF + b" email")
            a.post(
                f"/api/v1/documents/{doc}/shares",
                json={
                    "recipients": [{"type": "user", "id": str(bob.user_id)}],
                    "actions": ["view"],
                },
            )
            sender = RecordingEmail()
            process_with_email(w, sender)
            mails = [m for m in sender.sent if m.to == bob.email]
            assert len(mails) == 1
            body = mails[0].body_text + mails[0].subject
            assert "secret-plan" not in body  # titles are off by default
            assert "token" not in body.lower() and "/notifications" in body
            # redelivery of the same event is a no-op
            with w.db_factory() as db:
                db.execute(
                    text(
                        "UPDATE dms.outbox_events SET status='pending', next_attempt_at=now(), locked_until=NULL WHERE event_type='notification.email'"
                    )
                )
                db.commit()
            sender2 = RecordingEmail()
            process_with_email(w, sender2)
            assert [m for m in sender2.sent if m.to == bob.email] == []
            # opting in to titles in the organization changes the content
            a.patch("/api/v1/organization", json={"settings": {"email_include_titles": True}})
            doc2 = w.available_doc(a, env["folder"], "second-doc.pdf", PDF + b" email2")
            a.post(
                f"/api/v1/documents/{doc2}/shares",
                json={
                    "recipients": [{"type": "user", "id": str(bob.user_id)}],
                    "actions": ["view"],
                },
            )
            sender3 = RecordingEmail()
            process_with_email(w, sender3)
            assert any("second-doc" in m.body_text for m in sender3.sent if m.to == bob.email)
        finally:
            monkeypatch.undo()
            reset_settings_cache()

    def test_user_can_opt_out_of_email(self, env, monkeypatch):  # noqa: ANN001
        from app.core.config import reset_settings_cache

        monkeypatch.setenv("EMAIL_PROVIDER", "log")
        reset_settings_cache()
        try:
            w, a = env["world"], env["admin"]
            bob = w.user(a, "member", label="bob")
            bob.put(
                "/api/v1/notification-preferences",
                json=[{"group": "sharing", "in_app": True, "email": False}],
            )
            doc = w.available_doc(a, env["folder"], "o.pdf", PDF + b" optout")
            a.post(
                f"/api/v1/documents/{doc}/shares",
                json={
                    "recipients": [{"type": "user", "id": str(bob.user_id)}],
                    "actions": ["view"],
                },
            )
            sender = RecordingEmail()
            process_with_email(w, sender)
            assert not [m for m in sender.sent if m.to == bob.email]
            assert bob.get("/api/v1/notifications").json()["unread_count"] == 1
        finally:
            monkeypatch.undo()
            reset_settings_cache()

    def test_smtp_sender_builds_a_safe_message(self, monkeypatch):  # noqa: ANN001
        from app.adapters.email.base import EmailMessage
        from app.adapters.email.smtp import EmailDeliveryError, SmtpEmailSender

        captured = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):  # noqa: ANN001
                captured["host"] = (host, port)

            def __enter__(self):  # noqa: ANN204
                return self

            def __exit__(self, *a):  # noqa: ANN002, ANN204
                return False

            def starttls(self, context=None):  # noqa: ANN001, ANN201
                captured["starttls"] = context is not None

            def login(self, u, p):  # noqa: ANN001, ANN201
                captured["login"] = u

            def send_message(self, m):  # noqa: ANN001, ANN201
                captured["msg"] = m

        monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
        SmtpEmailSender("smtp.example.com", 587, "dms@example.com", "user", "pw").send(
            EmailMessage("bob@example.com", "Hello\r\nBcc: evil@x.test", "body", "key-1")
        )
        assert captured["starttls"] and captured["login"] == "user"
        msg = captured["msg"]
        assert "\n" not in msg["Subject"] and msg["Bcc"] is None and msg["To"] == "bob@example.com"

        class Boom(FakeSMTP):
            def send_message(self, m):  # noqa: ANN001, ANN201
                raise OSError("down")

        monkeypatch.setattr("smtplib.SMTP", Boom)
        with pytest.raises(EmailDeliveryError):
            SmtpEmailSender("smtp.example.com", 587, "dms@example.com").send(
                EmailMessage("a@b.c", "s", "b", "k")
            )


class TestAuditExportAndReports:
    def test_csv_export_is_authorized_audited_and_formula_safe(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        w.mkdir(a, env["folder"], "=SUM(1+1)")
        r = a.get("/api/v1/admin/audit-events/export", params={"action": "folder."})
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
        assert "attachment" in r.headers["content-disposition"]
        rows = list(csv.reader(io.StringIO(r.text.lstrip("﻿"))))
        assert rows[0][:4] == ["time_utc", "actor_user_id", "actor_email", "action"]
        assert any(row[3] == "folder.created" for row in rows[1:])
        assert not any(cell.startswith("=") for row in rows for cell in row)
        assert any(
            e["action"] == "audit.exported"
            for e in a.get("/api/v1/admin/audit-events").json()["items"]
        )
        member = w.user(a, "member", label="m")
        assert member.get("/api/v1/admin/audit-events/export").status_code == 403
        auditor = w.user(a, "auditor", label="aud")
        assert auditor.get("/api/v1/admin/audit-events/export").status_code == 200

    def test_export_never_includes_other_tenants(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        other = w.org("Other")
        w.mkdir(other, w.root_id(other), "foreign-folder-marker")
        text_out = a.get("/api/v1/admin/audit-events/export").text
        assert "foreign-folder-marker" not in text_out and str(other.org_id) not in text_out

    def test_summary_report_uses_real_counts(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "r.pdf", PDF + b" report")
        bob = w.user(a, "member", label="bob")
        a.post(
            f"/api/v1/documents/{doc}/shares",
            json={"recipients": [{"type": "user", "id": str(bob.user_id)}], "actions": ["view"]},
        )
        bob.get(f"/api/v1/documents/{doc}/versions")  # allowed
        bob.delete(f"/api/v1/documents/{doc}")  # denied -> counted
        rep = a.get("/api/v1/admin/reports/summary").json()
        assert (
            rep["documents_by_status"]["available"] == 1
            and rep["documents_by_classification"]["internal"] == 1
        )
        assert rep["shares"]["active"] == 1 and rep["denied_attempts"] >= 1
        assert any(t["action"] == "share.created" for t in rep["top_actions"])
        assert bob.get("/api/v1/admin/reports/summary").status_code == 403


class TestContractRefinements:
    def test_member_lookup_is_minimal_scoped_and_validated(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        bob = w.user(a, "member", label="bobby")
        other = w.org("Other")
        w.user(other, "member", label="bobby")
        r = a.get("/api/v1/members/lookup", params={"q": "bobby"})
        assert r.status_code == 200 and [u["id"] for u in r.json()] == [str(bob.user_id)]
        assert set(r.json()[0]) == {"id", "display_name", "email"}
        assert (
            bob.get("/api/v1/members/lookup", params={"q": "bobby"}).json() == []
        )  # never yourself
        assert a.get("/api/v1/members/lookup", params={"q": "b"}).status_code == 422
        assert (
            a.get("/api/v1/members/lookup", params={"q": "%%"}).status_code == 422
            or a.get("/api/v1/members/lookup", params={"q": "%%"}).json() == []
        )

    def test_usage_nulls_admin_only_counters_for_members(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        m = w.user(a, "member", label="m")
        mine = m.get("/api/v1/organization/usage").json()
        assert mine["users"] is None and mine["groups"] is None and mine["pending_scans"] is None
        assert a.get("/api/v1/organization/usage").json()["users"] >= 2

    def test_members_see_share_policy_settings(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        m = w.user(a, "member", label="m")
        s = m.get("/api/v1/organization").json()["settings"]
        assert {"max_share_days", "require_share_expiry", "mask_shared_breadcrumbs"} <= set(s)
        assert "trash_retention_days" not in s and "email_include_titles" not in s

    def test_recent_includes_uploads(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "fresh.pdf", PDF + b" fresh")
        assert doc in [i["id"] for i in a.get("/api/v1/recent").json()["items"]]

    def test_inline_preview_can_be_framed_by_configured_origins_only(self, env):  # noqa: ANN001
        w, a = env["world"], env["admin"]
        doc = w.available_doc(a, env["folder"], "p.pdf", PDF + b" preview")
        url = a.post(f"/api/v1/documents/{doc}/download-url", json={"inline": True}).json()["url"]
        r = w.client.get(url.replace("http://testserver", ""))
        assert "frame-ancestors http://localhost:3000" in r.headers["content-security-policy"]
        assert "x-frame-options" not in r.headers  # XFO would override the CSP allow-list
        # ordinary API responses and downloads stay unframeable
        assert a.get("/api/v1/me").headers["x-frame-options"] == "DENY"
        dl = a.post(f"/api/v1/documents/{doc}/download-url", json={}).json()["url"]
        assert (
            w.client.get(dl.replace("http://testserver", "")).headers["x-frame-options"] == "DENY"
        )

    def test_actions_and_classification_are_enumerated_in_the_contract(self, env):  # noqa: ANN001
        spec = env["world"].client.get("/openapi.json").json()["components"]["schemas"]
        assert "view" in spec["TreeItem"]["properties"]["permissions"]["items"]["enum"]
        assert set(spec["DocumentOut"]["properties"]["classification"]["enum"]) == {
            "public",
            "internal",
            "confidential",
            "restricted",
        }
        assert "uploaded" in spec["UploadSessionOut"]["properties"]["state"]["enum"]
        a = env["admin"]
        r = a.post(
            f"/api/v1/folders/{env['folder']}/shares",
            json={"recipients": [{"type": "user", "email": "x@y.z"}], "actions": ["teleport"]},
        )
        assert r.status_code == 422
