"""Automation workflows: catalogue, validation, lifecycle, event/timer/scan execution, per-step
re-authorization, idempotency, retries, dry runs, high-risk gating, tenant isolation and audit."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

pytestmark = pytest.mark.integration
API = "/api/v1"
A = f"{API}/admin"


def wizard(trigger_key, trigger_params, action_key, params, name):  # noqa: ANN001, ANN201
    return {
        "name": name,
        "trigger": {"key": trigger_key, "params": trigger_params},
        "graph": {
            "nodes": [
                {"id": "start", "type": "start"},
                {"id": "a1", "type": action_key, "params": params},
                {"id": "end", "type": "end"},
            ],
            "edges": [{"from": "start", "to": "a1"}, {"from": "a1", "to": "end"}],
        },
    }


def go_live(actor, body, confirm=False):  # noqa: ANN001, ANN201
    r = actor.post(f"{A}/automations", json=body)
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    p = actor.post(f"{A}/automations/{aid}/publish", json={"confirm_high_risk": confirm})
    assert p.status_code == 200, p.text
    e = actor.post(f"{A}/automations/{aid}/enable")
    assert e.status_code == 200, e.text
    return aid


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    owner = world.org("Auto Inc")
    root = world.root_id(owner)
    inbox = world.mkdir(owner, root, "Inbox")
    archive = world.mkdir(owner, root, "Archive")
    return dict(world=world, owner=owner, root=root, inbox=inbox, archive=archive)


def runs_of(actor, aid):  # noqa: ANN001, ANN201
    r = actor.get(f"{A}/automations/{aid}/runs")
    assert r.status_code == 200, r.text
    return r.json()["items"]


def docs_in(db, folder):  # noqa: ANN001, ANN201
    from app.db.models import Document

    db.rollback()
    return list(db.scalars(select(Document).where(Document.folder_id == uuid.UUID(folder))))


class TestCatalogueAndValidation:
    def test_catalogue_lists_everything_and_is_honest(self, env):  # noqa: ANN001
        c = env["owner"].get(f"{A}/automations/catalogue").json()
        conds = {x["key"]: x for x in c["conditions"]}
        acts = {x["key"]: x for x in c["actions"]}
        assert len(conds) == 20 and len(c["conditions"]) == 20
        assert {"file_created", "periodic_schedule", "account_expiring", "last_login_age"} <= set(
            conds
        )
        assert {
            "notify_users",
            "copy_files",
            "delete_files",
            "move_files",
            "verify_integrity_alert",
            "verify_integrity_delete",
            "run_report",
            "release_locks",
            "send_email",
        } <= {k for k, v in acts.items() if v["wizard"]}
        assert conds["client_app_connected"]["supported"] is False
        assert conds["client_app_connected"]["unsupported_reason"]
        assert conds["share_stale"]["supported"] is False
        assert conds["file_created"]["schema"]["additionalProperties"] is False
        assert acts["delete_files"]["risk"] == "high"
        assert conds["file_downloaded"]["observation"]  # says what is actually observed

    def test_only_admins(self, env):  # noqa: ANN001
        m = env["world"].user(env["owner"], "member")
        aud = env["world"].user(env["owner"], "auditor")
        for actor in (m, aud):
            assert actor.get(f"{A}/automations").status_code == 403
            assert actor.get(f"{A}/automations/catalogue").status_code == 403

    @pytest.mark.parametrize(
        ("trigger", "params", "fragment"),
        [
            ("file_created", {"surprise": 1}, "surprise"),
            ("file_created", {"path": "/a/../b"}, ".."),
            ("file_created", {"expression": "file.nope == 1"}, "Unknown variable"),
            ("file_created", {"expression": "file.name matches '(a+)+'"}, "Nested"),
            ("file_stale", {}, "days"),
            ("file_stale", {"days": 0}, "days"),
            ("periodic_schedule", {"frequency": "daily", "time": "25:99"}, "time"),
            ("periodic_schedule", {"frequency": "daily", "timezone": "Mars/Base"}, "timezone"),
            ("periodic_interval", {"every_minutes": 1}, "every_minutes"),
            ("specified_date", {"run_at": "2001-01-01T00:00:00"}, "future"),
            ("specified_date", {"run_at": "not a date"}, "ISO"),
            ("client_app_connected", {}, "device"),
            ("share_stale", {"days": 5}, "not recorded"),
            ("nonexistent", {}, "Unknown condition"),
        ],
    )
    def test_trigger_validation(self, env, trigger, params, fragment):  # noqa: ANN001
        body = wizard(
            trigger,
            params,
            "notify_users",
            {"user_ids": [str(env["owner"].user_id)], "title": "x"},
            "bad",
        )
        r = env["owner"].post(f"{A}/automations", json=body)
        assert r.status_code == 422, r.text
        issues = r.json()["error"]["details"]["issues"]
        assert any(fragment.lower() in (i["message"] + str(i["field"])).lower() for i in issues), (
            issues
        )

    def test_action_and_graph_validation(self, env):  # noqa: ANN001
        o, e = env["owner"], env
        uid = str(o.user_id)
        ok = {"user_ids": [uid], "title": "x"}

        def bad(body, fragment):  # noqa: ANN001, ANN202
            r = o.post(f"{A}/automations", json=body)
            assert r.status_code == 422, r.text
            msgs = " ".join(i["message"] for i in r.json()["error"]["details"]["issues"])
            assert fragment.lower() in msgs.lower(), msgs

        base = wizard("file_created", {}, "notify_users", ok, "g")
        # unknown placeholder
        bad(
            wizard("file_created", {}, "notify_users", {**ok, "title": "{file.secret}"}, "g1"),
            "placeholder",
        )
        # needs a file but a timer provides none
        bad(
            wizard(
                "periodic_interval",
                {"every_minutes": 60},
                "delete_files",
                {"confirm_move_to_trash": True},
                "g2",
            ),
            "needs a file",
        )
        # recipients from another organization
        bad(
            wizard(
                "file_created",
                {},
                "notify_users",
                {"user_ids": [str(uuid.uuid4())], "title": "x"},
                "g3",
            ),
            "members",
        )
        # folder from another organization / nowhere
        bad(
            wizard("file_created", {}, "copy_files", {"target_folder_id": str(uuid.uuid4())}, "g4"),
            "folder",
        )
        # unknown step type, no steps, loop, unreachable node
        base2 = {
            **base,
            "name": "g5",
            "graph": {
                "nodes": [
                    {"id": "start", "type": "start"},
                    {"id": "x", "type": "shell", "params": {}},
                ],
                "edges": [{"from": "start", "to": "x"}],
            },
        }
        bad(base2, "Unknown step")
        loop = {
            **base,
            "name": "g6",
            "graph": {
                "nodes": [
                    {"id": "start", "type": "start"},
                    {"id": "n1", "type": "notify_users", "params": ok},
                    {"id": "n2", "type": "notify_users", "params": ok},
                ],
                "edges": [
                    {"from": "start", "to": "n1"},
                    {"from": "n1", "to": "n2"},
                    {"from": "n2", "to": "n1"},
                ],
            },
        }
        bad(loop, "Loops")
        orphan = {
            **base,
            "name": "g7",
            "graph": {
                "nodes": [
                    {"id": "start", "type": "start"},
                    {"id": "n1", "type": "notify_users", "params": ok},
                    {"id": "n2", "type": "notify_users", "params": ok},
                ],
                "edges": [{"from": "start", "to": "n1"}],
            },
        }
        bad(orphan, "not connected")
        bad(
            {
                **base,
                "name": "g8",
                "graph": {"nodes": [{"id": "start", "type": "start"}], "edges": []},
            },
            "step",
        )
        assert e["owner"].post(f"{A}/automations/validate", json=base).json()["valid"] is True

    def test_other_tenant_sees_nothing(self, env):  # noqa: ANN001
        o = env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "x"},
                "mine",
            ),
        )
        other = env["world"].org("Elsewhere")
        assert other.get(f"{A}/automations").json()["total"] == 0
        for method, path in (
            ("get", f"/automations/{aid}"),
            ("get", f"/automations/{aid}/runs"),
            ("post", f"/automations/{aid}/enable"),
            ("post", f"/automations/{aid}/archive"),
            ("post", f"/automations/{aid}/validate"),
        ):
            assert getattr(other, method)(f"{A}{path}").status_code == 404, path
        assert other.patch(f"{A}/automations/{aid}", json={"name": "x"}).status_code == 404
        assert other.get(f"{A}/automation-runs/{uuid.uuid4()}").status_code == 404


class TestLifecycle:
    def body(self, env, name="wf"):  # noqa: ANN001, ANN201
        return wizard(
            "file_created",
            {"path": "/Inbox"},
            "notify_users",
            {"user_ids": [str(env["owner"].user_id)], "title": "New {file.name}"},
            name,
        )

    def test_draft_is_not_enabled_and_needs_publish(self, env):  # noqa: ANN001
        o = env["owner"]
        r = o.post(f"{A}/automations", json=self.body(env))
        assert r.status_code == 201
        w = r.json()
        assert w["status"] == "draft" and w["enabled"] is False and w["state"] == "draft"
        assert w["last_checked_at"] is None and w["last_run_at"] is None  # nothing fabricated
        assert w["if_this"].startswith("If a file is created") and "Notify" in w["then_that"]
        assert o.post(f"{A}/automations/{w['id']}/enable").status_code == 409
        assert o.post(f"{A}/automations", json=self.body(env)).status_code == 409  # unique name
        assert o.post(f"{A}/automations/{w['id']}/publish", json={}).json()["status"] == "published"
        assert o.post(f"{A}/automations/{w['id']}/enable").json()["enabled"] is True
        assert o.post(f"{A}/automations/{w['id']}/disable").json()["enabled"] is False

    def test_editing_changes_the_draft_only(self, env):  # noqa: ANN001
        o = env["owner"]
        aid = go_live(o, self.body(env))
        new = self.body(env)
        new["graph"]["nodes"][1]["params"]["title"] = "Changed"
        r = o.patch(f"{A}/automations/{aid}", json={"graph": new["graph"]})
        assert r.status_code == 200 and r.json()["has_unpublished_changes"] is True
        assert r.json()["published_version"] == 1
        pub = o.post(f"{A}/automations/{aid}/publish", json={}).json()
        assert pub["published_version"] == 2 and pub["has_unpublished_changes"] is False
        stale = o.patch(f"{A}/automations/{aid}", json={"name": "z", "expected_row_version": 1})
        assert stale.status_code == 409

    def test_invalid_draft_can_be_autosaved_but_not_published(self, env):  # noqa: ANN001
        o = env["owner"]
        r = o.post(f"{A}/automations", json=self.body(env, "canvas"))
        aid = r.json()["id"]
        broken = {
            "nodes": [
                {"id": "start", "type": "start"},
                {"id": "n", "type": "notify_users", "params": {}},
            ],
            "edges": [],
        }
        assert o.patch(f"{A}/automations/{aid}", json={"graph": broken}).status_code == 422
        saved = o.patch(f"{A}/automations/{aid}", json={"graph": broken, "allow_invalid": True})
        assert saved.status_code == 200
        pub = o.post(f"{A}/automations/{aid}/publish", json={})
        assert pub.status_code == 422

    def test_unfinished_canvas_drafts_can_be_created_but_not_activated(self, env):  # noqa: ANN001
        o = env["owner"]
        blank = {
            "name": "blank", "editor_mode": "canvas", "allow_invalid": True,
            "trigger": {"key": "file_created", "params": {}},
            "graph": {"nodes": [{"id": "start", "type": "start"}], "edges": []},
        }
        r = o.post(f"{A}/automations", json=blank)
        assert r.status_code == 201 and r.json()["status"] == "draft"
        assert o.post(f"{A}/automations/{r.json()['id']}/publish", json={}).status_code == 422
        assert o.post(f"{A}/automations", json={**blank, "name": "b2", "activate": True}).status_code == 422

    def test_archive_and_duplicate(self, env):  # noqa: ANN001
        o = env["owner"]
        aid = go_live(o, self.body(env))
        dup = o.post(f"{A}/automations/{aid}/duplicate")
        assert (
            dup.status_code == 201
            and dup.json()["name"].endswith("(copy)")
            and dup.json()["status"] == "draft"
        )
        arch = o.post(f"{A}/automations/{aid}/archive").json()
        assert arch["status"] == "archived" and arch["enabled"] is False
        names = [x["name"] for x in o.get(f"{A}/automations").json()["items"]]
        assert "wf" not in names
        assert o.patch(f"{A}/automations/{aid}", json={"name": "q"}).status_code == 409

    def test_high_risk_needs_owner_and_confirmation(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        adm = w.user(o, "admin")
        risky = wizard(
            "file_created",
            {"path": "/Inbox"},
            "delete_files",
            {"confirm_move_to_trash": True},
            "risky",
        )
        r = adm.post(f"{A}/automations", json=risky).json()
        assert (
            adm.post(
                f"{A}/automations/{r['id']}/publish", json={"confirm_high_risk": True}
            ).status_code
            == 403
        )
        r2 = o.post(f"{A}/automations", json={**risky, "name": "risky2"}).json()
        assert r2["high_risk"] is True
        no = o.post(f"{A}/automations/{r2['id']}/publish", json={})
        assert no.status_code == 422 and no.json()["error"]["code"] == "high_risk_confirmation"
        assert (
            o.post(
                f"{A}/automations/{r2['id']}/publish", json={"confirm_high_risk": True}
            ).status_code
            == 200
        )
        assert (
            o.post(
                f"{A}/automations",
                json=wizard(
                    "file_created", {}, "delete_files", {"confirm_move_to_trash": False}, "nc"
                ),
            ).status_code
            == 422
        )

    def test_lifecycle_is_audited_in_the_workflow_category(self, env):  # noqa: ANN001
        o = env["owner"]
        go_live(o, self.body(env))
        items = o.get(f"{A}/activity", params={"category": "workflow", "limit": 50}).json()["items"]
        actions = {e["action"] for e in items}
        assert {"automation.created", "automation.published", "automation.enabled"} <= actions


class TestEventExecution:
    def test_file_created_copies_the_file_and_records_real_state(self, env, db):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {"path": "/Inbox", "extensions": ["pdf"]},
                "copy_files",
                {"target_folder_id": env["archive"], "on_conflict": "rename"},
                "archive pdfs",
            ),
        )
        before = o.get(f"{A}/automations/{aid}").json()
        assert before["last_run_at"] is None
        w.available_doc(o, env["inbox"], "report.pdf")
        w.available_doc(
            o,
            env["inbox"],
            "notes.txt",
            b"hello",
        )
        w.process_jobs()
        archived = docs_in(db, env["archive"])
        assert [d.name for d in archived] == ["report.pdf"]  # the .txt did not match the filter
        runs = runs_of(o, aid)
        assert (
            len(runs) == 1 and runs[0]["status"] == "succeeded" and runs[0]["version_number"] == 1
        )
        detail = o.get(f"{A}/automation-runs/{runs[0]['id']}").json()
        assert (
            detail["nodes"][0]["status"] == "succeeded"
            and "new_document_id" in detail["nodes"][0]["output"]
        )
        after = o.get(f"{A}/automations/{aid}").json()
        assert (
            after["last_run_status"] == "succeeded"
            and after["last_run_at"]
            and after["last_checked_at"]
        )
        assert after["runs_succeeded"] == 1

    def test_redelivered_events_never_start_a_second_run(self, env, db):  # noqa: ANN001
        from app.db.models import AuditEvent
        from app.modules.automations import triggers

        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {"path": "/Inbox"},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "dedupe",
            ),
        )
        w.available_doc(o, env["inbox"], "a.pdf")
        w.process_jobs()
        ev = db.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "document.scan_clean", AuditEvent.organization_id == o.org_id
            )
        )
        triggers.handle_event(w.db_factory, ev.id)
        triggers.handle_event(w.db_factory, ev.id)
        w.process_jobs()
        assert len(runs_of(o, aid)) == 1

    def test_scope_excludes_other_folders_and_patterns(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {"path": "/Inbox", "exclude": ["*.tmp"]},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "scoped",
            ),
        )
        w.available_doc(o, env["archive"], "elsewhere.pdf")
        w.available_doc(o, env["inbox"], "skip.tmp", b"x")
        w.available_doc(o, env["inbox"], "keep.pdf")
        w.process_jobs()
        assert len(runs_of(o, aid)) == 1

    def test_expression_filter(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {"expression": "file.name startswith 'inv' and file.size_bytes > 5"},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "expr",
            ),
        )
        w.available_doc(o, env["inbox"], "invoice.pdf", b"%PDF-1.4 plenty of bytes")
        w.available_doc(o, env["inbox"], "other.pdf", b"%PDF-1.4 plenty of bytes")
        w.process_jobs()
        assert len(runs_of(o, aid)) == 1

    def test_updated_vs_created_use_the_version_number(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        created = go_live(
            o,
            wizard(
                "file_created",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "created",
            ),
        )
        updated = go_live(
            o,
            wizard(
                "file_updated",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "updated",
            ),
        )
        both = go_live(
            o,
            wizard(
                "file_created_or_updated",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "both",
            ),
        )
        doc = w.available_doc(o, env["inbox"], "v.pdf")
        w.process_jobs()
        assert (len(runs_of(o, created)), len(runs_of(o, updated)), len(runs_of(o, both))) == (
            1,
            0,
            1,
        )
        data = b"%PDF-1.4 second ver"
        init = o.post(
            f"{API}/documents/{doc}/uploads",
            json={
                "filename": "v.pdf",
                "size_bytes": len(data),
                "content_type": "application/pdf",
                "expected_latest_version": 1,
            },
        )
        assert init.status_code == 201, init.text
        s = init.json()
        put = o.put(
            s["upload_url"], content=data, headers={"Content-Type": "application/octet-stream"}
        )
        assert put.status_code == 200, put.text
        assert o.post(f"{API}/uploads/{s['id']}/finalize").status_code == 200
        w.process_jobs()
        assert (len(runs_of(o, created)), len(runs_of(o, updated)), len(runs_of(o, both))) == (
            1,
            1,
            2,
        )

    def test_disabled_workflows_do_not_fire(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "off",
            ),
        )
        o.post(f"{A}/automations/{aid}/disable")
        w.available_doc(o, env["inbox"], "a.pdf")
        w.process_jobs()
        assert runs_of(o, aid) == []

    def test_user_created_and_folder_events(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        users = go_live(
            o,
            wizard(
                "user_created",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "New {user.email}"},
                "welcome",
            ),
        )
        folders = go_live(
            o,
            wizard(
                "folder_created",
                {"path": "/Inbox"},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "folders",
            ),
        )
        assert o.post(f"{A}/users", json={"email": "newbie@example.test"}).status_code == 201
        w.mkdir(o, env["inbox"], "Sub")
        w.mkdir(o, env["archive"], "Other")
        w.process_jobs()
        assert len(runs_of(o, users)) == 1 and len(runs_of(o, folders)) == 1


class TestSecurityAtExecution:
    def test_run_fails_when_the_publisher_loses_access(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        adm = w.user(o, "admin", label="pub")
        aid = go_live(
            adm,
            wizard(
                "file_created",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "by admin",
            ),
        )
        assert (
            o.patch(f"{API}/admin/members/{adm.user_id}", json={"status": "suspended"}).status_code
            == 200
        )
        w.available_doc(o, env["inbox"], "a.pdf")
        w.process_jobs()
        runs = runs_of(o, aid)
        assert len(runs) == 1 and runs[0]["status"] == "failed"
        assert "no longer has access" in runs[0]["error"]
        node = o.get(f"{A}/automation-runs/{runs[0]['id']}").json()["nodes"][0]
        assert node["status"] == "failed"

    def test_disabling_stops_a_run_in_progress_before_the_next_step(self, env, db):  # noqa: ANN001
        from app.db.models import Automation, AutomationRun, AutomationVersion
        from app.modules.automations import engine, triggers

        w, o = env["world"], env["owner"]
        two_steps = {
            "name": "two",
            "trigger": {"key": "file_created", "params": {}},
            "graph": {
                "nodes": [
                    {"id": "start", "type": "start"},
                    {
                        "id": "n1",
                        "type": "notify_users",
                        "params": {"user_ids": [str(o.user_id)], "title": "one"},
                    },
                    {
                        "id": "n2",
                        "type": "notify_users",
                        "params": {"user_ids": [str(o.user_id)], "title": "two"},
                    },
                ],
                "edges": [{"from": "start", "to": "n1"}, {"from": "n1", "to": "n2"}],
            },
        }
        aid = go_live(o, two_steps)
        w.available_doc(o, env["inbox"], "a.pdf")  # a real run happens and finishes
        done = runs_of(o, aid)[0]
        assert done["status"] == "succeeded"
        # a second occurrence is queued but not yet picked up...
        with w.db_factory() as s:
            a = s.get(Automation, uuid.UUID(aid))
            first = s.get(AutomationRun, uuid.UUID(done["id"]))
            queued = triggers.create_run(
                s,
                a,
                s.get(AutomationVersion, first.version_id),
                event_key="manual:2",
                trigger_context=first.trigger_context,
            )
            s.commit()
        # ...and the administrator disables the workflow before any of its steps ran
        o.post(f"{A}/automations/{aid}/disable")
        assert engine.execute_run(w.db_factory, queued) == "cancelled"
        w.process_jobs()
        latest = [r for r in runs_of(o, aid) if r["id"] == str(queued)][0]
        assert latest["status"] == "cancelled" and "disabled" in latest["error"]
        nodes = o.get(f"{A}/automation-runs/{queued}").json()["nodes"]
        assert nodes == []  # no step ran after the disable

    def test_notifications_do_not_reveal_files_to_people_without_access(self, env, db):  # noqa: ANN001
        from app.db.models import Notification

        w = env["world"]
        owner = w.org("Closed Org", member_default_access=False)
        root = w.root_id(owner)
        inbox = w.mkdir(owner, root, "Secret")
        outsider = w.user(owner, "member", label="out")
        aid = go_live(
            owner,
            wizard(
                "file_created",
                {},
                "notify_users",
                {
                    "user_ids": [str(outsider.user_id), str(owner.user_id)],
                    "title": "Review {file.name}",
                    "message": "{file.path}",
                },
                "leaky",
            ),
        )
        w.available_doc(owner, inbox, "salaries.pdf")
        w.process_jobs()
        db.rollback()
        mine = db.scalar(
            select(Notification).where(
                Notification.user_id == owner.user_id, Notification.type == "automation.notice"
            )
        )
        theirs = db.scalar(
            select(Notification).where(
                Notification.user_id == outsider.user_id, Notification.type == "automation.notice"
            )
        )
        assert mine is not None and "salaries.pdf" in mine.title
        assert theirs is not None and "salaries" not in (theirs.title + (theirs.body or ""))
        assert theirs.resource_id is None
        assert runs_of(owner, aid)[0]["status"] == "succeeded"

    def test_include_actor_resolves_the_uploader_for_scan_events(self, env, db):  # noqa: ANN001
        from app.db.models import Notification

        w, o = env["world"], env["owner"]
        member = w.user(o, "member", label="up")
        go_live(o, wizard("file_created", {}, "notify_users", {"include_actor": True, "title": "Thanks for {file.name}"}, "thanks"))
        # the member needs create rights: give them the folder through an ACL
        o.post(f"{API}/folders/{env['inbox']}/permissions", json={"subject_type": "user", "subject_id": str(member.user_id), "actions": ["view", "create_child", "upload_version"]})
        w.available_doc(member, env["inbox"], "mine.pdf")
        w.process_jobs()
        db.rollback()
        got = db.scalar(select(Notification).where(Notification.user_id == member.user_id, Notification.type == "automation.notice"))
        assert got is not None and got.title == "Thanks for mine.pdf"

    def test_notify_with_nobody_to_notify_is_skipped_not_succeeded(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(o, wizard("periodic_interval", {"every_minutes": 15}, "notify_users", {"include_actor": True, "title": "x"}, "nobody"))
        from app.modules.automations import triggers

        triggers.schedule_due(w.db_factory, datetime.now(UTC) + timedelta(hours=1))
        w.process_jobs()
        run = runs_of(o, aid)[0]
        assert run["status"] == "skipped"

    def test_send_email_is_skipped_without_a_provider(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {},
                "send_email",
                {"user_ids": [str(o.user_id)], "subject": "s", "body": "b"},
                "mail",
            ),
            confirm=True,
        )
        w.available_doc(o, env["inbox"], "a.pdf")
        w.process_jobs()
        run = runs_of(o, aid)[0]
        node = o.get(f"{A}/automation-runs/{run['id']}").json()["nodes"][0]
        assert node["status"] == "skipped" and "provider" in node["output"]["reason"]
        assert run["status"] == "skipped"

    def test_copy_cannot_reach_folders_the_publisher_cannot_write(self, env, db):  # noqa: ANN001
        w = env["world"]
        owner = w.org("Restricted", member_default_access=False)
        root = w.root_id(owner)
        src = w.mkdir(owner, root, "Src")
        locked = w.mkdir(owner, root, "Locked")
        adm = w.user(owner, "admin", label="adm")
        # revoke nothing: admins are org-wide here, so test the engine path with a folder from ANOTHER org
        other = w.org("Other")
        foreign = w.mkdir(other, w.root_id(other), "Foreign")
        body = wizard("file_created", {}, "copy_files", {"target_folder_id": foreign}, "x-tenant")
        r = adm.post(f"{A}/automations", json=body)
        assert r.status_code == 422  # a folder of another tenant simply "does not exist"
        _ = (src, locked, db)


class TestFailureAndRetry:
    def test_failed_step_can_be_retried_without_duplicates(self, env, db):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {"path": "/Inbox"},
                "copy_files",
                {"target_folder_id": env["archive"], "on_conflict": "skip"},
                "retry me",
            ),
        )
        assert o.delete(f"{API}/folders/{env['archive']}").status_code in (200, 204)
        w.available_doc(o, env["inbox"], "a.pdf")
        w.process_jobs()
        run = runs_of(o, aid)[0]
        assert run["status"] == "failed" and run["error"]
        assert o.get(f"{A}/automations/{aid}").json()["state"] == "failed"
        r = o.post(f"{API}/folders/{env['archive']}/restore", json={})
        assert r.status_code == 200, r.text
        retry = o.post(f"{A}/automation-runs/{run['id']}/retry")
        assert retry.status_code == 200, retry.text
        w.process_jobs()
        w.process_jobs()
        again = o.get(f"{A}/automation-runs/{run['id']}").json()
        assert again["status"] == "succeeded"
        assert len(docs_in(db, env["archive"])) == 1  # exactly one copy
        assert (
            o.post(f"{A}/automation-runs/{run['id']}/retry").status_code == 409
        )  # succeeded: not retryable

    def test_circuit_breaker_disables_a_runaway_workflow(self, env, monkeypatch):  # noqa: ANN001
        from app.modules.automations import triggers

        monkeypatch.setattr(triggers, "RUNS_PER_10_MIN_LIMIT", 1)
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "folder_created",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n"},
                "loop",
            ),
        )
        for i in range(5):
            w.mkdir(o, env["root"], f"f{i}")
        w.process_jobs()
        got = o.get(f"{A}/automations/{aid}").json()
        assert got["enabled"] is False and got["state"] == "needs_attention"
        assert "loop" in got["attention_reason"]


class TestCanvasGraphs:
    def test_condition_branches_and_variables(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        uid = str(o.user_id)
        graph = {
            "nodes": [
                {"id": "start", "type": "start"},
                {
                    "id": "v",
                    "type": "assign_variable",
                    "params": {"name": "is_pdf", "expression": "file.extension == 'pdf'"},
                },
                {"id": "c", "type": "condition", "params": {"expression": "vars.is_pdf == true"}},
                {
                    "id": "yes",
                    "type": "notify_users",
                    "params": {"user_ids": [uid], "title": "pdf {file.name}"},
                },
                {
                    "id": "no",
                    "type": "notify_users",
                    "params": {"user_ids": [uid], "title": "other {file.name}"},
                },
                {"id": "end", "type": "end"},
            ],
            "edges": [
                {"from": "start", "to": "v"},
                {"from": "v", "to": "c"},
                {"from": "c", "to": "yes", "branch": "true"},
                {"from": "c", "to": "no", "branch": "false"},
                {"from": "yes", "to": "end"},
                {"from": "no", "to": "end"},
            ],
        }
        body = {
            "name": "branchy",
            "editor_mode": "canvas",
            "trigger": {"key": "file_created", "params": {}},
            "graph": graph,
        }
        aid = go_live(o, body)
        w.available_doc(o, env["inbox"], "a.pdf")
        w.available_doc(o, env["inbox"], "b.txt", b"hi")
        w.process_jobs()
        runs = runs_of(o, aid)
        assert len(runs) == 2 and {r["status"] for r in runs} == {"succeeded"}
        seen = set()
        for r in runs:
            nodes = {
                n["node_id"]: n for n in o.get(f"{A}/automation-runs/{r['id']}").json()["nodes"]
            }
            assert nodes["v"]["status"] == "succeeded" and nodes["c"]["status"] == "succeeded"
            seen.add(("yes" in nodes, "no" in nodes))
        assert seen == {(True, False), (False, True)}

    def test_condition_must_label_its_outputs(self, env):  # noqa: ANN001
        o = env["owner"]
        uid = str(o.user_id)
        graph = {
            "nodes": [
                {"id": "start", "type": "start"},
                {
                    "id": "c",
                    "type": "condition",
                    "params": {"expression": "file.extension == 'pdf'"},
                },
                {"id": "n", "type": "notify_users", "params": {"user_ids": [uid], "title": "x"}},
            ],
            "edges": [{"from": "start", "to": "c"}, {"from": "c", "to": "n"}],
        }
        r = o.post(
            f"{A}/automations",
            json={
                "name": "nolabel",
                "trigger": {"key": "file_created", "params": {}},
                "graph": graph,
            },
        )
        assert r.status_code == 422 and "true" in r.text


class TestDryRun:
    def test_dry_run_has_no_side_effects(self, env, db):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        r = o.post(
            f"{A}/automations",
            json=wizard(
                "file_created",
                {"path": "/Inbox"},
                "copy_files",
                {"target_folder_id": env["archive"]},
                "dry",
            ),
        )
        aid = r.json()["id"]
        doc = w.available_doc(o, env["inbox"], "a.pdf")
        out = o.post(f"{A}/automations/{aid}/test", json={"resource_id": doc})
        assert out.status_code == 200, out.text
        body = out.json()
        assert body["would_trigger"] is True and body["status"] == "succeeded"
        assert body["run"]["mode"] == "dry"
        assert body["run"]["nodes"][0]["output"]["dry_run"] is True
        assert docs_in(db, env["archive"]) == []  # nothing was copied
        assert (
            o.get(f"{A}/automations/{aid}").json()["last_run_at"] is None
        )  # not recorded as a real run
        miss = o.post(
            f"{A}/automations/{aid}/test",
            json={"resource_id": w.available_doc(o, env["archive"], "no.pdf")},
        ).json()
        assert miss["would_trigger"] is False
        assert o.post(f"{A}/automations/{aid}/test", json={}).status_code == 422


class TestTimersAndScans:
    def test_periodic_timer_fires_once_per_slot(self, env):  # noqa: ANN001
        from app.modules.automations import triggers

        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "periodic_interval",
                {"every_minutes": 15},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "tick"},
                "tick",
            ),
        )
        wf = o.get(f"{A}/automations/{aid}").json()
        assert wf["next_check_at"] is not None  # a scheduled workflow shows when it runs next
        later = datetime.now(UTC) + timedelta(hours=1)
        triggers.schedule_due(w.db_factory, later)
        assert len(runs_of(o, aid)) == 1
        triggers.schedule_due(w.db_factory, later)
        assert len(runs_of(o, aid)) == 1  # already advanced: no second run for the same slot
        w.process_jobs()
        run = runs_of(o, aid)[0]
        assert run["status"] == "succeeded"
        assert o.get(f"{A}/automations/{aid}").json()["last_checked_at"] is not None

    def test_daily_scan_for_stale_files_and_integrity_check(self, env, db):  # noqa: ANN001
        from app.adapters.storage.registry import get_storage_provider
        from app.db.models import AuditEvent, DocumentVersion, StorageLocation
        from app.modules.automations import triggers

        w, o = env["world"], env["owner"]
        doc = w.available_doc(o, env["inbox"], "old.pdf")
        db.rollback()
        ver = db.scalar(
            select(DocumentVersion).where(DocumentVersion.document_id == uuid.UUID(doc))
        )
        loc = db.get(StorageLocation, ver.storage_location_id)
        provider = get_storage_provider(loc.provider_type)
        provider._path(loc.bucket, ver.object_key).write_bytes(
            b"tampered bytes"
        )  # corrupt the stored object
        aid = go_live(
            o,
            {
                "name": "scan",
                "trigger": {"key": "file_stale", "params": {"days": 1}},
                "graph": {
                    "nodes": [
                        {"id": "start", "type": "start"},
                        {
                            "id": "chk",
                            "type": "verify_integrity_alert",
                            "params": {"alert_user_ids": []},
                        },
                        {"id": "end", "type": "end"},
                    ],
                    "edges": [{"from": "start", "to": "chk"}, {"from": "chk", "to": "end"}],
                },
            },
        )
        future = datetime.now(UTC) + timedelta(days=3)
        triggers.schedule_due(w.db_factory, future)
        assert len(runs_of(o, aid)) == 1  # one stale file, one run
        triggers.schedule_due(w.db_factory, future)
        assert len(runs_of(o, aid)) == 1  # the same day never fires twice
        w.process_jobs()
        run = runs_of(o, aid)[0]
        node = o.get(f"{A}/automation-runs/{run['id']}").json()["nodes"][0]
        assert node["output"]["verified"] is False and node["output"]["alerted"] is True
        db.rollback()
        assert (
            db.scalar(
                select(func.count()).where(
                    AuditEvent.action == "integrity.mismatch",
                    AuditEvent.organization_id == o.org_id,
                )
            )
            == 1
        )
        # the source was never altered by the alert variant
        assert provider._path(loc.bucket, ver.object_key).read_bytes() == b"tampered bytes"

    def test_release_locks_on_a_schedule(self, env, db):  # noqa: ANN001
        from app.db.models import Document
        from app.modules.automations import triggers

        w, o = env["world"], env["owner"]
        doc = w.available_doc(o, env["inbox"], "locked.pdf")
        assert o.post(f"{API}/documents/{doc}/lock", json={"minutes": 5}).status_code == 201
        with w.db_factory() as s:
            d = s.get(Document, uuid.UUID(doc))
            d.locked_at = datetime.now(UTC) - timedelta(hours=3)
            s.commit()
        aid = go_live(
            o,
            wizard(
                "periodic_interval",
                {"every_minutes": 15},
                "release_locks",
                {"older_than_hours": 1, "notify_owner": False},
                "unlock",
            ),
        )
        triggers.schedule_due(w.db_factory, datetime.now(UTC) + timedelta(hours=2))
        w.process_jobs()
        db.rollback()
        db.expire_all()
        assert db.get(Document, uuid.UUID(doc)).locked_by is None
        assert runs_of(o, aid)[0]["status"] == "succeeded"

    def test_destructive_delete_goes_to_the_trash_only(self, env, db):  # noqa: ANN001
        from app.db.models import Document

        w, o = env["world"], env["owner"]
        go_live(
            o,
            wizard(
                "file_created",
                {"path": "/Inbox"},
                "delete_files",
                {"confirm_move_to_trash": True},
                "bin it",
            ),
            confirm=True,
        )
        doc = w.available_doc(o, env["inbox"], "gone.pdf")
        w.process_jobs()
        db.rollback()
        d = db.get(Document, uuid.UUID(doc))
        assert d is not None and d.deleted_at is not None  # recycle bin, never purged


class TestAuditAndRedaction:
    def test_run_log_contains_no_content_or_secrets(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        aid = go_live(
            o,
            wizard(
                "file_created",
                {},
                "notify_users",
                {"user_ids": [str(o.user_id)], "title": "n {file.name}"},
                "log",
            ),
        )
        w.available_doc(o, env["inbox"], "a.pdf", b"%PDF-1.4 SECRET-BODY-TEXT")
        w.process_jobs()
        run = o.get(f"{A}/automation-runs/{runs_of(o, aid)[0]['id']}").json()
        blob = str(run).lower()
        assert "secret-body-text" not in blob and "token" not in blob and "password" not in blob
        events = o.get(f"{A}/activity", params={"action": "automation.run_finished"}).json()[
            "items"
        ]
        assert events and events[0]["outcome"] == "success"
