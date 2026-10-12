"""Workflow studio: human approval with approved / rejected / timeout exits, manual start by people,
access-request workflows (grant / deny), exclusive vs additive bindings, and the run views."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

pytestmark = pytest.mark.integration
API = "/api/v1"
A = f"{API}/admin"
PDF = b"%PDF-1.4 studio"


def go_live(actor, body, confirm=False):  # noqa: ANN001, ANN201
    r = actor.post(f"{A}/automations", json=body)
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    p = actor.post(f"{A}/automations/{aid}/publish", json={"confirm_high_risk": confirm})
    assert p.status_code == 200, p.text
    e = actor.post(f"{A}/automations/{aid}/enable")
    assert e.status_code == 200, e.text
    return aid


def notify(owner, title):  # noqa: ANN001, ANN201
    return {"user_ids": [str(owner.user_id)], "title": title}


def graph_approval(owner, approvers, *, timeout_days=None, completion="any"):  # noqa: ANN001, ANN201
    params = {"user_ids": [str(u.user_id) for u in approvers], "completion": completion}
    if timeout_days:
        params["timeout_days"] = timeout_days
    return {
        "nodes": [
            {"id": "start", "type": "start"},
            {"id": "h", "type": "human_approval", "params": params},
            {"id": "ok", "type": "notify_users", "params": notify(owner, "Approved {file.name}")},
            {"id": "no", "type": "notify_users", "params": notify(owner, "Rejected {file.name}")},
            {"id": "late", "type": "notify_users", "params": notify(owner, "No answer")},
            {"id": "end", "type": "end"},
        ],
        "edges": [
            {"from": "start", "to": "h"},
            {"from": "h", "to": "ok", "branch": "approved"},
            {"from": "h", "to": "no", "branch": "rejected"},
            {"from": "h", "to": "late", "branch": "timeout"},
            {"from": "ok", "to": "end"},
            {"from": "no", "to": "end"},
            {"from": "late", "to": "end"},
        ],
    }


def body_of(name, trigger, graph, **extra):  # noqa: ANN001, ANN201, ANN003
    return {"name": name, "trigger": trigger, "graph": graph, "editor_mode": "canvas", **extra}


def linear(action_key, params):  # noqa: ANN001, ANN201
    return {
        "nodes": [
            {"id": "start", "type": "start"},
            {"id": "a1", "type": action_key, "params": params},
            {"id": "end", "type": "end"},
        ],
        "edges": [{"from": "start", "to": "a1"}, {"from": "a1", "to": "end"}],
    }


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    owner = world.org("Studio Inc")
    root = world.root_id(owner)
    inbox = world.mkdir(owner, root, "Inbox")
    vault = world.mkdir(owner, root, "Vault")
    mia = world.user(owner, "member", label="mia")
    noah = world.user(owner, "member", label="noah")
    return dict(world=world, owner=owner, root=root, inbox=inbox, vault=vault, mia=mia, noah=noah)


def run_detail(owner, run_id):  # noqa: ANN001, ANN201
    r = owner.get(f"{A}/automation-runs/{run_id}")
    assert r.status_code == 200, r.text
    return r.json()


def only_run(owner, aid):  # noqa: ANN001, ANN201
    items = owner.get(f"{A}/automations/{aid}/runs").json()["items"]
    assert len(items) == 1, items
    return items[0]


def node_states(owner, run_id):  # noqa: ANN001, ANN201
    return {n["node_id"]: n for n in run_detail(owner, run_id)["nodes"]}


def decide(user, decision):  # noqa: ANN001, ANN201
    tasks = user.get(f"{API}/workflow-tasks/mine", params={"status": "pending"}).json()["items"]
    assert len(tasks) == 1, tasks
    r = user.post(f"{API}/workflow-tasks/{tasks[0]['id']}/decision", json={"decision": decision})
    assert r.status_code == 200, r.text


class TestCatalogue:
    def test_new_triggers_and_steps_are_listed_with_their_exits(self, env):  # noqa: ANN001
        c = env["owner"].get(f"{A}/automations/catalogue").json()
        conds = {x["key"]: x for x in c["conditions"]}
        acts = {x["key"]: x for x in c["actions"]}
        assert {"manual_file", "manual_folder", "access_request_created"} <= set(conds)
        assert conds["manual_file"]["kind"] == "manual"
        assert conds["manual_file"]["provides"] == "file"
        assert conds["manual_folder"]["provides"] == "folder"
        assert acts["human_approval"]["outputs"] == ["approved", "rejected", "timeout"]
        assert acts["condition"]["outputs"] == ["true", "false"]
        assert acts["notify_users"]["outputs"] == []
        assert acts["grant_access"]["risk"] == "high"
        assert acts["deny_access"]["needs_resource"] == "access_request"


class TestValidation:
    def check(self, owner, trigger, graph):  # noqa: ANN001, ANN201
        r = owner.post(
            f"{A}/automations/validate", json={"name": "check", "trigger": trigger, "graph": graph}
        )
        assert r.status_code == 200, r.text
        return r.json()

    def test_a_good_approval_graph_is_valid(self, env):  # noqa: ANN001
        o = env["owner"]
        rep = self.check(o, {"key": "file_created", "params": {}}, graph_approval(o, [env["mia"]]))
        assert rep["valid"], rep

    def test_approved_exit_must_be_connected_and_labels_must_be_exits(self, env):  # noqa: ANN001
        o = env["owner"]
        g = graph_approval(o, [env["mia"]])
        g["edges"] = [e for e in g["edges"] if e.get("branch") != "approved"]
        rep = self.check(o, {"key": "file_created", "params": {}}, g)
        assert any("approved" in i["message"] for i in rep["issues"])
        g2 = graph_approval(o, [env["mia"]])
        for e in g2["edges"]:
            if e.get("branch") == "timeout":
                e["branch"] = "true"  # condition vocabulary on an approval step
        rep2 = self.check(o, {"key": "file_created", "params": {}}, g2)
        assert not rep2["valid"]

    def test_unlabelled_or_duplicate_exits_are_refused(self, env):  # noqa: ANN001
        o = env["owner"]
        g = graph_approval(o, [env["mia"]])
        g["edges"][1]["branch"] = None
        assert not self.check(o, {"key": "file_created", "params": {}}, g)["valid"]

    def test_human_approval_needs_people_who_belong_to_the_organization(self, env):  # noqa: ANN001
        o = env["owner"]
        g = graph_approval(o, [env["mia"]])
        g["nodes"][1]["params"]["user_ids"] = []
        assert not self.check(o, {"key": "file_created", "params": {}}, g)["valid"]
        g["nodes"][1]["params"]["user_ids"] = [str(uuid.uuid4())]
        rep = self.check(o, {"key": "file_created", "params": {}}, g)
        assert any("members" in i["message"] for i in rep["issues"])

    def test_it_needs_a_file_so_a_folder_trigger_is_refused(self, env):  # noqa: ANN001
        o = env["owner"]
        rep = self.check(
            o, {"key": "folder_created", "params": {}}, graph_approval(o, [env["mia"]])
        )
        assert any("needs a file" in i["message"] for i in rep["issues"])

    def test_grant_and_deny_need_an_access_request_trigger(self, env):  # noqa: ANN001
        o = env["owner"]
        for key, prm in (("grant_access", {"actions": ["view"]}), ("deny_access", {})):
            rep = self.check(o, {"key": "file_created", "params": {}}, linear(key, prm))
            assert any("access request" in i["message"] for i in rep["issues"]), rep
            ok = self.check(o, {"key": "access_request_created", "params": {}}, linear(key, prm))
            assert ok["valid"], ok

    def test_grant_cannot_name_write_level_actions(self, env):  # noqa: ANN001
        o = env["owner"]
        rep = self.check(
            o,
            {"key": "access_request_created", "params": {}},
            linear("grant_access", {"actions": ["delete"]}),
        )
        assert not rep["valid"]


class TestHumanApproval:
    def test_approved_exit_runs_and_the_others_do_not(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = go_live(
            o,
            body_of(
                "Approve new files",
                {"key": "file_created", "params": {"path": "/Inbox"}},
                graph_approval(o, [mia]),
            ),
        )
        w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        run = only_run(o, aid)
        assert run["status"] == "waiting"
        nodes = node_states(o, run["id"])
        assert nodes["h"]["status"] == "waiting" and "ok" not in nodes
        decide(mia, "approve")
        w.process_jobs()  # the approval finishing wakes the run: no waiting for maintenance
        run = only_run(o, aid)
        assert run["status"] == "succeeded", run
        nodes = node_states(o, run["id"])
        assert nodes["h"]["output"]["branch"] == "approved"
        assert nodes["ok"]["status"] == "succeeded" and "no" not in nodes and "late" not in nodes

    def test_rejected_exit_is_a_normal_outcome_not_a_failure(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = go_live(
            o,
            body_of(
                "Approve or reject",
                {"key": "file_created", "params": {"path": "/Inbox"}},
                graph_approval(o, [mia]),
            ),
        )
        w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        decide(mia, "reject")
        w.process_jobs()
        run = only_run(o, aid)
        assert run["status"] == "succeeded", run
        nodes = node_states(o, run["id"])
        assert nodes["h"]["output"]["branch"] == "rejected"
        assert nodes["no"]["status"] == "succeeded" and "ok" not in nodes

    def test_no_decision_in_time_takes_the_timeout_exit_and_closes_the_approval(self, env):  # noqa: ANN001
        from app.db.models import AutomationNodeRun, WorkflowRun
        from app.modules.automations import engine

        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = go_live(
            o,
            body_of(
                "Approve within a day",
                {"key": "file_created", "params": {"path": "/Inbox"}},
                graph_approval(o, [mia], timeout_days=1),
            ),
        )
        w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        run = only_run(o, aid)
        assert run["status"] == "waiting"
        with w.db_factory() as db:  # pretend the question was asked three days ago
            nr = db.scalar(
                select(AutomationNodeRun).where(
                    AutomationNodeRun.run_id == uuid.UUID(run["id"]),
                    AutomationNodeRun.node_id == "h",
                )
            )
            nr.output = {
                **nr.output,
                "asked_at": (datetime.now(UTC) - timedelta(days=3)).isoformat(),
            }
            db.commit()
        engine.resume_waiting(w.db_factory)
        w.process_jobs()
        run = only_run(o, aid)
        assert run["status"] == "succeeded", run
        nodes = node_states(o, run["id"])
        assert nodes["h"]["output"]["branch"] == "timeout"
        assert nodes["late"]["status"] == "succeeded" and "ok" not in nodes
        approval_id = uuid.UUID(nodes["h"]["output"]["approval_run_id"])
        with w.db_factory() as db:
            assert db.get(WorkflowRun, approval_id).state == "cancelled"
        assert (
            mia.get(f"{API}/workflow-tasks/mine", params={"status": "pending"}).json()["items"]
            == []
        )

    def test_republishing_adds_a_version_instead_of_new_definitions(self, env):  # noqa: ANN001
        from app.db.models import WorkflowDefinition

        w, o, mia, noah = env["world"], env["owner"], env["mia"], env["noah"]
        aid = go_live(
            o,
            body_of(
                "Evolving approval",
                {"key": "file_created", "params": {"path": "/Inbox"}},
                graph_approval(o, [mia]),
            ),
        )
        # the first file is asked of mia and keeps asking her even after the people change
        w.available_doc(o, env["inbox"], "one.pdf", PDF + b"1")
        patched = graph_approval(o, [noah])
        r = o.patch(f"{A}/automations/{aid}", json={"graph": patched})
        assert r.status_code == 200, r.text
        assert o.post(f"{A}/automations/{aid}/publish", json={}).status_code == 200
        w.available_doc(o, env["inbox"], "two.pdf", PDF + b"2")
        assert (
            len(mia.get(f"{API}/workflow-tasks/mine", params={"status": "pending"}).json()["items"])
            == 1
        )
        assert (
            len(
                noah.get(f"{API}/workflow-tasks/mine", params={"status": "pending"}).json()["items"]
            )
            == 1
        )
        with w.db_factory() as db:
            names = list(
                db.scalars(
                    select(WorkflowDefinition.name).where(
                        WorkflowDefinition.name.like(
                            f"Workflow studio: {aid.replace('-', '')[:8]}/%"
                        )
                    )
                )
            )
        assert len(names) == 1  # one stable definition, two versions

    def test_dry_run_previews_the_approved_path_without_asking_anyone(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        doc = w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        r = o.post(
            f"{A}/automations",
            json=body_of(
                "Draft approval",
                {"key": "file_created", "params": {"path": "/Inbox"}},
                graph_approval(o, [mia]),
            ),
        )
        aid = r.json()["id"]
        t = o.post(f"{A}/automations/{aid}/test", json={"resource_id": doc})
        assert t.status_code == 200, t.text
        nodes = {n["node_id"]: n for n in t.json()["run"]["nodes"]}
        assert nodes["h"]["output"]["simulated_exit"] == "approved"
        assert nodes["ok"]["output"]["dry_run"] is True and "no" not in nodes
        assert (
            mia.get(f"{API}/workflow-tasks/mine", params={"status": "pending"}).json()["items"]
            == []
        )


class TestManualStart:
    def publish_manual(self, env, name="Review request", **params):  # noqa: ANN001, ANN201, ANN003
        o = env["owner"]
        trig = {"key": "manual_file", "params": {"path": "/Inbox", **params}}
        return go_live(
            o, body_of(name, trig, linear("notify_users", notify(o, "Started {file.name}")))
        )

    def grant_edit(self, env, user):  # noqa: ANN001, ANN201
        r = env["owner"].post(
            f"{API}/folders/{env['inbox']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(user.user_id),
                "actions": ["view", "edit_metadata", "create_child"],
            },
        )
        assert r.status_code == 201, r.text

    def test_editors_see_and_start_it_and_follow_the_run(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = self.publish_manual(env)
        doc = w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        self.grant_edit(env, mia)
        offered = mia.get(
            f"{API}/automations/startable",
            params={"resource_type": "document", "resource_id": doc},
        ).json()
        assert [x["id"] for x in offered] == [aid]
        s = mia.post(
            f"{API}/automations/{aid}/start",
            json={"resource_type": "document", "resource_id": doc, "note": "please run"},
        )
        assert s.status_code == 202, s.text
        w.process_jobs()
        mine = mia.get(f"{API}/automation-runs/mine").json()
        assert mine["total"] == 1
        run = mine["items"][0]
        assert run["status"] == "succeeded" and run["automation_name"] == "Review request"
        assert run["resource_name"] == "plan.pdf" and run["note"] == "please run"
        assert run["steps"] == [
            {
                "label": "Notify user(s)",
                "status": "succeeded",
                "branch": None,
                "error": None,
                "finished_at": run["steps"][0]["finished_at"],
            }
        ]
        assert mia.get(f"{API}/automation-runs/mine/{run['id']}").status_code == 200
        # the people who can see the file can follow what ran on it; others cannot see my list
        assert env["noah"].get(f"{API}/automation-runs/mine").json()["total"] == 0
        assert env["noah"].get(f"{API}/automation-runs/mine/{run['id']}").status_code == 404
        on_doc = o.get(f"{API}/documents/{doc}/automation-runs").json()
        assert [r["id"] for r in on_doc] == [run["id"]]

    def test_people_without_edit_rights_are_offered_nothing_and_cannot_start(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = self.publish_manual(env)
        doc = w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        q = {"resource_type": "document", "resource_id": doc}
        assert mia.get(f"{API}/automations/startable", params=q).json() == []
        s = mia.post(f"{API}/automations/{aid}/start", json=q)
        assert s.status_code in (403, 404), s.text
        w.process_jobs()
        assert o.get(f"{A}/automations/{aid}/runs").json()["total"] == 0

    def test_admins_only_workflows_are_hidden_from_editors(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = self.publish_manual(env, who_can_start="admins")
        doc = w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        self.grant_edit(env, mia)
        q = {"resource_type": "document", "resource_id": doc}
        assert mia.get(f"{API}/automations/startable", params=q).json() == []
        s = mia.post(f"{API}/automations/{aid}/start", json=q)
        assert s.status_code == 403 and s.json()["error"]["code"] == "admins_only"
        assert [x["id"] for x in o.get(f"{API}/automations/startable", params=q).json()] == [aid]

    def test_scope_and_type_are_enforced(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = self.publish_manual(env)
        outside = w.available_doc(o, env["vault"], "secret.pdf", PDF + b"x")
        self.grant_edit(env, mia)
        o.post(
            f"{API}/folders/{env['vault']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(mia.user_id),
                "actions": ["view", "edit_metadata"],
            },
        )
        q = {"resource_type": "document", "resource_id": outside}
        assert mia.get(f"{API}/automations/startable", params=q).json() == []
        s = mia.post(f"{API}/automations/{aid}/start", json=q)
        assert s.status_code == 422 and s.json()["error"]["code"] == "out_of_scope"
        folder_q = {"resource_type": "folder", "resource_id": env["inbox"]}
        s2 = mia.post(f"{API}/automations/{aid}/start", json=folder_q)
        assert s2.status_code == 422 and s2.json()["error"]["code"] == "wrong_item_type"

    def test_a_disabled_or_event_workflow_cannot_be_started(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = self.publish_manual(env)
        event = go_live(
            o,
            body_of(
                "Event one",
                {"key": "file_created", "params": {"path": "/Nowhere"}},
                linear("notify_users", notify(o, "x")),
            ),
        )
        doc = w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        self.grant_edit(env, mia)
        q = {"resource_type": "document", "resource_id": doc}
        assert mia.post(f"{API}/automations/{event}/start", json=q).status_code == 404
        assert o.post(f"{A}/automations/{aid}/disable").status_code == 200
        assert mia.post(f"{API}/automations/{aid}/start", json=q).status_code == 404
        assert mia.get(f"{API}/automations/startable", params=q).json() == []

    def test_folders_can_be_the_target(self, env):  # noqa: ANN001
        o, mia = env["owner"], env["mia"]
        trig = {"key": "manual_folder", "params": {"path": "/Inbox"}}
        aid = go_live(
            o,
            body_of(
                "Folder kickoff",
                trig,
                linear("create_directory", {"parent_folder_id": env["inbox"], "name": "Kickoff"}),
            ),
        )
        self.grant_edit(env, mia)
        q = {"resource_type": "folder", "resource_id": env["inbox"]}
        assert [x["id"] for x in mia.get(f"{API}/automations/startable", params=q).json()] == [aid]
        assert mia.post(f"{API}/automations/{aid}/start", json=q).status_code == 202
        env["world"].process_jobs()
        assert o.get(f"{A}/automations/{aid}/runs").json()["items"][0]["status"] == "succeeded"


class TestAccessRequests:
    @pytest.fixture()
    def locked(self, world):  # noqa: ANN001, ANN201
        owner = world.org("Locked Inc", member_default_access=False)
        root = world.root_id(owner)
        vault = world.mkdir(owner, root, "Vault")
        doc = world.available_doc(owner, vault, "plan.pdf", PDF)
        asker = world.user(owner, "member", label="asker")
        shared = owner.post(
            f"{API}/folders/{vault}/permissions",
            json={"subject_type": "user", "subject_id": str(asker.user_id), "actions": ["view"]},
        )
        assert shared.status_code == 201, shared.text
        return dict(world=world, owner=owner, vault=vault, doc=doc, asker=asker)

    def ask(self, locked, actions=("download",)):  # noqa: ANN001, ANN201
        r = locked["asker"].post(
            f"{API}/access-requests",
            json={
                "resource_type": "document",
                "resource_id": locked["doc"],
                "actions": list(actions),
                "reason": "I need it for the audit",
            },
        )
        assert r.status_code in (200, 201), r.text
        locked["world"].process_jobs()
        return r.json()["id"]

    def test_grant_access_answers_the_request_with_read_access_only(self, locked):  # noqa: ANN001
        o = locked["owner"]
        aid = go_live(
            o,
            body_of(
                "Auto grant",
                {"key": "access_request_created", "params": {"path": "/Vault"}},
                linear("grant_access", {"actions": ["download"], "expires_in_days": 7}),
            ),
            confirm=True,
        )
        before = locked["asker"].post(f"{API}/documents/{locked['doc']}/download-url", json={})
        assert before.status_code == 403
        rid = self.ask(locked, ("download", "comment"))
        req = locked["asker"].get(f"{API}/access-requests/{rid}").json()
        assert req["status"] == "approved", req
        run = only_run(o, aid)
        assert run["status"] == "succeeded"
        # only what the step allows was granted, although more was asked
        assert node_states(o, run["id"])["a1"]["output"]["granted"] == ["download"]
        after = locked["asker"].post(f"{API}/documents/{locked['doc']}/download-url", json={})
        assert after.status_code == 200, after.text

    def test_deny_access_rejects_with_the_reason(self, locked):  # noqa: ANN001
        o = locked["owner"]
        go_live(
            o,
            body_of(
                "Auto deny",
                {"key": "access_request_created", "params": {}},
                linear("deny_access", {"reason": "Not shared outside finance."}),
            ),
        )
        rid = self.ask(locked)
        req = locked["asker"].get(f"{API}/access-requests/{rid}").json()
        assert req["status"] == "rejected"
        assert req["decision_reason"] == "Not shared outside finance."

    def test_approve_after_a_person_asks_first(self, locked):  # noqa: ANN001
        """Request → Human approval → approved: grant, rejected: deny."""
        w, o = locked["world"], locked["owner"]
        boss = w.user(o, "member", label="boss")
        o.post(
            f"{API}/folders/{locked['vault']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(boss.user_id),
                "actions": ["view", "edit_metadata"],
            },
        )
        graph = {
            "nodes": [
                {"id": "start", "type": "start"},
                {"id": "h", "type": "human_approval", "params": {"user_ids": [str(boss.user_id)]}},
                {"id": "g", "type": "grant_access", "params": {"actions": ["download"]}},
                {"id": "d", "type": "deny_access", "params": {"reason": "Declined by the owner."}},
                {"id": "end", "type": "end"},
            ],
            "edges": [
                {"from": "start", "to": "h"},
                {"from": "h", "to": "g", "branch": "approved"},
                {"from": "h", "to": "d", "branch": "rejected"},
                {"from": "g", "to": "end"},
                {"from": "d", "to": "end"},
            ],
        }
        aid = go_live(
            o,
            body_of("Ask the owner", {"key": "access_request_created", "params": {}}, graph),
            confirm=True,
        )
        rid = self.ask(locked)
        assert locked["asker"].get(f"{API}/access-requests/{rid}").json()["status"] == "pending"
        decide(boss, "approve")
        w.process_jobs()
        assert locked["asker"].get(f"{API}/access-requests/{rid}").json()["status"] == "approved"
        assert only_run(o, aid)["status"] == "succeeded"

    def test_folder_requests_do_not_start_the_workflow(self, locked):  # noqa: ANN001
        o = locked["owner"]
        aid = go_live(
            o,
            body_of(
                "Files only",
                {"key": "access_request_created", "params": {}},
                linear("deny_access", {}),
            ),
        )
        r = locked["asker"].post(
            f"{API}/access-requests",
            json={
                "resource_type": "folder",
                "resource_id": locked["vault"],
                "actions": ["download"],
                "reason": "need the folder",
            },
        )
        assert r.status_code in (200, 201), r.text
        locked["world"].process_jobs()
        assert o.get(f"{A}/automations/{aid}/runs").json()["total"] == 0

    def test_publishing_grant_access_needs_the_owner_and_confirmation(self, locked):  # noqa: ANN001
        o = locked["owner"]
        r = o.post(
            f"{A}/automations",
            json=body_of(
                "Risky",
                {"key": "access_request_created", "params": {}},
                linear("grant_access", {}),
            ),
        )
        aid = r.json()["id"]
        denied = o.post(f"{A}/automations/{aid}/publish", json={})
        assert (
            denied.status_code == 422 and denied.json()["error"]["code"] == "high_risk_confirmation"
        )
        assert (
            o.post(f"{A}/automations/{aid}/publish", json={"confirm_high_risk": True}).status_code
            == 200
        )


class TestBindings:
    def make(self, env, name, mode, path, priority=0):  # noqa: ANN001, ANN201
        o = env["owner"]
        return go_live(
            o,
            body_of(
                name,
                {"key": "file_created", "params": {"path": path} if path else {}},
                linear("notify_users", notify(o, name)),
                binding_mode=mode,
                priority=priority,
            ),
        )

    def runs(self, env, aid):  # noqa: ANN001, ANN201
        return env["owner"].get(f"{A}/automations/{aid}/runs").json()["total"]

    def test_exclusive_most_specific_wins_and_additive_always_runs(self, env):  # noqa: ANN001
        w = env["world"]
        general = self.make(env, "Everywhere", "exclusive", None)
        specific = self.make(env, "Inbox only", "exclusive", "/Inbox")
        extra = self.make(env, "Audit trail", "additive", None)
        w.available_doc(env["owner"], env["inbox"], "a.pdf", PDF)
        assert (self.runs(env, general), self.runs(env, specific), self.runs(env, extra)) == (
            0,
            1,
            1,
        )
        w.available_doc(env["owner"], env["vault"], "b.pdf", PDF + b"b")
        assert (self.runs(env, general), self.runs(env, specific), self.runs(env, extra)) == (
            1,
            1,
            2,
        )

    def test_priority_breaks_a_tie_between_equally_specific_exclusive_workflows(self, env):  # noqa: ANN001
        w = env["world"]
        low = self.make(env, "Low", "exclusive", "/Inbox", priority=1)
        high = self.make(env, "High", "exclusive", "/Inbox", priority=9)
        w.available_doc(env["owner"], env["inbox"], "a.pdf", PDF)
        assert (self.runs(env, low), self.runs(env, high)) == (0, 1)

    def test_binding_can_be_changed_and_is_reported(self, env):  # noqa: ANN001
        o = env["owner"]
        aid = self.make(env, "Switchable", "additive", "/Inbox")
        out = o.patch(f"{A}/automations/{aid}", json={"binding_mode": "exclusive", "priority": 4})
        assert out.status_code == 200, out.text
        assert out.json()["binding_mode"] == "exclusive" and out.json()["priority"] == 4
        copy = o.post(f"{A}/automations/{aid}/duplicate").json()
        assert copy["binding_mode"] == "exclusive" and copy["priority"] == 4
        bad = o.patch(f"{A}/automations/{aid}", json={"binding_mode": "sometimes"})
        assert bad.status_code == 422


class TestRunViews:
    def test_everyone_runs_view_is_admin_only_and_filterable(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        aid = go_live(
            o,
            body_of(
                "Seen",
                {"key": "file_created", "params": {"path": "/Inbox"}},
                linear("notify_users", notify(o, "x")),
            ),
        )
        w.available_doc(o, env["inbox"], "a.pdf", PDF)
        assert mia.get(f"{A}/automation-runs").status_code == 403
        allr = o.get(f"{A}/automation-runs").json()
        assert allr["total"] == 1 and allr["items"][0]["automation_id"] == aid
        assert o.get(f"{A}/automation-runs", params={"status": "failed"}).json()["total"] == 0
        assert o.get(f"{A}/automation-runs", params={"automation_id": aid}).json()["total"] == 1

    def test_non_admins_never_see_step_parameters_or_raw_output(self, env):  # noqa: ANN001
        w, o, mia = env["world"], env["owner"], env["mia"]
        doc = w.available_doc(o, env["inbox"], "a.pdf", PDF)
        aid = go_live(
            o,
            body_of(
                "Quiet",
                {"key": "manual_file", "params": {"path": "/Inbox"}},
                linear("notify_users", notify(o, "secret title {file.name}")),
            ),
        )
        o.post(
            f"{API}/folders/{env['inbox']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(mia.user_id),
                "actions": ["view", "edit_metadata"],
            },
        )
        mia.post(
            f"{API}/automations/{aid}/start", json={"resource_type": "document", "resource_id": doc}
        )
        w.process_jobs()
        text = mia.get(f"{API}/automation-runs/mine").text
        assert "secret title" not in text and "output" not in text and "params" not in text


class TestManualStartWithApproval:
    def test_the_starters_note_reaches_the_approvers(self, env):  # noqa: ANN001
        from app.db.models import WorkflowRun

        w, o, mia, noah = env["world"], env["owner"], env["mia"], env["noah"]
        graph = graph_approval(o, [mia])
        aid = go_live(
            o,
            body_of(
                "Ask mia",
                {"key": "manual_file", "params": {"path": "/Inbox"}},
                graph,
            ),
        )
        doc = w.available_doc(o, env["inbox"], "plan.pdf", PDF)
        o.post(
            f"{API}/folders/{env['inbox']}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(noah.user_id),
                "actions": ["view", "edit_metadata"],
            },
        )
        s = noah.post(
            f"{API}/automations/{aid}/start",
            json={"resource_type": "document", "resource_id": doc, "note": "needed by Friday"},
        )
        assert s.status_code == 202, s.text
        w.process_jobs()
        with w.db_factory() as db:
            note = db.scalar(
                select(WorkflowRun.note)
                .where(WorkflowRun.document_id == uuid.UUID(doc))
                .order_by(WorkflowRun.created_at.desc())
            )
        assert note and "needed by Friday" in note and "Approve plan.pdf" in note
        # noah follows his own run; the approval is mia's to decide
        run = noah.get(f"{API}/automation-runs/mine").json()["items"][0]
        assert run["status"] == "waiting" and run["steps"][0]["status"] == "waiting"
        decide(mia, "approve")
        w.process_jobs()
        done = noah.get(f"{API}/automation-runs/mine/{run['id']}").json()
        assert done["status"] == "succeeded"
        assert done["steps"][0]["branch"] == "approved"
