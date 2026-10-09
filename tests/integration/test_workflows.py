"""Approval workflows: sequential/parallel/conditional steps, rejection, resubmission, delegation,
idempotency, concurrency, access for reviewers, versioning and deadlines."""

from __future__ import annotations

import threading
import uuid

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

PDF = b"%PDF-1.4 workflow"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Flow", member_default_access=True)
    root = world.root_id(admin)
    author = world.user(admin, "member", label="author")
    folder = world.mkdir(admin, root, "contracts")
    admin.post(
        f"/api/v1/folders/{folder}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(author.user_id),
            "actions": ["view", "edit_metadata", "create_child", "upload_version"],
        },
    )
    reviewers = {n: world.user(admin, "member", label=n) for n in ("alice", "bob", "carol")}
    doc = world.available_doc(author, folder, "contract.pdf", PDF + b" contract")
    return dict(
        world=world,
        admin=admin,
        root=root,
        folder=folder,
        author=author,
        reviewers=reviewers,
        doc=doc,
    )


def user_assignee(u):  # noqa: ANN001, ANN202
    return {"type": "user", "id": str(u.user_id)}


def make_flow(env, steps, name="Contract approval"):  # noqa: ANN001, ANN202
    r = env["admin"].post("/api/v1/admin/workflows", json={"name": name, "steps": steps})
    assert r.status_code == 201, r.text
    return r.json()


def start(env, flow, note="please review", actor=None, doc=None):  # noqa: ANN001, ANN202
    actor = actor or env["author"]
    return actor.post(
        f"/api/v1/documents/{doc or env['doc']}/workflow-runs",
        json={"definition_id": flow["id"], "note": note},
    )


def my_tasks(user, status="pending"):  # noqa: ANN001, ANN202
    return user.get("/api/v1/workflow-tasks/mine", params={"status": status}).json()["items"]


def decide(user, task_id, decision="approve", comment=None):  # noqa: ANN001, ANN202
    return user.post(
        f"/api/v1/workflow-tasks/{task_id}/decision",
        json={"decision": decision, "comment": comment},
    )


class TestSequentialApproval:
    def test_two_step_sequence_completes_and_notifies(self, env):  # noqa: ANN001
        rv, w = env["reviewers"], env["world"]
        flow = make_flow(
            env,
            [
                {"name": "Legal", "assignees": [user_assignee(rv["alice"])]},
                {"name": "Finance", "assignees": [user_assignee(rv["bob"])]},
            ],
        )
        run = start(env, flow).json()
        assert run["state"] == "in_progress" and run["current_step"] == 0
        w.process_jobs()  # deliver notifications while alice's task is still open
        assert any(
            n["type"] == "workflow.task_assigned"
            for n in rv["alice"].get("/api/v1/notifications").json()["items"]
        )
        assert [s["status"] for s in run["steps"]] == ["active", "upcoming"]
        assert my_tasks(rv["bob"]) == []  # step 2 not started yet
        t1 = my_tasks(rv["alice"])[0]
        assert (
            t1["document_name"] == "contract.pdf"
            and t1["document_version_number"] == 1
            and t1["note"] == "please review"
        )
        assert decide(rv["alice"], t1["id"], comment="legal ok").status_code == 200
        t2 = my_tasks(rv["bob"])[0]
        assert decide(rv["bob"], t2["id"]).status_code == 200
        final = env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()
        assert final["state"] == "approved" and [s["status"] for s in final["steps"]] == [
            "approved",
            "approved",
        ]
        assert [a["action"] for a in final["actions"]][:2] == ["submitted", "step_started"]
        assert final["actions"][-1]["action"] == "run_approved"
        w.process_jobs()
        types = {n["type"] for n in env["author"].get("/api/v1/notifications").json()["items"]}
        assert "workflow.approved" in types
        audit = {
            e["action"]
            for e in env["admin"]
            .get("/api/v1/admin/audit-events", params={"limit": 100})
            .json()["items"]
        }
        assert {"workflow.started", "workflow.task_approved", "workflow.approved"} <= audit

    def test_rejection_ends_the_run_and_resubmission_creates_a_new_one(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {"name": "Legal", "assignees": [user_assignee(rv["alice"])]},
                {"name": "CFO", "assignees": [user_assignee(rv["bob"])]},
            ],
        )
        run = start(env, flow).json()
        assert (
            decide(
                rv["alice"], my_tasks(rv["alice"])[0]["id"], "reject", "clause 4 is wrong"
            ).status_code
            == 200
        )
        r = env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()
        assert r["state"] == "rejected" and r["outcome_comment"] == "clause 4 is wrong"
        assert my_tasks(rv["bob"]) == []  # later steps never started
        again = env["author"].post(
            f"/api/v1/workflow-runs/{run['id']}/resubmit", json={"comment": "fixed clause 4"}
        )
        assert (
            again.status_code == 201
            and again.json()["resubmitted_from_run_id"] == run["id"]
            and again.json()["state"] == "in_progress"
        )
        # only rejected runs can be resubmitted; an in-flight one blocks a second start
        assert (
            env["author"].post(f"/api/v1/workflow-runs/{run['id']}/resubmit", json={}).status_code
            == 409
        )
        assert start(env, flow).status_code == 409


class TestParallelAndRules:
    def test_all_rule_needs_every_approval_and_one_rejection_fails(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {
                    "name": "Board",
                    "rule": "all",
                    "assignees": [
                        user_assignee(rv["alice"]),
                        user_assignee(rv["bob"]),
                        user_assignee(rv["carol"]),
                    ],
                }
            ],
        )
        run = start(env, flow).json()
        assert len(run["tasks"]) == 3
        decide(rv["alice"], my_tasks(rv["alice"])[0]["id"])
        decide(rv["bob"], my_tasks(rv["bob"])[0]["id"])
        assert (
            env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()["state"] == "in_progress"
        )
        decide(rv["carol"], my_tasks(rv["carol"])[0]["id"])
        assert env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()["state"] == "approved"

    def test_one_rejection_in_an_all_step_cancels_the_others(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {
                    "name": "Board",
                    "rule": "all",
                    "assignees": [user_assignee(rv["alice"]), user_assignee(rv["bob"])],
                }
            ],
        )
        run = start(env, flow).json()
        decide(rv["alice"], my_tasks(rv["alice"])[0]["id"], "reject")
        final = env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()
        assert final["state"] == "rejected"
        assert sorted(t["status"] for t in final["tasks"]) == ["cancelled", "rejected"]
        assert my_tasks(rv["bob"]) == []

    def test_any_rule_first_approval_wins_and_all_rejected_fails(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {
                    "name": "Any",
                    "rule": "any",
                    "assignees": [user_assignee(rv["alice"]), user_assignee(rv["bob"])],
                }
            ],
            name="any-flow",
        )
        run = start(env, flow).json()
        decide(
            rv["alice"], my_tasks(rv["alice"])[0]["id"], "reject"
        )  # one rejection does not fail an 'any' step
        assert (
            env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()["state"] == "in_progress"
        )
        decide(rv["bob"], my_tasks(rv["bob"])[0]["id"], "approve")
        assert env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()["state"] == "approved"

        flow2 = make_flow(
            env,
            [
                {
                    "name": "Any2",
                    "rule": "any",
                    "assignees": [user_assignee(rv["alice"]), user_assignee(rv["bob"])],
                }
            ],
            name="any-flow-2",
        )
        doc2 = env["world"].available_doc(env["author"], env["folder"], "second.pdf", PDF + b" 2")
        run2 = start(env, flow2, doc=doc2).json()
        decide(rv["alice"], my_tasks(rv["alice"])[0]["id"], "reject")
        decide(rv["bob"], my_tasks(rv["bob"])[0]["id"], "reject")
        assert (
            env["author"].get(f"/api/v1/workflow-runs/{run2['id']}").json()["state"] == "rejected"
        )

    def test_group_and_role_assignees_resolve_members(self, env):  # noqa: ANN001
        rv, admin = env["reviewers"], env["admin"]
        g = admin.post("/api/v1/admin/groups", json={"name": "Legal team"}).json()
        for u in (rv["alice"], rv["bob"]):
            admin.post(f"/api/v1/admin/groups/{g['id']}/members", json={"user_id": str(u.user_id)})
        flow = make_flow(
            env,
            [
                {"name": "Legal", "rule": "any", "assignees": [{"type": "group", "id": g["id"]}]},
                {"name": "Admin sign-off", "assignees": [{"type": "role", "role": "owner"}]},
            ],
        )
        run = start(env, flow).json()
        assert {t["assignee"]["id"] for t in run["tasks"]} == {
            str(rv["alice"].user_id),
            str(rv["bob"].user_id),
        }
        decide(rv["alice"], my_tasks(rv["alice"])[0]["id"])
        owner_tasks = my_tasks(admin)
        assert len(owner_tasks) == 1 and owner_tasks[0]["step_name"] == "Admin sign-off"


class TestConditionalSteps:
    def test_steps_are_skipped_or_run_based_on_document_attributes(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {"name": "Always", "assignees": [user_assignee(rv["alice"])]},
                {
                    "name": "Big files only",
                    "assignees": [user_assignee(rv["bob"])],
                    "condition": {"field": "size_bytes", "op": "gt", "value": 10_000_000},
                },
                {
                    "name": "Confidential only",
                    "assignees": [user_assignee(rv["carol"])],
                    "condition": {
                        "field": "classification",
                        "op": "in",
                        "value": ["confidential", "restricted"],
                    },
                },
            ],
        )
        env["admin"].patch(
            f"/api/v1/documents/{env['doc']}", json={"classification": "confidential"}
        )
        run = start(env, flow).json()
        decide(rv["alice"], my_tasks(rv["alice"])[0]["id"])
        assert my_tasks(rv["bob"]) == []  # size condition false -> skipped, visibly
        carol_task = my_tasks(rv["carol"])[0]
        decide(rv["carol"], carol_task["id"])
        final = env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()
        assert final["state"] == "approved" and [s["status"] for s in final["steps"]] == [
            "approved",
            "skipped",
            "approved",
        ]
        assert any(a["action"] == "step_skipped" for a in final["actions"])

    def test_metadata_condition(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {
                    "name": "EU",
                    "assignees": [user_assignee(rv["alice"])],
                    "condition": {"field": "metadata", "key": "region", "op": "eq", "value": "eu"},
                }
            ],
        )
        env["admin"].patch(f"/api/v1/documents/{env['doc']}", json={"metadata": {"region": "us"}})
        assert (
            start(env, flow).json()["state"] == "approved"
        )  # nothing applicable -> approved, steps skipped


class TestSecurity:
    def test_initiator_cannot_approve_own_request_and_empty_steps_fail_closed(self, env):  # noqa: ANN001
        a = env["author"]
        flow = make_flow(env, [{"name": "Self", "assignees": [user_assignee(a)]}])
        r = start(env, flow)
        assert r.status_code == 422 and r.json()["error"]["code"] == "no_approvers"
        with env["world"].db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.workflow_runs WHERE document_id = :d"),
                    {"d": env["doc"]},
                )
                == 0
            )

    def test_only_the_assignee_can_decide_and_outsiders_cannot_see_runs(self, env):  # noqa: ANN001
        rv, admin = env["reviewers"], env["admin"]
        flow = make_flow(env, [{"name": "Legal", "assignees": [user_assignee(rv["alice"])]}])
        run = start(env, flow).json()
        tid = my_tasks(rv["alice"])[0]["id"]
        assert decide(rv["bob"], tid).status_code == 404
        assert decide(admin, tid).status_code == 404  # not even admins impersonate approvers
        assert decide(env["author"], tid).status_code == 404
        assert rv["bob"].get(f"/api/v1/workflow-runs/{run['id']}").status_code == 404
        other = env["world"].org("Other")
        assert other.get(f"/api/v1/workflow-runs/{run['id']}").status_code == 404
        assert decide(other, tid).status_code == 404
        assert rv["alice"].get(f"/api/v1/workflow-runs/{run['id']}").status_code == 200
        assert admin.get(f"/api/v1/workflow-runs/{run['id']}").status_code == 200

    def test_reviewer_can_open_the_document_only_while_the_task_is_pending(self, env):  # noqa: ANN001
        rv, w = env["reviewers"], env["world"]
        flow = make_flow(env, [{"name": "Legal", "assignees": [user_assignee(rv["alice"])]}])
        assert rv["alice"].get(f"/api/v1/documents/{env['doc']}").status_code == 404
        start(env, flow)
        assert rv["alice"].get(f"/api/v1/documents/{env['doc']}").status_code == 200
        url = (
            rv["alice"].post(f"/api/v1/documents/{env['doc']}/download-url", json={}).json()["url"]
        )
        assert w.client.get(url.replace("http://testserver", "")).status_code == 200
        # no access to the parent folder or siblings through the task
        assert rv["alice"].get(f"/api/v1/folders/{env['folder']}/children").status_code == 404
        assert (
            rv["alice"].patch(f"/api/v1/documents/{env['doc']}", json={"name": "x.pdf"}).status_code
            == 403
        )
        decide(rv["alice"], my_tasks(rv["alice"])[0]["id"])
        assert (
            rv["alice"].get(f"/api/v1/documents/{env['doc']}").status_code == 404
        )  # access ends with the task

    def test_run_is_bound_to_the_exact_version_and_new_versions_do_not_change_it(self, env):  # noqa: ANN001
        rv, w, a = env["reviewers"], env["world"], env["author"]
        flow = make_flow(env, [{"name": "Legal", "assignees": [user_assignee(rv["alice"])]}])
        run = start(env, flow).json()
        s = a.post(
            f"/api/v1/documents/{env['doc']}/uploads",
            json={"filename": "contract.pdf", "size_bytes": 16, "expected_latest_version": 1},
        ).json()
        a.put(
            s["upload_url"],
            content=b"%PDF-1.4 changed!",
            headers={"Content-Type": "application/octet-stream"},
        )
        a.post(f"/api/v1/uploads/{s['id']}/finalize")
        w.process_jobs()
        task = my_tasks(rv["alice"])[0]
        assert task["document_version_number"] == 1
        got = a.get(f"/api/v1/workflow-runs/{run['id']}").json()
        assert got["document_version_number"] == 1

    def test_only_editors_can_submit_and_documents_must_be_available(self, env):  # noqa: ANN001
        rv, w = env["reviewers"], env["world"]
        flow = make_flow(env, [{"name": "Legal", "assignees": [user_assignee(rv["alice"])]}])
        assert start(env, flow, actor=rv["bob"]).status_code == 404  # cannot even see the document
        pending = w.upload(env["author"], env["folder"], "fresh.pdf", PDF + b" fresh")
        assert start(env, flow, doc=pending["document_id"]).status_code == 409

    def test_trashing_a_document_cancels_its_running_approval(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(env, [{"name": "Legal", "assignees": [user_assignee(rv["alice"])]}])
        run = start(env, flow).json()
        assert env["author"].delete(f"/api/v1/documents/{env['doc']}").status_code == 204
        assert env["admin"].get(f"/api/v1/workflow-runs/{run['id']}").json()["state"] == "cancelled"
        assert my_tasks(rv["alice"]) == []

    def test_purge_removes_workflow_rows_but_audit_remains(self, env):  # noqa: ANN001
        rv, admin = env["reviewers"], env["admin"]
        flow = make_flow(env, [{"name": "Legal", "assignees": [user_assignee(rv["alice"])]}])
        start(env, flow)
        env["author"].delete(f"/api/v1/documents/{env['doc']}")
        assert admin.delete(f"/api/v1/trash/documents/{env['doc']}").status_code == 200
        with env["world"].db_factory() as db:
            assert (
                db.scalar(
                    text("SELECT count(*) FROM dms.workflow_runs WHERE document_id = :d"),
                    {"d": env["doc"]},
                )
                == 0
            )
        assert any(
            e["action"] == "workflow.started"
            for e in admin.get("/api/v1/admin/audit-events", params={"limit": 200}).json()["items"]
        )


class TestIdempotencyAndConcurrency:
    def test_repeated_decisions_are_idempotent_and_conflicts_are_rejected(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {"name": "S1", "assignees": [user_assignee(rv["alice"])]},
                {"name": "S2", "assignees": [user_assignee(rv["bob"])]},
            ],
        )
        run = start(env, flow).json()
        tid = my_tasks(rv["alice"])[0]["id"]
        assert decide(rv["alice"], tid).status_code == 200
        assert decide(rv["alice"], tid).status_code == 200  # double click: same result
        assert decide(rv["alice"], tid, "reject").status_code == 409  # cannot flip a decision
        got = env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()
        assert (
            len([t for t in got["tasks"] if t["step_index"] == 1]) == 1
        )  # step 2 started exactly once
        assert sum(1 for a in got["actions"] if a["action"] == "task_approved") == 1

    def test_concurrent_decisions_advance_the_run_once(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(
            env,
            [
                {
                    "name": "S1",
                    "rule": "any",
                    "assignees": [user_assignee(rv["alice"]), user_assignee(rv["bob"])],
                },
                {"name": "S2", "assignees": [user_assignee(rv["carol"])]},
            ],
        )
        run = start(env, flow).json()
        tasks = {u: my_tasks(rv[u])[0]["id"] for u in ("alice", "bob")}
        codes: list[int] = []
        barrier = threading.Barrier(2)

        def go(name: str) -> None:
            barrier.wait()
            codes.append(decide(rv[name], tasks[name]).status_code)

        threads = [threading.Thread(target=go, args=(n,)) for n in tasks]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert sorted(codes) == [200, 409]  # the loser finds its task already skipped
        got = env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()
        assert (
            len([t for t in got["tasks"] if t["step_index"] == 1]) == 1 and got["current_step"] == 1
        )

    def test_approval_history_is_append_only(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(env, [{"name": "S1", "assignees": [user_assignee(rv["alice"])]}])
        start(env, flow)
        from sqlalchemy.exc import DBAPIError

        with env["world"].db_factory() as db:
            for sql in (
                "UPDATE dms.approval_actions SET comment = 'x'",
                "DELETE FROM dms.approval_actions",
            ):
                with pytest.raises(DBAPIError):
                    db.execute(text(sql))
                db.rollback()


class TestDelegationAndDeadlines:
    def test_delegation_moves_the_task_and_is_recorded(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(env, [{"name": "S1", "assignees": [user_assignee(rv["alice"])]}])
        run = start(env, flow).json()
        tid = my_tasks(rv["alice"])[0]["id"]
        assert (
            rv["alice"]
            .post(f"/api/v1/workflow-tasks/{tid}/delegate", json={"email": env["author"].email})
            .status_code
            == 422
        )  # not to the submitter
        assert (
            rv["alice"]
            .post(
                f"/api/v1/workflow-tasks/{tid}/delegate", json={"user_id": str(rv["alice"].user_id)}
            )
            .status_code
            == 422
        )
        assert (
            rv["alice"]
            .post(f"/api/v1/workflow-tasks/{tid}/delegate", json={"user_id": str(uuid.uuid4())})
            .status_code
            == 422
        )
        r = rv["alice"].post(
            f"/api/v1/workflow-tasks/{tid}/delegate",
            json={"email": rv["carol"].email, "comment": "on leave"},
        )
        assert (
            r.status_code == 200
            and r.json()["assignee"]["id"] == str(rv["carol"].user_id)
            and r.json()["delegated_from"]["id"] == str(rv["alice"].user_id)
        )
        assert my_tasks(rv["alice"]) == [] and decide(rv["alice"], tid).status_code == 404
        assert rv["alice"].get(f"/api/v1/documents/{env['doc']}").status_code == 404
        assert rv["carol"].get(f"/api/v1/documents/{env['doc']}").status_code == 200
        assert decide(rv["carol"], tid).status_code == 200
        assert any(
            a["action"] == "delegated"
            for a in env["author"].get(f"/api/v1/workflow-runs/{run['id']}").json()["actions"]
        )

    def test_overdue_tasks_notify_assignee_submitter_and_escalation_contact_once(self, env):  # noqa: ANN001
        rv, w = env["reviewers"], env["world"]
        flow = make_flow(
            env,
            [
                {
                    "name": "Timed",
                    "assignees": [user_assignee(rv["alice"])],
                    "due_days": 2,
                    "escalate_to_user_id": str(rv["carol"].user_id),
                }
            ],
        )
        start(env, flow)
        with w.db_factory() as db:
            db.execute(
                text(
                    "UPDATE dms.workflow_tasks SET due_at = now() - interval '1 hour' WHERE document_id = :d"
                ),
                {"d": env["doc"]},
            )
            db.commit()
        assert my_tasks(rv["alice"])[0]["overdue"] is True
        from app.modules.workflows.service import process_overdue_tasks

        with w.db_factory() as db:
            assert process_overdue_tasks(db) >= 1
        with w.db_factory() as db:
            assert process_overdue_tasks(db) == 0  # exactly once
        w.process_jobs()
        for who in (rv["alice"], rv["carol"], env["author"]):
            assert any(
                n["type"] == "workflow.task_overdue"
                for n in who.get("/api/v1/notifications").json()["items"]
            )

    def test_cancel_by_submitter_or_admin_only(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(env, [{"name": "S1", "assignees": [user_assignee(rv["alice"])]}])
        run = start(env, flow).json()
        assert (
            rv["alice"].post(f"/api/v1/workflow-runs/{run['id']}/cancel", json={}).status_code
            == 404
        )
        assert (
            env["author"]
            .post(f"/api/v1/workflow-runs/{run['id']}/cancel", json={"comment": "withdrawn"})
            .status_code
            == 204
        )
        assert (
            env["author"].post(f"/api/v1/workflow-runs/{run['id']}/cancel", json={}).status_code
            == 409
        )
        assert my_tasks(rv["alice"]) == []


class TestDefinitions:
    def test_admin_only_validation_and_versioning(self, env):  # noqa: ANN001
        rv, admin, author = env["reviewers"], env["admin"], env["author"]
        body = {"name": "WF", "steps": [{"name": "S1", "assignees": [user_assignee(rv["alice"])]}]}
        assert author.post("/api/v1/admin/workflows", json=body).status_code == 403
        bad = [
            {"name": "x", "steps": []},
            {"name": "x", "steps": [{"name": "s", "assignees": []}]},
            {"name": "x", "steps": [{"name": "s", "assignees": [{"type": "user"}]}]},
            {
                "name": "x",
                "steps": [
                    {
                        "name": "s",
                        "assignees": [{"type": "role", "role": "owner"}],
                        "condition": {"field": "metadata", "op": "eq", "value": 1},
                    }
                ],
            },
            {
                "name": "x",
                "steps": [{"name": "s", "assignees": [{"type": "user", "id": str(uuid.uuid4())}]}],
            },
        ]
        for payload in bad:
            assert admin.post("/api/v1/admin/workflows", json=payload).status_code == 422, payload
        flow = admin.post("/api/v1/admin/workflows", json=body).json()
        assert admin.post("/api/v1/admin/workflows", json=body).status_code == 409
        # running approvals keep their version when the workflow is edited
        run = start(env, flow).json()
        v2 = admin.post(
            f"/api/v1/admin/workflows/{flow['id']}/versions",
            json={
                "steps": [
                    {"name": "S1", "assignees": [user_assignee(rv["alice"])]},
                    {"name": "S2", "assignees": [user_assignee(rv["bob"])]},
                ]
            },
        )
        assert v2.status_code == 201 and v2.json()["latest_version"] == 2
        decide(rv["alice"], my_tasks(rv["alice"])[0]["id"])
        assert (
            author.get(f"/api/v1/workflow-runs/{run['id']}").json()["state"] == "approved"
        )  # still 1 step
        assert author.get(f"/api/v1/workflow-runs/{run['id']}").json()["definition_version"] == 1
        # archived workflows cannot be started but stay readable for history
        assert (
            admin.patch(
                f"/api/v1/admin/workflows/{flow['id']}", json={"archived": True}
            ).status_code
            == 200
        )
        assert [f["id"] for f in author.get("/api/v1/workflows").json()] == []
        doc2 = env["world"].available_doc(author, env["folder"], "again.pdf", PDF + b" again")
        assert start(env, flow, doc=doc2).status_code == 404

    def test_tenant_isolation_of_definitions(self, env):  # noqa: ANN001
        rv = env["reviewers"]
        flow = make_flow(env, [{"name": "S1", "assignees": [user_assignee(rv["alice"])]}])
        other = env["world"].org("Other")
        assert other.get("/api/v1/workflows").json() == []
        assert other.post(
            f"/api/v1/admin/workflows/{flow['id']}/versions", json={"steps": flow["steps"]}
        ).status_code in (404, 422)
