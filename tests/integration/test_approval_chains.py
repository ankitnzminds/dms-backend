"""Approval chains per folder: configuration, submit-for-approval, levels, optional, super approver."""

from __future__ import annotations

import pytest
from sqlalchemy import text

from tests.integration import test_workflows as base

env = base.env

pytestmark = pytest.mark.integration
API = "/api/v1"


@pytest.fixture()
def team(env):  # noqa: ANN001, ANN201
    w, admin = env["world"], env["admin"]
    people = dict(env["reviewers"])
    people["dave"] = w.user(admin, "member", label="dave")
    return {**env, "p": people}


def entry(user, optional=False, sup=False):  # noqa: ANN001, ANN201
    return {"user_id": str(user.user_id), "optional": optional, "is_super_approver": sup}


def put_chain(env, levels, group_ids=None, actor=None):  # noqa: ANN001, ANN201
    return (actor or env["admin"]).put(
        f"{API}/folders/{env['folder']}/approval-chain",
        json={"levels": levels, "group_ids": group_ids or []},
    )


def submit(env, note="please approve"):  # noqa: ANN001, ANN201
    return env["author"].post(
        f"{API}/documents/{env['doc']}/submit-for-approval", json={"note": note}
    )


def run_of(env, run_id):  # noqa: ANN001, ANN201
    return env["author"].get(f"{API}/workflow-runs/{run_id}").json()


def approve(user, reject=False, comment=None):  # noqa: ANN001, ANN201
    t = base.my_tasks(user)[0]
    return base.decide(user, t["id"], "reject" if reject else "approve", comment)


# ---- configuration ------------------------------------------------------------------------------
def test_admin_sets_levels_with_flags_and_it_is_readable_with_folder_access(team):  # noqa: ANN001
    p = team["p"]
    r = put_chain(
        team, [[entry(p["alice"], sup=True)], [entry(p["bob"]), entry(p["carol"], optional=True)]]
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["definition_id"] and [len(lv) for lv in out["levels"]] == [1, 2]
    flags = {s["email"]: (s["optional"], s["is_super_approver"]) for s in out["levels"][1]}
    assert flags == {p["bob"].email: (False, False), p["carol"].email: (True, False)}
    assert (
        team["author"].get(f"{API}/folders/{team['folder']}/approval-chain").json()["levels"]
        == out["levels"]
    )
    names = [d["name"] for d in team["admin"].get(f"{API}/workflows").json()]
    assert any(
        n.startswith("Folder approval chain:") for n in names
    )  # it is a normal, versioned workflow
    acts = {
        e["action"]
        for e in team["admin"]
        .get(f"{API}/admin/audit-events", params={"limit": 100})
        .json()["items"]
    }
    assert "folder.approval_chain.set" in acts


def test_only_admins_configure_and_other_tenants_see_nothing(team):  # noqa: ANN001
    p = team["p"]
    assert put_chain(team, [[entry(p["alice"])]], actor=team["author"]).status_code == 403
    other = team["world"].org("Approval Other Co", member_default_access=False)
    assert other.get(f"{API}/folders/{team['folder']}/approval-chain").status_code == 404


def test_validation(team):  # noqa: ANN001
    p = team["p"]
    assert put_chain(team, [[]]).status_code == 422
    assert (
        put_chain(team, [[entry(p["alice"])], [entry(p["alice"])]]).json()["error"]["code"]
        == "signer_in_two_levels"
    )
    other = team["world"].org("Approval Foreign Co", member_default_access=False)
    assert (
        put_chain(team, [[{"user_id": str(other.user_id)}]]).json()["error"]["code"]
        == "signer_not_found"
    )


def test_empty_chain_removes_it_and_submit_then_needs_a_workflow(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"])]])
    assert put_chain(team, []).json() == {
        "folder_id": team["folder"],
        "definition_id": None,
        "levels": [],
    }
    r = submit(team)
    assert r.status_code == 409 and r.json()["error"]["code"] == "no_chain"


def test_without_a_chain_the_manual_workflow_flow_is_unchanged(team):  # noqa: ANN001
    flow = base.make_flow(
        team, [{"name": "Legal", "assignees": [base.user_assignee(team["p"]["alice"])]}]
    )
    assert base.start(team, flow).status_code == 201


# ---- levels ---------------------------------------------------------------------------------------
def test_levels_run_in_order_and_complete_the_approval(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"])], [entry(p["bob"])]])
    run = submit(team).json()
    assert run["state"] == "in_progress" and run["current_step"] == 0
    assert base.my_tasks(p["bob"]) == []  # level 2 has not started
    assert approve(p["alice"]).status_code == 200
    assert len(base.my_tasks(p["bob"])) == 1
    assert approve(p["bob"]).status_code == 200
    assert run_of(team, run["id"])["state"] == "approved"


def test_everyone_required_in_a_level_must_approve_and_optional_ones_do_not_block(team):  # noqa: ANN001
    p = team["p"]
    put_chain(
        team,
        [
            [entry(p["alice"]), entry(p["bob"]), entry(p["carol"], optional=True)],
            [entry(p["dave"])],
        ],
    )
    run = submit(team).json()
    assert approve(p["alice"]).status_code == 200
    assert base.my_tasks(p["dave"]) == []  # bob (required) has not approved yet
    assert approve(p["bob"]).status_code == 200
    assert (
        len(base.my_tasks(p["dave"])) == 1
    )  # level 2 opened although carol (optional) never decided
    tasks = team["author"].get(f"{API}/workflow-runs/{run['id']}").json()
    assert tasks["state"] == "in_progress"
    assert approve(p["dave"]).status_code == 200
    assert run_of(team, run["id"])["state"] == "approved"
    assert base.my_tasks(p["carol"]) == []  # her task was skipped when the chain finished


def test_a_level_of_only_optional_approvers_needs_one_approval(team):  # noqa: ANN001
    p = team["p"]
    put_chain(
        team,
        [[entry(p["alice"], optional=True), entry(p["bob"], optional=True)], [entry(p["carol"])]],
    )
    submit(team)
    assert base.my_tasks(p["carol"]) == []
    assert approve(p["alice"]).status_code == 200
    assert len(base.my_tasks(p["carol"])) == 1
    assert base.my_tasks(p["bob"]) == []  # no longer needed


# ---- rejection --------------------------------------------------------------------------------------
def test_a_required_rejection_halts_the_chain_and_rejects_the_document(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"]), entry(p["bob"])], [entry(p["carol"])]])
    run = submit(team).json()
    assert approve(p["alice"], reject=True, comment="no").status_code == 200
    final = run_of(team, run["id"])
    assert final["state"] == "rejected"
    assert base.my_tasks(p["bob"]) == [] and base.my_tasks(p["carol"]) == []


def test_an_optional_rejection_is_recorded_but_halts_nothing(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"]), entry(p["bob"], optional=True)], [entry(p["carol"])]])
    run = submit(team).json()
    assert approve(p["bob"], reject=True).status_code == 200
    assert run_of(team, run["id"])["state"] == "in_progress"
    assert approve(p["alice"]).status_code == 200
    assert approve(p["carol"]).status_code == 200
    assert run_of(team, run["id"])["state"] == "approved"


# ---- super approver ---------------------------------------------------------------------------------
def test_super_approver_approves_the_document_at_once_and_skips_everyone_else(team):  # noqa: ANN001
    p = team["p"]
    put_chain(
        team,
        [[entry(p["alice"], sup=True), entry(p["bob"])], [entry(p["carol"])], [entry(p["dave"])]],
    )
    run = submit(team).json()
    t = base.my_tasks(p["alice"])[0]
    assert t["is_super_approver"] is True
    assert base.decide(p["alice"], t["id"], "approve", "boss").status_code == 200
    assert run_of(team, run["id"])["state"] == "approved"
    for n in ("bob", "carol", "dave"):
        assert base.my_tasks(p[n]) == []
    acts = {
        e["action"]
        for e in team["admin"]
        .get(f"{API}/admin/audit-events", params={"limit": 100})
        .json()["items"]
    }
    assert "workflow.chain_override" in acts


def test_a_super_approver_of_a_later_level_cannot_skip_the_queue(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"])], [entry(p["bob"], sup=True)]])
    submit(team)
    assert base.my_tasks(p["bob"]) == []  # no task exists before their level starts


def test_super_reject_is_just_a_required_rejection(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"], sup=True), entry(p["bob"])]])
    run = submit(team).json()
    assert approve(p["alice"], reject=True).status_code == 200
    assert run_of(team, run["id"])["state"] == "rejected"


# ---- versions ---------------------------------------------------------------------------------------
def test_editing_the_chain_does_not_change_an_approval_in_flight(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"])], [entry(p["bob"])]])
    submit(team)
    put_chain(team, [[entry(p["carol"])]])
    assert approve(p["alice"]).status_code == 200
    assert len(base.my_tasks(p["bob"])) == 1  # still the chain it started with
    assert base.my_tasks(p["carol"]) == []


def test_an_inactive_approver_blocks_submission_with_a_clear_error(team):  # noqa: ANN001
    p = team["p"]
    put_chain(team, [[entry(p["alice"])]])
    with team["world"].db_factory() as db:
        db.execute(
            text("UPDATE dms.memberships SET status = 'suspended' WHERE user_id = :u"),
            {"u": str(p["alice"].user_id)},
        )
        db.commit()
    r = submit(team)
    assert r.status_code == 422 and r.json()["error"]["code"] == "no_approvers"


def test_existing_workflow_definitions_without_flags_behave_as_before(team):  # noqa: ANN001
    # a manual two-assignee "all" step: both required, exactly as before the chain feature
    p = team["p"]
    flow = base.make_flow(
        team,
        [
            {
                "name": "Both",
                "assignees": [base.user_assignee(p["alice"]), base.user_assignee(p["bob"])],
            }
        ],
    )
    run = base.start(team, flow).json()
    assert approve(p["alice"]).status_code == 200
    assert run_of(team, run["id"])["state"] == "in_progress"
    assert approve(p["bob"]).status_code == 200
    assert run_of(team, run["id"])["state"] == "approved"
