"""Signature chains per folder: configuration, request creation, levels, optional, super signer, decline."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text

from app.db.models import SignatureRecipient
from tests.integration import test_signature_builtin as bi
from tests.integration import test_signatures as base

env = base.env
_fake_provider_state = base._fake_provider_state  # noqa: SLF001

pytestmark = pytest.mark.integration
API = "/api/v1"


@pytest.fixture()
def team(env):  # noqa: ANN001, ANN201
    w, admin = env["world"], env["admin"]
    users = {n: w.user(admin, "member", label=n) for n in ("dave", "erin", "frank")}
    users["carol"] = env["carol"]
    return {**env, **users}


def entry(user, optional=False, sup=False):  # noqa: ANN001, ANN201
    return {"user_id": str(user.user_id), "optional": optional, "is_super_signer": sup}


def put_chain(env, levels, group_ids=None, actor=None):  # noqa: ANN001, ANN201
    return (actor or env["admin"]).put(
        f"{API}/folders/{env['folder']}/signature-chain",
        json={"levels": levels, "group_ids": group_ids or []},
    )


def start(env, **body):  # noqa: ANN001, ANN003, ANN201
    r = env["admin"].post(
        f"{API}/documents/{env['doc']}/signature-requests", json={"provider": "builtin", **body}
    )
    assert r.status_code == 201, r.text
    return r.json()


def sign(user, rid, name="N"):  # noqa: ANN001, ANN201
    return bi.sign(user, rid, typed_name=name)


def signers(env, rid):  # noqa: ANN001, ANN201
    out = env["admin"].get(f"{API}/signature-requests/{rid}").json()
    return {s["email"]: s for s in out["signers"]}, out


# ---- configuration ----------------------------------------------------------------------------
def test_admin_configures_levels_and_everyone_with_folder_access_can_read_it(team):  # noqa: ANN001
    r = put_chain(
        team,
        [
            [entry(team["carol"])],
            [entry(team["dave"], optional=True), entry(team["erin"], sup=True)],
        ],
    )
    assert r.status_code == 200, r.text
    levels = r.json()["levels"]
    assert [len(lv) for lv in levels] == [1, 2]
    flags = {s["email"]: (s["optional"], s["is_super_signer"]) for s in levels[1]}
    assert flags == {team["dave"].email: (True, False), team["erin"].email: (False, True)}
    assert (
        team["admin"].get(f"{API}/folders/{team['folder']}/signature-chain").json()["levels"]
        == levels
    )
    acts = {
        e["action"]
        for e in team["admin"]
        .get(f"{API}/admin/audit-events", params={"limit": 100})
        .json()["items"]
    }
    assert "folder.signature_chain.set" in acts


def test_only_administrators_configure_and_foreign_tenants_see_nothing(team):  # noqa: ANN001
    assert put_chain(team, [[entry(team["dave"])]], actor=team["carol"]).status_code == 403
    other = team["world"].org("Chain Other Co", member_default_access=False)
    assert other.get(f"{API}/folders/{team['folder']}/signature-chain").status_code == 404
    assert put_chain(team, [[entry(team["dave"])]], actor=other).status_code in (403, 404)


def test_validation_of_levels_signers_and_groups(team):  # noqa: ANN001
    assert put_chain(team, [[]]).status_code == 422  # empty level
    r = put_chain(team, [[entry(team["carol"])], [entry(team["carol"])]])
    assert r.status_code == 422 and r.json()["error"]["code"] == "signer_in_two_levels"
    other = team["world"].org("Chain Foreign Co", member_default_access=False)
    r = put_chain(team, [[{"user_id": str(other.user_id)}]])
    assert r.status_code == 422 and r.json()["error"]["code"] == "signer_not_found"
    assert (
        put_chain(team, [[entry(team["carol"])]], group_ids=[[str(uuid.uuid4())]]).status_code
        == 422
    )


def test_groups_expand_to_their_members_at_save_time_and_duplicates_merge(team):  # noqa: ANN001
    from app.db.models import Group, GroupMembership

    w = team["world"]
    gid = uuid.uuid4()
    with w.db_factory() as db:
        db.add(Group(id=gid, organization_id=team["admin"].org_id, name="Legal", kind="group"))
        db.flush()
        for u in (team["dave"], team["erin"]):
            db.add(
                GroupMembership(
                    group_id=gid, user_id=u.user_id, organization_id=team["admin"].org_id
                )
            )
        db.commit()
    r = put_chain(team, [[entry(team["dave"], optional=True)]], group_ids=[[str(gid)]])
    assert r.status_code == 200, r.text
    lv = {s["email"]: s for s in r.json()["levels"][0]}
    assert set(lv) == {team["dave"].email, team["erin"].email}
    assert (
        lv[team["dave"].email]["optional"] is True
    )  # explicit flag kept when the group adds the same person
    assert lv[team["erin"].email]["optional"] is False
    with w.db_factory() as db:  # later membership changes do not change the saved chain (snapshot)
        db.execute(
            text("DELETE FROM dms.group_memberships WHERE user_id = :u"),
            {"u": str(team["erin"].user_id)},
        )
        db.commit()
    assert (
        len(
            team["admin"].get(f"{API}/folders/{team['folder']}/signature-chain").json()["levels"][0]
        )
        == 2
    )


def test_empty_chain_removes_it(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"])]])
    assert put_chain(team, []).json()["levels"] == []


# ---- request creation ---------------------------------------------------------------------------
def test_chain_decides_the_signers_and_the_body_list_is_ignored(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"])], [entry(team["dave"])]])
    out = start(team, signers=[{"email": team["frank"].email}])
    by = {s["email"]: s for s in out["signers"]}
    assert set(by) == {team["carol"].email, team["dave"].email}
    assert (by[team["carol"].email]["level"], by[team["dave"].email]["level"]) == (1, 2)
    assert by[team["dave"].email]["waiting"] is True and by[team["carol"].email]["waiting"] is False


def test_without_a_chain_signers_are_required(team):  # noqa: ANN001
    r = team["admin"].post(
        f"{API}/documents/{team['doc']}/signature-requests", json={"provider": "builtin"}
    )
    assert r.status_code == 422


def test_a_chain_signer_who_is_no_longer_active_blocks_the_request(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"])]])
    with team["world"].db_factory() as db:
        db.execute(
            text("UPDATE dms.memberships SET status = 'suspended' WHERE user_id = :u"),
            {"u": str(team["carol"].user_id)},
        )
        db.commit()
    r = team["admin"].post(
        f"{API}/documents/{team['doc']}/signature-requests", json={"provider": "builtin"}
    )
    assert r.status_code == 409 and r.json()["error"]["code"] == "chain_signer_inactive"


# ---- levels ---------------------------------------------------------------------------------------
def test_a_later_level_cannot_sign_until_the_earlier_one_is_done(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"])], [entry(team["dave"])]])
    rid = start(team)["id"]
    late = sign(team["dave"], rid, "Dave")
    assert late.status_code == 409 and late.json()["error"]["code"] == "not_your_turn"
    assert (
        team["dave"].get(f"{API}/signature-requests/{rid}").json()["my_signing_available"] is False
    )
    assert sign(team["carol"], rid, "Carol").status_code == 204
    assert (
        team["dave"].get(f"{API}/signature-requests/{rid}").json()["my_signing_available"] is True
    )
    assert base.env  # fixture alias used
    assert bi.state(team, rid) == "sent"
    assert sign(team["dave"], rid, "Dave").status_code == 204
    assert bi.state(team, rid) == "completed"
    acts = {
        e["action"]
        for e in team["admin"]
        .get(f"{API}/admin/audit-events", params={"limit": 100})
        .json()["items"]
    }
    assert {"signature.chain_advanced", "signature.completed"} <= acts


def test_signers_in_one_level_act_in_parallel_and_all_required_ones_must_sign(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"]), entry(team["dave"])], [entry(team["erin"])]])
    rid = start(team)["id"]
    assert sign(team["dave"], rid).status_code == 204  # any order inside the level
    assert sign(team["erin"], rid).status_code == 409
    assert sign(team["carol"], rid).status_code == 204
    assert sign(team["erin"], rid).status_code == 204
    assert bi.state(team, rid) == "completed"


def test_optional_signer_does_not_block_and_is_bypassed_when_the_chain_completes(team):  # noqa: ANN001
    put_chain(
        team, [[entry(team["carol"]), entry(team["dave"], optional=True)], [entry(team["erin"])]]
    )
    rid = start(team)["id"]
    assert sign(team["carol"], rid).status_code == 204
    assert sign(team["erin"], rid).status_code == 204  # level 2 was open although dave never signed
    by, out = signers(team, rid)
    assert out["state"] == "completed" and by[team["dave"].email]["status"] == "bypassed"
    assert sign(team["dave"], rid).status_code == 409  # request is over


def test_optional_signer_may_still_sign_after_their_level_moved_on(team):  # noqa: ANN001
    put_chain(
        team, [[entry(team["carol"]), entry(team["dave"], optional=True)], [entry(team["erin"])]]
    )
    rid = start(team)["id"]
    assert sign(team["carol"], rid).status_code == 204
    assert sign(team["dave"], rid).status_code == 204
    by, _ = signers(team, rid)
    assert by[team["dave"].email]["status"] == "signed"


# ---- super signer ----------------------------------------------------------------------------------
def test_super_signer_fast_forwards_everyone_else(team):  # noqa: ANN001
    put_chain(
        team,
        [
            [entry(team["carol"], sup=True), entry(team["dave"])],
            [entry(team["erin"])],
            [entry(team["frank"])],
        ],
    )
    rid = start(team)["id"]
    assert sign(team["carol"], rid, "Boss").status_code == 204
    by, out = signers(team, rid)
    assert out["state"] == "completed"
    assert by[team["carol"].email]["status"] == "signed"
    assert {by[team[n].email]["status"] for n in ("dave", "erin", "frank")} == {"bypassed"}
    acts = {
        e["action"]
        for e in team["admin"]
        .get(f"{API}/admin/audit-events", params={"limit": 100})
        .json()["items"]
    }
    assert "signature.chain_override" in acts


def test_super_signer_must_still_wait_for_their_own_level(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"])], [entry(team["dave"], sup=True)]])
    rid = start(team)["id"]
    assert sign(team["dave"], rid).status_code == 409  # super power does not skip the queue


# ---- decline ---------------------------------------------------------------------------------------
def test_required_decline_halts_the_chain_and_cancels_the_rest(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"]), entry(team["dave"])], [entry(team["erin"])]])
    rid = start(team)["id"]
    assert (
        team["carol"]
        .post(f"{API}/signature-requests/{rid}/decline", json={"reason": "no"})
        .status_code
        == 204
    )
    by, out = signers(team, rid)
    assert out["state"] == "declined"
    assert by[team["carol"].email]["status"] == "declined"
    assert (
        by[team["dave"].email]["status"] == "cancelled"
        and by[team["erin"].email]["status"] == "cancelled"
    )
    assert sign(team["dave"], rid).status_code == 409


def test_optional_decline_changes_nothing_else(team):  # noqa: ANN001
    put_chain(
        team, [[entry(team["carol"]), entry(team["dave"], optional=True)], [entry(team["erin"])]]
    )
    rid = start(team)["id"]
    assert team["dave"].post(f"{API}/signature-requests/{rid}/decline", json={}).status_code == 204
    assert bi.state(team, rid) == "sent"
    assert sign(team["carol"], rid).status_code == 204
    assert sign(team["erin"], rid).status_code == 204
    assert bi.state(team, rid) == "completed"


# ---- snapshot + providers ---------------------------------------------------------------------------
def test_editing_the_chain_does_not_change_a_running_request(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"])], [entry(team["dave"])]])
    rid = start(team)["id"]
    put_chain(team, [[entry(team["frank"])]])
    by, _ = signers(team, rid)
    assert set(by) == {team["carol"].email, team["dave"].email}


def test_external_provider_chain_supports_levels_but_not_optional_or_super(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"], optional=True)], [entry(team["dave"])]])
    r = team["admin"].post(f"{API}/documents/{team['doc']}/signature-requests", json={})
    assert r.status_code == 422 and r.json()["error"]["code"] == "chain_flags_builtin_only"
    put_chain(team, [[entry(team["carol"])], [entry(team["dave"])]])
    ok = team["admin"].post(f"{API}/documents/{team['doc']}/signature-requests", json={})
    assert ok.status_code == 201, ok.text
    rid = ok.json()["id"]
    # the provider's signing page is still gated by level inside the DMS
    late = team["dave"].post(f"{API}/signature-requests/{rid}/signing-session")
    assert late.status_code == 409 and late.json()["error"]["code"] == "not_your_turn"
    assert team["carol"].post(f"{API}/signature-requests/{rid}/signing-session").status_code == 200


def test_recipient_rows_keep_chain_fields(team):  # noqa: ANN001
    put_chain(team, [[entry(team["carol"], optional=True, sup=True)]])
    rid = start(team)["id"]
    with team["world"].db_factory() as db:
        rec = db.scalar(
            select(SignatureRecipient).where(SignatureRecipient.request_id == uuid.UUID(rid))
        )
    assert (rec.level, rec.optional, rec.is_super_signer) == (1, True, True)
