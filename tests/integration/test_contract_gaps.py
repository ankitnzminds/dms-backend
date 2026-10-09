"""Small contract additions requested by the frontend: member-by-id label lookup, single-task
fetch, 'all statuses' task listing and a typed report summary."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


def test_member_lookup_by_id_is_tenant_scoped(world):  # noqa: ANN001
    admin = world.org("Gaps")
    m = world.user(admin, "member", label="lbl")
    got = admin.get(f"{API}/members/{m.user_id}")
    assert got.status_code == 200 and got.json()["email"] == m.email
    other = world.org("GapsOther")
    assert other.get(f"{API}/members/{m.user_id}").status_code == 404
    assert admin.get(f"{API}/members/00000000-0000-0000-0000-000000000001").status_code == 404


def test_task_fetch_and_all_statuses(world):  # noqa: ANN001
    admin = world.org("GapsWf", member_default_access=True)
    root = world.root_id(admin)
    author = world.user(admin, "member", label="author")
    reviewer = world.user(admin, "member", label="rev")
    stranger = world.user(admin, "member", label="stranger")
    folder = world.mkdir(admin, root, "c")
    admin.post(
        f"{API}/folders/{folder}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(author.user_id),
            "actions": ["view", "edit_metadata", "create_child", "upload_version"],
        },
    )
    doc = world.available_doc(author, folder, "c.pdf", b"%PDF-1.4 gap contract")
    flow = admin.post(
        f"{API}/admin/workflows",
        json={
            "name": "gap flow",
            "steps": [
                {"name": "Review", "assignees": [{"type": "user", "id": str(reviewer.user_id)}]}
            ],
        },
    ).json()
    assert author.post(
        f"{API}/documents/{doc}/workflow-runs", json={"definition_id": flow["id"]}
    ).status_code in (200, 201)
    task = reviewer.get(f"{API}/workflow-tasks/mine").json()["items"][0]
    assert reviewer.get(f"{API}/workflow-tasks/{task['id']}").json()["step_name"] == "Review"
    assert stranger.get(f"{API}/workflow-tasks/{task['id']}").status_code == 404
    assert (
        reviewer.post(
            f"{API}/workflow-tasks/{task['id']}/decision", json={"decision": "approve"}
        ).status_code
        == 200
    )
    assert reviewer.get(f"{API}/workflow-tasks/mine").json()["total"] == 0  # default: pending only
    assert reviewer.get(f"{API}/workflow-tasks/mine", params={"status": "all"}).json()["total"] == 1


def test_report_summary_is_typed(world):  # noqa: ANN001
    admin = world.org("GapsRep")
    body = admin.get(f"{API}/admin/reports/summary").json()
    assert set(body["shares"]) == {"total", "revoked", "expired", "active"}
    assert isinstance(body["top_actions"], list) and body["period_days"] == 30
    member = world.user(admin, "member", label="m")
    assert member.get(f"{API}/admin/reports/summary").status_code == 403
