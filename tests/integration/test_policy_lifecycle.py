"""Policy lifecycle: draft -> validate -> publish, immutability, rollback, roles, tenant isolation."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"
URL = f"{API}/admin/policy-rules"


def body(**over):  # noqa: ANN003, ANN201
    doc = {
        "schema_version": 1,
        "effect": "DENY",
        "scope": {"type": "organization"},
        "subjects": {"access_levels": ["external"]},
        "resource_types": ["document"],
        "actions": ["download"],
        "condition": {
            "attribute": "resource.classification",
            "operator": "EQUALS",
            "value": "confidential",
        },
    }
    doc.update(over)
    return {"name": over.pop("_name", "Confidential download"), "document": doc}


def make(admin, **over):  # noqa: ANN001, ANN201
    r = admin.post(URL, json=body(**over))
    assert r.status_code == 201, r.text
    return r.json()


def publish(admin, pid, mode="enforce"):  # noqa: ANN001, ANN201
    assert admin.post(f"{URL}/{pid}/validate").json()["valid"] is True
    r = admin.post(f"{URL}/{pid}/publish", json={"mode": mode})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture()
def org(world):  # noqa: ANN001, ANN201
    owner = world.org("Policy Co", member_default_access=False)
    admin = world.user(owner, "admin", label="padmin")
    member = world.user(owner, "member", label="pmember")
    return dict(world=world, owner=owner, admin=admin, member=member)


def test_create_is_a_draft_that_is_not_published(org):  # noqa: ANN001
    p = make(org["admin"])
    assert p["status"] == "draft" and p["published_revision"] is None
    assert p["revisions"][0]["status"] == "draft"


def test_invalid_documents_are_rejected_with_paths(org):  # noqa: ANN001
    r = org["admin"].post(
        URL,
        json={
            "name": "bad",
            "document": {
                "schema_version": 1,
                "effect": "NUKE",
                "actions": ["fly"],
                "resource_types": ["share"],
            },
        },
    )
    assert r.status_code == 422
    paths = {d["path"] for d in r.json()["error"]["details"]}
    assert {"effect", "actions[0]", "resource_types[0]"} <= paths


def test_cannot_publish_without_validation_and_publish_is_audited(org):  # noqa: ANN001
    admin = org["admin"]
    pid = make(admin)["id"]
    assert admin.post(f"{URL}/{pid}/publish", json={}).status_code == 409
    out = publish(admin, pid)
    assert out["status"] == "published" and out["published_revision"] == 1
    events = admin.get(f"{API}/admin/audit-events", params={"action": "policy."}).json()["items"]
    assert {"policy.created", "policy.validated", "policy.published"} <= {
        e["action"] for e in events
    }


def test_editing_a_published_policy_opens_a_new_revision_and_keeps_enforcing_the_old(org):  # noqa: ANN001
    admin = org["admin"]
    pid = make(admin)["id"]
    publish(admin, pid)
    new_doc = body(actions=["download", "preview"])["document"]
    out = admin.patch(
        f"{URL}/{pid}", json={"document": new_doc, "change_reason": "add preview"}
    ).json()
    assert out["latest_revision"] == 2 and out["latest_revision_status"] == "draft"
    assert out["published_revision"] == 1 and out["status"] == "published"
    assert out["actions"] == ["download"]  # still the published content
    out = publish(admin, pid)
    assert out["published_revision"] == 2
    statuses = {r["revision"]: r["status"] for r in out["revisions"]}
    assert statuses == {1: "superseded", 2: "published"}


def test_rollback_creates_a_new_draft_and_never_rewrites_history(org):  # noqa: ANN001
    admin = org["admin"]
    pid = make(admin)["id"]
    publish(admin, pid)
    admin.patch(f"{URL}/{pid}", json={"document": body(actions=["share"])["document"]})
    publish(admin, pid)
    r = admin.post(f"{URL}/{pid}/rollback", json={"to_revision": 1, "change_reason": "mistake"})
    assert r.status_code == 200
    d = r.json()
    assert d["latest_revision"] == 3 and d["latest_revision_status"] == "draft"
    assert d["published_revision"] == 2
    assert d["revisions"][2]["document"]["actions"] == ["download"]
    diff = admin.get(f"{URL}/{pid}/compare", params={"a": 1, "b": 2}).json()
    assert any(c["field"] == "actions" for c in diff["changes"])


def test_published_revision_is_immutable_at_the_database(org, world):  # noqa: ANN001
    from sqlalchemy import text
    from sqlalchemy.exc import DBAPIError

    admin = org["admin"]
    pid = make(admin)["id"]
    publish(admin, pid)
    with world.db_factory() as db:
        with pytest.raises(DBAPIError):
            db.execute(
                text(
                    "UPDATE dms.policy_revisions SET document = '{}'::jsonb "
                    "WHERE policy_id = :p AND status = 'published'"
                ),
                {"p": pid},
            )
            db.commit()
        db.rollback()
        with pytest.raises(DBAPIError):
            db.execute(
                text(
                    "DELETE FROM dms.policy_revisions WHERE policy_id = :p AND status = 'published'"
                ),
                {"p": pid},
            )
            db.commit()


def test_disable_enable_archive_rules(org):  # noqa: ANN001
    admin = org["admin"]
    pid = make(admin)["id"]
    publish(admin, pid)
    assert admin.post(f"{URL}/{pid}/archive").status_code == 409  # disable first
    assert admin.post(f"{URL}/{pid}/disable").json()["status"] == "disabled"
    assert admin.post(f"{URL}/{pid}/enable").json()["status"] == "published"
    admin.post(f"{URL}/{pid}/disable")
    assert admin.post(f"{URL}/{pid}/archive").json()["status"] == "archived"
    assert admin.patch(f"{URL}/{pid}", json={"name": "x"}).status_code == 409


def test_references_must_exist_in_this_organization(org):  # noqa: ANN001
    import uuid

    admin = org["admin"]
    pid = make(admin, subjects={"groups": [str(uuid.uuid4())]})["id"]
    rep = admin.post(f"{URL}/{pid}/validate").json()
    assert rep["valid"] is False and rep["issues"][0]["path"] == "subjects.groups"
    assert admin.post(f"{URL}/{pid}/publish", json={}).status_code == 409


def test_members_cannot_manage_and_auditors_can_only_read(org):  # noqa: ANN001
    admin, member = org["admin"], org["member"]
    assert member.post(URL, json=body()).status_code == 403
    assert member.get(URL).status_code == 403
    pid = make(admin)["id"]
    auditor = org["world"].user(org["owner"], "auditor", label="paud")
    assert auditor.get(f"{URL}/{pid}").status_code == 200
    assert auditor.post(f"{URL}/{pid}/validate").status_code == 403


def test_mandatory_policies_need_an_owner(org):  # noqa: ANN001
    admin, owner = org["admin"], org["owner"]
    assert admin.post(URL, json=body(mandatory=True)).status_code == 403
    p = owner.post(URL, json=body(mandatory=True))
    assert p.status_code == 201 and p.json()["mandatory"] is True
    pid = p.json()["id"]
    publish(owner, pid)
    assert admin.post(f"{URL}/{pid}/disable").status_code == 403  # an admin cannot switch it off
    assert owner.post(f"{URL}/{pid}/disable").status_code == 200


def test_policies_are_invisible_across_tenants(org):  # noqa: ANN001
    pid = make(org["admin"])["id"]
    other = org["world"].org("Other Policy Co", member_default_access=False)
    assert other.get(f"{URL}/{pid}").status_code == 404
    assert other.post(f"{URL}/{pid}/disable").status_code == 404
    assert other.get(URL).json()["total"] == 0


def test_duplicate_names_are_rejected(org):  # noqa: ANN001
    make(org["admin"])
    assert org["admin"].post(URL, json=body()).status_code == 409
