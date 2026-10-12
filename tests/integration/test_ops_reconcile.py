"""Dead background events are visible, audited and replayable; missing storage objects are detectable."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import AuditEvent, OutboxEvent

pytestmark = pytest.mark.integration
API = "/api/v1/admin/ops"
PDF = b"%PDF-1.4 reconcile"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    admin = world.org("Ops Co", quota_bytes=2_000_000)
    member = world.user(admin, "member", label="opsmember")
    return dict(world=world, admin=admin, member=member, root=world.root_id(admin))


def add_event(world, org_id, status="dead"):  # noqa: ANN001, ANN201
    with world.db_factory() as db:
        e = OutboxEvent(
            id=uuid.uuid4(),
            organization_id=org_id,
            event_type="storage.delete_objects",
            aggregate_type="x",
            aggregate_id=uuid.uuid4(),
            payload={},
            status=status,
            attempts=8,
            max_attempts=8,
            last_error="boom",
        )
        db.add(e)
        db.commit()
        return str(e.id)


def test_event_that_exhausts_retries_is_audited_for_the_tenant(env):  # noqa: ANN001
    from app.workers import runner

    w = env["world"]
    eid = add_event(w, env["admin"].org_id, status="processing")
    assert (
        runner._record_failure(
            w.db_factory, uuid.UUID(eid), RuntimeError("secret detail"), "storage.delete_objects"
        )
        == "dead"
    )  # noqa: SLF001
    with w.db_factory() as db:
        ev = db.scalars(
            select(AuditEvent).where(
                AuditEvent.action == "outbox.event_dead", AuditEvent.resource_id == uuid.UUID(eid)
            )
        ).first()
    assert ev is not None and ev.organization_id == env["admin"].org_id
    assert ev.event_metadata["event_type"] == "storage.delete_objects"
    shown = env["admin"].get(f"{API}/dead-events").json()
    assert eid in {e["id"] for e in shown}


def test_dead_events_listing_and_replay_rules(env):  # noqa: ANN001
    w, a = env["world"], env["admin"]
    eid = add_event(w, a.org_id)
    assert env["member"].get(f"{API}/dead-events").status_code == 403
    assert env["member"].post(f"{API}/dead-events/{eid}/replay").status_code == 403
    other = w.org("Other Ops Co", member_default_access=False)
    assert other.get(f"{API}/dead-events").json() == []
    assert other.post(f"{API}/dead-events/{eid}/replay").status_code == 404
    r = a.post(f"{API}/dead-events/{eid}/replay")
    assert r.status_code == 200
    with w.db_factory() as db:
        e = db.get(OutboxEvent, uuid.UUID(eid))
        assert e.status == "pending" and e.attempts == 0
    assert a.post(f"{API}/dead-events/{eid}/replay").status_code == 409  # no longer dead
    actions = {
        x["action"]
        for x in a.get("/api/v1/admin/audit-events", params={"limit": 100}).json()["items"]
    }
    assert "outbox.event_replayed" in actions


def test_storage_check_reports_a_missing_object_and_is_admin_only(env):  # noqa: ANN001
    from app.core.config import get_settings

    w, a = env["world"], env["admin"]
    unique = PDF + uuid.uuid4().hex.encode()
    doc = w.available_doc(a, env["root"], "check.pdf", unique)
    ok = a.get(f"{API}/storage-check").json()
    assert ok["checked"] >= 1 and ok["missing"] == [] and ok["errors"] == 0
    base = Path(get_settings().local_storage_path)
    victim = next(p for p in base.rglob("*") if p.is_file() and p.read_bytes() == unique)
    victim.unlink()
    bad = a.get(f"{API}/storage-check").json()
    assert [m["document_id"] for m in bad["missing"]] == [doc]
    assert env["member"].get(f"{API}/storage-check").status_code == 403
    assert (
        w.org("Third Ops Co", member_default_access=False)
        .get(f"{API}/storage-check")
        .json()["checked"]
        == 0
    )
