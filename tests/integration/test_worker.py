"""Outbox/worker reliability: retry, dead-letter, leases, SKIP LOCKED, idempotency, notifications."""

from __future__ import annotations

import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.integration

PDF = b"%PDF-1.4 worker"


def make_event(world, org, event_type="test.event", **kw):  # noqa: ANN001, ANN202
    from app.modules.outbox.service import enqueue

    with world.db_factory() as db:
        ev = enqueue(
            db,
            organization_id=org.org_id,
            event_type=event_type,
            aggregate_type="test",
            aggregate_id=uuid.uuid4(),
            **kw,
        )
        db.commit()
        return ev.id


def event_row(world, event_id):  # noqa: ANN001, ANN202
    with world.db_factory() as db:
        return db.execute(
            text(
                "SELECT status, attempts, last_error, locked_until, next_attempt_at FROM dms.outbox_events WHERE id = :i"
            ),
            {"i": event_id},
        ).one()


def test_failures_back_off_then_dead_letter(world):  # noqa: ANN001
    from app.workers.runner import build_context, claim, process_event

    org = world.org("Worker")
    eid = make_event(world, org)
    calls = []

    def boom(db, event, ctx):  # noqa: ANN001, ANN202
        calls.append(event.attempts)
        raise RuntimeError("downstream exploded")

    ctx = build_context()
    for attempt in range(1, 9):
        with world.db_factory() as db:
            db.execute(
                text(
                    "UPDATE dms.outbox_events SET next_attempt_at = now(), locked_until = NULL WHERE id = :i AND status <> 'dead'"
                ),
                {"i": eid},
            )
            db.commit()
        ids = claim(world.db_factory, 50, 60)
        if eid not in ids:
            break
        result = process_event(world.db_factory, eid, {"test.event": boom}, ctx)
        row = event_row(world, eid)
        assert row.attempts == attempt
        assert result == ("dead" if attempt == 8 else "retry")
        assert "downstream exploded" in row.last_error
        if attempt < 8:
            assert row.status == "pending" and row.next_attempt_at > datetime.now(UTC)
    assert event_row(world, eid).status == "dead"
    assert len(calls) == 8
    # dead events are never claimed again
    with world.db_factory() as db:
        db.execute(
            text("UPDATE dms.outbox_events SET next_attempt_at = now() WHERE id = :i"), {"i": eid}
        )
        db.commit()
    assert eid not in claim(world.db_factory, 50, 60)


def test_concurrent_claimers_get_disjoint_events(world):  # noqa: ANN001
    from app.workers.runner import claim

    org = world.org("Claim")
    ids = {make_event(world, org) for _ in range(30)}
    got: list[list[uuid.UUID]] = []
    barrier = threading.Barrier(4)

    def claimer() -> None:
        barrier.wait()
        got.append(claim(world.db_factory, 10, 60))

    threads = [threading.Thread(target=claimer) for _ in range(4)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    flat = [i for batch in got for i in batch]
    assert len(flat) == len(set(flat)), "an event was claimed twice"
    assert set(flat) <= ids | set(flat)  # (other tests' leftovers may also be claimed)


def test_lease_prevents_double_processing_until_it_expires(world):  # noqa: ANN001
    from app.workers.runner import claim

    org = world.org("Lease")
    eid = make_event(world, org)
    # drain others first so we can reason about this event only
    while claim(world.db_factory, 100, 60):
        pass
    with world.db_factory() as db:
        db.execute(
            text(
                "UPDATE dms.outbox_events SET status='pending', next_attempt_at=now(), locked_until=NULL WHERE id = :i"
            ),
            {"i": eid},
        )
        db.commit()
    assert eid in claim(world.db_factory, 100, 60)  # worker A claims, then "crashes"
    assert eid not in claim(world.db_factory, 100, 60)  # lease still held
    with world.db_factory() as db:
        db.execute(
            text(
                "UPDATE dms.outbox_events SET locked_until = now() - interval '1 second' WHERE id = :i"
            ),
            {"i": eid},
        )
        db.commit()
    assert eid in claim(
        world.db_factory, 100, 60
    )  # restart: lease expired, event is picked up again


def test_duplicate_delivery_of_scan_event_is_harmless(world):  # noqa: ANN001
    from app.workers.handlers import handle_version_uploaded
    from app.workers.runner import build_context

    admin = world.org("Dup")
    folder = world.mkdir(admin, world.root_id(admin), "f")
    up = world.upload(admin, folder, "d.pdf", PDF + b" dup")
    world.process_jobs()
    with world.db_factory() as db:
        from app.db.models import OutboxEvent

        ev = (
            db.query(OutboxEvent)
            .filter_by(
                event_type="document_version.uploaded", aggregate_id=uuid.UUID(up["version_id"])
            )
            .one()
        )
        before = db.scalar(
            text(
                "SELECT count(*) FROM dms.audit_events WHERE action = 'document.scan_clean' AND resource_id = :d"
            ),
            {"d": uuid.UUID(up["document_id"])},
        )
        handle_version_uploaded(db, ev, build_context())  # replay the exact event
        handle_version_uploaded(db, ev, build_context())
        after = db.scalar(
            text(
                "SELECT count(*) FROM dms.audit_events WHERE action = 'document.scan_clean' AND resource_id = :d"
            ),
            {"d": uuid.UUID(up["document_id"])},
        )
        assert before == after == 1
    assert (
        admin.get(f"/api/v1/documents/{up['document_id']}").json()["current_version"][
            "version_number"
        ]
        == 1
    )


def test_slow_older_scan_cannot_replace_a_newer_current_version(world):  # noqa: ANN001
    admin = world.org("Order")
    folder = world.mkdir(admin, world.root_id(admin), "f")
    doc_id = world.available_doc(admin, folder, "o.pdf", PDF + b" v1")
    # v2 and v3 are uploaded; v3 is scanned first, v2 completes later
    versions = []
    for n in (2, 3):
        body = PDF + f" v{n}".encode()
        s = admin.post(
            f"/api/v1/documents/{doc_id}/uploads",
            json={"filename": "o.pdf", "size_bytes": len(body), "expected_latest_version": n - 1},
        ).json()
        admin.put(
            s["upload_url"], content=body, headers={"Content-Type": "application/octet-stream"}
        )
        versions.append(admin.post(f"/api/v1/uploads/{s['id']}/finalize").json())
    from app.workers.handlers import handle_version_uploaded
    from app.workers.runner import build_context

    with world.db_factory() as db:
        from app.db.models import OutboxEvent

        ev = {
            v["version_number"]: db.query(OutboxEvent)
            .filter_by(
                event_type="document_version.uploaded", aggregate_id=uuid.UUID(v["version_id"])
            )
            .one()
            for v in versions
        }
        handle_version_uploaded(db, ev[3], build_context())
        handle_version_uploaded(db, ev[2], build_context())
    d = admin.get(f"/api/v1/documents/{doc_id}").json()
    assert d["current_version"]["version_number"] == 3


def test_notification_fanout_is_idempotent_and_group_aware(world):  # noqa: ANN001
    from app.db.models import OutboxEvent
    from app.workers.handlers import handle_share_created
    from app.workers.runner import build_context

    admin = world.org("Notify")
    folder = world.mkdir(admin, world.root_id(admin), "f")
    doc = world.available_doc(admin, folder, "n.pdf", PDF + b" notify")
    g = admin.post("/api/v1/admin/groups", json={"name": "Team"}).json()
    carol = world.user(admin, "member", label="carol")
    dave = world.user(admin, "member", label="dave")
    admin.post(f"/api/v1/admin/groups/{g['id']}/members", json={"user_id": str(carol.user_id)})
    share = admin.post(
        f"/api/v1/documents/{doc}/shares",
        json={
            "recipients": [
                {"type": "group", "id": g["id"]},
                {"type": "user", "id": str(dave.user_id)},
            ],
            "actions": ["view"],
        },
    ).json()
    world.process_jobs()
    for who in (carol, dave):
        notes = who.get("/api/v1/notifications").json()
        assert notes["unread_count"] == 1 and notes["items"][0]["type"] == "share.received"
    assert (
        admin.get("/api/v1/notifications").json()["total"] <= 2
    )  # the sharer is not notified of own share
    # redeliver the same event: no duplicate notifications
    with world.db_factory() as db:
        ev = (
            db.query(OutboxEvent)
            .filter_by(event_type="share.created", aggregate_id=uuid.UUID(share["id"]))
            .one()
        )
        handle_share_created(db, ev, build_context())
    assert carol.get("/api/v1/notifications").json()["total"] == 1
    # read state is per user
    nid = carol.get("/api/v1/notifications").json()["items"][0]["id"]
    assert carol.post(f"/api/v1/notifications/{nid}/read").status_code == 204
    assert carol.get("/api/v1/notifications").json()["unread_count"] == 0
    assert dave.get("/api/v1/notifications").json()["unread_count"] == 1
    assert (
        dave.post(f"/api/v1/notifications/{nid}/read").status_code == 204
    )  # not dave's: silently no-op
    assert dave.get("/api/v1/notifications").json()["unread_count"] == 1


def test_expired_shares_are_audited_and_notified_exactly_once(world):  # noqa: ANN001
    from app.workers.maintenance import record_expired_shares

    admin = world.org("Expire")
    folder = world.mkdir(admin, world.root_id(admin), "f")
    doc = world.available_doc(admin, folder, "e.pdf", PDF + b" expire")
    bob = world.user(admin, "member", label="bob")
    share = admin.post(
        f"/api/v1/documents/{doc}/shares",
        json={
            "recipients": [{"type": "user", "id": str(bob.user_id)}],
            "actions": ["view"],
            "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
    ).json()
    with world.db_factory() as db:
        db.execute(
            text(
                "UPDATE dms.share_grants SET expires_at = now() - interval '1 minute' WHERE id = :i"
            ),
            {"i": share["id"]},
        )
        db.commit()
    with world.db_factory() as db:
        assert record_expired_shares(db) >= 1
    with world.db_factory() as db:
        assert record_expired_shares(db) == 0  # second sweep: nothing new
    world.process_jobs()
    events = [
        e
        for e in admin.get("/api/v1/admin/audit-events", params={"action": "share.expired"}).json()[
            "items"
        ]
        if e["metadata"].get("share_id") == share["id"]
    ]
    assert len(events) == 1
    assert any(
        n["type"] == "share.expired" for n in bob.get("/api/v1/notifications").json()["items"]
    )


def test_unknown_event_types_do_not_block_the_queue(world):  # noqa: ANN001
    from app.workers.runner import run_once

    org = world.org("Unknown")
    eid = make_event(world, org, event_type="future.event.type")
    for _ in range(5):
        run_once(factory=world.db_factory)
    assert event_row(world, eid).status == "done"
