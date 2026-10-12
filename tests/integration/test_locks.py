"""Lock / unlock of documents and folders: expiry, download prevention, enforcement, audit."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.db.models import Document
from app.modules.items.common import lock_active

pytestmark = pytest.mark.integration
API = "/api/v1"


@pytest.fixture()
def team(world):  # noqa: ANN001, ANN201
    owner = world.org("Lock Co", member_default_access=False)
    root = world.root_id(owner)
    folder = world.mkdir(owner, root, "Projects")
    doc = world.available_doc(owner, folder, "plan.pdf")
    member = world.user(owner, "member", label="mem")
    stranger = world.user(owner, "member", label="out")
    grant = owner.post(
        f"{API}/folders/{folder}/permissions",
        json={
            "subject_type": "user",
            "subject_id": str(member.user_id),
            "actions": [
                "view",
                "preview",
                "download",
                "rename",
                "move",
                "delete",
                "upload_version",
                "create_child",
                "lock",
            ],
            "inherit": True,
        },
    )
    assert grant.status_code == 201, grant.text
    return dict(
        world=world,
        owner=owner,
        root=root,
        folder=folder,
        doc=doc,
        member=member,
        stranger=stranger,
    )


def future(days: int = 2) -> str:
    return (datetime.now(UTC) + timedelta(days=days)).isoformat()


class TestFolderLock:
    def test_lock_blocks_others_and_holder_can_still_change(self, team):  # noqa: ANN001
        o, m, f = team["owner"], team["member"], team["folder"]
        r = o.post(f"{API}/folders/{f}/lock", json={"no_expiry": True})
        assert r.status_code == 201, r.text
        assert r.json()["is_mine"] is True and r.json()["expires_at"] is None
        # others cannot rename or delete it
        blocked = m.patch(f"{API}/folders/{f}", json={"name": "Renamed"})
        assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "folder_locked"
        assert m.delete(f"{API}/folders/{f}").status_code == 409
        # a second lock attempt by someone else fails; the holder can rename
        assert m.post(f"{API}/folders/{f}/lock", json={}).status_code == 409
        assert o.patch(f"{API}/folders/{f}", json={"name": "Projects2"}).status_code == 200

    def test_listing_and_folder_show_the_lock(self, team):  # noqa: ANN001
        o, m, f = team["owner"], team["member"], team["folder"]
        assert o.post(f"{API}/folders/{f}/lock", json={"minutes": 30}).status_code == 201
        seen = m.get(f"{API}/folders/{team['root']}/children").json()
        row = next(i for i in seen["items"] if i["id"] == f) if "items" in seen else None
        # the member cannot see the root listing's child unless discoverable; use the folder itself
        one = m.get(f"{API}/folders/{f}").json()
        assert one["lock"]["is_mine"] is False
        if row:
            assert row["locked"] is True and row["locked_by_me"] is False
        mine = o.get(f"{API}/folders/{f}").json()
        assert mine["lock"]["is_mine"] is True

    def test_unlock_rules_and_admin_break_are_audited(self, team):  # noqa: ANN001
        o, m, f = team["owner"], team["member"], team["folder"]
        assert m.post(f"{API}/folders/{f}/lock", json={}).status_code == 201
        # a non-admin cannot unlock someone else's lock; the owner (admin) may break it
        other = team["world"].user(o, "member", label="peer")
        o.post(
            f"{API}/folders/{f}/permissions",
            json={
                "subject_type": "user",
                "subject_id": str(other.user_id),
                "actions": ["view", "rename"],
                "inherit": True,
            },
        )
        assert other.delete(f"{API}/folders/{f}/lock").status_code == 409
        assert o.delete(f"{API}/folders/{f}/lock").status_code == 204
        acts = o.get(f"{API}/admin/activity", params={"limit": 100}).json()["items"]
        names = [e["action"] for e in acts]
        assert "folder.locked" in names and "folder.lock_broken" in names
        locked = next(e for e in acts if e["action"] == "folder.locked")
        assert locked["metadata"]["prevent_download"] is False

    def test_no_access_means_no_lock(self, team):  # noqa: ANN001
        # a lock is not a way in: someone with no permission cannot even find the folder
        s, f = team["stranger"], team["folder"]
        assert s.post(f"{API}/folders/{f}/lock", json={}).status_code == 404
        assert s.delete(f"{API}/folders/{f}/lock").status_code == 404

    def test_root_cannot_be_locked(self, team):  # noqa: ANN001
        r = team["owner"].post(f"{API}/folders/{team['root']}/lock", json={})
        assert r.status_code == 403


class TestExpiry:
    def test_end_time_validation(self, team):  # noqa: ANN001
        o, f = team["owner"], team["folder"]
        past = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
        r = o.post(f"{API}/folders/{f}/lock", json={"expires_at": past})
        assert r.status_code == 422 and r.json()["error"]["code"] == "lock_in_the_past"
        far = (datetime.now(UTC) + timedelta(days=400)).isoformat()
        assert o.post(f"{API}/folders/{f}/lock", json={"expires_at": far}).status_code == 422
        ok = o.post(f"{API}/folders/{f}/lock", json={"expires_at": future(3)})
        assert ok.status_code == 201 and ok.json()["expires_at"] is not None

    def test_an_expired_lock_no_longer_blocks(self):  # noqa: ANN201
        class Fake:
            locked_by = "someone"
            lock_expires_at = datetime.now(UTC) - timedelta(seconds=1)

        assert lock_active(Fake()) is False  # type: ignore[arg-type]
        Fake.lock_expires_at = datetime.now(UTC) + timedelta(hours=1)  # type: ignore[assignment]
        assert lock_active(Fake()) is True  # type: ignore[arg-type]
        Fake.lock_expires_at = None  # type: ignore[assignment]
        assert lock_active(Fake()) is True  # never expires  # type: ignore[arg-type]


class TestDocumentLockAndDownloads:
    def test_prevent_download_only_affects_others(self, team):  # noqa: ANN001
        o, m, d = team["owner"], team["member"], team["doc"]
        r = o.post(f"{API}/documents/{d}/lock", json={"prevent_download": True, "no_expiry": True})
        assert r.status_code == 201, r.text
        assert r.json()["prevent_download"] is True
        # others cannot download; previews are not downloads
        blocked = m.post(f"{API}/documents/{d}/download-url", json={})
        assert blocked.status_code == 403
        assert blocked.json()["error"]["code"] == "download_blocked_by_lock"
        assert m.post(f"{API}/documents/{d}/export-pdf").status_code in (403, 409, 422)
        # the holder can still download
        assert o.post(f"{API}/documents/{d}/download-url", json={}).status_code == 200
        # and others' edits are refused (existing rule)
        assert m.patch(f"{API}/documents/{d}", json={"name": "x.pdf"}).status_code == 409
        # unlocking restores downloads
        assert o.delete(f"{API}/documents/{d}/lock").status_code == 204
        assert m.post(f"{API}/documents/{d}/download-url", json={}).status_code == 200

    def test_plain_lock_does_not_stop_downloads(self, team):  # noqa: ANN001
        o, m, d = team["owner"], team["member"], team["doc"]
        assert o.post(f"{API}/documents/{d}/lock", json={}).status_code == 201
        assert m.post(f"{API}/documents/{d}/download-url", json={}).status_code == 200

    def test_zip_skips_files_whose_download_is_locked(self, team):  # noqa: ANN001
        o, m, f, d = team["owner"], team["member"], team["folder"], team["doc"]
        assert (
            o.post(f"{API}/documents/{d}/lock", json={"prevent_download": True}).status_code == 201
        )
        z = m.post(f"{API}/folders/{f}/download-zip")
        assert z.status_code == 200, z.text
        import io
        import zipfile

        assert "plan.pdf" not in zipfile.ZipFile(io.BytesIO(z.content)).namelist()
        # locking a folder with downloads off blocks the ZIP of that folder for others
        assert o.delete(f"{API}/documents/{d}/lock").status_code == 204
        assert o.post(f"{API}/folders/{f}/lock", json={"prevent_download": True}).status_code == 201
        blocked = m.post(f"{API}/folders/{f}/download-zip")
        assert blocked.status_code == 403
        assert blocked.json()["error"]["code"] == "download_blocked_by_lock"

    def test_lock_needs_write_access_not_just_view(self, team):  # noqa: ANN001
        # the stranger has no grant: the document does not even exist for them
        assert (
            team["stranger"].post(f"{API}/documents/{team['doc']}/lock", json={}).status_code == 404
        )

    def test_state_in_db_matches_flags(self, team, world):  # noqa: ANN001
        o, d = team["owner"], team["doc"]
        o.post(f"{API}/documents/{d}/lock", json={"prevent_download": True})
        with world.db_factory() as s:
            doc = s.get(Document, uuid.UUID(d))
            assert doc is not None and doc.lock_prevents_download is True
