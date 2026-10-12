"""Searching the trash by name (filtering happens before paging and after authorization)."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"


def test_trash_search_filters_by_name_before_paging(world):  # noqa: ANN001
    owner = world.org("Trash Co", member_default_access=False)
    root = world.root_id(owner)
    ids = {n: world.mkdir(owner, root, n) for n in ("Invoices 2024", "Holiday", "invoice-old")}
    for i in ids.values():
        assert owner.delete(f"{API}/folders/{i}").status_code in (200, 204)

    everything = owner.get(f"{API}/trash").json()
    assert everything["total"] == 3

    hit = owner.get(f"{API}/trash", params={"q": "INVOICE"}).json()
    assert hit["total"] == 2
    assert {i["name"] for i in hit["items"]} == {"Invoices 2024", "invoice-old"}

    # the total reflects the filter, so paging works on the filtered list
    paged = owner.get(f"{API}/trash", params={"q": "invoice", "limit": 1}).json()
    assert paged["total"] == 2 and len(paged["items"]) == 1

    assert owner.get(f"{API}/trash", params={"q": "nothing like this"}).json()["total"] == 0


def test_trash_search_never_reveals_other_users_items(world):  # noqa: ANN001
    owner = world.org("Trash Co 2", member_default_access=False)
    root = world.root_id(owner)
    secret = world.mkdir(owner, root, "Secret plans")
    assert owner.delete(f"{API}/folders/{secret}").status_code in (200, 204)
    member = world.user(owner, "member", label="mem")
    assert member.get(f"{API}/trash", params={"q": "secret"}).json()["total"] == 0
