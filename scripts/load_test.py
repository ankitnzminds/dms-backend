"""Small HTTP load/latency probe against a RUNNING API (default: the local dev stack).

    uv run python scripts/load_test.py --base http://localhost:8000 --docs 200 --concurrency 16

Seeds a folder with N small documents as the dev admin, then measures latency percentiles and
error rates for the hottest read paths (folder listing, search, document detail, download-url)
and for concurrent uploads. Numbers depend entirely on the machine/database it runs against -
treat them as a regression baseline, not a capacity claim (see docs/performance.md).
"""

from __future__ import annotations

import argparse
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx


def pct(values: list[float], p: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(len(s) * p))] * 1000


def run(label: str, fn, n: int, concurrency: int) -> None:  # noqa: ANN001
    lat: list[float] = []
    errors = 0

    def one(i: int) -> None:
        nonlocal errors
        t = time.perf_counter()
        try:
            ok = fn(i)
        except Exception:  # noqa: BLE001
            ok = False
        lat.append(time.perf_counter() - t)
        if not ok:
            errors += 1

    start = time.perf_counter()
    with ThreadPoolExecutor(concurrency) as pool:
        list(pool.map(one, range(n)))
    wall = time.perf_counter() - start
    print(
        f"{label:<28} n={n:<4} c={concurrency:<3} rps={n / wall:7.1f}  p50={pct(lat, 0.5):7.1f}ms  p95={pct(lat, 0.95):7.1f}ms  max={max(lat) * 1000:7.1f}ms  errors={errors}"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8000")
    ap.add_argument("--docs", type=int, default=100)
    ap.add_argument("--concurrency", type=int, default=8)
    args = ap.parse_args()

    client = httpx.Client(base_url=args.base, timeout=60)
    token = client.post("/api/v1/dev/token", json={"email": "alice@acme.test"}).json()[
        "access_token"
    ]
    h = {"Authorization": f"Bearer {token}"}
    root = client.get("/api/v1/folders/root", headers=h).json()["id"]
    folder = client.post(
        "/api/v1/folders",
        json={"parent_folder_id": root, "name": f"load-{uuid.uuid4().hex[:6]}"},
        headers=h,
    ).json()["id"]

    def upload(i: int) -> bool:
        data = f"%PDF-1.4 load test document {i} {uuid.uuid4()}".encode() * 20
        s = client.post(
            f"/api/v1/folders/{folder}/uploads",
            json={
                "filename": f"load-{i}-{uuid.uuid4().hex[:4]}.pdf",
                "size_bytes": len(data),
                "content_type": "application/pdf",
            },
            headers=h,
        )
        if s.status_code != 201:
            return False
        sess = s.json()
        put = client.put(
            sess["upload_url"],
            content=data,
            headers={**h, "Content-Type": "application/octet-stream"},
        )
        fin = client.post(f"/api/v1/uploads/{sess['id']}/finalize", headers=h)
        return put.status_code == 200 and fin.status_code == 200

    print(f"target {args.base}; seeding {args.docs} documents")
    run("upload (3 calls each)", upload, args.docs, args.concurrency)
    print("waiting for the worker to scan/process ...")
    for _ in range(120):
        items = client.get(
            f"/api/v1/folders/{folder}/children", params={"limit": 200}, headers=h
        ).json()["items"]
        if sum(1 for i in items if i["status"] == "available") >= args.docs:
            break
        time.sleep(1)
    available = [i for i in items if i["status"] == "available"]
    print(f"available after processing: {len(available)}/{args.docs}")

    ids = [i["id"] for i in available] or [""]
    run(
        "list folder (limit 50)",
        lambda i: (
            client.get(
                f"/api/v1/folders/{folder}/children",
                params={"limit": 50, "offset": (i % 3) * 50},
                headers=h,
            ).status_code
            == 200
        ),
        200,
        args.concurrency,
    )
    run(
        "search (name+content)",
        lambda i: client.get("/api/v1/search", params={"q": "load"}, headers=h).status_code == 200,
        100,
        args.concurrency,
    )
    run(
        "document detail",
        lambda i: (
            client.get(f"/api/v1/documents/{ids[i % len(ids)]}", headers=h).status_code == 200
        ),
        200,
        args.concurrency,
    )
    run(
        "download-url + download",
        lambda i: (
            lambda u: (
                u.status_code == 200
                and client.get(u.json()["url"].replace(args.base, "")).status_code == 200
            )
        )(client.post(f"/api/v1/documents/{ids[i % len(ids)]}/download-url", json={}, headers=h)),
        100,
        args.concurrency,
    )
    run(
        "audit events (admin)",
        lambda i: (
            client.get("/api/v1/admin/audit-events", params={"limit": 50}, headers=h).status_code
            == 200
        ),
        50,
        args.concurrency,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
