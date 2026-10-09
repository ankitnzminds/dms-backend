"""Backup & restore drill on a disposable embedded PostgreSQL (no external services).

    uv run python scripts/backup_restore_drill.py

1. creates database A, applies migrations, creates real data through the application services
   (org, folders, uploaded + scanned documents, versions, a share, workflow and audit events)
2. takes a logical backup (pg_dump -Fc) and copies the object store
3. restores into a brand new database B (pg_restore) and verifies:
     - row counts of every DMS table match
     - every document version's object exists in the copied store and its SHA-256 equals the
       checksum recorded in the database (bytes <-> metadata consistency)
     - the restored database passes `alembic check` and the app can authorize a request on it
4. prints a report with measured durations (use them to size RPO/RTO expectations)

Production procedure: docs/runbooks/backup-restore.md. Supabase-hosted databases use the
provider's PITR/backups plus this drill pattern against a restored branch/clone.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def sh(args: list[str], env: dict[str, str] | None = None) -> None:
    subprocess.run(args, check=True, capture_output=True, env=env)  # noqa: S603


def main() -> int:
    import pgserver
    from sqlalchemy import create_engine, text

    work = Path(tempfile.mkdtemp(prefix="dms-drill-"))
    objects = work / "objects"
    os.environ.update(
        {
            "APP_ENV": "test",
            "AUTH_PROVIDER": "local",
            "LOCAL_JWT_SECRET": "drill-secret-0123456789abcdef0123456789",
            "STORAGE_PROVIDER": "local",
            "LOCAL_STORAGE_PATH": str(objects),
            "MALWARE_SCANNER": "eicar",
            "DOWNLOAD_SIGNING_SECRET": "drill-download-secret-0123456789abcdef",
            "RATE_LIMIT_ENABLED": "false",
            "SIGNATURE_PROVIDER": "none",
            "SUPABASE_STORAGE_BUCKET": "dms-drill",
        }
    )
    srv_a = pgserver.get_server(work / "pg-a", cleanup_mode="stop")
    url_a = srv_a.get_uri()
    os.environ["DATABASE_URL"] = url_a

    from app.cli import main as cli
    from app.core.config import reset_settings_cache

    reset_settings_cache()
    cli(["migrate"])

    # ---- 1. real data through the real API
    from starlette.testclient import TestClient

    from app.adapters.identity.jwt_providers import LocalJwtProvider
    from app.core.config import get_settings
    from app.db.models import Folder, Membership, User
    from app.db.session import get_sessionmaker
    from app.main import create_app
    from app.modules.organizations.service import bootstrap_organization
    from app.workers.runner import run_once

    factory = get_sessionmaker()
    with factory() as db:
        org = bootstrap_organization(
            db,
            name="Drill Org",
            slug="drill",
            owner_email="owner@drill.test",
            member_default_access=False,
        )
        owner = db.query(User).filter_by(email="owner@drill.test").one()
        owner.identity_provider, owner.external_subject, owner.status = (
            "local",
            "sub-drill",
            "active",
        )
        for m in db.query(Membership).filter_by(user_id=owner.id):
            m.status = "active"
        db.commit()
        root = db.query(Folder).filter_by(organization_id=org.id, parent_folder_id=None).one().id
        org_id = org.id
    token = LocalJwtProvider(get_settings()).issue_token(
        subject="sub-drill", email="owner@drill.test"
    )
    headers = {"Authorization": f"Bearer {token}", "X-Organization-Id": str(org_id)}
    with TestClient(create_app()) as client:
        folder = client.post(
            "/api/v1/folders",
            json={"parent_folder_id": str(root), "name": "Contracts"},
            headers=headers,
        ).json()["id"]
        for i in range(5):
            data = b"%PDF-1.4 drill document " + str(i).encode() * 2000
            s = client.post(
                f"/api/v1/folders/{folder}/uploads",
                json={
                    "filename": f"doc{i}.pdf",
                    "size_bytes": len(data),
                    "content_type": "application/pdf",
                },
                headers=headers,
            ).json()
            client.put(
                s["upload_url"],
                content=data,
                headers={**headers, "Content-Type": "application/octet-stream"},
            )
            doc_id = client.post(f"/api/v1/uploads/{s['id']}/finalize", headers=headers).json()[
                "document_id"
            ]
            if i == 0:
                first = doc_id
        for _ in range(10):
            if run_once(factory=factory) == 0:
                break
        v2 = b"%PDF-1.4 second version of doc0"
        s = client.post(
            f"/api/v1/documents/{first}/uploads",
            json={"filename": "doc0.pdf", "size_bytes": len(v2), "expected_latest_version": 1},
            headers=headers,
        ).json()
        client.put(
            s["upload_url"],
            content=v2,
            headers={**headers, "Content-Type": "application/octet-stream"},
        )
        client.post(f"/api/v1/uploads/{s['id']}/finalize", headers=headers)
        for _ in range(10):
            if run_once(factory=factory) == 0:
                break

    tables_sql = "SELECT tablename FROM pg_tables WHERE schemaname = 'dms' AND tablename <> 'alembic_version' ORDER BY 1"
    eng_a = create_engine(url_a.replace("postgresql://", "postgresql+psycopg://"))
    with eng_a.connect() as conn:
        tables = [r[0] for r in conn.execute(text(tables_sql))]
        counts_a = {
            t: conn.execute(text(f'SELECT count(*) FROM dms."{t}"')).scalar()  # noqa: S608
            for t in tables
        }

    # ---- 2. backup (database + object store)
    bin_dir = Path(pgserver.__file__).parent / "pginstall" / "bin"
    dump = work / "dms.dump"
    t0 = time.perf_counter()
    sh([str(bin_dir / "pg_dump"), "-Fc", "-n", "dms", "-f", str(dump), url_a])
    backup_s = time.perf_counter() - t0
    backup_objects = work / "objects-backup"
    shutil.copytree(objects, backup_objects)

    # ---- 3. restore into a brand new database
    srv_b = pgserver.get_server(work / "pg-b", cleanup_mode="stop")
    url_b = srv_b.get_uri()
    t0 = time.perf_counter()
    sh([str(bin_dir / "pg_restore"), "--no-owner", "-d", url_b, str(dump)])
    restore_s = time.perf_counter() - t0

    eng_b = create_engine(url_b.replace("postgresql://", "postgresql+psycopg://"))
    with eng_b.connect() as conn:
        counts_b = {
            t: conn.execute(text(f'SELECT count(*) FROM dms."{t}"')).scalar()  # noqa: S608
            for t in tables
        }
        versions = conn.execute(
            text(
                "SELECT v.object_key, v.sha256, v.size_bytes, l.bucket FROM dms.document_versions v JOIN dms.storage_locations l ON l.id = v.storage_location_id"
            )
        ).all()
        rls_off = conn.execute(
            text(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='dms' AND c.relkind='r' AND NOT c.relrowsecurity AND c.relname <> 'alembic_version'"
            )
        ).scalar()
        triggers = conn.execute(
            text(
                "SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='dms' AND NOT t.tgisinternal"
            )
        ).scalar()

    mismatches = {t: (counts_a[t], counts_b[t]) for t in tables if counts_a[t] != counts_b[t]}
    bad_objects = []
    for key, sha, size, bucket in versions:
        path = backup_objects / bucket / key
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != sha
            or path.stat().st_size != size
        ):
            bad_objects.append(key)

    # alembic consistency + a real authorization decision on the restored database
    os.environ["DATABASE_URL"] = url_b
    reset_settings_cache()
    from app.db.session import get_engine

    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
    from alembic import command

    from app.cli import _alembic_config

    command.check(_alembic_config())
    with TestClient(create_app()) as client:
        r = client.get(f"/api/v1/folders/{folder}/children", headers=headers)
        restored_ok = r.status_code == 200 and r.json()["total"] == 5

    ok = not mismatches and not bad_objects and restored_ok and rls_off == 0 and triggers >= 3
    print("=== backup / restore drill ===")
    print(f"tables compared: {len(tables)}; rows total: {sum(counts_a.values())}")
    print(f"row-count mismatches: {mismatches or 'none'}")
    print(
        f"object versions verified against SHA-256: {len(versions)}; bad: {bad_objects or 'none'}"
    )
    print(
        f"RLS enabled on every table after restore: {rls_off == 0}; user triggers restored: {triggers}"
    )
    print(f"restored database serves authorized API request: {restored_ok}")
    print(
        f"pg_dump: {backup_s:.2f}s, pg_restore: {restore_s:.2f}s ({dump.stat().st_size / 1024:.0f} KiB dump)"
    )
    print("RESULT:", "PASS" if ok else "FAIL")
    shutil.rmtree(work, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
