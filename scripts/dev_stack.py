"""Run the whole backend locally with NO external services (no Docker, no Supabase).

    uv run python scripts/dev_stack.py

Starts an embedded PostgreSQL (pgserver) with a persistent data dir under .dev/, applies the
Alembic migrations, seeds a development organization, then runs the API (port 8000) and the
worker. Auth is the local HS256 provider and storage is the local filesystem; malware scanning
uses the EICAR test scanner. All of that is DEVELOPMENT ONLY and refused in staging/production.

Seeded sign-in emails: alice@acme.test (owner), bob@acme.test, carol@acme.test (members),
dave@acme.test (auditor). The frontend's "development sign-in" calls POST /api/v1/dev/token.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
DEV_DIR = ROOT / os.environ.get("DEV_STACK_DIR", ".dev")
PORT = os.environ.get("DEV_STACK_PORT", "8000")


def main() -> int:
    import pgserver

    DEV_DIR.mkdir(exist_ok=True)
    server = pgserver.get_server(DEV_DIR / "pgdata", cleanup_mode="stop")
    env = {
        **os.environ,
        "APP_ENV": "development",
        "DATABASE_URL": server.get_uri(),
        "AUTH_PROVIDER": "local",
        "LOCAL_JWT_SECRET": os.environ.get(
            "LOCAL_JWT_SECRET", "dev-only-local-jwt-secret-change-me-0123456789"
        ),
        "STORAGE_PROVIDER": "local",
        "LOCAL_STORAGE_PATH": str(DEV_DIR / "objects"),
        "MALWARE_SCANNER": "eicar",
        "DOWNLOAD_SIGNING_SECRET": os.environ.get(
            "DOWNLOAD_SIGNING_SECRET", "dev-only-download-secret-0123456789abcdef"
        ),
        "CORS_ALLOWED_ORIGINS": os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000"),
        "PUBLIC_API_BASE_URL": os.environ.get("PUBLIC_API_BASE_URL", f"http://localhost:{PORT}"),
        "FRAME_ANCESTORS": os.environ.get(
            "FRAME_ANCESTORS", "http://localhost:3000,http://localhost:3100"
        ),
        "PYTHONUTF8": "1",
    }
    os.environ.update(env)

    from app.cli import main as cli
    from app.db.session import get_sessionmaker
    from app.devseed import seed_dev

    cli(["migrate"])
    with get_sessionmaker()() as db:
        org = seed_dev(db)
        print(f"dev organization ready: {org.name}")

    procs = [
        subprocess.Popen(  # noqa: S603
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                PORT,
            ],
            cwd=ROOT,
            env=env,
        ),
        subprocess.Popen([sys.executable, "-m", "app.cli", "worker"], cwd=ROOT, env=env),
    ]
    print(f"API: http://localhost:{PORT}  (docs: /docs)   worker running. Ctrl+C to stop.")
    try:
        for p in procs:
            p.wait()
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
        server.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
