"""Test harness.

Integration tests run against a REAL PostgreSQL: either TEST_DATABASE_URL (CI service container /
a disposable non-production database) or an embedded PostgreSQL started by ``pgserver``.
Migrations are applied through Alembic, so every test run also verifies the migration path.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

# --- environment must be set before the app modules read settings -----------------------
_TMP = Path(tempfile.mkdtemp(prefix="dms-tests-"))
os.environ.update(
    {
        "APP_ENV": "test",
        "AUTH_PROVIDER": "local",
        "LOCAL_JWT_SECRET": "test-local-jwt-secret-0123456789abcdef0123456789",
        "STORAGE_PROVIDER": "local",
        "LOCAL_STORAGE_PATH": str(_TMP / "objects"),
        "MALWARE_SCANNER": "eicar",
        "DOWNLOAD_SIGNING_SECRET": "test-download-signing-secret-0123456789abcdef",
        "RATE_LIMIT_ENABLED": "false",
        "PUBLIC_API_BASE_URL": "http://testserver",
        "DATABASE_URL": "postgresql://placeholder:placeholder@127.0.0.1:1/placeholder",
        "SUPABASE_STORAGE_BUCKET": "dms-test",
        "SIGNATURE_PROVIDER": "fake",
        "AI_PROVIDER": "fake",
        "AGENT_RUN_MODE": "inline",
        "SIGNATURE_WEBHOOK_SECRET": "test-signature-webhook-secret-0123456789",
    }
)


def _reset_caches() -> None:
    from app.adapters.storage.registry import reset_storage_registry
    from app.api.deps import reset_identity_provider
    from app.core.config import reset_settings_cache
    from app.db.session import get_engine, get_sessionmaker

    reset_settings_cache()
    get_engine.cache_clear()
    get_sessionmaker.cache_clear()
    reset_storage_registry()
    reset_identity_provider()
    from app.adapters.signatures.factory import reset_signature_provider

    reset_signature_provider()
    from app.adapters.llm.factory import reset_llm

    reset_llm()


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    external = os.environ.get("TEST_DATABASE_URL")
    server = None
    if external:
        url = external
    else:
        import pgserver

        server = pgserver.get_server(_TMP / "pgdata", cleanup_mode="stop")
        url = server.get_uri()
    os.environ["DATABASE_URL"] = url
    _reset_caches()

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    cfg.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "migrations"))
    cfg.cmd_opts = type("o", (), {"x": [f"url={url}"]})()  # type: ignore[attr-defined]
    command.upgrade(cfg, "head")
    yield url
    from app.db.session import get_engine

    get_engine().dispose()
    if server is not None:
        server.cleanup()
    shutil.rmtree(_TMP, ignore_errors=True)


@pytest.fixture(scope="session")
def app(database_url: str):  # noqa: ANN201
    from app.main import create_app

    return create_app()


@pytest.fixture()
def db(database_url: str) -> Iterator:
    from app.db.session import get_sessionmaker

    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(autouse=True)
def _reset_rate_limiter() -> None:
    from app.core.ratelimit import limiter

    limiter.reset()


# ------------------------------------------------------------------------------ actors
@dataclass
class Actor:
    """A signed-in user bound to one organization, with a thin HTTP helper."""

    client: object
    user_id: uuid.UUID
    email: str
    subject: str
    org_id: uuid.UUID
    role: str
    token: str

    @property
    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}", "X-Organization-Id": str(self.org_id)}

    def _call(self, method: str, url: str, **kw):  # noqa: ANN202, ANN003
        headers = {**self.headers, **kw.pop("headers", {})}
        return getattr(self.client, method)(url, headers=headers, **kw)

    def get(self, url: str, **kw):  # noqa: ANN202, ANN003
        return self._call("get", url, **kw)

    def post(self, url: str, **kw):  # noqa: ANN202, ANN003
        return self._call("post", url, **kw)

    def put(self, url: str, **kw):  # noqa: ANN202, ANN003
        return self._call("put", url, **kw)

    def patch(self, url: str, **kw):  # noqa: ANN202, ANN003
        return self._call("patch", url, **kw)

    def delete(self, url: str, **kw):  # noqa: ANN202, ANN003
        return self._call("delete", url, **kw)


class World:
    """Factory for organizations, users and signed-in actors."""

    def __init__(self, client, db_factory) -> None:  # noqa: ANN001
        self.client = client
        self.db_factory = db_factory

    def token_for(self, subject: str, email: str, *, issued_at=None, verified: bool = True) -> str:  # noqa: ANN001
        from app.adapters.identity.jwt_providers import LocalJwtProvider
        from app.core.config import get_settings

        return LocalJwtProvider(get_settings()).issue_token(
            subject=subject, email=email, issued_at=issued_at, email_verified=verified
        )

    def org(
        self,
        name: str = "Acme",
        *,
        quota_bytes: int | None = None,
        member_default_access: bool = True,
    ) -> Actor:
        """Create an organization and return its signed-in owner."""
        from sqlalchemy import select

        from app.db.enums import UserStatus
        from app.db.models import Folder, User
        from app.modules.organizations.service import bootstrap_organization

        slug = f"org-{uuid.uuid4().hex[:10]}"
        email = f"owner-{uuid.uuid4().hex[:8]}@{slug}.test"
        with self.db_factory() as db:
            org = bootstrap_organization(
                db,
                name=name,
                slug=slug,
                owner_email=email,
                owner_display_name="Owner",
                quota_bytes=quota_bytes,
                member_default_access=member_default_access,
            )
            user = db.scalar(select(User).where(User.email == email))
            assert user is not None
            subject = f"sub-{uuid.uuid4().hex}"
            user.identity_provider, user.external_subject = "local", subject
            user.status = UserStatus.ACTIVE.value
            user.email_verified = True
            from app.db.models import Membership

            for m in db.scalars(select(Membership).where(Membership.user_id == user.id)):
                m.status = "active"
            db.commit()
            root = db.scalar(
                select(Folder).where(
                    Folder.organization_id == org.id, Folder.parent_folder_id.is_(None)
                )
            )
            assert root is not None
            self.root_ids = getattr(self, "root_ids", {})
            self.root_ids[org.id] = root.id
            return Actor(
                self.client,
                user.id,
                email,
                subject,
                org.id,
                "owner",
                self.token_for(subject, email),
            )

    def root_id(self, actor: Actor) -> str:
        return str(self.root_ids[actor.org_id])

    def user(
        self,
        org: Actor,
        role: str = "member",
        *,
        group_ids: list[uuid.UUID] | None = None,
        label: str = "u",
    ) -> Actor:
        """Add an active user with the given role to the organization."""
        from app.db.models import GroupMembership, Membership, User

        email = f"{label}-{uuid.uuid4().hex[:8]}@{org.email.split('@')[1]}"
        subject = f"sub-{uuid.uuid4().hex}"
        with self.db_factory() as db:
            user = User(
                id=uuid.uuid4(),
                email=email,
                display_name=label.title(),
                status="active",
                identity_provider="local",
                external_subject=subject,
                email_verified=True,
            )
            db.add(user)
            db.flush()
            db.add(
                Membership(
                    id=uuid.uuid4(),
                    organization_id=org.org_id,
                    user_id=user.id,
                    role=role,
                    status="active",
                )
            )
            for gid in group_ids or []:
                db.add(GroupMembership(group_id=gid, user_id=user.id, organization_id=org.org_id))
            db.commit()
            uid = user.id
        return Actor(
            self.client, uid, email, subject, org.org_id, role, self.token_for(subject, email)
        )

    # --- convenience wrappers around the real API ------------------------------------
    def mkdir(self, actor: Actor, parent_id: str, name: str) -> str:
        r = actor.post("/api/v1/folders", json={"parent_folder_id": parent_id, "name": name})
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def upload(
        self,
        actor: Actor,
        folder_id: str,
        filename: str,
        data: bytes,
        *,
        content_type: str = "application/pdf",
    ) -> dict:
        r = actor.post(
            f"/api/v1/folders/{folder_id}/uploads",
            json={"filename": filename, "size_bytes": len(data), "content_type": content_type},
        )
        assert r.status_code == 201, r.text
        session = r.json()
        r = actor.put(
            session["upload_url"],
            content=data,
            headers={"Content-Type": "application/octet-stream"},
        )
        assert r.status_code == 200, r.text
        r = actor.post(f"/api/v1/uploads/{session['id']}/finalize")
        assert r.status_code == 200, r.text
        return r.json()

    def process_jobs(self) -> int:
        """Run the outbox worker until idle (scan, notifications, ...)."""
        from app.workers.runner import build_context, run_once

        ctx = build_context()
        total = 0
        for _ in range(20):
            handled = run_once(ctx=ctx, factory=self.db_factory)
            total += handled
            if handled == 0:
                break
        return total

    def available_doc(
        self,
        actor: Actor,
        folder_id: str,
        filename: str = "file.pdf",
        data: bytes = b"%PDF-1.4 hello",
    ) -> str:
        doc = self.upload(actor, folder_id, filename, data)
        self.process_jobs()
        return doc["document_id"]


@pytest.fixture()
def world(app, database_url):  # noqa: ANN001, ANN201
    from starlette.testclient import TestClient

    from app.db.session import get_sessionmaker

    with TestClient(app, raise_server_exceptions=False) as client:
        yield World(client, get_sessionmaker())
