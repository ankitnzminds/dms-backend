"""Schema-level guarantees: migrations, RLS, immutability triggers, tenant-consistency constraints."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]


def alembic_cfg(url: str):  # noqa: ANN202
    from alembic.config import Config

    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.cmd_opts = type("o", (), {"x": [f"url={url}"]})()  # type: ignore[attr-defined]
    return cfg


def test_models_and_migrations_are_consistent(database_url):  # noqa: ANN001
    from alembic import command

    command.check(alembic_cfg(database_url))


def test_every_dms_table_has_row_level_security_enabled(world):  # noqa: ANN001
    with world.db_factory() as db:
        rows = db.execute(
            text(
                "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = 'dms' AND c.relkind = 'r' AND NOT c.relrowsecurity AND c.relname <> 'alembic_version'"
            )
        ).all()
        assert rows == [], f"tables without RLS: {rows}"
        n_tables = db.scalar(text("SELECT count(*) FROM pg_tables WHERE schemaname = 'dms'"))
        assert n_tables >= 20


def test_api_roles_have_no_access_to_dms_schema(world):  # noqa: ANN001
    """Supabase's PostgREST roles must not reach DMS data (RLS deny-all + no grants)."""
    with world.db_factory() as db:
        db.execute(
            text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dms_probe_anon') "
                "THEN CREATE ROLE dms_probe_anon NOLOGIN; END IF; END $$"
            )
        )
        db.commit()
        has_usage = db.scalar(text("SELECT has_schema_privilege('dms_probe_anon', 'dms', 'USAGE')"))
        has_select = db.scalar(
            text("SELECT has_table_privilege('dms_probe_anon', 'dms.documents', 'SELECT')")
        )
        assert has_usage is False and has_select is False
        # even if someone granted table access by mistake, RLS (no policies) would still deny rows
        db.execute(text("GRANT USAGE ON SCHEMA dms TO dms_probe_anon"))
        db.execute(text("GRANT SELECT ON dms.documents TO dms_probe_anon"))
        db.commit()
        db.execute(text("SET LOCAL ROLE dms_probe_anon"))
        assert db.scalar(text("SELECT count(*) FROM dms.documents")) == 0
        db.rollback()
        db.execute(text("REVOKE ALL ON dms.documents FROM dms_probe_anon"))
        db.execute(text("REVOKE ALL ON SCHEMA dms FROM dms_probe_anon"))
        db.commit()


def test_audit_events_are_append_only(world):  # noqa: ANN001
    admin = world.org("Audit")
    world.mkdir(admin, world.root_id(admin), "x")
    with world.db_factory() as db:
        for sql in (
            "UPDATE dms.audit_events SET action = 'tampered'",
            "DELETE FROM dms.audit_events",
            "TRUNCATE dms.audit_events",
        ):
            with pytest.raises(DBAPIError) as exc:
                db.execute(text(sql))
            assert "append-only" in str(exc.value) or "not permitted" in str(exc.value)
            db.rollback()
        assert (
            db.scalar(text("SELECT count(*) FROM dms.audit_events WHERE action = 'folder.created'"))
            >= 1
        )


def test_composite_foreign_keys_prevent_cross_tenant_references(world):  # noqa: ANN001
    a, b = world.org("A"), world.org("B")
    b_folder = world.mkdir(b, world.root_id(b), "bf")
    with world.db_factory() as db:
        # a document in org A pointing at org B's folder
        with pytest.raises(IntegrityError):
            db.execute(
                text(
                    "INSERT INTO dms.documents (id, organization_id, folder_id, name, status) VALUES (:i, :o, :f, 'x', 'processing')"
                ),
                {"i": uuid.uuid4(), "o": a.org_id, "f": uuid.UUID(b_folder)},
            )
        db.rollback()
        # a folder in org A whose parent is in org B
        with pytest.raises(IntegrityError):
            db.execute(
                text(
                    "INSERT INTO dms.folders (id, organization_id, parent_folder_id, name) VALUES (:i, :o, :p, 'x')"
                ),
                {"i": uuid.uuid4(), "o": a.org_id, "p": uuid.UUID(b_folder)},
            )
        db.rollback()


def test_structural_constraints(world):  # noqa: ANN001
    org = world.org("Constraints")
    root = world.root_id(org)
    f = world.mkdir(org, root, "x")
    with world.db_factory() as db:
        bad = [
            (
                "one root per org",
                "INSERT INTO dms.folders (id, organization_id, name) VALUES (gen_random_uuid(), :o, 'second root')",
                {"o": org.org_id},
            ),
            (
                "negative quota",
                "UPDATE dms.organizations SET quota_used_bytes = -1 WHERE id = :o",
                {"o": org.org_id},
            ),
            (
                "slash in name",
                "INSERT INTO dms.folders (id, organization_id, parent_folder_id, name) VALUES (gen_random_uuid(), :o, :p, 'a/b')",
                {"o": org.org_id, "p": uuid.UUID(root)},
            ),
            (
                "empty name",
                "INSERT INTO dms.folders (id, organization_id, parent_folder_id, name) VALUES (gen_random_uuid(), :o, :p, '  ')",
                {"o": org.org_id, "p": uuid.UUID(root)},
            ),
            (
                "own parent",
                "UPDATE dms.folders SET parent_folder_id = id WHERE id = :f",
                {"f": uuid.UUID(f)},
            ),
            (
                "uppercase email",
                "INSERT INTO dms.users (id, email, status) VALUES (gen_random_uuid(), 'UP@X.Y', 'active')",
                {},
            ),
            (
                "bad share status",
                "INSERT INTO dms.share_grants (id, organization_id, resource_type, resource_id, created_by, actions) VALUES (gen_random_uuid(), :o, 'folder', :f, :u, ARRAY[]::varchar[])",
                {"o": org.org_id, "f": uuid.UUID(f), "u": org.user_id},
            ),
            (
                "org grant with subject",
                "INSERT INTO dms.permission_grants (id, organization_id, resource_type, resource_id, subject_type, subject_id, actions) VALUES (gen_random_uuid(), :o, 'folder', :f, 'organization', :u, ARRAY['view'])",
                {"o": org.org_id, "f": uuid.UUID(f), "u": org.user_id},
            ),
        ]
        for label, sql, params in bad:
            with pytest.raises(IntegrityError):
                db.execute(text(sql), params)
            db.rollback()
            assert label  # keep label visible in failures


def test_stepwise_upgrade_with_existing_data(database_url):  # noqa: ANN001
    """The hardening migration must apply on a database that already holds data."""
    from alembic import command

    admin_engine = create_engine(
        database_url.replace("postgresql://", "postgresql+psycopg://"), isolation_level="AUTOCOMMIT"
    )
    name = f"dms_stepwise_{uuid.uuid4().hex[:8]}"
    try:
        with admin_engine.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{name}"'))
    except Exception:  # noqa: BLE001
        pytest.skip("cannot create a scratch database in this environment")
    scratch_url = database_url.rsplit("/", 1)[0] + f"/{name}"
    try:
        cfg = alembic_cfg(scratch_url)
        command.upgrade(cfg, "03af22e4d963")  # initial schema only
        engine = create_engine(scratch_url.replace("postgresql://", "postgresql+psycopg://"))
        org_id, user_id = uuid.uuid4(), uuid.uuid4()
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO dms.organizations (id, name, slug, status) VALUES (:i, 'Old', 'old', 'active')"
                ),
                {"i": org_id},
            )
            conn.execute(
                text(
                    "INSERT INTO dms.users (id, email, status) VALUES (:i, 'old@x.test', 'active')"
                ),
                {"i": user_id},
            )
            conn.execute(
                text(
                    "INSERT INTO dms.audit_events (id, organization_id, action, outcome) VALUES (gen_random_uuid(), :o, 'legacy', 'success')"
                ),
                {"o": org_id},
            )
        command.upgrade(cfg, "head")
        command.check(cfg)
        with engine.begin() as conn:
            assert (
                conn.scalar(text("SELECT count(*) FROM dms.audit_events WHERE action = 'legacy'"))
                == 1
            )
            with pytest.raises(DBAPIError):
                conn.execute(text("UPDATE dms.audit_events SET action = 'x'"))
        engine.dispose()
    finally:
        with admin_engine.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin_engine.dispose()
