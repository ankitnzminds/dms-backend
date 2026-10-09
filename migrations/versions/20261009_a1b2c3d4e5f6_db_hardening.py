"""DB hardening: immutability triggers, RLS deny-all, revoke API-role access.

Revision ID: a1b2c3d4e5f6
Revises: 03af22e4d963
Create Date: 2026-10-09 13:50:00
"""

from alembic import op

revision = "a1b2c3d4e5f6"
down_revision = "03af22e4d963"
branch_labels = None
depends_on = None

TABLES = [
    "organizations",
    "users",
    "memberships",
    "groups",
    "group_memberships",
    "storage_locations",
    "folders",
    "documents",
    "document_versions",
    "upload_sessions",
    "quota_ledger_entries",
    "permission_grants",
    "share_grants",
    "share_recipients",
    "audit_events",
    "outbox_events",
    "processed_events",
    "notifications",
    "document_stars",
    "recent_documents",
]


def upgrade() -> None:
    # --- audit_events: append-only -------------------------------------------------
    op.execute(
        """
        CREATE FUNCTION dms.forbid_modification() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION '% on %.% is not permitted (append-only)', TG_OP, TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = 'integrity_constraint_violation';
        END $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_append_only
          BEFORE UPDATE OR DELETE ON dms.audit_events
          FOR EACH ROW EXECUTE FUNCTION dms.forbid_modification();
        """
    )
    op.execute(
        """
        CREATE TRIGGER audit_events_no_truncate
          BEFORE TRUNCATE ON dms.audit_events
          FOR EACH STATEMENT EXECUTE FUNCTION dms.forbid_modification();
        """
    )

    # --- document_versions: content columns are immutable --------------------------
    op.execute(
        """
        CREATE FUNCTION dms.protect_document_version() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
          IF NEW.id IS DISTINCT FROM OLD.id
             OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
             OR NEW.document_id IS DISTINCT FROM OLD.document_id
             OR NEW.version_number IS DISTINCT FROM OLD.version_number
             OR NEW.storage_location_id IS DISTINCT FROM OLD.storage_location_id
             OR NEW.object_key IS DISTINCT FROM OLD.object_key
             OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
             OR NEW.sha256 IS DISTINCT FROM OLD.sha256
             OR NEW.content_type IS DISTINCT FROM OLD.content_type
             OR NEW.original_filename IS DISTINCT FROM OLD.original_filename
             OR NEW.created_by IS DISTINCT FROM OLD.created_by
             OR NEW.created_at IS DISTINCT FROM OLD.created_at
             OR NEW.restored_from_version_id IS DISTINCT FROM OLD.restored_from_version_id
          THEN
            RAISE EXCEPTION 'document version content is immutable'
              USING ERRCODE = 'integrity_constraint_violation';
          END IF;
          RETURN NEW;
        END $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER document_versions_immutable
          BEFORE UPDATE ON dms.document_versions
          FOR EACH ROW EXECUTE FUNCTION dms.protect_document_version();
        """
    )

    # --- RLS: deny-all for API roles; the backend connects as the table owner ------
    for table in TABLES:
        op.execute(f"ALTER TABLE dms.{table} ENABLE ROW LEVEL SECURITY")

    # Supabase exposes `anon` / `authenticated` through PostgREST. DMS data must only be
    # reachable through the backend, so those roles get no privileges at all.
    op.execute(
        """
        DO $$
        DECLARE r text;
        BEGIN
          FOREACH r IN ARRAY ARRAY['anon', 'authenticated'] LOOP
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
              EXECUTE format('REVOKE ALL ON SCHEMA dms FROM %I', r);
              EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA dms FROM %I', r);
              EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA dms FROM %I', r);
              EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA dms FROM %I', r);
              EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA dms REVOKE ALL ON TABLES FROM %I', r);
            END IF;
          END LOOP;
        END $$;
        """
    )


def downgrade() -> None:
    # Forward-fix is preferred; downgrade only removes hardening objects (no data loss).
    for table in TABLES:
        op.execute(f"ALTER TABLE dms.{table} DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TRIGGER IF EXISTS document_versions_immutable ON dms.document_versions")
    op.execute("DROP FUNCTION IF EXISTS dms.protect_document_version()")
    op.execute("DROP TRIGGER IF EXISTS audit_events_no_truncate ON dms.audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON dms.audit_events")
    op.execute("DROP FUNCTION IF EXISTS dms.forbid_modification()")
