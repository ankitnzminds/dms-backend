# Runbook: migrations (including Supabase)

Chain (head `d0e1f2a3b4c5`): `03af22e4d963` initial → `a1b2c3d4e5f6` hardening → `b2c3d4e5f6a7`
governance → `c3d4e5f6a7b8` processing/metadata → `d4e5f6a7b8c9` workflows → `e5f6a7b8c9d0`
e-signature → `f6a7b8c9d0e1` directory → `a7b8c9d0e1f2` notification prefs → `b8c9d0e1f2a3`
signing URL → `c9d0e1f2a3b4` file-manager support → `d0e1f2a3b4c5` agentic chat + access requests.

## Authoring

1. Change models, then autogenerate against a throwaway database at the current head.
2. **Review by hand**: add `ENABLE ROW LEVEL SECURITY` for every new table, triggers/indexes
   Alembic cannot see, and keep downgrades non-destructive (forward-fix policy).
3. Test: the pytest session migrates a fresh database from base to head, so every revision is
   exercised.

## Applying to Supabase (requires explicit approval; nothing has been applied yet)

1. Take a backup/PITR point. Confirm `DATABASE_URL` points at the intended project (direct or
   session-mode connection; not transaction pooler for DDL).
2. `uv run alembic upgrade head` from a trusted machine or CI job, never from the API container
   at startup.
3. Verify: `select * from dms.alembic_version` (the version table lives in schema `dms`); RLS on (`select relname from pg_class c join
   pg_namespace n on n.oid=c.relnamespace where n.nspname='dms' and relkind='r' and not
   relrowsecurity` must return no rows); run the Supabase security advisor.
4. Do **not** expose the `dms` schema in Supabase's API settings.

Rollback: restore from the backup point or write a forward migration; destructive downgrades are
intentionally unsupported on data-bearing environments.
