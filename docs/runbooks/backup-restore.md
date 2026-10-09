# Runbook: backup and restore

`scripts/backup_restore_drill.py` proves the procedure end to end on a throwaway embedded database:
create data → `pg_dump` → restore into a second database → compare per-table row counts and
migration head. It passed on the development machine.

Production notes (infrastructure decisions, not configured by this repository):

* Database: use Supabase backups/PITR; take a manual backup before every migration.
* Objects: the private bucket must be backed up consistently with the database. A restored
  database whose versions reference missing objects is detected by the processing/download paths
  (404/`object_missing`), but there is no automatic reconciliation job yet.
* After a restore: run `alembic current`, then the RLS query in `docs/runbooks/migrations.md`, then
  let the worker drain the outbox. Signature requests are re-synchronised by reconciliation.
