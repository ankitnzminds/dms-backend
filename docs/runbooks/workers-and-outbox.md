# Runbook: workers and the outbox

* Run exactly the same image as the API with the worker entrypoint (`python -m app.cli worker`); scale
  horizontally (claims use `SKIP LOCKED`).
* Health: `outbox_events` rows with `status='pending'` and an old `created_at` mean the worker is
  down or slow; rows with `status='dead'` exhausted `OUTBOX_MAX_ATTEMPTS` and need a human.
* Inspect: `select event_type, status, attempts, last_error from dms.outbox_events order by
  created_at desc limit 50;` (last_error never contains document text or secrets).
* Dead events are now **audited** (`outbox.event_dead`, tenant-visible in the Audit log) and counted by the
  `dms_outbox_dead` gauge: alert when it is > 0 for more than a few minutes.
* Retry a dead event after fixing the cause: an administrator calls `GET /api/v1/admin/ops/dead-events`
  then `POST /api/v1/admin/ops/dead-events/{id}/replay` (audited as `outbox.event_replayed`; handlers are
  idempotent). Manual SQL (`status='pending', attempts=0, next_attempt_at=now()`) still works.
* Storage consistency: `GET /api/v1/admin/ops/storage-check?limit=200&offset=0` lists versions whose object
  is missing (read-only, bounded, tenant scoped). It cannot find *orphan* objects: the storage adapter has
  no listing operation.
* Rejected credentials: `auth.token_rejected` events (NULL organization, one per client+reason per minute)
  are for platform operators; query `dms.audit_events where action='auth.token_rejected'`.
* Stuck leases expire after `OUTBOX_LOCK_SECONDS`; no manual unlock is normally needed.
* Typical causes: scanner unreachable (clamd), storage errors, extraction limits (document is
  marked `unsupported`/`failed`, not retried forever), Documenso unreachable (reconciliation
  retries on the next cycle).
* Chat runs are **not** on the outbox: they run in API threads. A run left `running` after a
  crash is failed automatically by `GET /chat/runs/{id}` after `AGENT_MAX_RUNTIME_SECONDS + 60`.
