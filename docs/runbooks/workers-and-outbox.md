# Runbook: workers and the outbox

* Run exactly the same image as the API with the worker entrypoint (`python -m app.cli worker`); scale
  horizontally (claims use `SKIP LOCKED`).
* Health: `outbox_events` rows with `status='pending'` and an old `created_at` mean the worker is
  down or slow; rows with `status='dead'` exhausted `OUTBOX_MAX_ATTEMPTS` and need a human.
* Inspect: `select event_type, status, attempts, last_error from dms.outbox_events order by
  created_at desc limit 50;` (last_error never contains document text or secrets).
* Retry a dead event after fixing the cause: set `status='pending', attempts=0,
  next_attempt_at=now()` for that row (handlers are idempotent).
* Stuck leases expire after `OUTBOX_LOCK_SECONDS`; no manual unlock is normally needed.
* Typical causes: scanner unreachable (clamd), storage errors, extraction limits (document is
  marked `unsupported`/`failed`, not retried forever), Documenso unreachable (reconciliation
  retries on the next cycle).
* Chat runs are **not** on the outbox: they run in API threads. A run left `running` after a
  crash is failed automatically by `GET /chat/runs/{id}` after `AGENT_MAX_RUNTIME_SECONDS + 60`.
