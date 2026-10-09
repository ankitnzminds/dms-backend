# ADR 0004: Transactional outbox and a polling worker

**Status:** accepted

**Decision.** Side effects that must not run inline (scan, extraction, notifications, purge,
reconciliation) are written to an outbox table in the same transaction as the business change. A
worker claims rows with `FOR UPDATE SKIP LOCKED` plus a lease, retries with backoff, and
dead-letters after `OUTBOX_MAX_ATTEMPTS`. Handlers are idempotent.

**Consequences.** No broker to operate; at-least-once delivery, so handlers tolerate duplicates.
Latency is bounded by `WORKER_POLL_INTERVAL_SECONDS`. Lock order rule for workflows: run → task
(documented deadlock regression). Organization counter rows use `FOR NO KEY UPDATE` (documented
deadlock regression found by `scripts/load_test.py`).
