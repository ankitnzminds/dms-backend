# Security gap analysis

Evidence level: **R** = read in source during this audit, **T** = reproduced by an executed test,
**N** = not verified. Priorities: P0 critical security/data-integrity, P1 essential for production,
P2 advanced enterprise, P3 optional. Nothing here is a claim that a test passes unless marked **T**.

## Confirmed gaps

| # | Pri | Gap | Evidence |
|---|---|---|---|
| G1 | P1 | **Legal hold / retention is enforced only on delete and purge.** Rename, move (out of a held folder) and `restore_version` do not call `assert_deletable`/`find_protections`, so a hold can be sidestepped by moving content. Soft-delete checks holds only; retention is checked at purge. | R documents/service.py `update_document`, `restore_version`; governance/service.py |
| G2 | P1 | **No storage reconciliation.** No object-vs-DB sweep; dead-lettered outbox events are only logged, so a dead scan event leaves a version `pending` forever and a dead `storage.delete_objects` leaks objects. | R docs/runbooks/backup-restore.md ("no automatic reconciliation job yet"), workers/runner.py |
| G3 | P1 | **Rate limiting is per process, in memory, and keyed by user** (requires a resolved principal); failed-token requests are not limited; replicas multiply limits. Credential brute force depends entirely on Supabase. | R core/ratelimit.py, api/deps.py `limited()` |
| G4 | P1 | **Failed logins and token-verification failures are not audited** (only a Prometheus counter). No `auth.login` event. No alert rules in repo. | R grep of audit actions; core/metrics.py |
| G5 | P1 | **`app_env` defaults to `development`**, so a deploy that forgets `APP_ENV` skips every production check and exposes `/docs`. No check of DATABASE_URL, SUPABASE_URL, METRICS_TOKEN or default `local_dev_password`. | R core/config.py `_validate_environment` |
| G6 | P2 | Upload validation is an extension **blocklist** + executable magic bytes only; no allowlist, no per-type size limit; safety rests on ClamAV (never run live in tests). | R uploads/service.py, adapters/malware |
| G7 | P2 | Supabase storage adapter only tested against a mocked transport; restore drill only on local storage; no bucket-backup procedure consistent with the DB. | R adapters/storage, scripts/backup_restore_drill.py, runbook |
| G8 | P2 | RLS is enabled but deny-all; API is table owner, so it is **not** defence in depth. | R docs/security/tenant-isolation.md |
| G9 | P2 | No MFA/step-up for admin actions; tokens are not checked for `amr`/`aal`. Policy effect REQUIRE_STEP_UP is deliberately unsupported. | R identity/principal.py |
| G10 | P2 | No audit retention/archival, no SIEM export beyond CSV; append-only trigger also blocks TRUNCATE. | R maintenance.py, db_hardening migration |
| G11 | P2 | `REQUIRE_APPROVAL` policy effect cannot be enforced (no mechanism to hold an operation). Sharing approval flag `require_share_approval` is stored, not enforced. | R policy_engine/service.py, policies/schema.py |
| G12 | P2 | Single global stateless session model: no single-token revocation; 1 s granularity. | R identity/service.py |
| G13 | P3 | Download tickets are replayable for 60 s (jti not stored). | R documents/downloads.py |
| G14 | P3 | Any admin can add anyone to any group (no rank check); admin is already fully trusted. | R groups/service.py |
| G15 | P3 | `document_versions` has no DELETE-block trigger; `purge_expired_trash` has no per-org error isolation. | R |
| G16 | P3 | No deploy manifest, alerting rules or incident runbook; migrations runbook head is stale. | R docs/runbooks |
| G17 | P3 | Plain `/search` snippets are not masked for DLP-classified documents (only chat withholds them). | N |
| G18 | P3 | Test coverage thin for notifications, quota/storage admin, reports, quarantine, favorites, org management. | R test names |

## Fixed during this work (executed tests)

| Item | Fix | Evidence |
|---|---|---|
| G1 hold/retention bypass via move/rename/version-restore | `governance.assert_not_held` / `assert_movable` called from `update_document`, `update_folder` (so bulk move too) and `restore_version`. Hold blocks all three; a folder-scoped retention policy blocks leaving its scope while the period runs (org-wide retention follows the item). Denials write `governance.blocked` with the operation and reason | **T** tests/integration/test_governance_move_rename.py (5) |
| G5 production config guard | Production-like env now also requires DATABASE_URL and (for Supabase auth) SUPABASE_URL; an unset `APP_ENV` with a **remote** DATABASE_URL refuses to start (local/unix-socket DBs and tests unaffected) | **T** tests/unit/test_core.py |
| G4 token failures not audited | `auth.token_rejected` (NULL org, reason + route, never the token), one per client+reason per 60 s, plus structured log. Visible to platform operators/SIEM, **not** in tenant admins' audit UI (a rejected token has no trustworthy tenant). Failed *password* logins happen at Supabase and are not visible to this backend | **T** tests/integration/test_auth_audit.py (3) |
| G2 dead events / missing objects | `outbox.event_dead` audit (tenant-visible) + `dms_outbox_dead` gauge; admin `GET /admin/ops/dead-events`, `POST .../{id}/replay`; read-only `GET /admin/ops/storage-check` (versions whose object is missing). Orphan objects still cannot be detected (adapter has no listing) | **T** tests/integration/test_ops_reconcile.py (3) |

| Item | Fix | Evidence |
|---|---|---|
| Public (anonymous) folder link served files classified `restricted` that named recipients cannot get, and ignored policies | `sharing/public.py` now applies `share_blocked_classifications` and enforcing policies (evaluated as an external visitor) | **T** tests/integration/test_policy_enforcement.py `test_public_link_*` |
| Admin permission dashboard returned 200 (empty) for a foreign-tenant resource | 404 before authorization | **T** test_permission_dashboards.py `test_cross_tenant_*` |

## Verified controls (R, with sampled T)

Dev login impossible in production (3 layers) · JWT verification (aud/iss/exp/iat) · session revocation ·
suspended/locked/expired account rejection · no-escalation on grants and shares · role-change rules and
last-owner protection · audit append-only + document-version content immutability triggers · private
streamed storage (no direct URLs) · download re-authorization at redemption · scan gate ("clean" only after a
scan) · search and AI retrieval filtered by authorization before content is read · write-tool confirmation
gate · security headers/CSP/CORS · request-size limits · tenant isolation tests (security/test_tenant_isolation.py).

## Not verified

Per-query org scoping across every module (sampled only) · 500-error leakage · log redaction · signature
webhook auth · WOPI token scoping · thumbnail authorization · clamd/Supabase live behaviour · whether
every write path in policy enforcement is covered beyond the choke point · live Supabase MFA/lockout settings.
