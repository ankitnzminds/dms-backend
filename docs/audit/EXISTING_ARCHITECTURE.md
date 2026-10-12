# Existing architecture (as found in code)

**Stack.** Backend: Python 3.12, FastAPI, SQLAlchemy 2, Alembic (24 revisions), PostgreSQL (embedded pgserver
for dev/tests; Supabase in the target), outbox worker (`workers/`). Frontend: Next.js 16, React 19, TypeScript,
Tailwind v4, TanStack Query; API types generated from `docs/api/openapi.json`. Repos are separate.

**Identity.** `adapters/identity`: `SupabaseJwtProvider` (JWKS/aud/iss/exp/iat) or `LocalJwtProvider`
(dev only; refused in production-like config, router not mounted outside development/test). `resolve_principal`
rebuilds the caller on every request from DB state: active user, active membership/org (not locked/expired),
`X-Organization-Id` only as a selector among the user's own memberships, group ids, role. Sessions are
stateless; `sessions_valid_after` (1 s resolution) revokes all tokens of a user.

**Authorization.** One `AuthorizationService` (`modules/authorization/service.py`). `_effective_acl`: admin =
all actions; else ownership (own space only), permission grants (user/group/org, inheritance via recursive
CTE, `inherit_acl` cut), share grants (+ per-recipient override), workflow assignees, DLP classification block,
non-AVAILABLE documents owner-only. `_effective` then applies the **policy layer** (`modules/policy_engine`),
which can only remove actions. `require_*` give 404 for undiscoverable, 403 for missing action; denials are
audited (`authz.denied`). No cache: everything is recomputed per request, so revocation is immediate.

**Data model highlights.** organizations (settings JSONB), users, memberships (role, access_level),
groups/group_memberships (flat), folders/documents/document_versions (immutable content trigger),
permission_grants, share_grants/share_recipients, access_requests, workflow_* (versioned definitions, runs,
tasks, append-only approval_actions), retention_policies/legal_holds, policies (settings), policy_rules /
policy_revisions (rules; published revisions immutable), audit_events (append-only triggers), outbox.
RLS is enabled but deny-all and the API connects as table owner, so isolation is application-level.

**Document lifecycle.** initiate (size/policy/quota/extension blocklist) → store (size + SHA-256) → finalize
→ outbox `document_version.uploaded` → malware scan (clamd INSTREAM; unconfigured = stays pending, never
"clean") → extract/OCR in an isolated child process → servable only when `scan_status=CLEAN`. Download = signed
60 s ticket after authz, re-authorized at redemption, streamed by the API (no direct storage URL). Delete =
soft delete (batch id); admin Recycle Bin restores/purges; purge re-checks DELETE, legal hold and retention,
then enqueues `storage.delete_objects` (idempotent, backoff, dead-letter).

**Search / AI.** Postgres FTS + chunk scoring (no vector store). Search filters by `organization_id` then runs
`document_actions`; content hits need PREVIEW. Chat retrieval only loads text of documents the caller can
DISCOVER+PREVIEW and that are not DLP-blocked; write tools create hash-bound, single-use `PendingAction`s that
re-authorize at execution. No cache in search/chat.

**Ops.** Prometheus-style metrics + `/health/{live,ready}`, structured JSON logs, CI (ruff, mypy, OpenAPI
diff, tests with 80% coverage floor, migration check, pip-audit, gitleaks), Dockerfile (non-root).
Runbooks: backup-restore, migrations, workers, local dev.
