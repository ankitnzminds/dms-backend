# Implementation status and traceability

Status vocabulary: **Verified** = automated tests pass against a real PostgreSQL (and, where noted,
a real external service); **Built, not verified live** = implemented and unit/integration-tested
against fakes only; **Not built** = absent. Test counts are from the last full run (367 passed,
2 opt-in live tests skipped, 90 % line coverage).

## Capabilities

| Area | Status | Evidence (code → tests) | Gaps / notes |
|---|---|---|---|
| Auth, principal, tenant resolution | Verified (local HS256) | `modules/identity` → `test_tenant_isolation`, `tests/security/*` | **Supabase JWT/JWKS path is built but unverified against a live project**; no project has the schema applied yet |
| Authorization (union model, DLP, non-disclosure) | Verified | `modules/authorization` → `test_authorization_matrix`, mutation checks | see `docs/security/authorization-model.md` |
| Folders, documents, versions, trash/restore | Verified | `modules/folders`, `documents` → `test_folders_*`, `test_uploads_versions` | |
| Uploads (single, folder tree via ensure-path), quota ledger, scan | Verified (EICAR-style dev scanner) | `modules/uploads`, `quota` → `test_uploads_versions` (incl. concurrency/deadlock regressions), `test_file_manager::TestEnsurePath` | **clamd (production scanner) not exercised**; infected-marker test uses the dev scanner |
| Downloads/preview (tickets, streaming, thumbnails) | Verified | `documents/downloads.py` → download tests | |
| Sharing (users/groups, expiry, revoke), Shared with/by me | Verified | `modules/sharing` → `test_sharing_acceptance` (mandatory acceptance test) | external/link sharing **not built** |
| File-manager operations (bulk move/copy/delete, folder copy, favorites, properties, locks, preferences, sorting) | Verified | `modules/items`, `documents/locks.py` → `test_file_manager` (19 tests) | no "replace on conflict"; copy of folders is bounded by limits |
| Governance (legal holds, retention, trash expiry, purge) | Verified | `modules/governance` → `test_governance` | |
| Search + extraction (text/PDF/DOCX/image), OCR hook, metadata | Verified | `modules/processing`, `search`, `metadata` → `test_search_processing_metadata` | OCR needs a configured `OCR_COMMAND` (not installed here); semantic search **not built** |
| Approval workflows | Verified | `modules/workflows` → `test_workflows` (concurrency, delegation, overdue) | |
| E-signature (Documenso) | Verified live for create → sign → complete → download; fake provider for tests | `adapters/signatures`, `modules/signatures` → `test_signatures`, `test_documenso_live` (opt-in) | **webhook delivery from Documenso not verified** (no public URL); reconciliation covers it |
| Directory provisioning | Static verified; Entra/LDAP **mock-only** | `modules/directory` → `test_directory` | never connected to real Entra/LDAP |
| Notifications (in-app, prefs, e-mail via outbox) | Verified; SMTP path not exercised against a real server | `modules/notifications` | |
| Reports/audit export | Verified | `modules/reports`, `audit` | |
| Access requests | Verified | `modules/access_requests` → `test_chat::*access*` | |
| Agentic chatbot (tools, retrieval, pending actions, history re-filtering) | Verified with a recording fake model; **smoke-verified with the real Groq model** (`test_chat_live`) | `modules/chat` → `test_chat` (28 tests) | no systematic model-quality eval; no vector search; polling instead of token streaming; see `docs/security/chatbot-security.md` |
| Single-document AI helpers (summary, Q&A, metadata suggestions) | Verified with fake; Groq smoke verified | `modules/ai` → `test_ai` | |
| Observability (structured logs, request IDs, Prometheus) | Built | `core/logging`, `metrics` | dashboards/alerts not provided |
| Backup/restore | Drill script passes locally | `scripts/backup_restore_drill.py` | Supabase PITR/backup policy is an infra decision, not configured here |
| Docker image / compose | **Not built or run** (no Docker daemon in the dev environment) | `Dockerfile`, `docker-compose.yml` exist, untested | |
| Native desktop sync / Windows shell integration | **Not built** (out of scope per spec) | | |

## Requirements traceability (source documents → implementation)

| Source requirement | Where |
|---|---|
| Two independent repos, versioned REST, OpenAPI contract | repo split; `docs/api/openapi.json` (119 paths) |
| Multi-tenant isolation, composite FKs, RLS deny-all | `docs/security/tenant-isolation.md`; migrations |
| Mandatory sharing acceptance test | `tests/security/test_sharing_acceptance.py` |
| Windows Explorer experience (backend support) | `modules/items`, `GET /folders/{id}/children` sorts, `/items/bulk/*`, `/favorites`, `/…/properties`, `/…/lock`, `/me/preferences/*` |
| Folder upload / drag and drop (backend support) | `POST /folders/{id}/ensure-path` + upload flow; UI in the frontend repo |
| Advanced chatbot guide §5–§16 | `modules/chat`, `modules/access_requests`, `/api/v1/chat/*`, `/api/v1/access-requests`; §8 semantic search and §10 visual workflow preview data: workflow draft = pending action preview (`create_workflow`), no separate draft entity |
| E-signature guide | `docs/integrations/documenso.md` |

## Known issues / follow-ups

* Apply migrations to the Supabase project only after review (`docs/runbooks/migrations.md`).
* One flaky concurrency test was root-caused (ADR 0007) and fixed; if a similar intermittent
  failure reappears, capture the `upload_storage_failed` log line first.
* Groq free-tier rate limits slow multi-step agent runs.
