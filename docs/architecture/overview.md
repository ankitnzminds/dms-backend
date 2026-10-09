# Architecture overview

## Shape

A modular monolith: one FastAPI process (`app.main`) plus one worker process (`app.workers`) sharing
one PostgreSQL schema (`dms`). Modules under `app/modules/*` own business rules; routers under
`app/api/v1/*` only validate input, resolve the caller and delegate. Adapters under `app/adapters/*`
isolate everything external (storage, identity, malware scanner, e-signature provider, LLM, e-mail,
directory sources) behind small interfaces with a real and a fake/dev implementation.

```mermaid
flowchart LR
  FE[Next.js frontend\n(separate repo)] -->|HTTPS + Supabase JWT| API[FastAPI API]
  API --> PG[(PostgreSQL schema dms)]
  API --> ST[(Private storage\nSupabase / local dev)]
  API -->|enqueue| OB[(outbox table)]
  W[Worker] -->|SKIP LOCKED + lease| OB
  W --> ST
  W --> SC[Malware scanner clamd]
  W --> EX[Extraction subprocess\ntext / PDF / DOCX / image]
  API --> SIG[Documenso]
  API --> LLM[Groq gpt-oss-20b]
```

## Request path

1. `get_verified_identity` verifies the JWT (Supabase JWKS/HS256 in production, local HS256 in
   dev/test only). Identity is **authentication only**.
2. `resolve_principal` loads the user and **server-side memberships**; `X-Organization-Id` is only a
   selector among organizations the user is already an active member of. The result is a `Principal`
   (user, organization, role, group ids). Nothing tenant-related comes from the client.
3. `AuthorizationService` computes effective actions per resource (see
   `docs/security/authorization-model.md`). Services call `require_document/require_folder(action)`;
   hidden resources yield 404, missing rights 403.
4. The service performs the change in one transaction, writes an append-only audit event and, where
   work must happen later, an outbox event in the same transaction.

## Data model highlights

* Every tenant table carries `organization_id`; composite foreign keys (`(id, organization_id)`)
  make cross-tenant references impossible at the database level.
* Documents are logical items; **versions are immutable** (DB trigger). `current_version_id` only
  moves forward after the malware scan is clean.
* Quota is an idempotent ledger plus a locked counter on the organization row (`FOR NO KEY UPDATE`).
* Audit table is append-only (trigger). Approval actions are append-only.
* Full table list: `docs/database/data-dictionary.md` (generated), relationships in `docs/database/erd.md`.

## Uploads and downloads

Three steps: *initiate* (quota reserved, session recorded) → *PUT raw bytes* through the API (size,
SHA-256, magic-byte and content-type sniffing, blocked extensions) → *finalize* (version row,
outbox events). A folder upload is a sequence of `POST /folders/{id}/ensure-path` (idempotent
find-or-create) and per-file uploads. Downloads are streamed by the backend after re-authorization;
tickets are short-lived signed JWTs, never storage URLs.

## Workers (outbox)

The outbox claims rows with `FOR UPDATE SKIP LOCKED` and a lease, retries with backoff, dead-letters
after `OUTBOX_MAX_ATTEMPTS`, and every handler is idempotent. Handlers: malware scan → promote
version, text extraction + thumbnail (isolated subprocess with limits), notifications, trash expiry /
retention, purge + object deletion, signature reconciliation, directory sync.

## Agentic chat

See `docs/security/chatbot-security.md` and `docs/adr/0006-agent-propose-confirm.md`. Summary: the
model only has typed tools; every tool calls the same services a user would; reads are filtered by
permission *before* text reaches the model; writes are proposals that the user confirms by hash;
confirmation re-authorizes by executing through the normal services.

## Modules

| Module | Responsibility |
|---|---|
| authorization | effective actions (roles, ownership, grants, shares, approver access), DLP rule, breadcrumb masking |
| folders / documents / uploads / items | tree, versions, upload sessions, file-manager operations (bulk move/copy/delete, favorites, locks, properties) |
| sharing / groups / users / organizations | shares with expiry, groups, memberships, org settings |
| governance | legal holds, retention, trash expiry, purge |
| processing / search / metadata | extraction, thumbnails, full-text search, typed metadata |
| workflows | versioned approval workflows, tasks, delegation, overdue handling |
| signatures | provider adapter, requests, webhook + reconciliation, signed artifact as new version |
| directory | static / Entra / LDAP provisioning with guards |
| access_requests | request → authorized decision → grant through the permission service |
| chat / ai | agent orchestrator, tools, retrieval, pending actions, single-document AI helpers |
| notifications / reports / audit | in-app notifications, compliance summaries and CSV export, append-only audit |
