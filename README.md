# enterprise-dms-backend

FastAPI + SQLAlchemy 2 + Alembic backend for the Enterprise DMS. The frontend lives in a **separate
repository** (`enterprise-dms-frontend`); the OpenAPI contract in `docs/api/openapi.json` is the
only coupling.

* Modular monolith, one PostgreSQL schema (`dms`), RLS enabled and deny-all on every table; the API
  connects as the owner and enforces authorization itself (see `docs/security/tenant-isolation.md`).
* Supabase Postgres + private Supabase Storage in production; a local filesystem provider and an
  embedded PostgreSQL for development and tests (dev-only, refused in staging/production).
* Background work (malware scan, text extraction, thumbnails, notifications, retention, signature
  reconciliation, directory sync) runs in a worker fed by a transactional outbox.

**Status and honesty:** see [`docs/requirements/implementation-status.md`](docs/requirements/implementation-status.md)
for what is built, what is verified and how, and what is *not* verified (Supabase live paths,
Docker image, Documenso webhooks, Entra/LDAP against real servers).

## Quick start (no Docker, no external services)

```bash
uv sync                                  # Python 3.12+
uv run python scripts/dev_stack.py       # embedded Postgres, migrations, seed, API :8000 + worker
```

Seeded dev users (local HS256 auth, `POST /api/v1/dev/token {"email": ...}`): `alice@acme.test`
(owner), `bob@acme.test`, `carol@acme.test` (members), `dave@acme.test` (auditor). Interactive docs:
<http://localhost:8000/docs>.

Copy `.env.example` to `.env` for anything beyond defaults. `.env` is git-ignored; never commit it.

## Checks

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy app
uv run pytest --cov=app                  # real embedded PostgreSQL, ~5 minutes
```

Opt-in live tests (call real external services; skipped by default):

```bash
RUN_LIVE_DOCUMENSO=1 uv run pytest tests/integration/test_documenso_live.py
RUN_LIVE_GROQ=1      uv run pytest tests/integration/test_chat_live.py -s
```

Scripts: `scripts/dev_stack.py`, `load_test.py`, `backup_restore_drill.py`, `documenso_smoke.py`,
`groq_smoke.py`, `gen_data_dictionary.py`.

## Layout

```
app/
  api/v1/          routers (thin: validation, dependency injection)
  modules/         business logic per domain (authorization, folders, documents, uploads, sharing,
                   governance, processing, search, metadata, workflows, signatures, directory,
                   items (file manager), access_requests, chat (agent), ai, notifications, reports)
  adapters/        storage, identity, malware, signatures (Documenso/fake), llm (Gemini/Groq/fake), email, directory
  db/models/       SQLAlchemy models   migrations/  Alembic (hand-reviewed, RLS appended)
  workers/         outbox worker and handlers
docs/              architecture, ADRs, requirements matrix, security, runbooks, operations
tests/             unit / integration / security (pytest on embedded PostgreSQL)
```

## Documentation index

| Topic | Where |
|---|---|
| Architecture overview | `docs/architecture/overview.md` |
| Decisions | `docs/adr/` |
| Requirements traceability + status | `docs/requirements/` |
| Tenant isolation, authorization model, threat model, chatbot security | `docs/security/` |
| Configuration reference | `docs/operations/configuration.md` |
| Performance | `docs/operations/performance.md` |
| Runbooks (local dev, migrations, backup/restore, workers, Documenso, chatbot) | `docs/runbooks/` |
| Documenso / Gemini / Groq integrations | `docs/integrations/` |
| Data dictionary (generated), ERD | `docs/database/` |
| API contract | `docs/api/openapi.json` (regenerate after changing endpoints) |

## Safety rules for this repo

Never push, deploy, run destructive production migrations or commit secrets without explicit
approval. Applying migrations to a Supabase project is a deliberate, reviewed step (see the
migrations runbook).
