# Configuration reference

All settings are environment variables (case-insensitive), loaded by `app/core/config.py` (and an
optional `.env`). Secrets use `SecretStr` and are never logged. **Staging/production validation**
(startup fails if violated): `AUTH_PROVIDER` and `STORAGE_PROVIDER` must not be `local`,
`MALWARE_SCANNER` must be a real scanner (`clamd`), `SIGNATURE_PROVIDER`/`AI_PROVIDER` must not be
`fake`, `CORS_ALLOWED_ORIGINS` must not contain `*`, Documenso requires `DOCUMENSO_WEBHOOK_SECRET`.

| Group | Variables |
|---|---|
| App | `APP_ENV` (development/test/staging/production), `PUBLIC_API_BASE_URL`, `CORS_ALLOWED_ORIGINS`, `LOG_LEVEL`, `FRAME_ANCESTORS`, `METRICS_TOKEN` (metrics disabled when unset), `WEB_BASE_URL` |
| Database | `DATABASE_URL`, `DB_POOL_SIZE`, `DB_MAX_OVERFLOW` |
| Auth | `AUTH_PROVIDER` (supabase/local), `SUPABASE_URL`, `SUPABASE_JWT_AUDIENCE`, `SUPABASE_JWT_SECRET` (legacy), `LOCAL_JWT_SECRET` (dev/test), `AUTH_CLOCK_SKEW_SECONDS` |
| Storage | `STORAGE_PROVIDER`, `SUPABASE_SERVICE_ROLE_KEY` (**server only**), `SUPABASE_STORAGE_BUCKET`, `LOCAL_STORAGE_PATH`, `MAX_UPLOAD_BYTES`, `UPLOAD_SESSION_TTL_SECONDS`, `BLOCKED_EXTENSIONS`, `DOWNLOAD_SIGNING_SECRET`, `DOWNLOAD_URL_TTL_SECONDS` |
| Malware | `MALWARE_SCANNER` (clamd/eicar/none), `CLAMD_HOST`, `CLAMD_PORT`, `CLAMD_TIMEOUT_SECONDS` |
| Extraction | `EXTRACT_MAX_BYTES`, `EXTRACT_MAX_CHARS`, `EXTRACT_MAX_PAGES`, `EXTRACT_TIMEOUT_SECONDS`, `OCR_COMMAND` |
| E-signature | `SIGNATURE_PROVIDER` (auto/none/fake/documenso), `DOCUMENSO_URL`, `DOCUMENSO_API_KEY`, `DOCUMENSO_WEBHOOK_SECRET`, `SIGNATURE_RECONCILE_MINUTES` |
| AI / agent | `AI_PROVIDER` (auto/none/fake/groq), `GROQ_API_KEY`, `GROQ_MODEL` (default `openai/gpt-oss-20b`), `GROQ_BASE_URL`, `AI_MAX_INPUT_CHARS`, `AI_TIMEOUT_SECONDS`, `AGENT_MAX_STEPS`, `AGENT_MAX_TOOL_CALLS`, `AGENT_MAX_RUNTIME_SECONDS`, `AGENT_MAX_BULK_ITEMS`, `AGENT_ACTION_TTL_MINUTES`, `AGENT_HISTORY_MESSAGES`, `AGENT_RUN_MODE` (thread/inline) |
| Rate limits | `RATE_LIMIT_ENABLED`, `RATE_LIMIT_DEFAULT_PER_MINUTE`, `RATE_LIMIT_SENSITIVE_PER_MINUTE` |
| Worker | `WORKER_POLL_INTERVAL_SECONDS`, `WORKER_BATCH_SIZE`, `OUTBOX_MAX_ATTEMPTS`, `OUTBOX_LOCK_SECONDS` |
| E-mail | `EMAIL_PROVIDER` (none/log/smtp), `SMTP_HOST/PORT/USERNAME/PASSWORD/FROM`, `SMTP_STARTTLS`, `SMTP_IMPLICIT_TLS` |
| Directory | secrets are referenced as `env:DMS_DIR_<NAME>`; the value lives only in the process environment |

Model/provider notes: the model identifier is configuration only; verify the provider's
tool-calling support, context limit and data-handling terms before changing it
(`docs/integrations/groq.md`).
