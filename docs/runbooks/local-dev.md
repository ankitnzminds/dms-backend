# Runbook: local development

```bash
uv sync
uv run python scripts/dev_stack.py        # embedded Postgres in .dev/, migrations, seed, API :8000 + worker
```

* Data lives in `.dev/pgdata` and `.local-storage`; delete `.dev/` for a clean slate (this is local
  data only). Use `DEV_STACK_DIR` / `DEV_STACK_PORT` to run a second isolated stack.
* The stack uses the local HS256 auth provider, local filesystem storage and the dev scanner. These
  are refused when `APP_ENV` is staging/production.
* AI: put `GROQ_API_KEY` in `.env`; `AI_PROVIDER=auto` then enables the assistant. Without a key,
  `/api/v1/chat/status` reports `enabled: false` and chat endpoints answer `ai_not_configured`.
* E-signature: `DOCUMENSO_URL` + `DOCUMENSO_API_KEY` in `.env` enable the deployed Documenso;
  otherwise e-signature is reported unavailable.
* Troubleshooting: port in use → another stack is running (check `netstat -ano | findstr :8000`);
  Windows Defender may delete files containing real EICAR strings, which is why the dev scanner uses
  the marker `DMS-TEST-INFECTED-FILE-SIGNATURE`.
* Tests: `uv run pytest` (self-contained, own embedded Postgres per session).
