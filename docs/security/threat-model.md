# Threat model (summary)

| Threat | Mitigation | Evidence |
|---|---|---|
| Cross-tenant access / IDOR | org-scoped queries, composite FKs, 404 for foreign IDs | `test_tenant_isolation`, per-feature cross-tenant tests |
| Privilege escalation via grants | grantor can only grant held actions; `administer` not grantable | authorization tests, `test_approver_cannot_grant_what_they_do_not_hold` |
| Existence oracle | uniform 404 for undiscoverable resources and foreign tenants | authorization matrix |
| Malicious upload (type spoofing, executables, malware) | blocked extensions, magic-byte/content sniffing, scanner gate before a version becomes current, inline-HTML not previewable | upload tests |
| Zip/PDF/image bombs in extraction | isolated subprocess, byte/char/page/time limits | processing tests |
| Download link leakage | short-lived signed tickets, re-authorized on redemption, streamed via API, no storage URLs | download tests |
| XSS via snippets/filenames | snippets are plain text with `[[ ]]` markers; frontend escapes; names validated | search tests |
| Replay / double submit | upload idempotency keys, outbox idempotent handlers, single-use chat confirmations | upload, outbox, chat tests |
| Deadlocks / lost updates | documented lock orders, `populate_existing`, row versions, regression tests | concurrency tests |
| Audit tampering | append-only triggers | governance/audit tests |
| Secret exposure | `SecretStr` config, `.env` ignored, no secrets in logs or responses, signing link not logged | config tests, signature tests |
| Prompt injection / data exfiltration through the assistant | permission-first retrieval, typed tools, propose-confirm writes, DLP exclusion, history re-filtering | `docs/security/chatbot-security.md` |
| Third-party data egress (Groq, Documenso) | DLP classification excluded from AI; provider choice is configuration; **no per-org AI opt-out yet** | documented limit |
| Brute force / abuse | per-user rate limits (default/sensitive buckets), bulk limits | ratelimit tests |
| Supply chain | `pip-audit` in dev dependencies; lockfile (`uv.lock`) | run `uv run pip-audit` in CI |

Out of scope / not verified: network-level controls, WAF, TLS termination, Supabase project
hardening, clamd deployment, penetration testing.
