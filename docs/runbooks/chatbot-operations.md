# Runbook: chatbot operations

**Disable the assistant immediately:** set `AI_PROVIDER=none` (or unset `GROQ_API_KEY`) and restart
the API. `/chat/status` returns `enabled:false`; existing conversations stay readable; pending
actions can still be cancelled but no new runs start.

**Symptom → check**

| Symptom | Look at |
|---|---|
| "The assistant is temporarily unavailable" | API log `agent_model_error` (provider HTTP status/message; 429 = rate limit, retry later or raise the Groq tier), `agent_runs.error_code` |
| Runs stay `running` | process crashed; `GET /chat/runs/{id}` fails them after the timeout; check API logs for `agent_run_crashed` |
| User says an action did not happen | `pending_actions.status`: `pending` (never confirmed), `expired`, `invalidated` (target changed), `failed` (authorization/conflict at execution; `error_code`) |
| Suspected misuse | `tool_executions` (tool, decision allow/deny/invalid, reason, argument hash) joined to `agent_runs`; audit events `chat.*` and `authz.denied` |
| Answer cites something the user cannot open | citation shows `accessible:false`; opening the route re-authorizes |

**Retention:** conversations/messages are kept until deleted by policy; there is no automatic purge
yet (follow-up). They contain model output derived from authorized documents, so treat them as
confidential and include them in backup and legal-hold decisions.

**Tuning:** `AGENT_MAX_STEPS`, `AGENT_MAX_TOOL_CALLS`, `AGENT_MAX_RUNTIME_SECONDS`,
`AGENT_MAX_BULK_ITEMS`, `AGENT_ACTION_TTL_MINUTES`, rate bucket `chat` (sensitive limit).
