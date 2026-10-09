# ADR 0006: Chatbot = bounded tool-using agent with propose-then-confirm writes

**Status:** accepted

**Context.** The guide requires an agent that searches, answers with citations, explains sharing,
files access requests, operates on files and drafts workflows without ever becoming an
authorization bypass.

**Decision.**
* Provider adapter (`adapters/llm`): Groq OpenAI-compatible API, model from `GROQ_MODEL`
  (`openai/gpt-oss-20b`), tool calling verified live. Swappable without touching services.
* Orchestrator (`modules/chat/orchestrator.py`): bounded steps/tools/runtime; identity rebuilt from
  the database per run; every tool runs through the normal services.
* Retrieval is permission-first (authorize, then load text) over PostgreSQL full-text + passage
  scoring; no vector store (not needed for the first release; avoids a second ACL copy that could
  go stale).
* Reads return data directly. Writes create a `pending_actions` row; the user confirms by the
  payload hash; execution re-authorizes through the same services. Access requests are records,
  never grants.
* Runs are asynchronous (thread pool in-process; `AGENT_RUN_MODE=inline` in tests), progress via
  polling `GET /chat/runs/{id}`.

**Consequences.** Safe by construction for writes, at the cost of a confirmation click. In-process
threads mean a crashed process leaves runs in `running`; `GET /chat/runs/{id}` fails stale runs
after `AGENT_MAX_RUNTIME_SECONDS + 60 s`. For horizontal scale the run should move to the outbox
worker (the run state machine already supports it).
