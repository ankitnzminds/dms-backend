# Groq (LLM) integration

* Endpoint: OpenAI-compatible `POST {GROQ_BASE_URL}/chat/completions`, bearer `GROQ_API_KEY`
  (backend only, `SecretStr`). Model: `GROQ_MODEL`, default `openai/gpt-oss-20b`.
* Verified live (2026-10-09): plain completions, JSON mode (`response_format=json_object`), and
  function/tool calling with the full tool catalogue; end-to-end agent run (grounded answer with a
  verified citation, proposed write, confirmed execution) via `test_chat_live.py`.
* gpt-oss specifics handled in `adapters/llm/groq.py`: `reasoning_effort="low"`, extra completion
  token headroom for reasoning tokens, tool-call parsing, citation bracket normalisation
  (`[S1]`, `【S1】`, `(S1)` → `[S1]`, then verified against sources of the same run).
* Rate limits: the free/on-demand tier observed at 8,000 tokens/minute; each agent call carries
  ~2–3k tokens of tool schemas. The client retries HTTP 429 up to twice, waiting for `Retry-After`
  (≤ 20 s). Use a higher tier for real use.
* Privacy: prompts contain authorized document passages. Documents in DLP-blocked classifications
  are never sent. Nothing is logged except provider error text.
* Gemini: see `gemini.md` (same request shape; also transcribes scanned PDFs/images).
* Replacing the provider: implement `LlmClient` (`complete`, `chat`) and register it in
  `adapters/llm/factory.py`; no service, schema or API change is required.
