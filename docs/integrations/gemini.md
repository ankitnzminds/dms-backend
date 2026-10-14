# Google Gemini (LLM + document transcription) integration

* Chat / tool calling: Gemini's OpenAI-compatible endpoint,
  `POST {GEMINI_BASE_URL}/chat/completions` (default
  `https://generativelanguage.googleapis.com/v1beta/openai`), bearer `GEMINI_API_KEY`
  (backend only, `SecretStr`). Model: `GEMINI_MODEL`, default `gemini-3.8-flash`.
  `adapters/llm/gemini.py` reuses the Groq request/response code (`adapters/llm/groq.py`) and
  only changes the token budget (2.5 models think before answering; thinking tokens count against
  `max_tokens`, so 2048 tokens of headroom are added and `reasoning_effort=low` is sent).
* Provider selection (`AI_PROVIDER`): `auto` picks `gemini` when `GEMINI_API_KEY` is set, else
  `groq` when `GROQ_API_KEY` is set, else `none`. Set `gemini` or `groq` to force one.
* Scanned documents (`AI_OCR=true`, default): when local extraction finds no usable text layer in
  a PDF or image (status `ocr_unavailable`/`empty`, or a PDF averaging fewer than 80 characters per
  page, which is what a watermark/header-only text layer looks like), the processing worker sends
  the file to the native `models/{model}:generateContent` API with the bytes inline
  (`x-goog-api-key` header) and stores the transcription as the version's text with engine
  `gemini-ocr`. That text then feeds full-text search, the assistant's `read_document` /
  `retrieve_passages` tools and the per-document AI summary/Q&A.
  * `GEMINI_OCR_MODEL` selects the transcription model (default: `GEMINI_MODEL`); a `*-flash-lite`
    model is much faster and has a larger free-tier quota. PDFs go one page at a time (2 pages in
    parallel); a page the recitation filter blocks is retried with a paraphrasing prompt and,
    failing that, recorded as not transcribed rather than dropped.
  * Supported: PDF, PNG, JPEG, WebP, HEIC/HEIF, up to `AI_OCR_MAX_BYTES` (default 20 MB, Gemini's
    inline limit; `AI_OCR_TIMEOUT_SECONDS`, default 300). Thinking is disabled for transcription (`thinkingBudget: 0`), temperature 0.
  * Isolation: the call is made by the worker parent *after* the sandboxed child extractor
    returns; the child still opens no sockets. Deployments that block all egress from processing
    workers must allow `generativelanguage.googleapis.com` or set `AI_OCR=false`.
  * Privacy: documents whose classification is in the organization's
    `share_blocked_classifications` DLP list are never sent. A provider failure keeps the local
    result (and its honest `ocr_unavailable` status) and logs `ai_ocr_failed` without content.
* Replacing the provider: implement `LlmClient` (`complete`, `chat`, optionally `transcribe`) and
  register it in `adapters/llm/factory.py`.
