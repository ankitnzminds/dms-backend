"""Google Gemini client.

Chat/tool calling goes through Gemini's OpenAI-compatible endpoint (same request shape as Groq).
Document transcription (OCR of scanned PDFs and images) uses the native ``generateContent`` API,
which accepts the file bytes inline. PDFs are sent one page at a time: a page is a small request
(fast, retryable) and the provider's recitation filter, which silently drops a whole response
that reproduces published text (laws, standards), then only costs that page, which is retried
with a paraphrasing prompt. Never logs prompts, file content or the key.
"""

from __future__ import annotations

import base64
import io
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import httpx

from app.adapters.llm.base import LlmError
from app.adapters.llm.groq import MAX_429_RETRIES, GroqClient, _retry_after

PAGE_PROMPT = (
    "This is page {n} of a scanned document. Transcribe ALL the text on this page exactly as "
    "written, preserving the reading order, headings, numbers, dates, amounts and table rows "
    "(one table row per line, cells separated by ' | '). Output plain text only: no commentary, "
    "no markdown fences, no translation. If the page has no text, output exactly: (no text)"
)
PARAPHRASE_PROMPT = (
    "This is page {n} of a scanned document. Write a thorough plain-text account of everything "
    "on this page, in order: every heading, party name, address, identifier, date, amount, "
    "table row (one per line, cells separated by ' | ') and the substance of each paragraph. "
    "Where the page quotes published legal or standard text, state what it says in your own "
    "words instead of reproducing it. No commentary, no markdown."
)
# Gemini's inline-data limit for generateContent requests.
TRANSCRIBE_MAX_BYTES = 20 * 1024 * 1024
TRANSCRIBE_MIME_TYPES = frozenset(
    {"application/pdf", "image/png", "image/jpeg", "image/webp", "image/heic", "image/heif"}
)
PAGE_WORKERS = 2  # pages transcribed concurrently (bounded: free-tier per-minute limits)
PAGE_MAX_TOKENS = 8192


def _split_pdf(data: bytes, max_pages: int) -> list[bytes]:
    """One single-page PDF per page (bounded). Raises LlmError for unusable input."""
    from pypdf import PdfReader, PdfWriter

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise LlmError("encrypted PDF cannot be transcribed")
        pages: list[bytes] = []
        for index, page in enumerate(reader.pages):
            if index >= max_pages:
                break
            writer = PdfWriter()
            writer.add_page(page)
            buf = io.BytesIO()
            writer.write(buf)
            pages.append(buf.getvalue())
    except LlmError:
        raise
    except Exception as exc:  # malformed input: pypdf raises many types
        raise LlmError(f"PDF could not be split into pages: {type(exc).__name__}") from exc
    if not pages:
        raise LlmError("PDF has no pages")
    return pages


class GeminiClient(GroqClient):
    provider = "Gemini"

    def __init__(
        self,
        api_key: str,
        model: str,
        base_url: str,
        timeout_seconds: int,
        transcribe_timeout_seconds: int = 300,
        ocr_model: str = "",
    ) -> None:
        super().__init__(api_key, model, base_url, timeout_seconds)
        self._transcribe_timeout = transcribe_timeout_seconds
        self.ocr_model = ocr_model or model
        # base_url is ".../v1beta/openai"; the native API lives one level up
        root = base_url.rstrip("/")
        self._native_root = root[: -len("/openai")] if root.endswith("/openai") else root

    def _body(self, messages: list[dict[str, Any]], max_tokens: int) -> dict[str, Any]:
        body = super()._body(messages, max_tokens)
        # Gemini Flash models think before answering and the thinking tokens count against the
        # output budget; keep thinking short and leave headroom so answers are not cut off.
        body["max_tokens"] = max_tokens + 2048
        body["reasoning_effort"] = "low"
        return body

    # ------------------------------------------------------------------ transcription
    def _generate(self, data: bytes, mime_type: str, prompt: str) -> tuple[str, str]:
        """(text, finish_reason) for one inline file + prompt. Raises LlmError on failure."""
        url = f"{self._native_root}/models/{self.ocr_model}:generateContent"
        body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "inline_data": {
                                "mime_type": mime_type,
                                "data": base64.b64encode(data).decode("ascii"),
                            }
                        },
                        {"text": prompt},
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": PAGE_MAX_TOKENS,
                "thinkingConfig": {"thinkingBudget": 0},
            },
        }
        for attempt in range(MAX_429_RETRIES + 1):
            try:
                resp = httpx.post(
                    url,
                    json=body,
                    headers={"x-goog-api-key": self._api_key},
                    timeout=httpx.Timeout(self._transcribe_timeout, connect=30),
                )
            except httpx.HTTPError as exc:
                raise LlmError(f"Gemini request failed: {type(exc).__name__}") from exc
            if resp.status_code in (429, 503) and attempt < MAX_429_RETRIES:
                time.sleep(_retry_after(resp))  # rate limited / overloaded: bounded wait, retry
                continue
            break
        if resp.status_code != 200:
            detail = ""
            try:
                detail = str(resp.json().get("error", {}).get("message", ""))[:200]
            except (ValueError, AttributeError):
                pass
            raise LlmError(f"Gemini returned HTTP {resp.status_code}: {detail}".rstrip(": "))
        try:
            candidate = resp.json()["candidates"][0]
            parts = candidate.get("content", {}).get("parts") or []
            text = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
            reason = str(candidate.get("finishReason", ""))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LlmError("Gemini returned an unexpected response shape") from exc
        return text.strip(), reason

    def _transcribe_page(self, data: bytes, mime_type: str, n: int) -> str:
        text, reason = self._generate(data, mime_type, PAGE_PROMPT.format(n=n))
        if not text:
            # Blocked (typically RECITATION on quoted public text) or empty: ask for an account
            # of the page in the model's own words instead of a verbatim copy.
            text, reason = self._generate(data, mime_type, PARAPHRASE_PROMPT.format(n=n))
        if not text:
            return f"Page {n}: (could not be transcribed: {reason or 'empty'})"
        if text == "(no text)":
            return f"Page {n}: (no text)"
        return f"Page {n}\n{text}"

    def transcribe(
        self, data: bytes, mime_type: str, *, max_chars: int, max_pages: int = 300
    ) -> str:
        """Plain-text transcription of a PDF or image (OCR). Raises LlmError when unusable."""
        if mime_type not in TRANSCRIBE_MIME_TYPES:
            raise LlmError("Gemini transcription does not support this file type")
        if len(data) > TRANSCRIBE_MAX_BYTES:
            raise LlmError("file too large for Gemini transcription")
        if mime_type != "application/pdf":
            return self._transcribe_page(data, mime_type, 1)[:max_chars]
        pages = _split_pdf(data, max_pages)
        with ThreadPoolExecutor(max_workers=PAGE_WORKERS) as pool:
            texts = list(
                pool.map(
                    lambda item: self._transcribe_page(item[1], mime_type, item[0] + 1),
                    enumerate(pages),
                )
            )
        return "\n\n".join(texts)[:max_chars]
