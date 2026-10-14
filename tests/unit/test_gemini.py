"""Gemini provider: configuration selection, request shaping and the scanned-document fallback."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from pydantic import SecretStr

from app.adapters.llm.base import LlmError
from app.adapters.llm.gemini import GeminiClient
from app.core.config import Settings
from app.modules.processing.service import needs_ai_ocr

MINIMAL_PDF = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 100]/Contents 4 0 R"
    b"/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
    b"4 0 obj<</Length 52>>stream\nBT /F1 14 Tf 20 50 Td (Quarterly revenue forecast) Tj ET\n"
    b"endstream endobj\n"
    b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
    b"trailer<</Root 1 0 R/Size 6>>\nstartxref\n0\n%%EOF"
)
BASE = "https://generativelanguage.googleapis.com/v1beta/openai"
NATIVE = "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.8-flash:generateContent"


def make_settings(**kw):  # noqa: ANN003, ANN201
    base = dict(app_env="test", database_url="postgresql://u:p@localhost/x", ai_provider="auto")
    base.update(kw)
    return Settings(_env_file=None, **base)  # type: ignore[call-arg]


def candidate(text: str | None, reason: str = "STOP") -> dict:
    content = {"parts": [{"text": text}]} if text is not None else {}
    return {"candidates": [{"content": content, "finishReason": reason}]}


class FakeResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return self._payload


class TestProviderSelection:
    def test_auto_prefers_gemini_then_groq_then_none(self):
        assert make_settings().effective_ai_provider == "none"
        assert make_settings(groq_api_key=SecretStr("g")).effective_ai_provider == "groq"
        both = make_settings(groq_api_key=SecretStr("g"), gemini_api_key=SecretStr("k"))
        assert both.effective_ai_provider == "gemini"
        assert make_settings(gemini_api_key=SecretStr("k")).gemini_model == "gemini-3.8-flash"

    def test_explicit_provider_wins(self):
        s = make_settings(
            ai_provider="groq", groq_api_key=SecretStr("g"), gemini_api_key=SecretStr("k")
        )
        assert s.effective_ai_provider == "groq"

    def test_factory_builds_gemini_client(self, monkeypatch):  # noqa: ANN001
        from app.adapters.llm import factory

        s = make_settings(gemini_api_key=SecretStr("k"))
        monkeypatch.setattr(factory, "get_settings", lambda: s)
        factory.reset_llm()
        try:
            llm = factory.get_llm()
            assert isinstance(llm, GeminiClient) and llm.model == "gemini-3.8-flash"
        finally:
            factory.reset_llm()


class TestChat:
    def test_chat_uses_openai_endpoint_with_thinking_headroom(self, monkeypatch):  # noqa: ANN001
        seen: dict = {}

        def fake_post(url, json, headers, timeout):  # noqa: ANN001, ANN202, A002
            seen.update(url=url, body=json, headers=headers)
            return FakeResponse(
                200, {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}
            )

        monkeypatch.setattr(httpx, "post", fake_post)
        c = GeminiClient("secret", "gemini-3.8-flash", BASE, 30)
        turn = c.chat([{"role": "user", "content": "x"}], max_tokens=900)
        assert turn.content == "hi" and not turn.tool_calls
        assert seen["url"] == BASE + "/chat/completions"
        assert seen["headers"]["Authorization"] == "Bearer secret"
        assert seen["body"]["model"] == "gemini-3.8-flash"
        assert seen["body"]["max_tokens"] == 900 + 2048
        assert seen["body"]["reasoning_effort"] == "low"
        assert "max_completion_tokens" not in seen["body"]


class TestTranscription:
    def test_each_pdf_page_is_sent_inline_to_the_native_api(self, monkeypatch):  # noqa: ANN001
        calls: list[dict] = []

        def fake_post(url, json, headers, timeout):  # noqa: ANN001, ANN202, A002
            calls.append(dict(url=url, body=json, headers=headers))
            return FakeResponse(200, candidate("Form GST DRC-01"))

        monkeypatch.setattr(httpx, "post", fake_post)
        c = GeminiClient("secret", "gemini-3.8-flash", BASE, 30)
        text = c.transcribe(MINIMAL_PDF, "application/pdf", max_chars=100_000)
        assert text == "Page 1\nForm GST DRC-01"
        assert len(calls) == 1
        assert calls[0]["url"] == NATIVE
        assert calls[0]["headers"] == {"x-goog-api-key": "secret"}
        parts = calls[0]["body"]["contents"][0]["parts"]
        assert parts[0]["inline_data"]["mime_type"] == "application/pdf"
        assert base64.b64decode(parts[0]["inline_data"]["data"]).startswith(b"%PDF")
        assert "page 1 of" in parts[1]["text"]
        assert calls[0]["body"]["generationConfig"]["thinkingConfig"] == {"thinkingBudget": 0}
        assert "secret" not in json.dumps(calls[0]["body"])

    def test_images_are_sent_whole(self, monkeypatch):  # noqa: ANN001
        seen: dict = {}

        def fake_post(url, json, headers, timeout):  # noqa: ANN001, ANN202, A002
            seen.update(body=json)
            return FakeResponse(200, candidate("Invoice 4711"))

        monkeypatch.setattr(httpx, "post", fake_post)
        c = GeminiClient("secret", "gemini-3.8-flash", BASE, 30)
        assert c.transcribe(b"PNG-bytes", "image/png", max_chars=100) == "Page 1\nInvoice 4711"
        part = seen["body"]["contents"][0]["parts"][0]["inline_data"]
        assert base64.b64decode(part["data"]) == b"PNG-bytes"

    def test_recitation_blocked_page_is_retried_with_paraphrase_prompt(self, monkeypatch):  # noqa: ANN001
        prompts: list[str] = []

        def fake_post(url, json, headers, timeout):  # noqa: ANN001, ANN202, A002
            prompts.append(json["contents"][0]["parts"][1]["text"])
            if len(prompts) == 1:
                return FakeResponse(200, candidate(None, "RECITATION"))
            return FakeResponse(200, candidate("Section 16 says..."))

        monkeypatch.setattr(httpx, "post", fake_post)
        c = GeminiClient("secret", "gemini-3.8-flash", BASE, 30)
        text = c.transcribe(MINIMAL_PDF, "application/pdf", max_chars=100_000)
        assert text == "Page 1\nSection 16 says..."
        assert "exactly as written" in prompts[0] and "in your own words" in prompts[1]

    def test_page_that_stays_blocked_is_marked_not_dropped(self, monkeypatch):  # noqa: ANN001
        monkeypatch.setattr(
            httpx, "post", lambda *a, **k: FakeResponse(200, candidate(None, "RECITATION"))
        )
        c = GeminiClient("secret", "gemini-3.8-flash", BASE, 30)
        text = c.transcribe(MINIMAL_PDF, "application/pdf", max_chars=100_000)
        assert text == "Page 1: (could not be transcribed: RECITATION)"

    def test_rejects_unsupported_and_oversized_inputs(self):
        c = GeminiClient("secret", "gemini-3.8-flash", BASE, 30)
        with pytest.raises(LlmError):
            c.transcribe(b"x", "application/zip", max_chars=100)
        with pytest.raises(LlmError):
            c.transcribe(b"x" * (20 * 1024 * 1024 + 1), "image/png", max_chars=100)
        with pytest.raises(LlmError, match="split"):
            c.transcribe(b"not a pdf", "application/pdf", max_chars=100)

    def test_provider_errors_surface_without_crashing(self, monkeypatch):  # noqa: ANN001
        monkeypatch.setattr(
            httpx,
            "post",
            lambda *a, **k: FakeResponse(400, {"error": {"message": "bad request"}}),
        )
        c = GeminiClient("secret", "gemini-3.8-flash", BASE, 30)
        with pytest.raises(LlmError, match="HTTP 400: bad request"):
            c.transcribe(b"x", "image/png", max_chars=100)
        monkeypatch.setattr(httpx, "post", lambda *a, **k: FakeResponse(200, {"candidates": []}))
        with pytest.raises(LlmError, match="unexpected response shape"):
            c.transcribe(b"x", "image/png", max_chars=100)


class TestScannedDocumentDetection:
    def test_pdf_without_text_layer_needs_ocr(self):
        assert needs_ai_ocr("ocr_unavailable", "application/pdf", 0, 6)
        assert needs_ai_ocr("empty", "application/pdf", 0, 3)

    def test_pdf_with_only_a_watermark_per_page_is_treated_as_scanned(self):
        # six pages of "Xavier - 10/14/2026, 6:28:07 AM" = 197 characters in total
        assert needs_ai_ocr("extracted", "application/pdf", 197, 6)

    def test_real_text_pdf_keeps_local_extraction(self):
        assert not needs_ai_ocr("extracted", "application/pdf", 12_000, 6)
        assert not needs_ai_ocr("extracted", "application/pdf", 500, None)

    def test_images_and_other_types(self):
        assert needs_ai_ocr("ocr_unavailable", "image/png", 0, None)
        assert needs_ai_ocr("empty", "image/jpeg", 0, None)
        assert not needs_ai_ocr("extracted", "text/plain", 3, None)
        assert not needs_ai_ocr("failed", "application/pdf", 0, 0)
        assert not needs_ai_ocr("unsupported", "application/zip", 0, None)


class TestThoughtSignatures:
    def test_tool_call_extra_content_is_kept_for_replay(self, monkeypatch):  # noqa: ANN001
        sig = {"google": {"thought_signature": "abc"}}
        monkeypatch.setattr(
            httpx,
            "post",
            lambda *a, **k: FakeResponse(
                200,
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "tool_calls": [
                                    {
                                        "id": "c1",
                                        "type": "function",
                                        "extra_content": sig,
                                        "function": {"name": "read_document", "arguments": "{}"},
                                    }
                                ],
                            }
                        }
                    ]
                },
            ),
        )
        c = GeminiClient("secret", "gemini-3.1-flash-lite", BASE, 30)
        turn = c.chat([{"role": "user", "content": "x"}])
        assert turn.tool_calls[0].extra == sig


class TestOverloadRetries:
    def test_chat_retries_a_transient_503_then_succeeds(self, monkeypatch):  # noqa: ANN001
        import app.adapters.llm.groq as groq_mod

        monkeypatch.setattr(groq_mod.time, "sleep", lambda s: None)
        calls = {"n": 0}

        def fake_post(url, json, headers, timeout):  # noqa: ANN001, ANN202, A002
            calls["n"] += 1
            if calls["n"] < 3:
                return FakeResponse(503, {"error": {"message": "high demand"}})
            return FakeResponse(
                200, {"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
            )

        monkeypatch.setattr(httpx, "post", fake_post)
        c = GeminiClient("secret", "gemini-3.1-flash-lite", BASE, 30)
        assert c.chat([{"role": "user", "content": "x"}]).content == "ok"
        assert calls["n"] == 3

    def test_persistent_503_still_fails_cleanly(self, monkeypatch):  # noqa: ANN001
        import app.adapters.llm.groq as groq_mod

        monkeypatch.setattr(groq_mod.time, "sleep", lambda s: None)
        monkeypatch.setattr(
            httpx, "post", lambda *a, **k: FakeResponse(503, {"error": {"message": "busy"}})
        )
        c = GeminiClient("secret", "gemini-3.1-flash-lite", BASE, 30)
        with pytest.raises(LlmError, match="HTTP 503"):
            c.chat([{"role": "user", "content": "x"}])
