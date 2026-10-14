from __future__ import annotations

from functools import lru_cache

from app.adapters.llm.base import LlmClient
from app.adapters.llm.fake import FakeLlmClient
from app.adapters.llm.gemini import GeminiClient
from app.adapters.llm.groq import GroqClient
from app.core.config import get_settings


@lru_cache
def _build(name: str, _settings_id: int) -> LlmClient | None:
    s = get_settings()
    if name == "fake":
        if s.is_production_like:
            raise RuntimeError("the fake AI provider is not allowed in staging/production")
        return FakeLlmClient()
    if name == "groq" and s.groq_api_key:
        return GroqClient(
            s.groq_api_key.get_secret_value(),
            s.groq_model,
            s.groq_base_url,
            s.ai_timeout_seconds,
        )
    if name == "gemini" and s.gemini_api_key:
        return GeminiClient(
            s.gemini_api_key.get_secret_value(),
            s.gemini_model,
            s.gemini_base_url,
            s.ai_timeout_seconds,
            s.ai_ocr_timeout_seconds,
            s.gemini_ocr_model,
        )
    return None


def get_llm() -> LlmClient | None:
    """The configured client, or None when AI assistance is not configured."""
    s = get_settings()
    return _build(s.effective_ai_provider, id(s))


def reset_llm() -> None:
    _build.cache_clear()
