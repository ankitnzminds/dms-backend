"""Groq (OpenAI-compatible chat completions) client."""

from __future__ import annotations

from typing import Any

import httpx

from app.adapters.llm.base import LlmError


class GroqClient:
    def __init__(self, api_key: str, model: str, base_url: str, timeout_seconds: int) -> None:
        self._api_key = api_key
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._timeout = timeout_seconds

    def complete(
        self, system: str, user: str, *, json_mode: bool = False, max_tokens: int = 1024
    ) -> str:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0.2,
            # reasoning models spend completion tokens on thinking; leave headroom
            "max_completion_tokens": max_tokens + (1024 if "gpt-oss" in self.model else 0),
        }
        if "gpt-oss" in self.model:
            body["reasoning_effort"] = "low"
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        try:
            resp = httpx.post(
                self._url,
                json=body,
                headers={"Authorization": f"Bearer {self._api_key}"},
                timeout=self._timeout,
            )
        except httpx.HTTPError as exc:
            raise LlmError(f"Groq request failed: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise LlmError(f"Groq returned HTTP {resp.status_code}")
        try:
            content = resp.json()["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LlmError("Groq returned an unexpected response shape") from exc
        if not isinstance(content, str) or not content.strip():
            raise LlmError("Groq returned an empty completion")
        return content.strip()
