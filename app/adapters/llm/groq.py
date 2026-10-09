"""Groq (OpenAI-compatible chat completions) client."""

from __future__ import annotations

import time
from typing import Any

import httpx

from app.adapters.llm.base import ChatTurn, LlmError, ToolCall

MAX_429_RETRIES = 2
MAX_WAIT_SECONDS = 20.0


def _retry_after(resp: httpx.Response) -> float:
    try:
        return min(max(float(resp.headers.get("retry-after", "")), 1.0), MAX_WAIT_SECONDS)
    except ValueError:
        return 8.0


class GroqClient:
    def __init__(self, api_key: str, model: str, base_url: str, timeout_seconds: int) -> None:
        self._api_key = api_key
        self.model = model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._timeout = timeout_seconds

    def _body(self, messages: list[dict[str, Any]], max_tokens: int) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
            # reasoning models spend completion tokens on thinking; leave headroom
            "max_completion_tokens": max_tokens + (1024 if "gpt-oss" in self.model else 0),
        }
        if "gpt-oss" in self.model:
            body["reasoning_effort"] = "low"
        return body

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(MAX_429_RETRIES + 1):
            try:
                resp = httpx.post(
                    self._url,
                    json=body,
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    timeout=self._timeout,
                )
            except httpx.HTTPError as exc:
                raise LlmError(f"Groq request failed: {type(exc).__name__}") from exc
            if resp.status_code == 429 and attempt < MAX_429_RETRIES:
                time.sleep(_retry_after(resp))  # rate limited: wait as told (bounded), then retry
                continue
            break
        if resp.status_code != 200:
            detail = ""
            try:  # the provider's error text describes the request shape, never our secrets
                detail = str(resp.json().get("error", {}).get("message", ""))[:200]
            except (ValueError, AttributeError):
                pass
            raise LlmError(f"Groq returned HTTP {resp.status_code}: {detail}".rstrip(": "))
        try:
            data = resp.json()
            assert isinstance(data["choices"][0]["message"], dict)
        except (ValueError, KeyError, IndexError, TypeError, AssertionError) as exc:
            raise LlmError("Groq returned an unexpected response shape") from exc
        return data

    def complete(
        self, system: str, user: str, *, json_mode: bool = False, max_tokens: int = 1024
    ) -> str:
        body = self._body(
            [{"role": "system", "content": system}, {"role": "user", "content": user}], max_tokens
        )
        if json_mode:
            body["response_format"] = {"type": "json_object"}
        content = self._post(body)["choices"][0]["message"].get("content")
        if not isinstance(content, str) or not content.strip():
            raise LlmError("Groq returned an empty completion")
        return content.strip()

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        max_tokens: int = 1024,
    ) -> ChatTurn:
        body = self._body(messages, max_tokens)
        if tools:
            body["tools"] = tools
            body["tool_choice"] = "auto"
        message = self._post(body)["choices"][0]["message"]
        calls: list[ToolCall] = []
        for raw in message.get("tool_calls") or []:
            try:
                fn = raw["function"]
                calls.append(
                    ToolCall(
                        id=str(raw["id"]), name=str(fn["name"]), arguments=fn["arguments"] or "{}"
                    )
                )
            except (KeyError, TypeError) as exc:
                raise LlmError("Groq returned a malformed tool call") from exc
        content = message.get("content")
        if not calls and not (isinstance(content, str) and content.strip()):
            raise LlmError("Groq returned an empty completion")
        return ChatTurn(
            content=content.strip() if isinstance(content, str) else None, tool_calls=calls
        )
