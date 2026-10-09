"""Deterministic test double: records every payload it receives and returns scripted replies.
Dev/test only. ``seen`` lets tests assert exactly which text reached the model."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from app.adapters.llm.base import ChatTurn, LlmError, ToolCall


class FakeLlmClient:
    model = "fake-model"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []
        self.reply: Callable[[str, str, bool], str] | str | None = None
        self.fail = False
        # chat(): every message list sent to the model, and a script of turns to return
        self.seen: list[list[dict[str, Any]]] = []
        self.tool_names: list[list[str]] = []  # tools offered on each chat() call
        self.script: list[ChatTurn | Callable[[list[dict[str, Any]]], ChatTurn]] = []

    def reset(self) -> None:
        self.calls.clear()
        self.seen.clear()
        self.tool_names.clear()
        self.script.clear()
        self.reply = None
        self.fail = False

    def all_text_seen(self) -> str:
        """Everything that was ever sent to the model, as one string (for leak assertions)."""
        return json.dumps(self.seen, default=str) + json.dumps(self.calls, default=str)

    def complete(
        self, system: str, user: str, *, json_mode: bool = False, max_tokens: int = 1024
    ) -> str:
        self.calls.append((system, user, json_mode))
        if self.fail:
            raise LlmError("fake failure")
        if callable(self.reply):
            return self.reply(system, user, json_mode)
        if self.reply is not None:
            return self.reply
        return "{}" if json_mode else "fake completion"

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        max_tokens: int = 1024,
    ) -> ChatTurn:
        self.seen.append(json.loads(json.dumps(messages, default=str)))
        self.tool_names.append([t["function"]["name"] for t in tools or []])
        if self.fail:
            raise LlmError("fake failure")
        if not self.script:
            return ChatTurn(content="fake answer")
        step = self.script.pop(0)
        return step(messages) if callable(step) else step


def tool_turn(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> ChatTurn:
    return ChatTurn(content=None, tool_calls=[ToolCall(call_id, name, json.dumps(arguments))])
