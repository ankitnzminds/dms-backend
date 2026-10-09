"""Deterministic test double: records calls, returns scripted replies. Dev/test only."""

from __future__ import annotations

from collections.abc import Callable

from app.adapters.llm.base import LlmError


class FakeLlmClient:
    model = "fake-model"

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, bool]] = []
        self.reply: Callable[[str, str, bool], str] | str | None = None
        self.fail = False

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
