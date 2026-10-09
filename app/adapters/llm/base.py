"""LLM provider port. Implementations must never log prompts, completions or credentials."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class LlmError(Exception):
    """The provider failed or returned something unusable (message is safe to log)."""


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: str  # raw JSON text from the model - untrusted until validated


@dataclass(frozen=True)
class ChatTurn:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)


class LlmClient(Protocol):
    model: str

    def complete(
        self, system: str, user: str, *, json_mode: bool = False, max_tokens: int = 1024
    ) -> str: ...

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        *,
        max_tokens: int = 1024,
    ) -> ChatTurn:
        """One model turn over OpenAI-style messages and function-tool schemas."""
        ...
