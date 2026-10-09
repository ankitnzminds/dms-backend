"""LLM provider port. Implementations must never log prompts, completions or credentials."""

from __future__ import annotations

from typing import Protocol


class LlmError(Exception):
    """The provider failed or returned something unusable (message is safe to log)."""


class LlmClient(Protocol):
    model: str

    def complete(
        self, system: str, user: str, *, json_mode: bool = False, max_tokens: int = 1024
    ) -> str: ...
