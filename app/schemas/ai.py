"""AI assistance schemas."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from app.schemas.common import ApiModel, Classification


class AiStatus(ApiModel):
    enabled: bool
    model: str | None = None


class AiSource(ApiModel):
    version_number: int
    chars_used: int
    truncated: bool = Field(
        description="The text was longer than the model input limit; only the beginning was used."
    )


class AiSummaryOut(ApiModel):
    summary: str
    model: str
    source: AiSource


class AiQuestionIn(ApiModel):
    question: str = Field(min_length=3, max_length=1000)


class AiAnswerOut(ApiModel):
    answer: str
    model: str
    source: AiSource


class AiMetadataSuggestion(ApiModel):
    classification: Classification | None = None
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Only valid values for active metadata definitions."
    )
    keywords: list[str] = Field(default_factory=list, max_length=10)
    model: str
    source: AiSource
    applied: bool = Field(False, description="Always false: suggestions are never applied.")
