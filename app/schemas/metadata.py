"""Metadata definition schemas."""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import Field

from app.schemas.common import ApiModel

FieldType = Literal["text", "number", "date", "boolean", "select"]


class MetadataDefinitionIn(ApiModel):
    key: str = Field(min_length=1, max_length=64, description="lowercase_snake_case identifier")
    label: str = Field(min_length=1, max_length=200)
    field_type: FieldType
    required: bool = False
    options: list[str] | None = Field(None, description="Allowed values for select fields.")


class MetadataDefinitionUpdate(ApiModel):
    label: str | None = Field(None, min_length=1, max_length=200)
    required: bool | None = None
    options: list[str] | None = None
    archived: bool | None = None


class MetadataDefinitionOut(ApiModel):
    id: uuid.UUID
    key: str
    label: str
    field_type: FieldType
    required: bool
    options: list[str] | None
    schema_version: int
    archived: bool


class ProcessingStatusOut(ApiModel):
    version_number: int | None
    text_status: str | None = Field(
        None,
        description="extracted | empty | unsupported | failed | ocr_unavailable | null (pending)",
    )
    text_characters: int = 0
    text_truncated: bool = False
    has_thumbnail: bool = False
