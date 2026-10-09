"""Schemas for version comparison."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from app.schemas.common import ApiModel


class VersionRef(ApiModel):
    version_number: int
    size_bytes: int
    sha256: str
    content_type: str
    created_by: uuid.UUID | None
    created_at: datetime
    is_current: bool


class DiffSectionOut(ApiModel):
    title: str
    status: Literal["unchanged", "changed", "added", "removed"]
    note: str | None = None
    changes: list[dict[str, Any]]


class DiffSummary(ApiModel):
    added: int
    removed: int
    changed: int
    unchanged: int


class DiffOut(ApiModel):
    document_id: uuid.UUID
    from_version: VersionRef
    to_version: VersionRef
    status: Literal["ready", "unsupported", "too_large", "failed"]
    kind: Literal["text", "csv", "json", "docx", "xlsx", "pptx", "pdf", "image", "binary"]
    identical: bool = False
    summary: DiffSummary | None = None
    sections: list[DiffSectionOut] = []
    notes: list[str] = []
    truncated: bool = False
    parser_version: str
    cached: bool = False
    message: str | None = None
