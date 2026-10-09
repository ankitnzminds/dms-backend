"""Schemas for folders, documents, versions and listings."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ActionName, ApiModel, BreadcrumbSegmentOut, Classification


class VersionOut(ApiModel):
    id: uuid.UUID
    version_number: int
    size_bytes: int
    sha256: str
    content_type: str
    original_filename: str
    created_by: uuid.UUID | None
    created_at: datetime
    scan_status: Literal["pending", "clean", "infected", "error"]
    is_current: bool
    restored_from_version_number: int | None = None


class FolderOut(ApiModel):
    id: uuid.UUID
    name: str
    parent_folder_id: uuid.UUID | None
    is_root: bool
    is_team_folder: bool
    created_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    row_version: int
    deleted_at: datetime | None = None
    permissions: list[ActionName]
    breadcrumb: list[BreadcrumbSegmentOut] = Field(
        description="Path of ancestors, root first (excludes the folder itself)."
    )


class DocumentOut(ApiModel):
    id: uuid.UUID
    name: str
    folder_id: uuid.UUID
    owner_id: uuid.UUID | None
    status: Literal["processing", "available", "quarantined", "failed"]
    classification: Classification
    metadata: dict[str, Any]
    latest_version_number: int
    current_version: VersionOut | None
    created_at: datetime
    updated_at: datetime
    row_version: int
    deleted_at: datetime | None = None
    starred: bool = False
    permissions: list[ActionName]
    breadcrumb: list[BreadcrumbSegmentOut]


class TreeItem(ApiModel):
    kind: Literal["folder", "document"]
    id: uuid.UUID
    name: str
    updated_at: datetime
    permissions: list[ActionName]
    # document-only
    size_bytes: int | None = None
    content_type: str | None = None
    status: str | None = None
    current_version_number: int | None = None
    owner_id: uuid.UUID | None = None
    starred: bool = False
    is_team_folder: bool = False


class FolderCreate(ApiModel):
    parent_folder_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)


class FolderUpdate(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    parent_folder_id: uuid.UUID | None = None
    expected_row_version: int | None = None


class DocumentUpdate(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    folder_id: uuid.UUID | None = Field(None, description="Move the document to this folder.")
    metadata: dict[str, Any] | None = None
    classification: Classification | None = None
    expected_row_version: int | None = None


class DocumentCopyRequest(ApiModel):
    target_folder_id: uuid.UUID
    name: str | None = Field(None, min_length=1, max_length=255)


class RestoreRequest(ApiModel):
    new_name: str | None = Field(None, min_length=1, max_length=255)


class TrashItem(ApiModel):
    kind: Literal["folder", "document"]
    id: uuid.UUID
    name: str
    deleted_at: datetime
    deleted_by: uuid.UUID | None
    original_breadcrumb: list[BreadcrumbSegmentOut]
    size_bytes: int | None = None
