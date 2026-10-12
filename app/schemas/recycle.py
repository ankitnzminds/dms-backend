"""Administrators' Recycle Bin."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.common import ApiModel


class UserBrief(ApiModel):
    id: uuid.UUID
    email: str
    display_name: str | None = None


class RecycleItem(ApiModel):
    kind: Literal["document", "folder"]
    id: uuid.UUID
    name: str
    content_type: str | None = None
    original_path: str = Field(description="Where it lived (folder path, never a storage URL).")
    deleted_by: UserBrief | None = None
    owner: UserBrief | None = None
    deleted_at: datetime
    size_bytes: int | None = None
    item_count: int = Field(0, description="Documents inside (folders only).")
    deletion_source: Literal["trash", "user_permanent"] = Field(
        description="trash = moved to the trash; user_permanent = the user chose 'delete permanently'."
    )
    permanent_requested_at: datetime | None = None
    recovery_status: Literal["recoverable", "protected"] = Field(
        description="protected: a legal hold or retention rule currently blocks permanent deletion."
    )
    original_location_available: bool = Field(
        description="False when the original parent folder is gone or itself in the trash."
    )


class ProtectionBrief(ApiModel):
    kind: str
    id: uuid.UUID
    reason: str


class RecycleDetail(RecycleItem):
    documents: int
    folders: int
    versions: int
    protections: list[ProtectionBrief]
    permanent_requested_by: UserBrief | None = None


class RecycleRef(ApiModel):
    kind: Literal["document", "folder"]
    id: uuid.UUID


class RestoreItem(RecycleRef):
    new_name: str | None = Field(
        None, max_length=255, description="Rename on restore (name conflicts)."
    )
    target_folder_id: uuid.UUID | None = Field(
        None, description="Restore here instead of the original location."
    )


class RestoreIn(ApiModel):
    items: list[RestoreItem] = Field(min_length=1, max_length=100)


class PurgeIn(ApiModel):
    items: list[RecycleRef] = Field(min_length=1, max_length=100)


class RecycleBulkResult(ApiModel):
    kind: Literal["document", "folder"]
    id: uuid.UUID
    ok: bool
    code: str | None = None
    message: str | None = None


class RecycleBulkOut(ApiModel):
    results: list[RecycleBulkResult]
    succeeded: int
    failed: int
