"""File-manager schemas: bulk operations, properties, preferences, locks."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ActionName, ApiModel, BreadcrumbSegmentOut, UserRef
from app.schemas.tree import LockOut

ConflictPolicy = Literal["fail", "rename", "skip"]
ColorName = Literal["red", "orange", "yellow", "green", "blue", "purple", "pink", "gray"]


class ColorTagIn(ApiModel):
    color: ColorName | None = Field(None, description="Null removes the tag.")


class ItemRef(ApiModel):
    kind: Literal["folder", "document"]
    id: uuid.UUID


class BulkMoveCopyIn(ApiModel):
    items: list[ItemRef] = Field(min_length=1, max_length=200)
    target_folder_id: uuid.UUID
    on_conflict: ConflictPolicy = Field(
        "fail",
        description="fail = report name conflicts; rename = add ' (2)'; skip = leave conflicting items alone.",
    )


class BulkDeleteIn(ApiModel):
    items: list[ItemRef] = Field(min_length=1, max_length=200)


class BulkItemResult(ApiModel):
    kind: Literal["folder", "document"]
    id: uuid.UUID
    status: Literal["ok", "error", "skipped"]
    code: str | None = Field(
        None, description="Machine-readable error code (e.g. name_conflict, legal_hold)."
    )
    message: str | None = None
    new_id: uuid.UUID | None = Field(None, description="Identity of the created copy (copy only).")
    new_name: str | None = None


class BulkResult(ApiModel):
    results: list[BulkItemResult]
    succeeded: int
    failed: int
    skipped: int


class FolderCopyIn(ApiModel):
    target_folder_id: uuid.UUID
    name: str | None = Field(None, min_length=1, max_length=255)


class FolderCopyOut(ApiModel):
    folder_id: uuid.UUID
    name: str
    folders_copied: int
    documents_copied: int
    skipped_not_permitted: int = Field(
        description="Items inside the folder that the caller may not copy (not visible, or not copy-able)."
    )
    skipped_not_available: int = Field(description="Documents still processing/quarantined.")


class ProtectionInfo(ApiModel):
    legal_hold: bool
    retention_until: datetime | None


class ItemProperties(ApiModel):
    kind: Literal["folder", "document"]
    id: uuid.UUID
    name: str
    type: str | None = Field(None, description="MIME type (documents) or null for folders.")
    size_bytes: int | None = None
    created_at: datetime
    created_by: UserRef | None = None
    updated_at: datetime
    updated_by: UserRef | None = None
    location: list[BreadcrumbSegmentOut]
    classification: str | None = None
    status: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    version_count: int | None = None
    current_version_number: int | None = None
    protection: ProtectionInfo
    lock: LockOut | None = None
    starred: bool = False
    your_permissions: list[ActionName]
    # Only for callers who may manage access (otherwise null - no leakage of who else has access)
    active_shares: int | None = None
    acl_entries: int | None = None
    # folders: counts over what the caller may see (never the true totals)
    visible_folders: int | None = None
    visible_documents: int | None = None
    visible_size_bytes: int | None = None
    truncated: bool = False


class LockIn(ApiModel):
    minutes: int | None = Field(None, ge=5, le=10080, description="Defaults to 8 hours.")


class PreferenceValue(ApiModel):
    value: dict[str, Any] = Field(default_factory=dict)
