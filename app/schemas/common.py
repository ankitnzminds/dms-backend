"""Shared API schemas."""

from __future__ import annotations

import uuid
from typing import Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")

ActionName = Literal[
    "discover",
    "view",
    "preview",
    "download",
    "upload_version",
    "create_child",
    "edit_metadata",
    "rename",
    "move",
    "copy",
    "share",
    "manage_access",
    "delete",
    "restore",
    "comment",
    "export",
    "sync",
    "administer",
    "create_folder",
    "upload",
    "create_file",
    "view_versions",
    "restore_version",
    "lock",
]
Classification = Literal["public", "internal", "confidential", "restricted"]
UploadStateName = Literal["initiated", "uploaded", "finalized", "failed", "cancelled", "expired"]


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class Page(ApiModel, Generic[T]):
    items: list[T]
    total: int = Field(description="Total items visible to the caller (after authorization).")
    limit: int
    offset: int


class BreadcrumbSegmentOut(ApiModel):
    folder_id: uuid.UUID | None = Field(
        None, description="Present only if the caller may open this folder. Names are context only."
    )
    name: str | None = Field(None, description="Null when masked by organization policy.")
    navigable: bool


class UserRef(ApiModel):
    id: uuid.UUID
    display_name: str | None = None
    email: str | None = None


class Message(ApiModel):
    message: str
