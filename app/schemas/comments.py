"""Comment schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.common import ApiModel, UserRef


class CommentCreate(ApiModel):
    body: str = Field(min_length=1, max_length=4000, description="Plain text.")
    parent_id: uuid.UUID | None = Field(None, description="Reply to this top-level comment.")


class CommentEdit(ApiModel):
    body: str = Field(min_length=1, max_length=4000)


class CommentOut(ApiModel):
    id: uuid.UUID
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    parent_id: uuid.UUID | None
    author: UserRef | None
    body: str
    created_at: datetime
    edited_at: datetime | None
    deleted: bool
    can_edit: bool
    can_delete: bool


class CommentList(ApiModel):
    items: list[CommentOut]
    total: int
    limit: int
    offset: int
    can_comment: bool = Field(description="The caller may add comments here.")
