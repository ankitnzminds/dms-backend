"""Sharing and ACL schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, model_validator

from app.schemas.common import ActionName, ApiModel, BreadcrumbSegmentOut, UserRef


class RecipientIn(ApiModel):
    type: Literal["user", "group"]
    id: uuid.UUID | None = None
    email: str | None = Field(
        None, max_length=320, description="Resolve an internal user by email."
    )

    @model_validator(mode="after")
    def _one_identifier(self) -> RecipientIn:
        if self.type == "group" and self.id is None:
            raise ValueError("group recipients require id")
        if self.type == "user" and (self.id is None) == (self.email is None):
            raise ValueError("user recipients require exactly one of id or email")
        return self


class ShareCreate(ApiModel):
    recipients: list[RecipientIn] = Field(min_length=1, max_length=50)
    actions: list[ActionName] = Field(min_length=1, max_length=20)
    expires_at: datetime | None = None
    message: str | None = Field(None, max_length=1000)


class RecipientOut(ApiModel):
    type: Literal["user", "group"]
    id: uuid.UUID
    name: str | None = None
    email: str | None = None


class ShareOut(ApiModel):
    id: uuid.UUID
    resource_type: Literal["folder", "document"]
    resource_id: uuid.UUID
    resource_name: str | None
    created_by: UserRef
    actions: list[ActionName]
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None
    status: Literal["active", "expired", "revoked"]
    message: str | None = None
    recipients: list[RecipientOut]


class ReceivedShare(ApiModel):
    """A row of *Shared with Me*: a view over a grant that points at the ORIGINAL resource."""

    share_id: uuid.UUID
    resource_type: Literal["folder", "document"]
    resource_id: uuid.UUID
    name: str
    status: Literal["active", "expired", "revoked"]
    shared_by: UserRef
    actions: list[ActionName]
    shared_at: datetime
    expires_at: datetime | None
    message: str | None = None
    # Canonical location. Context only: ``navigable`` is true solely where the recipient is
    # independently authorized; the share does NOT authorize browsing parents or siblings.
    breadcrumb: list[BreadcrumbSegmentOut]
    size_bytes: int | None = None
    content_type: str | None = None


class PermissionGrantIn(ApiModel):
    subject_type: Literal["user", "group", "organization"]
    subject_id: uuid.UUID | None = None
    actions: list[ActionName] = Field(min_length=1, max_length=20)
    inherit: bool = True
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def _subject(self) -> PermissionGrantIn:
        if (self.subject_type == "organization") != (self.subject_id is None):
            raise ValueError("subject_id is required unless subject_type is 'organization'")
        return self


class PermissionGrantOut(ApiModel):
    id: uuid.UUID
    resource_type: Literal["folder", "document"]
    resource_id: uuid.UUID
    subject_type: Literal["user", "group", "organization"]
    subject_id: uuid.UUID | None
    subject_name: str | None = None
    actions: list[ActionName]
    inherit: bool
    expires_at: datetime | None
    revoked_at: datetime | None
    created_by: uuid.UUID | None
    created_at: datetime


__all__ = [
    "PermissionGrantIn",
    "PermissionGrantOut",
    "ReceivedShare",
    "RecipientIn",
    "RecipientOut",
    "ShareCreate",
    "ShareOut",
]
