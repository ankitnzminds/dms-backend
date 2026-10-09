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
    name: str | None = Field(None, min_length=1, max_length=200)
    expires_at: datetime | None = None
    message: str | None = Field(None, max_length=1000)


class RecipientOut(ApiModel):
    type: Literal["user", "group", "organization"]
    id: uuid.UUID
    name: str | None = None
    email: str | None = None
    # Friendly permissions of this principal (View, Download, Upload, Share, Sync, Delete, Manage).
    permissions: list[str] = []


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
    # ---- Share Link dialog (managers only; recipients see name/owner/status)
    name: str | None = None
    owner: UserRef | None = None
    restricted: bool = True
    notify_email: bool = True
    upload_quota_mb: int | None = Field(None, description="Null = unlimited.")
    upload_used_bytes: int = 0
    link_enabled: bool = False
    link_url: str | None = Field(
        None, description="Present only for managers and only while enabled."
    )
    can_manage: bool = False
    resource_path: str | None = None


class ShareUpdate(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    owner_id: uuid.UUID | None = None
    expires_at: datetime | None = None
    never_expires: bool | None = None
    upload_quota_mb: int | None = Field(None, ge=1, le=10_000_000)
    unlimited_quota: bool | None = None
    notify_email: bool | None = None
    restricted: bool | None = None
    link_enabled: bool | None = None


class ShareInvite(ApiModel):
    users: list[RecipientIn] = Field(min_length=1, max_length=50)
    send_email: bool = False


class InviteResult(ApiModel):
    share: ShareOut
    invited: list[str]
    skipped: list[str]
    email: Literal["off", "queued", "not_configured"]


class ShareGroupAdd(ApiModel):
    group_id: uuid.UUID | None = None
    everyone: bool = Field(False, description="Add the whole organization (EVERYONE).")
    confirm_broad: bool = False


class PrincipalPermissions(ApiModel):
    type: Literal["user", "group", "organization"]
    id: uuid.UUID
    permissions: list[
        Literal["view", "download", "upload", "share", "sync", "delete", "manage"]
    ] = Field(min_length=1)


class SharePermissionsUpdate(ApiModel):
    principals: list[PrincipalPermissions] = Field(min_length=1, max_length=100)


class ShareHistoryItem(ApiModel):
    id: uuid.UUID
    occurred_at: datetime
    action: str
    summary: str
    actor: UserRef | None
    outcome: Literal["success", "denied", "failure"]
    details: dict[str, object] = {}
    ip_address: str | None = None


class LinkTrack(ApiModel):
    event: Literal["copied", "opened", "emailed"]


class LinkResolveIn(ApiModel):
    token: str = Field(min_length=20, max_length=200)


class LinkResolveOut(ApiModel):
    resource_type: Literal["folder", "document"]
    resource_id: uuid.UUID
    name: str
    joined: bool = Field(description="True if opening the link added you to the share just now.")


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
    # Friendly columns of the Manage Folder Permissions table (Read, Write, Share, Delete, Manage).
    permissions: list[str] = []


__all__ = [
    "PermissionGrantIn",
    "PermissionGrantOut",
    "ReceivedShare",
    "RecipientIn",
    "RecipientOut",
    "ShareCreate",
    "ShareOut",
]
