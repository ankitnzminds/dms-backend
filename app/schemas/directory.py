"""Directory provisioning schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ApiModel


class DirectorySourceIn(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    kind: Literal["static", "entra", "ldap"]
    config: dict[str, Any] = Field(default_factory=dict)
    secret_ref: str | None = Field(
        None,
        max_length=200,
        description="env:DMS_DIR_<NAME> - a reference, never the secret itself.",
    )
    sync_interval_minutes: int | None = Field(None, ge=15, le=10080)


class DirectorySourceUpdate(ApiModel):
    config: dict[str, Any] | None = None
    secret_ref: str | None = Field(None, max_length=200)
    enabled: bool | None = None
    sync_interval_minutes: int | None = Field(None, ge=15, le=10080)


class DirectorySourceOut(ApiModel):
    id: uuid.UUID
    name: str
    kind: Literal["static", "entra", "ldap"]
    config: dict[str, Any]
    secret_ref: str | None
    enabled: bool
    sync_interval_minutes: int | None
    last_sync_at: datetime | None
    has_snapshot: bool


class DirectoryUserIn(ApiModel):
    external_id: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=3, max_length=320)
    display_name: str | None = Field(None, max_length=200)
    active: bool = True


class DirectoryGroupIn(ApiModel):
    external_id: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=200)
    member_ids: list[str] = Field(default_factory=list, max_length=20000)


class SnapshotIn(ApiModel):
    users: list[DirectoryUserIn] = Field(max_length=20000)
    groups: list[DirectoryGroupIn] = Field(default_factory=list, max_length=5000)


class SyncRequestIn(ApiModel):
    dry_run: bool = Field(True, description="Preview the changes without applying them.")


class SyncRunOut(ApiModel):
    id: uuid.UUID
    source_id: uuid.UUID
    source_name: str | None
    state: Literal["running", "succeeded", "failed", "aborted"]
    dry_run: bool
    stats: dict[str, Any]
    error: str | None
    started_at: datetime
    finished_at: datetime | None
