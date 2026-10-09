"""Governance schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.common import ApiModel


class RetentionPolicyIn(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)
    scope_folder_id: uuid.UUID | None = Field(None, description="Null = whole organization.")
    min_retention_days: int = Field(ge=1, le=36500)


class RetentionPolicyUpdate(ApiModel):
    enabled: bool | None = None
    min_retention_days: int | None = Field(None, ge=1, le=36500)


class RetentionPolicyOut(ApiModel):
    id: uuid.UUID
    name: str
    description: str | None
    scope_folder_id: uuid.UUID | None
    min_retention_days: int
    enabled: bool
    created_at: datetime


class LegalHoldIn(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)


class LegalHoldOut(ApiModel):
    id: uuid.UUID
    name: str
    description: str | None
    status: Literal["active", "released"]
    item_count: int
    created_at: datetime
    released_at: datetime | None
    release_reason: str | None


class LegalHoldItemIn(ApiModel):
    resource_type: Literal["folder", "document"]
    resource_id: uuid.UUID


class LegalHoldItemOut(ApiModel):
    id: uuid.UUID
    resource_type: Literal["folder", "document"]
    resource_id: uuid.UUID
    resource_name: str | None
    created_at: datetime


class ReleaseHoldIn(ApiModel):
    reason: str = Field(min_length=3, max_length=1000)


class ProtectionOut(ApiModel):
    legal_hold: bool
    retention_until: datetime | None
    can_delete: bool
    can_purge: bool


class PurgeOut(ApiModel):
    documents: int
    folders: int
