"""API shapes for rule policies (policy engine)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ApiModel

PolicyStatus = Literal["draft", "published", "disabled", "archived"]
RevisionStatus = Literal["draft", "validated", "published", "superseded"]
PolicyMode = Literal["enforce", "observe"]


class PolicyCreate(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    category: str = Field("custom", min_length=1, max_length=40)
    document: dict[str, Any]
    change_reason: str | None = Field(None, max_length=500)
    template_key: str | None = Field(None, max_length=60)


class PolicyUpdate(ApiModel):
    """Edit the working draft. Editing a published policy opens a NEW draft revision."""

    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=2000)
    document: dict[str, Any] | None = None
    change_reason: str | None = Field(None, max_length=500)


class PublishIn(ApiModel):
    mode: PolicyMode = "enforce"
    change_reason: str | None = Field(None, max_length=500)


class RollbackIn(ApiModel):
    to_revision: int = Field(ge=1)
    change_reason: str = Field(min_length=1, max_length=500)


class ModeIn(ApiModel):
    mode: PolicyMode


class RevisionOut(ApiModel):
    id: uuid.UUID
    revision: int
    status: RevisionStatus
    document: dict[str, Any]
    change_reason: str | None
    created_by: uuid.UUID | None
    created_at: datetime
    validated_at: datetime | None
    published_by: uuid.UUID | None
    published_at: datetime | None


class PolicyOut(ApiModel):
    id: uuid.UUID
    name: str
    description: str | None
    category: str
    owner_kind: Literal["organization", "user"]
    owner_user_id: uuid.UUID | None
    status: PolicyStatus
    mode: PolicyMode
    mandatory: bool
    template_key: str | None
    published_revision: int | None
    latest_revision: int
    latest_revision_status: RevisionStatus
    effect: str | None
    actions: list[str]
    created_at: datetime
    updated_at: datetime


class PolicyDetail(PolicyOut):
    revisions: list[RevisionOut]


class PolicyIssue(ApiModel):
    path: str
    message: str


class PolicyValidationReport(ApiModel):
    valid: bool
    issues: list[PolicyIssue]
    warnings: list[str]
    affected_members: int | None = None
    scope_name: str | None = None
    revision: int


class RevisionDiff(ApiModel):
    from_revision: int
    to_revision: int
    changes: list[dict[str, Any]]
