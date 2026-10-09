"""Schemas for administrator user management, policies and activity."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.admin import RoleName
from app.schemas.common import ApiModel

AccessLevelName = Literal["full", "guest", "external"]
CreationSourceName = Literal["default", "invitation", "csv_import", "directory"]
StatusFilter = Literal["all", "guest", "full", "external", "disabled"]
AccountState = Literal["active", "invited", "disabled", "locked", "expired"]


class AdminUserOut(ApiModel):
    user_id: uuid.UUID
    username: str | None
    email: str
    display_name: str | None
    secondary_email: str | None
    phone: str | None
    notes: str | None
    role: RoleName
    access_level: AccessLevelName
    membership_status: Literal["invited", "active", "suspended", "removed"]
    state: AccountState = Field(
        description="Effective state. Access level is separate: it never means disabled."
    )
    account_locked: bool
    account_expires_at: datetime | None
    email_verified: bool
    last_login_at: datetime | None
    created_at: datetime
    creation_source: CreationSourceName
    authentication: str = Field(
        description="'default' or the identity provider that owns the login."
    )
    group_ids: list[uuid.UUID] = []
    tos_accepted_at: datetime | None = Field(
        None, description="Terms-of-service acceptance is not tracked yet; always null."
    )


class AdminUserCreate(ApiModel):
    email: str = Field(min_length=3, max_length=320)
    username: str | None = Field(None, max_length=100)
    display_name: str | None = Field(None, max_length=200)
    secondary_email: str | None = Field(None, max_length=320)
    phone: str | None = Field(None, max_length=32)
    notes: str | None = Field(None, max_length=2000)
    role: RoleName = "member"
    access_level: AccessLevelName = "full"
    account_expires_at: datetime | None = None
    group_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)


class AdminUserUpdate(ApiModel):
    username: str | None = Field(None, max_length=100)
    display_name: str | None = Field(None, max_length=200)
    secondary_email: str | None = Field(None, max_length=320)
    phone: str | None = Field(None, max_length=32)
    notes: str | None = Field(None, max_length=2000)
    access_level: AccessLevelName | None = None
    account_expires_at: datetime | None = None
    clear_account_expiry: bool = False
    account_locked: bool | None = None


class AdminUserCreated(ApiModel):
    user: AdminUserOut
    invitation_email: Literal["not_configured", "queued"] = Field(
        description="No email is sent unless an email provider is configured for this deployment."
    )


class DeleteImpact(ApiModel):
    owned_documents: int
    owned_bytes: int
    active_shares_created: int
    group_memberships: int
    files_are_deleted: Literal[False] = False
    summary: str


class DeleteRequest(ApiModel):
    confirm: bool
    confirm_email: str = Field(max_length=320, description="Must equal the account's email.")


class QuotaOut(ApiModel):
    quota_bytes: int | None = Field(None, description="Null = no per-user limit.")
    used_bytes: int
    available_bytes: int | None
    organization_quota_bytes: int | None
    organization_used_bytes: int
    quota_source: str
    calculated_at: datetime


class UserGroupsPut(ApiModel):
    group_ids: list[uuid.UUID] = Field(max_length=200)


class PolicyDocument(ApiModel):
    """Overrides stored at one scope + the version for optimistic concurrency."""

    overrides: dict[str, dict[str, Any]]
    version: int


class PolicyPut(ApiModel):
    overrides: dict[str, dict[str, Any]]
    expected_version: int | None = None


class EffectivePolicyOut(ApiModel):
    values: dict[str, dict[str, Any]]
    provenance: dict[str, str]
    enforced: list[str] = Field(description="'tab.key' of settings the backend acts on today.")
    applied_from: Literal["default", "organization", "group", "user"]
    watermark_rules: list[str] = []


class ImportRowOut(ApiModel):
    line: int
    email: str | None
    outcome: Literal["create", "skip_existing", "invalid"]
    problems: list[str] = []


class ImportPreviewOut(ApiModel):
    total: int
    creates: int
    existing: int
    invalid: int
    rows: list[ImportRowOut] = Field(description="First 200 rows, for the preview table.")
    columns_seen: list[str]
    duplicate_policy: Literal["skip_existing"] = "skip_existing"


class ImportResultOut(ApiModel):
    created: int
    skipped_existing: int
    invalid: int
    errors: list[ImportRowOut] = Field(description="Row-level problems (no passwords, no tokens).")


class AdminOut(ApiModel):
    user_id: uuid.UUID
    email: str
    display_name: str | None
    role: RoleName
    membership_status: Literal["invited", "active", "suspended", "removed"]
    authentication: str
    last_login_at: datetime | None


class ActivityEventOut(ApiModel):
    id: uuid.UUID
    occurred_at: datetime
    category: str
    action: str
    outcome: Literal["success", "denied", "failure"]
    actor_user_id: uuid.UUID | None
    actor_email: str | None
    target_type: str | None
    target_id: uuid.UUID | None
    target_label: str | None = None
    request_id: str | None
    ip_address: str | None
    user_agent: str | None
    metadata: dict[str, Any] = {}


class ActivityPage(ApiModel):
    items: list[ActivityEventOut]
    next_cursor: str | None


class AuditPolicyOut(ApiModel):
    append_only: bool
    retention_days: int | None
    categories: list[str]
    never_recorded: list[str]
    coverage_note: str


class UserShareOut(ApiModel):
    id: uuid.UUID
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    resource_name: str | None
    actions: list[str]
    recipient_count: int
    created_at: datetime
    expires_at: datetime | None
    revoked_at: datetime | None


class ImportRequest(ApiModel):
    csv: str = Field(
        max_length=1_100_000, description="CSV text; see GET /admin/users/import/template."
    )
