"""Schemas for administration, identity and platform endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ApiModel, UploadStateName

RoleName = Literal["owner", "admin", "member", "auditor"]
MembershipStatusName = Literal["invited", "active", "suspended", "removed"]


class MembershipOut(ApiModel):
    organization_id: uuid.UUID
    organization_name: str
    role: RoleName
    status: MembershipStatusName


class MeOut(ApiModel):
    user_id: uuid.UUID
    email: str
    display_name: str | None
    organization_id: uuid.UUID | None
    organization_name: str | None
    role: RoleName | None
    capabilities: list[str] = Field(description="Org-level capabilities for UI affordances only.")
    memberships: list[MembershipOut]
    pending_invitations: list[MembershipOut]


class MemberOut(ApiModel):
    user_id: uuid.UUID
    email: str
    display_name: str | None
    role: RoleName
    membership_status: MembershipStatusName
    user_status: Literal["invited", "active", "disabled"]
    last_login_at: datetime | None
    group_ids: list[uuid.UUID] = []


class InviteRequest(ApiModel):
    email: str = Field(min_length=3, max_length=320)
    display_name: str | None = Field(None, max_length=200)
    role: RoleName = "member"


class MemberUpdate(ApiModel):
    role: RoleName | None = None
    status: Literal["active", "suspended", "removed"] | None = None
    display_name: str | None = Field(None, max_length=200)


class GroupIn(ApiModel):
    name: str = Field(min_length=1, max_length=200)
    kind: Literal["group", "department", "team"] = "group"
    description: str | None = Field(None, max_length=1000)


class GroupUpdate(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=1000)


class GroupOut(ApiModel):
    id: uuid.UUID
    name: str
    kind: Literal["group", "department", "team"]
    description: str | None
    member_count: int
    created_at: datetime


class GroupMemberAdd(ApiModel):
    user_id: uuid.UUID


class OrganizationOut(ApiModel):
    id: uuid.UUID
    name: str
    slug: str
    status: str
    settings: dict[str, Any]
    quota_bytes: int | None
    root_folder_id: uuid.UUID


class OrganizationUpdate(ApiModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    settings: dict[str, Any] | None = None


class UsageOut(ApiModel):
    quota_bytes: int | None
    used_bytes: int
    reserved_bytes: int
    documents: int
    folders: int
    versions: int | None = Field(None, description="Null for non-administrators.")
    pending_scans: int | None = None
    quarantined_documents: int | None = None
    users: int | None = None
    groups: int | None = None
    organization_status: str


class AuditEventOut(ApiModel):
    id: uuid.UUID
    created_at: datetime
    actor_user_id: uuid.UUID | None
    actor_email: str | None = None
    action: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    outcome: Literal["success", "denied", "failure"]
    request_id: str | None
    metadata: dict[str, Any]


class NotificationOut(ApiModel):
    id: uuid.UUID
    type: str
    title: str
    body: str | None
    resource_type: str | None
    resource_id: uuid.UUID | None
    read_at: datetime | None
    created_at: datetime


class UploadSessionOut(ApiModel):
    id: uuid.UUID
    folder_id: uuid.UUID
    document_id: uuid.UUID | None
    filename: str
    declared_size: int
    content_type: str
    state: UploadStateName
    expires_at: datetime
    upload_url: str = Field(
        description="PUT the raw bytes here (Content-Type: application/octet-stream)."
    )
    failure_reason: str | None = None


class UploadInitiate(ApiModel):
    filename: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(gt=0)
    content_type: str | None = Field(None, max_length=255)
    sha256: str | None = Field(
        None, description="Hex SHA-256 of the content; verified server-side."
    )
    expected_latest_version: int | None = Field(
        None, description="Required when uploading a new version (optimistic concurrency)."
    )
    intent: Literal["upload", "create_file"] = Field(
        "upload",
        description='"create_file" needs the Create File right; "upload" needs the Upload right.',
    )


class UploadFinalizeOut(ApiModel):
    document_id: uuid.UUID
    version_id: uuid.UUID
    version_number: int
    status: Literal["pending_scan"] = "pending_scan"
    message: str = "Upload received. The file becomes available after required checks pass."


class DownloadUrlRequest(ApiModel):
    version_number: int | None = Field(None, ge=1)
    inline: bool = False
    variant: Literal["original", "thumbnail"] = Field(
        "original", description="'thumbnail' returns a generated image preview (requires preview)."
    )


class DownloadUrlOut(ApiModel):
    url: str
    expires_at: datetime


class QuarantineItem(ApiModel):
    document_id: uuid.UUID
    document_name: str
    version_id: uuid.UUID
    version_number: int
    scan_status: str
    scan_detail: str | None
    scan_engine: str | None
    scanned_at: datetime | None
    uploaded_by: uuid.UUID | None
    size_bytes: int


class TopAction(ApiModel):
    action: str
    count: int


class SharesSummary(ApiModel):
    total: int
    revoked: int
    expired: int
    active: int


class ReportSummaryOut(ApiModel):
    period_days: int
    documents_by_classification: dict[str, int]
    documents_by_status: dict[str, int]
    shares: SharesSummary
    legal_holds: dict[str, int]
    retention_policies_enabled: int
    workflow_runs: dict[str, int]
    signature_requests: dict[str, int]
    audit_events_by_outcome: dict[str, int]
    top_actions: list[TopAction]
    denied_attempts: int
