"""Chat, pending-action and access-request schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from app.schemas.common import ActionName, ApiModel, UserRef

ResourceKind = Literal["document", "folder"]
RunStatus = Literal[
    "queued", "running", "awaiting_confirmation", "completed", "failed", "cancelled"
]
ActionStatus = Literal[
    "pending",
    "confirmed",
    "executed",
    "partially_executed",
    "failed",
    "cancelled",
    "expired",
    "invalidated",
]


# ---------------------------------------------------------------- access requests
class AccessRequestCreate(ApiModel):
    resource_type: ResourceKind
    resource_id: uuid.UUID
    actions: list[ActionName] = Field(min_length=1, max_length=16)
    reason: str = Field(min_length=3, max_length=1000)


class AccessRequestDecision(ApiModel):
    decision: Literal["approve", "reject"]
    reason: str | None = Field(None, max_length=1000)
    actions: list[ActionName] | None = Field(
        None, description="Approve only this subset of the requested actions."
    )
    expires_at: datetime | None = None


class AccessRequestOut(ApiModel):
    id: uuid.UUID
    resource_type: ResourceKind
    resource_id: uuid.UUID
    resource_name: str | None
    requester: UserRef
    requested_actions: list[str]
    reason: str
    status: Literal["pending", "approved", "rejected", "cancelled"]
    approver: UserRef | None = None
    decision_reason: str | None = None
    created_at: datetime
    decided_at: datetime | None = None
    can_decide: bool = Field(False, description="The caller may approve/reject this request.")


# ---------------------------------------------------------------- chat
class ConversationCreate(ApiModel):
    title: str | None = Field(None, max_length=200)
    context_document_id: uuid.UUID | None = Field(
        None, description="Optional focus: stable ID only - it grants nothing."
    )
    context_folder_id: uuid.UUID | None = None


class ConversationOut(ApiModel):
    id: uuid.UUID
    title: str
    status: Literal["active", "archived"]
    created_at: datetime
    updated_at: datetime


class CitationOut(ApiModel):
    ref: str
    document_id: uuid.UUID
    version_id: uuid.UUID
    version_number: int
    chunk_index: int
    document_name: str | None = Field(None, description="Null if you can no longer access it.")
    accessible: bool
    route: str | None = Field(None, description="App route; opening re-checks authorization.")


class MessageOut(ApiModel):
    id: uuid.UUID
    role: Literal["user", "assistant"]
    content: str
    redacted: bool = Field(
        False, description="Content hidden because access to a source document changed."
    )
    citations: list[CitationOut] = Field(default_factory=list)
    blocks: list[dict[str, Any]] = Field(default_factory=list)
    run_id: uuid.UUID | None = None
    model: str | None = None
    feedback: Literal["up", "down"] | None = None
    created_at: datetime


class MessageCreate(ApiModel):
    content: str = Field(min_length=1, max_length=4000)
    context_document_id: uuid.UUID | None = None
    context_folder_id: uuid.UUID | None = None


class RunOut(ApiModel):
    id: uuid.UUID
    conversation_id: uuid.UUID
    status: RunStatus
    current_step: str | None
    steps: int
    tool_calls: int
    error_code: str | None
    started_at: datetime | None
    finished_at: datetime | None
    assistant_message_id: uuid.UUID | None = None
    pending_action_ids: list[uuid.UUID] = Field(default_factory=list)


class MessageAccepted(ApiModel):
    message: MessageOut
    run: RunOut


class FeedbackIn(ApiModel):
    feedback: Literal["up", "down"] | None


class PendingActionOut(ApiModel):
    id: uuid.UUID
    conversation_id: uuid.UUID
    action_type: str
    status: ActionStatus
    preview: dict[str, Any]
    payload_hash: str
    expires_at: datetime
    result: dict[str, Any] | None = None
    error_code: str | None = None


class ConfirmIn(ApiModel):
    payload_hash: str = Field(
        min_length=64,
        max_length=64,
        description="The hash shown in the preview; a different/stale value is rejected.",
    )
