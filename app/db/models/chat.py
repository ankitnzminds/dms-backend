"""Agentic chat: conversations, messages, bounded agent runs, audited tool executions, pending
(confirmation-gated) actions, and access requests (records awaiting a decision - never grants)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, updated_at_col, uuid_pk

RUN_STATUSES = ["queued", "running", "awaiting_confirmation", "completed", "failed", "cancelled"]
ACTION_STATUSES = [
    "pending",
    "confirmed",
    "executed",
    "partially_executed",
    "failed",
    "cancelled",
    "expired",
    "invalidated",
]
ACCESS_REQUEST_STATUSES = ["pending", "approved", "rejected", "cancelled"]


class ChatConversation(Base):
    __tablename__ = "chat_conversations"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    owner_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(200), default="New conversation")
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_chat_conversations_id_org"),
        CheckConstraint(
            check_in("status", ["active", "archived"], "conversations_status"),
            name="conversations_status",
        ),
        Index("ix_chat_conversations_owner", "organization_id", "owner_user_id", "updated_at"),
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    conversation_id: Mapped[uuid.UUID] = mapped_column()
    role: Mapped[str] = mapped_column(String(12))
    content: Mapped[str] = mapped_column(Text)
    # [{ref, document_id, version_id, version_number, chunk_index, document_name}] - no storage keys
    citations: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    # Server-built structured cards (never model-authored): documents, shares, requests, actions...
    blocks: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    # 'preview:<doc>' / 'share:<type>:<id>' rights this message's content depends on; re-checked
    # whenever history is displayed so a revoked user can no longer replay it.
    access_guards: Mapped[list[str]] = mapped_column(
        ARRAY(String), default=list, server_default=text("'{}'")
    )
    run_id: Mapped[uuid.UUID | None] = mapped_column()
    model: Mapped[str | None] = mapped_column(String(100))
    feedback: Mapped[str | None] = mapped_column(String(8))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["conversation_id", "organization_id"],
            ["dms.chat_conversations.id", "dms.chat_conversations.organization_id"],
            ondelete="CASCADE",
            name="fk_chat_messages_conversation_org",
        ),
        CheckConstraint(
            check_in("role", ["user", "assistant"], "messages_role"), name="messages_role"
        ),
        CheckConstraint("feedback IS NULL OR feedback IN ('up', 'down')", name="feedback"),
        Index("ix_chat_messages_conversation", "conversation_id", "created_at"),
    )


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    requester_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="CASCADE"))
    conversation_id: Mapped[uuid.UUID] = mapped_column()
    status: Mapped[str] = mapped_column(String(24), default="queued")
    current_step: Mapped[str | None] = mapped_column(String(200))
    steps: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    tool_calls: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    error_code: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_agent_runs_id_org"),
        ForeignKeyConstraint(
            ["conversation_id", "organization_id"],
            ["dms.chat_conversations.id", "dms.chat_conversations.organization_id"],
            ondelete="CASCADE",
            name="fk_agent_runs_conversation_org",
        ),
        CheckConstraint(check_in("status", RUN_STATUSES, "runs_status"), name="runs_status"),
        Index("ix_agent_runs_conversation", "conversation_id", "created_at"),
    )


class ToolExecution(Base):
    """One audited tool invocation. Arguments are stored only as a hash; results never."""

    __tablename__ = "tool_executions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    run_id: Mapped[uuid.UUID] = mapped_column()
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments_hash: Mapped[str] = mapped_column(String(64))
    decision: Mapped[str] = mapped_column(String(8))  # allow | deny | invalid
    reason_code: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # ok | error | proposed
    duration_ms: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["run_id", "organization_id"],
            ["dms.agent_runs.id", "dms.agent_runs.organization_id"],
            ondelete="CASCADE",
            name="fk_tool_executions_run_org",
        ),
        CheckConstraint(
            check_in("decision", ["allow", "deny", "invalid"], "executions_decision"),
            name="executions_decision",
        ),
        Index("ix_tool_executions_run", "run_id", "created_at"),
    )


class PendingAction(Base):
    """A consequential action proposed by the agent. Nothing happens until its requester confirms
    this exact payload (hash-bound, single-use, expiring); authorization is re-checked on execute."""

    __tablename__ = "pending_actions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    requester_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="CASCADE"))
    conversation_id: Mapped[uuid.UUID] = mapped_column()
    run_id: Mapped[uuid.UUID | None] = mapped_column()
    action_type: Mapped[str] = mapped_column(String(48))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    payload_hash: Mapped[str] = mapped_column(String(64))
    preview: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["conversation_id", "organization_id"],
            ["dms.chat_conversations.id", "dms.chat_conversations.organization_id"],
            ondelete="CASCADE",
            name="fk_pending_actions_conversation_org",
        ),
        CheckConstraint(
            check_in("status", ACTION_STATUSES, "actions_status"), name="actions_status"
        ),
        Index("ix_pending_actions_conversation", "conversation_id", "created_at"),
    )


class AccessRequest(Base):
    """A request for access. It grants nothing; only an authorized approver's decision does."""

    __tablename__ = "access_requests"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    resource_type: Mapped[str] = mapped_column(String(16))
    resource_id: Mapped[uuid.UUID] = mapped_column()
    requester_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="CASCADE"))
    requested_actions: Mapped[list[str]] = mapped_column(ARRAY(String))
    reason: Mapped[str] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    approver_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    decision_reason: Mapped[str | None] = mapped_column(String(1000))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        CheckConstraint(
            check_in("resource_type", ["document", "folder"], "requests_resource_type"),
            name="requests_resource_type",
        ),
        CheckConstraint(
            check_in("status", ACCESS_REQUEST_STATUSES, "requests_status"), name="requests_status"
        ),
        CheckConstraint("cardinality(requested_actions) > 0", name="actions"),
        # One open request per requester and resource: submissions are idempotent.
        Index(
            "uq_access_requests_open",
            "organization_id",
            "requester_id",
            "resource_type",
            "resource_id",
            unique=True,
            postgresql_where=text("status = 'pending'"),
        ),
        Index("ix_access_requests_resource", "organization_id", "resource_type", "resource_id"),
    )
