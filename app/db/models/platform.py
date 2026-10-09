"""Cross-cutting platform tables: audit, outbox, notifications, stars, recents."""

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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk
from app.db.enums import AuditOutcome, OutboxStatus, values


class AuditEvent(Base):
    """Append-only (UPDATE/DELETE blocked by trigger). See ADR-0009 for the integrity model."""

    __tablename__ = "audit_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    # nullable: authentication failures happen before a tenant is resolved
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column()
    action: Mapped[str] = mapped_column(String(100))
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[uuid.UUID | None] = mapped_column()
    outcome: Mapped[str] = mapped_column(String(16))
    request_id: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    event_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        CheckConstraint(check_in("outcome", values(AuditOutcome), "outcome"), name="outcome"),
        Index("ix_audit_events_org_created", "organization_id", text("created_at DESC")),
        Index("ix_audit_events_org_action", "organization_id", "action", text("created_at DESC")),
        Index("ix_audit_events_resource", "organization_id", "resource_type", "resource_id"),
        Index("ix_audit_events_actor", "organization_id", "actor_user_id"),
    )


class OutboxEvent(Base):
    """Transactional outbox. Rows are written in the same transaction as the business change
    and double as the durable job queue (consumers claim rows with FOR UPDATE SKIP LOCKED)."""

    __tablename__ = "outbox_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    event_type: Mapped[str] = mapped_column(String(100))
    aggregate_type: Mapped[str] = mapped_column(String(50))
    aggregate_id: Mapped[uuid.UUID] = mapped_column()
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    status: Mapped[str] = mapped_column(String(16), default=OutboxStatus.PENDING.value)
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    max_attempts: Mapped[int] = mapped_column(Integer, default=8, server_default="8")
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("now()")
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_col()
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(check_in("status", values(OutboxStatus), "status"), name="status"),
        Index(
            "ix_outbox_claimable",
            "next_attempt_at",
            postgresql_where=text("status IN ('pending', 'processing')"),
        ),
        Index("ix_outbox_aggregate", "aggregate_type", "aggregate_id"),
    )


class ProcessedEvent(Base):
    """Consumer-side idempotency: (consumer, event) is applied at most once."""

    __tablename__ = "processed_events"

    consumer: Mapped[str] = mapped_column(String(100), primary_key=True)
    event_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    processed_at: Mapped[datetime] = created_at_col()


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="CASCADE")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str | None] = mapped_column(Text)
    resource_type: Mapped[str | None] = mapped_column(String(50))
    resource_id: Mapped[uuid.UUID | None] = mapped_column()
    source_event_id: Mapped[uuid.UUID | None] = mapped_column()
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("user_id", "source_event_id", "type", name="uq_notifications_event"),
        Index("ix_notifications_user_created", "user_id", text("created_at DESC")),
    )


class DocumentStar(Base):
    __tablename__ = "document_stars"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.users.id", ondelete="CASCADE"), primary_key=True
    )
    document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column()
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="CASCADE",
            name="fk_document_stars_document_org",
        ),
    )


class RecentDocument(Base):
    __tablename__ = "recent_documents"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.users.id", ondelete="CASCADE"), primary_key=True
    )
    document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column()
    last_action: Mapped[str] = mapped_column(String(32))
    last_accessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="CASCADE",
            name="fk_recent_documents_document_org",
        ),
        Index("ix_recent_user_time", "user_id", "organization_id", text("last_accessed_at DESC")),
    )
