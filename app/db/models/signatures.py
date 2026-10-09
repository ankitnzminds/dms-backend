"""E-signature requests, recipients, provider events and preserved signed artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
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

REQUEST_STATES = ["creating", "sent", "completed", "declined", "cancelled", "expired", "failed"]
RECIPIENT_STATES = ["pending", "signed", "declined"]
EVENT_STATES = ["received", "processed", "ignored", "failed"]


class SignatureRequest(Base):
    __tablename__ = "signature_requests"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    document_id: Mapped[uuid.UUID] = mapped_column()
    # the EXACT immutable version that is sent for signature
    source_version_id: Mapped[uuid.UUID] = mapped_column()
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="RESTRICT"))
    provider: Mapped[str] = mapped_column(String(32))
    provider_request_id: Mapped[str | None] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(300))
    message: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(16), default="creating")
    failure_reason: Mapped[str | None] = mapped_column(String(300))
    last_reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_signature_requests_id_org"),
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="CASCADE",
            name="fk_signature_requests_document_org",
        ),
        ForeignKeyConstraint(
            ["source_version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="CASCADE",
            name="fk_signature_requests_version_org",
        ),
        CheckConstraint(check_in("state", REQUEST_STATES, "state"), name="state"),
        Index(
            "uq_signature_requests_provider_id",
            "provider",
            "provider_request_id",
            unique=True,
            postgresql_where=text("provider_request_id IS NOT NULL"),
        ),
        Index("ix_signature_requests_org_state", "organization_id", "state"),
        Index("ix_signature_requests_document", "organization_id", "document_id"),
    )


class SignatureRecipient(Base):
    __tablename__ = "signature_recipients"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    request_id: Mapped[uuid.UUID] = mapped_column()
    email: Mapped[str] = mapped_column(String(320))
    name: Mapped[str] = mapped_column(String(200))
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )  # set for internal signers
    order_index: Mapped[int] = mapped_column(Integer, default=0)
    provider_recipient_id: Mapped[str | None] = mapped_column(String(200))
    # Secret-equivalent link (contains the signer's token). Only ever returned to that signer.
    signing_url: Mapped[str | None] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(16), default="pending")
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["request_id", "organization_id"],
            ["dms.signature_requests.id", "dms.signature_requests.organization_id"],
            ondelete="CASCADE",
            name="fk_signature_recipients_request_org",
        ),
        UniqueConstraint("request_id", "email", name="uq_signature_recipients_email"),
        CheckConstraint(check_in("status", RECIPIENT_STATES, "status"), name="status"),
    )


class SignatureEvent(Base):
    """Every webhook delivery, deduplicated by (provider, provider_event_id)."""

    __tablename__ = "signature_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    provider: Mapped[str] = mapped_column(String(32))
    provider_event_id: Mapped[str] = mapped_column(String(200))
    organization_id: Mapped[uuid.UUID | None] = mapped_column()
    request_id: Mapped[uuid.UUID | None] = mapped_column()
    provider_request_id: Mapped[str | None] = mapped_column(String(200))
    event_type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(16), default="received")
    error: Mapped[str | None] = mapped_column(String(300))
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    received_at: Mapped[datetime] = created_at_col()
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("provider", "provider_event_id", name="uq_signature_events_dedupe"),
        CheckConstraint(check_in("status", EVENT_STATES, "status"), name="status"),
        Index("ix_signature_events_request", "request_id", "received_at"),
    )


class SignedArtifact(Base):
    """The signed document returned by the provider, preserved as a new immutable version."""

    __tablename__ = "signed_artifacts"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    request_id: Mapped[uuid.UUID] = mapped_column()
    version_id: Mapped[uuid.UUID] = mapped_column()  # the DMS version holding the signed bytes
    source_version_id: Mapped[uuid.UUID] = mapped_column()  # exactly what was signed
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["request_id", "organization_id"],
            ["dms.signature_requests.id", "dms.signature_requests.organization_id"],
            ondelete="CASCADE",
            name="fk_signed_artifacts_request_org",
        ),
        ForeignKeyConstraint(
            ["version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="CASCADE",
            name="fk_signed_artifacts_version_org",
        ),
        UniqueConstraint("request_id", name="uq_signed_artifacts_request"),
    )
