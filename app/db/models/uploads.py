"""Upload sessions and the quota ledger."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, updated_at_col, uuid_pk
from app.db.enums import LedgerEntryType, UploadState, values


class UploadSession(Base):
    __tablename__ = "upload_sessions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    folder_id: Mapped[uuid.UUID] = mapped_column()
    # set when the session uploads a new version of an existing document
    document_id: Mapped[uuid.UUID | None] = mapped_column()
    expected_latest_version: Mapped[int | None] = mapped_column()
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="RESTRICT"))
    filename: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(255))
    declared_size: Mapped[int] = mapped_column(BigInteger)
    declared_sha256: Mapped[str | None] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(32), default=UploadState.INITIATED.value)
    storage_location_id: Mapped[uuid.UUID] = mapped_column()
    object_key: Mapped[str] = mapped_column(String(512))
    received_size: Mapped[int | None] = mapped_column(BigInteger)
    received_sha256: Mapped[str | None] = mapped_column(String(64))
    reserved_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    idempotency_key: Mapped[str | None] = mapped_column(String(128))
    failure_reason: Mapped[str | None] = mapped_column(Text)
    result_version_id: Mapped[uuid.UUID | None] = mapped_column()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_upload_sessions_id_org"),
        ForeignKeyConstraint(
            ["folder_id", "organization_id"],
            ["dms.folders.id", "dms.folders.organization_id"],
            ondelete="RESTRICT",
            name="fk_upload_sessions_folder_org",
        ),
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="RESTRICT",
            name="fk_upload_sessions_document_org",
        ),
        ForeignKeyConstraint(
            ["storage_location_id", "organization_id"],
            ["dms.storage_locations.id", "dms.storage_locations.organization_id"],
            ondelete="RESTRICT",
            name="fk_upload_sessions_location_org",
        ),
        CheckConstraint(check_in("state", values(UploadState), "state"), name="state"),
        CheckConstraint("declared_size >= 0", name="declared_nonneg"),
        CheckConstraint("reserved_bytes >= 0", name="reserved_nonneg"),
        UniqueConstraint("storage_location_id", "object_key", name="uq_upload_sessions_object"),
        Index(
            "uq_upload_sessions_idem",
            "organization_id",
            "created_by",
            "idempotency_key",
            unique=True,
            postgresql_where=text("idempotency_key IS NOT NULL"),
        ),
        Index("ix_upload_sessions_state_expiry", "state", "expires_at"),
    )


class QuotaLedgerEntry(Base):
    """Append-only accounting trail. Counters on organizations are derived from it."""

    __tablename__ = "quota_ledger_entries"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    entry_type: Mapped[str] = mapped_column(String(16))
    # reserved_delta/used_delta make reconciliation a plain SUM()
    reserved_delta: Mapped[int] = mapped_column(BigInteger, default=0)
    used_delta: Mapped[int] = mapped_column(BigInteger, default=0)
    upload_session_id: Mapped[uuid.UUID | None] = mapped_column()
    document_version_id: Mapped[uuid.UUID | None] = mapped_column()
    idempotency_key: Mapped[str] = mapped_column(String(200))
    note: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("organization_id", "idempotency_key", name="uq_quota_ledger_idem"),
        CheckConstraint(check_in("entry_type", values(LedgerEntryType), "entry_type"), name="type"),
        Index("ix_quota_ledger_org_created", "organization_id", "created_at"),
        Index("ix_quota_ledger_session", "upload_session_id"),
    )
