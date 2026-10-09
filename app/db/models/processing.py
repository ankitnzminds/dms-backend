"""Derived data: extracted text (search), thumbnails/previews, and metadata definitions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk

TEXT_STATUSES = ["extracted", "empty", "unsupported", "failed", "ocr_unavailable"]
METADATA_FIELD_TYPES = ["text", "number", "date", "boolean", "select"]


class DocumentText(Base):
    """Extracted text of a (clean) version. Derived and rebuildable; same ACL as the source."""

    __tablename__ = "document_texts"

    version_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column()
    document_id: Mapped[uuid.UUID] = mapped_column()
    status: Mapped[str] = mapped_column(String(24))
    engine: Mapped[str | None] = mapped_column(String(50))
    char_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    content: Mapped[str | None] = mapped_column("text", Text)
    error: Mapped[str | None] = mapped_column(String(300))
    extracted_at: Mapped[datetime] = created_at_col()
    search_vector: Mapped[Any] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('simple', left(coalesce(text, ''), 1000000))", persisted=True),
        nullable=True,
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="CASCADE",
            name="fk_document_texts_version_org",
        ),
        CheckConstraint(check_in("status", TEXT_STATUSES, "status"), name="status"),
        Index("ix_document_texts_search", "search_vector", postgresql_using="gin"),
        Index("ix_document_texts_document", "organization_id", "document_id"),
    )


class DocumentDerivative(Base):
    """Generated artifacts (thumbnails). Not charged to quota; size-capped at generation."""

    __tablename__ = "document_derivatives"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    version_id: Mapped[uuid.UUID] = mapped_column()
    kind: Mapped[str] = mapped_column(String(24))
    storage_location_id: Mapped[uuid.UUID] = mapped_column()
    object_key: Mapped[str] = mapped_column(String(512))
    content_type: Mapped[str] = mapped_column(String(100))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="CASCADE",
            name="fk_document_derivatives_version_org",
        ),
        UniqueConstraint("version_id", "kind", name="uq_document_derivatives_kind"),
        CheckConstraint(check_in("kind", ["thumbnail"], "kind"), name="kind"),
    )


class MetadataDefinition(Base):
    """Typed custom metadata field (organization scoped, versioned, archived not deleted)."""

    __tablename__ = "metadata_definitions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    key: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(200))
    field_type: Mapped[str] = mapped_column(String(16))
    required: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    options: Mapped[list[str] | None] = mapped_column(JSONB)
    schema_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("organization_id", "key", name="uq_metadata_definitions_key"),
        CheckConstraint(check_in("field_type", METADATA_FIELD_TYPES, "field_type"), name="type"),
        CheckConstraint("key ~ '^[a-z][a-z0-9_]{0,63}$'", name="key_format"),
        Index("ix_metadata_definitions_org", "organization_id", text("archived_at NULLS FIRST")),
    )
