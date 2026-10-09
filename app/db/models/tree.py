"""Canonical folder tree, documents, immutable versions and storage locations."""

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
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, updated_at_col, uuid_pk
from app.db.enums import DocumentStatus, ScanStatus, values

# Names may not contain path separators (no traversal through display names).
NAME_NO_SEPARATORS = r"name !~ '[/\\]'"


class StorageLocation(Base):
    """Where bytes live. Holds a *reference* to credentials, never the secret itself."""

    __tablename__ = "storage_locations"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    provider_type: Mapped[str] = mapped_column(String(50))
    bucket: Mapped[str] = mapped_column(String(200))
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    secret_ref: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), default="active")
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_storage_locations_id_org"),
        CheckConstraint(check_in("status", ["active", "disabled"], "status"), name="status"),
        Index(
            "uq_storage_locations_default",
            "organization_id",
            unique=True,
            postgresql_where=text("is_default"),
        ),
    )


class Folder(Base):
    __tablename__ = "folders"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    parent_folder_id: Mapped[uuid.UUID | None] = mapped_column()
    name: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    is_team_folder: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    delete_batch_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    row_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_folders_id_org"),
        ForeignKeyConstraint(
            ["parent_folder_id", "organization_id"],
            ["dms.folders.id", "dms.folders.organization_id"],
            ondelete="RESTRICT",
            name="fk_folders_parent_org",
        ),
        CheckConstraint("length(btrim(name)) > 0", name="name_nonempty"),
        CheckConstraint(NAME_NO_SEPARATORS, name="name_no_separators"),
        CheckConstraint(
            "parent_folder_id IS NULL OR parent_folder_id <> id", name="not_own_parent"
        ),
        # exactly one root per organization
        Index(
            "uq_folders_one_root",
            "organization_id",
            unique=True,
            postgresql_where=text("parent_folder_id IS NULL"),
        ),
        Index(
            "uq_folders_sibling_name",
            "organization_id",
            "parent_folder_id",
            func.lower(name),
            unique=True,
            postgresql_where=text("deleted_at IS NULL AND parent_folder_id IS NOT NULL"),
        ),
        Index("ix_folders_parent", "organization_id", "parent_folder_id"),
        Index(
            "ix_folders_delete_batch",
            "delete_batch_id",
            postgresql_where=text("delete_batch_id IS NOT NULL"),
        ),
    )


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    folder_id: Mapped[uuid.UUID] = mapped_column()
    name: Mapped[str] = mapped_column(String(255))
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    current_version_id: Mapped[uuid.UUID | None] = mapped_column()
    latest_version_number: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    status: Mapped[str] = mapped_column(String(32), default=DocumentStatus.PROCESSING.value)
    classification: Mapped[str] = mapped_column(
        String(50), default="internal", server_default="internal"
    )
    custom_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    delete_batch_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    row_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()
    search_vector: Mapped[Any] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('simple', coalesce(name, ''))", persisted=True),
        nullable=True,
    )

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_documents_id_org"),
        ForeignKeyConstraint(
            ["folder_id", "organization_id"],
            ["dms.folders.id", "dms.folders.organization_id"],
            ondelete="RESTRICT",
            name="fk_documents_folder_org",
        ),
        ForeignKeyConstraint(
            ["current_version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="RESTRICT",
            use_alter=True,
            name="fk_documents_current_version_org",
        ),
        CheckConstraint(check_in("status", values(DocumentStatus), "status"), name="status"),
        CheckConstraint("length(btrim(name)) > 0", name="name_nonempty"),
        CheckConstraint(NAME_NO_SEPARATORS, name="name_no_separators"),
        CheckConstraint("latest_version_number >= 0", name="latest_nonneg"),
        Index(
            "uq_documents_sibling_name",
            "organization_id",
            "folder_id",
            func.lower(name),
            unique=True,
            postgresql_where=text("deleted_at IS NULL"),
        ),
        Index("ix_documents_folder", "organization_id", "folder_id"),
        Index("ix_documents_owner", "organization_id", "owner_id"),
        Index("ix_documents_search", "search_vector", postgresql_using="gin"),
        Index(
            "ix_documents_delete_batch",
            "delete_batch_id",
            postgresql_where=text("delete_batch_id IS NOT NULL"),
        ),
    )


class DocumentVersion(Base):
    """Immutable content record. Only scan_* columns may change after insert (DB trigger)."""

    __tablename__ = "document_versions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    document_id: Mapped[uuid.UUID] = mapped_column()
    version_number: Mapped[int] = mapped_column(Integer)
    storage_location_id: Mapped[uuid.UUID] = mapped_column()
    object_key: Mapped[str] = mapped_column(String(512))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    content_type: Mapped[str] = mapped_column(String(255))
    original_filename: Mapped[str] = mapped_column(String(255))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    restored_from_version_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.document_versions.id", ondelete="RESTRICT")
    )
    scan_status: Mapped[str] = mapped_column(String(32), default=ScanStatus.PENDING.value)
    scan_engine: Mapped[str | None] = mapped_column(String(100))
    scan_detail: Mapped[str | None] = mapped_column(Text)
    scanned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_document_versions_id_org"),
        UniqueConstraint("document_id", "version_number", name="uq_document_versions_doc_number"),
        UniqueConstraint("storage_location_id", "object_key", name="uq_document_versions_object"),
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="RESTRICT",
            name="fk_document_versions_document_org",
        ),
        ForeignKeyConstraint(
            ["storage_location_id", "organization_id"],
            ["dms.storage_locations.id", "dms.storage_locations.organization_id"],
            ondelete="RESTRICT",
            name="fk_document_versions_location_org",
        ),
        CheckConstraint(
            check_in("scan_status", values(ScanStatus), "scan_status"), name="scan_status"
        ),
        CheckConstraint("size_bytes >= 0", name="size_nonneg"),
        CheckConstraint("version_number >= 1", name="number_positive"),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="sha256_hex"),
        Index("ix_document_versions_org_scan", "organization_id", "scan_status"),
    )
