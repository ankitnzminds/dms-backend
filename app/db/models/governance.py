"""Governance: retention policies and legal holds."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk
from app.db.enums import ResourceType, values


class RetentionPolicy(Base):
    """Minimum retention: content under ``scope_folder_id`` (or the whole organization when
    null) cannot be permanently purged until ``min_retention_days`` after it was created."""

    __tablename__ = "retention_policies"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    scope_folder_id: Mapped[uuid.UUID | None] = mapped_column()
    min_retention_days: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        CheckConstraint("min_retention_days BETWEEN 1 AND 36500", name="days_range"),
        Index("ix_retention_policies_org", "organization_id", "enabled"),
        Index("uq_retention_policies_name", "organization_id", func.lower(name), unique=True),
    )


class LegalHold(Base):
    __tablename__ = "legal_holds"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16), default="active")
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    release_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_legal_holds_id_org"),
        CheckConstraint(check_in("status", ["active", "released"], "status"), name="status"),
        Index("ix_legal_holds_org_status", "organization_id", "status"),
    )


class LegalHoldItem(Base):
    __tablename__ = "legal_hold_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    hold_id: Mapped[uuid.UUID] = mapped_column()
    resource_type: Mapped[str] = mapped_column(String(16))
    resource_id: Mapped[uuid.UUID] = mapped_column()
    added_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["hold_id", "organization_id"],
            ["dms.legal_holds.id", "dms.legal_holds.organization_id"],
            ondelete="CASCADE",
            name="fk_legal_hold_items_hold_org",
        ),
        UniqueConstraint("hold_id", "resource_type", "resource_id", name="uq_legal_hold_items"),
        CheckConstraint(
            check_in("resource_type", values(ResourceType), "resource_type"), name="resource_type"
        ),
        Index("ix_legal_hold_items_resource", "organization_id", "resource_type", "resource_id"),
    )
