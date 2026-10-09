"""Directory provisioning: sources, links to external identities and sync run history."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk

SOURCE_KINDS = ["static", "entra", "ldap"]
RUN_STATES = ["running", "succeeded", "failed", "aborted"]


class DirectorySource(Base):
    """A configured provisioning source. Secrets are referenced (env:NAME), never stored."""

    __tablename__ = "directory_sources"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(16))
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    sync_interval_minutes: Mapped[int | None] = mapped_column(Integer)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_directory_sources_id_org"),
        UniqueConstraint("organization_id", "name", name="uq_directory_sources_name"),
        CheckConstraint(check_in("kind", SOURCE_KINDS, "kind"), name="kind"),
    )


class DirectoryUserLink(Base):
    """Maps a stable external id (Entra object id / LDAP entryUUID) to a DMS user."""

    __tablename__ = "directory_user_links"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    source_id: Mapped[uuid.UUID] = mapped_column()
    external_id: Mapped[str] = mapped_column(String(255))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="CASCADE"))
    last_seen_at: Mapped[datetime] = created_at_col()
    # set when the sync removed this user's access; only then may a later sync reactivate it
    deprovisioned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id", "organization_id"],
            ["dms.directory_sources.id", "dms.directory_sources.organization_id"],
            ondelete="CASCADE",
            name="fk_directory_user_links_source_org",
        ),
        UniqueConstraint("source_id", "external_id", name="uq_directory_user_links_external"),
        UniqueConstraint("source_id", "user_id", name="uq_directory_user_links_user"),
    )


class DirectoryGroupLink(Base):
    __tablename__ = "directory_group_links"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    source_id: Mapped[uuid.UUID] = mapped_column()
    external_id: Mapped[str] = mapped_column(String(255))
    group_id: Mapped[uuid.UUID] = mapped_column()

    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id", "organization_id"],
            ["dms.directory_sources.id", "dms.directory_sources.organization_id"],
            ondelete="CASCADE",
            name="fk_directory_group_links_source_org",
        ),
        ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["dms.groups.id", "dms.groups.organization_id"],
            ondelete="CASCADE",
            name="fk_directory_group_links_group_org",
        ),
        UniqueConstraint("source_id", "external_id", name="uq_directory_group_links_external"),
        UniqueConstraint("group_id", name="uq_directory_group_links_group"),
    )


class DirectorySyncRun(Base):
    __tablename__ = "directory_sync_runs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    source_id: Mapped[uuid.UUID] = mapped_column()
    state: Mapped[str] = mapped_column(String(16), default="running")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    stats: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id", "organization_id"],
            ["dms.directory_sources.id", "dms.directory_sources.organization_id"],
            ondelete="CASCADE",
            name="fk_directory_sync_runs_source_org",
        ),
        CheckConstraint(check_in("state", RUN_STATES, "state"), name="state"),
        Index("ix_directory_sync_runs_source", "source_id", "started_at"),
    )
