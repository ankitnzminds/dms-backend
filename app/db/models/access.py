"""Resource permission grants and user-facing share grants."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk
from app.db.enums import RecipientType, ResourceType, SubjectType, values


class PermissionGrant(Base):
    """Administrative ACL entry (team folders, delegated access). Additive; no explicit deny in v1."""

    __tablename__ = "permission_grants"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    resource_type: Mapped[str] = mapped_column(String(16))
    resource_id: Mapped[uuid.UUID] = mapped_column()
    subject_type: Mapped[str] = mapped_column(String(16))
    subject_id: Mapped[uuid.UUID | None] = mapped_column()
    actions: Mapped[list[str]] = mapped_column(ARRAY(String(32)))
    # inherit=True: also applies to every descendant of a folder resource
    inherit: Mapped[bool] = mapped_column(default=True, server_default="true")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        CheckConstraint(
            check_in("resource_type", values(ResourceType), "resource_type"), name="resource_type"
        ),
        CheckConstraint(
            check_in("subject_type", values(SubjectType), "subject_type"), name="subject_type"
        ),
        CheckConstraint(
            "(subject_type = 'organization') = (subject_id IS NULL)", name="subject_id_matches_type"
        ),
        CheckConstraint("cardinality(actions) > 0", name="actions_nonempty"),
        Index("ix_permission_grants_resource", "organization_id", "resource_type", "resource_id"),
        Index("ix_permission_grants_subject", "organization_id", "subject_type", "subject_id"),
    )


class ShareGrant(Base):
    __tablename__ = "share_grants"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    resource_type: Mapped[str] = mapped_column(String(16))
    resource_id: Mapped[uuid.UUID] = mapped_column()
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="RESTRICT"))
    actions: Mapped[list[str]] = mapped_column(ARRAY(String(32)))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    message: Mapped[str | None] = mapped_column(Text)
    # --- share link + options (Share Link dialog)
    name: Mapped[str | None] = mapped_column(String(200))
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    # Opaque high-entropy token: only its SHA-256 is used for lookup; the encrypted copy lets a
    # manager see/copy the link again. Never logged, never in audit metadata.
    link_token_hash: Mapped[str | None] = mapped_column(String(64))
    link_token_enc: Mapped[str | None] = mapped_column(Text)
    link_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # True: only the listed users/groups may use the share ("Allow selected users or groups").
    restricted: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    upload_quota_bytes: Mapped[int | None] = mapped_column(BigInteger)  # null = unlimited
    upload_used_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    # set by the maintenance sweep once the expiry has been audited/notified (exactly once)
    expiry_recorded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_share_grants_id_org"),
        Index(
            "uq_share_grants_link_token",
            "link_token_hash",
            unique=True,
            postgresql_where=text("link_token_hash IS NOT NULL"),
        ),
        CheckConstraint(
            check_in("resource_type", values(ResourceType), "resource_type"), name="resource_type"
        ),
        CheckConstraint("cardinality(actions) > 0", name="actions_nonempty"),
        Index("ix_share_grants_resource", "organization_id", "resource_type", "resource_id"),
        Index("ix_share_grants_creator", "organization_id", "created_by"),
        Index(
            "ix_share_grants_active_expiry",
            "organization_id",
            "expires_at",
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )


class ShareRecipient(Base):
    __tablename__ = "share_recipients"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    share_grant_id: Mapped[uuid.UUID] = mapped_column()
    recipient_type: Mapped[str] = mapped_column(String(16))
    recipient_id: Mapped[uuid.UUID] = mapped_column()
    # Per-principal permissions; null means "the share's default actions".
    actions: Mapped[list[str] | None] = mapped_column(ARRAY(String(32)))
    created_by: Mapped[uuid.UUID | None] = mapped_column()
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["share_grant_id", "organization_id"],
            ["dms.share_grants.id", "dms.share_grants.organization_id"],
            ondelete="CASCADE",
            name="fk_share_recipients_grant_org",
        ),
        CheckConstraint(
            check_in("recipient_type", values(RecipientType), "recipient_type"),
            name="recipient_type",
        ),
        UniqueConstraint(
            "share_grant_id", "recipient_type", "recipient_id", name="uq_share_recipients_unique"
        ),
        Index("ix_share_recipients_lookup", "organization_id", "recipient_type", "recipient_id"),
    )
