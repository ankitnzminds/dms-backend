"""Organizations, users, memberships, groups."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, updated_at_col, uuid_pk
from app.db.enums import (
    AccessLevel,
    CreationSource,
    GroupKind,
    MembershipStatus,
    OrgStatus,
    Role,
    UserStatus,
    values,
)

DEFAULT_QUOTA_BYTES = 5 * 1024**3


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    status: Mapped[str] = mapped_column(String(32), default=OrgStatus.ACTIVE.value)
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger, default=DEFAULT_QUOTA_BYTES)
    quota_used_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    quota_reserved_bytes: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        CheckConstraint(check_in("status", values(OrgStatus), "status"), name="status"),
        CheckConstraint("quota_used_bytes >= 0", name="used_nonneg"),
        CheckConstraint("quota_reserved_bytes >= 0", name="reserved_nonneg"),
        CheckConstraint("quota_bytes IS NULL OR quota_bytes >= 0", name="quota_nonneg"),
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(320))
    display_name: Mapped[str | None] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(32), default=UserStatus.INVITED.value)
    identity_provider: Mapped[str | None] = mapped_column(String(50))
    external_subject: Mapped[str | None] = mapped_column(String(255))
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # Tokens issued before this instant are rejected (session revocation, deprovisioning).
    sessions_valid_after: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # LOCAL DEVELOPMENT sign-in only: scrypt hash of this user's own password (see core/local_password.py).
    # Never set in staging/production, where the identity provider owns passwords.
    local_password_hash: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        CheckConstraint(check_in("status", values(UserStatus), "status"), name="status"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        Index("uq_users_email", "email", unique=True),
        Index(
            "uq_users_identity",
            "identity_provider",
            "external_subject",
            unique=True,
            postgresql_where=text("external_subject IS NOT NULL"),
        ),
        CheckConstraint(
            "(external_subject IS NULL) = (identity_provider IS NULL)", name="identity_pair"
        ),
    )


class Membership(Base):
    __tablename__ = "memberships"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("dms.users.id", ondelete="RESTRICT"))
    role: Mapped[str] = mapped_column(String(32), default=Role.MEMBER.value)
    status: Mapped[str] = mapped_column(String(32), default=MembershipStatus.INVITED.value)
    invited_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    # Administrator-managed profile of the account *within this organization*.
    username: Mapped[str | None] = mapped_column(String(100))
    access_level: Mapped[str] = mapped_column(
        String(16), default=AccessLevel.FULL.value, server_default=AccessLevel.FULL.value
    )
    secondary_email: Mapped[str | None] = mapped_column(String(320))
    phone: Mapped[str | None] = mapped_column(String(32))
    notes: Mapped[str | None] = mapped_column(Text)
    account_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    account_locked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    creation_source: Mapped[str] = mapped_column(
        String(16),
        default=CreationSource.DEFAULT.value,
        server_default=CreationSource.DEFAULT.value,
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_memberships_org_user"),
        Index(
            "uq_memberships_org_username",
            "organization_id",
            func.lower(username),
            unique=True,
            postgresql_where=text("username IS NOT NULL"),
        ),
        CheckConstraint(
            check_in("access_level", values(AccessLevel), "access_level"), name="access_level"
        ),
        CheckConstraint(
            check_in("creation_source", values(CreationSource), "creation_source"),
            name="creation_source",
        ),
        CheckConstraint(check_in("role", values(Role), "role"), name="role"),
        CheckConstraint(check_in("status", values(MembershipStatus), "status"), name="status"),
        Index("ix_memberships_user", "user_id"),
    )


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(32), default=GroupKind.GROUP.value)
    description: Mapped[str | None] = mapped_column(Text)
    # Stable id from an external directory (Entra/LDAP); never map by display name.
    external_id: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = updated_at_col()

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_groups_id_org"),
        CheckConstraint(check_in("kind", values(GroupKind), "kind"), name="kind"),
        Index("uq_groups_org_name", "organization_id", func.lower(name), unique=True),
        Index(
            "uq_groups_org_external",
            "organization_id",
            "external_id",
            unique=True,
            postgresql_where=text("external_id IS NOT NULL"),
        ),
    )


class GroupMembership(Base):
    __tablename__ = "group_memberships"

    group_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.users.id", ondelete="CASCADE"), primary_key=True
    )
    organization_id: Mapped[uuid.UUID] = mapped_column()
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["dms.groups.id", "dms.groups.organization_id"],
            ondelete="CASCADE",
            name="fk_group_memberships_group_org",
        ),
        Index("ix_group_memberships_user_org", "user_id", "organization_id"),
    )
