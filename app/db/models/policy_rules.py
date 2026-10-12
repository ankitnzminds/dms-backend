"""Rule policies (policy engine): named policies with immutable, versioned revisions.

Distinct from ``policies`` (flat per-scope *settings*): these hold typed rules with an effect
(ALLOW / DENY / REQUIRE_APPROVAL), targeting and conditions. See docs/security/policy-engine.md.
"""

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

from app.db.base import Base, created_at_col, uuid_pk

POLICY_STATUSES = ("draft", "published", "disabled", "archived")
REVISION_STATUSES = ("draft", "validated", "published", "superseded")
POLICY_MODES = ("enforce", "observe")
OWNER_KINDS = ("organization", "user")


def _in(col: str, vals: tuple[str, ...]) -> str:
    return f"{col} IN ({', '.join(repr(v) for v in vals)})"


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(40), default="custom", server_default="custom")
    owner_kind: Mapped[str] = mapped_column(
        String(16), default="organization", server_default="organization"
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    # draft: never published | published: enforced via published_revision_id | disabled | archived
    status: Mapped[str] = mapped_column(String(16), default="draft", server_default="draft")
    # enforce: decisions apply | observe: decisions are only recorded (shadow mode)
    mode: Mapped[str] = mapped_column(String(16), default="enforce", server_default="enforce")
    mandatory: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    published_revision_id: Mapped[uuid.UUID | None] = mapped_column()
    template_key: Mapped[str | None] = mapped_column(String(60))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_policy_rules_id_org"),
        CheckConstraint(_in("status", POLICY_STATUSES), name="status"),
        CheckConstraint(_in("mode", POLICY_MODES), name="mode"),
        CheckConstraint(_in("owner_kind", OWNER_KINDS), name="owner_kind"),
        Index("ix_policy_rules_org_status", "organization_id", "status"),
    )


class PolicyRevision(Base):
    """One version of a policy's rule document. Published/superseded revisions are immutable (DB trigger)."""

    __tablename__ = "policy_revisions"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column()
    policy_id: Mapped[uuid.UUID] = mapped_column()
    revision: Mapped[int] = mapped_column(Integer)
    document: Mapped[dict[str, Any]] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(String(16), default="draft", server_default="draft")
    change_reason: Mapped[str | None] = mapped_column(String(500))
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    published_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        ForeignKeyConstraint(
            ["policy_id", "organization_id"],
            ["dms.policy_rules.id", "dms.policy_rules.organization_id"],
            ondelete="RESTRICT",
            name="fk_policy_revisions_policy_org",
        ),
        UniqueConstraint("policy_id", "revision", name="uq_policy_revisions_policy_revision"),
        CheckConstraint(_in("status", REVISION_STATUSES), name="status"),
        Index("ix_policy_revisions_org_policy", "organization_id", "policy_id"),
    )
