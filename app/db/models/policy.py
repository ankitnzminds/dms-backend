"""Administrator policies: one versioned settings document per scope (organization / group / user)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk
from app.db.enums import PolicyScope, values


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    scope_type: Mapped[str] = mapped_column(String(16))
    # null for the organization default; the group id / user id otherwise
    scope_id: Mapped[uuid.UUID | None] = mapped_column()
    # Only the keys an administrator explicitly overrode at this scope (validated server-side).
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = created_at_col()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            check_in("scope_type", values(PolicyScope), "scope_type"), name="scope_type"
        ),
        CheckConstraint(
            "(scope_type = 'organization') = (scope_id IS NULL)", name="scope_id_matches_type"
        ),
        Index(
            "uq_policies_scope",
            "organization_id",
            "scope_type",
            func.coalesce(scope_id, text("'00000000-0000-0000-0000-000000000000'::uuid")),
            unique=True,
        ),
    )
