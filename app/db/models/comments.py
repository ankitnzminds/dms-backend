"""Comments on documents and folders (threaded one level deep)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk


class Comment(Base):
    __tablename__ = "comments"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    resource_type: Mapped[str] = mapped_column(String(16))
    resource_id: Mapped[uuid.UUID] = mapped_column()
    parent_id: Mapped[uuid.UUID | None] = mapped_column()
    author_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = created_at_col()
    edited_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_comments_id_org"),
        ForeignKeyConstraint(
            ["parent_id", "organization_id"],
            ["dms.comments.id", "dms.comments.organization_id"],
            ondelete="CASCADE",
            name="fk_comments_parent_org",
        ),
        CheckConstraint(
            check_in("resource_type", ["document", "folder"], "resource_type"), name="resource_type"
        ),
        CheckConstraint("char_length(body) BETWEEN 1 AND 4000", name="body_length"),
        Index(
            "ix_comments_resource", "organization_id", "resource_type", "resource_id", "created_at"
        ),
    )
