"""Cached, format-aware comparisons between two immutable versions of a document."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, ForeignKeyConstraint, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, check_in, created_at_col, uuid_pk

DIFF_STATUSES = ["ready", "failed", "too_large", "unsupported"]


class VersionDiff(Base):
    """Versions are immutable, so a (from, to, parser) result never goes stale; a new parser
    version simply produces a new row."""

    __tablename__ = "version_diffs"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    document_id: Mapped[uuid.UUID] = mapped_column()
    from_version_id: Mapped[uuid.UUID] = mapped_column()
    to_version_id: Mapped[uuid.UUID] = mapped_column()
    parser_version: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(String(300))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="CASCADE",
            name="fk_version_diffs_document_org",
        ),
        ForeignKeyConstraint(
            ["from_version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="CASCADE",
            name="fk_version_diffs_from_org",
        ),
        ForeignKeyConstraint(
            ["to_version_id", "organization_id"],
            ["dms.document_versions.id", "dms.document_versions.organization_id"],
            ondelete="CASCADE",
            name="fk_version_diffs_to_org",
        ),
        UniqueConstraint(
            "from_version_id", "to_version_id", "parser_version", name="uq_version_diffs_pair"
        ),
        CheckConstraint(check_in("status", DIFF_STATUSES, "status"), name="status"),
    )
