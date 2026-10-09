"""Office-suite (WOPI) editing locks. Distinct from the user-facing 'check-out' lock on documents:
this one belongs to the editing *session* of the office server and expires on its own."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, ForeignKeyConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, created_at_col


class OfficeLock(Base):
    __tablename__ = "office_locks"

    document_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dms.organizations.id", ondelete="RESTRICT")
    )
    lock_id: Mapped[str] = mapped_column(String(1024))
    locked_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("dms.users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at_col()

    __table_args__ = (
        ForeignKeyConstraint(
            ["document_id", "organization_id"],
            ["dms.documents.id", "dms.documents.organization_id"],
            ondelete="CASCADE",
            name="fk_office_locks_document_org",
        ),
    )
