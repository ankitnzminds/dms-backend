"""Total Upload Quota of a shared folder, enforced server-side for uploads that come in through it.

Applies to people who are *recipients* of a share with a quota on the folder (or one of its
ancestors) and are not administrators. Checked when the upload starts and charged (under a row
lock, re-checked) when it finalizes, so concurrent uploads cannot both slip under the limit.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError
from app.db.enums import RecipientType, ResourceType
from app.db.models import Folder, ShareGrant, ShareRecipient
from app.modules.identity.principal import Principal


def _chain(db: Session, org: uuid.UUID, folder_id: uuid.UUID) -> list[uuid.UUID]:
    out: list[uuid.UUID] = []
    cur: uuid.UUID | None = folder_id
    for _ in range(100):
        if cur is None:
            break
        out.append(cur)
        cur = db.scalar(
            select(Folder.parent_folder_id).where(Folder.id == cur, Folder.organization_id == org)
        )
    return out


def applicable(
    db: Session, p: Principal, folder_id: uuid.UUID, *, lock: bool = False
) -> list[ShareGrant]:
    if p.is_admin:
        return []
    chain = _chain(db, p.organization_id, folder_id)
    now = datetime.now(UTC)
    stmt = (
        select(ShareGrant)
        .join(
            ShareRecipient,
            and_(
                ShareRecipient.share_grant_id == ShareGrant.id,
                ShareRecipient.organization_id == ShareGrant.organization_id,
            ),
        )
        .where(
            ShareGrant.organization_id == p.organization_id,
            ShareGrant.resource_type == ResourceType.FOLDER.value,
            ShareGrant.resource_id.in_(chain or [uuid.UUID(int=0)]),
            ShareGrant.revoked_at.is_(None),
            or_(ShareGrant.expires_at.is_(None), ShareGrant.expires_at > now),
            ShareGrant.upload_quota_bytes.is_not(None),
            or_(
                and_(
                    ShareRecipient.recipient_type == RecipientType.USER.value,
                    ShareRecipient.recipient_id == p.user_id,
                ),
                and_(
                    ShareRecipient.recipient_type == RecipientType.GROUP.value,
                    ShareRecipient.recipient_id.in_(list(p.group_ids) or [uuid.UUID(int=0)]),
                ),
                and_(
                    ShareRecipient.recipient_type == RecipientType.ORGANIZATION.value,
                    ShareRecipient.recipient_id == p.organization_id,
                ),
            ),
        )
    )
    if lock:
        stmt = stmt.with_for_update(of=ShareGrant).execution_options(populate_existing=True)
    unique: dict[uuid.UUID, ShareGrant] = {
        s.id: s for s in db.scalars(stmt)
    }  # FOR UPDATE cannot use DISTINCT
    return list(unique.values())


def check(db: Session, p: Principal, folder_id: uuid.UUID, size: int) -> None:
    for s in applicable(db, p, folder_id):
        if s.upload_used_bytes + size > (s.upload_quota_bytes or 0):
            raise ConflictError(
                "This share's upload quota would be exceeded.", code="share_quota_exceeded"
            )


def charge(db: Session, p: Principal, folder_id: uuid.UUID, size: int) -> None:
    shares = applicable(db, p, folder_id, lock=True)
    for s in shares:
        if s.upload_used_bytes + size > (s.upload_quota_bytes or 0):
            raise ConflictError(
                "This share's upload quota would be exceeded.", code="share_quota_exceeded"
            )
    for s in shares:
        s.upload_used_bytes += size
