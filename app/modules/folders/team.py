"""Team Folders: top-level folders an administrator marks as shared team spaces.

Marking a folder changes only where it is listed; access still comes from permissions and shares,
so a team folder is never visible to someone who could not already discover it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError
from app.db.enums import Action, ResourceType
from app.db.models import Folder, ShareGrant
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.schemas.common import ActionName, ApiModel


class TeamFolderOut(ApiModel):
    id: uuid.UUID
    name: str
    created_at: datetime
    updated_at: datetime
    permissions: list[ActionName]
    shared: bool


def list_team_folders(db: Session, authz: AuthorizationService) -> list[TeamFolderOut]:
    p = authz.principal
    folders = list(
        db.scalars(
            select(Folder)
            .where(
                Folder.organization_id == p.organization_id,
                Folder.is_team_folder.is_(True),
                Folder.deleted_at.is_(None),
            )
            .order_by(Folder.name)
        )
    )
    perms = authz.folder_actions([f.id for f in folders])
    now = datetime.now(UTC)
    shared = set(
        db.scalars(
            select(ShareGrant.resource_id).where(
                ShareGrant.organization_id == p.organization_id,
                ShareGrant.resource_type == ResourceType.FOLDER.value,
                ShareGrant.resource_id.in_([f.id for f in folders] or [uuid.UUID(int=0)]),
                ShareGrant.revoked_at.is_(None),
                or_(ShareGrant.expires_at.is_(None), ShareGrant.expires_at > now),
            )
        )
    )
    return [
        TeamFolderOut(
            id=f.id,
            name=f.name,
            created_at=f.created_at,
            updated_at=f.updated_at,
            permissions=sorted(perms[f.id]),  # type: ignore[arg-type]
            shared=f.id in shared,
        )
        for f in folders
        if Action.DISCOVER.value in perms.get(f.id, ())
    ]


def set_team_folder(
    db: Session, authz: AuthorizationService, folder_id: uuid.UUID, enabled: bool
) -> None:
    p = authz.principal
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required.")
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    parent = db.get(Folder, folder.parent_folder_id) if folder.parent_folder_id else None
    if parent is None or parent.parent_folder_id is not None:
        raise ConflictError(
            "Only folders directly under the organization root can be team folders.",
            code="not_top_level",
        )
    if folder.is_team_folder != enabled:
        folder.is_team_folder = enabled
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="folder.team_folder_changed",
            resource_type="folder",
            resource_id=folder.id,
            metadata={"enabled": enabled},
        )
        db.commit()
