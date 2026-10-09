"""Anonymous access through an open share link (opt-in per organization, read-only).

Off unless the organization sets ``allow_public_links`` AND the share is unrestricted, enabled,
unexpired and not revoked. What an anonymous holder can do is limited to what the share carries:
list the shared folder tree (view) and download files (download). Never upload, change or delete.
Every call re-reads the share, so removing the share, disabling the link, rotating the token or an
expiry takes effect on the next request.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.db.enums import Action, DocumentStatus, ResourceType
from app.db.models import Document, DocumentVersion, Folder, ShareGrant, StorageLocation
from app.modules.audit import service as audit
from app.modules.documents.downloads import Servable, _servable_version
from app.modules.organizations.service import get_org, org_settings
from app.modules.sharing import manage


def _live_open_share(db: Session, token: str) -> ShareGrant:
    share = manage._share_by_token(db, token)
    if share is None or not manage.link_is_live(share) or share.restricted:
        raise NotFoundError("This link is not valid.")
    if not org_settings(get_org(db, share.organization_id))["allow_public_links"]:
        raise NotFoundError("This link is not valid.")
    return share


def _carries(share: ShareGrant, action: Action) -> bool:
    return action.value in set(share.actions) or action.value == Action.VIEW.value


def _in_subtree(db: Session, share: ShareGrant, folder_id: uuid.UUID) -> bool:
    cur: uuid.UUID | None = folder_id
    for _ in range(100):
        if cur is None:
            return False
        if cur == share.resource_id:
            return True
        f = db.scalar(
            select(Folder).where(Folder.id == cur, Folder.organization_id == share.organization_id)
        )
        if f is None or f.deleted_at is not None:
            return False
        cur = f.parent_folder_id
    return False


def describe(db: Session, token: str) -> dict[str, Any]:
    share = _live_open_share(db, token)
    audit.record(
        db,
        organization_id=share.organization_id,
        actor_user_id=None,
        action="share.link_opened",
        resource_type=share.resource_type,
        resource_id=share.resource_id,
        metadata={"share_id": str(share.id), "anonymous": True},
    )
    db.commit()
    if share.resource_type == ResourceType.DOCUMENT.value:
        d = db.get(Document, share.resource_id)
        if d is None or d.deleted_at is not None:
            raise NotFoundError("This link is not valid.")
        v = db.get(DocumentVersion, d.current_version_id) if d.current_version_id else None
        return {
            "resource_type": "document",
            "id": str(d.id),
            "name": share.name or d.name,
            "size_bytes": v.size_bytes if v else None,
            "content_type": v.content_type if v else None,
            "can_download": _carries(share, Action.DOWNLOAD),
        }
    f = db.get(Folder, share.resource_id)
    if f is None or f.deleted_at is not None:
        raise NotFoundError("This link is not valid.")
    return {
        "resource_type": "folder",
        "id": str(f.id),
        "name": share.name or f.name,
        "can_download": _carries(share, Action.DOWNLOAD),
    }


def children(db: Session, token: str, folder_id: uuid.UUID | None) -> list[dict[str, Any]]:
    share = _live_open_share(db, token)
    if share.resource_type != ResourceType.FOLDER.value:
        raise NotFoundError("This link is not valid.")
    target = folder_id or share.resource_id
    if not _in_subtree(db, share, target):
        raise NotFoundError("Not found.")
    out: list[dict[str, Any]] = []
    for f in db.scalars(
        select(Folder)
        .where(
            Folder.organization_id == share.organization_id,
            Folder.parent_folder_id == target,
            Folder.deleted_at.is_(None),
        )
        .order_by(Folder.name)
    ):
        out.append({"kind": "folder", "id": str(f.id), "name": f.name})
    for d in db.scalars(
        select(Document)
        .where(
            Document.organization_id == share.organization_id,
            Document.folder_id == target,
            Document.deleted_at.is_(None),
            Document.status == DocumentStatus.AVAILABLE.value,
        )
        .order_by(Document.name)
    ):
        v = db.get(DocumentVersion, d.current_version_id) if d.current_version_id else None
        out.append(
            {
                "kind": "document",
                "id": str(d.id),
                "name": d.name,
                "size_bytes": v.size_bytes if v else None,
                "content_type": v.content_type if v else None,
            }
        )
    return out


def servable_for(db: Session, token: str, document_id: uuid.UUID) -> Servable:
    share = _live_open_share(db, token)
    if not _carries(share, Action.DOWNLOAD):
        raise NotFoundError("Not found.")
    doc = db.scalar(
        select(Document).where(
            Document.id == document_id,
            Document.organization_id == share.organization_id,
            Document.deleted_at.is_(None),
        )
    )
    if doc is None:
        raise NotFoundError("Not found.")
    inside = (
        doc.id == share.resource_id
        if share.resource_type == ResourceType.DOCUMENT.value
        else _in_subtree(db, share, doc.folder_id)
    )
    if not inside:
        raise NotFoundError("Not found.")
    version = _servable_version(db, doc.organization_id, doc, None)  # scan gate + quarantine
    location = db.get(StorageLocation, version.storage_location_id)
    if location is None:
        raise NotFoundError("Not found.")
    audit.record(
        db,
        organization_id=share.organization_id,
        actor_user_id=None,
        action="share.public_downloaded",
        resource_type="document",
        resource_id=doc.id,
        metadata={
            "share_id": str(share.id),
            "anonymous": True,
            "version_number": version.version_number,
        },
    )
    db.commit()
    return Servable(
        location=location,
        object_key=version.object_key,
        size=version.size_bytes,
        content_type=version.content_type,
        disposition="attachment",
        filename=doc.name,
    )
