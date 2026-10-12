"""Administrators' Recycle Bin: everything deleted in the organization, restore and permanent deletion.

A deleted item stays recoverable until an administrator permanently deletes it, even when its user chose
"delete permanently" (see ``governance.purge``). Every request re-checks that the caller is an administrator
of the organization; all reads and writes are scoped to that organization. Restore reuses the normal
restore services (audit, name checks), and permanent deletion reuses the governance purge (legal holds,
retention, append-only audit, object deletion through the outbox worker).
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import AppError, ConflictError, ForbiddenError, NotFoundError
from app.db.enums import Action
from app.db.models import Document, DocumentVersion, Folder, User
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.documents import service as documents
from app.modules.folders import service as folders
from app.modules.folders.common import plain_path, subtree_folder_ids
from app.modules.governance import service as gov
from app.schemas.recycle import (
    ProtectionBrief,
    PurgeIn,
    RecycleBulkOut,
    RecycleBulkResult,
    RecycleDetail,
    RecycleItem,
    RecycleRef,
    RestoreIn,
    UserBrief,
)

Kind = Literal["document", "folder"]


def _require_admin(authz: AuthorizationService) -> None:
    if not authz.principal.is_admin:
        raise ForbiddenError("Only organization administrators can use the Recycle Bin.")


def _brief(users: dict[uuid.UUID, User], uid: uuid.UUID | None) -> UserBrief | None:
    u = users.get(uid) if uid else None
    return UserBrief(id=u.id, email=u.email, display_name=u.display_name) if u else None


def _roots(
    db: Session, org_id: uuid.UUID
) -> tuple[list[Folder], list[Document], dict[uuid.UUID, Folder]]:
    """Deleted batch roots: items whose parent was not deleted in the same operation."""
    fl = list(
        db.scalars(
            select(Folder).where(Folder.organization_id == org_id, Folder.deleted_at.is_not(None))
        )
    )
    dl = list(
        db.scalars(
            select(Document).where(
                Document.organization_id == org_id, Document.deleted_at.is_not(None)
            )
        )
    )
    batch = {f.id: f.delete_batch_id for f in fl}
    root_f = [
        f
        for f in fl
        if f.parent_folder_id is None or batch.get(f.parent_folder_id) != f.delete_batch_id
    ]
    root_d = [d for d in dl if batch.get(d.folder_id) != d.delete_batch_id]
    return root_f, root_d, {f.id: f for f in fl}


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def list_items(
    db: Session,
    authz: AuthorizationService,
    *,
    q: str | None,
    deleted_by: uuid.UUID | None,
    date_from: datetime | None,
    date_to: datetime | None,
    file_type: str | None,
    source: str | None,
    limit: int,
    offset: int,
) -> tuple[list[RecycleItem], int]:
    _require_admin(authz)
    org_id = authz.principal.organization_id
    root_f, root_d, _ = _roots(db, org_id)
    needle = (q or "").strip().casefold()
    ftype = (file_type or "").strip().lower().lstrip(".")

    def keep(kind: str, item: Folder | Document) -> bool:
        if needle and needle not in item.name.casefold():
            return False
        if deleted_by and item.deleted_by != deleted_by:
            return False
        at = item.deleted_at
        if at is None or (date_from and at < date_from) or (date_to and at > date_to):
            return False
        if source == "user_permanent" and item.purge_requested_at is None:
            return False
        if source == "trash" and item.purge_requested_at is not None:
            return False
        if ftype == "folder":
            return kind == "folder"
        return not ftype or (kind == "document" and _ext(item.name) == ftype)

    rows: list[tuple[str, Folder | Document]] = [
        *(("folder", f) for f in root_f if keep("folder", f)),
        *(("document", d) for d in root_d if keep("document", d)),
    ]
    rows.sort(key=lambda r: r[1].deleted_at or datetime.min, reverse=True)
    page = rows[offset : offset + limit]
    return [_item(db, org_id, k, it) for k, it in page], len(rows)


def _users(db: Session, ids: set[uuid.UUID | None]) -> dict[uuid.UUID, User]:
    wanted = [i for i in ids if i]
    if not wanted:
        return {}
    return {u.id: u for u in db.scalars(select(User).where(User.id.in_(wanted)))}


def _stats(db: Session, org_id: uuid.UUID, kind: str, item: Folder | Document) -> dict:
    """Size / counts of what would be restored or deleted with this item."""
    if kind == "document":
        assert isinstance(item, Document)
        v = db.get(DocumentVersion, item.current_version_id) if item.current_version_id else None
        count = db.scalar(
            select(func.count())
            .select_from(DocumentVersion)
            .where(
                DocumentVersion.document_id == item.id, DocumentVersion.organization_id == org_id
            )
        )
        return {
            "size": v.size_bytes if v else None,
            "content_type": v.content_type if v else None,
            "documents": 1,
            "folders": 0,
            "versions": int(count or 0),
        }
    ids = subtree_folder_ids(db, org_id, item.id)
    docs = list(
        db.scalars(
            select(Document).where(Document.folder_id.in_(ids), Document.organization_id == org_id)
        )
    )
    size = 0
    for d in docs:
        v = db.get(DocumentVersion, d.current_version_id) if d.current_version_id else None
        size += v.size_bytes if v else 0
    nver = (
        db.scalar(
            select(func.count())
            .select_from(DocumentVersion)
            .where(
                DocumentVersion.document_id.in_([d.id for d in docs]),
                DocumentVersion.organization_id == org_id,
            )
        )
        if docs
        else 0
    )
    return {
        "size": size,
        "content_type": None,
        "documents": len(docs),
        "folders": len(ids),
        "versions": int(nver or 0),
    }


def _item(db: Session, org_id: uuid.UUID, kind: str, item: Folder | Document) -> RecycleItem:
    return RecycleItem(**_item_fields(db, org_id, kind, item)[0])


def _item_fields(
    db: Session, org_id: uuid.UUID, kind: str, item: Folder | Document
) -> tuple[dict, dict]:
    parent_id = item.parent_folder_id if isinstance(item, Folder) else item.folder_id
    parent = db.get(Folder, parent_id) if parent_id else None
    available = (
        parent is not None and parent.organization_id == org_id and parent.deleted_at is None
    )
    path = plain_path(db, org_id, parent_id) if parent_id else ""
    st = _stats(db, org_id, kind, item)
    docs, flds = gov._purge_set(db, org_id, kind, item.id)
    blocked = gov.find_protections(db, org_id, documents=docs, folders=flds, check_retention=True)
    owner_id = item.owner_id if isinstance(item, Document) else item.created_by
    users = _users(db, {item.deleted_by, owner_id, item.purge_requested_by})
    fields = dict(
        kind=kind,
        id=item.id,
        name=item.name,
        content_type=st["content_type"],
        original_path=path,
        deleted_by=_brief(users, item.deleted_by),
        owner=_brief(users, owner_id),
        deleted_at=item.deleted_at,
        size_bytes=st["size"],
        item_count=st["documents"] if kind == "folder" else 0,
        deletion_source="user_permanent" if item.purge_requested_at else "trash",
        permanent_requested_at=item.purge_requested_at,
        recovery_status="protected" if blocked else "recoverable",
        original_location_available=available,
    )
    extra = dict(
        documents=st["documents"],
        folders=st["folders"],
        versions=st["versions"],
        protections=[
            ProtectionBrief(kind=b.resource_type, id=b.resource_id, reason=b.reason)
            for b in blocked
        ],
        permanent_requested_by=_brief(users, item.purge_requested_by),
    )
    return fields, extra


def _load(db: Session, authz: AuthorizationService, kind: str, rid: uuid.UUID) -> Folder | Document:
    """The deleted batch root, scoped to the caller's organization (foreign ids are simply not found)."""
    org_id = authz.principal.organization_id
    item: Folder | Document | None
    if kind == "folder":
        item = db.scalar(select(Folder).where(Folder.id == rid, Folder.organization_id == org_id))
    else:
        item = db.scalar(
            select(Document).where(Document.id == rid, Document.organization_id == org_id)
        )
    if item is None or item.deleted_at is None:
        raise NotFoundError("That item is not in the Recycle Bin.")
    return item


def detail(db: Session, authz: AuthorizationService, kind: Kind, rid: uuid.UUID) -> RecycleDetail:
    _require_admin(authz)
    item = _load(db, authz, kind, rid)
    fields, extra = _item_fields(db, authz.principal.organization_id, kind, item)
    return RecycleDetail(**fields, **extra)


def _restore_one(
    db: Session,
    authz: AuthorizationService,
    kind: str,
    rid: uuid.UUID,
    new_name: str | None,
    target: uuid.UUID | None,
) -> None:
    p = authz.principal
    item = _load(db, authz, kind, rid)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=f"{kind}.restore_requested",
        resource_type=kind,
        resource_id=rid,
        metadata={"name": item.name, "alternative_location": bool(target)},
    )
    db.commit()
    if target is not None:
        dest = authz.require_folder(
            target, Action.CREATE_FOLDER if kind == "folder" else Action.UPLOAD
        )
        if dest.deleted_at is not None:
            raise ConflictError("That destination folder is in the trash.", code="parent_deleted")
        if kind == "folder" and dest.id in subtree_folder_ids(db, p.organization_id, rid):
            raise ConflictError("A folder cannot be restored into itself.", code="invalid_target")
        if isinstance(item, Folder):
            item.parent_folder_id = dest.id
        else:
            item.folder_id = dest.id
        db.flush()
    if kind == "folder":
        folders.restore_folder(db, authz, rid, new_name)
    else:
        documents.restore_document(db, authz, rid, new_name)


def restore(db: Session, authz: AuthorizationService, body: RestoreIn) -> RecycleBulkOut:
    _require_admin(authz)
    results: list[RecycleBulkResult] = []
    for it in body.items:
        try:
            _restore_one(db, authz, it.kind, it.id, it.new_name, it.target_folder_id)
            results.append(RecycleBulkResult(kind=it.kind, id=it.id, ok=True))
        except AppError as e:
            db.rollback()
            results.append(
                RecycleBulkResult(kind=it.kind, id=it.id, ok=False, code=e.code, message=e.message)
            )
    return _bulk(results)


def purge(db: Session, authz: AuthorizationService, body: PurgeIn) -> RecycleBulkOut:
    """Permanently delete. Holds / retention block an item (reported per item); others still proceed."""
    _require_admin(authz)
    results: list[RecycleBulkResult] = []
    for it in body.items:
        try:
            _load(db, authz, it.kind, it.id)
            gov.purge(db, authz, it.kind, it.id)
            results.append(RecycleBulkResult(kind=it.kind, id=it.id, ok=True))
        except AppError as e:
            db.rollback()
            results.append(
                RecycleBulkResult(kind=it.kind, id=it.id, ok=False, code=e.code, message=e.message)
            )
    return _bulk(results)


def _bulk(results: list[RecycleBulkResult]) -> RecycleBulkOut:
    ok = sum(1 for r in results if r.ok)
    return RecycleBulkOut(results=results, succeeded=ok, failed=len(results) - ok)


__all__ = ["RecycleRef", "detail", "list_items", "purge", "restore"]
