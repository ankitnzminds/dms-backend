"""File-manager operations: bulk move/copy/delete with per-item results, recursive folder copy,
Quick Access favorites, properties and small per-user preferences.

Every item is authorized and executed independently (own transaction), so one denied or
conflicting item never blocks or half-applies the others, and the caller gets an accurate
per-item report. Nothing here trusts the client's idea of what is allowed.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.adapters.storage.base import StorageError, new_object_key
from app.adapters.storage.registry import get_storage_provider
from app.core.errors import (
    AppError,
    ConflictError,
    DependencyUnavailableError,
    ForbiddenError,
    NotFoundError,
    ValidationFailed,
)
from app.core.naming import validate_name
from app.db.enums import Action, DocumentStatus, ScanStatus
from app.db.models import (
    Document,
    DocumentStar,
    DocumentVersion,
    Folder,
    FolderFavorite,
    Organization,
    PermissionGrant,
    ShareGrant,
    StorageLocation,
    UserPreference,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.documents import locks as documents_locks
from app.modules.documents import service as documents
from app.modules.folders import service as folders
from app.modules.folders.common import ensure_name_free, name_taken, plain_path, subtree_folder_ids
from app.modules.governance.service import protection_summary
from app.modules.identity.principal import Principal
from app.modules.items.common import lock_out, user_refs
from app.modules.outbox import service as outbox
from app.modules.quota import service as quota
from app.schemas.items import (
    BulkItemResult,
    BulkResult,
    FolderCopyOut,
    ItemProperties,
    ItemRef,
    ProtectionInfo,
)
from app.schemas.tree import TreeItem

MAX_COPY_FOLDERS = 500
MAX_COPY_DOCUMENTS = 200
MAX_PREFERENCE_BYTES = 16_000
_PREF_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_SUFFIX = re.compile(r"^(.*?)(\.[A-Za-z0-9]{1,10})?$")


def unique_name(db: Session, org_id: uuid.UUID, folder_id: uuid.UUID, name: str) -> str:
    """'report.pdf' -> 'report (2).pdf', keeping the extension."""
    m = _SUFFIX.match(name)
    stem, ext = (m.group(1), m.group(2) or "") if m else (name, "")
    for n in range(2, 1000):
        candidate = f"{stem} ({n}){ext}"
        if not name_taken(db, org_id, folder_id, candidate):
            return candidate[:255]
    raise ConflictError("Could not find a free name.", code="name_conflict")


# --------------------------------------------------------------------- bulk
def _result(item: ItemRef, status: str, **kw: Any) -> BulkItemResult:
    return BulkItemResult(kind=item.kind, id=item.id, status=status, **kw)  # type: ignore[arg-type]


def _summarize(results: list[BulkItemResult]) -> BulkResult:
    return BulkResult(
        results=results,
        succeeded=sum(r.status == "ok" for r in results),
        failed=sum(r.status == "error" for r in results),
        skipped=sum(r.status == "skipped" for r in results),
    )


def _current_name(
    db: Session, authz: AuthorizationService, item: ItemRef
) -> tuple[str, uuid.UUID | None]:
    """(name, parent) of an item the caller can see; 404 otherwise (same as everywhere else)."""
    if item.kind == "document":
        doc = authz.require_document(item.id, Action.VIEW)
        return doc.name, doc.folder_id
    folder = authz.require_folder(item.id, Action.DISCOVER)
    return folder.name, folder.parent_folder_id


def bulk_move(
    db: Session,
    authz: AuthorizationService,
    items: list[ItemRef],
    target_id: uuid.UUID,
    on_conflict: str,
) -> BulkResult:
    target = authz.require_folder(target_id, Action.CREATE_CHILD)  # fails the whole request
    org = authz.principal.organization_id
    results: list[BulkItemResult] = []
    for item in items:
        try:
            name, parent = _current_name(db, authz, item)
            if parent == target.id:
                results.append(
                    _result(
                        item, "skipped", code="already_there", message="Already in this folder."
                    )
                )
                continue
            new_name: str | None = None
            if name_taken(db, org, target.id, name):
                if on_conflict == "skip":
                    results.append(
                        _result(
                            item,
                            "skipped",
                            code="name_conflict",
                            message="An item with this name exists.",
                        )
                    )
                    continue
                if on_conflict == "fail":
                    raise ConflictError(
                        "An item with this name already exists in the destination.",
                        code="name_conflict",
                    )
                new_name = unique_name(db, org, target.id, name)
            if item.kind == "document":
                documents.update_document(
                    db,
                    authz,
                    item.id,
                    name=new_name,
                    folder_id=target.id,
                    metadata=None,
                    classification=None,
                    expected_row_version=None,
                )
            else:
                folders.update_folder(
                    db,
                    authz,
                    item.id,
                    name=new_name,
                    parent_folder_id=target.id,
                    expected_row_version=None,
                )
            results.append(_result(item, "ok", new_name=new_name))
        except AppError as exc:
            db.rollback()
            results.append(_result(item, "error", code=exc.code, message=exc.message))
    return _summarize(results)


def bulk_copy(
    db: Session,
    authz: AuthorizationService,
    items: list[ItemRef],
    target_id: uuid.UUID,
    on_conflict: str,
) -> BulkResult:
    target = authz.require_folder(target_id, Action.CREATE_CHILD)
    org = authz.principal.organization_id
    results: list[BulkItemResult] = []
    for item in items:
        try:
            name, _ = _current_name(db, authz, item)
            new_name = name
            if name_taken(db, org, target.id, name):
                if on_conflict == "skip":
                    results.append(
                        _result(
                            item,
                            "skipped",
                            code="name_conflict",
                            message="An item with this name exists.",
                        )
                    )
                    continue
                if on_conflict == "fail":
                    raise ConflictError(
                        "An item with this name already exists in the destination.",
                        code="name_conflict",
                    )
                new_name = unique_name(db, org, target.id, name)
            if item.kind == "document":
                out = documents.copy_document(
                    db, authz, item.id, target.id, new_name if new_name != name else None
                )
                results.append(_result(item, "ok", new_id=out.id, new_name=out.name))
            else:
                res = copy_folder(
                    db, authz, item.id, target.id, new_name if new_name != name else None
                )
                results.append(_result(item, "ok", new_id=res.folder_id, new_name=res.name))
        except AppError as exc:
            db.rollback()
            results.append(_result(item, "error", code=exc.code, message=exc.message))
    return _summarize(results)


def bulk_delete(db: Session, authz: AuthorizationService, items: list[ItemRef]) -> BulkResult:
    results: list[BulkItemResult] = []
    for item in items:
        try:
            if item.kind == "document":
                documents.delete_document(db, authz, item.id)
            else:
                folders.delete_folder(db, authz, item.id)
            results.append(_result(item, "ok"))
        except AppError as exc:
            db.rollback()
            results.append(_result(item, "error", code=exc.code, message=exc.message))
    return _summarize(results)


# -------------------------------------------------------------- folder copy
def copy_folder(
    db: Session,
    authz: AuthorizationService,
    folder_id: uuid.UUID,
    target_id: uuid.UUID,
    name: str | None,
) -> FolderCopyOut:
    """Recursively copy a folder as NEW logical items (new ids, new objects).

    Copied: structure, document content of the current clean version, classification and
    metadata. NOT copied: version history, shares, ACL entries, stars, locks (the copier becomes
    the owner). Only what the caller may see AND copy is included; the report says how much was
    left out. Bounded (<= 500 folders / 200 documents) so it stays a safe synchronous request."""
    p = authz.principal
    src = authz.require_folder(folder_id, Action.COPY)
    if src.parent_folder_id is None:
        raise ForbiddenError("The root folder cannot be copied.")
    target = authz.require_folder(target_id, Action.CREATE_CHILD)
    subtree = subtree_folder_ids(db, p.organization_id, src.id)
    if target.id in set(subtree):
        raise ValidationFailed("A folder cannot be copied into itself or one of its subfolders.")
    new_name = validate_name(name, what="Folder name") if name else src.name
    ensure_name_free(db, p.organization_id, target.id, new_name)

    all_folders = list(
        db.scalars(
            select(Folder).where(
                Folder.id.in_(subtree),
                Folder.organization_id == p.organization_id,
                Folder.deleted_at.is_(None),
            )
        )
    )
    all_docs = list(
        db.scalars(
            select(Document).where(
                Document.folder_id.in_(subtree),
                Document.organization_id == p.organization_id,
                Document.deleted_at.is_(None),
            )
        )
    )
    fperm = authz.folder_actions([f.id for f in all_folders])
    dperm = authz.document_actions(all_docs)
    visible_folders = {f.id: f for f in all_folders if Action.DISCOVER.value in fperm.get(f.id, ())}
    if src.id not in visible_folders:
        raise NotFoundError("Folder not found.")
    # a folder is only copied together with its (visible) ancestors inside the subtree
    copy_folders = {
        fid: f
        for fid, f in visible_folders.items()
        if fid == src.id or f.parent_folder_id in visible_folders
    }
    copyable = [
        d
        for d in all_docs
        if d.folder_id in copy_folders and Action.COPY.value in dperm.get(d.id, ())
    ]
    available = [
        d for d in copyable if d.status == DocumentStatus.AVAILABLE.value and d.current_version_id
    ]
    skipped_permission = (len(all_folders) - len(copy_folders)) + (len(all_docs) - len(copyable))
    if len(copy_folders) > MAX_COPY_FOLDERS or len(available) > MAX_COPY_DOCUMENTS:
        raise ValidationFailed(
            f"This folder is too large to copy in one step (limit {MAX_COPY_FOLDERS} folders / {MAX_COPY_DOCUMENTS} documents).",
            code="too_large_for_copy",
        )

    versions = {
        v.id: v
        for v in db.scalars(
            select(DocumentVersion).where(
                DocumentVersion.id.in_(
                    [d.current_version_id for d in available] or [uuid.UUID(int=0)]
                ),
                DocumentVersion.organization_id == p.organization_id,
            )
        )
    }
    total_bytes = sum(v.size_bytes for v in versions.values())
    org = db.get(Organization, p.organization_id)
    assert org is not None
    if (
        org.quota_bytes is not None
        and org.quota_used_bytes + org.quota_reserved_bytes + total_bytes > org.quota_bytes
    ):
        from app.core.errors import QuotaExceededError

        raise QuotaExceededError("Not enough storage quota to copy this folder.")

    # ---- objects first (external calls, no DB locks); compensate on any failure
    copied: list[tuple[str, str, str]] = []  # (provider_type, bucket, new_key)
    plan: list[tuple[Document, DocumentVersion, StorageLocation, str]] = []
    try:
        for d in available:
            v = versions[d.current_version_id]  # type: ignore[index]
            loc = db.get(StorageLocation, v.storage_location_id)
            assert loc is not None and loc.organization_id == p.organization_id
            key = new_object_key(p.organization_id)
            get_storage_provider(loc.provider_type).copy_object(loc.bucket, v.object_key, key)
            copied.append((loc.provider_type, loc.bucket, key))
            plan.append((d, v, loc, key))
    except StorageError as exc:
        _discard(copied)
        raise DependencyUnavailableError("Storage is unavailable. Please retry.") from exc

    try:
        # parents before children
        depth: dict[uuid.UUID, int] = {}
        for fid, f in copy_folders.items():
            d_, cur = 0, f
            while cur.id != src.id and cur.parent_folder_id in copy_folders:
                cur = copy_folders[cur.parent_folder_id]  # type: ignore[index]
                d_ += 1
            depth[fid] = d_
        mapping: dict[uuid.UUID, uuid.UUID] = {}
        for fid in sorted(copy_folders, key=lambda x: depth[x]):
            f = copy_folders[fid]
            nf = Folder(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                parent_folder_id=target.id if fid == src.id else mapping[f.parent_folder_id],  # type: ignore[index]
                name=new_name if fid == src.id else f.name,
                created_by=p.user_id,
                updated_by=p.user_id,
            )
            db.add(nf)
            db.flush()
            mapping[fid] = nf.id
        for d, v, loc, key in plan:
            nd = Document(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                folder_id=mapping[d.folder_id],
                name=d.name,
                owner_id=p.user_id,
                updated_by=p.user_id,
                status=DocumentStatus.PROCESSING.value,
                classification=d.classification,
                custom_metadata=dict(d.custom_metadata or {}),
                latest_version_number=1,
            )
            db.add(nd)
            db.flush()
            nv = DocumentVersion(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                document_id=nd.id,
                version_number=1,
                storage_location_id=loc.id,
                object_key=key,
                size_bytes=v.size_bytes,
                sha256=v.sha256,
                content_type=v.content_type,
                original_filename=v.original_filename,
                created_by=p.user_id,
                scan_status=ScanStatus.PENDING.value,
            )
            db.add(nv)
            db.flush()
            quota.charge_direct(
                db,
                organization_id=p.organization_id,
                reference_id=nv.id,
                size_bytes=nv.size_bytes,
                document_version_id=nv.id,
            )
            outbox.enqueue(
                db,
                organization_id=p.organization_id,
                event_type="document_version.uploaded",
                aggregate_type="document_version",
                aggregate_id=nv.id,
                payload={"document_id": str(nd.id), "version_number": 1},
            )
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="folder.copied",
            resource_type="folder",
            resource_id=mapping[src.id],
            metadata={
                "source_folder_id": str(src.id),
                "folders": len(mapping),
                "documents": len(plan),
                "skipped_not_permitted": skipped_permission,
                "path": f"{plain_path(db, p.organization_id, target.id)}/{new_name}",
            },
        )
        db.commit()
    except Exception:
        db.rollback()
        _discard(copied)
        raise
    return FolderCopyOut(
        folder_id=mapping[src.id],
        name=new_name,
        folders_copied=len(mapping),
        documents_copied=len(plan),
        skipped_not_permitted=skipped_permission,
        skipped_not_available=len(copyable) - len(available),
    )


def _discard(copied: list[tuple[str, str, str]]) -> None:
    for provider_type, bucket, key in copied:
        try:
            get_storage_provider(provider_type).delete_object(bucket, key)
        except StorageError:
            pass


# ---------------------------------------------------------------- favorites
def set_folder_favorite(
    db: Session, authz: AuthorizationService, folder_id: uuid.UUID, on: bool
) -> None:
    p = authz.principal
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    if on:
        db.execute(
            pg_insert(FolderFavorite)
            .values(user_id=p.user_id, folder_id=folder.id, organization_id=p.organization_id)
            .on_conflict_do_nothing()
        )
    else:
        db.query(FolderFavorite).filter_by(user_id=p.user_id, folder_id=folder.id).delete()
    db.commit()


def list_favorites(
    db: Session, authz: AuthorizationService, limit: int, offset: int
) -> tuple[list[TreeItem], int]:
    """Quick Access: pinned folders + starred documents, re-authorized on every read."""
    p = authz.principal
    fav_folders = list(
        db.scalars(
            select(Folder)
            .join(FolderFavorite, FolderFavorite.folder_id == Folder.id)
            .where(
                FolderFavorite.user_id == p.user_id,
                Folder.organization_id == p.organization_id,
                Folder.deleted_at.is_(None),
            )
            .order_by(FolderFavorite.created_at.desc())
        )
    )
    perms = authz.folder_actions([f.id for f in fav_folders])
    refs = user_refs(db, [f.updated_by for f in fav_folders])
    items = [
        TreeItem(
            kind="folder",
            id=f.id,
            name=f.name,
            updated_at=f.updated_at,
            permissions=sorted(perms[f.id]),  # type: ignore[arg-type]
            is_team_folder=f.is_team_folder,
            starred=True,
            color_tag=f.color_tag,
            updated_by=refs.get(f.updated_by) if f.updated_by else None,
        )
        for f in fav_folders
        if Action.DISCOVER.value in perms.get(f.id, ())
    ]
    doc_items, _ = documents.list_starred(db, authz, 200, 0)
    items.extend(doc_items)
    return items[offset : offset + limit], len(items)


# --------------------------------------------------------------- properties
def properties(
    db: Session, authz: AuthorizationService, kind: str, resource_id: uuid.UUID
) -> ItemProperties:
    p = authz.principal
    prot = protection_summary(db, authz, kind, resource_id)
    protection = ProtectionInfo(
        legal_hold=bool(prot["legal_hold"]), retention_until=prot["retention_until"]
    )
    mask = folders.mask_policy(db, authz)
    if kind == "document":
        doc = authz.require_document(resource_id, Action.VIEW)
        perms = authz.document_actions([doc])[doc.id]
        refs = user_refs(db, [doc.owner_id, doc.updated_by, doc.locked_by])
        v = db.get(DocumentVersion, doc.current_version_id) if doc.current_version_id else None
        version_count = db.scalar(select(func.count()).where(DocumentVersion.document_id == doc.id))
        manage = Action.MANAGE_ACCESS.value in perms or Action.SHARE.value in perms
        shares = acl = None
        if manage:
            now = datetime.now(UTC)
            shares = int(
                db.scalar(
                    select(func.count()).where(
                        ShareGrant.organization_id == p.organization_id,
                        ShareGrant.resource_type == "document",
                        ShareGrant.resource_id == doc.id,
                        ShareGrant.revoked_at.is_(None),
                        (ShareGrant.expires_at.is_(None)) | (ShareGrant.expires_at > now),
                    )
                )
                or 0
            )
            acl = int(
                db.scalar(
                    select(func.count()).where(
                        PermissionGrant.organization_id == p.organization_id,
                        PermissionGrant.resource_type == "document",
                        PermissionGrant.resource_id == doc.id,
                        PermissionGrant.revoked_at.is_(None),
                    )
                )
                or 0
            )
        starred = bool(
            db.execute(
                select(func.count())
                .select_from(DocumentStar)
                .where(DocumentStar.user_id == p.user_id, DocumentStar.document_id == doc.id)
            ).scalar()
        )
        return ItemProperties(
            kind="document",
            id=doc.id,
            name=doc.name,
            type=v.content_type if v else None,
            size_bytes=v.size_bytes if v else None,
            created_at=doc.created_at,
            created_by=refs.get(doc.owner_id) if doc.owner_id else None,
            updated_at=doc.updated_at,
            updated_by=refs.get(doc.updated_by) if doc.updated_by else None,
            location=folders.to_breadcrumb_out(
                authz.breadcrumb_for_folder(doc.folder_id, mask_unauthorized=mask)
            ),
            classification=doc.classification,
            status=doc.status,
            metadata=doc.custom_metadata or {},
            version_count=int(version_count or 0),
            current_version_number=v.version_number if v else None,
            protection=protection,
            lock=lock_out(doc, p.user_id, refs),
            starred=starred,
            your_permissions=sorted(perms),
            active_shares=shares,
            acl_entries=acl,  # type: ignore[arg-type]
        )
    folder = authz.require_folder(resource_id, Action.DISCOVER)
    perms = authz.folder_actions([folder.id])[folder.id]
    refs = user_refs(db, [folder.created_by, folder.updated_by])
    subtree = subtree_folder_ids(db, p.organization_id, folder.id)
    kids = list(
        db.scalars(
            select(Folder)
            .where(
                Folder.id.in_(subtree),
                Folder.id != folder.id,
                Folder.organization_id == p.organization_id,
                Folder.deleted_at.is_(None),
            )
            .limit(5001)
        )
    )
    docs = list(
        db.scalars(
            select(Document)
            .where(
                Document.folder_id.in_(subtree),
                Document.organization_id == p.organization_id,
                Document.deleted_at.is_(None),
            )
            .limit(5001)
        )
    )
    truncated = len(kids) > 5000 or len(docs) > 5000
    kids, docs = kids[:5000], docs[:5000]
    kperm = authz.folder_actions([k.id for k in kids])
    dperm = authz.document_actions(docs)
    seen_docs = [d for d in docs if Action.DISCOVER.value in dperm.get(d.id, ())]
    sizes = dict(
        db.execute(
            select(DocumentVersion.id, DocumentVersion.size_bytes).where(
                DocumentVersion.id.in_(
                    [d.current_version_id for d in seen_docs if d.current_version_id]
                    or [uuid.UUID(int=0)]
                )
            )
        ).all()
    )
    manage = Action.MANAGE_ACCESS.value in perms or Action.SHARE.value in perms
    shares = acl = None
    if manage:
        now = datetime.now(UTC)
        shares = int(
            db.scalar(
                select(func.count()).where(
                    ShareGrant.organization_id == p.organization_id,
                    ShareGrant.resource_type == "folder",
                    ShareGrant.resource_id == folder.id,
                    ShareGrant.revoked_at.is_(None),
                    (ShareGrant.expires_at.is_(None)) | (ShareGrant.expires_at > now),
                )
            )
            or 0
        )
        acl = int(
            db.scalar(
                select(func.count()).where(
                    PermissionGrant.organization_id == p.organization_id,
                    PermissionGrant.resource_type == "folder",
                    PermissionGrant.resource_id == folder.id,
                    PermissionGrant.revoked_at.is_(None),
                )
            )
            or 0
        )
    return ItemProperties(
        kind="folder",
        id=folder.id,
        name=folder.name,
        created_at=folder.created_at,
        created_by=refs.get(folder.created_by) if folder.created_by else None,
        updated_at=folder.updated_at,
        updated_by=refs.get(folder.updated_by) if folder.updated_by else None,
        location=folders.to_breadcrumb_out(
            authz.breadcrumb_for_folder(folder.parent_folder_id, mask_unauthorized=mask)
            if folder.parent_folder_id
            else []
        ),
        protection=protection,
        your_permissions=sorted(perms),  # type: ignore[arg-type]
        active_shares=shares,
        acl_entries=acl,
        visible_folders=sum(1 for k in kids if Action.DISCOVER.value in kperm.get(k.id, ())),
        visible_documents=len(seen_docs),
        visible_size_bytes=sum(
            sizes.get(d.current_version_id, 0) for d in seen_docs if d.current_version_id
        ),
        truncated=truncated,
    )


# -------------------------------------------------------------- preferences
def get_preference(db: Session, p: Principal, key: str) -> dict[str, Any]:
    _check_key(key)
    row = db.get(UserPreference, (p.user_id, p.organization_id, key))
    return dict(row.value) if row else {}


def set_preference(db: Session, p: Principal, key: str, value: dict[str, Any]) -> dict[str, Any]:
    _check_key(key)
    if len(str(value)) > MAX_PREFERENCE_BYTES:
        raise ValidationFailed("Preference value is too large.")
    stmt = pg_insert(UserPreference).values(
        user_id=p.user_id, organization_id=p.organization_id, key=key, value=value
    )
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=["user_id", "organization_id", "key"],
            set_={"value": stmt.excluded.value, "updated_at": func.now()},
        )
    )
    db.commit()
    return value


def _check_key(key: str) -> None:
    if not _PREF_KEY.match(key):
        raise ValidationFailed("Invalid preference key.")


# ------------------------------------------------------------------ color tags
def set_color_tag(
    db: Session, authz: AuthorizationService, kind: str, resource_id: uuid.UUID, color: str | None
) -> None:
    """A searchable, filterable label. Needs the same right as editing the item's details."""
    p = authz.principal
    if kind == "document":
        doc = authz.require_document(resource_id, Action.EDIT_METADATA)
        documents_locks.assert_unlocked_for(db, doc, p)
        target: Any = doc
    else:
        target = authz.require_folder(resource_id, Action.RENAME)
    if target.color_tag == color:
        return
    previous = target.color_tag
    target.color_tag = color
    target.row_version += 1
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=f"{kind}.color_tagged",
        resource_type=kind,
        resource_id=target.id,
        metadata={"from": previous, "to": color},
    )
    db.commit()
