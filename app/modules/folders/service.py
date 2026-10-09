"""Canonical folder tree: create, list, rename, move, trash, restore."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.core.naming import validate_name
from app.db.enums import Action
from app.db.models import Document, DocumentVersion, Folder
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService, BreadcrumbSegment
from app.modules.folders.common import ensure_name_free, plain_path, subtree_folder_ids
from app.modules.items.common import document_stars, folder_favorites, lock_active, user_refs
from app.modules.organizations.service import get_org, org_settings
from app.schemas.common import BreadcrumbSegmentOut
from app.schemas.tree import FolderOut, TrashItem, TreeItem

MAX_LIST_CHILDREN = 10_000


def to_breadcrumb_out(segments: list[BreadcrumbSegment]) -> list[BreadcrumbSegmentOut]:
    return [
        BreadcrumbSegmentOut(folder_id=s.folder_id, name=s.name, navigable=s.navigable)
        for s in segments
    ]


def mask_policy(db: Session, authz: AuthorizationService) -> bool:
    org = get_org(db, authz.principal.organization_id)
    return bool(org_settings(org)["mask_shared_breadcrumbs"])


def folder_out(
    db: Session, authz: AuthorizationService, folder: Folder, permissions: frozenset[str]
) -> FolderOut:
    breadcrumb: list[BreadcrumbSegment] = []
    if folder.parent_folder_id is not None:
        breadcrumb = authz.breadcrumb_for_folder(
            folder.parent_folder_id, mask_unauthorized=mask_policy(db, authz)
        )
    refs = user_refs(db, [folder.updated_by])
    return FolderOut(
        id=folder.id,
        name=folder.name,
        parent_folder_id=folder.parent_folder_id,
        is_root=folder.parent_folder_id is None,
        is_team_folder=folder.is_team_folder,
        created_by=folder.created_by,
        created_at=folder.created_at,
        updated_at=folder.updated_at,
        row_version=folder.row_version,
        deleted_at=folder.deleted_at,
        updated_by=refs.get(folder.updated_by) if folder.updated_by else None,
        is_favorite=bool(folder_favorites(db, authz.principal.user_id, [folder.id])),
        permissions=sorted(permissions),
        breadcrumb=to_breadcrumb_out(breadcrumb),
    )


def get_folder(db: Session, authz: AuthorizationService, folder_id: uuid.UUID) -> FolderOut:
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    perms = authz.folder_actions([folder.id])[folder.id]
    return folder_out(db, authz, folder, perms)


def get_root(db: Session, authz: AuthorizationService) -> FolderOut:
    root = db.scalar(
        select(Folder).where(
            Folder.organization_id == authz.principal.organization_id,
            Folder.parent_folder_id.is_(None),
        )
    )
    if root is None:
        raise NotFoundError("Organization has no root folder.")
    # root visibility follows the normal rules (a user with no grants gets 404, not a leak)
    return get_folder(db, authz, root.id)


def list_children(
    db: Session,
    authz: AuthorizationService,
    folder_id: uuid.UUID,
    *,
    limit: int,
    offset: int,
    sort: str,
    descending: bool,
    kind: str | None,
) -> tuple[list[TreeItem], int]:
    """Children the caller may discover. Authorization is applied per child *before* counting or
    slicing, so totals never reveal hidden entries."""
    parent = authz.require_folder(folder_id, Action.DISCOVER)
    org_id = authz.principal.organization_id

    folders: list[Folder] = []
    docs: list[Document] = []
    if kind in (None, "folder"):
        folders = list(
            db.scalars(
                select(Folder)
                .where(
                    Folder.organization_id == org_id,
                    Folder.parent_folder_id == parent.id,
                    Folder.deleted_at.is_(None),
                )
                .limit(MAX_LIST_CHILDREN)
            )
        )
    if kind in (None, "document"):
        docs = list(
            db.scalars(
                select(Document)
                .where(
                    Document.organization_id == org_id,
                    Document.folder_id == parent.id,
                    Document.deleted_at.is_(None),
                )
                .limit(MAX_LIST_CHILDREN)
            )
        )

    folder_perms = authz.folder_actions([f.id for f in folders])
    doc_perms = authz.document_actions(docs)
    visible_folders = [f for f in folders if Action.DISCOVER.value in folder_perms.get(f.id, ())]
    visible_docs = [d for d in docs if Action.DISCOVER.value in doc_perms.get(d.id, ())]

    version_ids = [d.current_version_id for d in visible_docs if d.current_version_id]
    versions = (
        {
            v.id: v
            for v in db.scalars(
                select(DocumentVersion).where(
                    DocumentVersion.id.in_(version_ids), DocumentVersion.organization_id == org_id
                )
            )
        }
        if version_ids
        else {}
    )
    starred = document_stars(db, authz.principal.user_id, [d.id for d in visible_docs])
    pinned = folder_favorites(db, authz.principal.user_id, [f.id for f in visible_folders])
    refs = user_refs(
        db, [*(f.updated_by for f in visible_folders), *(d.updated_by for d in visible_docs)]
    )

    items: list[TreeItem] = []
    for f in visible_folders:
        items.append(
            TreeItem(
                kind="folder",
                id=f.id,
                name=f.name,
                updated_at=f.updated_at,
                permissions=sorted(folder_perms[f.id]),
                is_team_folder=f.is_team_folder,
                starred=f.id in pinned,
                updated_by=refs.get(f.updated_by) if f.updated_by else None,
            )
        )
    for d in visible_docs:
        v = versions.get(d.current_version_id) if d.current_version_id else None
        items.append(
            TreeItem(
                kind="document",
                id=d.id,
                name=d.name,
                updated_at=d.updated_at,
                permissions=sorted(doc_perms[d.id]),
                size_bytes=v.size_bytes if v else None,
                content_type=v.content_type if v else None,
                status=d.status,
                current_version_number=v.version_number if v else None,
                owner_id=d.owner_id,
                starred=d.id in starred,
                updated_by=refs.get(d.updated_by) if d.updated_by else None,
                locked=lock_active(d),
                locked_by_me=lock_active(d) and d.locked_by == authz.principal.user_id,
            )
        )

    key_funcs: dict[str, Any] = {
        "name": lambda i: i.name.lower(),
        "updated_at": lambda i: i.updated_at,
        "size": lambda i: i.size_bytes or 0,
        "type": lambda i: (i.content_type or "", i.name.lower()),
        "modified_by": lambda i: (
            (i.updated_by.display_name or i.updated_by.email or "").lower() if i.updated_by else ""
        ),
    }
    if sort not in key_funcs:
        raise ValidationFailed("sort must be one of: name, updated_at, size, type, modified_by.")
    items.sort(key=key_funcs[sort], reverse=descending)
    items.sort(key=lambda i: 0 if i.kind == "folder" else 1)  # folders first (stable)
    return items[offset : offset + limit], len(items)


def breadcrumb(
    db: Session, authz: AuthorizationService, folder_id: uuid.UUID
) -> list[BreadcrumbSegmentOut]:
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    segments = authz.breadcrumb_for_folder(folder.id, mask_unauthorized=mask_policy(db, authz))
    return to_breadcrumb_out(segments)


def create_folder(
    db: Session, authz: AuthorizationService, parent_id: uuid.UUID, raw_name: str
) -> FolderOut:
    name = validate_name(raw_name, what="Folder name")
    parent = authz.require_folder(parent_id, Action.CREATE_CHILD)
    p = authz.principal
    ensure_name_free(db, p.organization_id, parent.id, name)
    folder = Folder(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        parent_folder_id=parent.id,
        name=name,
        created_by=p.user_id,
        updated_by=p.user_id,
    )
    db.add(folder)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError(
            "A file or folder with this name already exists here.", code="name_conflict"
        ) from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="folder.created",
        resource_type="folder",
        resource_id=folder.id,
        metadata={"path": f"{plain_path(db, p.organization_id, parent.id)}/{name}"},
    )
    db.commit()
    perms = authz.folder_actions([folder.id])[folder.id]
    return folder_out(db, authz, folder, perms)


def update_folder(
    db: Session,
    authz: AuthorizationService,
    folder_id: uuid.UUID,
    *,
    name: str | None,
    parent_folder_id: uuid.UUID | None,
    expected_row_version: int | None,
) -> FolderOut:
    p = authz.principal
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    if folder.parent_folder_id is None:
        raise ForbiddenError("The root folder cannot be renamed or moved.")
    if expected_row_version is not None and expected_row_version != folder.row_version:
        raise ConflictError("The folder was modified by someone else.", code="stale_version")
    if name is None and parent_folder_id is None:
        raise ValidationFailed("Nothing to update.")

    old_path = plain_path(db, p.organization_id, folder.id)
    orig_parent = folder.parent_folder_id
    new_name = folder.name
    new_parent = folder.parent_folder_id

    if name is not None and name != folder.name:
        authz.require_folder(folder.id, Action.RENAME)
        new_name = validate_name(name, what="Folder name")
    if parent_folder_id is not None and parent_folder_id != folder.parent_folder_id:
        authz.require_folder(folder.id, Action.MOVE)
        target = authz.require_folder(parent_folder_id, Action.CREATE_CHILD)
        # Cycle guard: the target must not be the folder itself or inside its subtree.
        if target.id in set(subtree_folder_ids(db, p.organization_id, folder.id)):
            raise ValidationFailed("A folder cannot be moved into itself or its own subfolder.")
        new_parent = target.id

    if new_name != folder.name or new_parent != folder.parent_folder_id:
        ensure_name_free(db, p.organization_id, new_parent, new_name, exclude_folder_id=folder.id)  # type: ignore[arg-type]
        folder.name = new_name
        folder.parent_folder_id = new_parent
        folder.row_version += 1
        folder.updated_at = datetime.now(UTC)
        folder.updated_by = p.user_id
        try:
            db.flush()
        except IntegrityError as exc:
            db.rollback()
            raise ConflictError(
                "A file or folder with this name already exists here.", code="name_conflict"
            ) from exc
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="folder.moved" if new_parent != orig_parent else "folder.renamed",
            resource_type="folder",
            resource_id=folder.id,
            metadata={
                "old_path": old_path,
                "new_path": plain_path(db, p.organization_id, folder.id),
            },
        )
        db.commit()
    perms = authz.folder_actions([folder.id])[folder.id]
    return folder_out(db, authz, folder, perms)


def delete_folder(db: Session, authz: AuthorizationService, folder_id: uuid.UUID) -> None:
    """Soft-delete the folder and its whole subtree as one restorable batch."""
    p = authz.principal
    folder = authz.require_folder(folder_id, Action.DELETE)
    if folder.parent_folder_id is None:
        raise ForbiddenError("The root folder cannot be deleted.")

    subtree = subtree_folder_ids(db, p.organization_id, folder.id)
    docs = list(
        db.scalars(
            select(Document).where(
                Document.organization_id == p.organization_id,
                Document.folder_id.in_(subtree),
                Document.deleted_at.is_(None),
            )
        )
    )
    # The caller must be allowed to delete *everything* inside; otherwise refuse (no partial
    # deletes, no deleting other people's content by deleting a parent).
    folder_perms = authz.folder_actions(subtree)
    doc_perms = authz.document_actions(docs)
    if any(Action.DELETE.value not in folder_perms.get(fid, ()) for fid in subtree) or any(
        Action.DELETE.value not in doc_perms.get(d.id, ()) for d in docs
    ):
        authz.deny("folder", folder.id, Action.DELETE, "descendant_not_deletable")
        raise ForbiddenError("You do not have permission to delete everything inside this folder.")

    from app.modules.governance.service import assert_deletable

    subtree_rows = list(
        db.scalars(
            select(Folder).where(
                Folder.id.in_(subtree), Folder.organization_id == p.organization_id
            )
        )
    )
    assert_deletable(db, p.organization_id, documents=docs, folders=subtree_rows)

    batch = uuid.uuid4()
    now = datetime.now(UTC)
    path = plain_path(db, p.organization_id, folder.id)
    db.execute(
        update(Folder)
        .where(
            Folder.organization_id == p.organization_id,
            Folder.id.in_(subtree),
            Folder.deleted_at.is_(None),
        )
        .values(deleted_at=now, deleted_by=p.user_id, delete_batch_id=batch)
    )
    if docs:
        db.execute(
            update(Document)
            .where(
                Document.id.in_([d.id for d in docs]), Document.organization_id == p.organization_id
            )
            .values(deleted_at=now, deleted_by=p.user_id, delete_batch_id=batch)
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="folder.deleted",
        resource_type="folder",
        resource_id=folder.id,
        metadata={
            "path": path,
            "folders": len(subtree),
            "documents": len(docs),
            "batch": str(batch),
        },
    )
    db.commit()


def restore_folder(
    db: Session, authz: AuthorizationService, folder_id: uuid.UUID, new_name: str | None
) -> FolderOut:
    p = authz.principal
    folder = authz.require_folder(folder_id, Action.RESTORE, include_deleted=True)
    if folder.deleted_at is None:
        raise ConflictError("Folder is not in the trash.", code="not_deleted")
    parent = db.get(Folder, folder.parent_folder_id) if folder.parent_folder_id else None
    if (
        parent is None
        or parent.organization_id != p.organization_id
        or parent.deleted_at is not None
    ):
        raise ConflictError(
            "The original parent folder no longer exists. Restore it first.", code="parent_deleted"
        )
    name = validate_name(new_name, what="Folder name") if new_name else folder.name
    ensure_name_free(db, p.organization_id, parent.id, name, exclude_folder_id=folder.id)
    batch = folder.delete_batch_id
    folder.name = name
    if batch is not None:
        db.execute(
            update(Folder)
            .where(Folder.organization_id == p.organization_id, Folder.delete_batch_id == batch)
            .values(deleted_at=None, deleted_by=None, delete_batch_id=None)
        )
        db.execute(
            update(Document)
            .where(Document.organization_id == p.organization_id, Document.delete_batch_id == batch)
            .values(deleted_at=None, deleted_by=None, delete_batch_id=None)
        )
    else:
        folder.deleted_at = None
        folder.deleted_by = None
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="folder.restored",
        resource_type="folder",
        resource_id=folder.id,
        metadata={"path": plain_path(db, p.organization_id, folder.id)},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("A name conflict prevents restoring.", code="name_conflict") from exc
    db.refresh(folder)
    perms = authz.folder_actions([folder.id])[folder.id]
    return folder_out(db, authz, folder, perms)


def list_trash(
    db: Session, authz: AuthorizationService, *, limit: int, offset: int
) -> tuple[list[TrashItem], int]:
    """Top-level trashed items (batch roots) the caller may restore."""
    p = authz.principal
    org_id = p.organization_id

    folders = list(
        db.scalars(
            select(Folder).where(Folder.organization_id == org_id, Folder.deleted_at.is_not(None))
        )
    )
    docs = list(
        db.scalars(
            select(Document).where(
                Document.organization_id == org_id, Document.deleted_at.is_not(None)
            )
        )
    )
    # A batch root is an item whose parent is not part of the same delete batch.
    batch_of_folder = {f.id: f.delete_batch_id for f in folders}
    roots_f = [
        f
        for f in folders
        if f.parent_folder_id is None
        or batch_of_folder.get(f.parent_folder_id) != f.delete_batch_id
    ]
    roots_d = [d for d in docs if batch_of_folder.get(d.folder_id) != d.delete_batch_id]

    fperms = authz.folder_actions([f.id for f in roots_f])
    dperms = authz.document_actions(roots_d)
    allowed_f = [f for f in roots_f if Action.RESTORE.value in fperms.get(f.id, ())]
    allowed_d = [d for d in roots_d if Action.RESTORE.value in dperms.get(d.id, ())]

    parent_ids = [f.parent_folder_id for f in allowed_f if f.parent_folder_id] + [
        d.folder_id for d in allowed_d
    ]
    crumbs = authz.breadcrumbs_for_folders(parent_ids, mask_unauthorized=mask_policy(db, authz))
    sizes = (
        {
            did: size
            for did, size in db.execute(
                select(Document.id, DocumentVersion.size_bytes)
                .join(DocumentVersion, DocumentVersion.id == Document.current_version_id)
                .where(Document.id.in_([d.id for d in allowed_d]))
            ).all()
        }
        if allowed_d
        else {}
    )

    items: list[TrashItem] = [
        TrashItem(
            kind="folder",
            id=f.id,
            name=f.name,
            deleted_at=f.deleted_at,  # type: ignore[arg-type]
            deleted_by=f.deleted_by,
            original_breadcrumb=to_breadcrumb_out(crumbs.get(f.parent_folder_id, []))
            if f.parent_folder_id
            else [],
        )
        for f in allowed_f
    ] + [
        TrashItem(
            kind="document",
            id=d.id,
            name=d.name,
            deleted_at=d.deleted_at,  # type: ignore[arg-type]
            deleted_by=d.deleted_by,
            original_breadcrumb=to_breadcrumb_out(crumbs.get(d.folder_id, [])),
            size_bytes=sizes.get(d.id),
        )
        for d in allowed_d
    ]
    items.sort(key=lambda i: i.deleted_at, reverse=True)
    return items[offset : offset + limit], len(items)


__all__ = [
    "breadcrumb",
    "create_folder",
    "delete_folder",
    "folder_out",
    "get_folder",
    "get_root",
    "list_children",
    "list_trash",
    "restore_folder",
    "update_folder",
]


MAX_PATH_DEPTH = 20


def ensure_path(
    db: Session, authz: AuthorizationService, base_id: uuid.UUID, segments: list[str]
) -> tuple[FolderOut, int]:
    """Resolve ``segments`` below ``base_id``, creating missing folders (folder upload / drop).

    Idempotent. An existing folder must be visible to the caller (otherwise this would be an
    existence oracle, so it is reported as a name conflict); a document with the same name is a
    conflict. Missing folders need CREATE_CHILD on their parent. Returns (leaf, created_count).
    """
    if not segments or len(segments) > MAX_PATH_DEPTH:
        raise ValidationFailed(f"path must have between 1 and {MAX_PATH_DEPTH} segments")
    names = [validate_name(s, what="Folder name") for s in segments]
    org_id = authz.principal.organization_id
    current = authz.require_folder(base_id, Action.DISCOVER)
    created = 0
    for name in names:
        child = db.scalar(
            select(Folder).where(
                Folder.organization_id == org_id,
                Folder.parent_folder_id == current.id,
                func.lower(Folder.name) == name.lower(),
                Folder.deleted_at.is_(None),
            )
        )
        if child is not None:
            if Action.DISCOVER.value not in authz.folder_actions([child.id]).get(
                child.id, frozenset()
            ):
                raise ConflictError(
                    "A file or folder with this name already exists here.", code="name_conflict"
                )
            current = child
            continue
        made = create_folder(db, authz, current.id, name)
        created += 1
        current = authz.require_folder(made.id, Action.DISCOVER)
    perms = authz.folder_actions([current.id])[current.id]
    return folder_out(db, authz, current, perms), created
