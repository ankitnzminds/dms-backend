"""Documents: stable identity, metadata, versions, trash, copy, stars and recents."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.adapters.storage.base import StorageError, new_object_key
from app.adapters.storage.registry import get_storage_provider
from app.core.errors import (
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
    RecentDocument,
    StorageLocation,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import ensure_name_free, plain_path
from app.modules.folders.service import mask_policy, to_breadcrumb_out
from app.modules.outbox import service as outbox
from app.modules.quota import service as quota
from app.schemas.tree import DocumentOut, TreeItem, VersionOut

CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
_MAX_METADATA_BYTES = 16_000


def version_out(
    v: DocumentVersion, current_id: uuid.UUID | None, restored_number: int | None = None
) -> VersionOut:
    return VersionOut(
        id=v.id,
        version_number=v.version_number,
        size_bytes=v.size_bytes,
        sha256=v.sha256,
        content_type=v.content_type,
        original_filename=v.original_filename,
        created_by=v.created_by,
        created_at=v.created_at,
        scan_status=v.scan_status,  # type: ignore[arg-type]
        is_current=v.id == current_id,
        restored_from_version_number=restored_number,
    )


def touch_recent(db: Session, user_id: uuid.UUID, doc: Document, action: str) -> None:
    stmt = pg_insert(RecentDocument).values(
        user_id=user_id,
        document_id=doc.id,
        organization_id=doc.organization_id,
        last_action=action,
        last_accessed_at=datetime.now(UTC),
    )
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=[RecentDocument.user_id, RecentDocument.document_id],
            set_={"last_action": action, "last_accessed_at": stmt.excluded.last_accessed_at},
        )
    )


def _document_out(
    db: Session,
    authz: AuthorizationService,
    doc: Document,
    permissions: frozenset[str],
    *,
    include_current: bool = True,
) -> DocumentOut:
    p = authz.principal
    current = None
    if include_current and doc.current_version_id and Action.VIEW.value in permissions:
        v = db.get(DocumentVersion, doc.current_version_id)
        if v is not None and v.organization_id == p.organization_id:
            current = version_out(v, doc.current_version_id)
    starred = (
        db.scalar(
            select(DocumentStar.document_id).where(
                DocumentStar.user_id == p.user_id, DocumentStar.document_id == doc.id
            )
        )
        is not None
    )
    crumbs = authz.breadcrumb_for_folder(doc.folder_id, mask_unauthorized=mask_policy(db, authz))
    return DocumentOut(
        id=doc.id,
        name=doc.name,
        folder_id=doc.folder_id,
        owner_id=doc.owner_id,
        status=doc.status,  # type: ignore[arg-type]
        classification=doc.classification,
        metadata=doc.custom_metadata or {},
        latest_version_number=doc.latest_version_number,
        current_version=current,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        row_version=doc.row_version,
        deleted_at=doc.deleted_at,
        starred=starred,
        permissions=sorted(permissions),
        breadcrumb=to_breadcrumb_out(crumbs),
    )


def get_document(db: Session, authz: AuthorizationService, document_id: uuid.UUID) -> DocumentOut:
    doc = authz.require_document(document_id, Action.VIEW)
    perms = authz.document_actions([doc])[doc.id]
    out = _document_out(db, authz, doc, perms)
    touch_recent(db, authz.principal.user_id, doc, "viewed")
    db.commit()
    return out


def _validate_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    if len(str(metadata)) > _MAX_METADATA_BYTES:
        raise ValidationFailed("Metadata is too large.")
    if not all(isinstance(k, str) and 0 < len(k) <= 100 for k in metadata):
        raise ValidationFailed("Metadata keys must be non-empty strings (max 100 chars).")
    return metadata


def update_document(
    db: Session,
    authz: AuthorizationService,
    document_id: uuid.UUID,
    *,
    name: str | None,
    folder_id: uuid.UUID | None,
    metadata: dict[str, Any] | None,
    classification: str | None,
    expected_row_version: int | None,
) -> DocumentOut:
    p = authz.principal
    doc = authz.require_document(document_id, Action.VIEW)
    if name is None and folder_id is None and metadata is None and classification is None:
        raise ValidationFailed("Nothing to update.")
    if expected_row_version is not None and expected_row_version != doc.row_version:
        raise ConflictError("The document was modified by someone else.", code="stale_version")

    old_path = f"{plain_path(db, p.organization_id, doc.folder_id)}/{doc.name}"
    orig_folder = doc.folder_id
    new_name, new_folder = doc.name, doc.folder_id
    if name is not None and name != doc.name:
        authz.require_document(doc.id, Action.RENAME)
        new_name = validate_name(name, what="Document name")
    if folder_id is not None and folder_id != doc.folder_id:
        authz.require_document(doc.id, Action.MOVE)
        target = authz.require_folder(folder_id, Action.CREATE_CHILD)
        new_folder = target.id
    if metadata is not None:
        authz.require_document(doc.id, Action.EDIT_METADATA)
        from app.modules.metadata.service import validate_document_metadata

        doc.custom_metadata = validate_document_metadata(db, p.organization_id, metadata)
    if classification is not None:
        authz.require_document(doc.id, Action.MANAGE_ACCESS)  # classification is an access control
        if classification not in CLASSIFICATIONS:
            raise ValidationFailed(f"classification must be one of {sorted(CLASSIFICATIONS)}")
        doc.classification = classification

    if new_name != doc.name or new_folder != doc.folder_id:
        ensure_name_free(db, p.organization_id, new_folder, new_name, exclude_document_id=doc.id)
        doc.name, doc.folder_id = new_name, new_folder
    doc.row_version += 1
    doc.updated_at = datetime.now(UTC)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError(
            "A file or folder with this name already exists here.", code="name_conflict"
        ) from exc

    new_path = f"{plain_path(db, p.organization_id, doc.folder_id)}/{doc.name}"
    action = (
        "document.moved"
        if new_folder != orig_folder
        else ("document.renamed" if name is not None else "document.metadata_updated")
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=action,
        resource_type="document",
        resource_id=doc.id,
        metadata={"old_path": old_path, "new_path": new_path},
    )
    touch_recent(db, p.user_id, doc, "edited")
    db.commit()
    perms = authz.document_actions([doc])[doc.id]
    return _document_out(db, authz, doc, perms)


def delete_document(db: Session, authz: AuthorizationService, document_id: uuid.UUID) -> None:
    p = authz.principal
    doc = authz.require_document(document_id, Action.DELETE)
    from app.modules.governance.service import assert_deletable

    assert_deletable(db, p.organization_id, documents=[doc], folders=[])
    now = datetime.now(UTC)
    doc.deleted_at, doc.deleted_by, doc.delete_batch_id = now, p.user_id, uuid.uuid4()
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.deleted",
        resource_type="document",
        resource_id=doc.id,
        metadata={"path": f"{plain_path(db, p.organization_id, doc.folder_id)}/{doc.name}"},
    )
    db.commit()


def restore_document(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, new_name: str | None
) -> DocumentOut:
    p = authz.principal
    doc = authz.require_document(document_id, Action.RESTORE, include_deleted=True)
    if doc.deleted_at is None:
        raise ConflictError("Document is not in the trash.", code="not_deleted")
    folder = db.get(Folder, doc.folder_id)
    if (
        folder is None
        or folder.organization_id != p.organization_id
        or folder.deleted_at is not None
    ):
        raise ConflictError(
            "The original folder no longer exists. Restore it first.", code="parent_deleted"
        )
    name = validate_name(new_name, what="Document name") if new_name else doc.name
    ensure_name_free(db, p.organization_id, doc.folder_id, name, exclude_document_id=doc.id)
    doc.name = name
    doc.deleted_at = doc.deleted_by = doc.delete_batch_id = None
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.restored",
        resource_type="document",
        resource_id=doc.id,
        metadata={"path": f"{plain_path(db, p.organization_id, doc.folder_id)}/{doc.name}"},
    )
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise ConflictError("A name conflict prevents restoring.", code="name_conflict") from exc
    perms = authz.document_actions([doc])[doc.id]
    return _document_out(db, authz, doc, perms)


# ------------------------------------------------------------------ versions
def list_versions(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID
) -> list[VersionOut]:
    doc = authz.require_document(document_id, Action.VIEW)
    perms = authz.document_actions([doc])[doc.id]
    versions = list(
        db.scalars(
            select(DocumentVersion)
            .where(
                DocumentVersion.document_id == doc.id,
                DocumentVersion.organization_id == doc.organization_id,
            )
            .order_by(DocumentVersion.version_number.desc())
        )
    )
    privileged = authz.principal.is_admin or doc.owner_id == authz.principal.user_id
    can_see_unreleased = privileged or Action.UPLOAD_VERSION.value in perms
    by_id = {v.id: v.version_number for v in versions}
    visible = [
        v
        for v in versions
        if v.scan_status == ScanStatus.CLEAN.value
        or (
            can_see_unreleased
            and v.scan_status in (ScanStatus.PENDING.value, ScanStatus.ERROR.value)
        )
        or (privileged and v.scan_status == ScanStatus.INFECTED.value)
    ]
    return [
        version_out(
            v,
            doc.current_version_id,
            by_id.get(v.restored_from_version_id) if v.restored_from_version_id else None,
        )
        for v in visible
    ]


def _storage_for(
    db: Session, organization_id: uuid.UUID, location_id: uuid.UUID
) -> tuple[Any, StorageLocation]:
    location = db.get(StorageLocation, location_id)
    if location is None or location.organization_id != organization_id:
        raise NotFoundError("Storage location not found.")
    return get_storage_provider(location.provider_type), location


def _new_version_from_existing(
    db: Session,
    authz: AuthorizationService,
    doc: Document,
    source: DocumentVersion,
    *,
    restored_from: DocumentVersion | None,
) -> DocumentVersion:
    """Copy source bytes to a fresh object and register a new pending version (re-scanned)."""
    p = authz.principal
    provider, location = _storage_for(db, p.organization_id, source.storage_location_id)
    key = new_object_key(p.organization_id)
    try:
        provider.copy_object(location.bucket, source.object_key, key)
    except StorageError as exc:
        raise DependencyUnavailableError("Storage is unavailable. Please retry.") from exc
    try:
        locked = db.scalar(
            select(Document)
            .where(Document.id == doc.id, Document.organization_id == p.organization_id)
            .with_for_update()
        )
        assert locked is not None
        locked.latest_version_number += 1
        version = DocumentVersion(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            document_id=doc.id,
            version_number=locked.latest_version_number,
            storage_location_id=location.id,
            object_key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            content_type=source.content_type,
            original_filename=source.original_filename,
            created_by=p.user_id,
            restored_from_version_id=restored_from.id if restored_from else None,
            scan_status=ScanStatus.PENDING.value,
        )
        db.add(version)
        db.flush()
        quota.charge_direct(
            db,
            organization_id=p.organization_id,
            reference_id=version.id,
            size_bytes=version.size_bytes,
            document_version_id=version.id,
        )
        outbox.enqueue(
            db,
            organization_id=p.organization_id,
            event_type="document_version.uploaded",
            aggregate_type="document_version",
            aggregate_id=version.id,
            payload={"document_id": str(doc.id), "version_number": version.version_number},
        )
        return version
    except Exception:
        db.rollback()
        try:
            provider.delete_object(location.bucket, key)  # compensate the orphaned copy
        except StorageError:
            pass
        raise


def restore_version(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, version_number: int
) -> VersionOut:
    """Restore = create a *new* version with the old content. History is never rewritten."""
    p = authz.principal
    doc = authz.require_document(document_id, Action.UPLOAD_VERSION)
    source = db.scalar(
        select(DocumentVersion).where(
            DocumentVersion.document_id == doc.id,
            DocumentVersion.organization_id == p.organization_id,
            DocumentVersion.version_number == version_number,
        )
    )
    if source is None or source.scan_status != ScanStatus.CLEAN.value:
        raise NotFoundError("Version not found.")
    version = _new_version_from_existing(db, authz, doc, source, restored_from=source)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="document.version_restored",
        resource_type="document",
        resource_id=doc.id,
        metadata={"from_version": source.version_number, "new_version": version.version_number},
    )
    db.commit()
    return version_out(version, doc.current_version_id, source.version_number)


def copy_document(
    db: Session,
    authz: AuthorizationService,
    document_id: uuid.UUID,
    target_folder_id: uuid.UUID,
    name: str | None,
) -> DocumentOut:
    """Copy creates a NEW logical document (new id, new object); move keeps identity."""
    p = authz.principal
    src_doc = authz.require_document(document_id, Action.COPY)
    target = authz.require_folder(target_folder_id, Action.CREATE_CHILD)
    if src_doc.current_version_id is None or src_doc.status != DocumentStatus.AVAILABLE.value:
        raise ConflictError("Only available documents can be copied.", code="not_available")
    source = db.get(DocumentVersion, src_doc.current_version_id)
    assert source is not None and source.organization_id == p.organization_id
    new_name = validate_name(name, what="Document name") if name else src_doc.name
    ensure_name_free(db, p.organization_id, target.id, new_name)

    provider, location = _storage_for(db, p.organization_id, source.storage_location_id)
    key = new_object_key(p.organization_id)
    try:
        provider.copy_object(location.bucket, source.object_key, key)
    except StorageError as exc:
        raise DependencyUnavailableError("Storage is unavailable. Please retry.") from exc
    try:
        new_doc = Document(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            folder_id=target.id,
            name=new_name,
            owner_id=p.user_id,
            status=DocumentStatus.PROCESSING.value,
            classification=src_doc.classification,
            custom_metadata=dict(src_doc.custom_metadata or {}),
            latest_version_number=1,
        )
        db.add(new_doc)
        db.flush()
        version = DocumentVersion(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            document_id=new_doc.id,
            version_number=1,
            storage_location_id=location.id,
            object_key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            content_type=source.content_type,
            original_filename=source.original_filename,
            created_by=p.user_id,
            scan_status=ScanStatus.PENDING.value,
        )
        db.add(version)
        db.flush()
        quota.charge_direct(
            db,
            organization_id=p.organization_id,
            reference_id=version.id,
            size_bytes=version.size_bytes,
            document_version_id=version.id,
        )
        outbox.enqueue(
            db,
            organization_id=p.organization_id,
            event_type="document_version.uploaded",
            aggregate_type="document_version",
            aggregate_id=version.id,
            payload={"document_id": str(new_doc.id), "version_number": 1},
        )
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="document.copied",
            resource_type="document",
            resource_id=new_doc.id,
            metadata={"source_document_id": str(src_doc.id), "target_folder_id": str(target.id)},
        )
        db.commit()
    except Exception:
        db.rollback()
        try:
            provider.delete_object(location.bucket, key)
        except StorageError:
            pass
        raise
    perms = authz.document_actions([new_doc])[new_doc.id]
    return _document_out(db, authz, new_doc, perms)


# ----------------------------------------------------------- stars / recents
def set_star(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, starred: bool
) -> None:
    p = authz.principal
    doc = authz.require_document(document_id, Action.VIEW)
    if starred:
        db.execute(
            pg_insert(DocumentStar)
            .values(user_id=p.user_id, document_id=doc.id, organization_id=p.organization_id)
            .on_conflict_do_nothing()
        )
    else:
        db.execute(
            delete(DocumentStar).where(
                DocumentStar.user_id == p.user_id, DocumentStar.document_id == doc.id
            )
        )
    db.commit()


def _tree_items_for(
    db: Session, authz: AuthorizationService, docs: list[Document]
) -> list[TreeItem]:
    perms = authz.document_actions(docs)
    org_id = authz.principal.organization_id
    vids = [d.current_version_id for d in docs if d.current_version_id]
    versions = (
        {
            v.id: v
            for v in db.scalars(
                select(DocumentVersion).where(
                    DocumentVersion.id.in_(vids), DocumentVersion.organization_id == org_id
                )
            )
        }
        if vids
        else {}
    )
    starred = set(
        db.scalars(
            select(DocumentStar.document_id).where(
                DocumentStar.user_id == authz.principal.user_id,
                DocumentStar.document_id.in_([d.id for d in docs] or [uuid.UUID(int=0)]),
            )
        )
    )
    items = []
    for d in docs:
        if Action.DISCOVER.value not in perms.get(d.id, ()):
            continue
        v = versions.get(d.current_version_id) if d.current_version_id else None
        items.append(
            TreeItem(
                kind="document",
                id=d.id,
                name=d.name,
                updated_at=d.updated_at,
                permissions=sorted(perms[d.id]),
                size_bytes=v.size_bytes if v else None,
                content_type=v.content_type if v else None,
                status=d.status,
                current_version_number=v.version_number if v else None,
                owner_id=d.owner_id,
                starred=d.id in starred,
            )
        )
    return items


def list_starred(
    db: Session, authz: AuthorizationService, limit: int, offset: int
) -> tuple[list[TreeItem], int]:
    p = authz.principal
    docs = list(
        db.scalars(
            select(Document)
            .join(DocumentStar, DocumentStar.document_id == Document.id)
            .where(
                DocumentStar.user_id == p.user_id,
                Document.organization_id == p.organization_id,
                Document.deleted_at.is_(None),
            )
            .order_by(DocumentStar.created_at.desc())
        )
    )
    items = _tree_items_for(db, authz, docs)  # re-authorized: revoked access hides the star
    return items[offset : offset + limit], len(items)


def list_recent(
    db: Session, authz: AuthorizationService, limit: int, offset: int
) -> tuple[list[TreeItem], int]:
    p = authz.principal
    docs = list(
        db.scalars(
            select(Document)
            .join(RecentDocument, RecentDocument.document_id == Document.id)
            .where(
                RecentDocument.user_id == p.user_id,
                Document.organization_id == p.organization_id,
                Document.deleted_at.is_(None),
            )
            .order_by(RecentDocument.last_accessed_at.desc())
            .limit(200)
        )
    )
    items = _tree_items_for(db, authz, docs)
    return items[offset : offset + limit], len(items)


__all__ = [
    "ForbiddenError",
    "copy_document",
    "delete_document",
    "get_document",
    "list_recent",
    "list_starred",
    "list_versions",
    "restore_document",
    "restore_version",
    "set_star",
    "touch_recent",
    "update",
    "update_document",
    "version_out",
]


def processing_status(db: Session, authz: AuthorizationService, document_id: uuid.UUID):  # noqa: ANN201
    from app.db.models import DocumentDerivative, DocumentText
    from app.schemas.metadata import ProcessingStatusOut

    doc = authz.require_document(document_id, Action.VIEW)
    if doc.current_version_id is None:
        return ProcessingStatusOut(version_number=None)
    version = db.get(DocumentVersion, doc.current_version_id)
    text_row = db.get(DocumentText, doc.current_version_id)
    has_thumb = (
        db.scalar(
            select(DocumentDerivative.id).where(
                DocumentDerivative.version_id == doc.current_version_id
            )
        )
        is not None
    )
    return ProcessingStatusOut(
        version_number=version.version_number if version else None,
        text_status=text_row.status if text_row else None,
        text_characters=text_row.char_count if text_row else 0,
        text_truncated=text_row.truncated if text_row else False,
        has_thumbnail=has_thumb,
    )
