"""Retention policies, legal holds, protected deletion and permanent purge.

Rules (ADR-0011):
  * A legal hold on a document protects it; a hold on a folder protects the whole subtree.
  * Held content can be neither moved to trash nor purged until every covering hold is released.
  * A retention policy forbids permanent purge until ``created_at + min_retention_days``.
  * Purge is irreversible: it requires the item to be in the trash, the DELETE right on it, and
    that nothing in its subtree is protected. Object deletion is done by the worker after the
    database transaction commits (outbox), and is idempotent.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import Action, LedgerEntryType, ResourceType
from app.db.models import (
    Document,
    DocumentDerivative,
    DocumentVersion,
    Folder,
    LegalHold,
    LegalHoldItem,
    Organization,
    PermissionGrant,
    QuotaLedgerEntry,
    RetentionPolicy,
    ShareGrant,
    StorageLocation,
    UploadSession,
)
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import plain_path, subtree_folder_ids
from app.modules.identity.principal import Principal
from app.modules.outbox import service as outbox
from app.modules.users.service import require_admin

_CHAINS_SQL = text(
    """
    WITH RECURSIVE chain(start_id, folder_id, parent_id, depth) AS (
      SELECT f.id, f.id, f.parent_folder_id, 0 FROM dms.folders f
       WHERE f.id = ANY(:ids) AND f.organization_id = :org
      UNION ALL
      SELECT c.start_id, p.id, p.parent_folder_id, c.depth + 1
        FROM chain c JOIN dms.folders p ON p.id = c.parent_id AND p.organization_id = :org
       WHERE c.depth < 100
    )
    SELECT start_id, folder_id FROM chain
    """
)


@dataclass(frozen=True)
class Protection:
    resource_type: str
    resource_id: uuid.UUID
    reason: str  # legal_hold | retention_active
    until: datetime | None = None


def _chains(
    db: Session, org_id: uuid.UUID, folder_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, set[uuid.UUID]]:
    ids = list({*folder_ids})
    out: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    if ids:
        for start, fid in db.execute(_CHAINS_SQL, {"ids": ids, "org": org_id}):
            out[start].add(fid)
    return out


def _active_hold_targets(db: Session, org_id: uuid.UUID) -> tuple[set[uuid.UUID], set[uuid.UUID]]:
    rows = db.execute(
        select(LegalHoldItem.resource_type, LegalHoldItem.resource_id)
        .join(
            LegalHold,
            (LegalHold.id == LegalHoldItem.hold_id)
            & (LegalHold.organization_id == LegalHoldItem.organization_id),
        )
        .where(LegalHoldItem.organization_id == org_id, LegalHold.status == "active")
    ).all()
    return (
        {rid for t, rid in rows if t == ResourceType.FOLDER.value},
        {rid for t, rid in rows if t == ResourceType.DOCUMENT.value},
    )


def find_protections(
    db: Session,
    org_id: uuid.UUID,
    *,
    documents: list[Document],
    folders: list[Folder],
    check_retention: bool,
) -> list[Protection]:
    """Everything that currently forbids deleting (hold) / purging (hold + retention)."""
    held_folders, held_docs = _active_hold_targets(db, org_id)
    policies = list(
        db.scalars(
            select(RetentionPolicy).where(
                RetentionPolicy.organization_id == org_id, RetentionPolicy.enabled.is_(True)
            )
        )
    )
    if not (held_folders or held_docs or (check_retention and policies)):
        return []
    chains = _chains(db, org_id, [*(d.folder_id for d in documents), *(f.id for f in folders)])
    now = datetime.now(UTC)
    found: list[Protection] = []
    for f in folders:
        if chains.get(f.id, set()) & held_folders:
            found.append(Protection("folder", f.id, "legal_hold"))
    for d in documents:
        if d.id in held_docs or chains.get(d.folder_id, set()) & held_folders:
            found.append(Protection("document", d.id, "legal_hold"))
        if check_retention:
            days = [
                p.min_retention_days
                for p in policies
                if p.scope_folder_id is None or p.scope_folder_id in chains.get(d.folder_id, set())
            ]
            if days:
                until = d.created_at + timedelta(days=max(days))
                if until > now:
                    found.append(Protection("document", d.id, "retention_active", until))
    return found


def _raise_if_protected(found: list[Protection]) -> None:
    if found:
        codes = {p.reason for p in found}
        code = "legal_hold" if "legal_hold" in codes else "retention_active"
        raise ConflictError(
            "This item is protected by a "
            + ("legal hold." if code == "legal_hold" else "retention policy.")
            + " Contact an administrator.",
            code=code,
            details=[
                {
                    "resource_type": p.resource_type,
                    "resource_id": str(p.resource_id),
                    "reason": p.reason,
                    "until": p.until.isoformat() if p.until else None,
                }
                for p in found[:20]
            ],
        )


def assert_deletable(
    db: Session, org_id: uuid.UUID, *, documents: list[Document], folders: list[Folder]
) -> None:
    _raise_if_protected(
        find_protections(db, org_id, documents=documents, folders=folders, check_retention=False)
    )


# ------------------------------------------------------------------ purge
def _delete_document_rows(db: Session, doc: Document) -> list[dict[str, str]]:
    """Remove a document and everything that belongs to it. Returns objects to delete."""
    org_id = doc.organization_id
    versions = list(
        db.scalars(
            select(DocumentVersion)
            .where(DocumentVersion.document_id == doc.id, DocumentVersion.organization_id == org_id)
            .order_by(DocumentVersion.version_number.desc())
        )
    )
    objects = [{"location_id": str(v.storage_location_id), "key": v.object_key} for v in versions]
    objects.extend(
        {"location_id": str(d.storage_location_id), "key": d.object_key}
        for d in db.scalars(
            select(DocumentDerivative).where(
                DocumentDerivative.organization_id == org_id,
                DocumentDerivative.version_id.in_([v.id for v in versions] or [uuid.UUID(int=0)]),
            )
        )
    )
    total = sum(v.size_bytes for v in versions)
    db.execute(
        delete(UploadSession).where(
            UploadSession.document_id == doc.id, UploadSession.organization_id == org_id
        )
    )
    share_ids = list(
        db.scalars(
            select(ShareGrant.id).where(
                ShareGrant.organization_id == org_id,
                ShareGrant.resource_type == "document",
                ShareGrant.resource_id == doc.id,
            )
        )
    )
    if share_ids:
        db.execute(delete(ShareGrant).where(ShareGrant.id.in_(share_ids)))  # recipients cascade
    db.execute(
        delete(PermissionGrant).where(
            PermissionGrant.organization_id == org_id,
            PermissionGrant.resource_type == "document",
            PermissionGrant.resource_id == doc.id,
        )
    )
    db.execute(
        delete(LegalHoldItem).where(
            LegalHoldItem.organization_id == org_id,
            LegalHoldItem.resource_type == "document",
            LegalHoldItem.resource_id == doc.id,
        )
    )
    doc.current_version_id = None
    db.flush()
    # Newest first: a restored version references an older one (RESTRICT FK).
    for v in versions:
        db.delete(v)
        db.flush()
    db.delete(doc)
    db.flush()
    if total:
        org = db.scalar(
            select(Organization)
            .where(Organization.id == org_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        assert org is not None
        stmt = (
            pg_insert(QuotaLedgerEntry)
            .values(
                id=uuid.uuid4(),
                organization_id=org_id,
                entry_type=LedgerEntryType.ADJUST.value,
                reserved_delta=0,
                used_delta=-total,
                idempotency_key=f"purge:{doc.id}",
                note="document purged",
            )
            .on_conflict_do_nothing(constraint="uq_quota_ledger_idem")
            .returning(QuotaLedgerEntry.id)
        )
        if db.execute(stmt).first() is not None:
            org.quota_used_bytes = max(0, org.quota_used_bytes - total)
    return objects


def _purge_set(
    db: Session, org_id: uuid.UUID, root_kind: str, root_id: uuid.UUID
) -> tuple[list[Document], list[Folder]]:
    if root_kind == "document":
        doc = db.scalar(
            select(Document).where(Document.id == root_id, Document.organization_id == org_id)
        )
        return ([doc] if doc else []), []
    folder_ids = subtree_folder_ids(db, org_id, root_id)
    folders = list(
        db.scalars(
            select(Folder).where(Folder.id.in_(folder_ids), Folder.organization_id == org_id)
        )
    )
    docs = list(
        db.scalars(
            select(Document).where(
                Document.folder_id.in_(folder_ids), Document.organization_id == org_id
            )
        )
    )
    return docs, folders


def _execute_purge(
    db: Session, org_id: uuid.UUID, docs: list[Document], folders: list[Folder]
) -> list[dict[str, str]]:
    objects: list[dict[str, str]] = []
    for d in docs:
        objects.extend(_delete_document_rows(db, d))
    if folders:
        ids = [f.id for f in folders]
        # parents are referenced by children (RESTRICT): delete deepest first
        depth = {f.id: 0 for f in folders}
        by_id = {f.id: f for f in folders}
        for f in folders:
            cur, levels = f, 0
            while cur.parent_folder_id in by_id:
                cur = by_id[cur.parent_folder_id]
                levels += 1
            depth[f.id] = levels
        db.execute(
            delete(ShareGrant).where(
                ShareGrant.organization_id == org_id,
                ShareGrant.resource_type == "folder",
                ShareGrant.resource_id.in_(ids),
            )
        )
        db.execute(
            delete(PermissionGrant).where(
                PermissionGrant.organization_id == org_id,
                PermissionGrant.resource_type == "folder",
                PermissionGrant.resource_id.in_(ids),
            )
        )
        db.execute(
            delete(LegalHoldItem).where(
                LegalHoldItem.organization_id == org_id,
                LegalHoldItem.resource_type == "folder",
                LegalHoldItem.resource_id.in_(ids),
            )
        )
        db.execute(
            delete(RetentionPolicy).where(
                RetentionPolicy.organization_id == org_id, RetentionPolicy.scope_folder_id.in_(ids)
            )
        )
        db.execute(
            delete(UploadSession).where(
                UploadSession.organization_id == org_id, UploadSession.folder_id.in_(ids)
            )
        )
        for f in sorted(folders, key=lambda x: -depth[x.id]):
            db.delete(f)
            db.flush()
    return objects


def purge(
    db: Session, authz: AuthorizationService, kind: str, resource_id: uuid.UUID
) -> dict[str, int]:
    """Permanently delete a TRASHED document or folder (user initiated)."""
    p = authz.principal
    if kind == "document":
        item: Document | Folder = authz.require_document(
            resource_id, Action.DELETE, include_deleted=True
        )
    else:
        item = authz.require_folder(resource_id, Action.DELETE, include_deleted=True)
        if item.parent_folder_id is None:
            raise ForbiddenError("The root folder cannot be deleted.")
    if item.deleted_at is None:
        raise ConflictError(
            "Only items in the trash can be permanently deleted.", code="not_in_trash"
        )

    docs, folders = _purge_set(db, p.organization_id, kind, resource_id)
    fperms = authz.folder_actions([f.id for f in folders])
    dperms = authz.document_actions(docs)
    if any(Action.DELETE.value not in fperms.get(f.id, ()) for f in folders) or any(
        Action.DELETE.value not in dperms.get(d.id, ()) for d in docs
    ):
        authz.deny(kind, resource_id, Action.DELETE, "descendant_not_purgeable")
        raise ForbiddenError("You do not have permission to delete everything inside.")
    _raise_if_protected(
        find_protections(
            db, p.organization_id, documents=docs, folders=folders, check_retention=True
        )
    )
    path_info = plain_path(db, p.organization_id, item.id) if kind == "folder" else item.name
    stats = {"documents": len(docs), "folders": len(folders)}
    objects = _execute_purge(db, p.organization_id, docs, folders)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=f"{kind}.purged",
        resource_type=kind,
        resource_id=resource_id,
        metadata={"name": path_info, **stats, "objects": len(objects)},
    )
    _enqueue_object_deletion(db, p.organization_id, resource_id, objects)
    db.commit()
    return stats


def _enqueue_object_deletion(
    db: Session, org_id: uuid.UUID, aggregate_id: uuid.UUID, objects: list[dict[str, str]]
) -> None:
    for i in range(0, len(objects), 200):
        outbox.enqueue(
            db,
            organization_id=org_id,
            event_type="storage.delete_objects",
            aggregate_type="purge",
            aggregate_id=uuid.uuid4() if i else aggregate_id,
            payload={"objects": objects[i : i + 200]},
        )


def purge_expired_trash(db: Session, *, limit: int = 100) -> dict[str, int]:
    """Maintenance: permanently delete trash older than each organization's retention window
    (``trash_retention_days``), skipping anything under hold/retention. System actor."""
    from app.modules.organizations.service import org_settings

    purged = skipped = 0
    now = datetime.now(UTC)
    for org in db.scalars(select(Organization).where(Organization.status == "active")):
        days = org_settings(org)["trash_retention_days"]
        if days is None:
            continue
        cutoff = now - timedelta(days=days)
        folders = list(
            db.scalars(
                select(Folder)
                .where(Folder.organization_id == org.id, Folder.deleted_at < cutoff)
                .limit(limit)
            )
        )
        docs = list(
            db.scalars(
                select(Document)
                .where(Document.organization_id == org.id, Document.deleted_at < cutoff)
                .limit(limit)
            )
        )
        in_batch = {f.delete_batch_id for f in folders if f.delete_batch_id}
        roots: list[tuple[str, uuid.UUID]] = []
        folder_by_id = {f.id: f for f in folders}
        for f in folders:
            parent = folder_by_id.get(f.parent_folder_id) if f.parent_folder_id else None
            if parent is None or parent.delete_batch_id != f.delete_batch_id:
                roots.append(("folder", f.id))
        for d in docs:
            parent_batch = (
                folder_by_id[d.folder_id].delete_batch_id if d.folder_id in folder_by_id else None
            )
            if d.delete_batch_id is None or parent_batch != d.delete_batch_id:
                roots.append(("document", d.id))
        del in_batch
        for kind, rid in roots:
            sub_docs, sub_folders = _purge_set(db, org.id, kind, rid)
            if find_protections(
                db, org.id, documents=sub_docs, folders=sub_folders, check_retention=True
            ):
                skipped += 1
                continue
            objects = _execute_purge(db, org.id, sub_docs, sub_folders)
            audit.record(
                db,
                organization_id=org.id,
                actor_user_id=None,
                action=f"{kind}.purged",
                resource_type=kind,
                resource_id=rid,
                metadata={
                    "reason": "trash_retention_elapsed",
                    "documents": len(sub_docs),
                    "folders": len(sub_folders),
                },
            )
            _enqueue_object_deletion(db, org.id, rid, objects)
            db.commit()
            purged += 1
    return {"purged": purged, "skipped_protected": skipped}


def handle_delete_objects(db: Session, payload: dict[str, Any], get_provider: Any) -> None:
    """Worker side: delete storage objects (idempotent)."""
    for obj in payload.get("objects", []):
        location = db.get(StorageLocation, uuid.UUID(obj["location_id"]))
        if location is None:
            continue
        get_provider(location.provider_type).delete_object(location.bucket, obj["key"])


# ---------------------------------------------------------- admin CRUD: policies
def list_policies(db: Session, p: Principal) -> list[RetentionPolicy]:
    if not p.can_read_audit:
        raise ForbiddenError("Compliance access is restricted to administrators and auditors.")
    return list(
        db.scalars(
            select(RetentionPolicy)
            .where(RetentionPolicy.organization_id == p.organization_id)
            .order_by(RetentionPolicy.name)
        )
    )


def create_policy(
    db: Session,
    p: Principal,
    *,
    name: str,
    description: str | None,
    scope_folder_id: uuid.UUID | None,
    min_retention_days: int,
) -> RetentionPolicy:
    require_admin(p)
    if scope_folder_id is not None:
        exists = db.scalar(
            select(Folder.id).where(
                Folder.id == scope_folder_id, Folder.organization_id == p.organization_id
            )
        )
        if exists is None:
            raise ValidationFailed("Unknown folder.", code="unknown_folder")
    policy = RetentionPolicy(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=name.strip(),
        description=description,
        scope_folder_id=scope_folder_id,
        min_retention_days=min_retention_days,
        created_by=p.user_id,
    )
    db.add(policy)
    try:
        db.flush()
    except Exception as exc:
        db.rollback()
        raise ConflictError(
            "A policy with this name already exists.", code="name_conflict"
        ) from exc
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="retention_policy.created",
        resource_type="retention_policy",
        resource_id=policy.id,
        metadata={
            "name": policy.name,
            "days": min_retention_days,
            "scope_folder_id": str(scope_folder_id) if scope_folder_id else None,
        },
    )
    db.commit()
    return policy


def update_policy(
    db: Session,
    p: Principal,
    policy_id: uuid.UUID,
    *,
    enabled: bool | None,
    min_retention_days: int | None,
) -> RetentionPolicy:
    require_admin(p)
    policy = db.scalar(
        select(RetentionPolicy).where(
            RetentionPolicy.id == policy_id, RetentionPolicy.organization_id == p.organization_id
        )
    )
    if policy is None:
        raise NotFoundError("Policy not found.")
    changes: dict[str, Any] = {}
    if enabled is not None and enabled != policy.enabled:
        policy.enabled = enabled
        changes["enabled"] = enabled
    if min_retention_days is not None and min_retention_days != policy.min_retention_days:
        policy.min_retention_days = min_retention_days
        changes["min_retention_days"] = min_retention_days
    if changes:
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="retention_policy.updated",
            resource_type="retention_policy",
            resource_id=policy.id,
            metadata=changes,
        )
    db.commit()
    return policy


def delete_policy(db: Session, p: Principal, policy_id: uuid.UUID) -> None:
    require_admin(p)
    policy = db.scalar(
        select(RetentionPolicy).where(
            RetentionPolicy.id == policy_id, RetentionPolicy.organization_id == p.organization_id
        )
    )
    if policy is None:
        raise NotFoundError("Policy not found.")
    db.delete(policy)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="retention_policy.deleted",
        resource_type="retention_policy",
        resource_id=policy_id,
        metadata={"name": policy.name},
    )
    db.commit()


# --------------------------------------------------------- admin CRUD: legal holds
def list_holds(db: Session, p: Principal) -> list[tuple[LegalHold, int]]:
    if not p.can_read_audit:
        raise ForbiddenError("Compliance access is restricted to administrators and auditors.")
    holds = list(
        db.scalars(
            select(LegalHold)
            .where(LegalHold.organization_id == p.organization_id)
            .order_by(LegalHold.created_at.desc())
        )
    )
    counts = dict(
        db.execute(
            select(LegalHoldItem.hold_id, func.count())
            .where(LegalHoldItem.organization_id == p.organization_id)
            .group_by(LegalHoldItem.hold_id)
        ).all()
    )
    return [(h, counts.get(h.id, 0)) for h in holds]


def _hold(db: Session, p: Principal, hold_id: uuid.UUID) -> LegalHold:
    hold = db.scalar(
        select(LegalHold).where(
            LegalHold.id == hold_id, LegalHold.organization_id == p.organization_id
        )
    )
    if hold is None:
        raise NotFoundError("Legal hold not found.")
    return hold


def create_hold(db: Session, p: Principal, *, name: str, description: str | None) -> LegalHold:
    require_admin(p)
    hold = LegalHold(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=name.strip(),
        description=description,
        created_by=p.user_id,
    )
    db.add(hold)
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="legal_hold.created",
        resource_type="legal_hold",
        resource_id=hold.id,
        metadata={"name": hold.name},
    )
    db.commit()
    return hold


def hold_items(db: Session, p: Principal, hold_id: uuid.UUID) -> list[dict[str, Any]]:
    if not p.can_read_audit:
        raise ForbiddenError("Compliance access is restricted to administrators and auditors.")
    _hold(db, p, hold_id)
    items = list(
        db.scalars(
            select(LegalHoldItem)
            .where(
                LegalHoldItem.hold_id == hold_id, LegalHoldItem.organization_id == p.organization_id
            )
            .order_by(LegalHoldItem.created_at)
        )
    )
    doc_names = dict(
        db.execute(
            select(Document.id, Document.name).where(
                Document.id.in_(
                    [i.resource_id for i in items if i.resource_type == "document"]
                    or [uuid.UUID(int=0)]
                )
            )
        ).all()
    )
    folder_names = dict(
        db.execute(
            select(Folder.id, Folder.name).where(
                Folder.id.in_(
                    [i.resource_id for i in items if i.resource_type == "folder"]
                    or [uuid.UUID(int=0)]
                )
            )
        ).all()
    )
    return [
        {
            "id": i.id,
            "resource_type": i.resource_type,
            "resource_id": i.resource_id,
            "resource_name": (doc_names if i.resource_type == "document" else folder_names).get(
                i.resource_id
            ),
            "added_by": i.added_by,
            "created_at": i.created_at,
        }
        for i in items
    ]


def add_hold_item(
    db: Session,
    p: Principal,
    hold_id: uuid.UUID,
    resource_type: ResourceType,
    resource_id: uuid.UUID,
) -> LegalHoldItem:
    require_admin(p)
    hold = _hold(db, p, hold_id)
    if hold.status != "active":
        raise ConflictError("This hold has been released.", code="hold_released")
    model = Document if resource_type == ResourceType.DOCUMENT else Folder
    exists = db.scalar(
        select(model.id).where(model.id == resource_id, model.organization_id == p.organization_id)
    )
    if exists is None:
        raise NotFoundError("Resource not found.")
    item = db.scalar(
        select(LegalHoldItem).where(
            LegalHoldItem.hold_id == hold_id,
            LegalHoldItem.resource_type == resource_type.value,
            LegalHoldItem.resource_id == resource_id,
        )
    )
    if item is None:
        item = LegalHoldItem(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            hold_id=hold_id,
            resource_type=resource_type.value,
            resource_id=resource_id,
            added_by=p.user_id,
        )
        db.add(item)
        audit.record(
            db,
            organization_id=p.organization_id,
            actor_user_id=p.user_id,
            action="legal_hold.item_added",
            resource_type=resource_type.value,
            resource_id=resource_id,
            metadata={"hold_id": str(hold_id)},
        )
    db.commit()
    return item


def remove_hold_item(db: Session, p: Principal, hold_id: uuid.UUID, item_id: uuid.UUID) -> None:
    require_admin(p)
    _hold(db, p, hold_id)
    item = db.scalar(
        select(LegalHoldItem).where(
            LegalHoldItem.id == item_id,
            LegalHoldItem.hold_id == hold_id,
            LegalHoldItem.organization_id == p.organization_id,
        )
    )
    if item is None:
        raise NotFoundError("Hold item not found.")
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="legal_hold.item_removed",
        resource_type=item.resource_type,
        resource_id=item.resource_id,
        metadata={"hold_id": str(hold_id)},
    )
    db.delete(item)
    db.commit()


def release_hold(db: Session, p: Principal, hold_id: uuid.UUID, reason: str) -> LegalHold:
    require_admin(p)
    hold = _hold(db, p, hold_id)
    if hold.status == "released":
        return hold
    hold.status, hold.released_at, hold.released_by, hold.release_reason = (
        "released",
        datetime.now(UTC),
        p.user_id,
        reason,
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="legal_hold.released",
        resource_type="legal_hold",
        resource_id=hold.id,
        metadata={"reason": reason[:300]},
    )
    db.commit()
    return hold


def protection_summary(
    db: Session, authz: AuthorizationService, kind: str, resource_id: uuid.UUID
) -> dict[str, Any]:
    """What blocks deletion/purge of this item, for UI hints (no hold names for non-admins)."""
    p = authz.principal
    if kind == "document":
        doc = authz.require_document(resource_id, Action.VIEW, include_deleted=True)
        docs: list[Document] = [doc]
        folders: list[Folder] = []
    else:
        folder = authz.require_folder(resource_id, Action.VIEW, include_deleted=True)
        docs, folders = _purge_set(db, p.organization_id, "folder", folder.id)
    found = find_protections(
        db, p.organization_id, documents=docs, folders=folders, check_retention=True
    )
    until = max((x.until for x in found if x.until), default=None)
    return {
        "legal_hold": any(x.reason == "legal_hold" for x in found),
        "retention_until": until,
        "can_delete": not any(x.reason == "legal_hold" for x in found),
        "can_purge": not found,
    }
