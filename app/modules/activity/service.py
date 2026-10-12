"""Per-item activity feed (the 'Activity' tab), derived from the append-only audit log.

Only events whose resource is this item are returned, never denied/noise events, never IPs or
user agents. Content-change events are visible to anyone who can view the item; *who looked at or
shared it* (views, downloads, shares, permission changes, access requests) is visible only to those
who manage access (owners/admins), so a read-only recipient cannot see who else has access.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import NotFoundError
from app.db.enums import Action
from app.db.models import AuditEvent, Document, Folder
from app.modules.authorization.service import AuthorizationService
from app.modules.items.common import user_refs
from app.schemas.activity import ActivityItem, MyActivityItem
from app.schemas.common import UserRef

# action -> (label, manager_only)
LABELS: dict[str, tuple[str, bool]] = {
    "document.created": ("created this file", False),
    "folder.created": ("created this folder", False),
    "upload.initiated": ("started an upload", False),
    "document.scan_clean": ("file passed the security scan", False),
    "document.version_created": ("uploaded a new version", False),
    "document.version_restored": ("restored an earlier version", False),
    "document.renamed": ("renamed this", False),
    "document.metadata_updated": ("edited the details", False),
    "document.moved": ("moved this", False),
    "folder.moved": ("moved this folder", False),
    "folder.renamed": ("renamed this folder", False),
    "document.copied": ("copied this", False),
    "folder.copied": ("copied this folder", False),
    "document.deleted": ("moved this to the trash", False),
    "folder.deleted": ("moved this folder to the trash", False),
    "document.restored": ("restored this from the trash", False),
    "folder.restored": ("restored this folder", False),
    "document.locked": ("checked this out", False),
    "document.unlocked": ("checked this in", False),
    "document.lock_broken": ("broke the check-out lock", False),
    "comment.created": ("commented", False),
    "comment.edited": ("edited a comment", False),
    "comment.deleted": ("deleted a comment", False),
    "signature.requested": ("requested signatures", False),
    "signature.completed": ("signatures were completed", False),
    "workflow.started": ("submitted this for approval", False),
    "document.previewed": ("viewed this", True),
    "document.downloaded": ("downloaded this", True),
    "share.created": ("shared this", True),
    "share.revoked": ("revoked a share", True),
    "permission.granted": ("granted access", True),
    "permission.revoked": ("revoked access", True),
    "access_request.created": ("requested access", True),
    "access_request.approved": ("approved an access request", True),
    "access_request.rejected": ("rejected an access request", True),
}


def _held(authz: AuthorizationService, rtype: str, rid: uuid.UUID) -> frozenset[str]:
    if rtype == "document":
        doc = authz.load_document(rid)
        acts = authz.document_actions([doc]).get(doc.id, frozenset()) if doc else frozenset()
    else:
        folder = authz.load_folder(rid)
        acts = (
            authz.folder_actions([folder.id]).get(folder.id, frozenset()) if folder else frozenset()
        )
    if Action.DISCOVER.value not in acts or Action.VIEW.value not in acts:
        raise NotFoundError(f"{rtype.capitalize()} not found.")
    return acts


def list_activity(
    db: Session, authz: AuthorizationService, rtype: str, rid: uuid.UUID, *, limit: int, offset: int
) -> list[ActivityItem]:
    held = _held(authz, rtype, rid)
    p = authz.principal
    sees_access_events = p.is_admin or Action.MANAGE_ACCESS.value in held
    allowed = [
        a for a, (_, manager_only) in LABELS.items() if sees_access_events or not manager_only
    ]
    rows = list(
        db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.organization_id == p.organization_id,
                AuditEvent.resource_type == rtype,
                AuditEvent.resource_id == rid,
                AuditEvent.outcome == "success",
                AuditEvent.action.in_(allowed),
            )
            .order_by(AuditEvent.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    refs = user_refs(db, [r.actor_user_id for r in rows])
    return [
        ActivityItem(
            id=r.id,
            action=r.action,
            label=LABELS[r.action][0],
            actor=refs.get(r.actor_user_id, UserRef(id=r.actor_user_id))
            if r.actor_user_id
            else None,
            at=r.created_at,
            you=r.actor_user_id == p.user_id,
        )
        for r in rows
    ]


# action -> verb for the signed-in user's own feed ("You <verb> <item>")
MY_VERBS: dict[str, str] = {
    "document.created": "created",
    "folder.created": "created folder",
    "document.version_created": "uploaded a new version of",
    "document.version_restored": "restored an earlier version of",
    "document.renamed": "renamed",
    "folder.renamed": "renamed",
    "document.metadata_updated": "edited the details of",
    "document.moved": "moved",
    "folder.moved": "moved",
    "document.copied": "copied",
    "folder.copied": "copied",
    "document.deleted": "moved to the trash",
    "folder.deleted": "moved to the trash",
    "document.restored": "restored",
    "folder.restored": "restored",
    "document.locked": "checked out",
    "document.unlocked": "checked in",
    # one entry per request: the URL being issued is the user's act (the later byte transfer is not repeated)
    "document.preview_url_issued": "viewed",
    "document.download_url_issued": "downloaded",
    "share.created": "shared",
    "share.revoked": "revoked a share of",
    "permission.granted": "granted access to",
    "permission.revoked": "revoked access to",
    "workflow.started": "submitted for approval:",
    "signature.requested": "requested signatures on",
    "signature.recipient_signed": "signed",
    "signature.recipient_declined": "declined to sign",
}


def my_activity(
    db: Session, authz: AuthorizationService, *, limit: int, offset: int
) -> list[MyActivityItem]:
    """The caller's own recent actions on files and folders. Never anyone else's, never IPs."""
    p = authz.principal
    rows = list(
        db.scalars(
            select(AuditEvent)
            .where(
                AuditEvent.organization_id == p.organization_id,
                AuditEvent.actor_user_id == p.user_id,
                AuditEvent.outcome == "success",
                AuditEvent.resource_type.in_(("document", "folder")),
                AuditEvent.resource_id.is_not(None),
                AuditEvent.action.in_(list(MY_VERBS)),
            )
            .order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )
    doc_ids = {r.resource_id for r in rows if r.resource_type == "document" and r.resource_id}
    folder_ids = {r.resource_id for r in rows if r.resource_type == "folder" and r.resource_id}
    names: dict[uuid.UUID, str] = {}
    if doc_ids:
        docs = list(
            db.scalars(
                select(Document).where(
                    Document.organization_id == p.organization_id, Document.id.in_(doc_ids)
                )
            )
        )
        held = authz.document_actions(docs)
        names.update({d.id: d.name for d in docs if Action.DISCOVER.value in held.get(d.id, ())})
    if folder_ids:
        folders = list(
            db.scalars(
                select(Folder).where(
                    Folder.organization_id == p.organization_id, Folder.id.in_(folder_ids)
                )
            )
        )
        held_f = authz.folder_actions([f.id for f in folders])
        names.update(
            {f.id: f.name for f in folders if Action.DISCOVER.value in held_f.get(f.id, ())}
        )
    return [
        MyActivityItem(
            id=r.id,
            action=r.action,
            verb=MY_VERBS[r.action],
            target_type=r.resource_type or "document",
            target_id=r.resource_id,  # type: ignore[arg-type]
            target_name=names.get(r.resource_id),  # type: ignore[arg-type]
            at=r.created_at,
        )
        for r in rows
    ]
