"""Pending actions: typed payloads, human-readable previews, freshness checks and executors.

The agent can only PROPOSE. A proposal is validated and authorized for the requester, stored with
a canonical hash, and shown as a preview. Confirmation (see service.confirm_action) re-validates,
re-checks freshness and re-authorizes by calling the very same application services a user would,
so the model can never do anything the user could not do - and nothing happens unconfirmed."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import Action, ResourceType
from app.db.models import Document, Folder, ShareGrant
from app.modules.access_requests import service as access_requests
from app.modules.authorization.service import AuthorizationService
from app.modules.documents import service as documents
from app.modules.folders import service as folders
from app.modules.items import service as items
from app.modules.sharing import service as sharing
from app.modules.workflows import service as workflows
from app.schemas.chat import AccessRequestCreate
from app.schemas.common import ActionName
from app.schemas.items import ItemRef
from app.schemas.sharing import RecipientIn, ShareCreate
from app.schemas.workflows import WorkflowDefinitionIn

Kind = Literal["document", "folder"]
ConflictPolicy = Literal["fail", "rename", "skip"]


# ------------------------------------------------------------------ payloads
class Target(BaseModel):
    kind: Kind
    id: uuid.UUID
    row_version: int | None = Field(
        None, description="Fingerprint taken at proposal time; a change invalidates the action."
    )


class CreateFolderP(BaseModel):
    parent_folder_id: uuid.UUID
    name: str = Field(min_length=1, max_length=255)


class RenameItemP(BaseModel):
    target: Target
    new_name: str = Field(min_length=1, max_length=255)


class MoveCopyP(BaseModel):
    items: list[Target] = Field(min_length=1, max_length=200)
    target_folder_id: uuid.UUID
    on_conflict: ConflictPolicy = "fail"


class TrashP(BaseModel):
    items: list[Target] = Field(min_length=1, max_length=200)


class FavoriteP(BaseModel):
    target: Target
    on: bool = True


class RequestAccessP(BaseModel):
    resource_type: Kind
    resource_id: uuid.UUID
    actions: list[ActionName] = Field(min_length=1, max_length=16)
    reason: str = Field(min_length=3, max_length=1000)


class CreateShareP(BaseModel):
    resource_type: Kind
    resource_id: uuid.UUID
    recipients: list[RecipientIn] = Field(min_length=1, max_length=50)
    actions: list[ActionName] = Field(min_length=1, max_length=20)
    expires_at: datetime | None = None
    message: str | None = Field(None, max_length=1000)


class RevokeShareP(BaseModel):
    share_id: uuid.UUID


class CreateWorkflowP(BaseModel):
    definition: WorkflowDefinitionIn


class StartRunP(BaseModel):
    document_id: uuid.UUID
    definition_id: uuid.UUID
    note: str | None = Field(None, max_length=1000)


PAYLOADS: dict[str, type[BaseModel]] = {
    "create_folder": CreateFolderP,
    "rename_item": RenameItemP,
    "move_items": MoveCopyP,
    "copy_items": MoveCopyP,
    "trash_items": TrashP,
    "favorite_item": FavoriteP,
    "request_access": RequestAccessP,
    "create_share": CreateShareP,
    "revoke_share": RevokeShareP,
    "create_workflow": CreateWorkflowP,
    "start_workflow_run": StartRunP,
}

# Actions that change who can see/do what, or are hard to undo: flagged in the preview.
HIGH_IMPACT = {"create_share", "revoke_share", "trash_items", "create_workflow", "move_items"}


def canonical_hash(
    action_type: str, payload: dict[str, Any], requester: uuid.UUID, org: uuid.UUID
) -> str:
    blob = json.dumps(
        {"t": action_type, "p": payload, "u": str(requester), "o": str(org)},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(blob.encode()).hexdigest()


def dump(model: BaseModel) -> dict[str, Any]:
    return json.loads(model.model_dump_json())


# ------------------------------------------------------------------ describing targets
def path_of(authz: AuthorizationService, folder_id: uuid.UUID | None) -> str:
    if folder_id is None:
        return ""
    segs = authz.breadcrumbs_for_folders([folder_id], mask_unauthorized=True).get(folder_id, [])
    return "/" + "/".join(s.name or "…" for s in segs)


def describe(
    db: Session, authz: AuthorizationService, kind: Kind, rid: uuid.UUID
) -> dict[str, Any]:
    """Name/location of a DISCOVERABLE item (raises NotFound otherwise, non-disclosing)."""
    if kind == "document":
        d = authz.require_document(rid, Action.DISCOVER)
        return {
            "kind": kind,
            "id": str(d.id),
            "name": d.name,
            "location": path_of(authz, d.folder_id),
        }
    f = authz.require_folder(rid, Action.DISCOVER)
    return {
        "kind": kind,
        "id": str(f.id),
        "name": f.name,
        "location": path_of(authz, f.parent_folder_id),
    }


def target_with_version(
    db: Session, authz: AuthorizationService, kind: Kind, rid: uuid.UUID
) -> Target:
    if kind == "document":
        return Target(
            kind=kind, id=rid, row_version=authz.require_document(rid, Action.DISCOVER).row_version
        )
    return Target(
        kind=kind, id=rid, row_version=authz.require_folder(rid, Action.DISCOVER).row_version
    )


# ------------------------------------------------------------------ freshness
def check_fresh(
    db: Session, authz: AuthorizationService, action_type: str, payload: BaseModel
) -> None:
    """Raise ConflictError(action_stale) if what the user was shown has changed."""
    org = authz.principal.organization_id

    def stale() -> ConflictError:
        return ConflictError(
            "The items changed since this was previewed. Please review a fresh preview.",
            code="action_stale",
        )

    targets: list[Target] = []
    if isinstance(payload, MoveCopyP | TrashP):
        targets = list(payload.items)
    elif isinstance(payload, RenameItemP | FavoriteP):
        targets = [payload.target]
    for t in targets:
        model: Any = Document if t.kind == "document" else Folder
        row = db.scalar(
            select(model).where(
                model.id == t.id, model.organization_id == org, model.deleted_at.is_(None)
            )
        )
        if row is None or (t.row_version is not None and row.row_version != t.row_version):
            raise stale()
    if isinstance(payload, MoveCopyP):
        dest = db.scalar(
            select(Folder.id).where(
                Folder.id == payload.target_folder_id,
                Folder.organization_id == org,
                Folder.deleted_at.is_(None),
            )
        )
        if dest is None:
            raise stale()
    if isinstance(payload, RevokeShareP):
        share = db.scalar(
            select(ShareGrant).where(
                ShareGrant.id == payload.share_id, ShareGrant.organization_id == org
            )
        )
        if share is None or share.revoked_at is not None:
            raise stale()


# ------------------------------------------------------------------ proposals -> (payload, preview)
Proposal = tuple[BaseModel, dict[str, Any]]


def _items_preview(
    db: Session, authz: AuthorizationService, ts: list[Target]
) -> list[dict[str, Any]]:
    return [describe(db, authz, t.kind, t.id) for t in ts]


def _fingerprinted(
    db: Session, authz: AuthorizationService, refs: list[ItemRef | Target]
) -> list[Target]:
    return [target_with_version(db, authz, r.kind, r.id) for r in refs]


def propose_create_folder(db: Session, authz: AuthorizationService, p: CreateFolderP) -> Proposal:
    parent = authz.require_folder(p.parent_folder_id, Action.CREATE_FOLDER)
    return p, {
        "title": f"Create folder “{p.name}”",
        "targets": [],
        "destination": {
            "id": str(parent.id),
            "name": parent.name,
            "location": path_of(authz, parent.id),
        },
        "impact": "A new empty folder is created. Nothing else changes.",
    }


def propose_rename(db: Session, authz: AuthorizationService, p: RenameItemP) -> Proposal:
    t = p.target
    if t.kind == "document":
        authz.require_document(t.id, Action.RENAME)
    else:
        authz.require_folder(t.id, Action.RENAME)
    fp = RenameItemP(target=target_with_version(db, authz, t.kind, t.id), new_name=p.new_name)
    return fp, {
        "title": f"Rename to “{p.new_name}”",
        "targets": [describe(db, authz, t.kind, t.id)],
        "impact": "Only the name changes; location, versions and access stay the same.",
    }


def _need(authz: AuthorizationService, t: Target, action: Action) -> None:
    if t.kind == "document":
        authz.require_document(t.id, action)
    else:
        authz.require_folder(t.id, action)


def propose_move_copy(
    db: Session, authz: AuthorizationService, p: MoveCopyP, *, copy: bool, max_items: int
) -> Proposal:
    if len(p.items) > max_items:
        raise ValidationFailed(f"At most {max_items} items per action.", code="too_many_items")
    dest = authz.require_folder(p.target_folder_id, Action.UPLOAD)
    for t in p.items:
        _need(authz, t, Action.COPY if copy else Action.MOVE)
    fp = MoveCopyP(
        items=_fingerprinted(db, authz, list(p.items)),
        target_folder_id=p.target_folder_id,
        on_conflict=p.on_conflict,
    )
    return fp, {
        "title": f"{'Copy' if copy else 'Move'} {len(p.items)} item(s) to “{dest.name}”",
        "targets": _items_preview(db, authz, p.items),
        "destination": {"id": str(dest.id), "name": dest.name, "location": path_of(authz, dest.id)},
        "on_conflict": p.on_conflict,
        "impact": (
            "New independent copies are created (shares and version history are not copied)."
            if copy
            else "Items keep their identity; access that came from their old location may change."
        ),
    }


def propose_trash(
    db: Session, authz: AuthorizationService, p: TrashP, *, max_items: int
) -> Proposal:
    if len(p.items) > max_items:
        raise ValidationFailed(f"At most {max_items} items per action.", code="too_many_items")
    for t in p.items:
        _need(authz, t, Action.DELETE)
    fp = TrashP(items=_fingerprinted(db, authz, list(p.items)))
    return fp, {
        "title": f"Move {len(p.items)} item(s) to the trash",
        "targets": _items_preview(db, authz, p.items),
        "impact": "Items go to the trash and can be restored until it is emptied or expires. "
        "Legal holds and retention rules still apply.",
        "destructive": True,
    }


def propose_favorite(db: Session, authz: AuthorizationService, p: FavoriteP) -> Proposal:
    fp = FavoriteP(target=target_with_version(db, authz, p.target.kind, p.target.id), on=p.on)
    return fp, {
        "title": "Add to Quick Access" if p.on else "Remove from Quick Access",
        "targets": [describe(db, authz, p.target.kind, p.target.id)],
        "impact": "Only your own Quick Access list changes.",
    }


def propose_request_access(db: Session, authz: AuthorizationService, p: RequestAccessP) -> Proposal:
    info = describe(db, authz, p.resource_type, p.resource_id)  # must be discoverable
    return p, {
        "title": f"Request {', '.join(sorted(set(p.actions)))} access",
        "targets": [info],
        "reason": p.reason,
        "impact": "A request is sent to the people who manage access. It grants nothing by itself.",
    }


def propose_create_share(db: Session, authz: AuthorizationService, p: CreateShareP) -> Proposal:
    if p.resource_type == "document":
        authz.require_document(p.resource_id, Action.SHARE)
    else:
        authz.require_folder(p.resource_id, Action.SHARE)
    info = describe(db, authz, p.resource_type, p.resource_id)
    return p, {
        "title": f"Share “{info['name']}”",
        "targets": [info],
        "recipients": [r.model_dump(mode="json", exclude_none=True) for r in p.recipients],
        "permissions": sorted(set(p.actions)),
        "expires_at": p.expires_at.isoformat() if p.expires_at else None,
        "impact": "The recipients gain exactly these permissions on this item"
        + (" and everything inside it." if p.resource_type == "folder" else "."),
        "external": False,
    }


def propose_revoke_share(db: Session, authz: AuthorizationService, p: RevokeShareP) -> Proposal:
    out = sharing.get_share_out(db, authz, p.share_id)
    return p, {
        "title": f"Revoke share of “{out.resource_name or 'item'}”",
        "targets": [
            {"kind": out.resource_type, "id": str(out.resource_id), "name": out.resource_name}
        ],
        "recipients": [r.model_dump(mode="json", exclude_none=True) for r in out.recipients],
        "permissions": list(out.actions),
        "impact": "Only this share is revoked. Access that comes from folder permissions, "
        "groups or other shares is not affected.",
        "destructive": True,
    }


def propose_create_workflow(
    db: Session, authz: AuthorizationService, p: CreateWorkflowP
) -> Proposal:
    p_ = authz.principal
    if not p_.is_admin:
        authz.deny("organization", p_.organization_id, Action.ADMINISTER, "workflow_admin_only")
        from app.core.errors import ForbiddenError

        raise ForbiddenError("Only administrators can create workflows.")
    workflows._validate_references(db, p_.organization_id, p.definition.steps)  # noqa: SLF001
    steps = [
        {
            "name": s.name,
            "rule": s.rule,
            "assignees": [a.model_dump(mode="json", exclude_none=True) for a in s.assignees],
            "due_days": s.due_days,
            "condition": s.condition.model_dump(mode="json", exclude_none=True)
            if s.condition
            else None,
        }
        for s in p.definition.steps
    ]
    return p, {
        "title": f"Create workflow “{p.definition.name}”",
        "workflow": {
            "name": p.definition.name,
            "description": p.definition.description,
            "steps": steps,
        },
        "validation": "Valid: all reviewers, groups and roles resolve inside your organization.",
        "impact": "The workflow becomes available to start on documents. It does not start anything.",
    }


def propose_start_run(db: Session, authz: AuthorizationService, p: StartRunP) -> Proposal:
    doc = authz.require_document(p.document_id, Action.EDIT_METADATA)
    info = describe(db, authz, "document", doc.id)
    return p, {
        "title": f"Submit “{doc.name}” for approval",
        "targets": [info],
        "workflow_id": str(p.definition_id),
        "note": p.note,
        "impact": "Approval tasks are created for the workflow's reviewers.",
    }


# ------------------------------------------------------------------ executors
Outcome = tuple[str, dict[str, Any], str]  # (summary, result, status)


def _bulk(result: Any, verb: str) -> Outcome:
    status = (
        "executed"
        if result.failed == 0 and result.skipped == 0
        else ("failed" if result.succeeded == 0 and result.failed > 0 else "partially_executed")
    )
    return (
        f"{verb}: {result.succeeded} succeeded, {result.failed} failed, {result.skipped} skipped.",
        result.model_dump(mode="json"),
        status,
    )


def ex_create_folder(db: Session, authz: AuthorizationService, p: CreateFolderP) -> Outcome:
    out = folders.create_folder(db, authz, p.parent_folder_id, p.name)
    return f"Created folder “{out.name}”.", {"folder_id": str(out.id)}, "executed"


def ex_rename(db: Session, authz: AuthorizationService, p: RenameItemP) -> Outcome:
    t = p.target
    if t.kind == "document":
        d = documents.update_document(
            db,
            authz,
            t.id,
            name=p.new_name,
            folder_id=None,
            metadata=None,
            classification=None,
            expected_row_version=t.row_version,
        )
        name = d.name
    else:
        f = folders.update_folder(
            db,
            authz,
            t.id,
            name=p.new_name,
            parent_folder_id=None,
            expected_row_version=t.row_version,
        )
        name = f.name
    return f"Renamed to “{name}”.", {"id": str(t.id), "name": name}, "executed"


def ex_move(db: Session, authz: AuthorizationService, p: MoveCopyP) -> Outcome:
    refs = [ItemRef(kind=t.kind, id=t.id) for t in p.items]
    return _bulk(items.bulk_move(db, authz, refs, p.target_folder_id, p.on_conflict), "Move")


def ex_copy(db: Session, authz: AuthorizationService, p: MoveCopyP) -> Outcome:
    refs = [ItemRef(kind=t.kind, id=t.id) for t in p.items]
    return _bulk(items.bulk_copy(db, authz, refs, p.target_folder_id, p.on_conflict), "Copy")


def ex_trash(db: Session, authz: AuthorizationService, p: TrashP) -> Outcome:
    refs = [ItemRef(kind=t.kind, id=t.id) for t in p.items]
    return _bulk(items.bulk_delete(db, authz, refs), "Move to trash")


def ex_favorite(db: Session, authz: AuthorizationService, p: FavoriteP) -> Outcome:
    if p.target.kind == "document":
        documents.set_star(db, authz, p.target.id, p.on)
    else:
        items.set_folder_favorite(db, authz, p.target.id, p.on)
    return ("Added to Quick Access." if p.on else "Removed from Quick Access."), {}, "executed"


def ex_request_access(db: Session, authz: AuthorizationService, p: RequestAccessP) -> Outcome:
    out = access_requests.create(
        db,
        authz,
        AccessRequestCreate(
            resource_type=p.resource_type,
            resource_id=p.resource_id,
            actions=p.actions,
            reason=p.reason,
        ),
    )
    return (
        "Access request submitted.",
        {"access_request_id": str(out.id), "status": out.status},
        "executed",
    )


def ex_create_share(db: Session, authz: AuthorizationService, p: CreateShareP) -> Outcome:
    out = sharing.create_share(
        db,
        authz,
        ResourceType.DOCUMENT if p.resource_type == "document" else ResourceType.FOLDER,
        p.resource_id,
        ShareCreate(
            recipients=p.recipients, actions=p.actions, expires_at=p.expires_at, message=p.message
        ),
    )
    return "Share created.", {"share_id": str(out.id)}, "executed"


def ex_revoke_share(db: Session, authz: AuthorizationService, p: RevokeShareP) -> Outcome:
    out = sharing.revoke_share(db, authz, p.share_id)
    return (
        "Share revoked. Other access paths (folder permissions, groups, other shares) are unchanged.",
        {"share_id": str(out.id)},
        "executed",
    )


def ex_create_workflow(db: Session, authz: AuthorizationService, p: CreateWorkflowP) -> Outcome:
    out = workflows.create_definition(db, authz.principal, p.definition)
    return f"Workflow “{out.name}” created.", {"workflow_id": str(out.id)}, "executed"


def ex_start_run(db: Session, authz: AuthorizationService, p: StartRunP) -> Outcome:
    out = workflows.start_run(db, authz, p.document_id, p.definition_id, p.note)
    return "Submitted for approval.", {"run_id": str(out.id)}, "executed"


EXECUTORS: dict[str, Callable[[Session, AuthorizationService, Any], Outcome]] = {
    "create_folder": ex_create_folder,
    "rename_item": ex_rename,
    "move_items": ex_move,
    "copy_items": ex_copy,
    "trash_items": ex_trash,
    "favorite_item": ex_favorite,
    "request_access": ex_request_access,
    "create_share": ex_create_share,
    "revoke_share": ex_revoke_share,
    "create_workflow": ex_create_workflow,
    "start_workflow_run": ex_start_run,
}


def parse_payload(action_type: str, raw: dict[str, Any]) -> BaseModel:
    model = PAYLOADS.get(action_type)
    if model is None:
        raise NotFoundError("Unknown action type.")
    return model.model_validate(raw)
