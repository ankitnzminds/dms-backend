"""Per-folder approval chains on top of the existing workflow engine (no second engine).

An administrator configures *levels* of approvers for a folder (each person optionally ``optional`` or
``super approver``, groups expand to members). Saving compiles the chain into a versioned workflow
definition (one sequential step per level) and binds it to the folder. "Submit for approval" on a file
in that folder then starts that definition, so tasks, My approvals, delegation, resubmission, due dates
and audit are all the engine's own.

Rules (enforced by the engine, covered by tests): levels run in order; everyone in a level is asked in
parallel; a level is done when every *required* approver approved (a level of only optional approvers
needs one approval); a required approver's rejection halts the chain and rejects the document; an
optional approver's rejection is recorded only; a super approver's approval approves the document at
once and skips everyone still pending. Editing the chain creates a new definition version, so approvals
already in flight keep the chain they started with.
"""

from __future__ import annotations

import uuid

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError
from app.db.models import (
    Folder,
    FolderApprovalChain,
    User,
    WorkflowDefinition,
    WorkflowDefinitionVersion,
)
from app.modules import chain_plan
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.modules.workflows import service as wf
from app.schemas.workflows import (
    ApprovalChainIn,
    ApprovalChainOut,
    ApprovalChainSignerOut,
    AssigneeSpec,
    RunOut,
    StepSpec,
    WorkflowDefinitionIn,
)

DESCRIPTION = "Generated from the folder's approval chain. Change it on the Approval chains page."


def _binding(db: Session, org_id: uuid.UUID, folder_id: uuid.UUID) -> FolderApprovalChain | None:
    return db.scalar(
        select(FolderApprovalChain).where(
            FolderApprovalChain.organization_id == org_id,
            FolderApprovalChain.folder_id == folder_id,
        )
    )


def bound_definition_id(db: Session, org_id: uuid.UUID, folder_id: uuid.UUID) -> uuid.UUID | None:
    b = _binding(db, org_id, folder_id)
    if b is None:
        return None
    archived = db.scalar(
        select(WorkflowDefinition.archived_at).where(WorkflowDefinition.id == b.definition_id)
    )
    return None if archived is not None else b.definition_id


def _out(db: Session, folder_id: uuid.UUID, definition_id: uuid.UUID | None) -> ApprovalChainOut:
    if definition_id is None:
        return ApprovalChainOut(folder_id=folder_id, definition_id=None, levels=[])
    v = wf._latest_version(db, definition_id)  # noqa: SLF001
    steps = v.steps
    ids = {uuid.UUID(a["id"]) for st in steps for a in st["assignees"] if a.get("id")}
    users = {u.id: u for u in db.scalars(select(User).where(User.id.in_(ids)))}
    levels = [
        [
            ApprovalChainSignerOut(
                user_id=uuid.UUID(a["id"]),
                name=(users[uuid.UUID(a["id"])].display_name or users[uuid.UUID(a["id"])].email)
                if uuid.UUID(a["id"]) in users
                else "Unknown",
                email=users[uuid.UUID(a["id"])].email if uuid.UUID(a["id"]) in users else "",
                optional=bool(a.get("optional")),
                is_super_approver=bool(a.get("is_super_approver")),
            )
            for a in st["assignees"]
            if a["type"] == "user"
        ]
        for st in steps
    ]
    return ApprovalChainOut(folder_id=folder_id, definition_id=definition_id, levels=levels)


def get_chain(db: Session, authz: AuthorizationService, folder_id: uuid.UUID) -> ApprovalChainOut:
    from app.db.enums import Action

    folder = authz.require_folder(folder_id, Action.DISCOVER)
    return _out(db, folder.id, bound_definition_id(db, authz.principal.organization_id, folder.id))


def set_chain(
    db: Session, p: Principal, folder_id: uuid.UUID, body: ApprovalChainIn
) -> ApprovalChainOut:
    """Replace the folder's approval chain (administrators). An empty chain removes it."""
    if not p.is_admin:
        raise ForbiddenError("Only administrators can configure approval chains.")
    folder = db.scalar(
        select(Folder).where(Folder.id == folder_id, Folder.organization_id == p.organization_id)
    )
    if folder is None or folder.deleted_at is not None:
        raise NotFoundError("Folder not found.")
    existing = _binding(db, p.organization_id, folder.id)

    if not body.levels and not any(body.group_ids):  # clear the chain
        if existing is not None:
            wf.update_definition(
                db, p, existing.definition_id, name=None, description=None, archived=True
            )
            db.execute(delete(FolderApprovalChain).where(FolderApprovalChain.id == existing.id))
            audit.record(
                db,
                organization_id=p.organization_id,
                actor_user_id=p.user_id,
                action="folder.approval_chain.set",
                resource_type="folder",
                resource_id=folder.id,
                metadata={"levels": 0},
            )
            db.commit()
        return _out(db, folder.id, None)

    plan = chain_plan.plan_levels(
        db,
        p.organization_id,
        [[(e.user_id, e.optional, e.is_super_approver) for e in lv] for lv in body.levels],
        body.group_ids,
    )
    steps = [
        StepSpec(
            name=f"Level {i + 1}",
            rule="all",
            assignees=[
                AssigneeSpec(type="user", id=uid, optional=opt, is_super_approver=sup)
                for uid, (opt, sup) in level.items()
            ],
        )
        for i, level in enumerate(plan)
    ]
    if existing is not None and bound_definition_id(db, p.organization_id, folder.id):
        out = wf.add_version(db, p, existing.definition_id, steps)
        definition_id = out.id
    else:
        if existing is not None:  # the old definition was archived by someone: start a fresh one
            db.execute(delete(FolderApprovalChain).where(FolderApprovalChain.id == existing.id))
            db.flush()
        created = wf.create_definition(
            db,
            p,
            WorkflowDefinitionIn(
                name=f"Folder approval chain: {folder.name} ({folder.id.hex[:6]})",
                description=DESCRIPTION,
                steps=steps,
            ),
        )
        definition_id = created.id
        db.add(
            FolderApprovalChain(
                id=uuid.uuid4(),
                organization_id=p.organization_id,
                folder_id=folder.id,
                definition_id=definition_id,
                updated_by=p.user_id,
            )
        )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="folder.approval_chain.set",
        resource_type="folder",
        resource_id=folder.id,
        metadata={"levels": len(plan), "people": sum(len(lv) for lv in plan)},
    )
    db.commit()
    return _out(db, folder.id, definition_id)


def submit(
    db: Session, authz: AuthorizationService, document_id: uuid.UUID, note: str | None
) -> RunOut:
    """Start the approval chain of the document's folder (no approver to pick)."""
    from app.db.enums import Action

    doc = authz.require_document(document_id, Action.EDIT_METADATA)
    definition_id = bound_definition_id(db, authz.principal.organization_id, doc.folder_id)
    if definition_id is None:
        raise ConflictError(
            "This folder has no approval chain. Choose a workflow instead.", code="no_chain"
        )
    return wf.start_run(db, authz, doc.id, definition_id, note)


__all__ = ["bound_definition_id", "get_chain", "set_chain", "submit", "WorkflowDefinitionVersion"]
