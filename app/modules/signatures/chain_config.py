"""Per-folder signature chain configuration (administrators) and lookup for requests."""

from __future__ import annotations

import uuid
from collections import defaultdict

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError
from app.db.enums import Action
from app.db.models import Folder, SignatureChainStep, User
from app.modules import chain_plan
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.schemas.signatures import ChainIn, ChainOut, ChainSignerOut


def steps_for_folder(
    db: Session, org_id: uuid.UUID, folder_id: uuid.UUID
) -> list[SignatureChainStep]:
    """The folder's own chain (like the reference app, chains are not inherited by subfolders)."""
    return list(
        db.scalars(
            select(SignatureChainStep)
            .where(
                SignatureChainStep.organization_id == org_id,
                SignatureChainStep.folder_id == folder_id,
            )
            .order_by(
                SignatureChainStep.level, SignatureChainStep.created_at, SignatureChainStep.id
            )
        )
    )


def chain_users(
    db: Session, org_id: uuid.UUID, steps: list[SignatureChainStep]
) -> dict[uuid.UUID, User]:
    """The chain's signers, who must STILL be active members; otherwise the request is refused."""
    users = chain_plan.active_users(db, org_id, {s.user_id for s in steps})
    gone = {s.user_id for s in steps} - set(users)
    if gone:
        raise ConflictError(
            "The signature chain of this folder contains someone who is no longer an active member. "
            "An administrator needs to update the chain.",
            code="chain_signer_inactive",
        )
    return users


def _out(db: Session, folder_id: uuid.UUID, steps: list[SignatureChainStep]) -> ChainOut:
    users = {
        u.id: u for u in db.scalars(select(User).where(User.id.in_({s.user_id for s in steps})))
    }
    by_level: dict[int, list[ChainSignerOut]] = defaultdict(list)
    for s in steps:
        u = users.get(s.user_id)
        by_level[s.level].append(
            ChainSignerOut(
                user_id=s.user_id,
                name=(u.display_name if u else None) or (u.email if u else "Unknown"),
                email=u.email if u else "",
                optional=s.optional,
                is_super_signer=s.is_super_signer,
            )
        )
    return ChainOut(folder_id=folder_id, levels=[by_level[k] for k in sorted(by_level)])


def get_chain(db: Session, authz: AuthorizationService, folder_id: uuid.UUID) -> ChainOut:
    folder = authz.require_folder(folder_id, Action.DISCOVER)
    return _out(db, folder.id, steps_for_folder(db, folder.organization_id, folder.id))


def set_chain(db: Session, p: Principal, folder_id: uuid.UUID, body: ChainIn) -> ChainOut:
    """Replace the folder's chain (administrators). An empty chain removes it."""
    if not p.is_admin:
        raise ForbiddenError("Only administrators can configure signature chains.")
    folder = db.scalar(
        select(Folder).where(Folder.id == folder_id, Folder.organization_id == p.organization_id)
    )
    if folder is None or folder.deleted_at is not None:
        raise NotFoundError("Folder not found.")
    plan = chain_plan.plan_levels(
        db,
        p.organization_id,
        [[(e.user_id, e.optional, e.is_super_signer) for e in lv] for lv in body.levels],
        body.group_ids,
    )
    total = sum(len(level) for level in plan)

    db.execute(
        delete(SignatureChainStep).where(
            SignatureChainStep.organization_id == p.organization_id,
            SignatureChainStep.folder_id == folder.id,
        )
    )
    for i, level in enumerate(plan):
        for uid, (optional, sup) in level.items():
            db.add(
                SignatureChainStep(
                    id=uuid.uuid4(),
                    organization_id=p.organization_id,
                    folder_id=folder.id,
                    level=i + 1,
                    user_id=uid,
                    optional=optional,
                    is_super_signer=sup,
                    created_by=p.user_id,
                )
            )
    db.flush()
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="folder.signature_chain.set",
        resource_type="folder",
        resource_id=folder.id,
        metadata={"levels": len(plan), "signers": total},
    )
    db.commit()
    return _out(db, folder.id, steps_for_folder(db, p.organization_id, folder.id))
