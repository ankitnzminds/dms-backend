"""Non-destructive policy simulation ("what would happen if ...").

It only READS: it rebuilds the target user's Principal from current server state, asks the ACL/share
model what they hold, then asks the policy engine - optionally with one unpublished draft included.
It never grants, approves, changes or executes anything, and its output is labelled ``simulated``.
"""

from __future__ import annotations

import uuid
from pathlib import PurePosixPath
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ForbiddenError, NotFoundError
from app.db.models import Document, Folder, PolicyRevision, PolicyRule, User
from app.modules.audit import service as audit
from app.modules.authorization.service import AuthorizationService
from app.modules.identity.principal import Principal
from app.modules.identity.service import principal_for
from app.modules.policy_engine import evaluator as ev
from app.modules.policy_engine.runtime import PolicyRuntime, folder_chain_ids, load_rules
from app.modules.policy_engine.schema import PolicyValidationError, parse_document
from app.schemas.common import ApiModel


class SimulationIn(ApiModel):
    user_id: uuid.UUID
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    action: str
    # include this policy's latest (draft/validated) revision as if it were published and enforcing
    draft_policy_id: uuid.UUID | None = None


class MatchedPolicy(ApiModel):
    policy_id: uuid.UUID
    name: str
    revision: int
    effect: str
    mandatory: bool
    source: Literal["published", "draft"]
    mode: Literal["enforce", "observe"]


class SimulationOut(ApiModel):
    simulated: Literal[True] = True
    user_id: uuid.UUID
    user_email: str
    resource_type: Literal["document", "folder"]
    resource_id: uuid.UUID
    resource_name: str
    action: str
    holds_permission: bool
    outcome: Literal["allow", "deny", "require_approval"]
    reason: str
    matched: list[MatchedPolicy]
    observed_only: list[MatchedPolicy]
    notes: list[str]


def simulate(db: Session, p: Principal, body: SimulationIn) -> SimulationOut:
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required to simulate policies.")
    org = p.organization_id
    target = principal_for(db, body.user_id, org)  # fails closed for a suspended/removed user
    email = db.scalar(select(User.email).where(User.id == target.user_id)) or ""
    doc_obj: Document | None = None
    if body.resource_type == "document":
        doc_obj = db.scalar(
            select(Document).where(Document.id == body.resource_id, Document.organization_id == org)
        )
        if doc_obj is None:
            raise NotFoundError("Resource not found.")
        name, folder_id, classification = doc_obj.name, doc_obj.folder_id, doc_obj.classification
        owned = doc_obj.owner_id == target.user_id
    else:
        folder_obj = db.scalar(
            select(Folder).where(Folder.id == body.resource_id, Folder.organization_id == org)
        )
        if folder_obj is None:
            raise NotFoundError("Resource not found.")
        name, folder_id, classification, owned = folder_obj.name, folder_obj.id, None, False

    authz = AuthorizationService(db, target)
    rid = body.resource_id
    if doc_obj is not None:
        acl = authz._effective_acl(folder_ids=[], documents=[doc_obj])[1].get(rid, frozenset())  # noqa: SLF001
    else:
        acl = authz._effective_acl(folder_ids=[rid], documents=[])[0].get(rid, frozenset())  # noqa: SLF001
    holds = body.action in acl

    runtime = PolicyRuntime(db, target)
    loaded = list(load_rules(db, org))
    meta: dict[tuple[uuid.UUID, int], tuple[str, str, str]] = {
        (ld.rule.policy_id, ld.rule.revision): (ld.name, ld.mode, "published") for ld in loaded
    }
    rules = [ld.rule for ld in loaded]
    modes = {(ld.rule.policy_id, ld.rule.revision): ld.mode for ld in loaded}
    notes: list[str] = []
    if body.draft_policy_id:
        pol = db.scalar(
            select(PolicyRule).where(
                PolicyRule.id == body.draft_policy_id, PolicyRule.organization_id == org
            )
        )
        if pol is None:
            raise NotFoundError("Policy not found.")
        rev = db.scalar(
            select(PolicyRevision)
            .where(PolicyRevision.policy_id == pol.id)
            .order_by(PolicyRevision.revision.desc())
            .limit(1)
        )
        try:
            doc = parse_document(rev.document) if rev else None
        except PolicyValidationError as e:
            raise NotFoundError("The draft is not valid; fix it before simulating.") from e
        if doc is not None and rev is not None:
            # replace the policy's published revision (if any) by the draft, as publishing would
            rules = [r for r in rules if r.policy_id != pol.id]
            rules.append(ev.Rule(pol.id, rev.revision, doc))
            meta[(pol.id, rev.revision)] = (pol.name, "enforce", "draft")
            modes[(pol.id, rev.revision)] = "enforce"
            notes.append("The draft is simulated as if it were published in enforce mode.")

    if target.is_admin:
        rules = [r for r in rules if r.doc.mandatory]
        notes.append("Administrators are subject to mandatory policies only.")

    resource = ev.Resource(
        body.resource_type,
        body.resource_id,
        folder_chain_ids(db, org, folder_id),
        classification,
        (PurePosixPath(name).suffix.lstrip(".").lower() or None)
        if body.resource_type == "document"
        else None,
        owned,
    )
    ctx = ev.EvalContext(runtime.subject(), resource, body.action)
    enforce_rules = [
        r for r in rules if modes.get((r.policy_id, r.revision), "enforce") == "enforce"
    ]
    observe_rules = [r for r in rules if modes.get((r.policy_id, r.revision)) == "observe"]
    decision = ev.evaluate(enforce_rules, ctx)
    observed = ev.evaluate(observe_rules, ctx) if observe_rules else None

    def show(ms: tuple[ev.Match, ...] | list[ev.Match]) -> list[MatchedPolicy]:
        out: list[MatchedPolicy] = []
        for m in ms:
            nm, mode, src = meta.get(
                (m.policy_id, m.revision), ("(unknown)", "enforce", "published")
            )
            out.append(
                MatchedPolicy(
                    policy_id=m.policy_id,
                    name=nm,
                    revision=m.revision,
                    effect=m.effect,
                    mandatory=m.mandatory,
                    source=src,  # type: ignore[arg-type]
                    mode=mode,  # type: ignore[arg-type]
                )
            )
        return out

    if not holds:
        outcome, reason = "deny", "ACL_PERMISSION_MISSING"
        notes.append(
            "The user does not hold this permission through ACLs or shares; a policy cannot grant it."
        )
    elif decision.outcome == "deny":
        outcome, reason = "deny", decision.reason
    elif decision.outcome == "require_approval":
        outcome, reason = "require_approval", decision.reason
    else:
        outcome, reason = "allow", decision.reason
    audit.record(
        db,
        organization_id=org,
        actor_user_id=p.user_id,
        action="policy.simulated",
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        metadata={
            "subject_user_id": str(body.user_id),
            "requested_action": body.action,
            "outcome": outcome,
            "reason": reason,
            "draft_policy_id": str(body.draft_policy_id) if body.draft_policy_id else None,
        },
    )
    db.commit()
    return SimulationOut(
        user_id=target.user_id,
        user_email=email,
        resource_type=body.resource_type,
        resource_id=body.resource_id,
        resource_name=name,
        action=body.action,
        holds_permission=holds,
        outcome=outcome,  # type: ignore[arg-type]
        reason=reason,
        matched=show(list(decision.matched) + list(decision.errors)),
        observed_only=show(list(observed.matched)) if observed else [],
        notes=notes,
    )
