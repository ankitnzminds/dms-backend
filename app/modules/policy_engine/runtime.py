"""Runtime hook between the authorization service and the pure evaluator.

The policy layer can only REMOVE actions from the set the ACL/share model already produced. It never
adds one, so a policy (or a bug in one) cannot grant access.

* enforce-mode DENY  -> the action is removed from the effective set (so every caller - single
  operations, list filtering, search, AI, hover hints - sees the same answer).
* observe-mode rules -> evaluated and written to the audit log only when a real operation is checked.
* organization administrators are subject to *mandatory* rules only (documented exception, so an
  ordinary DENY cannot lock the people who administer it out of their own tenant).
* a published revision that cannot be parsed fails the operation closed (``policy_config_error``).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.core.logging import get_logger
from app.db.enums import AuditOutcome
from app.db.models import Document, Membership, PolicyRevision, PolicyRule
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.policy_engine import evaluator as ev
from app.modules.policy_engine.schema import PolicyValidationError, parse_document

log = get_logger(__name__)

EXTERNAL_LEVELS = frozenset({"guest", "external"})
ANONYMOUS_USER = uuid.UUID(int=0)


class PolicyConfigError(AppError):
    status_code = 503
    code = "policy_config_error"


@dataclass(frozen=True)
class Loaded:
    rule: ev.Rule
    mode: str  # "enforce" | "observe"
    name: str


def refs(decision: ev.Decision) -> list[dict[str, object]]:
    """Stable, non-sensitive references to the policy revisions that decided."""
    out = [*decision.matched, *decision.errors]
    return [
        {
            "policy_id": str(m.policy_id),
            "revision": m.revision,
            "effect": m.effect,
            "mandatory": m.mandatory,
        }
        for m in out
    ]


def load_rules(db: Session, organization_id: uuid.UUID) -> list[Loaded]:
    rows = db.execute(
        select(PolicyRule, PolicyRevision)
        .join(
            PolicyRevision,
            (PolicyRevision.id == PolicyRule.published_revision_id)
            & (PolicyRevision.organization_id == PolicyRule.organization_id),
        )
        .where(PolicyRule.organization_id == organization_id, PolicyRule.status == "published")
    ).all()
    out: list[Loaded] = []
    for rule, rev in rows:
        try:
            doc = parse_document(rev.document)
        except (
            PolicyValidationError
        ) as e:  # immutable + validated before publish: should not happen
            log.error(
                "policy_unparsable", extra={"policy_id": str(rule.id), "revision": rev.revision}
            )
            raise PolicyConfigError(
                "An organization policy is misconfigured; this operation was blocked."
            ) from e
        out.append(Loaded(ev.Rule(rule.id, rev.revision, doc), rule.mode, rule.name))
    return out


def folder_chain_ids(
    db: Session, organization_id: uuid.UUID, folder_id: uuid.UUID
) -> frozenset[uuid.UUID]:
    from app.db.models import Folder

    out: set[uuid.UUID] = set()
    cur: uuid.UUID | None = folder_id
    for _ in range(100):
        if cur is None or cur in out:
            break
        out.add(cur)
        cur = db.scalar(
            select(Folder.parent_folder_id).where(
                Folder.id == cur, Folder.organization_id == organization_id
            )
        )
    return frozenset(out)


def anonymous_blocked(db: Session, organization_id: uuid.UUID, doc: Document, action: str) -> bool:
    """Would an enforcing policy deny ``action`` on this document for an anonymous link holder?

    The holder is evaluated as an external, role-less subject, so a policy aimed at external users
    also covers share links. Administrators' exemption does not apply: nobody on a link is an admin.
    """
    rules = [ld.rule for ld in load_rules(db, organization_id) if ld.mode == "enforce"]
    if not rules:
        return False
    res = ev.Resource(
        "document",
        doc.id,
        folder_chain_ids(db, organization_id, doc.folder_id),
        doc.classification,
        PurePosixPath(doc.name).suffix.lstrip(".").lower() or None,
        False,
    )
    subject = ev.Subject(ANONYMOUS_USER, "anonymous", frozenset(), "external", True)
    return ev.evaluate(rules, ev.EvalContext(subject, res, action)).outcome == "deny"


class PolicyRuntime:
    def __init__(self, db: Session, principal: Principal) -> None:
        self.db = db
        self.principal = principal
        self._rules: list[Loaded] | None = None
        self._access_level: str | None = None
        self._resources: dict[tuple[str, uuid.UUID], ev.Resource] = {}
        self._denials: dict[tuple[str, uuid.UUID, str], ev.Decision] = {}
        self._observed: set[tuple[str, uuid.UUID, str]] = set()

    # ---- inputs (all from trusted server state) ------------------------------------------------
    def rules(self) -> list[Loaded]:
        if self._rules is None:
            self._rules = load_rules(self.db, self.principal.organization_id)
        return self._rules

    def subject(self) -> ev.Subject:
        p = self.principal
        if self._access_level is None:
            self._access_level = (
                self.db.scalar(
                    select(Membership.access_level).where(
                        Membership.user_id == p.user_id,
                        Membership.organization_id == p.organization_id,
                    )
                )
                or "full"
            )
        return ev.Subject(
            p.user_id,
            p.role,
            frozenset(p.group_ids),
            self._access_level,
            self._access_level in EXTERNAL_LEVELS,
        )

    def _active(self, mode: str) -> list[ev.Rule]:
        admin = self.principal.is_admin
        return [
            ld.rule
            for ld in self.rules()
            if ld.mode == mode and (not admin or ld.rule.doc.mandatory)
        ]

    # ---- enforcement ---------------------------------------------------------------------------
    def restrict(
        self,
        folder_sets: dict[uuid.UUID, frozenset[str]],
        doc_sets: dict[uuid.UUID, frozenset[str]],
        documents: Sequence[Document],
        chains: dict[uuid.UUID, frozenset[uuid.UUID]],
    ) -> tuple[dict[uuid.UUID, frozenset[str]], dict[uuid.UUID, frozenset[str]]]:
        """Remove every action an enforcing DENY covers. ``chains``: folder id -> ids up to the root."""
        enforcing = self._active("enforce")
        watched = {a for r in enforcing for a in r.doc.actions}
        subject = self.subject()
        p = self.principal
        if enforcing:
            for fid, held in list(folder_sets.items()):
                res = ev.Resource(
                    "folder", fid, chains.get(fid, frozenset({fid})), None, None, False
                )
                folder_sets[fid] = self._cut("folder", fid, held, watched, enforcing, subject, res)
            for d in documents:
                res = ev.Resource(
                    "document",
                    d.id,
                    chains.get(d.folder_id, frozenset({d.folder_id})),
                    d.classification,
                    PurePosixPath(d.name).suffix.lstrip(".").lower() or None,
                    d.owner_id == p.user_id,
                )
                doc_sets[d.id] = self._cut(
                    "document",
                    d.id,
                    doc_sets.get(d.id, frozenset()),
                    watched,
                    enforcing,
                    subject,
                    res,
                )
        # remember context for observe-mode checks of single operations
        for fid in folder_sets:
            self._resources[("folder", fid)] = ev.Resource(
                "folder", fid, chains.get(fid, frozenset({fid})), None, None, False
            )
        for d in documents:
            self._resources[("document", d.id)] = ev.Resource(
                "document",
                d.id,
                chains.get(d.folder_id, frozenset({d.folder_id})),
                d.classification,
                PurePosixPath(d.name).suffix.lstrip(".").lower() or None,
                d.owner_id == p.user_id,
            )
        return folder_sets, doc_sets

    def _cut(
        self,
        rtype: str,
        rid: uuid.UUID,
        held: frozenset[str],
        watched: set[str],
        rules: list[ev.Rule],
        subject: ev.Subject,
        res: ev.Resource,
    ) -> frozenset[str]:
        out = set(held)
        for action in watched & held:
            d = ev.evaluate(rules, ev.EvalContext(subject, res, action))
            if d.outcome == "deny":
                out.discard(action)
                self._denials[(rtype, rid, action)] = d
        return frozenset(out)

    def denial(self, rtype: str, rid: uuid.UUID, action: str) -> ev.Decision | None:
        return self._denials.get((rtype, rid, action))

    # ---- shadow mode ---------------------------------------------------------------------------
    def observe(self, rtype: str, rid: uuid.UUID, action: str) -> None:
        """Record what observe-mode policies WOULD decide. Never changes the outcome."""
        key = (rtype, rid, action)
        rules = self._active("observe")
        res = self._resources.get((rtype, rid))
        if not rules or res is None or key in self._observed:
            return
        self._observed.add(key)
        d = ev.evaluate(rules, ev.EvalContext(self.subject(), res, action))
        if d.outcome == "no_opinion":
            return
        audit.record_independent(
            organization_id=self.principal.organization_id,
            actor_user_id=self.principal.user_id,
            action="policy.observed",
            resource_type=rtype,
            resource_id=rid,
            outcome=AuditOutcome.SUCCESS,
            metadata={
                "requested_action": action,
                "would_be": d.outcome,
                "reason": d.reason,
                "policies": refs(d),
                "enforced": False,
            },
        )
