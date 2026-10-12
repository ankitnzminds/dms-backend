"""Policy lifecycle: create, edit, validate, publish, disable, archive, roll back, compare.

Capabilities (existing RBAC roles; no second admin mechanism):
  * view policies & history ........ owner, admin, auditor
  * create/edit/validate/publish/disable/archive organization policies ... owner, admin
  * create/publish/disable *mandatory* (security) policies ................. owner only
Published revisions are immutable (also enforced by a DB trigger); editing opens a new draft
revision, and rolling back publishes nothing - it creates a new draft copy of an old revision.
Every state change writes an audit event in the same transaction.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, ForbiddenError, NotFoundError, ValidationFailed
from app.db.enums import MembershipStatus, Role
from app.db.models import (
    Document,
    Folder,
    Group,
    GroupMembership,
    Membership,
    PolicyRevision,
    PolicyRule,
)
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.policy_engine.schema import PolicyDoc, PolicyValidationError, parse_document
from app.schemas.policy_rules import (
    PolicyDetail,
    PolicyIssue,
    PolicyOut,
    PolicyValidationReport,
    RevisionDiff,
    RevisionOut,
)

OWNER_ONLY_MSG = "Only an organization owner can manage mandatory security policies."
APPROVAL_UNAVAILABLE = (
    "REQUIRE_APPROVAL cannot be enforced yet: the application cannot hold an operation until it is "
    "approved. Publish it in observe mode to see where it would apply, or use DENY."
)


# ---- capabilities --------------------------------------------------------------------------------
def _require_manage(p: Principal) -> None:
    if not p.is_admin:
        raise ForbiddenError("Administrator access is required to manage policies.")


def _require_view(p: Principal) -> None:
    if not p.can_read_audit:
        raise ForbiddenError("Policy access is restricted to administrators and auditors.")


def _require_mandatory_right(p: Principal, mandatory: bool) -> None:
    if mandatory and p.role != Role.OWNER.value:
        raise ForbiddenError(OWNER_ONLY_MSG)


# ---- helpers -------------------------------------------------------------------------------------
def _parse(document: dict[str, Any]) -> PolicyDoc:
    try:
        return parse_document(document)
    except PolicyValidationError as e:
        raise ValidationFailed(
            "The policy is not valid.",
            details=[{"path": i.path, "message": i.message} for i in e.issues],
            code="policy_invalid",
        ) from e


def _locked(db: Session, p: Principal, policy_id: uuid.UUID) -> PolicyRule:
    rule = db.scalar(
        select(PolicyRule)
        .where(PolicyRule.id == policy_id, PolicyRule.organization_id == p.organization_id)
        .with_for_update()
    )
    if rule is None:
        raise NotFoundError("Policy not found.")
    return rule


def _revisions(db: Session, rule: PolicyRule) -> list[PolicyRevision]:
    return list(
        db.scalars(
            select(PolicyRevision)
            .where(
                PolicyRevision.policy_id == rule.id,
                PolicyRevision.organization_id == rule.organization_id,
            )
            .order_by(PolicyRevision.revision)
        )
    )


def _latest(revs: list[PolicyRevision]) -> PolicyRevision:
    return revs[-1]


def _rev_out(r: PolicyRevision) -> RevisionOut:
    return RevisionOut.model_validate(r)


def _out(rule: PolicyRule, revs: list[PolicyRevision]) -> PolicyOut:
    latest = _latest(revs)
    shown = next((r for r in revs if r.id == rule.published_revision_id), latest)
    pub = next((r.revision for r in revs if r.id == rule.published_revision_id), None)
    return PolicyOut(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        category=rule.category,
        owner_kind=rule.owner_kind,  # type: ignore[arg-type]
        owner_user_id=rule.owner_user_id,
        status=rule.status,  # type: ignore[arg-type]
        mode=rule.mode,  # type: ignore[arg-type]
        mandatory=rule.mandatory,
        template_key=rule.template_key,
        published_revision=pub,
        latest_revision=latest.revision,
        latest_revision_status=latest.status,  # type: ignore[arg-type]
        effect=shown.document.get("effect"),
        actions=list(shown.document.get("actions") or []),
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )


def _audit(db: Session, p: Principal, action: str, rule: PolicyRule, **meta: Any) -> None:
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action=action,
        resource_type="policy",
        resource_id=rule.id,
        metadata={"name": rule.name, "mandatory": rule.mandatory, **meta},
    )


def _new_revision(
    db: Session, rule: PolicyRule, document: dict[str, Any], p: Principal, reason: str | None
) -> PolicyRevision:
    last = db.scalar(
        select(func.max(PolicyRevision.revision)).where(PolicyRevision.policy_id == rule.id)
    )
    rev = PolicyRevision(
        id=uuid.uuid4(),
        organization_id=rule.organization_id,
        policy_id=rule.id,
        revision=(last or 0) + 1,
        document=document,
        status="draft",
        change_reason=reason,
        created_by=p.user_id,
    )
    db.add(rev)
    db.flush()
    return rev


# ---- queries -------------------------------------------------------------------------------------
def list_policies(
    db: Session,
    p: Principal,
    *,
    status: str | None,
    q: str | None,
    limit: int,
    offset: int,
) -> tuple[list[PolicyOut], int]:
    _require_view(p)
    stmt = select(PolicyRule).where(
        PolicyRule.organization_id == p.organization_id, PolicyRule.owner_kind == "organization"
    )
    if status:
        stmt = stmt.where(PolicyRule.status == status)
    if q:
        stmt = stmt.where(PolicyRule.name.ilike(f"%{q.strip()}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rules = list(
        db.scalars(
            stmt.order_by(PolicyRule.updated_at.desc(), PolicyRule.id).limit(limit).offset(offset)
        )
    )
    out = [_out(r, _revisions(db, r)) for r in rules]
    return out, int(total)


def get_policy(db: Session, p: Principal, policy_id: uuid.UUID) -> PolicyDetail:
    _require_view(p)
    rule = db.scalar(
        select(PolicyRule).where(
            PolicyRule.id == policy_id, PolicyRule.organization_id == p.organization_id
        )
    )
    if rule is None:
        raise NotFoundError("Policy not found.")
    revs = _revisions(db, rule)
    return PolicyDetail(**_out(rule, revs).model_dump(), revisions=[_rev_out(r) for r in revs])


# ---- lifecycle -----------------------------------------------------------------------------------
def create(
    db: Session,
    p: Principal,
    *,
    name: str,
    description: str | None,
    category: str,
    document: dict[str, Any],
    change_reason: str | None,
    template_key: str | None = None,
) -> PolicyDetail:
    _require_manage(p)
    doc = _parse(document)
    _require_mandatory_right(p, doc.mandatory)
    clash = db.scalar(
        select(PolicyRule.id).where(
            PolicyRule.organization_id == p.organization_id,
            func.lower(PolicyRule.name) == name.strip().lower(),
            PolicyRule.status != "archived",
        )
    )
    if clash:
        raise ConflictError("A policy with this name already exists.", code="policy_name_taken")
    rule = PolicyRule(
        id=uuid.uuid4(),
        organization_id=p.organization_id,
        name=name.strip(),
        description=description,
        category=category,
        owner_kind="organization",
        owner_user_id=p.user_id,
        status="draft",
        mode="enforce",
        mandatory=doc.mandatory,
        template_key=template_key,
        created_by=p.user_id,
        updated_by=p.user_id,
    )
    db.add(rule)
    db.flush()
    _new_revision(db, rule, document, p, change_reason)
    _audit(db, p, "policy.created", rule, revision=1, effect=doc.effect)
    db.commit()
    return get_policy(db, p, rule.id)


def update_draft(
    db: Session,
    p: Principal,
    policy_id: uuid.UUID,
    *,
    name: str | None,
    description: str | None,
    document: dict[str, Any] | None,
    change_reason: str | None,
) -> PolicyDetail:
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    if rule.status == "archived":
        raise ConflictError("An archived policy cannot be edited.", code="policy_archived")
    revs = _revisions(db, rule)
    latest = _latest(revs)
    if rule.mandatory:
        _require_mandatory_right(p, True)
    if name is not None and name.strip():
        rule.name = name.strip()
    if description is not None:
        rule.description = description
    changed_rev = latest.revision
    if document is not None:
        doc = _parse(document)
        _require_mandatory_right(p, doc.mandatory or rule.mandatory)
        if latest.status in ("draft", "validated"):
            latest.document = document  # still a working draft: edit in place
            latest.status = "draft"
            latest.validated_at = None
            if change_reason:
                latest.change_reason = change_reason
        else:  # latest is published/superseded: immutable -> open a new draft revision
            latest = _new_revision(db, rule, document, p, change_reason)
            changed_rev = latest.revision
    rule.updated_by = p.user_id
    _audit(
        db, p, "policy.updated", rule, revision=changed_rev, document_changed=document is not None
    )
    db.commit()
    return get_policy(db, p, rule.id)


def _refs_and_impact(
    db: Session, p: Principal, doc: PolicyDoc, rule: PolicyRule
) -> tuple[list[PolicyIssue], list[str], int | None, str | None]:
    org = p.organization_id
    issues: list[PolicyIssue] = []
    warnings: list[str] = []
    t = doc.subjects
    if t.users:
        found = set(
            db.scalars(
                select(Membership.user_id).where(
                    Membership.organization_id == org,
                    Membership.user_id.in_(t.users),
                    Membership.status != MembershipStatus.REMOVED.value,
                )
            )
        )
        for u in t.users - found:
            issues.append(
                PolicyIssue(path="subjects.users", message=f"user {u} is not in this organization")
            )
    if t.groups:
        found_g = set(
            db.scalars(select(Group.id).where(Group.organization_id == org, Group.id.in_(t.groups)))
        )
        for g in t.groups - found_g:
            issues.append(
                PolicyIssue(
                    path="subjects.groups", message=f"group {g} is not in this organization"
                )
            )
    scope_name: str | None = None
    if doc.scope_type == "folder" and doc.scope_id:
        scope_name = db.scalar(
            select(Folder.name).where(Folder.id == doc.scope_id, Folder.organization_id == org)
        )
    elif doc.scope_type == "file" and doc.scope_id:
        scope_name = db.scalar(
            select(Document.name).where(
                Document.id == doc.scope_id, Document.organization_id == org
            )
        )
    if doc.scope_type != "organization" and scope_name is None:
        issues.append(
            PolicyIssue(
                path="scope.id", message=f"the {doc.scope_type} does not exist in this organization"
            )
        )
    affected: int | None
    if t.everyone:
        affected = db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.organization_id == org,
                Membership.status == MembershipStatus.ACTIVE.value,
            )
        )
    else:
        ids: set[uuid.UUID] = set(t.users)
        if t.groups:
            ids |= set(
                db.scalars(
                    select(GroupMembership.user_id).where(
                        GroupMembership.organization_id == org,
                        GroupMembership.group_id.in_(t.groups),
                    )
                )
            )
        by_attr = select(Membership.user_id).where(
            Membership.organization_id == org, Membership.status == MembershipStatus.ACTIVE.value
        )
        if t.roles:
            ids |= set(db.scalars(by_attr.where(Membership.role.in_(t.roles))))
        if t.access_levels:
            ids |= set(db.scalars(by_attr.where(Membership.access_level.in_(t.access_levels))))
        affected = len(ids)
    # overlap with other published rules of a different effect: deny wins, but tell the author
    others = db.execute(
        select(PolicyRule, PolicyRevision)
        .join(PolicyRevision, PolicyRevision.id == PolicyRule.published_revision_id)
        .where(
            PolicyRule.organization_id == org,
            PolicyRule.status == "published",
            PolicyRule.id != rule.id,
        )
    ).all()
    for o_rule, o_rev in others:
        od = o_rev.document
        if (
            set(od.get("actions") or []) & doc.actions
            and set(od.get("resource_types") or []) & doc.resource_types
            and od.get("effect") != doc.effect
        ):
            warnings.append(
                f"Overlaps with “{o_rule.name}” ({od.get('effect')}); DENY wins over "
                "REQUIRE_APPROVAL, and ALLOW never lifts either."
            )
    if doc.effect == "ALLOW":
        warnings.append(
            "ALLOW policies are recorded for explanation only: they never grant a permission "
            "and never lift a DENY or approval requirement."
        )
    return issues, warnings, affected, scope_name


def validate(db: Session, p: Principal, policy_id: uuid.UUID) -> PolicyValidationReport:
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    revs = _revisions(db, rule)
    latest = _latest(revs)
    if latest.status in ("published", "superseded"):
        raise ConflictError(
            "Nothing to validate: edit the policy to open a new draft.", code="no_draft"
        )
    try:
        doc = parse_document(latest.document)
    except PolicyValidationError as e:
        return PolicyValidationReport(
            valid=False,
            issues=[PolicyIssue(path=i.path, message=i.message) for i in e.issues],
            warnings=[],
            revision=latest.revision,
        )
    issues, warnings, affected, scope_name = _refs_and_impact(db, p, doc, rule)
    if doc.mandatory:
        _require_mandatory_right(p, True)
    if not issues:
        latest.status = "validated"
        latest.validated_at = datetime.now(UTC)
    _audit(db, p, "policy.validated", rule, revision=latest.revision, valid=not issues)
    db.commit()
    return PolicyValidationReport(
        valid=not issues,
        issues=issues,
        warnings=warnings,
        affected_members=affected,
        scope_name=scope_name,
        revision=latest.revision,
    )


def publish(
    db: Session, p: Principal, policy_id: uuid.UUID, *, mode: str, change_reason: str | None
) -> PolicyDetail:
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    if rule.status == "archived":
        raise ConflictError("An archived policy cannot be published.", code="policy_archived")
    revs = _revisions(db, rule)
    latest = _latest(revs)
    if latest.status != "validated":
        raise ConflictError(
            "Validate the latest draft before publishing it.", code="policy_not_validated"
        )
    doc = _parse(latest.document)  # re-check: never publish what does not parse now
    _require_mandatory_right(p, doc.mandatory or rule.mandatory)
    if doc.effect == "REQUIRE_APPROVAL" and mode == "enforce":
        raise ConflictError(APPROVAL_UNAVAILABLE, code="approval_not_available")
    issues, _, _, _ = _refs_and_impact(db, p, doc, rule)
    if issues:
        raise ValidationFailed(
            "The policy refers to things that no longer exist.",
            details=[i.model_dump() for i in issues],
            code="policy_invalid",
        )
    for r in revs:
        if r.status == "published":
            r.status = "superseded"
    latest.status = "published"
    latest.published_by = p.user_id
    latest.published_at = datetime.now(UTC)
    if change_reason:
        latest.change_reason = change_reason
    rule.status = "published"
    rule.mode = mode
    rule.mandatory = doc.mandatory
    rule.published_revision_id = latest.id
    rule.updated_by = p.user_id
    _audit(
        db,
        p,
        "policy.published",
        rule,
        revision=latest.revision,
        mode=mode,
        effect=doc.effect,
        change_reason=change_reason,
    )
    db.commit()
    return get_policy(db, p, rule.id)


def set_mode(db: Session, p: Principal, policy_id: uuid.UUID, mode: str) -> PolicyDetail:
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    _require_mandatory_right(p, rule.mandatory)
    if rule.status != "published":
        raise ConflictError(
            "Only a published policy has an enforcement mode.", code="not_published"
        )
    if mode == "enforce" and rule.published_revision_id is not None:
        pub = db.scalar(
            select(PolicyRevision.document).where(PolicyRevision.id == rule.published_revision_id)
        )
        if pub and pub.get("effect") == "REQUIRE_APPROVAL":
            raise ConflictError(APPROVAL_UNAVAILABLE, code="approval_not_available")
    old, rule.mode = rule.mode, mode
    rule.updated_by = p.user_id
    _audit(db, p, "policy.mode_changed", rule, old_mode=old, new_mode=mode)
    db.commit()
    return get_policy(db, p, rule.id)


def disable(db: Session, p: Principal, policy_id: uuid.UUID, reason: str | None) -> PolicyDetail:
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    _require_mandatory_right(p, rule.mandatory)
    if rule.status != "published":
        raise ConflictError("Only a published policy can be disabled.", code="not_published")
    rule.status = "disabled"
    rule.updated_by = p.user_id
    _audit(db, p, "policy.disabled", rule, reason=reason)
    db.commit()
    return get_policy(db, p, rule.id)


def enable(db: Session, p: Principal, policy_id: uuid.UUID) -> PolicyDetail:
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    _require_mandatory_right(p, rule.mandatory)
    if rule.status != "disabled" or rule.published_revision_id is None:
        raise ConflictError("Only a disabled policy can be re-enabled.", code="not_disabled")
    rule.status = "published"
    rule.updated_by = p.user_id
    _audit(db, p, "policy.enabled", rule)
    db.commit()
    return get_policy(db, p, rule.id)


def archive(db: Session, p: Principal, policy_id: uuid.UUID) -> PolicyDetail:
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    _require_mandatory_right(p, rule.mandatory)
    if rule.status == "published":
        raise ConflictError("Disable the policy before archiving it.", code="disable_first")
    rule.status = "archived"
    rule.updated_by = p.user_id
    _audit(db, p, "policy.archived", rule)
    db.commit()
    return get_policy(db, p, rule.id)


def rollback(
    db: Session, p: Principal, policy_id: uuid.UUID, *, to_revision: int, reason: str
) -> PolicyDetail:
    """Rolling back = a NEW draft revision with the old content. It still has to be validated and published."""
    _require_manage(p)
    rule = _locked(db, p, policy_id)
    _require_mandatory_right(p, rule.mandatory)
    if rule.status == "archived":
        raise ConflictError("An archived policy cannot be edited.", code="policy_archived")
    revs = _revisions(db, rule)
    old = next((r for r in revs if r.revision == to_revision), None)
    if old is None:
        raise NotFoundError("Revision not found.")
    latest = _latest(revs)
    if latest.status in ("draft", "validated"):
        raise ConflictError(
            "Finish or discard the current draft before rolling back.", code="draft_open"
        )
    new = _new_revision(
        db, rule, dict(old.document), p, f"Rollback to revision {to_revision}: {reason}"
    )
    _audit(db, p, "policy.rolled_back", rule, from_revision=to_revision, new_revision=new.revision)
    db.commit()
    return get_policy(db, p, rule.id)


def compare(db: Session, p: Principal, policy_id: uuid.UUID, a: int, b: int) -> RevisionDiff:
    _require_view(p)
    detail = get_policy(db, p, policy_id)
    ra = next((r for r in detail.revisions if r.revision == a), None)
    rb = next((r for r in detail.revisions if r.revision == b), None)
    if ra is None or rb is None:
        raise NotFoundError("Revision not found.")
    changes = [
        {"field": k, "from": ra.document.get(k), "to": rb.document.get(k)}
        for k in sorted(set(ra.document) | set(rb.document))
        if ra.document.get(k) != rb.document.get(k)
    ]
    return RevisionDiff(from_revision=a, to_revision=b, changes=changes)
