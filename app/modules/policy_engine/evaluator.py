"""Pure, deterministic policy evaluation (no database, no I/O, no clock).

Precedence (one place, documented in docs/security/policy-engine.md):

    1. a matching *mandatory* DENY                       -> deny   POLICY_MANDATORY_DENY
    2. a matching DENY                                    -> deny   POLICY_DENY
    3. a rule whose context is incomplete (fail closed)   -> deny   POLICY_CONTEXT_MISSING
    4. a matching REQUIRE_APPROVAL                        -> require_approval
    5. otherwise                                          -> no_opinion

``no_opinion`` means "the policy layer adds no restriction"; it NEVER grants access. ALLOW policies are
matched and reported (for explanation and the simulator) but they cannot lift a DENY or an approval
requirement and cannot create a missing resource permission. The caller must already hold the
permission from the ACL/share model before the policy layer is consulted.

Every matching rule is reported, never just the first, and rules are visited in a stable order so the
same inputs and policy revisions always give the same answer.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.modules.policy_engine.schema import Combine, Condition, Leaf, PolicyDoc

MANDATORY_DENY = "POLICY_MANDATORY_DENY"
DENY = "POLICY_DENY"
CONTEXT_MISSING = "POLICY_CONTEXT_MISSING"
APPROVAL_REQUIRED = "POLICY_APPROVAL_REQUIRED"
NO_OPINION = "POLICY_NONE_APPLIED"


@dataclass(frozen=True)
class Subject:
    user_id: uuid.UUID
    role: str
    group_ids: frozenset[uuid.UUID]
    access_level: str
    # resolved by the trusted builder from access_level, never supplied by a client
    is_external: bool


@dataclass(frozen=True)
class Resource:
    type: str  # "document" | "folder"
    id: uuid.UUID
    # ids of the folder itself (for a folder) or of the containing folder, then every ancestor
    folder_chain: frozenset[uuid.UUID]
    classification: str | None = None
    file_extension: str | None = None
    owner_is_subject: bool = False


@dataclass(frozen=True)
class EvalContext:
    subject: Subject
    resource: Resource
    action: str


@dataclass(frozen=True)
class Rule:
    policy_id: uuid.UUID
    revision: int
    doc: PolicyDoc


@dataclass(frozen=True)
class Match:
    policy_id: uuid.UUID
    revision: int
    effect: str
    mandatory: bool


@dataclass(frozen=True)
class Decision:
    outcome: str  # "deny" | "require_approval" | "no_opinion"
    reason: str
    matched: tuple[Match, ...] = ()
    errors: tuple[Match, ...] = ()
    allow_matched: tuple[Match, ...] = field(default=())

    @property
    def denied(self) -> bool:
        return self.outcome == "deny"


class _Missing(Exception):
    """A condition needs a value the trusted context did not provide."""


def _attribute(ctx: EvalContext, name: str) -> object | None:
    s, r = ctx.subject, ctx.resource
    return {
        "resource.classification": r.classification,
        "resource.file_extension": r.file_extension,
        "resource.owner_is_subject": r.owner_is_subject,
        "subject.role": s.role,
        "subject.access_level": s.access_level,
        "subject.is_external": s.is_external,
    }[name]


def _eval(cond: Condition, ctx: EvalContext) -> bool:
    if isinstance(cond, Combine):
        results = (_eval(c, ctx) for c in cond.conditions)
        return all(results) if cond.op == "AND" else any(results)
    assert isinstance(cond, Leaf)
    value = _attribute(ctx, cond.attribute)
    if cond.operator == "EXISTS":
        return value is not None
    if cond.operator == "NOT_EXISTS":
        return value is None
    if value is None:
        # Unknown is never "equal" and never "not equal": the author must see a failure, not a guess.
        raise _Missing(cond.attribute)
    if isinstance(value, str):
        value = value.lower()
    if cond.operator in ("EQUALS", "NOT_EQUALS"):
        expected = cond.value.lower() if isinstance(cond.value, str) else cond.value
        return (value == expected) == (cond.operator == "EQUALS")
    options = {v.lower() for v in cond.value}
    return (value in options) == (cond.operator == "IN")


def applies(rule: Rule, ctx: EvalContext) -> bool:
    """Scope, subject, resource type and action targeting (before conditions)."""
    d, s, r = rule.doc, ctx.subject, ctx.resource
    if ctx.action not in d.actions or r.type not in d.resource_types:
        return False
    if d.scope_type != "organization":
        if d.scope_id is None:
            return False
        if d.scope_type == "file" and not (r.type == "document" and r.id == d.scope_id):
            return False
        if d.scope_type == "folder" and d.scope_id not in r.folder_chain:
            return False
    t = d.subjects
    if t.everyone:
        return True
    return (
        s.user_id in t.users
        or bool(s.group_ids & t.groups)
        or s.role in t.roles
        or s.access_level in t.access_levels
    )


def evaluate(rules: list[Rule], ctx: EvalContext) -> Decision:
    matched: list[Match] = []
    allows: list[Match] = []
    errors: list[Match] = []
    for rule in sorted(rules, key=lambda r: (str(r.policy_id), r.revision)):
        if not applies(rule, ctx):
            continue
        m = Match(rule.policy_id, rule.revision, rule.doc.effect, rule.doc.mandatory)
        try:
            hit = True if rule.doc.condition is None else _eval(rule.doc.condition, ctx)
        except _Missing:
            if rule.doc.effect != "ALLOW":
                errors.append(m)
            continue
        if not hit:
            continue
        (allows if rule.doc.effect == "ALLOW" else matched).append(m)

    def with_(outcome: str, reason: str) -> Decision:
        return Decision(outcome, reason, tuple(matched), tuple(errors), tuple(allows))

    if any(m.effect == "DENY" and m.mandatory for m in matched):
        return with_("deny", MANDATORY_DENY)
    if any(m.effect == "DENY" for m in matched):
        return with_("deny", DENY)
    if errors:
        return with_("deny", CONTEXT_MISSING)
    if any(m.effect == "REQUIRE_APPROVAL" for m in matched):
        return with_("require_approval", APPROVAL_REQUIRED)
    return with_("no_opinion", NO_OPINION)
