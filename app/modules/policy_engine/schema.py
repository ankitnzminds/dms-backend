"""Typed, declarative policy documents (schema v1) and their validator.

A policy document is plain data. It is parsed into frozen dataclasses by an explicit allow-list
grammar; nothing is ever executed (no eval, no expressions, no attribute paths outside ATTRIBUTES).

    {
      "schema_version": 1,
      "effect": "DENY" | "REQUIRE_APPROVAL" | "ALLOW",
      "mandatory": false,
      "scope": {"type": "organization" | "folder" | "file", "id": "<uuid>"},
      "subjects": {"users": [...], "groups": [...], "roles": [...], "access_levels": [...]},
      "resource_types": ["document", "folder"],
      "actions": ["download", ...],
      "condition": {"attribute": "resource.classification", "operator": "EQUALS", "value": "confidential"}
                 | {"op": "AND" | "OR", "conditions": [ ... ]}   (optional)
    }

Unknown keys, attributes, operators, actions, effects and mistyped values are rejected with a path
so the author can fix them. A document that does not validate can never be published.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from app.db.enums import Action, Role

SCHEMA_VERSION = 1
MAX_DEPTH = 4
MAX_CONDITIONS = 25
MAX_LIST = 100

Effect = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
EFFECTS: tuple[str, ...] = ("ALLOW", "DENY", "REQUIRE_APPROVAL")
# REQUIRE_STEP_UP_AUTHENTICATION is deliberately NOT accepted: the application has no step-up flow.

OPERATORS = ("EQUALS", "NOT_EQUALS", "IN", "NOT_IN", "EXISTS", "NOT_EXISTS")
GROUP_OPS = ("AND", "OR")
SCOPE_TYPES = ("organization", "folder", "file")
RESOURCE_TYPES = ("document", "folder")
ACCESS_LEVELS = ("full", "guest", "external")
CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")


@dataclass(frozen=True)
class AttributeDef:
    kind: Literal["enum", "string", "bool"]
    resource_types: tuple[str, ...]  # resource types for which the attribute is always populated
    choices: tuple[str, ...] = ()


# The ONLY attributes a condition may read. Every one is populated by the trusted context builder.
ATTRIBUTES: dict[str, AttributeDef] = {
    "resource.classification": AttributeDef("enum", ("document",), CLASSIFICATIONS),
    "resource.file_extension": AttributeDef("string", ("document",)),
    "resource.owner_is_subject": AttributeDef("bool", ("document", "folder")),
    "subject.role": AttributeDef("enum", ("document", "folder"), tuple(r.value for r in Role)),
    "subject.access_level": AttributeDef("enum", ("document", "folder"), ACCESS_LEVELS),
    "subject.is_external": AttributeDef("bool", ("document", "folder")),
}

ACTION_NAMES = frozenset(a.value for a in Action)


@dataclass(frozen=True)
class Issue:
    path: str
    message: str


class PolicyValidationError(ValueError):
    def __init__(self, issues: list[Issue]) -> None:
        self.issues = issues
        super().__init__("; ".join(f"{i.path}: {i.message}" for i in issues))


@dataclass(frozen=True)
class Leaf:
    attribute: str
    operator: str
    value: Any = None  # scalar, tuple of scalars (IN/NOT_IN) or None (EXISTS/NOT_EXISTS)


@dataclass(frozen=True)
class Combine:
    op: str
    conditions: tuple[Condition, ...]


Condition = Leaf | Combine


@dataclass(frozen=True)
class Subjects:
    users: frozenset[uuid.UUID] = frozenset()
    groups: frozenset[uuid.UUID] = frozenset()
    roles: frozenset[str] = frozenset()
    access_levels: frozenset[str] = frozenset()

    @property
    def everyone(self) -> bool:
        return not (self.users or self.groups or self.roles or self.access_levels)


@dataclass(frozen=True)
class PolicyDoc:
    effect: str
    mandatory: bool
    scope_type: str
    scope_id: uuid.UUID | None
    subjects: Subjects
    resource_types: frozenset[str]
    actions: frozenset[str]
    condition: Condition | None = None
    attributes_used: frozenset[str] = field(default_factory=frozenset)


def _uuid_list(raw: Any, path: str, issues: list[Issue]) -> frozenset[uuid.UUID]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list) or len(raw) > MAX_LIST:
        issues.append(Issue(path, f"must be a list of at most {MAX_LIST} ids"))
        return frozenset()
    out: set[uuid.UUID] = set()
    for i, v in enumerate(raw):
        try:
            out.add(uuid.UUID(str(v)))
        except ValueError:
            issues.append(Issue(f"{path}[{i}]", "is not a valid id"))
    return frozenset(out)


def _str_list(raw: Any, path: str, allowed: tuple[str, ...], issues: list[Issue]) -> frozenset[str]:
    if raw is None:
        return frozenset()
    if not isinstance(raw, list) or len(raw) > MAX_LIST:
        issues.append(Issue(path, "must be a list"))
        return frozenset()
    out: set[str] = set()
    for i, v in enumerate(raw):
        if not isinstance(v, str) or v not in allowed:
            issues.append(Issue(f"{path}[{i}]", f"must be one of: {', '.join(allowed)}"))
        else:
            out.add(v)
    return frozenset(out)


def _scalar_ok(attr: AttributeDef, v: Any) -> str | None:
    if attr.kind == "bool":
        return None if isinstance(v, bool) else "must be true or false"
    if not isinstance(v, str) or not v or len(v) > 200:
        return "must be a non-empty text value"
    if attr.kind == "enum" and v not in attr.choices:
        return f"must be one of: {', '.join(attr.choices)}"
    return None


class _Counter:
    n = 0


def _parse_condition(
    raw: Any, path: str, depth: int, issues: list[Issue], used: set[str], counter: _Counter
) -> Condition | None:
    if depth > MAX_DEPTH:
        issues.append(Issue(path, f"conditions are nested more than {MAX_DEPTH} levels"))
        return None
    if not isinstance(raw, dict):
        issues.append(Issue(path, "must be an object"))
        return None
    counter.n += 1
    if counter.n > MAX_CONDITIONS:
        issues.append(Issue(path, f"more than {MAX_CONDITIONS} conditions"))
        return None
    if "op" in raw:
        extra = set(raw) - {"op", "conditions"}
        if extra:
            issues.append(Issue(path, f"unknown keys: {', '.join(sorted(extra))}"))
        op = raw.get("op")
        if op not in GROUP_OPS:
            issues.append(Issue(f"{path}.op", "must be AND or OR"))
            return None
        kids = raw.get("conditions")
        if not isinstance(kids, list) or not kids:
            issues.append(Issue(f"{path}.conditions", "must be a non-empty list"))
            return None
        parsed = [
            _parse_condition(k, f"{path}.conditions[{i}]", depth + 1, issues, used, counter)
            for i, k in enumerate(kids)
        ]
        if any(p is None for p in parsed):
            return None
        return Combine(op, tuple(p for p in parsed if p is not None))
    extra = set(raw) - {"attribute", "operator", "value"}
    if extra:
        issues.append(Issue(path, f"unknown keys: {', '.join(sorted(extra))}"))
    name, operator = raw.get("attribute"), raw.get("operator")
    attr = ATTRIBUTES.get(name) if isinstance(name, str) else None
    if attr is None:
        issues.append(Issue(f"{path}.attribute", "is not a supported attribute"))
        return None
    if operator not in OPERATORS:
        issues.append(Issue(f"{path}.operator", f"must be one of: {', '.join(OPERATORS)}"))
        return None
    used.add(name)  # type: ignore[arg-type]
    value = raw.get("value")
    if operator in ("EXISTS", "NOT_EXISTS"):
        if value is not None:
            issues.append(Issue(f"{path}.value", f"{operator} takes no value"))
        return Leaf(name, operator)  # type: ignore[arg-type]
    if operator in ("IN", "NOT_IN"):
        if attr.kind == "bool":
            issues.append(Issue(f"{path}.operator", "IN/NOT_IN do not apply to true/false values"))
            return None
        if not isinstance(value, list) or not value or len(value) > MAX_LIST:
            issues.append(Issue(f"{path}.value", "must be a non-empty list"))
            return None
        bad = [m for m in (_scalar_ok(attr, v) for v in value) if m]
        if bad:
            issues.append(Issue(f"{path}.value", bad[0]))
            return None
        return Leaf(name, operator, tuple(value))  # type: ignore[arg-type]
    msg = _scalar_ok(attr, value)
    if msg:
        issues.append(Issue(f"{path}.value", msg))
        return None
    return Leaf(name, operator, value)  # type: ignore[arg-type]


def parse_document(raw: Any) -> PolicyDoc:
    """Validate and parse a policy document. Raises PolicyValidationError listing every problem."""
    issues: list[Issue] = []
    if not isinstance(raw, dict):
        raise PolicyValidationError([Issue("$", "policy must be an object")])
    allowed = {
        "schema_version",
        "effect",
        "mandatory",
        "scope",
        "subjects",
        "resource_types",
        "actions",
        "condition",
    }
    extra = set(raw) - allowed
    if extra:
        issues.append(Issue("$", f"unknown keys: {', '.join(sorted(extra))}"))
    if raw.get("schema_version") != SCHEMA_VERSION:
        issues.append(Issue("schema_version", f"must be {SCHEMA_VERSION}"))
    effect = raw.get("effect")
    if effect not in EFFECTS:
        issues.append(
            Issue(
                "effect", f"must be one of: {', '.join(EFFECTS)} (other effects are not supported)"
            )
        )
    mandatory = raw.get("mandatory", False)
    if not isinstance(mandatory, bool):
        issues.append(Issue("mandatory", "must be true or false"))
        mandatory = False
    if mandatory and effect == "ALLOW":
        issues.append(Issue("mandatory", "an ALLOW policy cannot be mandatory"))

    scope = raw.get("scope") or {"type": "organization"}
    scope_type, scope_id = "organization", None
    if not isinstance(scope, dict) or set(scope) - {"type", "id"}:
        issues.append(Issue("scope", "must be {type, id}"))
    else:
        scope_type = str(scope.get("type"))
        if scope_type not in SCOPE_TYPES:
            issues.append(Issue("scope.type", f"must be one of: {', '.join(SCOPE_TYPES)}"))
        elif scope_type == "organization":
            if scope.get("id") is not None:
                issues.append(Issue("scope.id", "an organization-wide policy has no id"))
        else:
            try:
                scope_id = uuid.UUID(str(scope.get("id")))
            except ValueError:
                issues.append(Issue("scope.id", "a folder/file policy needs a valid id"))

    subj_raw = raw.get("subjects") or {}
    subjects = Subjects()
    if not isinstance(subj_raw, dict) or set(subj_raw) - {
        "users",
        "groups",
        "roles",
        "access_levels",
    }:
        issues.append(Issue("subjects", "may contain only users, groups, roles, access_levels"))
    else:
        subjects = Subjects(
            users=_uuid_list(subj_raw.get("users"), "subjects.users", issues),
            groups=_uuid_list(subj_raw.get("groups"), "subjects.groups", issues),
            roles=_str_list(
                subj_raw.get("roles"), "subjects.roles", tuple(r.value for r in Role), issues
            ),
            access_levels=_str_list(
                subj_raw.get("access_levels"), "subjects.access_levels", ACCESS_LEVELS, issues
            ),
        )

    rtypes = _str_list(raw.get("resource_types"), "resource_types", RESOURCE_TYPES, issues)
    if not rtypes:
        issues.append(Issue("resource_types", "choose at least one of: document, folder"))
    actions = _str_list(raw.get("actions"), "actions", tuple(sorted(ACTION_NAMES)), issues)
    if not actions:
        issues.append(Issue("actions", "choose at least one action"))

    cond: Condition | None = None
    used: set[str] = set()
    if raw.get("condition") is not None:
        cond = _parse_condition(raw["condition"], "condition", 1, issues, used, _Counter())
        # every attribute must be available on EVERY resource type the policy targets
        for name in sorted(used):
            missing = [t for t in rtypes if t not in ATTRIBUTES[name].resource_types]
            if missing:
                issues.append(
                    Issue(
                        "condition",
                        f"{name} is not available for {', '.join(sorted(missing))}; "
                        "limit resource_types or remove the condition",
                    )
                )
    if issues:
        raise PolicyValidationError(issues)
    return PolicyDoc(
        effect=str(effect),
        mandatory=mandatory,
        scope_type=scope_type,
        scope_id=scope_id,
        subjects=subjects,
        resource_types=rtypes,
        actions=actions,
        condition=cond,
        attributes_used=frozenset(used),
    )
