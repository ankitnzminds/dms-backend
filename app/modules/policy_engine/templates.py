"""Predefined policy library (all start as DRAFT; nothing is ever published automatically).

Only templates the backend can really enforce today are offered. Each one states its purpose,
default scope, subjects, actions, effect, whether it is mandatory or optional, what it needs from the
application and its known limitations. Baseline invariants (authentication, suspended users, tenant
isolation, no self-grant) are NOT templates: they are enforced in code and cannot be switched off.
"""

from __future__ import annotations

from typing import Any

from app.schemas.common import ApiModel

BASE: dict[str, Any] = {"schema_version": 1, "scope": {"type": "organization"}}
CONF_OR_RESTRICTED = {
    "attribute": "resource.classification",
    "operator": "IN",
    "value": ["confidential", "restricted"],
}


class PolicyTemplate(ApiModel):
    key: str
    name: str
    category: str
    purpose: str
    mandatory: bool
    requires: list[str]
    limitations: list[str]
    document: dict[str, Any]


def _t(
    key: str,
    name: str,
    category: str,
    purpose: str,
    document: dict[str, Any],
    *,
    requires: list[str] | None = None,
    limitations: list[str] | None = None,
) -> PolicyTemplate:
    return PolicyTemplate(
        key=key,
        name=name,
        category=category,
        purpose=purpose,
        mandatory=bool(document.get("mandatory")),
        requires=requires or [],
        limitations=limitations or [],
        document={**BASE, **document},
    )


TEMPLATES: list[PolicyTemplate] = [
    _t(
        "external_confidential_download",
        "External users cannot download confidential files",
        "sharing",
        "Guest/external accounts and anonymous share links cannot download or preview files classified "
        "confidential or restricted.",
        {
            "effect": "DENY",
            "subjects": {"access_levels": ["external", "guest"]},
            "resource_types": ["document"],
            "actions": ["download", "preview"],
            "condition": CONF_OR_RESTRICTED,
        },
        limitations=[
            "Public links are evaluated as an external, role-less visitor, so this applies to them too.",
            "Folders carry no classification; only files are matched.",
        ],
    ),
    _t(
        "external_no_resharing",
        "External users cannot share or manage access",
        "delegation",
        "Guest/external accounts cannot share items or change who has access, even if they hold the permission.",
        {
            "effect": "DENY",
            "subjects": {"access_levels": ["external", "guest"]},
            "resource_types": ["document", "folder"],
            "actions": ["share", "manage_access"],
        },
    ),
    _t(
        "members_no_delete_confidential",
        "Only administrators can delete confidential files",
        "lifecycle",
        "Ordinary members cannot delete or restore versions of confidential/restricted files; administrators "
        "(who are exempt from ordinary policies) still can.",
        {
            "effect": "DENY",
            "subjects": {"roles": ["member"]},
            "resource_types": ["document"],
            "actions": ["delete", "restore_version"],
            "condition": CONF_OR_RESTRICTED,
        },
        limitations=["Retention periods and legal holds are enforced separately by governance."],
    ),
    _t(
        "no_sync_for_externals",
        "External users cannot sync or export",
        "data-loss-prevention",
        "Guest/external accounts cannot sync files to a device or export them.",
        {
            "effect": "DENY",
            "subjects": {"access_levels": ["external", "guest"]},
            "resource_types": ["document", "folder"],
            "actions": ["sync", "export"],
        },
        limitations=[
            "Applies where the backend authorizes sync/export; no desktop client ships yet."
        ],
    ),
    _t(
        "members_no_create_folders",
        "Members cannot create folders",
        "folder-security",
        "Ordinary members cannot create folders anywhere (organization-wide). Use a folder-scoped copy of "
        "this policy to restrict a single area.",
        {
            "effect": "DENY",
            "subjects": {"roles": ["member"]},
            "resource_types": ["folder"],
            "actions": ["create_folder"],
        },
        limitations=["Change scope to a folder in the builder to limit it to one subtree."],
    ),
    _t(
        "no_uploads_into_scope",
        "Block uploads into a folder",
        "folder-security",
        "Uploads, new files and new versions are blocked in the selected folder and everything below it. "
        "Also stops files being moved or copied in, because those need the same rights on the destination.",
        {
            "effect": "DENY",
            "resource_types": ["folder"],
            "actions": ["upload", "create_file", "create_folder"],
        },
        requires=["Choose a folder as the policy scope before publishing."],
    ),
    _t(
        "approval_for_confidential_shares",
        "Approval required to share confidential files (observe only)",
        "approval",
        "Records where sharing a confidential file WOULD need approval. It cannot be enforced yet: the "
        "application cannot hold an operation until it is approved.",
        {
            "effect": "REQUIRE_APPROVAL",
            "resource_types": ["document"],
            "actions": ["share"],
            "condition": CONF_OR_RESTRICTED,
        },
        requires=["Approval execution (hold an operation until approved) - not available yet"],
        limitations=["Publish in observe mode only; enforce mode is refused."],
    ),
]


def catalogue() -> list[PolicyTemplate]:
    return TEMPLATES


class AttributeInfo(ApiModel):
    name: str
    kind: str
    resource_types: list[str]
    choices: list[str]
    operators: list[str]


class Grammar(ApiModel):
    schema_version: int
    effects: list[str]
    unsupported_effects: list[str]
    operators: list[str]
    group_ops: list[str]
    scope_types: list[str]
    resource_types: list[str]
    actions: list[str]
    roles: list[str]
    access_levels: list[str]
    attributes: list[AttributeInfo]
    limits: dict[str, int]


def grammar() -> Grammar:
    from app.modules.policy_engine import schema as s

    def ops(kind: str) -> list[str]:
        return [o for o in s.OPERATORS if not (kind == "bool" and o in ("IN", "NOT_IN"))]

    return Grammar(
        schema_version=s.SCHEMA_VERSION,
        effects=list(s.EFFECTS),
        unsupported_effects=["REQUIRE_STEP_UP_AUTHENTICATION"],
        operators=list(s.OPERATORS),
        group_ops=list(s.GROUP_OPS),
        scope_types=list(s.SCOPE_TYPES),
        resource_types=list(s.RESOURCE_TYPES),
        actions=sorted(a for a in s.ACTION_NAMES if a != "administer"),
        roles=sorted(s.ATTRIBUTES["subject.role"].choices),
        access_levels=list(s.ACCESS_LEVELS),
        attributes=[
            AttributeInfo(
                name=n,
                kind=a.kind,
                resource_types=list(a.resource_types),
                choices=list(a.choices),
                operators=ops(a.kind),
            )
            for n, a in s.ATTRIBUTES.items()
        ],
        limits={
            "max_depth": s.MAX_DEPTH,
            "max_conditions": s.MAX_CONDITIONS,
            "max_list": s.MAX_LIST,
        },
    )
