"""Policy storage, precedence and lookups.

Precedence (lowest to highest): built-in defaults < organization default < group policies
(applied in group-name order) < user policy. Each scope stores only the keys it overrides, so
the effective value always knows where it came from (``provenance``).
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError, ValidationFailed
from app.db.enums import PolicyScope
from app.db.models import Group, GroupMembership, Policy
from app.modules.audit import service as audit
from app.modules.identity.principal import Principal
from app.modules.policies.schema import ENFORCED, TABS


def defaults() -> dict[str, dict[str, Any]]:
    return {tab: model().model_dump() for tab, model in TABS.items()}


def _load(db: Session, org_id: uuid.UUID, scope: str, scope_id: uuid.UUID | None) -> Policy | None:
    stmt = select(Policy).where(Policy.organization_id == org_id, Policy.scope_type == scope)
    stmt = stmt.where(
        Policy.scope_id.is_(None) if scope_id is None else Policy.scope_id == scope_id
    )
    return db.scalar(stmt)


def validate_overrides(overrides: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Check every tab/key against the typed catalogue. Returns only what was explicitly set."""
    clean: dict[str, dict[str, Any]] = {}
    for tab, values in overrides.items():
        model = TABS.get(tab)
        if model is None:
            raise ValidationFailed(f"Unknown policy tab '{tab}'.", code="unknown_policy_tab")
        if not isinstance(values, dict):
            raise ValidationFailed(f"Policy tab '{tab}' must be an object.")
        try:
            parsed = model.model_validate(values)
        except ValidationError as e:
            first = e.errors()[0]
            key = ".".join(str(x) for x in first["loc"])
            raise ValidationFailed(
                f"{tab}.{key}: {first['msg'].removeprefix('Value error, ')}",
                code="invalid_policy",
            ) from None
        explicit = {k: getattr(parsed, k) for k in parsed.model_fields_set}
        if explicit:
            clean[tab] = explicit
    return clean


def stored_overrides(
    db: Session, org_id: uuid.UUID, scope: str, scope_id: uuid.UUID | None
) -> tuple[dict[str, dict[str, Any]], int]:
    row = _load(db, org_id, scope, scope_id)
    return (row.settings, row.version) if row else ({}, 0)


def save(
    db: Session,
    p: Principal,
    scope: str,
    scope_id: uuid.UUID | None,
    overrides: dict[str, Any],
    *,
    expected_version: int | None,
) -> int:
    """Replace the overrides at one scope (optimistic concurrency on ``version``)."""
    clean = validate_overrides(overrides)
    row = _load(db, p.organization_id, scope, scope_id)
    current = row.version if row else 0
    if expected_version is not None and expected_version != current:
        raise ConflictError(
            "This policy was changed by someone else. Reload and try again.",
            code="policy_version_conflict",
        )
    before = row.settings if row else {}
    if row is None:
        row = Policy(
            id=uuid.uuid4(),
            organization_id=p.organization_id,
            scope_type=scope,
            scope_id=scope_id,
            settings=clean,
            version=1,
            updated_by=p.user_id,
        )
        db.add(row)
    else:
        row.settings = clean
        row.version = current + 1
        row.updated_by = p.user_id
    changed = sorted(
        f"{tab}.{k}"
        for tab in set(before) | set(clean)
        for k in set(before.get(tab, {})) | set(clean.get(tab, {}))
        if before.get(tab, {}).get(k) != clean.get(tab, {}).get(k)
    )
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="policy.updated",
        resource_type="policy",
        resource_id=scope_id or p.organization_id,
        metadata={"scope": scope, "version": row.version, "changed": changed[:100]},
    )
    db.flush()
    return row.version


def reset(db: Session, p: Principal, scope: str, scope_id: uuid.UUID | None) -> None:
    row = _load(db, p.organization_id, scope, scope_id)
    if row is None:
        return
    row.settings = {}
    row.version += 1
    row.updated_by = p.user_id
    audit.record(
        db,
        organization_id=p.organization_id,
        actor_user_id=p.user_id,
        action="policy.reset",
        resource_type="policy",
        resource_id=scope_id or p.organization_id,
        metadata={"scope": scope, "version": row.version},
    )


class Effective(BaseModel):
    values: dict[str, dict[str, Any]]
    provenance: dict[str, str]  # "tab.key" -> "default" | "organization" | "group:<name>" | "user"


def effective(
    db: Session, org_id: uuid.UUID, user_id: uuid.UUID, *, include_user: bool = True
) -> Effective:
    values = defaults()
    provenance = {f"{t}.{k}": "default" for t, kv in values.items() for k in kv}

    def apply(overrides: dict[str, dict[str, Any]], source: str) -> None:
        for tab, kv in overrides.items():
            for k, v in kv.items():
                if tab in values and k in values[tab]:
                    values[tab][k] = v
                    provenance[f"{tab}.{k}"] = source

    org_row = _load(db, org_id, PolicyScope.ORGANIZATION.value, None)
    if org_row:
        apply(org_row.settings, "organization")
    group_rows = db.execute(
        select(Policy, Group.name)
        .join(Group, Group.id == Policy.scope_id)
        .join(GroupMembership, GroupMembership.group_id == Group.id)
        .where(
            Policy.organization_id == org_id,
            Policy.scope_type == PolicyScope.GROUP.value,
            GroupMembership.user_id == user_id,
        )
        .order_by(Group.name)
    ).all()
    for pol, name in group_rows:
        apply(pol.settings, f"group:{name}")
    user_row = _load(db, org_id, PolicyScope.USER.value, user_id) if include_user else None
    if user_row:
        apply(user_row.settings, "user")
    return Effective(values=values, provenance=provenance)


def get(db: Session, org_id: uuid.UUID, user_id: uuid.UUID, tab: str, key: str) -> Any:
    """One effective setting, e.g. ``get(db, org, user, "user_policy", "max_upload_bytes")``."""
    return effective(db, org_id, user_id).values[tab][key]


def require_group(db: Session, p: Principal, group_id: uuid.UUID) -> Group:
    group = db.scalar(
        select(Group).where(Group.id == group_id, Group.organization_id == p.organization_id)
    )
    if group is None:
        raise NotFoundError("Group not found.")
    return group


__all__ = ["ENFORCED", "TABS"]
