"""Shared validation for folder chains (signature chains and approval chains).

A chain is a list of levels; every level is a set of people with two flags (optional, super). Groups
are expanded to their current members when the chain is saved (a snapshot, as in the reference app),
duplicates inside a level merge with OR, a person may appear in one level only, and every person must
be an active member of the organization.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.db.enums import MembershipStatus, UserStatus
from app.db.models import Group, GroupMembership, Membership, User

MAX_LEVELS = 20
MAX_SIGNERS = 50

Entry = tuple[uuid.UUID, bool, bool]  # (user id, optional, super)


def active_users(db: Session, org_id: uuid.UUID, ids: set[uuid.UUID]) -> dict[uuid.UUID, User]:
    if not ids:
        return {}
    return {
        u.id: u
        for u in db.scalars(
            select(User)
            .join(Membership, Membership.user_id == User.id)
            .where(
                Membership.organization_id == org_id,
                Membership.status == MembershipStatus.ACTIVE.value,
                User.status == UserStatus.ACTIVE.value,
                User.id.in_(ids),
            )
        )
    }


def plan_levels(
    db: Session,
    org_id: uuid.UUID,
    levels: Sequence[Sequence[Entry]],
    group_ids: Sequence[Sequence[uuid.UUID]],
) -> list[dict[uuid.UUID, tuple[bool, bool]]]:
    """Validated, group-expanded levels (index = level - 1). Raises ValidationFailed."""
    n_levels = max(len(levels), len(group_ids))
    if n_levels > MAX_LEVELS:
        raise ValidationFailed(f"A chain can have at most {MAX_LEVELS} levels.")
    plan: list[dict[uuid.UUID, list[bool]]] = [dict() for _ in range(n_levels)]

    def add(level: int, user_id: uuid.UUID, optional: bool, sup: bool) -> None:
        cur = plan[level].setdefault(user_id, [False, False])
        cur[0], cur[1] = cur[0] or optional, cur[1] or sup  # duplicates in one level merge (OR)

    for i, entries in enumerate(levels):
        for uid, optional, sup in entries:
            add(i, uid, optional, sup)
    for i, gids in enumerate(group_ids):
        if not gids:
            continue
        known = set(
            db.scalars(select(Group.id).where(Group.organization_id == org_id, Group.id.in_(gids)))
        )
        if known != set(gids):
            raise ValidationFailed("One or more groups were not found.", code="group_not_found")
        for uid in db.scalars(
            select(GroupMembership.user_id).where(
                GroupMembership.organization_id == org_id, GroupMembership.group_id.in_(gids)
            )
        ):
            add(i, uid, False, False)

    seen: set[uuid.UUID] = set()
    for i, level in enumerate(plan):
        if not level:
            raise ValidationFailed(f"Level {i + 1} has no people.", code="empty_level")
        for uid in level:
            if uid in seen:
                raise ValidationFailed(
                    "A person can appear in one level only.", code="signer_in_two_levels"
                )
            seen.add(uid)
    if len(seen) > MAX_SIGNERS:
        raise ValidationFailed(f"A chain can have at most {MAX_SIGNERS} people.")
    if seen - set(active_users(db, org_id, seen)):
        raise ValidationFailed(
            "One or more people were not found or are not active members.",
            code="signer_not_found",
        )
    return [{uid: (f[0], f[1]) for uid, f in level.items()} for level in plan]
