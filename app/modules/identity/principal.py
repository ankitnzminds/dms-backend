"""The authenticated, tenant-resolved caller. Built server-side from DB state, never from the client."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from app.db.enums import Role

ADMIN_ROLES = frozenset({Role.OWNER.value, Role.ADMIN.value})


@dataclass(frozen=True)
class Principal:
    user_id: uuid.UUID
    email: str
    display_name: str | None
    organization_id: uuid.UUID
    role: str
    group_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)

    @property
    def is_admin(self) -> bool:
        return self.role in ADMIN_ROLES

    @property
    def can_read_audit(self) -> bool:
        return self.role in ADMIN_ROLES or self.role == Role.AUDITOR.value
