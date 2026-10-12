"""Permission dashboards: org-wide access overview (admin), "my access", effective access and history."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query
from pydantic import Field

from app.api.deps import CurrentPrincipal, DbSession
from app.db.enums import ResourceType
from app.modules.permission_admin import service
from app.schemas.admin import AuditEventOut
from app.schemas.common import ApiModel, Page

router = APIRouter(tags=["permissions"])
Kind = Literal["document", "folder"]


class EffectiveAccessOut(ApiModel):
    resource_type: Kind
    resource_id: uuid.UUID
    actions: list[str] = Field(
        description="Actions the caller holds, from the one authorization engine."
    )


@router.get(
    "/admin/permissions/access",
    response_model=Page[service.AccessEntry],
    summary="Organization-wide live grants and shares (administrators)",
)
def org_access(
    db: DbSession,
    principal: CurrentPrincipal,
    source: Literal["all", "grant", "share"] = "all",
    expiring_within_days: int | None = Query(None, ge=1, le=365),
    user_id: uuid.UUID | None = None,
    group_id: uuid.UUID | None = None,
    q: str | None = Query(None, max_length=200),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[service.AccessEntry]:
    items, total = service.org_access(
        db,
        principal,
        source=source,
        expiring_within_days=expiring_within_days,
        user_id=user_id,
        group_id=group_id,
        q=q,
        limit=limit,
        offset=offset,
    )
    return Page[service.AccessEntry](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/me/access",
    response_model=Page[service.AccessEntry],
    summary="Access granted to me (directly, via my groups, or organization-wide)",
)
def my_access(
    db: DbSession,
    principal: CurrentPrincipal,
    expiring_within_days: int | None = Query(None, ge=1, le=365),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[service.AccessEntry]:
    items, total = service.my_access(
        db, principal, expiring_within_days=expiring_within_days, limit=limit, offset=offset
    )
    return Page[service.AccessEntry](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/resources/{kind}/{resource_id}/effective-access",
    response_model=EffectiveAccessOut,
    summary="My effective actions on a file or folder",
)
def effective_access(
    kind: Kind, resource_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> EffectiveAccessOut:
    out = service.effective_for_me(db, principal, ResourceType(kind), resource_id)
    return EffectiveAccessOut(**out)  # type: ignore[arg-type]


@router.get(
    "/resources/{kind}/{resource_id}/permission-history",
    response_model=Page[AuditEventOut],
    summary="Permission, share and request events for one item (managers and administrators)",
)
def permission_history(
    kind: Kind,
    resource_id: uuid.UUID,
    db: DbSession,
    principal: CurrentPrincipal,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[AuditEventOut]:
    items, total = service.resource_history(
        db, principal, ResourceType(kind), resource_id, limit=limit, offset=offset
    )
    return Page[AuditEventOut](items=items, total=total, limit=limit, offset=offset)
