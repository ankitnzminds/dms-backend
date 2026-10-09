"""Shared with Me / Shared by Me and share management."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query

from app.api.deps import Authz, DbSession
from app.core.errors import ErrorResponse
from app.modules.sharing import service as sharing
from app.schemas.common import Page
from app.schemas.sharing import ReceivedShare, ShareOut

router = APIRouter(prefix="/shares", tags=["sharing"], responses={404: {"model": ErrorResponse}})


@router.get(
    "/received",
    response_model=Page[ReceivedShare],
    summary="Shared with Me - original documents with their canonical breadcrumb",
)
def received(
    db: DbSession,
    authz: Authz,
    include_inactive: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[ReceivedShare]:
    items, total = sharing.list_received(
        db, authz, include_inactive=include_inactive, limit=limit, offset=offset
    )
    return Page[ReceivedShare](items=items, total=total, limit=limit, offset=offset)


@router.get("/sent", response_model=Page[ShareOut], summary="Shared by Me")
def sent(
    db: DbSession,
    authz: Authz,
    include_inactive: bool = False,
    scope: Literal["mine", "all"] = "mine",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[ShareOut]:
    items, total = sharing.list_sent(
        db,
        authz,
        include_inactive=include_inactive,
        scope_all=scope == "all",
        limit=limit,
        offset=offset,
    )
    return Page[ShareOut](items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/{share_id}",
    response_model=ShareOut,
    summary="Share details (creator, managers and recipients)",
)
def get_share(share_id: uuid.UUID, db: DbSession, authz: Authz) -> ShareOut:
    return sharing.get_share_out(db, authz, share_id)


@router.post(
    "/{share_id}/revoke",
    response_model=ShareOut,
    summary="Revoke a share (takes effect immediately)",
)
def revoke(share_id: uuid.UUID, db: DbSession, authz: Authz) -> ShareOut:
    return sharing.revoke_share(db, authz, share_id)
