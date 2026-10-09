"""Access requests: request access, track status, and (as an authorized approver) decide."""

from __future__ import annotations

import uuid
from typing import Literal

from fastapi import APIRouter, Query

from app.api.deps import Authz, DbSession, limited
from app.core.errors import ErrorResponse
from app.modules.access_requests import service as svc
from app.schemas.chat import AccessRequestCreate, AccessRequestDecision, AccessRequestOut
from app.schemas.common import Page

router = APIRouter(
    prefix="/access-requests",
    tags=["access requests"],
    responses={404: {"model": ErrorResponse}, 409: {"model": ErrorResponse}},
)


@router.post(
    "",
    response_model=AccessRequestOut,
    status_code=201,
    summary="Request access to a document/folder you can see (grants nothing by itself)",
    dependencies=[limited("access_requests", sensitive=True)],
)
def create(body: AccessRequestCreate, db: DbSession, authz: Authz) -> AccessRequestOut:
    return svc.create(db, authz, body)


@router.get("", response_model=Page[AccessRequestOut], summary="Requests I made / can decide")
def list_requests(
    db: DbSession,
    authz: Authz,
    view: Literal["mine", "to_decide"] = "mine",
    status: Literal["pending", "approved", "rejected", "cancelled"] | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Page[AccessRequestOut]:
    found, total = svc.list_requests(
        db, authz, mine=view == "mine", status=status, limit=limit, offset=offset
    )
    return Page[AccessRequestOut](items=found, total=total, limit=limit, offset=offset)


@router.get("/{request_id}", response_model=AccessRequestOut, summary="One access request")
def get_request(request_id: uuid.UUID, db: DbSession, authz: Authz) -> AccessRequestOut:
    return svc.get(db, authz, request_id)


@router.post(
    "/{request_id}/decision",
    response_model=AccessRequestOut,
    summary="Approve or reject (needs MANAGE_ACCESS on the resource; never your own request)",
    dependencies=[limited("access_requests", sensitive=True)],
)
def decide(
    request_id: uuid.UUID, body: AccessRequestDecision, db: DbSession, authz: Authz
) -> AccessRequestOut:
    return svc.decide(db, authz, request_id, body)


@router.post("/{request_id}/cancel", response_model=AccessRequestOut, summary="Withdraw my request")
def cancel(request_id: uuid.UUID, db: DbSession, authz: Authz) -> AccessRequestOut:
    return svc.cancel(db, authz, request_id)
