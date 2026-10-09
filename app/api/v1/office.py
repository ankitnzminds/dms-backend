"""Office viewer/editor sessions for the frontend (normal authentication)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter

from app.api.deps import Authz, CurrentPrincipal, DbSession, limited
from app.core.errors import ErrorResponse
from app.modules.office import service as office
from app.schemas.office import OfficeSessionIn, OfficeSessionOut, OfficeStatus

router = APIRouter(
    tags=["office"],
    responses={
        404: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
        503: {"model": ErrorResponse},
    },
)


@router.get(
    "/office/status", response_model=OfficeStatus, summary="Is the office viewer/editor available?"
)
def office_status(_principal: CurrentPrincipal) -> OfficeStatus:
    return office.status()


@router.post(
    "/documents/{document_id}/office-session",
    response_model=OfficeSessionOut,
    summary="Open a document in the office viewer/editor (view needs preview; edit needs upload_version)",
    dependencies=[limited("office_session")],
)
def create_office_session(
    document_id: uuid.UUID, body: OfficeSessionIn, db: DbSession, authz: Authz
) -> OfficeSessionOut:
    return office.create_session(db, authz, document_id, body.mode)
