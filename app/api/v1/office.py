"""Office viewer/editor sessions for the frontend (normal authentication)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import Authz, CurrentPrincipal, DbSession, limited
from app.core.errors import ErrorResponse
from app.modules.documents import downloads
from app.modules.office import convert
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


@router.post(
    "/documents/{document_id}/export-pdf",
    summary="Download as PDF (converted by the office server; needs download permission)",
    response_class=Response,
    responses={200: {"content": {"application/pdf": {}}}},
    dependencies=[limited("export_pdf", sensitive=True)],
)
def export_pdf(document_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    data, filename = convert.to_pdf(db, authz, document_id)
    return Response(
        data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": downloads.content_disposition("attachment", filename),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
