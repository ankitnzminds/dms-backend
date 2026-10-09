"""Upload sessions (private staging) and authorized downloads."""

from __future__ import annotations

import hashlib
import tempfile
import uuid
from typing import Annotated, BinaryIO, cast

from fastapi import APIRouter, Header, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from app.api.deps import Authz, DbSession, limited
from app.core.config import get_settings
from app.core.errors import ErrorResponse
from app.core.ratelimit import rate_limit
from app.db.models import UploadSession
from app.modules.documents import downloads
from app.modules.uploads import service as uploads
from app.schemas.admin import UploadFinalizeOut, UploadInitiate, UploadSessionOut

router = APIRouter(tags=["uploads"], responses={404: {"model": ErrorResponse}})

IdempotencyKey = Annotated[str | None, Header(alias="Idempotency-Key", max_length=128)]
_SPOOL_MEMORY = 8 * 1024 * 1024


def session_out(s: UploadSession) -> UploadSessionOut:
    return UploadSessionOut(
        id=s.id,
        folder_id=s.folder_id,
        document_id=s.document_id,
        filename=s.filename,
        declared_size=s.declared_size,
        content_type=s.content_type,
        state=s.state,
        expires_at=s.expires_at,
        upload_url=f"{get_settings().api_v1_prefix}/uploads/{s.id}/content",
        failure_reason=s.failure_reason,
    )


@router.post(
    "/folders/{folder_id}/uploads",
    response_model=UploadSessionOut,
    status_code=201,
    summary="Start uploading a new document into a folder (reserves quota)",
    dependencies=[limited("upload_initiate")],
)
def initiate_upload(
    folder_id: uuid.UUID,
    body: UploadInitiate,
    db: DbSession,
    authz: Authz,
    idempotency_key: IdempotencyKey = None,
) -> UploadSessionOut:
    session = uploads.initiate(
        db,
        authz,
        folder_id=folder_id,
        document_id=None,
        filename=body.filename,
        size_bytes=body.size_bytes,
        content_type=body.content_type,
        sha256=body.sha256,
        expected_latest_version=None,
        idempotency_key=idempotency_key,
    )
    return session_out(session)


@router.get(
    "/uploads/{session_id}", response_model=UploadSessionOut, summary="Upload session status"
)
def get_upload(session_id: uuid.UUID, db: DbSession, authz: Authz) -> UploadSessionOut:
    return session_out(uploads.get_session(db, authz, session_id))


@router.put(
    "/uploads/{session_id}/content",
    response_model=UploadSessionOut,
    summary="Send the raw bytes (size and optional SHA-256 are verified)",
    openapi_extra={
        "requestBody": {
            "content": {
                "application/octet-stream": {"schema": {"type": "string", "format": "binary"}}
            },
            "required": True,
        }
    },
)
async def upload_content(
    session_id: uuid.UUID, request: Request, db: DbSession, authz: Authz
) -> UploadSessionOut:
    session = await run_in_threadpool(uploads.prepare_content, db, authz, session_id)
    declared = session.declared_size
    hasher = hashlib.sha256()
    size = 0
    head = b""
    spool = tempfile.SpooledTemporaryFile(max_size=_SPOOL_MEMORY)  # noqa: SIM115
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            if len(head) < 16:
                head = (head + chunk)[:16]
            size += len(chunk)
            if size > declared:
                break  # mismatch is reported below; never buffer more than declared + one chunk
            hasher.update(chunk)
            spool.write(chunk)
        stored = await run_in_threadpool(
            uploads.store_content,
            db,
            authz,
            session_id,
            cast(BinaryIO, spool),
            size,
            hasher.hexdigest(),
            head,
        )
    finally:
        spool.close()
    return session_out(stored)


@router.post(
    "/uploads/{session_id}/finalize",
    response_model=UploadFinalizeOut,
    summary="Register the uploaded bytes as a document/version",
)
def finalize_upload(session_id: uuid.UUID, db: DbSession, authz: Authz) -> UploadFinalizeOut:
    doc, version = uploads.finalize(db, authz, session_id)
    return UploadFinalizeOut(
        document_id=doc.id, version_id=version.id, version_number=version.version_number
    )


@router.delete(
    "/uploads/{session_id}",
    status_code=204,
    summary="Cancel an upload and release its quota reservation",
)
def cancel_upload(session_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    uploads.cancel(db, authz, session_id)
    return Response(status_code=204)


# --- ticket redemption (no Authorization header: the ticket is re-authorized server-side)
@router.get(
    "/downloads/{token}",
    summary="Redeem a short-lived ticket (permissions are re-checked now)",
    response_class=StreamingResponse,
    responses={
        200: {"content": {"application/octet-stream": {}}},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
    },
    dependencies=[],
)
def redeem_download(token: str, request: Request, db: DbSession) -> StreamingResponse:
    rate_limit("download_redeem", sensitive=True)(request)
    version, location, disposition, name = downloads.redeem_ticket(db, token)
    size, content_type = version.size_bytes, version.content_type
    stream = downloads.open_stream(version, location)
    db.close()  # release the connection before streaming
    inline = disposition == "inline"
    origins = " ".join(get_settings().cors_origins) or "'none'"
    headers = {
        "Content-Disposition": downloads.content_disposition(disposition, name),
        "Content-Length": str(size),
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": (
            f"default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors {origins}"
            if inline
            else "default-src 'none'; sandbox"
        ),
    }
    return StreamingResponse(
        stream, media_type=content_type if inline else "application/octet-stream", headers=headers
    )
