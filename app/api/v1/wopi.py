"""WOPI host endpoints, called by the office server (Collabora), never by the browser.

Authentication is the scoped, short-lived ``access_token`` (query string per the WOPI spec, or
Bearer); see ``modules/office/wopi.py`` for the per-call authorization rules.
"""

from __future__ import annotations

import hashlib
import tempfile
import uuid
from datetime import UTC
from typing import BinaryIO, cast

from fastapi import APIRouter, Request, Response
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse

from app.api.deps import DbSession
from app.core.config import get_settings
from app.core.errors import PayloadTooLargeError
from app.modules.documents.downloads import open_stream
from app.modules.office import wopi

router = APIRouter(prefix="/wopi/files", tags=["wopi (office server)"], include_in_schema=False)


def _token(request: Request) -> str | None:
    q = request.query_params.get("access_token")
    if q:
        return q
    auth = request.headers.get("authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else None


def _conflict(current: str) -> Response:
    return Response(status_code=409, headers={"X-WOPI-Lock": current})


@router.get("/{file_id}")
def check_file_info(file_id: uuid.UUID, request: Request, db: DbSession) -> JSONResponse:
    return JSONResponse(wopi.check_file_info(db, _token(request), file_id))


@router.get("/{file_id}/contents")
def get_file(file_id: uuid.UUID, request: Request, db: DbSession) -> StreamingResponse:
    servable = wopi.get_contents(db, _token(request), file_id)
    return StreamingResponse(
        open_stream(servable),
        media_type=servable.content_type,
        headers={"Content-Length": str(servable.size), "Cache-Control": "no-store"},
    )


@router.post("/{file_id}/contents")
async def put_file(file_id: uuid.UUID, request: Request, db: DbSession) -> Response:
    if request.headers.get("x-wopi-override", "PUT").upper() != "PUT":
        return Response(status_code=501)
    limit = get_settings().office_max_bytes
    hasher = hashlib.sha256()
    size, head = 0, b""
    spool = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024)  # noqa: SIM115
    try:
        async for chunk in request.stream():
            if not chunk:
                continue
            size += len(chunk)
            if size > limit:
                raise PayloadTooLargeError("The saved file is too large.")
            if len(head) < 16:
                head = (head + chunk)[:16]
            hasher.update(chunk)
            spool.write(chunk)
        try:
            version = await run_in_threadpool(
                wopi.put_contents,
                db,
                _token(request),
                file_id,
                request.headers.get("x-wopi-lock"),
                cast(BinaryIO, spool),
                size,
                hasher.hexdigest(),
                head,
            )
        except wopi.WopiConflict as exc:
            return _conflict(exc.current_lock)
    finally:
        spool.close()
    return JSONResponse(
        {"LastModifiedTime": version.created_at.astimezone(UTC).isoformat()},
        headers={"X-WOPI-ItemVersion": str(version.version_number)},
    )


@router.post("/{file_id}")
def file_operation(file_id: uuid.UUID, request: Request, db: DbSession) -> Response:
    op = request.headers.get("x-wopi-override", "").upper()
    if op not in {"LOCK", "UNLOCK", "REFRESH_LOCK", "GET_LOCK", "UNLOCK_AND_RELOCK"}:
        return Response(
            status_code=501
        )  # PUT_RELATIVE, RENAME_FILE, ... are deliberately unsupported
    try:
        current = wopi.lock_op(
            db,
            _token(request),
            file_id,
            op,
            request.headers.get("x-wopi-lock", ""),
            request.headers.get("x-wopi-oldlock"),
        )
    except wopi.WopiConflict as exc:
        return _conflict(exc.current_lock)
    return Response(status_code=200, headers={"X-WOPI-Lock": current})
