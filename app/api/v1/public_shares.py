"""Anonymous, read-only access through an open share link (see modules/sharing/public.py).
No authentication; every request is rate limited by client address."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from app.api.deps import DbSession
from app.core.ratelimit import rate_limit
from app.modules.documents import downloads
from app.modules.sharing import public

router = APIRouter(
    prefix="/public/shares",
    tags=["public-links"],
    dependencies=[Depends(rate_limit("public_link", sensitive=True))],
)


@router.get("/{token}", summary="What this open link points at")
def describe(token: str, db: DbSession) -> dict[str, object]:
    return public.describe(db, token)


@router.get("/{token}/children", summary="List a shared folder (or a sub-folder of it)")
def children(
    token: str, db: DbSession, folder_id: uuid.UUID | None = None
) -> list[dict[str, object]]:
    return public.children(db, token, folder_id)


@router.get("/{token}/documents/{document_id}/download", summary="Download a shared file")
def download(token: str, document_id: uuid.UUID, db: DbSession) -> StreamingResponse:
    s = public.servable_for(db, token, document_id)
    return StreamingResponse(
        downloads.open_stream(s),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": downloads.content_disposition("attachment", s.filename),
            "Content-Length": str(s.size),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
