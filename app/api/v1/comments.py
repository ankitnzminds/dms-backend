"""Comments on documents and folders (shared recipients with comment access can comment)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, Response

from app.api.deps import Authz, DbSession, limited
from app.core.errors import ErrorResponse
from app.modules.comments import service as svc
from app.schemas.comments import CommentCreate, CommentEdit, CommentList, CommentOut

router = APIRouter(
    tags=["comments"], responses={404: {"model": ErrorResponse}, 403: {"model": ErrorResponse}}
)


def _list(
    db: DbSession, authz: Authz, rtype: str, rid: uuid.UUID, limit: int, offset: int
) -> CommentList:
    items, total, can = svc.list_comments(db, authz, rtype, rid, limit=limit, offset=offset)
    return CommentList(items=items, total=total, limit=limit, offset=offset, can_comment=can)


@router.get(
    "/documents/{document_id}/comments",
    response_model=CommentList,
    summary="Comments on a document",
)
def list_document_comments(
    document_id: uuid.UUID,
    db: DbSession,
    authz: Authz,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> CommentList:
    return _list(db, authz, "document", document_id, limit, offset)


@router.post(
    "/documents/{document_id}/comments",
    response_model=CommentOut,
    status_code=201,
    summary="Comment on a document (needs the comment permission)",
    dependencies=[limited("comments")],
)
def add_document_comment(
    document_id: uuid.UUID, body: CommentCreate, db: DbSession, authz: Authz
) -> CommentOut:
    return svc.add_comment(db, authz, "document", document_id, body.body, body.parent_id)


@router.get(
    "/folders/{folder_id}/comments", response_model=CommentList, summary="Comments on a folder"
)
def list_folder_comments(
    folder_id: uuid.UUID,
    db: DbSession,
    authz: Authz,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> CommentList:
    return _list(db, authz, "folder", folder_id, limit, offset)


@router.post(
    "/folders/{folder_id}/comments",
    response_model=CommentOut,
    status_code=201,
    summary="Comment on a folder (needs the comment permission)",
    dependencies=[limited("comments")],
)
def add_folder_comment(
    folder_id: uuid.UUID, body: CommentCreate, db: DbSession, authz: Authz
) -> CommentOut:
    return svc.add_comment(db, authz, "folder", folder_id, body.body, body.parent_id)


@router.patch("/comments/{comment_id}", response_model=CommentOut, summary="Edit my comment")
def edit_comment(
    comment_id: uuid.UUID, body: CommentEdit, db: DbSession, authz: Authz
) -> CommentOut:
    return svc.edit_comment(db, authz, comment_id, body.body)


@router.delete("/comments/{comment_id}", status_code=204, summary="Delete my comment (or moderate)")
def delete_comment(comment_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    svc.delete_comment(db, authz, comment_id)
    return Response(status_code=204)
