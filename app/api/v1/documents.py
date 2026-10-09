"""Document endpoints: metadata, versions, download tickets, sharing, ACL."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import Authz, DbSession, limited
from app.api.v1.uploads import IdempotencyKey, session_out
from app.core.errors import ErrorResponse
from app.db.enums import ResourceType
from app.modules.authorization import acl
from app.modules.documents import downloads
from app.modules.documents import service as documents
from app.modules.sharing import service as sharing
from app.modules.uploads import service as uploads
from app.schemas.admin import (
    DownloadUrlOut,
    DownloadUrlRequest,
    UploadInitiate,
    UploadSessionOut,
)
from app.schemas.sharing import PermissionGrantIn, PermissionGrantOut, ShareCreate, ShareOut
from app.schemas.tree import (
    DocumentCopyRequest,
    DocumentOut,
    DocumentUpdate,
    RestoreRequest,
    VersionOut,
)

router = APIRouter(
    prefix="/documents", tags=["documents"], responses={404: {"model": ErrorResponse}}
)


@router.get("/{document_id}", response_model=DocumentOut, summary="Document details")
def get_document(document_id: uuid.UUID, db: DbSession, authz: Authz) -> DocumentOut:
    return documents.get_document(db, authz, document_id)


@router.patch(
    "/{document_id}",
    response_model=DocumentOut,
    summary="Rename, move, edit metadata/classification",
)
def update_document(
    document_id: uuid.UUID, body: DocumentUpdate, db: DbSession, authz: Authz
) -> DocumentOut:
    return documents.update_document(
        db,
        authz,
        document_id,
        name=body.name,
        folder_id=body.folder_id,
        metadata=body.metadata,
        classification=body.classification,
        expected_row_version=body.expected_row_version,
    )


@router.delete("/{document_id}", status_code=204, summary="Move a document to the trash")
def delete_document(document_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    documents.delete_document(db, authz, document_id)
    return Response(status_code=204)


@router.post(
    "/{document_id}/restore", response_model=DocumentOut, summary="Restore a trashed document"
)
def restore_document(
    document_id: uuid.UUID, db: DbSession, authz: Authz, body: RestoreRequest | None = None
) -> DocumentOut:
    return documents.restore_document(db, authz, document_id, body.new_name if body else None)


@router.post(
    "/{document_id}/copy",
    response_model=DocumentOut,
    status_code=201,
    summary="Copy to a new document identity",
)
def copy_document(
    document_id: uuid.UUID, body: DocumentCopyRequest, db: DbSession, authz: Authz
) -> DocumentOut:
    return documents.copy_document(db, authz, document_id, body.target_folder_id, body.name)


@router.put("/{document_id}/star", status_code=204, summary="Star a document")
def star(document_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    documents.set_star(db, authz, document_id, True)
    return Response(status_code=204)


@router.delete("/{document_id}/star", status_code=204, summary="Remove star")
def unstar(document_id: uuid.UUID, db: DbSession, authz: Authz) -> Response:
    documents.set_star(db, authz, document_id, False)
    return Response(status_code=204)


# ---- versions
@router.get("/{document_id}/versions", response_model=list[VersionOut], summary="Version history")
def list_versions(document_id: uuid.UUID, db: DbSession, authz: Authz) -> list[VersionOut]:
    return documents.list_versions(db, authz, document_id)


@router.post(
    "/{document_id}/versions/{version_number}/restore",
    response_model=VersionOut,
    status_code=201,
    summary="Restore an old version as a NEW version (history is preserved)",
)
def restore_version(
    document_id: uuid.UUID, version_number: int, db: DbSession, authz: Authz
) -> VersionOut:
    return documents.restore_version(db, authz, document_id, version_number)


@router.post(
    "/{document_id}/uploads",
    response_model=UploadSessionOut,
    status_code=201,
    summary="Start uploading a new version",
    dependencies=[limited("upload_initiate")],
)
def initiate_version_upload(
    document_id: uuid.UUID,
    body: UploadInitiate,
    db: DbSession,
    authz: Authz,
    idempotency_key: IdempotencyKey = None,
) -> UploadSessionOut:
    session = uploads.initiate(
        db,
        authz,
        folder_id=None,
        document_id=document_id,
        filename=body.filename,
        size_bytes=body.size_bytes,
        content_type=body.content_type,
        sha256=body.sha256,
        expected_latest_version=body.expected_latest_version,
        idempotency_key=idempotency_key,
    )
    return session_out(session)


# ---- download / preview tickets
@router.post(
    "/{document_id}/download-url",
    response_model=DownloadUrlOut,
    summary="Authorize, then issue a short-lived download (or inline preview) URL",
    dependencies=[limited("download_url", sensitive=True)],
)
def download_url(
    document_id: uuid.UUID, body: DownloadUrlRequest, db: DbSession, authz: Authz
) -> DownloadUrlOut:
    url, expires = downloads.create_download_url(
        db, authz, document_id, version_number=body.version_number, inline=body.inline
    )
    return DownloadUrlOut(url=url, expires_at=expires)


# ---- sharing & ACL
@router.post(
    "/{document_id}/shares",
    response_model=ShareOut,
    status_code=201,
    summary="Share this document (a grant on the original; no copy is made)",
    dependencies=[limited("share_create", sensitive=True)],
)
def share_document(
    document_id: uuid.UUID, body: ShareCreate, db: DbSession, authz: Authz
) -> ShareOut:
    return sharing.create_share(db, authz, ResourceType.DOCUMENT, document_id, body)


@router.get(
    "/{document_id}/shares", response_model=list[ShareOut], summary="Shares of this document"
)
def document_shares(document_id: uuid.UUID, db: DbSession, authz: Authz) -> list[ShareOut]:
    return sharing.list_for_resource(db, authz, ResourceType.DOCUMENT, document_id)


@router.get(
    "/{document_id}/permissions",
    response_model=list[PermissionGrantOut],
    summary="ACL entries (requires manage_access)",
)
def document_permissions(
    document_id: uuid.UUID, db: DbSession, authz: Authz
) -> list[PermissionGrantOut]:
    return acl.list_grants(db, authz, ResourceType.DOCUMENT, document_id)


@router.post(
    "/{document_id}/permissions",
    response_model=PermissionGrantOut,
    status_code=201,
    summary="Add an ACL entry",
)
def add_document_permission(
    document_id: uuid.UUID, body: PermissionGrantIn, db: DbSession, authz: Authz
) -> PermissionGrantOut:
    return acl.add_grant(db, authz, ResourceType.DOCUMENT, document_id, body)


@router.delete(
    "/{document_id}/permissions/{grant_id}", status_code=204, summary="Revoke an ACL entry"
)
def revoke_document_permission(
    document_id: uuid.UUID, grant_id: uuid.UUID, db: DbSession, authz: Authz
) -> Response:
    acl.revoke_grant(db, authz, ResourceType.DOCUMENT, document_id, grant_id)
    return Response(status_code=204)
