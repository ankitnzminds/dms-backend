"""Search over names (PostgreSQL FTS + substring) with authorization applied BEFORE anything is
returned: rows, totals, breadcrumbs and permissions. Unauthorized candidates are dropped and
never counted, so results, totals and paths cannot leak hidden siblings or parents.

Extracted-text search arrives with the processing pipeline (Phase 7); this is names + metadata.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.enums import Action
from app.db.models import Document, DocumentVersion, Folder
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import subtree_folder_ids
from app.modules.folders.service import mask_policy, to_breadcrumb_out
from app.schemas.common import ApiModel, BreadcrumbSegmentOut

MAX_CANDIDATES = 500


class SearchResult(ApiModel):
    kind: Literal["folder", "document"]
    id: uuid.UUID
    name: str
    updated_at: datetime
    permissions: list[str]
    breadcrumb: list[BreadcrumbSegmentOut]
    size_bytes: int | None = None
    content_type: str | None = None
    status: str | None = None


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search(
    db: Session,
    authz: AuthorizationService,
    *,
    q: str,
    folder_id: uuid.UUID | None,
    kind: str | None,
    owner_id: uuid.UUID | None,
    content_type: str | None,
    modified_after: datetime | None,
    modified_before: datetime | None,
    limit: int,
    offset: int,
) -> tuple[list[SearchResult], int]:
    p = authz.principal
    org = p.organization_id
    q = q.strip()
    scope: list[uuid.UUID] | None = None
    if folder_id is not None:
        base = authz.require_folder(folder_id, Action.DISCOVER)
        scope = subtree_folder_ids(db, org, base.id)

    pattern = f"%{_escape_like(q.lower())}%"
    docs: list[Document] = []
    folders: list[Folder] = []

    if kind in (None, "document"):
        ts = func.websearch_to_tsquery("simple", q)
        stmt = select(Document).where(
            Document.organization_id == org,
            Document.deleted_at.is_(None),
            or_(
                Document.search_vector.op("@@")(ts),
                func.lower(Document.name).like(pattern, escape="\\"),
            ),
        )
        if scope is not None:
            stmt = stmt.where(Document.folder_id.in_(scope))
        if owner_id:
            stmt = stmt.where(Document.owner_id == owner_id)
        if modified_after:
            stmt = stmt.where(Document.updated_at >= modified_after)
        if modified_before:
            stmt = stmt.where(Document.updated_at <= modified_before)
        if content_type:
            stmt = stmt.join(
                DocumentVersion, DocumentVersion.id == Document.current_version_id
            ).where(DocumentVersion.content_type == content_type)
        docs = list(
            db.scalars(
                stmt.order_by(
                    func.ts_rank(Document.search_vector, ts).desc(), Document.updated_at.desc()
                ).limit(MAX_CANDIDATES)
            )
        )
    if kind in (None, "folder") and not (owner_id or content_type):
        fstmt = select(Folder).where(
            Folder.organization_id == org,
            Folder.deleted_at.is_(None),
            Folder.parent_folder_id.is_not(None),
            func.lower(Folder.name).like(pattern, escape="\\"),
        )
        if scope is not None:
            fstmt = fstmt.where(Folder.id.in_(scope))
        if modified_after:
            fstmt = fstmt.where(Folder.updated_at >= modified_after)
        if modified_before:
            fstmt = fstmt.where(Folder.updated_at <= modified_before)
        folders = list(db.scalars(fstmt.order_by(Folder.updated_at.desc()).limit(MAX_CANDIDATES)))

    doc_perms = authz.document_actions(docs)
    folder_perms = authz.folder_actions([f.id for f in folders])
    docs = [d for d in docs if Action.DISCOVER.value in doc_perms.get(d.id, ())]
    folders = [f for f in folders if Action.DISCOVER.value in folder_perms.get(f.id, ())]

    page_docs, page_folders = docs, folders  # slice after merge below
    merged: list[tuple[str, Document | Folder]] = [("document", d) for d in page_docs] + [
        ("folder", f) for f in page_folders
    ]
    total = len(merged)
    window = merged[offset : offset + limit]

    parent_ids = [
        item.folder_id if isinstance(item, Document) else item.parent_folder_id
        for _, item in window
    ]
    crumbs = authz.breadcrumbs_for_folders(
        [x for x in parent_ids if x], mask_unauthorized=mask_policy(db, authz)
    )
    vids = [
        item.current_version_id
        for _, item in window
        if isinstance(item, Document) and item.current_version_id
    ]
    versions = (
        {v.id: v for v in db.scalars(select(DocumentVersion).where(DocumentVersion.id.in_(vids)))}
        if vids
        else {}
    )

    results: list[SearchResult] = []
    for _, item in window:
        if isinstance(item, Document):
            d = item
            v = versions.get(d.current_version_id) if d.current_version_id else None
            results.append(
                SearchResult(
                    kind="document",
                    id=d.id,
                    name=d.name,
                    updated_at=d.updated_at,
                    permissions=sorted(doc_perms[d.id]),
                    breadcrumb=to_breadcrumb_out(crumbs.get(d.folder_id, [])),
                    size_bytes=v.size_bytes if v else None,
                    content_type=v.content_type if v else None,
                    status=d.status,
                )
            )
        else:
            f = item
            results.append(
                SearchResult(
                    kind="folder",
                    id=f.id,
                    name=f.name,
                    updated_at=f.updated_at,
                    permissions=sorted(folder_perms[f.id]),
                    breadcrumb=to_breadcrumb_out(
                        crumbs.get(f.parent_folder_id, []) if f.parent_folder_id else []
                    ),
                )
            )
    return results, total
