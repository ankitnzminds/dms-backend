"""Search over names, metadata and extracted text (PostgreSQL FTS) with authorization applied
BEFORE anything is returned: rows, totals, breadcrumbs, permissions and snippets.

* Unauthorized candidates are dropped and never counted, so results/totals/paths cannot leak
  hidden siblings or parents.
* A *content* match reveals information about the file's text, so it is only honoured (and a
  snippet only produced) when the caller holds the PREVIEW right on that document. A user who
  may merely see a document's name can find it by name, never by what is inside it.
* The index is derived data: it is rebuildable from versions and always re-checked against the
  source-of-truth permissions at query time.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.db.enums import Action
from app.db.models import Document, DocumentText, DocumentVersion, Folder
from app.modules.authorization.service import AuthorizationService
from app.modules.folders.common import subtree_folder_ids
from app.modules.folders.service import mask_policy, to_breadcrumb_out
from app.modules.metadata.service import parse_filters
from app.schemas.common import ActionName, ApiModel, BreadcrumbSegmentOut

MAX_CANDIDATES = 500
SNIPPET_SOURCE_CHARS = 200_000


class SearchResult(ApiModel):
    kind: Literal["folder", "document"]
    id: uuid.UUID
    name: str
    updated_at: datetime
    permissions: list[ActionName]
    breadcrumb: list[BreadcrumbSegmentOut]
    size_bytes: int | None = None
    content_type: str | None = None
    status: str | None = None
    match: Literal["name", "content", "both"] | None = None
    snippet: str | None = None  # plain text; matched terms wrapped in [[ ]] - never HTML


_WORD = re.compile(r"[^\W_]+")  # unicode letters/digits only: safe to splice into a tsquery


def query_terms(q: str) -> list[str]:
    return _WORD.findall(q.lower())[:8]


def build_tsquery(q: str, *, any_term: bool = False) -> Any:
    """Prefix-matching query: 'budg 2026' finds 'budget ... 2026' (as-you-type search). Quoted
    phrases and -exclusions/OR keep PostgreSQL's web-search semantics."""
    terms = query_terms(q)
    if not terms or '"' in q or re.search(r"(^|\s)(-\S|or(\s|$))", q, re.IGNORECASE):
        return func.websearch_to_tsquery("simple", q)
    return func.to_tsquery("simple", (" | " if any_term else " & ").join(f"{t}:*" for t in terms))


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search(
    db: Session,
    authz: AuthorizationService,
    *,
    q: str,
    scope: Literal["all", "name", "content"],
    folder_id: uuid.UUID | None,
    kind: str | None,
    owner_id: uuid.UUID | None,
    content_type: str | None,
    modified_after: datetime | None,
    modified_before: datetime | None,
    meta: list[str],
    color_tag: str | None = None,
    limit: int,
    offset: int,
) -> tuple[list[SearchResult], int]:
    p = authz.principal
    org = p.organization_id
    q = q.strip()
    subtree: list[uuid.UUID] | None = None
    if folder_id is not None:
        base = authz.require_folder(folder_id, Action.DISCOVER)
        subtree = subtree_folder_ids(db, org, base.id)
    meta_filters = parse_filters(db, org, meta)

    pattern = f"%{_escape_like(q.lower())}%"
    ts = build_tsquery(q)

    def doc_filters(stmt):  # noqa: ANN001, ANN202
        stmt = stmt.where(Document.organization_id == org, Document.deleted_at.is_(None))
        if subtree is not None:
            stmt = stmt.where(Document.folder_id.in_(subtree))
        if owner_id:
            stmt = stmt.where(Document.owner_id == owner_id)
        if modified_after:
            stmt = stmt.where(Document.updated_at >= modified_after)
        if modified_before:
            stmt = stmt.where(Document.updated_at <= modified_before)
        for key, value in meta_filters.items():
            stmt = stmt.where(Document.custom_metadata[key].astext == value)
        if color_tag:
            stmt = stmt.where(Document.color_tag == color_tag)
        if content_type:
            stmt = stmt.join(
                DocumentVersion, DocumentVersion.id == Document.current_version_id
            ).where(DocumentVersion.content_type == content_type)
        return stmt

    folders: list[Folder] = []

    def fetch(ts: Any) -> tuple[list[Document], list[Document]]:
        found_by_name: list[Document] = []
        found_by_content: list[Document] = []
        if kind in (None, "document") and scope in ("all", "name"):
            stmt = doc_filters(select(Document)).where(
                or_(
                    Document.search_vector.op("@@")(ts),
                    func.lower(Document.name).like(pattern, escape="\\"),
                )
            )
            found_by_name = list(
                db.scalars(
                    stmt.order_by(
                        func.ts_rank(Document.search_vector, ts).desc(), Document.updated_at.desc()
                    ).limit(MAX_CANDIDATES)
                )
            )
        if kind in (None, "document") and scope in ("all", "content"):
            stmt = (
                doc_filters(select(Document))
                .join(
                    DocumentText,
                    (DocumentText.version_id == Document.current_version_id)
                    & (DocumentText.organization_id == Document.organization_id),
                )
                .where(DocumentText.search_vector.op("@@")(ts))
            )
            found_by_content = list(
                db.scalars(
                    stmt.order_by(func.ts_rank(DocumentText.search_vector, ts).desc()).limit(
                        MAX_CANDIDATES
                    )
                )
            )
        return found_by_name, found_by_content

    name_docs, content_docs = fetch(ts)
    if not name_docs and not content_docs and len(query_terms(q)) > 1:
        # Nothing contains every word: fall back to documents that contain ANY of them, ranked.
        ts = build_tsquery(q, any_term=True)
        name_docs, content_docs = fetch(ts)

    if (
        kind in (None, "folder")
        and scope in ("all", "name")
        and not (owner_id or content_type or meta_filters)
    ):
        fstmt = select(Folder).where(
            Folder.organization_id == org,
            Folder.deleted_at.is_(None),
            Folder.parent_folder_id.is_not(None),
            func.lower(Folder.name).like(pattern, escape="\\"),
        )
        if color_tag:
            fstmt = fstmt.where(Folder.color_tag == color_tag)
        if subtree is not None:
            fstmt = fstmt.where(Folder.id.in_(subtree))
        if modified_after:
            fstmt = fstmt.where(Folder.updated_at >= modified_after)
        if modified_before:
            fstmt = fstmt.where(Folder.updated_at <= modified_before)
        folders = list(db.scalars(fstmt.order_by(Folder.updated_at.desc()).limit(MAX_CANDIDATES)))

    # ---- authorization BEFORE anything else is derived from the candidates
    unique_docs: dict[uuid.UUID, Document] = {d.id: d for d in [*name_docs, *content_docs]}
    doc_perms = authz.document_actions(list(unique_docs.values()))
    folder_perms = authz.folder_actions([f.id for f in folders])
    name_ids = {d.id for d in name_docs}
    content_ids = {d.id for d in content_docs}

    ordered: list[tuple[str, Document | Folder, str | None]] = []
    seen: set[uuid.UUID] = set()
    for d in [*name_docs, *content_docs]:
        if d.id in seen:
            continue
        perms = doc_perms.get(d.id, frozenset())
        if Action.DISCOVER.value not in perms:
            continue
        by_name = d.id in name_ids
        by_content = d.id in content_ids and Action.PREVIEW.value in perms
        if not (by_name or by_content):
            continue  # content hit without the right to read content: invisible
        seen.add(d.id)
        ordered.append(
            ("document", d, "both" if by_name and by_content else "name" if by_name else "content")
        )
    for f in folders:
        if Action.DISCOVER.value in folder_perms.get(f.id, ()):
            ordered.append(("folder", f, "name"))

    total = len(ordered)
    window = ordered[offset : offset + limit]

    parent_ids = [
        item.folder_id if isinstance(item, Document) else item.parent_folder_id
        for _, item, _ in window
    ]
    crumbs = authz.breadcrumbs_for_folders(
        [x for x in parent_ids if x], mask_unauthorized=mask_policy(db, authz)
    )
    vids = [
        item.current_version_id
        for _, item, _ in window
        if isinstance(item, Document) and item.current_version_id
    ]
    versions = (
        {v.id: v for v in db.scalars(select(DocumentVersion).where(DocumentVersion.id.in_(vids)))}
        if vids
        else {}
    )
    # Snippets: computed only for the visible page, only for documents the caller may preview.
    snippet_versions = [
        item.current_version_id
        for _, item, m in window
        if isinstance(item, Document)
        and item.current_version_id
        and m in ("content", "both")
        and Action.PREVIEW.value in doc_perms[item.id]
    ]
    snippets: dict[uuid.UUID, str] = {}
    if snippet_versions:
        rows = db.execute(
            select(
                DocumentText.version_id,
                func.ts_headline(
                    "simple",
                    func.left(DocumentText.content, SNIPPET_SOURCE_CHARS),
                    ts,
                    "StartSel=[[, StopSel=]], MaxFragments=2, MaxWords=24, MinWords=8, FragmentDelimiter= … ",
                ),
            ).where(
                DocumentText.version_id.in_(snippet_versions), DocumentText.organization_id == org
            )
        ).all()
        snippets = {vid: snippet for vid, snippet in rows}

    results: list[SearchResult] = []
    for _, item, match in window:
        if isinstance(item, Document):
            v = versions.get(item.current_version_id) if item.current_version_id else None
            results.append(
                SearchResult(
                    kind="document",
                    id=item.id,
                    name=item.name,
                    updated_at=item.updated_at,
                    permissions=sorted(doc_perms[item.id]),
                    breadcrumb=to_breadcrumb_out(crumbs.get(item.folder_id, [])),
                    size_bytes=v.size_bytes if v else None,
                    content_type=v.content_type if v else None,
                    status=item.status,
                    match=match,  # type: ignore[arg-type]
                    snippet=snippets.get(item.current_version_id)
                    if item.current_version_id
                    else None,
                )
            )
        else:
            results.append(
                SearchResult(
                    kind="folder",
                    id=item.id,
                    name=item.name,
                    updated_at=item.updated_at,
                    permissions=sorted(folder_perms[item.id]),
                    breadcrumb=to_breadcrumb_out(
                        crumbs.get(item.parent_folder_id, []) if item.parent_folder_id else []
                    ),
                    match="name",
                )
            )
    return results, total
