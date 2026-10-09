"""Permission-first retrieval for the agent.

Order matters and is the whole security property: candidates come from the permission-filtered
search (or are explicitly authorized), the PREVIEW right and the DLP classification rule are
checked, and ONLY THEN is extracted text loaded. Text of a document the caller may not preview
never reaches this module's return value, so it can never enter model context.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.enums import Action
from app.db.models import Document, DocumentText
from app.modules.authorization.service import AuthorizationService
from app.modules.search import service as search

CHUNK_CHARS = 1200
CHUNK_OVERLAP = 150
MAX_TEXT_CHARS = 400_000  # per document; extraction already caps at settings.extract_max_chars
_STOP = frozenset(
    [
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "with",
        "is",
        "are",
        "was",
        "were",
        "be",
        "been",
        "what",
        "which",
        "who",
        "whom",
        "whose",
        "when",
        "where",
        "why",
        "how",
        "do",
        "does",
        "did",
        "can",
        "could",
        "should",
        "would",
        "about",
        "from",
        "by",
        "at",
        "as",
        "it",
        "its",
        "this",
        "that",
        "these",
        "those",
        "me",
        "my",
        "our",
        "we",
        "you",
        "your",
        "their",
        "there",
        "any",
        "all",
    ]
)


@dataclass(frozen=True)
class Passage:
    document_id: uuid.UUID
    document_name: str
    version_id: uuid.UUID
    version_number: int
    chunk_index: int
    text: str


def terms(query: str) -> list[str]:
    seen: list[str] = []
    for tok in re.findall(r"[\w'-]+", query.lower()):
        tok = tok.strip("'-")
        if len(tok) > 2 and tok not in _STOP and tok not in seen:
            seen.append(tok)
    return seen


def chunk(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    step = CHUNK_CHARS - CHUNK_OVERLAP
    for i, start in enumerate(range(0, max(len(text), 1), step)):
        piece = text[start : start + CHUNK_CHARS].strip()
        if piece:
            out.append((i, piece))
        if start + CHUNK_CHARS >= len(text):
            break
    return out


def _score(piece: str, qterms: list[str]) -> int:
    low = piece.lower()
    return sum(low.count(t) for t in qterms)


def eligible_documents(
    db: Session, authz: AuthorizationService, doc_ids: list[uuid.UUID]
) -> list[Document]:
    """Documents the caller may PREVIEW whose classification may be sent to the model provider.
    Anything else is silently excluded (no existence oracle)."""
    blocked = authz.share_blocked_classifications()
    docs: list[Document] = []
    loaded = [d for i in doc_ids if (d := authz.load_document(i)) is not None]
    perms = authz.document_actions(loaded) if loaded else {}
    for d in loaded:
        acts = perms.get(d.id, frozenset())
        if (
            Action.DISCOVER.value in acts
            and Action.PREVIEW.value in acts
            and d.classification not in blocked
            and d.status == "available"
        ):
            docs.append(d)
    return docs


def find_candidates(
    db: Session, authz: AuthorizationService, query: str, *, limit: int
) -> list[uuid.UUID]:
    """Permission-filtered candidate documents for a natural-language query."""

    def run(q: str) -> list[uuid.UUID]:
        results, _ = search.search(
            db,
            authz,
            q=q,
            scope="all",
            folder_id=None,
            kind="document",
            owner_id=None,
            content_type=None,
            modified_after=None,
            modified_before=None,
            meta=[],
            limit=limit,
            offset=0,
        )
        return [r.id for r in results]

    found = run(query) if query.strip() else []
    if found:
        return found[:limit]
    ids: list[uuid.UUID] = []
    for term in sorted(terms(query), key=len, reverse=True)[:5]:  # OR-style fallback
        for i in run(term):
            if i not in ids:
                ids.append(i)
    return ids[:limit]


def retrieve(
    db: Session,
    authz: AuthorizationService,
    query: str,
    *,
    document_ids: list[uuid.UUID] | None = None,
    limit: int = 6,
) -> list[Passage]:
    org = authz.principal.organization_id
    candidates = document_ids or find_candidates(db, authz, query, limit=10)
    docs = eligible_documents(db, authz, candidates)  # authorization BEFORE any text is loaded
    if not docs:
        return []
    version_ids = [d.current_version_id for d in docs if d.current_version_id]
    rows = {
        r.version_id: r
        for r in db.scalars(
            select(DocumentText).where(
                DocumentText.version_id.in_(version_ids),
                DocumentText.organization_id == org,
                DocumentText.status == "extracted",
            )
        )
    }
    qterms = terms(query)
    scored: list[tuple[int, int, Passage]] = []
    for order, d in enumerate(docs):
        row = rows.get(d.current_version_id) if d.current_version_id else None
        if row is None or not row.content:
            continue
        for idx, piece in chunk(row.content[:MAX_TEXT_CHARS]):
            score = _score(piece, qterms) if qterms else 1
            if score > 0 or document_ids:
                scored.append(
                    (
                        score,
                        -order,
                        Passage(d.id, d.name, row.version_id, d.latest_version_number, idx, piece),
                    )
                )
    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    best = [p for _, _, p in scored[:limit]]
    if document_ids:  # explicit documents: best passages first picked, then shown in reading order
        best.sort(key=lambda p: (str(p.document_id), p.chunk_index))
    return best
