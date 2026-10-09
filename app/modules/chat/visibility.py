"""Re-apply CURRENT authorization when stored chat content is displayed or replayed.

An assistant message remembers which rights its content depended on (``access_guards``). If the
viewer has since lost any of them (revocation, move, reclassification, deletion) the message is
shown as redacted and is never fed back to the model - a revoked user cannot replay old answers.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.db.enums import Action
from app.db.models import ChatMessage
from app.modules.authorization.service import AuthorizationService
from app.schemas.chat import CitationOut

REDACTED_TEXT = (
    "This earlier answer is hidden because your access to one of its sources has changed."
)


def _doc_actions(authz: AuthorizationService, doc_id: uuid.UUID) -> frozenset[str]:
    d = authz.load_document(doc_id)
    return authz.document_actions([d]).get(d.id, frozenset()) if d else frozenset()


def _folder_actions(authz: AuthorizationService, folder_id: uuid.UUID) -> frozenset[str]:
    f = authz.load_folder(folder_id)
    return authz.folder_actions([f.id]).get(f.id, frozenset()) if f else frozenset()


def guard_ok(authz: AuthorizationService, guard: str) -> bool:
    parts = guard.split(":")
    try:
        if parts[0] == "preview":
            doc = authz.load_document(uuid.UUID(parts[1]))
            if doc is None:
                return False
            acts = authz.document_actions([doc]).get(doc.id, frozenset())
            return (
                Action.PREVIEW.value in acts
                and Action.DISCOVER.value in acts
                and doc.classification not in authz.share_blocked_classifications()
            )
        if parts[0] == "share":
            rid = uuid.UUID(parts[2])
            acts = (
                _doc_actions(authz, rid) if parts[1] == "document" else _folder_actions(authz, rid)
            )
            return Action.SHARE.value in acts and Action.DISCOVER.value in acts
    except (ValueError, IndexError):
        return False
    return False


def message_visible(db: Any, authz: AuthorizationService, m: ChatMessage) -> bool:
    return all(guard_ok(authz, g) for g in m.access_guards or [])


def citations_out(authz: AuthorizationService, m: ChatMessage) -> list[CitationOut]:
    out: list[CitationOut] = []
    for c in m.citations or []:
        did = uuid.UUID(c["document_id"])
        acts = _doc_actions(authz, did)
        ok = Action.DISCOVER.value in acts and Action.PREVIEW.value in acts
        out.append(
            CitationOut(
                ref=c["ref"],
                document_id=did,
                version_id=uuid.UUID(c["version_id"]),
                version_number=c["version_number"],
                chunk_index=c["chunk_index"],
                document_name=c.get("document_name") if ok else None,
                accessible=ok,
                route=f"/documents/{did}" if ok else None,
            )
        )
    return out


def blocks_out(authz: AuthorizationService, blocks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop (not redact-in-place) anything the viewer may no longer see."""
    result: list[dict[str, Any]] = []
    for b in blocks or []:
        t = b.get("type")
        if t == "documents":
            keep = []
            for item in b.get("items", []):
                try:
                    rid = uuid.UUID(item["id"])
                except (KeyError, ValueError):
                    continue
                acts = (
                    _doc_actions(authz, rid)
                    if item.get("kind") == "document"
                    else _folder_actions(authz, rid)
                )
                if Action.DISCOVER.value in acts:
                    keep.append(item)
            if keep:
                result.append({**b, "items": keep})
        elif t == "sharing":
            res = b.get("resource", {})
            if guard_ok(authz, f"share:{res.get('type')}:{res.get('id')}"):
                result.append(b)
        else:
            result.append(b)
    return result
