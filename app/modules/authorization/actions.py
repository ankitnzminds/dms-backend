"""Capability vocabulary helpers (no DB access)."""

from __future__ import annotations

from collections.abc import Iterable

from app.db.enums import Action

ALL_ACTIONS: frozenset[str] = frozenset(a.value for a in Action)

# What an owner (creator) of a folder/document may do. ADMINISTER stays an org-admin capability.
OWNER_ACTIONS: frozenset[str] = ALL_ACTIONS - {Action.ADMINISTER.value}

# Actions a share can carry. Sharing never delegates re-sharing, deletion, moving or access
# management: those stay with owners/admins (prevents privilege escalation through shares).
SHAREABLE_ACTIONS: frozenset[str] = frozenset(
    a.value
    for a in (
        Action.VIEW,
        Action.PREVIEW,
        Action.DOWNLOAD,
        Action.UPLOAD_VERSION,
        Action.CREATE_CHILD,
        Action.EDIT_METADATA,
        Action.RENAME,
        Action.COMMENT,
        Action.CREATE_FOLDER,
        Action.UPLOAD,
        Action.CREATE_FILE,
        Action.VIEW_VERSIONS,
        Action.RESTORE_VERSION,
        Action.LOCK,
    )
)

_VIEW = Action.VIEW.value
_DISCOVER = Action.DISCOVER.value


def expand_actions(actions: Iterable[str]) -> frozenset[str]:
    """Closure: holding any operational action implies being able to see (view) the resource,
    and viewing implies discovery. Keeps grants minimal without allowing blind operations."""
    result = {a for a in actions if a in ALL_ACTIONS}
    if Action.CREATE_CHILD.value in result:  # the older "create anything" umbrella
        result.update((Action.CREATE_FOLDER.value, Action.UPLOAD.value, Action.CREATE_FILE.value))
    if result - {_DISCOVER}:
        result.add(_VIEW)
    if _VIEW in result:
        result.add(_DISCOVER)
    return frozenset(result)


def validate_known_actions(actions: Iterable[str]) -> list[str]:
    cleaned = sorted({a for a in actions})
    unknown = [a for a in cleaned if a not in ALL_ACTIONS]
    if unknown:
        raise ValueError(f"Unknown actions: {', '.join(unknown)}")
    return cleaned
