"""The two friendly permission vocabularies, and how they map onto internal capabilities.

* Share dialog: View, Download, Upload, Share, Sync, Delete, Manage.
* Folder permissions dialog: Read, Write, Share, Delete, Manage.

Internally everything is the one ``Action`` vocabulary enforced by the authorization service; these
maps only translate for the UI and API so a label always means the same thing in both places, in
audit events, and when read back. A label is "on" only if *every* capability it stands for is held.
"""

from __future__ import annotations

from collections.abc import Iterable

from app.db.enums import Action

A = Action

SHARE_LABELS: dict[str, tuple[str, ...]] = {
    "view": (A.VIEW.value, A.PREVIEW.value),
    "download": (A.DOWNLOAD.value,),
    "upload": (A.CREATE_CHILD.value, A.UPLOAD_VERSION.value),
    "share": (A.SHARE.value,),
    "sync": (A.SYNC.value,),
    "delete": (A.DELETE.value, A.RESTORE.value),
    "manage": (A.MANAGE_ACCESS.value,),
}
ACL_LABELS: dict[str, tuple[str, ...]] = {
    "read": (A.VIEW.value, A.PREVIEW.value, A.DOWNLOAD.value),
    "write": (
        A.CREATE_CHILD.value,
        A.UPLOAD_VERSION.value,
        A.EDIT_METADATA.value,
        A.RENAME.value,
        A.MOVE.value,
        A.COPY.value,
        A.COMMENT.value,
    ),
    "share": (A.SHARE.value,),
    "delete": (A.DELETE.value, A.RESTORE.value),
    "manage": (A.MANAGE_ACCESS.value,),
}
# Capabilities that need the grantor to hold them (no escalation) and are called out as sensitive.
SENSITIVE = frozenset({A.SHARE.value, A.DELETE.value, A.RESTORE.value, A.MANAGE_ACCESS.value})
# What a *minimal* invitation carries: see and preview, nothing more.
MINIMUM = (A.VIEW.value, A.PREVIEW.value)


def to_actions(labels: Iterable[str], table: dict[str, tuple[str, ...]]) -> list[str]:
    out: set[str] = set()
    for label in labels:
        if label not in table:
            raise ValueError(f"Unknown permission '{label}'.")
        out.update(table[label])
    return sorted(out)


def to_labels(actions: Iterable[str], table: dict[str, tuple[str, ...]]) -> list[str]:
    held = set(actions)
    return [label for label, needs in table.items() if set(needs) <= held]
