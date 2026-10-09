"""Format-independent diff primitives and the result model.

A comparison is a list of *sections* (a page, a sheet, a slide, "Body", "Header"...), each with
*changes*. Unchanged runs collapse into ``skip`` entries (with two lines of context kept) so large
documents stay small on the wire.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

PARSER_VERSION = "1.0"
CONTEXT = 2
MAX_CHANGES = 4000
_TOKEN = re.compile(r"\s+|\w+|[^\w\s]", re.UNICODE)


@dataclass
class Section:
    title: str
    changes: list[dict[str, Any]] = field(default_factory=list)
    status: str = "changed"  # unchanged | changed | added | removed
    note: str | None = None

    def out(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "status": self.status,
            "note": self.note,
            "changes": self.changes,
        }


@dataclass
class Counts:
    added: int = 0
    removed: int = 0
    changed: int = 0
    unchanged: int = 0

    def add(self, op: str, n: int = 1) -> None:
        if op == "add":
            self.added += n
        elif op == "remove":
            self.removed += n
        elif op == "change":
            self.changed += n
        elif op == "equal":
            self.unchanged += n


def inline_diff(old: str, new: str) -> list[dict[str, str]]:
    """Word-level diff of two strings: [{op: equal|add|remove, text}]."""
    a, b = _TOKEN.findall(old), _TOKEN.findall(new)
    out: list[dict[str, str]] = []
    for tag, i1, i2, j1, j2 in SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            out.append({"op": "equal", "text": "".join(a[i1:i2])})
        else:
            if i2 > i1:
                out.append({"op": "remove", "text": "".join(a[i1:i2])})
            if j2 > j1:
                out.append({"op": "add", "text": "".join(b[j1:j2])})
    return out


def diff_sequences(
    old: Sequence[str],
    new: Sequence[str],
    counts: Counts,
    *,
    loc_old: int = 1,
    loc_new: int = 1,
    old_meta: Sequence[Any] | None = None,
    new_meta: Sequence[Any] | None = None,
    meta_label: str = "formatting",
) -> tuple[list[dict[str, Any]], bool]:
    """Line/paragraph diff -> change entries. ``*_meta`` are parallel sequences (e.g. formatting
    signatures): equal text with different meta is reported as a ``change`` of that kind."""
    changes: list[dict[str, Any]] = []
    truncated = False
    sm = SequenceMatcher(None, list(old), list(new), autojunk=False)

    def push(entry: dict[str, Any]) -> None:
        nonlocal truncated
        if len(changes) >= MAX_CHANGES:
            truncated = True
            return
        changes.append(entry)

    ops = sm.get_opcodes()
    for n, (tag, i1, i2, j1, j2) in enumerate(ops):
        if tag == "equal":
            lead = n > 0  # a change precedes this run
            trail = n < len(ops) - 1  # a change follows it
            run: list[dict[str, Any]] = []
            for k in range(i2 - i1):
                i, j = i1 + k, j1 + k
                if old_meta is not None and new_meta is not None and old_meta[i] != new_meta[j]:
                    counts.add("change")
                    run.append(
                        {
                            "op": "change",
                            "kind": meta_label,
                            "old": old[i],
                            "new": new[j],
                            "old_loc": loc_old + i,
                            "new_loc": loc_new + j,
                            "detail": f"{meta_label}: {old_meta[i] or '-'} → {new_meta[j] or '-'}",
                        }
                    )
                else:
                    counts.add("equal")
                    run.append(
                        {
                            "op": "equal",
                            "old": old[i],
                            "new": new[j],
                            "old_loc": loc_old + i,
                            "new_loc": loc_new + j,
                        }
                    )
            _emit_with_context(run, push, lead=lead, trail=trail)
        elif tag == "delete":
            for i in range(i1, i2):
                counts.add("remove")
                push({"op": "remove", "old": old[i], "old_loc": loc_old + i})
        elif tag == "insert":
            for j in range(j1, j2):
                counts.add("add")
                push({"op": "add", "new": new[j], "new_loc": loc_new + j})
        else:  # replace: pair up the overlap as changes, the remainder as add/remove
            pair = min(i2 - i1, j2 - j1)
            for k in range(pair):
                counts.add("change")
                push(
                    {
                        "op": "change",
                        "old": old[i1 + k],
                        "new": new[j1 + k],
                        "old_loc": loc_old + i1 + k,
                        "new_loc": loc_new + j1 + k,
                        "inline": inline_diff(old[i1 + k], new[j1 + k]),
                    }
                )
            for i in range(i1 + pair, i2):
                counts.add("remove")
                push({"op": "remove", "old": old[i], "old_loc": loc_old + i})
            for j in range(j1 + pair, j2):
                counts.add("add")
                push({"op": "add", "new": new[j], "new_loc": loc_new + j})
    return changes, truncated


def _emit_with_context(run: list[dict[str, Any]], push: Any, *, lead: bool, trail: bool) -> None:
    """Keep CONTEXT unchanged lines next to a change, collapse the rest into one skip entry."""
    if not run:
        return
    keep = [e["op"] != "equal" for e in run]
    show = [False] * len(run)
    for i, k in enumerate(keep):
        if k:
            for d in range(-CONTEXT, CONTEXT + 1):
                if 0 <= i + d < len(run):
                    show[i + d] = True
    if lead:
        for i in range(min(CONTEXT, len(run))):
            show[i] = True
    if trail:
        for i in range(max(0, len(run) - CONTEXT), len(run)):
            show[i] = True
    if not any(show):
        push({"op": "skip", "count": len(run)})
        return
    hidden = 0
    for entry, vis in zip(run, show, strict=True):
        if vis:
            if hidden:
                push({"op": "skip", "count": hidden})
                hidden = 0
            push(entry)
        else:
            hidden += 1
    if hidden:
        push({"op": "skip", "count": hidden})


def line_diff_section(
    title: str, old: Sequence[str], new: Sequence[str], counts: Counts
) -> Section:
    changes, _ = diff_sequences(old, new, counts)
    status = "unchanged" if all(c["op"] in ("equal", "skip") for c in changes) else "changed"
    return Section(title=title, changes=changes, status=status)
