"""Plain text, Markdown, code, CSV, JSON and PDF text comparison."""

from __future__ import annotations

import io
import json
from typing import Any

from app.modules.diffs.core import Counts, Section, diff_sequences, line_diff_section

MAX_TEXT_BYTES = 5 * 1024 * 1024
MAX_PDF_PAGES = 300

TEXT_EXTENSIONS = {
    "txt",
    "md",
    "markdown",
    "csv",
    "tsv",
    "json",
    "xml",
    "html",
    "htm",
    "css",
    "js",
    "ts",
    "tsx",
    "jsx",
    "py",
    "java",
    "c",
    "h",
    "cpp",
    "cs",
    "go",
    "rs",
    "rb",
    "php",
    "sh",
    "yml",
    "yaml",
    "toml",
    "ini",
    "cfg",
    "log",
    "sql",
}


def decode(data: bytes) -> list[str]:
    if b"\x00" in data[:8192]:
        raise ValueError("binary")
    return (
        data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    )


def diff_text(old: bytes, new: bytes, counts: Counts) -> tuple[list[Section], list[str], bool]:
    ol, nl = decode(old), decode(new)
    changes, truncated = diff_sequences(ol, nl, counts)
    changed = any(c["op"] not in ("equal", "skip") for c in changes)
    return (
        [Section("Lines", changes, "changed" if changed else "unchanged")],
        ["Exact line-by-line comparison. Line endings are normalized."],
        truncated,
    )


def _flatten(value: Any, path: str = "$") -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(value, dict):
        for k, v in value.items():
            out.update(_flatten(v, f"{path}.{k}"))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            out.update(_flatten(v, f"{path}[{i}]"))
    else:
        out[path] = json.dumps(value, ensure_ascii=False)
    if not isinstance(value, (dict, list)):
        return out
    if not out:
        out[path] = "{}" if isinstance(value, dict) else "[]"
    return out


def diff_json(old: bytes, new: bytes, counts: Counts) -> tuple[list[Section], list[str], bool]:
    sections, notes, truncated = diff_text(old, new, counts)
    try:
        a, b = _flatten(json.loads(old)), _flatten(json.loads(new))
    except (ValueError, RecursionError):
        return (
            sections,
            notes + ["One of the files is not valid JSON, so no structural comparison was made."],
            truncated,
        )
    changes: list[dict[str, Any]] = []
    for path in sorted(set(a) | set(b)):
        if path not in a:
            changes.append({"op": "add", "loc": path, "new": b[path]})
        elif path not in b:
            changes.append({"op": "remove", "loc": path, "old": a[path]})
        elif a[path] != b[path]:
            changes.append({"op": "change", "loc": path, "old": a[path], "new": b[path]})
    sections.append(
        Section("Structure (values by path)", changes[:4000], "changed" if changes else "unchanged")
    )
    return (
        sections,
        notes + ["Structure compares scalar values by JSON path; key order is ignored."],
        truncated,
    )


def diff_csv(old: bytes, new: bytes, counts: Counts) -> tuple[list[Section], list[str], bool]:
    import csv

    sections, notes, truncated = diff_text(old, new, counts)
    ra = list(csv.reader(io.StringIO(old.decode("utf-8", errors="replace"))))
    rb = list(csv.reader(io.StringIO(new.decode("utf-8", errors="replace"))))
    changes: list[dict[str, Any]] = []
    header = rb[0] if rb else []
    for i in range(min(len(ra), len(rb))):
        if ra[i] == rb[i]:
            continue
        for j in range(max(len(ra[i]), len(rb[i]))):
            o = ra[i][j] if j < len(ra[i]) else None
            n = rb[i][j] if j < len(rb[i]) else None
            if o != n:
                col = header[j] if j < len(header) and header[j] else f"col {j + 1}"
                changes.append({"op": "change", "loc": f"row {i + 1}, {col}", "old": o, "new": n})
                if len(changes) >= 4000:
                    break
    sections.append(
        Section("Cells (rows matched by position)", changes, "changed" if changes else "unchanged")
    )
    if len(ra) != len(rb):
        notes.append(f"Row count: {len(ra)} → {len(rb)}.")
    return (
        sections,
        notes
        + [
            "Cell comparison assumes rows kept their position; inserted rows shift everything below."
        ],
        truncated,
    )


def _pdf_pages(data: bytes) -> list[list[str]]:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    if reader.is_encrypted:
        raise ValueError("encrypted")
    pages = []
    for page in reader.pages[:MAX_PDF_PAGES]:
        text = page.extract_text() or ""
        pages.append([ln.strip() for ln in text.splitlines() if ln.strip()])
    return pages


def diff_pdf(old: bytes, new: bytes, counts: Counts) -> tuple[list[Section], list[str], bool]:
    a, b = _pdf_pages(old), _pdf_pages(new)
    sections: list[Section] = []
    for i in range(max(len(a), len(b))):
        if i >= len(a):
            counts.add("add", len(b[i]))
            sections.append(
                Section(
                    f"Page {i + 1}",
                    [{"op": "add", "new": ln, "new_loc": k + 1} for k, ln in enumerate(b[i])],
                    "added",
                    "New page",
                )
            )
        elif i >= len(b):
            counts.add("remove", len(a[i]))
            sections.append(
                Section(
                    f"Page {i + 1}",
                    [{"op": "remove", "old": ln, "old_loc": k + 1} for k, ln in enumerate(a[i])],
                    "removed",
                    "Page removed",
                )
            )
        else:
            sections.append(line_diff_section(f"Page {i + 1}", a[i], b[i], counts))
    notes = [
        "Compares text extracted from each page; layout, images and fonts are not compared and a visual page "
        "comparison is not available.",
        "Text in scanned pages (images) is not extracted.",
    ]
    if len(a) != len(b):
        notes.append(f"Page count: {len(a)} → {len(b)}.")
    return sections, notes, False
