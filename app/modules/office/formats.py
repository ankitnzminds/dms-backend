"""Which file types the office suite can open, and which of those we allow to be edited.

Editing is limited to the formats the office engine saves back losslessly enough to be safe as a
new version: OOXML, ODF and plain text (txt, md, csv). Legacy binary formats (doc/xls/ppt) are view-only because saving them
re-encodes the whole file and can silently change content.
"""

from __future__ import annotations

import os

VIEW_ONLY = frozenset({"doc", "xls", "ppt", "rtf", "dot", "xlt", "pot", "pps", "ppsx"})
# Plain text formats (txt, md, csv) round-trip byte-for-byte meaningful, so web editing them is safe too.
EDITABLE = frozenset(
    {"docx", "xlsx", "pptx", "odt", "ods", "odp", "dotx", "xltx", "potx", "txt", "md", "csv"}
)
SUPPORTED = VIEW_ONLY | EDITABLE


def extension(filename: str) -> str:
    return os.path.splitext(filename)[1].lower().lstrip(".")


def is_supported(filename: str) -> bool:
    return extension(filename) in SUPPORTED


def is_editable(filename: str) -> bool:
    return extension(filename) in EDITABLE
