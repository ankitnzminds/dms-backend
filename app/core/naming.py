"""Validation of user-supplied names (folders, documents, filenames)."""

from __future__ import annotations

import re
import unicodedata

from app.core.errors import ValidationFailed

MAX_NAME_LENGTH = 255
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_FORBIDDEN = re.compile(r"[/\\]")
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}  # fmt: skip


def validate_name(raw: str, *, what: str = "Name") -> str:
    """Return the normalized name or raise ValidationFailed. Rejects path separators, control
    characters, dot-names and trailing dots/spaces so a name can never act as a path."""
    if raw is None:
        raise ValidationFailed(f"{what} is required.")
    name = unicodedata.normalize("NFC", raw).strip()
    if not name:
        raise ValidationFailed(f"{what} must not be empty.")
    if len(name) > MAX_NAME_LENGTH:
        raise ValidationFailed(f"{what} must be at most {MAX_NAME_LENGTH} characters.")
    if _CONTROL.search(name) or _FORBIDDEN.search(name):
        raise ValidationFailed(f"{what} contains invalid characters.")
    if name in {".", ".."} or name.endswith((".", " ")):
        raise ValidationFailed(f"{what} is not allowed.")
    if name.split(".")[0].lower() in _WINDOWS_RESERVED:
        raise ValidationFailed(f"{what} is reserved.")
    return name


def split_extension(filename: str) -> str:
    return filename.rsplit(".", 1)[1].lower() if "." in filename.strip(".") else ""
