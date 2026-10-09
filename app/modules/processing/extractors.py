"""Content extraction. Runs ONLY inside the isolated child process (see extract_child.py).

Inputs are untrusted: every parser is bounded (bytes, pages, characters, decompression ratio)
and never executes content. Nothing here talks to the network or the database.
"""

from __future__ import annotations

import html
import re
import subprocess  # noqa: S404  (fixed argv, no shell; used for the optional OCR binary)
import warnings
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

TEXT_TYPES = {
    "text/plain",
    "text/csv",
    "text/markdown",
    "application/json",
    "application/xml",
    "text/xml",
}
IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}
DOCX_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
THUMB_MAX = 320
THUMB_MAX_BYTES = 512 * 1024
MAX_IMAGE_PIXELS = 50_000_000
MAX_ZIP_MEMBER_BYTES = 40 * 1024 * 1024
MAX_ZIP_RATIO = 200

OcrFn = Callable[[Path], str]


@dataclass
class ExtractResult:
    status: str  # extracted | empty | unsupported | failed | ocr_unavailable
    text: str = ""
    truncated: bool = False
    engine: str | None = None
    error: str | None = None
    thumbnail: Path | None = field(default=None)


def _clip(text: str, max_chars: int) -> tuple[str, bool]:
    text = text.replace("\x00", "")
    return (text[:max_chars], True) if len(text) > max_chars else (text, False)


def _done(text: str, engine: str, max_chars: int, thumbnail: Path | None = None) -> ExtractResult:
    text, truncated = _clip(text, max_chars)
    status = "extracted" if text.strip() else "empty"
    return ExtractResult(status, text, truncated, engine, thumbnail=thumbnail)


def extract_plain(path: Path, max_chars: int) -> ExtractResult:
    with path.open("rb") as fh:
        raw = fh.read(max_chars * 4 + 1)  # utf-8 is at most 4 bytes per character
    return _done(raw.decode("utf-8", errors="replace"), "plain-text", max_chars)


def extract_pdf(path: Path, max_chars: int, max_pages: int, ocr: OcrFn | None) -> ExtractResult:
    from pypdf import PdfReader

    reader = PdfReader(str(path), strict=False)
    if reader.is_encrypted:
        return ExtractResult("unsupported", engine="pypdf", error="encrypted PDF")
    parts: list[str] = []
    total = 0
    for index, page in enumerate(reader.pages):
        if index >= max_pages or total > max_chars:
            break
        chunk = page.extract_text() or ""
        parts.append(chunk)
        total += len(chunk)
    result = _done("\n".join(parts), "pypdf", max_chars)
    if result.status == "empty" and ocr is None:
        # Scanned PDF without a text layer: needs OCR, which is not configured.
        return ExtractResult(
            "ocr_unavailable", engine="pypdf", error="no text layer; OCR not configured"
        )
    return result


_W_TOKEN = re.compile(r"</w:p>|<w:t(?: [^>]*)?>([^<]*)</w:t>")


def extract_docx(path: Path, max_chars: int) -> ExtractResult:
    """Regex over word/document.xml (no XML parser => no entity-expansion/XXE surface)."""
    with zipfile.ZipFile(path) as zf:
        try:
            info = zf.getinfo("word/document.xml")
        except KeyError:
            return ExtractResult("unsupported", engine="docx", error="not a Word document")
        if info.file_size > MAX_ZIP_MEMBER_BYTES or (
            info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO
        ):
            return ExtractResult(
                "failed", engine="docx", error="archive member too large (possible zip bomb)"
            )
        xml = zf.read(info).decode("utf-8", errors="replace")
    pieces = ["\n" if m.group(0) == "</w:p>" else m.group(1) for m in _W_TOKEN.finditer(xml)]
    return _done(html.unescape("".join(pieces)), "docx-xml", max_chars)


def extract_image(path: Path, max_chars: int, out_dir: Path, ocr: OcrFn | None) -> ExtractResult:
    from PIL import Image

    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    warnings.simplefilter("error", Image.DecompressionBombWarning)  # warn zone => reject too
    with Image.open(path) as img:
        img.verify()  # structural check; the file must be reopened afterwards
    with Image.open(path) as img:
        img.load()
        thumb = img.convert("RGB") if img.mode not in ("RGB", "L") else img.copy()
        thumb.thumbnail((THUMB_MAX, THUMB_MAX))
        out = out_dir / "thumb.png"
        thumb.save(out, format="PNG", optimize=True)
    if out.stat().st_size > THUMB_MAX_BYTES:
        out.unlink()
        out = None  # type: ignore[assignment]
    if ocr is None:
        return ExtractResult(
            "ocr_unavailable", engine="pillow", error="OCR not configured", thumbnail=out
        )
    result = _done(ocr(path), "ocr", max_chars, thumbnail=out)
    return result


def tesseract_ocr(command: str, timeout: int = 60) -> OcrFn:
    def run(path: Path) -> str:
        proc = subprocess.run(  # noqa: S603
            [command, str(path), "stdout", "-l", "eng"],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError("ocr engine failed")
        return proc.stdout.decode("utf-8", errors="replace")

    return run


def extract(
    path: Path,
    *,
    content_type: str,
    filename: str,
    max_chars: int,
    max_pages: int,
    out_dir: Path,
    ocr: OcrFn | None = None,
) -> ExtractResult:
    ctype = content_type.lower()
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    try:
        if ctype in TEXT_TYPES or ext in {"txt", "md", "csv", "json", "xml"}:
            return extract_plain(path, max_chars)
        if ctype == "application/pdf" or ext == "pdf":
            return extract_pdf(path, max_chars, max_pages, ocr)
        if ctype == DOCX_TYPE or ext == "docx":
            return extract_docx(path, max_chars)
        if ctype in IMAGE_TYPES:
            return extract_image(path, max_chars, out_dir, ocr)
    except Exception as exc:  # malformed / hostile input must never escape as a crash
        return ExtractResult("failed", error=f"{type(exc).__name__}: {str(exc)[:200]}")
    return ExtractResult("unsupported", error="no extractor for this file type")
