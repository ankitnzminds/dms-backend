"""Turn a document into the PDF that is sent for signing (and previewed for field placement).

Ported from the reference app's ``pdfConversionService`` (same supported set, same text-based approach):

  * PDF ............................ passed through (validated)
  * images (JPEG, PNG, TIFF, ...) .. one page per image/frame, upright, on white
  * plain text, CSV, Markdown ...... readable pages with a bold title (shown as text, not rendered)
  * Word (.docx) ................... paragraphs and tables as text (no layout, images or headers)
  * Excel (.xlsx) .................. every sheet as "# Sheet" followed by its rows (no formatting, charts)
  * anything else .................. refused with a clear message (the original is never touched)

This is a *signing copy*, not a visual rendition: layout, fonts, images inside Word/Excel files and non-Latin
scripts are not preserved (the PDF standard fonts are used). The original document is never modified. Inputs
are size-limited, Office files are checked for zip bombs before they are parsed, and nothing is executed.
"""

from __future__ import annotations

import io
import zipfile
from xml.sax.saxutils import escape

MAX_INPUT_BYTES = 25 * 1024 * 1024
MAX_UNZIPPED_BYTES = 150 * 1024 * 1024
MAX_IMAGE_PIXELS = 60_000_000
MAX_CHARS = 2_000_000
MAX_ROWS_PER_SHEET = 5_000

SUPPORTED_HELP = "Supported for signing: PDF, images (JPEG/PNG/TIFF), Word (.docx), Excel (.xlsx) and plain text."
_TEXT_EXT = {"txt", "csv", "md", "markdown", "tsv", "log"}
_IMAGE_EXT = {"jpg", "jpeg", "png", "tif", "tiff", "gif", "bmp", "webp"}
_DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


class ConversionError(Exception):
    """A message that is safe to show to the user."""


def _ext(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def _unsupported(filename: str, content_type: str) -> ConversionError:
    what = _ext(filename) or content_type or "unknown"
    return ConversionError(
        f"This file type ({what}) can't be converted to PDF for e-signature yet. {SUPPORTED_HELP}"
    )


def kind_of(filename: str, content_type: str, head: bytes) -> str | None:
    """pdf | image | text | docx | xlsx - decided by content first, extension second (never extension alone)."""
    ext, ct = _ext(filename), (content_type or "").lower().split(";")[0].strip()
    if head.startswith(b"%PDF-"):
        return "pdf"
    if head.startswith(b"PK\x03\x04"):
        if ext == "docx" or ct == _DOCX:
            return "docx"
        if ext == "xlsx" or ct == _XLSX:
            return "xlsx"
        return None
    if head.startswith(
        (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n", b"GIF8", b"BM", b"II*\x00", b"MM\x00*")
    ) or (head[:4] == b"RIFF" and head[8:12] == b"WEBP"):
        return "image"
    if ct.startswith("text/") or ext in _TEXT_EXT:
        return "text"
    if ext in _IMAGE_EXT or ct.startswith("image/"):
        return "image"  # extension says image but the bytes are not: Pillow will reject it
    return None


def _check_zip(data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            total = sum(i.file_size for i in z.infolist())
            if total > MAX_UNZIPPED_BYTES or len(z.infolist()) > 5_000:
                raise ConversionError("This file is too large or complex to prepare for signing.")
    except zipfile.BadZipFile as exc:
        raise ConversionError("This Office file is damaged and can't be read.") from exc


def _image_pdf(data: bytes) -> bytes:
    from PIL import Image, ImageOps, UnidentifiedImageError

    try:
        im = Image.open(io.BytesIO(data))
        if im.width * im.height > MAX_IMAGE_PIXELS:
            raise ConversionError("This image is too large to prepare for signing.")
        frames = []
        for i in range(min(getattr(im, "n_frames", 1), 50)):
            im.seek(i)
            f = ImageOps.exif_transpose(im.copy())
            if f.mode in ("RGBA", "LA", "P"):
                f = f.convert("RGBA")
                bg = Image.new("RGB", f.size, (255, 255, 255))
                bg.paste(f, mask=f.split()[-1])
                f = bg
            else:
                f = f.convert("RGB")
            frames.append(f)
        out = io.BytesIO()
        frames[0].save(out, "PDF", resolution=150.0, save_all=True, append_images=frames[1:])
        return out.getvalue()
    except ConversionError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError) as exc:
        raise ConversionError("This image can't be read.") from exc


def _text_pdf(title: str, body: str) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    if len(body) > MAX_CHARS:
        raise ConversionError("This document has too much text to prepare for signing.")
    head = ParagraphStyle("t", fontName="Helvetica-Bold", fontSize=16, leading=20, spaceAfter=8)
    mono = ParagraphStyle("b", fontName="Courier", fontSize=9, leading=11.5)
    story = [Paragraph(escape(title) or "Document", head), Spacer(1, 4)]
    for line in body.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        # keep indentation; reportlab collapses plain spaces
        shown = escape(line).replace("\t", "    ").replace("  ", "&nbsp;&nbsp;")
        story.append(Paragraph(shown or "&nbsp;", mono))
    out = io.BytesIO()
    SimpleDocTemplate(
        out,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    ).build(story)
    return out.getvalue()


def _docx_text(data: bytes) -> str:
    import docx

    _check_zip(data)
    try:
        d = docx.Document(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 - python-docx raises many types for bad files
        raise ConversionError("This Word file can't be read.") from exc
    lines: list[str] = [p.text for p in d.paragraphs]
    for t in d.tables:
        lines.append("")
        for row in t.rows:
            lines.append(" | ".join(c.text.strip().replace("\n", " ") for c in row.cells))
    return "\n".join(lines)


def _xlsx_text(data: bytes) -> str:
    import openpyxl

    _check_zip(data)
    try:
        wb = openpyxl.load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    except Exception as exc:  # noqa: BLE001
        raise ConversionError("This Excel file can't be read.") from exc
    parts: list[str] = []
    for ws in wb.worksheets:
        if ws.sheet_state != "visible":
            continue
        parts.append(f"# {ws.title}")
        for n, row in enumerate(ws.iter_rows(values_only=True)):
            if n >= MAX_ROWS_PER_SHEET:
                parts.append("... (more rows not shown)")
                break
            parts.append(", ".join("" if v is None else str(v) for v in row).rstrip(", "))
        parts.append("")
    return "\n".join(parts)


def convert_to_pdf(*, filename: str, content_type: str, data: bytes) -> bytes:
    """The signing PDF for ``data``; raises ConversionError (user-facing) when it can't be made."""
    if len(data) > MAX_INPUT_BYTES:
        raise ConversionError("This file is too large to prepare for signing (25 MB maximum).")
    if not data:
        raise ConversionError("This file is empty.")
    kind = kind_of(filename, content_type, data[:16])
    title = filename.rsplit(".", 1)[0][:120]
    if kind == "pdf":
        return data
    if kind == "image":
        return _image_pdf(data)
    if kind == "text":
        return _text_pdf(title, data.decode("utf-8", errors="replace"))
    if kind == "docx":
        return _text_pdf(title, _docx_text(data))
    if kind == "xlsx":
        return _text_pdf(title, _xlsx_text(data))
    raise _unsupported(filename, content_type)


def page_count(pdf: bytes) -> int:
    """Pages in the PDF; a PDF pypdf cannot count is treated as a single page (as the provider adapter does)."""
    from pypdf import PdfReader

    try:
        return max(1, len(PdfReader(io.BytesIO(pdf), strict=False).pages))
    except Exception:  # noqa: BLE001 - malformed PDF
        return 1
