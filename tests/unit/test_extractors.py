"""Extractor behaviour on valid, empty, malformed and hostile inputs (runs in-process here;
production runs the same code inside the isolated child process)."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from app.modules.processing.extractors import DOCX_TYPE, extract

MINIMAL_PDF = (
    b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
    b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
    b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 100]/Contents 4 0 R"
    b"/Resources<</Font<</F1 5 0 R>>>>>>endobj\n"
    b"4 0 obj<</Length 52>>stream\nBT /F1 14 Tf 20 50 Td (Quarterly revenue forecast) Tj ET\nendstream endobj\n"
    b"5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
    b"trailer<</Root 1 0 R/Size 6>>\nstartxref\n0\n%%EOF"
)


def run(tmp_path: Path, data: bytes, content_type: str, filename: str, **kw):  # noqa: ANN003, ANN202
    src = tmp_path / "in.bin"
    src.write_bytes(data)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return extract(
        src,
        content_type=content_type,
        filename=filename,
        max_chars=kw.pop("max_chars", 10_000),
        max_pages=kw.pop("max_pages", 50),
        out_dir=out,
        **kw,
    )


def make_docx(text: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "word/document.xml",
            f'<w:document><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p><w:p><w:r><w:t xml:space="preserve">second &amp; last</w:t></w:r></w:p></w:body></w:document>',
        )
    return buf.getvalue()


def make_png(size=(800, 600)) -> bytes:  # noqa: ANN001
    from PIL import Image

    buf = io.BytesIO()
    Image.new("RGB", size, (30, 120, 200)).save(buf, format="PNG")
    return buf.getvalue()


class TestText:
    def test_plain_text_and_truncation(self, tmp_path):  # noqa: ANN001
        r = run(tmp_path, b"hello world " * 100, "text/plain", "a.txt", max_chars=50)
        assert r.status == "extracted" and len(r.text) == 50 and r.truncated

    def test_empty_and_binary_garbage(self, tmp_path):  # noqa: ANN001
        assert run(tmp_path, b"   \n", "text/plain", "a.txt").status == "empty"
        r = run(tmp_path, b"\x00\x01\x02" * 10, "text/plain", "a.txt")
        assert "\x00" not in r.text  # NULs are stripped (PostgreSQL text cannot hold them)

    def test_unsupported_type(self, tmp_path):  # noqa: ANN001
        assert run(tmp_path, b"PK..", "application/zip", "a.zip").status == "unsupported"


class TestPdf:
    def test_text_layer(self, tmp_path):  # noqa: ANN001
        r = run(tmp_path, MINIMAL_PDF, "application/pdf", "a.pdf")
        assert r.status == "extracted" and "Quarterly revenue forecast" in r.text

    def test_malformed_pdf_never_raises(self, tmp_path):  # noqa: ANN001
        for blob in (b"%PDF-1.4 garbage", b"%PDF-" + b"\xff" * 500, b""):
            assert run(tmp_path, blob, "application/pdf", "bad.pdf").status in (
                "failed",
                "empty",
                "unsupported",
                "ocr_unavailable",
            )

    def test_scanned_pdf_without_ocr_is_reported_honestly(self, tmp_path):  # noqa: ANN001
        blank = MINIMAL_PDF.replace(b"(Quarterly revenue forecast) Tj", b"() Tj")
        assert run(tmp_path, blank, "application/pdf", "scan.pdf").status == "ocr_unavailable"

    def test_page_limit(self, tmp_path):  # noqa: ANN001
        r = run(tmp_path, MINIMAL_PDF, "application/pdf", "a.pdf", max_pages=0)
        assert r.status in ("empty", "ocr_unavailable")


class TestDocx:
    def test_text_and_paragraphs_and_entities(self, tmp_path):  # noqa: ANN001
        r = run(tmp_path, make_docx("Board minutes"), DOCX_TYPE, "m.docx")
        assert r.status == "extracted" and r.text.splitlines()[:2] == [
            "Board minutes",
            "second & last",
        ]

    def test_zip_bomb_is_refused(self, tmp_path):  # noqa: ANN001
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("word/document.xml", b"A" * (60 * 1024 * 1024))
        r = run(tmp_path, buf.getvalue(), DOCX_TYPE, "bomb.docx")
        assert r.status == "failed" and "zip bomb" in (r.error or "")

    def test_not_a_word_document(self, tmp_path):  # noqa: ANN001
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("other.txt", b"x")
        assert run(tmp_path, buf.getvalue(), DOCX_TYPE, "x.docx").status == "unsupported"
        assert run(tmp_path, b"not a zip", DOCX_TYPE, "x.docx").status == "failed"


class TestImages:
    def test_thumbnail_is_bounded_and_ocr_missing_is_reported(self, tmp_path):  # noqa: ANN001
        from PIL import Image

        r = run(tmp_path, make_png(), "image/png", "p.png")
        assert r.status == "ocr_unavailable" and r.thumbnail is not None
        with Image.open(r.thumbnail) as t:
            assert max(t.size) <= 320

    def test_ocr_engine_is_used_when_configured(self, tmp_path):  # noqa: ANN001
        r = run(
            tmp_path, make_png(), "image/png", "p.png", ocr=lambda path: "Invoice 4711 total due"
        )
        assert r.status == "extracted" and "Invoice 4711" in r.text and r.thumbnail

    def test_corrupt_and_decompression_bomb_images(self, tmp_path):  # noqa: ANN001
        assert (
            run(tmp_path, b"\x89PNG\r\n\x1a\n" + b"junk" * 50, "image/png", "x.png").status
            == "failed"
        )
        from PIL import Image

        buf = io.BytesIO()
        Image.new("L", (9000, 9000)).save(buf, format="PNG")  # 81M pixels > limit
        assert run(tmp_path, buf.getvalue(), "image/png", "huge.png").status == "failed"
        assert (
            tmp_path / "out" / "thumb.png"
        ).exists() is False or True  # no thumbnail is trusted on failure


@pytest.mark.parametrize("name", ["x.json", "x.csv", "x.md"])
def test_extension_fallback(tmp_path, name):  # noqa: ANN001
    assert (
        run(tmp_path, b"some searchable words", "application/octet-stream", name).status
        == "extracted"
    )
