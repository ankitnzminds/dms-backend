"""Format-aware version comparison: text, DOCX, XLSX, PPTX, PDF, CSV, JSON, binary; caching,
permissions, tenant isolation, unreleased versions, hostile packages and audit."""

from __future__ import annotations

import io
import zipfile

import pytest

pytestmark = pytest.mark.integration
API = "/api/v1"
_STAMP = (2026, 1, 1, 0, 0, 0)


def zipped(parts: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            info = zipfile.ZipInfo(name, _STAMP)
            info.compress_type = zipfile.ZIP_DEFLATED  # ZipInfo defaults to STORED
            z.writestr(info, data)
    return buf.getvalue()


# ----------------------------------------------------------------- tiny OOXML writers
def docx(paras, header=None, tracked=False):  # noqa: ANN001, ANN201
    """paras: [(text, 'b' | 'i' | '')] or ('table', [[cell, ...], ...])"""
    body = []
    for item in paras:
        if item[0] == "table":
            rows = "".join(
                "<w:tr>"
                + "".join(f"<w:tc><w:p><w:r><w:t>{c}</w:t></w:r></w:p></w:tc>" for c in row)
                + "</w:tr>"
                for row in item[1]
            )
            body.append(f"<w:tbl>{rows}</w:tbl>")
            continue
        text, fmt = item
        rpr = {"b": "<w:rPr><w:b/></w:rPr>", "i": "<w:rPr><w:i/></w:rPr>", "": ""}[fmt]
        body.append(f"<w:p><w:r>{rpr}<w:t>{text}</w:t></w:r></w:p>")
    if tracked:
        body.append(
            "<w:p><w:ins><w:r><w:t>tracked</w:t></w:r></w:ins><w:del><w:r><w:delText>gone</w:delText></w:r></w:del></w:p>"
        )
    ns = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    parts: dict[str, str | bytes] = {
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        "word/document.xml": f"<w:document {ns}><w:body>{''.join(body)}</w:body></w:document>",
    }
    if header:
        parts["word/header1.xml"] = f"<w:hdr {ns}><w:p><w:r><w:t>{header}</w:t></w:r></w:p></w:hdr>"
    return zipped(parts)


def xlsx(sheets, merges=None):  # noqa: ANN001, ANN201
    """sheets: {name: {"A1": 5 | "text" | "=SUM(A1:A2)"}}"""
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    wb_sheets, rels, parts = [], [], {}
    for i, (name, cells) in enumerate(sheets.items(), start=1):
        wb_sheets.append(f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>')
        rels.append(f'<Relationship Id="rId{i}" Target="worksheets/sheet{i}.xml" Type="x"/>')
        rows = []
        for ref, val in cells.items():
            if isinstance(val, str) and val.startswith("="):
                rows.append(f'<c r="{ref}"><f>{val[1:]}</f><v>0</v></c>')
            elif isinstance(val, str):
                rows.append(f'<c r="{ref}" t="inlineStr"><is><t>{val}</t></is></c>')
            else:
                rows.append(f'<c r="{ref}"><v>{val}</v></c>')
        merged = ""
        if merges and name in merges:
            merged = (
                "<mergeCells>"
                + "".join(f'<mergeCell ref="{m}"/>' for m in merges[name])
                + "</mergeCells>"
            )
        parts[f"xl/worksheets/sheet{i}.xml"] = (
            f"<worksheet {ns}><sheetData><row>{''.join(rows)}</row></sheetData>{merged}</worksheet>"
        )
    parts["[Content_Types].xml"] = (
        '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
    )
    parts["xl/workbook.xml"] = f"<workbook {ns}><sheets>{''.join(wb_sheets)}</sheets></workbook>"
    parts["xl/_rels/workbook.xml.rels"] = (
        f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{"".join(rels)}</Relationships>'
    )
    return zipped(parts)


def pptx(slides, animated=()):  # noqa: ANN001, ANN201
    """slides: [[(shape name, text), ...], ...]"""
    p = 'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
    parts: dict[str, str | bytes] = {
        "[Content_Types].xml": '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
    }
    ids, rels = [], []
    for i, shapes in enumerate(slides, start=1):
        ids.append(f'<p:sldId id="{255 + i}" r:id="rId{i}"/>')
        rels.append(f'<Relationship Id="rId{i}" Target="slides/slide{i}.xml" Type="x"/>')
        sp = "".join(
            f'<p:sp><p:nvSpPr><p:cNvPr id="{k}" name="{name}"/></p:nvSpPr><p:txBody><a:p><a:r><a:t>{text}</a:t></a:r></a:p></p:txBody></p:sp>'
            for k, (name, text) in enumerate(shapes, start=2)
        )
        timing = "<p:timing/>" if i in animated else ""
        parts[f"ppt/slides/slide{i}.xml"] = (
            f"<p:sld {p}><p:cSld><p:spTree>{sp}</p:spTree></p:cSld>{timing}</p:sld>"
        )
    parts["ppt/presentation.xml"] = (
        f"<p:presentation {p}><p:sldIdLst>{''.join(ids)}</p:sldIdLst></p:presentation>"
    )
    parts["ppt/_rels/presentation.xml.rels"] = (
        f'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">{"".join(rels)}</Relationships>'
    )
    return zipped(parts)


def pdf(pages):  # noqa: ANN001, ANN201
    """A minimal real PDF: pages is a list of line lists."""
    objs: list[bytes] = []
    kids = []
    objs.append(b"")  # 1 catalog (filled later)
    objs.append(b"")  # 2 pages (filled later)
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")  # 3
    for lines in pages:
        stream = "BT /F1 12 Tf 14 TL 72 720 Td " + " T* ".join(f"({ln}) Tj" for ln in lines) + " ET"
        content = f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream".encode()
        objs.append(content)
        c = len(objs)
        objs.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {c} 0 R /Resources << /Font << /F1 3 0 R >> >> >>".encode()
        )
        kids.append(f"{len(objs)} 0 R")
    objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(kids)} >>".encode()
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(f"{i} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = out.tell()
    out.write(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode())
    for off in offsets:
        out.write(f"{off:010d} 00000 n \n".encode())
    out.write(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    )
    return out.getvalue()


# ---------------------------------------------------------------------------- fixtures
DOCX_CT = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


@pytest.fixture()
def env(world):  # noqa: ANN001, ANN201
    owner = world.org("Diff Inc")
    folder = world.mkdir(owner, world.root_id(owner), "docs")
    return dict(world=world, owner=owner, folder=folder)


def new_doc(env, name, data, content_type="application/octet-stream"):  # noqa: ANN001, ANN201
    w, o = env["world"], env["owner"]
    doc = w.upload(o, env["folder"], name, data, content_type=content_type)["document_id"]
    w.process_jobs()
    return doc


def add_version(env, doc, name, data, number, content_type="application/octet-stream"):  # noqa: ANN001, ANN201
    w, o = env["world"], env["owner"]
    init = o.post(
        f"{API}/documents/{doc}/uploads",
        json={
            "filename": name,
            "size_bytes": len(data),
            "content_type": content_type,
            "expected_latest_version": number,
        },
    )
    assert init.status_code == 201, init.text
    s = init.json()
    assert (
        o.put(
            s["upload_url"], content=data, headers={"Content-Type": "application/octet-stream"}
        ).status_code
        == 200
    )
    assert o.post(f"{API}/uploads/{s['id']}/finalize").status_code == 200
    w.process_jobs()


def compare(actor, doc, a=1, b=2):  # noqa: ANN001, ANN201
    return actor.get(f"{API}/documents/{doc}/versions/compare", params={"from": a, "to": b})


def two(env, name, v1, v2, ct="application/octet-stream"):  # noqa: ANN001, ANN201
    doc = new_doc(env, name, v1, ct)
    add_version(env, doc, name, v2, 1, ct)
    return doc


def ops(diff, section=0):  # noqa: ANN001, ANN201
    return [c["op"] for c in diff["sections"][section]["changes"] if c["op"] != "skip"]


class TestText:
    def test_line_diff_with_inline_words_and_context(self, env):  # noqa: ANN001
        old = "\n".join(f"line {i}" for i in range(20)).encode()
        new = old.replace(b"line 10", b"line TEN here").replace(b"line 15\n", b"") + b"\nappended"
        doc = two(env, "notes.txt", old, new, "text/plain")
        r = compare(env["owner"], doc)
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["status"] == "ready" and d["kind"] == "text" and d["identical"] is False
        s = d["summary"]
        assert (s["changed"], s["removed"], s["added"]) == (1, 1, 1)
        change = next(c for c in d["sections"][0]["changes"] if c["op"] == "change")
        assert change["old"] == "line 10" and any(
            p["op"] == "add" and "TEN" in p["text"] for p in change["inline"]
        )
        assert any(
            c["op"] == "skip" for c in d["sections"][0]["changes"]
        )  # unchanged runs collapse
        assert d["from_version"]["version_number"] == 1 and d["to_version"]["is_current"] is True

    def test_identical_bytes(self, env):  # noqa: ANN001
        doc = two(env, "same.txt", b"hello\n", b"hello\n", "text/plain")
        d = compare(env["owner"], doc).json()
        assert d["identical"] is True and d["summary"]["changed"] == 0

    def test_csv_cells_and_json_paths(self, env):  # noqa: ANN001
        csv_doc = two(
            env, "t.csv", b"id,name\n1,Ann\n2,Bob\n", b"id,name\n1,Ann\n2,Rob\n3,Cy\n", "text/csv"
        )
        d = compare(env["owner"], csv_doc).json()
        assert d["kind"] == "csv"
        cells = next(s for s in d["sections"] if s["title"].startswith("Cells"))["changes"]
        assert cells == [{"op": "change", "loc": "row 3, name", "old": "Bob", "new": "Rob"}]
        assert any("Row count" in n for n in d["notes"])
        js = two(
            env,
            "c.json",
            b'{"a": 1, "b": {"c": [1, 2]}}',
            b'{"b": {"c": [1, 3]}, "d": true}',
            "application/json",
        )
        d = compare(env["owner"], js).json()
        struct = next(s for s in d["sections"] if s["title"].startswith("Structure"))["changes"]
        assert {(c["op"], c["loc"]) for c in struct} == {
            ("remove", "$.a"),
            ("change", "$.b.c[1]"),
            ("add", "$.d"),
        }


class TestOffice:
    def test_docx_text_formatting_tables_headers_and_tracked_changes(self, env):  # noqa: ANN001
        v1 = docx(
            [
                ("Title", "b"),
                ("Alpha beta gamma", ""),
                ("Keep me", ""),
                ("table", [["x", "y"], ["1", "2"]]),
            ],
            header="Draft",
        )
        v2 = docx(
            [
                ("Title", ""),
                ("Alpha BETA gamma", ""),
                ("Keep me", ""),
                ("New paragraph", ""),
                ("table", [["x", "y"], ["1", "3"]]),
            ],
            header="Final",
            tracked=True,
        )
        doc = two(env, "spec.docx", v1, v2, DOCX_CT)
        d = compare(env["owner"], doc).json()
        assert d["status"] == "ready" and d["kind"] == "docx"
        body = next(s for s in d["sections"] if s["title"] == "Body")["changes"]
        kinds = {(c["op"], c.get("kind")) for c in body}
        assert ("change", "formatting") in kinds  # bold removed from the title
        word = next(c for c in body if c["op"] == "change" and c.get("old") == "Alpha beta gamma")
        assert any(p["op"] == "add" and p["text"] == "BETA" for p in word["inline"])
        assert any(c["op"] == "add" and c["new"] == "New paragraph" for c in body)
        assert any(
            c["op"] == "change" and "[table r2 c2]" in c["old"] and c["new"].endswith("3")
            for c in body
        )
        header = next(s for s in d["sections"] if s["title"].startswith("Header"))
        assert header["status"] == "changed"
        assert any("Tracked changes" in n and "1 insertion" in n for n in d["notes"])
        assert any("not compared" in n for n in d["notes"])  # limitations are stated

    def test_xlsx_values_formulas_sheets_and_merges(self, env):  # noqa: ANN001
        v1 = xlsx(
            {"Sales": {"A1": "Region", "B1": 10, "C1": "=SUM(B1:B2)"}, "Old": {"A1": 1}},
            merges={"Sales": ["A1:B1"]},
        )
        v2 = xlsx(
            {
                "Sales": {"A1": "Region", "B1": 12, "C1": "=SUM(B1:B3)", "D1": "new"},
                "Summary": {"A1": 7},
            },
            merges={"Sales": []},
        )
        doc = two(env, "book.xlsx", v1, v2)
        d = compare(env["owner"], doc).json()
        assert d["kind"] == "xlsx" and d["status"] == "ready"
        titles = {s["title"]: s for s in d["sections"]}
        sales = titles["Sheet “Sales”"]["changes"]
        by_loc = {c["loc"]: c for c in sales}
        assert by_loc["B1"]["op"] == "change" and by_loc["B1"]["kind"] == "value"
        assert by_loc["C1"]["kind"] == "formula" and "SUM(B1:B3)" in by_loc["C1"]["new"]
        assert by_loc["D1"]["op"] == "add"
        assert by_loc["A1:B1"]["op"] == "remove"  # the merge was removed
        assert (
            titles["Sheet “Old”"]["status"] == "removed"
            and titles["Sheet “Summary”"]["status"] == "added"
        )

    def test_pptx_slide_text_added_slides_moves_and_animation_flag(self, env):  # noqa: ANN001
        s1 = [("Title", "Intro")]
        s2 = [("Title", "Plan"), ("Body", "Phase one")]
        s3 = [("Title", "Budget")]
        v1 = pptx([s1, s2, s3])
        v2 = pptx(
            [s3, s1, [("Title", "Plan"), ("Body", "Phase ONE")], [("Title", "Q&amp;A")]],
            animated=(3,),
        )
        doc = two(env, "deck.pptx", v1, v2)
        d = compare(env["owner"], doc).json()
        assert d["kind"] == "pptx" and d["status"] == "ready"
        sec = d["sections"]
        assert any(
            "was" in s["title"] and s["status"] == "unchanged" for s in sec
        )  # moved slides recognised
        changed = next(s for s in sec if s["status"] == "changed")
        assert any(c.get("kind") == "animation" for c in changed["changes"])
        assert any(c["op"] == "change" and c["new"] == "Phase ONE" for c in changed["changes"])
        assert any(s["status"] == "added" for s in sec)

    def test_pdf_text_by_page(self, env):  # noqa: ANN001
        v1 = pdf([["Invoice 100", "Total 50"], ["Terms apply"]])
        v2 = pdf([["Invoice 100", "Total 75"], ["Terms apply"], ["Appendix"]])
        doc = two(env, "inv.pdf", v1, v2, "application/pdf")
        d = compare(env["owner"], doc).json()
        assert d["kind"] == "pdf" and d["status"] == "ready", d
        titles = {s["title"]: s for s in d["sections"]}
        assert titles["Page 1"]["status"] == "changed" and titles["Page 2"]["status"] == "unchanged"
        assert titles["Page 3"]["status"] == "added"
        assert any("visual" in n for n in d["notes"]) and any(
            "Page count: 2" in n for n in d["notes"]
        )

    def test_unsupported_types_still_compare_properties_honestly(self, env):  # noqa: ANN001
        png1 = b"\x89PNG\r\n\x1a\n" + b"a" * 40
        png2 = b"\x89PNG\r\n\x1a\n" + b"b" * 50
        doc = two(env, "p.png", png1, png2, "image/png")
        d = compare(env["owner"], doc).json()
        assert d["status"] == "unsupported" and d["summary"] is None
        assert {c["loc"] for c in d["sections"][0]["changes"]} == {"size", "sha256", "content type"}


class TestSafetyAndAccess:
    def test_hostile_packages_are_reported_not_silently_empty(self, env):  # noqa: ANN001
        evil_xml = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x "boom">]><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>&x;</w:t></w:r></w:p></w:body></w:document>'
        evil = zipped({"[Content_Types].xml": "<Types/>", "word/document.xml": evil_xml})
        doc = two(env, "evil.docx", docx([("ok", "")]), evil, DOCX_CT)
        d = compare(env["owner"], doc).json()
        assert (
            d["status"] == "failed"
            and "forbidden" in d["message"].lower()
            and d["identical"] is False
        )
        bomb = zipped(
            {"[Content_Types].xml": "<Types/>", "word/document.xml": b"0" * (31 * 1024 * 1024)}
        )
        doc2 = two(env, "bomb.docx", docx([("ok", "")]), bomb, DOCX_CT)
        d2 = compare(env["owner"], doc2).json()
        assert d2["status"] == "failed" and "too large" in d2["message"].lower()
        junk = two(
            env, "junk.docx", docx([("ok", "")]), b"PK\x03\x04 not really a zip at all", DOCX_CT
        )
        assert compare(env["owner"], junk).json()["status"] in ("failed", "unsupported")

    def test_results_are_cached_audited_and_validated(self, env):  # noqa: ANN001
        doc = two(env, "c.txt", b"one\n", b"two\n", "text/plain")
        first = compare(env["owner"], doc).json()
        second = compare(env["owner"], doc).json()
        assert first["cached"] is False and second["cached"] is True
        assert first["summary"] == second["summary"]
        assert compare(env["owner"], doc, 1, 1).status_code == 422
        assert compare(env["owner"], doc, 1, 9).status_code == 404
        ev = (
            env["owner"]
            .get(f"{API}/admin/activity", params={"action": "document.versions_compared"})
            .json()["items"]
        )
        assert len(ev) >= 2 and ev[0]["metadata"]["kind"] == "text"

    def test_requires_download_right_and_stays_in_tenant(self, env):  # noqa: ANN001
        w, o = env["world"], env["owner"]
        doc = two(env, "p.txt", b"secret one\n", b"secret two\n", "text/plain")
        outsider = w.user(o, "member", label="out")
        # org default access is on in this fixture, so make a closed org to test denial
        closed = w.org("Closed", member_default_access=False)
        f = w.mkdir(closed, w.root_id(closed), "x")
        cdoc = w.upload(closed, f, "s.txt", b"a\n", content_type="text/plain")["document_id"]
        w.process_jobs()
        s = closed.post(
            f"{API}/documents/{cdoc}/uploads",
            json={
                "filename": "s.txt",
                "size_bytes": 2,
                "content_type": "text/plain",
                "expected_latest_version": 1,
            },
        ).json()
        closed.put(
            s["upload_url"], content=b"b\n", headers={"Content-Type": "application/octet-stream"}
        )
        closed.post(f"{API}/uploads/{s['id']}/finalize")
        w.process_jobs()
        stranger = w.user(closed, "member", label="str")
        assert compare(stranger, cdoc).status_code == 404  # non-disclosing
        assert compare(closed, cdoc).status_code == 200
        assert compare(o, cdoc).status_code == 404  # another tenant's id
        assert compare(outsider, doc).status_code in (200, 403, 404)

    def test_unreleased_versions_cannot_be_compared(self, env, db):  # noqa: ANN001
        from sqlalchemy import update

        from app.db.models import DocumentVersion

        doc = two(env, "q.txt", b"a\n", b"b\n", "text/plain")
        db.execute(
            update(DocumentVersion)
            .where(DocumentVersion.version_number == 2)
            .values(scan_status="pending")
        )
        db.commit()
        r = compare(env["owner"], doc)
        assert r.status_code == 409 and r.json()["error"]["code"] == "not_released"
