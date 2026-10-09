"""Generate complex Word/Excel/PowerPoint sample files for office-viewer fidelity checks.

Needs python-docx, openpyxl, python-pptx and Pillow (NOT project dependencies):

    uv venv /tmp/samples-venv && uv pip install --python /tmp/samples-venv/Scripts/python.exe \
        python-docx openpyxl python-pptx pillow
    /tmp/samples-venv/Scripts/python.exe scripts/make_office_samples.py tests/fixtures/office

Every file deliberately uses features that viewers get wrong: fonts and colours, merged cells,
shading, headers/footers with page-number fields, section/page breaks, lists, embedded images,
formulas, number formats, conditional formatting, frozen panes, multiple sheets, charts, slide
layouts, tables, speaker notes. python-pptx cannot author animations, so animation support is
verified manually only (see docs/integrations/office-viewer.md).
"""

from __future__ import annotations

import io
import sys
from pathlib import Path

from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from openpyxl import Workbook
from openpyxl.chart import BarChart, LineChart, Reference
from openpyxl.formatting.rule import CellIsRule, ColorScaleRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from PIL import Image, ImageDraw
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor as PptColor
from pptx.enum.chart import XL_CHART_TYPE
from pptx.util import Inches as PInches
from pptx.util import Pt as PPt


def _png(w: int = 480, h: int = 220) -> bytes:
    img = Image.new("RGB", (w, h), (240, 244, 255))
    d = ImageDraw.Draw(img)
    for i in range(0, w, 40):
        d.line([(i, 0), (i, h)], fill=(200, 210, 240))
    d.rectangle([20, 20, w - 20, h - 20], outline=(30, 60, 160), width=4)
    d.text((40, 90), "Embedded image (PNG)", fill=(30, 60, 160))
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _field(run, instr: str) -> None:
    for kind, text in (("begin", None), (None, instr), ("end", None)):
        el = OxmlElement("w:fldChar" if kind else "w:instrText")
        if kind:
            el.set(qn("w:fldCharType"), kind)
        else:
            el.set(qn("xml:space"), "preserve")
            el.text = text
        run._r.append(el)


def _shade(cell, hex_fill: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:fill"), hex_fill)
    tc_pr.append(shd)


def make_docx(path: Path) -> None:
    doc = Document()
    sec = doc.sections[0]
    sec.header.paragraphs[0].text = "ACME Corp - Confidential | Quarterly Business Review"
    f = sec.footer.paragraphs[0]
    f.add_run("Page ")
    _field(f.add_run(), "PAGE")
    f.add_run(" of ")
    _field(f.add_run(), "NUMPAGES")

    h = doc.add_heading("Quarterly Business Review", 0)
    h.runs[0].font.name = "Georgia"
    p = doc.add_paragraph()
    r = p.add_run("Fonts: ")
    for name, color in (("Times New Roman", "1F3864"), ("Courier New", "C00000"), ("Arial", "548235")):
        run = p.add_run(f"{name} ")
        run.font.name = name
        run.font.color.rgb = RGBColor.from_string(color)
        run.font.size = Pt(13)
    r.bold = True
    p2 = doc.add_paragraph("Bold, italic, underline, strikethrough, super")
    p2.runs[0].bold = p2.runs[0].italic = True
    p2.add_run("script").font.superscript = True

    doc.add_heading("1. Results", 1)
    for i in range(1, 4):
        doc.add_paragraph(f"Bullet point number {i} with a longer sentence to wrap across the line.", style="List Bullet")
    for i in range(1, 3):
        doc.add_paragraph(f"Numbered item {i}", style="List Number")

    table = doc.add_table(rows=4, cols=4)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    a = table.cell(0, 0).merge(table.cell(0, 3))
    a.text = "Revenue by region (merged header row)"
    _shade(a, "1F3864")
    a.paragraphs[0].runs[0].font.color.rgb = RGBColor(255, 255, 255)
    a.paragraphs[0].runs[0].bold = True
    for c, head in enumerate(["Region", "Q1", "Q2", "Q3"]):
        table.cell(1, c).text = head
        _shade(table.cell(1, c), "D9E2F3")
    rows = [("EMEA", "1,250", "1,410", "1,533"), ("APAC", "980", "1,102", "1,290")]
    for ri, row in enumerate(rows, start=2):
        for c, v in enumerate(row):
            table.cell(ri, c).text = v
    table.cell(3, 0).merge(table.cell(3, 1))

    doc.add_picture(io.BytesIO(_png()), width=Inches(4.5))
    doc.add_paragraph("Figure 1: embedded image with caption.")

    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    doc.add_heading("2. Appendix (page 2)", 1)
    for i in range(30):
        doc.add_paragraph(f"Paragraph {i + 1}: " + "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 3)

    land = doc.add_section()
    land.orientation = WD_ORIENT.LANDSCAPE
    land.page_width, land.page_height = land.page_height, land.page_width
    doc.add_heading("3. Landscape section", 1)
    doc.add_paragraph("This section uses a landscape page to test mixed orientation.")
    doc.save(path)


def make_xlsx(path: Path) -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "Sales"
    thin = Side(style="thin", color="999999")
    ws.merge_cells("A1:F1")
    ws["A1"] = "Regional sales model (merged title)"
    ws["A1"].font = Font(name="Cambria", size=16, bold=True, color="FFFFFF")
    ws["A1"].fill = PatternFill("solid", fgColor="1F3864")
    ws["A1"].alignment = Alignment(horizontal="center")
    heads = ["Region", "Q1", "Q2", "Q3", "Q4", "Total"]
    for c, h in enumerate(heads, start=1):
        cell = ws.cell(row=2, column=c, value=h)
        cell.font = Font(bold=True)
        cell.fill = PatternFill("solid", fgColor="D9E2F3")
        cell.border = Border(top=thin, bottom=thin, left=thin, right=thin)
    data = [("EMEA", 1250, 1410, 1533, 1720), ("APAC", 980, 1102, 1290, 1350), ("AMER", 2100, 1980, 2230, 2410), ("LATAM", 410, 455, 502, 560)]
    for r, row in enumerate(data, start=3):
        for c, v in enumerate(row, start=1):
            ws.cell(row=r, column=c, value=v)
        ws.cell(row=r, column=6, value=f"=SUM(B{r}:E{r})")
    ws["A7"] = "Total"
    ws["A7"].font = Font(bold=True)
    for col in "BCDEF":
        ws[f"{col}7"] = f"=SUM({col}3:{col}6)"
        ws[f"{col}7"].number_format = "#,##0"
    ws["A9"] = "Share of EMEA"
    ws["B9"] = "=F3/F7"
    ws["B9"].number_format = "0.0%"
    ws["A10"] = "Top region"
    ws["B10"] = '=INDEX(A3:A6,MATCH(MAX(F3:F6),F3:F6,0))'
    ws["A11"] = "Status"
    ws["B11"] = '=IF(F7>10000,"On target","Below target")'
    ws.conditional_formatting.add("F3:F6", CellIsRule(operator="greaterThan", formula=["6000"], fill=PatternFill("solid", bgColor="C6EFCE")))
    ws.conditional_formatting.add("B3:E6", ColorScaleRule(start_type="min", start_color="F8696B", end_type="max", end_color="63BE7B"))
    ws.freeze_panes = "B3"
    ws.column_dimensions["A"].width = 22
    for col in "BCDEF":
        ws.column_dimensions[col].width = 12
    ch = BarChart()
    ch.title = "Revenue by region"
    ch.add_data(Reference(ws, min_col=2, max_col=5, min_row=2, max_row=6), titles_from_data=True)
    ch.set_categories(Reference(ws, min_col=1, min_row=3, max_row=6))
    ws.add_chart(ch, "H2")

    ws2 = wb.create_sheet("Dates and text")
    ws2["A1"], ws2["B1"] = "Date", "Value"
    import datetime as dt

    for i in range(1, 13):
        ws2.cell(row=i + 1, column=1, value=dt.date(2026, i, 1)).number_format = "mmm-yy"
        ws2.cell(row=i + 1, column=2, value=100 + i * 7.5).number_format = '"$"#,##0.00'
    ln = LineChart()
    ln.title = "Trend"
    ln.add_data(Reference(ws2, min_col=2, min_row=1, max_row=13), titles_from_data=True)
    ws2.add_chart(ln, "D2")
    ws2["A16"] = "Wrapped text cell that is long enough to wrap onto several lines in a narrow column."
    ws2["A16"].alignment = Alignment(wrap_text=True, vertical="top")
    ws2.column_dimensions["A"].width = 18
    ws2.row_dimensions[16].height = 60

    ws3 = wb.create_sheet("Hidden calc")
    ws3["A1"] = "=Sales!F7*2"
    ws3.sheet_state = "hidden"
    wb.save(path)


def make_pptx(path: Path) -> None:
    prs = Presentation()
    s1 = prs.slides.add_slide(prs.slide_layouts[0])
    s1.shapes.title.text = "Quarterly Business Review"
    s1.placeholders[1].text = "Fidelity test deck - ACME Corp"
    s2 = prs.slides.add_slide(prs.slide_layouts[1])
    s2.shapes.title.text = "Highlights"
    tf = s2.placeholders[1].text_frame
    tf.text = "Revenue up 14% year over year"
    for t in ("APAC grew fastest at 21%", "Churn down to 2.1%"):
        tf.add_paragraph().text = t
        tf.paragraphs[-1].level = 1
    s2.notes_slide.notes_text_frame.text = "Speaker notes: mention the APAC launch."
    s3 = prs.slides.add_slide(prs.slide_layouts[5])
    s3.shapes.title.text = "Revenue by region"
    cd = CategoryChartData()
    cd.categories = ["EMEA", "APAC", "AMER", "LATAM"]
    cd.add_series("2025", (5913, 4722, 8720, 1927))
    cd.add_series("2026", (6000, 5200, 9100, 2100))
    s3.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, PInches(1), PInches(1.6), PInches(8), PInches(5), cd)
    s4 = prs.slides.add_slide(prs.slide_layouts[6])
    box = s4.shapes.add_textbox(PInches(0.7), PInches(0.5), PInches(8.5), PInches(1))
    box.text_frame.text = "Shapes, table and image"
    box.text_frame.paragraphs[0].runs[0].font.size = PPt(30)
    box.text_frame.paragraphs[0].runs[0].font.color.rgb = PptColor(0x1F, 0x38, 0x64)
    shp = s4.shapes.add_shape(1, PInches(0.7), PInches(1.6), PInches(3), PInches(1.5))
    shp.fill.solid()
    shp.fill.fore_color.rgb = PptColor(0xC0, 0x00, 0x00)
    shp.text_frame.text = "Rounded call-out"
    tbl = s4.shapes.add_table(3, 3, PInches(0.7), PInches(3.5), PInches(5), PInches(1.8)).table
    for r in range(3):
        for c in range(3):
            tbl.cell(r, c).text = f"R{r + 1}C{c + 1}"
    s4.shapes.add_picture(io.BytesIO(_png()), PInches(5.9), PInches(1.6), width=PInches(3.6))
    prs.save(path)


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/office")
    out.mkdir(parents=True, exist_ok=True)
    make_docx(out / "complex.docx")
    make_xlsx(out / "complex.xlsx")
    make_pptx(out / "complex.pptx")
    print("wrote", sorted(p.name for p in out.iterdir()))
