"""Semantic extraction + diff for OOXML packages (DOCX, XLSX, PPTX).

The package is read with hard limits (entry count, per-member and total uncompressed size) so a
hostile archive cannot exhaust memory, and every XML part is parsed with defusedxml (no DTDs or
entity expansion). Only the parts needed for a meaningful diff are read.

What each differ understands is listed in ``LIMITS`` and returned with every result, so the UI can
say plainly what a "no differences" answer does and does not cover.
"""

from __future__ import annotations

import hashlib
import io
import posixpath
import re
import zipfile
from typing import Any

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.modules.diffs.core import Counts, Section, diff_sequences, inline_diff

MAX_ENTRIES = 5000
MAX_MEMBER_BYTES = 30 * 1024 * 1024
MAX_TOTAL_BYTES = 150 * 1024 * 1024
MAX_CELLS = 150_000

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
P = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"

LIMITS = {
    "docx": [
        "Compares paragraph text, tables (cell by cell), headers and footers, and run formatting flags "
        "(bold, italic, underline, strike, colour, size).",
        "Native tracked changes (insertions/deletions) are counted and reported, not replayed.",
        "Images, floating objects, fields, comments and page layout are not compared.",
    ],
    "xlsx": [
        "Compares sheets by name, cell values and formulas, merged ranges and number/font/fill/border style ids.",
        "Formulas are compared as text; results are not recalculated. Charts, pivots, macros and external links are not compared.",
    ],
    "pptx": [
        "Compares slide order, shape text and the set of shapes on each slide, and whether animation timing exists.",
        "Animation details, transitions, embedded objects and a visual comparison are not available.",
    ],
}


class PackageError(Exception):
    """Unreadable or unsafe package. Message is safe to show."""


def open_package(data: bytes) -> zipfile.ZipFile:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise PackageError("The file is not a valid Office document.") from None
    infos = z.infolist()
    if len(infos) > MAX_ENTRIES:
        raise PackageError("The document package has too many parts.")
    if sum(i.file_size for i in infos) > MAX_TOTAL_BYTES or any(
        i.file_size > MAX_MEMBER_BYTES for i in infos
    ):
        raise PackageError("The document is too large to compare safely.")
    return z


def _xml(z: zipfile.ZipFile, name: str) -> Any | None:
    try:
        with z.open(name) as f:
            return ET.fromstring(f.read(MAX_MEMBER_BYTES + 1))
    except KeyError:
        return None
    except ET.ParseError:
        raise PackageError(f"Part {name} is not well-formed.") from None
    except DefusedXmlException:
        raise PackageError(
            f"Part {name} uses forbidden XML constructs (DTD or entities)."
        ) from None


def _rels(z: zipfile.ZipFile, part: str) -> dict[str, str]:
    base = posixpath.dirname(part)
    root = _xml(z, posixpath.join(base, "_rels", posixpath.basename(part) + ".rels"))
    out: dict[str, str] = {}
    if root is not None:
        for rel in root.iter(f"{REL}Relationship"):
            target = rel.get("Target", "")
            out[rel.get("Id", "")] = posixpath.normpath(
                target.lstrip("/") if target.startswith("/") else posixpath.join(base, target)
            )
    return out


# ================================================================== DOCX
def _run_flags(r: Any) -> str:
    props = r.find(f"{W}rPr")
    if props is None:
        return ""
    flags = []
    for tag, label in (("b", "bold"), ("i", "italic"), ("strike", "strike")):
        e = props.find(f"{W}{tag}")
        if e is not None and e.get(f"{W}val", "true") not in ("0", "false"):
            flags.append(label)
    u = props.find(f"{W}u")
    if u is not None and u.get(f"{W}val", "single") != "none":
        flags.append("underline")
    c = props.find(f"{W}color")
    if c is not None and c.get(f"{W}val") not in (None, "auto", "000000"):
        flags.append(f"color {c.get(f'{W}val')}")
    sz = props.find(f"{W}sz")
    if sz is not None:
        flags.append(f"{int(sz.get(f'{W}val', '0')) / 2:g}pt")
    return ",".join(flags)


def _paragraph(p: Any) -> tuple[str, str]:
    """(text, formatting signature). Deleted tracked text lives in w:delText and is skipped."""
    text: list[str] = []
    sig: list[str] = []
    style = p.find(f"{W}pPr/{W}pStyle")
    for r in p.iter(f"{W}r"):
        piece = []
        for node in r:
            if node.tag == f"{W}t":
                piece.append(node.text or "")
            elif node.tag == f"{W}tab":
                piece.append("\t")
            elif node.tag == f"{W}br":
                piece.append("\n")
        s = "".join(piece)
        if s:
            text.append(s)
            f = _run_flags(r)
            if f and f not in sig:
                sig.append(f)
    label = style.get(f"{W}val") if style is not None else ""
    out_sig = ";".join(sig)
    if label and label.lower() not in ("normal", "a"):
        out_sig = f"style {label}" + (f"; {out_sig}" if out_sig else "")
    return "".join(text), out_sig


def _docx_part(root: Any) -> tuple[list[str], list[str]]:
    lines: list[str] = []
    sigs: list[str] = []
    body = root.find(f"{W}body") if root.find(f"{W}body") is not None else root
    for el in body:
        if el.tag == f"{W}p":
            t, s = _paragraph(el)
            lines.append(t)
            sigs.append(s)
        elif el.tag == f"{W}tbl":
            for ri, tr in enumerate(el.iter(f"{W}tr"), start=1):
                for ci, tc in enumerate(tr.findall(f"{W}tc"), start=1):
                    t = " ".join(_paragraph(p)[0] for p in tc.iter(f"{W}p")).strip()
                    lines.append(f"[table r{ri} c{ci}] {t}")
                    sigs.append("")
    return lines, sigs


def docx_model(data: bytes) -> dict[str, Any]:
    z = open_package(data)
    main = _xml(z, "word/document.xml")
    if main is None:
        raise PackageError("This is not a Word document (word/document.xml is missing).")
    parts: dict[str, tuple[list[str], list[str]]] = {"Body": _docx_part(main)}
    for name in sorted(z.namelist()):
        m = re.fullmatch(r"word/(header|footer)(\d*)\.xml", name)
        if m:
            root = _xml(z, name)
            if root is not None:
                parts[f"{m.group(1).title()} {m.group(2) or ''}".strip()] = _docx_part(root)
    ins = sum(1 for _ in main.iter(f"{W}ins"))
    dels = sum(1 for _ in main.iter(f"{W}del"))
    return {"parts": parts, "tracked": {"insertions": ins, "deletions": dels}}


def diff_docx(old: bytes, new: bytes, counts: Counts) -> tuple[list[Section], list[str], bool]:
    a, b = docx_model(old), docx_model(new)
    sections: list[Section] = []
    truncated = False
    for name in sorted(set(a["parts"]) | set(b["parts"]), key=lambda n: (n != "Body", n)):
        if name not in a["parts"]:
            lines = b["parts"][name][0]
            counts.add("add", len(lines))
            sections.append(
                Section(
                    name,
                    [{"op": "add", "new": t, "new_loc": i + 1} for i, t in enumerate(lines)],
                    "added",
                )
            )
            continue
        if name not in b["parts"]:
            lines = a["parts"][name][0]
            counts.add("remove", len(lines))
            sections.append(
                Section(
                    name,
                    [{"op": "remove", "old": t, "old_loc": i + 1} for i, t in enumerate(lines)],
                    "removed",
                )
            )
            continue
        (ol, osg), (nl, nsg) = a["parts"][name], b["parts"][name]
        changes, tr = diff_sequences(ol, nl, counts, old_meta=osg, new_meta=nsg)
        truncated = truncated or tr
        changed = any(c["op"] not in ("equal", "skip") for c in changes)
        sections.append(Section(name, changes, "changed" if changed else "unchanged"))
    notes = list(LIMITS["docx"])
    ta, tb = a["tracked"], b["tracked"]
    if ta != tb or any(tb.values()):
        notes.append(
            f"Tracked changes in the newer file: {tb['insertions']} insertion(s), {tb['deletions']} deletion(s) "
            f"(older file: {ta['insertions']} / {ta['deletions']})."
        )
    return sections, notes, truncated


# ================================================================== XLSX
def _col_row(ref: str) -> tuple[int, int]:
    m = re.fullmatch(r"([A-Z]+)(\d+)", ref)
    if not m:
        return 10**6, 10**6
    col = 0
    for ch in m.group(1):
        col = col * 26 + ord(ch) - 64
    return int(m.group(2)), col


def _styles(z: zipfile.ZipFile) -> list[str]:
    root = _xml(z, "xl/styles.xml")
    if root is None:
        return []
    xfs = root.find(f"{S}cellXfs")
    if xfs is None:
        return []
    return [
        f"numFmt {x.get('numFmtId', '0')}, font {x.get('fontId', '0')}, fill {x.get('fillId', '0')}, border {x.get('borderId', '0')}"
        for x in xfs.findall(f"{S}xf")
    ]


def xlsx_model(data: bytes) -> dict[str, Any]:
    z = open_package(data)
    wb = _xml(z, "xl/workbook.xml")
    if wb is None:
        raise PackageError("This is not an Excel workbook (xl/workbook.xml is missing).")
    shared: list[str] = []
    sst = _xml(z, "xl/sharedStrings.xml")
    if sst is not None:
        shared = ["".join(t.text or "" for t in si.iter(f"{S}t")) for si in sst.findall(f"{S}si")]
    styles = _styles(z)
    rels = _rels(z, "xl/workbook.xml")
    sheets: dict[str, dict[str, Any]] = {}
    total = 0
    for sh in wb.iter(f"{S}sheet"):
        name = sh.get("name", "Sheet")
        target = rels.get(sh.get(f"{R}id", ""))
        root = _xml(z, target) if target else None
        cells: dict[str, tuple[str, str, str]] = {}
        merges: set[str] = set()
        if root is not None:
            for c in root.iter(f"{S}c"):
                total += 1
                if total > MAX_CELLS:
                    raise PackageError("The workbook has too many cells to compare safely.")
                v = c.find(f"{S}v")
                f = c.find(f"{S}f")
                t = c.get("t", "n")
                if (
                    t == "s"
                    and v is not None
                    and (v.text or "").isdigit()
                    and int(v.text) < len(shared)
                ):
                    val = shared[int(v.text)]
                elif t == "inlineStr":
                    val = "".join(x.text or "" for x in c.iter(f"{S}t"))
                else:
                    val = (v.text or "") if v is not None else ""
                formula = (f.text or "") if f is not None else ""
                s_idx = c.get("s")
                style = (
                    styles[int(s_idx)]
                    if s_idx is not None and s_idx.isdigit() and int(s_idx) < len(styles)
                    else ""
                )
                if val or formula:
                    cells[c.get("r", "")] = (val, formula, style)
            for mc in root.iter(f"{S}mergeCell"):
                merges.add(mc.get("ref", ""))
        sheets[name] = {"cells": cells, "merges": merges}
    return {"sheets": sheets}


def diff_xlsx(old: bytes, new: bytes, counts: Counts) -> tuple[list[Section], list[str], bool]:
    a, b = xlsx_model(old), xlsx_model(new)
    sections: list[Section] = []
    truncated = False
    for name in list(b["sheets"]) + [n for n in a["sheets"] if n not in b["sheets"]]:
        in_a, in_b = name in a["sheets"], name in b["sheets"]
        if not in_a:
            n = len(b["sheets"][name]["cells"])
            counts.add("add", n)
            sections.append(
                Section(f"Sheet “{name}”", [], "added", f"New sheet with {n} populated cell(s).")
            )
            continue
        if not in_b:
            n = len(a["sheets"][name]["cells"])
            counts.add("remove", n)
            sections.append(
                Section(f"Sheet “{name}”", [], "removed", f"Sheet removed ({n} populated cell(s)).")
            )
            continue
        ca, cb = a["sheets"][name]["cells"], b["sheets"][name]["cells"]
        changes: list[dict[str, Any]] = []
        for ref in sorted(set(ca) | set(cb), key=_col_row):
            o, n_ = ca.get(ref), cb.get(ref)
            if o == n_:
                counts.add("equal")
                continue
            if len(changes) >= 4000:
                truncated = True
                continue

            def fmt(c: tuple[str, str, str] | None) -> str | None:
                if c is None:
                    return None
                return (
                    f"={c[1]}  →  {c[0]}" if c[1] and c[0] else (f"={c[1]}" if c[1] else c[0])
                ) or "(empty)"

            if o is None:
                counts.add("add")
                changes.append({"op": "add", "loc": ref, "new": fmt(n_)})
            elif n_ is None:
                counts.add("remove")
                changes.append({"op": "remove", "loc": ref, "old": fmt(o)})
            elif o[:2] != n_[:2]:
                counts.add("change")
                kind = "formula" if o[1] != n_[1] else "value"
                changes.append(
                    {
                        "op": "change",
                        "kind": kind,
                        "loc": ref,
                        "old": fmt(o),
                        "new": fmt(n_),
                        "inline": inline_diff(fmt(o) or "", fmt(n_) or ""),
                    }
                )
            else:
                counts.add("change")
                changes.append(
                    {
                        "op": "change",
                        "kind": "formatting",
                        "loc": ref,
                        "old": fmt(o),
                        "new": fmt(n_),
                        "detail": f"style: {o[2] or '-'} → {n_[2] or '-'}",
                    }
                )
        ma, mb = a["sheets"][name]["merges"], b["sheets"][name]["merges"]
        for m in sorted(mb - ma):
            counts.add("add")
            changes.append({"op": "add", "kind": "merged range", "loc": m, "new": f"Merged {m}"})
        for m in sorted(ma - mb):
            counts.add("remove")
            changes.append({"op": "remove", "kind": "merged range", "loc": m, "old": f"Merged {m}"})
        sections.append(Section(f"Sheet “{name}”", changes, "changed" if changes else "unchanged"))
    return sections, list(LIMITS["xlsx"]), truncated


# ================================================================== PPTX
def _shape_text(sp: Any) -> str:
    paras = []
    for p in sp.iter(f"{A}p"):
        paras.append("".join(t.text or "" for t in p.iter(f"{A}t")))
    return "\n".join(x for x in paras if x)


def pptx_model(data: bytes) -> dict[str, Any]:
    z = open_package(data)
    pres = _xml(z, "ppt/presentation.xml")
    if pres is None:
        raise PackageError("This is not a PowerPoint file (ppt/presentation.xml is missing).")
    rels = _rels(z, "ppt/presentation.xml")
    slides: list[dict[str, Any]] = []
    for sid in pres.iter(f"{P}sldId"):
        part = rels.get(sid.get(f"{R}id", ""))
        root = _xml(z, part) if part else None
        if root is None:
            continue
        shapes: dict[str, str] = {}
        order: list[str] = []
        for el in root.iter():
            if el.tag in (f"{P}sp", f"{P}pic", f"{P}graphicFrame", f"{P}cxnSp"):
                nv = el.find(f".//{P}cNvPr")
                name = nv.get("name", "shape") if nv is not None else "shape"
                kind = {
                    f"{P}sp": "text",
                    f"{P}pic": "picture",
                    f"{P}graphicFrame": "table/chart",
                    f"{P}cxnSp": "line",
                }[el.tag]
                key = f"{name} ({kind})"
                k, n = key, 2
                while k in shapes:
                    k, n = f"{key} #{n}", n + 1
                shapes[k] = _shape_text(el) if el.tag in (f"{P}sp", f"{P}graphicFrame") else ""
                order.append(k)
        slides.append(
            {
                "shapes": shapes,
                "order": order,
                "animated": root.find(f"{P}timing") is not None,
                "digest": hashlib.sha256(
                    ("\x00".join(f"{k}\x01{v}" for k, v in shapes.items())).encode()
                ).hexdigest(),
            }
        )
    return {"slides": slides}


def diff_pptx(old: bytes, new: bytes, counts: Counts) -> tuple[list[Section], list[str], bool]:
    from difflib import SequenceMatcher

    a, b = pptx_model(old)["slides"], pptx_model(new)["slides"]
    sections: list[Section] = []
    sm = SequenceMatcher(None, [s["digest"] for s in a], [s["digest"] for s in b], autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                counts.add("equal")
                label = f"Slide {j1 + k + 1}" + (f" (was {i1 + k + 1})" if i1 != j1 else "")
                sections.append(
                    Section(
                        label,
                        [],
                        "unchanged",
                        "Identical text and shapes." + (" Moved." if i1 != j1 else ""),
                    )
                )
            continue
        pair = min(i2 - i1, j2 - j1) if tag == "replace" else 0
        for k in range(pair):
            so, sn = a[i1 + k], b[j1 + k]
            changes: list[dict[str, Any]] = []
            for key in list(sn["shapes"]) + [x for x in so["shapes"] if x not in sn["shapes"]]:
                if key not in so["shapes"]:
                    counts.add("add")
                    changes.append(
                        {"op": "add", "loc": key, "new": sn["shapes"][key] or "(new shape)"}
                    )
                elif key not in sn["shapes"]:
                    counts.add("remove")
                    changes.append(
                        {"op": "remove", "loc": key, "old": so["shapes"][key] or "(shape removed)"}
                    )
                elif so["shapes"][key] != sn["shapes"][key]:
                    counts.add("change")
                    changes.append(
                        {
                            "op": "change",
                            "loc": key,
                            "old": so["shapes"][key],
                            "new": sn["shapes"][key],
                            "inline": inline_diff(so["shapes"][key], sn["shapes"][key]),
                        }
                    )
                else:
                    counts.add("equal")
            if so["animated"] != sn["animated"]:
                counts.add("change")
                changes.append(
                    {
                        "op": "change",
                        "kind": "animation",
                        "old": "animated" if so["animated"] else "no animation",
                        "new": "animated" if sn["animated"] else "no animation",
                    }
                )
            sections.append(
                Section(
                    f"Slide {j1 + k + 1}" + (f" (was {i1 + k + 1})" if i1 != j1 else ""),
                    changes,
                    "changed",
                )
            )
        for i in range(i1 + pair, i2):
            counts.add("remove")
            sections.append(
                Section(
                    f"Slide {i + 1} (old)",
                    [],
                    "removed",
                    "Slide removed: " + "; ".join(v for v in a[i]["shapes"].values() if v)[:200],
                )
            )
        for j in range(j1 + pair, j2):
            counts.add("add")
            sections.append(
                Section(
                    f"Slide {j + 1}",
                    [],
                    "added",
                    "New slide: " + "; ".join(v for v in b[j]["shapes"].values() if v)[:200],
                )
            )
    return sections, list(LIMITS["pptx"]), False
