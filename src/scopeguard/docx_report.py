"""Professional Word (.docx) report built from structured scan data.

Requires the optional ``python-docx`` package (imported lazily, so the rest of
scopeguard stays stdlib-only). Layout:

* cover block: title, target, key facts table, at-a-glance severity bar
* executive summary with clickable ``[Sn]`` citations (internal links)
* severity overview table with coloured cells, red flags
* findings, most severe first: coloured severity badge, details table
  (category, CWE link, confidence, source, affected URL link), description,
  shaded monospace evidence block, recommendation
* sources (bookmarked, so citations jump to them; external links validated)
* out-of-scope links, disclaimer; header with target, footer "Page X of Y"

All text from the target or a model is stripped of XML-invalid control
characters; only ``citations.safe_url`` URLs become hyperlinks.
"""
from __future__ import annotations

import re
from pathlib import Path

from scopeguard import citations

ORDER = ["critical", "high", "medium", "low", "info"]
SEV_COLORS = {  # badge fill, text on fill
    "critical": ("7B1E1E", "FFFFFF"),
    "high": ("C0392B", "FFFFFF"),
    "medium": ("D68910", "FFFFFF"),
    "low": ("2E86C1", "FFFFFF"),
    "info": ("7F8C8D", "FFFFFF"),
}
ACCENT = "1F3A5F"
MUTED = "5B6475"
CODE_FILL = "F3F4F6"
HEAD_FILL = "E8EDF3"

_INVALID_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def _clean(text) -> str:
    return _INVALID_XML.sub("", "" if text is None else str(text))


def _val(x, key):
    v = x.get(key) if isinstance(x, dict) else getattr(x, key, None)
    return getattr(v, "value", v)


def _sev(x) -> str:
    s = str(_val(x, "severity") or "info").lower()
    return s if s in ORDER else "info"


# --------------------------------------------------------------------------- low-level OOXML helpers
def _ox():
    from docx.oxml import OxmlElement
    from docx.oxml.ns import qn
    return OxmlElement, qn


def _shade(cell, fill: str) -> None:
    OxmlElement, qn = _ox()
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)


def _para_shade_border(paragraph, fill: str, border: str = "D1D5DB") -> None:
    OxmlElement, qn = _ox()
    p_pr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill)
    bdr = OxmlElement("w:pBdr")
    for side in ("top", "left", "bottom", "right"):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:val"), "single")
        el.set(qn("w:sz"), "4")
        el.set(qn("w:space"), "4")
        el.set(qn("w:color"), border)
        bdr.append(el)
    p_pr.append(bdr)
    p_pr.append(shd)


def _cell_margins(table, top=60, bottom=60, left=100, right=100) -> None:
    OxmlElement, qn = _ox()
    tbl_pr = table._tbl.tblPr
    mar = OxmlElement("w:tblCellMar")
    for side, v in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        el = OxmlElement(f"w:{side}")
        el.set(qn("w:w"), str(v))
        el.set(qn("w:type"), "dxa")
        mar.append(el)
    tbl_pr.append(mar)


def _repeat_header(row) -> None:
    OxmlElement, qn = _ox()
    tr_pr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    tr_pr.append(el)


def _keep_row_together(row) -> None:
    OxmlElement, _qn = _ox()
    tr_pr = row._tr.get_or_add_trPr()
    tr_pr.append(OxmlElement("w:cantSplit"))


def _bookmark(paragraph, name: str, bid: int) -> None:
    OxmlElement, qn = _ox()
    start = OxmlElement("w:bookmarkStart")
    start.set(qn("w:id"), str(bid))
    start.set(qn("w:name"), name)
    end = OxmlElement("w:bookmarkEnd")
    end.set(qn("w:id"), str(bid))
    paragraph._p.insert(0, start)
    paragraph._p.append(end)


def _hyperlink(paragraph, text: str, *, url: str | None = None, anchor: str | None = None,
               color: str = "1F5FBF", bold: bool = False, size=None, mono: bool = False):
    """Append a clickable run: external ``url`` or internal bookmark ``anchor``."""
    from docx.opc.constants import RELATIONSHIP_TYPE as RT

    OxmlElement, qn = _ox()
    link = OxmlElement("w:hyperlink")
    if url:
        link.set(qn("r:id"), paragraph.part.relate_to(url, RT.HYPERLINK, is_external=True))
    else:
        link.set(qn("w:anchor"), anchor)
    link.set(qn("w:history"), "1")
    run = OxmlElement("w:r")
    r_pr = OxmlElement("w:rPr")
    c = OxmlElement("w:color")
    c.set(qn("w:val"), color)
    r_pr.append(c)
    u = OxmlElement("w:u")
    u.set(qn("w:val"), "single" if url else "none")
    r_pr.append(u)
    if bold:
        r_pr.append(OxmlElement("w:b"))
    if mono:
        fonts = OxmlElement("w:rFonts")
        for a in ("w:ascii", "w:hAnsi", "w:cs"):
            fonts.set(qn(a), "Consolas")
        r_pr.append(fonts)
    if size:
        sz = OxmlElement("w:sz")
        sz.set(qn("w:val"), str(int(size * 2)))
        r_pr.append(sz)
    run.append(r_pr)
    t = OxmlElement("w:t")
    t.text = _clean(text)
    t.set(qn("xml:space"), "preserve")
    run.append(t)
    link.append(run)
    paragraph._p.append(link)


def _field(paragraph, instr: str, placeholder: str = "1") -> None:
    """Insert a Word field (PAGE, NUMPAGES, ...)."""
    OxmlElement, qn = _ox()
    for kind, text in (("begin", None), ("instr", instr), ("separate", None),
                       ("text", placeholder), ("end", None)):
        r = OxmlElement("w:r")
        if kind == "instr":
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = f" {text} "
        elif kind == "text":
            el = OxmlElement("w:t")
            el.text = text
        else:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        r.append(el)
        paragraph._p.append(r)


# --------------------------------------------------------------------------- document builder
class _Builder:
    def __init__(self, title: str):
        import docx
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.shared import Cm, Pt, RGBColor

        self.Pt, self.Cm, self.RGB, self.ALIGN = Pt, Cm, RGBColor, WD_ALIGN_PARAGRAPH
        self.doc = docx.Document()
        self._bid = 0
        sec = self.doc.sections[0]
        sec.left_margin = sec.right_margin = Cm(2.0)
        sec.top_margin = Cm(2.0)
        sec.bottom_margin = Cm(1.8)

        styles = self.doc.styles
        normal = styles["Normal"]
        normal.font.name = "Calibri"
        normal.font.size = Pt(10.5)
        normal.paragraph_format.space_after = Pt(4)
        normal.paragraph_format.line_spacing = 1.12
        for name, size, color, before in (("Title", 24, ACCENT, 0), ("Heading 1", 15, ACCENT, 14),
                                          ("Heading 2", 12.5, ACCENT, 10), ("Heading 3", 11, "1D2330", 8)):
            st = styles[name]
            st.font.name = "Calibri"
            st.font.size = Pt(size)
            st.font.bold = True
            st.font.color.rgb = RGBColor.from_string(color)
            st.paragraph_format.space_before = Pt(before)
            st.paragraph_format.space_after = Pt(4)
            st.paragraph_format.keep_with_next = True
        for name in ("Header", "Footer"):
            styles[name].font.size = Pt(8)
            styles[name].font.color.rgb = RGBColor.from_string(MUTED)
        self.doc.core_properties.title = _clean(title)[:250]
        self.doc.core_properties.author = "ScopeGuard"
        self.doc.core_properties.subject = "Automated web security assessment"
        self.doc.core_properties.keywords = "security, DAST, SAST, OWASP"

    def bid(self) -> int:
        self._bid += 1
        return self._bid

    # -- primitives
    def para(self, text: str = "", *, bold=False, italic=False, color=None, size=None, style=None,
             align=None, space_after=None):
        p = self.doc.add_paragraph(style=style)
        if text:
            r = p.add_run(_clean(text))
            r.bold, r.italic = bold, italic
            if color:
                r.font.color.rgb = self.RGB.from_string(color)
            if size:
                r.font.size = self.Pt(size)
        if align is not None:
            p.alignment = align
        if space_after is not None:
            p.paragraph_format.space_after = self.Pt(space_after)
        return p

    def badge(self, paragraph, sev: str):
        fill, fg = SEV_COLORS[sev]
        r = paragraph.add_run(f" {sev.upper()} ")
        r.bold = True
        r.font.size = self.Pt(8.5)
        r.font.color.rgb = self.RGB.from_string(fg)
        OxmlElement, qn = _ox()
        shd = OxmlElement("w:shd")
        shd.set(qn("w:val"), "clear")
        shd.set(qn("w:color"), "auto")
        shd.set(qn("w:fill"), fill)
        r._r.get_or_add_rPr().append(shd)
        paragraph.add_run("  ")

    def kv_table(self, rows: list[tuple[str, object]], key_width_cm=4.2):
        t = self.doc.add_table(rows=0, cols=2)
        t.style = "Table Grid"
        _cell_margins(t)
        for key, value in rows:
            cells = t.add_row().cells
            _keep_row_together(t.rows[-1])
            cells[0].width = self.Cm(key_width_cm)
            cells[1].width = self.Cm(17.0 - key_width_cm)
            self._key_cell(cells[0], key)
            self._value_cell(cells[1], value)
        self.spacer()
        return t

    # -- table cell helpers
    def _tight(self, paragraph):
        paragraph.paragraph_format.space_after = self.Pt(0)
        paragraph.paragraph_format.space_before = self.Pt(0)
        paragraph.paragraph_format.line_spacing = 1.0
        return paragraph

    def _key_cell(self, cell, key):
        _shade(cell, HEAD_FILL)
        r = self._tight(cell.paragraphs[0]).add_run(_clean(key))
        r.bold = True
        r.font.size = self.Pt(9)
        r.font.color.rgb = self.RGB.from_string("1D2330")

    def _value_cell(self, cell, value):
        vp = self._tight(cell.paragraphs[0])
        if callable(value):
            value(vp)
        else:
            vp.add_run(_clean(value)).font.size = self.Pt(9)

    def spacer(self, pt=4):
        p = self.doc.add_paragraph()
        p.paragraph_format.space_after = self.Pt(0)
        p.paragraph_format.line_spacing = self.Pt(pt)
        return p

    def detail_grid(self, pairs: list[tuple[str, object]], wide: tuple[str, object] | None = None):
        """Compact 4-column grid: two key/value pairs per row, optional full-width last row."""
        widths = (2.8, 5.7, 2.8, 5.7)
        t = self.doc.add_table(rows=0, cols=4)
        t.style = "Table Grid"
        _cell_margins(t, 50, 50, 90, 90)
        for i in range(0, len(pairs), 2):
            cells = t.add_row().cells
            _keep_row_together(t.rows[-1])
            for j, (k, v) in enumerate(pairs[i:i + 2]):
                self._key_cell(cells[2 * j], k)
                self._value_cell(cells[2 * j + 1], v)
        if wide:
            cells = t.add_row().cells
            _keep_row_together(t.rows[-1])
            merged = cells[1].merge(cells[3])
            self._key_cell(cells[0], wide[0])
            self._value_cell(merged, wide[1])
        for row in t.rows:
            for cell, w in zip(row.cells, widths):
                cell.width = self.Cm(w)
        self.spacer()
        return t

    def link_or_text(self, paragraph, url, text=None, size=9.5, mono=False):
        u = citations.safe_url(url)
        if u:
            _hyperlink(paragraph, text or u, url=u, size=size, mono=mono)
        else:
            r = paragraph.add_run(_clean(text or url or "n/a"))
            r.font.size = self.Pt(size)

    def cited_text(self, paragraph, text: str, sources: dict, size=None):
        """Plain text with [Sn] markers turned into internal links to the Sources section."""
        pos = 0
        for m in citations.CITATION_RE.finditer(text or ""):
            if m.start() > pos:
                r = paragraph.add_run(_clean(text[pos:m.start()]))
                if size:
                    r.font.size = self.Pt(size)
            ids = citations.citation_ids(m.group(1))
            ids = [i for i in ids if i in sources]
            if ids:
                paragraph.add_run("[")
                for k, sid in enumerate(ids):
                    if k:
                        paragraph.add_run(", ")
                    _hyperlink(paragraph, sid, anchor=f"src_{sid}", bold=True, size=size)
                paragraph.add_run("]")
            pos = m.end()
        if pos < len(text or ""):
            r = paragraph.add_run(_clean(text[pos:]))
            if size:
                r.font.size = self.Pt(size)

    def header_footer(self, header_text: str):
        sec = self.doc.sections[0]
        hp = sec.header.paragraphs[0]
        hr = hp.add_run(_clean(header_text)[:120])
        hr.font.size = self.Pt(8)
        hr.font.color.rgb = self.RGB.from_string(MUTED)
        hp.alignment = self.ALIGN.RIGHT
        fp = sec.footer.paragraphs[0]
        fp.alignment = self.ALIGN.CENTER
        r = fp.add_run("ScopeGuard security report  ·  Page ")
        r.font.size = self.Pt(8)
        r.font.color.rgb = self.RGB.from_string(MUTED)
        _field(fp, "PAGE")
        r2 = fp.add_run(" of ")
        r2.font.size = self.Pt(8)
        r2.font.color.rgb = self.RGB.from_string(MUTED)
        _field(fp, "NUMPAGES")


def build_docx(path: str | Path, *, title: str, target: str, meta: list[tuple[str, str]],
               summary: str | None, findings: list, sources: dict[str, dict], red_flags: list[str],
               blocked: list[str], summary_heading: str = "Executive Summary",
               recommendations: list[dict] | None = None, guardrails: dict | None = None) -> Path:
    """Write a formatted report to ``path``. Raises ImportError without python-docx.

    ``recommendations`` / ``guardrails``: the source-code SAST step's per-rule fixes and pre/post
    guardrail verdicts, so the scan's one report also holds everything about the code."""
    b = _Builder(title)
    doc = b.doc
    counts = {s: sum(1 for f in findings if _sev(f) == s) for s in ORDER}

    # ---- cover block
    b.para("CONFIDENTIAL · AUTHORIZED SECURITY ASSESSMENT", bold=True, color=MUTED, size=8.5, space_after=2)
    doc.add_paragraph(_clean(title), style="Title")
    tp = b.para(space_after=8)
    tr = tp.add_run("Target: ")
    tr.bold = True
    b.link_or_text(tp, target, size=10.5)
    b.kv_table([(k, v) for k, v in meta])

    # at-a-glance severity strip
    strip = doc.add_table(rows=2, cols=len(ORDER))
    strip.style = "Table Grid"
    _cell_margins(strip, 80, 80, 60, 60)
    for i, s in enumerate(ORDER):
        fill, fg = SEV_COLORS[s]
        for row, text, size in ((0, str(counts[s]), 18), (1, s.upper(), 8.5)):
            cell = strip.rows[row].cells[i]
            _shade(cell, fill)
            p = cell.paragraphs[0]
            p.alignment = b.ALIGN.CENTER
            p.paragraph_format.space_after = b.Pt(0)
            r = p.add_run(text)
            r.bold = True
            r.font.size = b.Pt(size)
            r.font.color.rgb = b.RGB.from_string(fg)
    b.para(space_after=2)

    # ---- summary
    doc.add_heading(summary_heading, level=1)
    if summary:
        b.cited_text(b.para(), summary, sources)
    else:
        b.para("No summary available.", italic=True, color=MUTED)

    # ---- severity overview
    doc.add_heading("Findings Overview", level=1)
    ov = doc.add_table(rows=1, cols=3)
    ov.style = "Table Grid"
    _cell_margins(ov)
    for cell, text in zip(ov.rows[0].cells, ("Severity", "Count", "Findings")):
        _shade(cell, ACCENT)
        r = cell.paragraphs[0].add_run(text)
        r.bold = True
        r.font.color.rgb = b.RGB.from_string("FFFFFF")
        r.font.size = b.Pt(9.5)
    _repeat_header(ov.rows[0])
    for s in ORDER:
        cells = ov.add_row().cells
        _shade(cells[0], SEV_COLORS[s][0])
        r = cells[0].paragraphs[0].add_run(s.upper())
        r.bold = True
        r.font.size = b.Pt(9)
        r.font.color.rgb = b.RGB.from_string(SEV_COLORS[s][1])
        cells[1].paragraphs[0].add_run(str(counts[s])).font.size = b.Pt(9.5)
        titles = sorted({_clean(_val(f, "title")) for f in findings if _sev(f) == s})
        shown = ", ".join(titles[:6]) + (f" (+{len(titles) - 6} more)" if len(titles) > 6 else "")
        cells[2].paragraphs[0].add_run(shown or "—").font.size = b.Pt(9)
    for row in ov.rows:
        row.cells[0].width, row.cells[1].width, row.cells[2].width = b.Cm(2.6), b.Cm(1.8), b.Cm(12.6)
    b.para(space_after=2)

    if red_flags:
        doc.add_heading("Red Flags", level=2)
        for rf in red_flags:
            p = doc.add_paragraph(style="List Bullet")
            r = p.add_run(_clean(rf))
            r.font.color.rgb = b.RGB.from_string("9B2C2C")

    if recommendations:
        doc.add_heading("Source Code: How to Fix (per rule)", level=2)
        for rec in recommendations[:40]:
            rem = rec.get("remediation") or {}
            p = b.para(space_after=2)
            b.badge(p, str(rec.get("severity") or "info").lower() if str(rec.get("severity") or "").lower()
                    in ORDER else "info")
            r = p.add_run(f"{_clean(rec.get('rule'))} x{int(rec.get('count') or 0)}"
                          + (f"  ({_clean(rec.get('cwe'))})" if rec.get("cwe") else ""))
            r.bold = True
            b.para(_clean(rem.get("summary") or rec.get("recommendation") or ""), size=9.5, space_after=2)
            for step in (rem.get("steps") or [])[:10]:
                doc.add_paragraph(_clean(step), style="List Number")
            example = rem.get("example") or {}
            if example.get("after"):
                b.para(f"Fixed ({_clean(example.get('language'))}):", italic=True, color=MUTED, size=8.5,
                       space_after=0)
                b.para(_clean(example["after"])[:2000], size=8.5, space_after=4)
            for ref in (rem.get("references") or [])[:4]:
                b.link_or_text(b.para(space_after=0), ref, size=8.5)
    if guardrails:
        doc.add_heading("Source Code: Guardrails", level=2)
        b.kv_table([(f"{stage} · {_clean(c.get('name'))}",
                     f"{'passed' if c.get('passed') else 'FAILED'}: {_clean(c.get('detail'))}")
                    for stage in ("pre", "post") for c in (guardrails.get(stage) or [])][:40])

    # ---- detailed findings
    doc.add_page_break()
    doc.add_heading("Detailed Findings", level=1)
    if not findings:
        b.para("The scan produced no findings.", italic=True, color=MUTED)
    ranked = sorted(enumerate(findings), key=lambda t: (ORDER.index(_sev(t[1])), t[0]))
    for n, (_, f) in enumerate(ranked, 1):
        sev = _sev(f)
        h = doc.add_heading(level=3)
        b.badge(h, sev)
        h.add_run(f"F-{n:02d}  {_clean(_val(f, 'title'))}")
        sid = citations.source_for_finding(sources, f)
        if sid:
            h.add_run("  ")
            _hyperlink(h, f"[{sid}]", anchor=f"src_{sid}", size=10)

        cwe = _val(f, "cwe")
        cid = citations.cwe_id(cwe)
        cwe_cell = ((lambda p, c=cwe, i=cid: b.link_or_text(p, citations.cwe_url(c), f"CWE-{i}", size=9))
                    if cid else "n/a")
        affected_url = _val(f, "affected_url")
        b.detail_grid(
            [("Category", _val(f, "category") or "n/a"), ("CWE", cwe_cell),
             ("Confidence", str(_val(f, "confidence") or "n/a").capitalize()),
             ("Detected by", _val(f, "source") or "n/a")],
            wide=("Affected URL", lambda p, u=affected_url: b.link_or_text(p, u, size=8.5, mono=True)),
        )

        desc = _val(f, "description")
        if desc:
            b.para("Description", bold=True, color=ACCENT, size=10, space_after=1)
            b.para(desc)
        ev = _val(f, "evidence")
        if ev:
            b.para("Evidence", bold=True, color=ACCENT, size=10, space_after=1)
            ep = doc.add_paragraph()
            _para_shade_border(ep, CODE_FILL)
            er = ep.add_run(_clean(ev)[:1500])
            er.font.name = "Consolas"
            er.font.size = b.Pt(8.5)
            ep.paragraph_format.space_after = b.Pt(6)
        rec = _val(f, "recommendation")
        if rec:
            rp = b.para(space_after=8)
            rr = rp.add_run("Recommendation: ")
            rr.bold = True
            rr.font.color.rgb = b.RGB.from_string("1E7B4F")
            rp.add_run(_clean(rec))

    # ---- sources
    if sources:
        doc.add_heading("Sources", level=1)
        b.para("Citations [Sn] in this report link to the entries below. Links are taken from scan data "
               "and validated; nothing here was written by a language model.", italic=True, color=MUTED,
               size=9)
        for sid, s in sources.items():
            p = b.para(space_after=3)
            _bookmark(p, f"src_{sid}", b.bid())
            r = p.add_run(f"[{sid}] ")
            r.bold = True
            b.badge(p, s["severity"] if s["severity"] in ORDER else "info")
            p.add_run(_clean(s["title"]))
            if s.get("url"):
                p.add_run("  ·  ")
                b.link_or_text(p, s["url"], size=9, mono=True)
            if s.get("cwe_url"):
                p.add_run("  ·  ")
                b.link_or_text(p, s["cwe_url"], s.get("cwe") or "CWE", size=9)

    if blocked:
        doc.add_heading("Out-of-Scope Links (never fetched)", level=2)
        for u in blocked[:200]:
            p = doc.add_paragraph(style="List Bullet")
            r = p.add_run(_clean(u))
            r.font.size = b.Pt(8.5)
            r.font.name = "Consolas"
        if len(blocked) > 200:
            b.para(f"... and {len(blocked) - 200} more.", italic=True, color=MUTED, size=9)

    doc.add_heading("Disclaimer", level=2)
    b.para("This report was generated automatically by non-destructive checks against a target the operator "
           "confirmed they are authorized to test. Findings, especially from pattern-based and active checks, "
           "can include false positives and must be triaged by a qualified reviewer before remediation or "
           "disclosure. Absence of findings does not prove the application is secure.",
           color=MUTED, size=9)

    b.header_footer(f"Security report · {target}")
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out))
    return out
