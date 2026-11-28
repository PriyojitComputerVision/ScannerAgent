"""Source citations for LLM-written (and deterministic) report prose. Stdlib only.

Every finding becomes a numbered source ``S1..Sn``. An LLM is shown only that
source list and must cite claims as ``[Sn]``. Its output is then checked:

* citations to ids that are not in the dictionary are removed (hallucinated);
* bare URLs that do not belong to a known source are removed (hallucinated links);
* surviving ``[Sn]`` markers are replaced, by regex, with links built from the
  dictionary, so every rendered link comes from scan data, never from the model.

Source links are validated: only absolute http(s) URLs without credentials or
whitespace are kept, and CWE ids map to their canonical MITRE page.
"""
from __future__ import annotations

import html
import re
import urllib.parse as up

# [S1]  [S1, S3]  [S1][S2]  [S1; S2]  and ranges [S2-S5] / [S2-5] (case-insensitive "s").
# Range dashes include the Unicode hyphens/dashes LLMs emit (U+2010..U+2015, U+2212).
_DASH = r"\-" + "‐‑‒–—―−"
_ITEM = rf"[Ss]\d+(?:\s*[{_DASH}]\s*[Ss]?\d+)?"
_ITEM_RE = re.compile(_ITEM)
_LIST_SEP = re.compile(r"\s*[,;]\s*")


def _id_list(group: str) -> bool:
    """True when ``group`` is exactly source ids / ranges separated by ',' or ';'."""
    return all(_ITEM_RE.fullmatch(part) for part in _LIST_SEP.split(group.strip()))


class _CitationPattern:
    """A bracketed list of source ids. The regex only finds a candidate (one bounded character
    class, so no nested repetition and no catastrophic backtracking); ``_id_list`` then checks the
    exact grammar ``item ([,;] item)*``. finditer / sub / search behave like the compiled regex's,
    but only for real citation lists; other candidates are left as they are."""

    def __init__(self, opening: str, closing: str) -> None:
        self._rx = re.compile(rf"{opening}\s*([Ss][\sSs\d,;{_DASH}]{{0,400}}?)\s*{closing}")

    def finditer(self, text: str):
        return (m for m in self._rx.finditer(text) if _id_list(m.group(1)))

    def search(self, text: str):
        return next(self.finditer(text), None)

    def sub(self, repl, text: str) -> str:
        def one(m: re.Match) -> str:
            if not _id_list(m.group(1)):
                return m.group(0)
            return repl(m) if callable(repl) else m.expand(repl)
        return self._rx.sub(one, text)


CITATION_RE = _CitationPattern(r"\[", r"\]")
# LLMs sometimes cite as (S1) / (S1, S3-S5). Only parentheses that hold nothing
# but source ids are treated as citations; ordinary parenthesised text is untouched.
_PAREN_CITATION_RE = _CitationPattern(r"\(", r"\)")
_RANGE_RE = re.compile(rf"[Ss](\d+)(?:\s*[{_DASH}]\s*[Ss]?(\d+))?")
_MAX_RANGE = 200  # a longer "range" is a typo, not a citation list


def citation_ids(group: str) -> list[str]:
    """Ids inside one citation marker, ranges expanded: ``"S1, S3-S5"`` ->
    ``["S1", "S3", "S4", "S5"]``. Order is kept, duplicates dropped."""
    out: list[str] = []
    for a, b in _RANGE_RE.findall(group or ""):
        lo = int(a)
        hi = int(b) if b else lo
        nums = range(lo, hi + 1) if lo <= hi <= lo + _MAX_RANGE else (lo, int(b) if b else lo)
        for n in nums:
            sid = f"S{n}"
            if sid not in out:
                out.append(sid)
    return out
_CWE_RE = re.compile(r"^\s*(?:CWE[-_ ]?)?(\d{1,5})\s*$", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>\"'`)\]*]+", re.IGNORECASE)
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def safe_url(url: str | None) -> str | None:
    """Return ``url`` if it is a well-formed absolute http(s) URL, else None."""
    if not url or not isinstance(url, str) or any(c.isspace() for c in url):
        return None
    try:
        p = up.urlparse(url)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        return None
    return url


def cwe_id(cwe) -> int | None:
    """``"CWE-79"`` / ``"79"`` / ``79`` -> 79; anything else -> None."""
    m = _CWE_RE.match(str(cwe)) if cwe is not None else None
    return int(m.group(1)) if m and int(m.group(1)) > 0 else None


def cwe_url(cwe) -> str | None:
    n = cwe_id(cwe)
    return f"https://cwe.mitre.org/data/definitions/{n}.html" if n else None


def _get(item, key, default=None):
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _sev(item) -> str:
    s = _get(item, "severity", "info")
    return str(getattr(s, "value", s)).lower()


def build_sources(findings) -> dict[str, dict]:
    """Map ``"S1".."Sn"`` to source records, one per finding, most severe first.

    Accepts finding dicts or objects with the same attribute names (pydantic
    ``Finding``). Order is stable, so ids are deterministic for a given scan.
    """
    ordered = sorted(enumerate(findings), key=lambda t: (_SEVERITY_RANK.get(_sev(t[1]), 9), t[0]))
    sources: dict[str, dict] = {}
    for n, (_, f) in enumerate(ordered, 1):
        cwe = _get(f, "cwe")
        sources[f"S{n}"] = {
            "id": f"S{n}",
            "finding_id": _get(f, "id"),
            "title": str(_get(f, "title", "")),
            "severity": _sev(f),
            "url": safe_url(_get(f, "affected_url")),
            "cwe": f"CWE-{cwe_id(cwe)}" if cwe_id(cwe) else None,
            "cwe_url": cwe_url(cwe),
        }
    return sources


def source_for_finding(sources: dict[str, dict], finding) -> str | None:
    """Return the source id (``"S3"``) assigned to ``finding``, if any."""
    fid = _get(finding, "id")
    title = _get(finding, "title")
    url = safe_url(_get(finding, "affected_url"))
    for sid, s in sources.items():
        if fid is not None and s["finding_id"] == fid:
            return sid
    for sid, s in sources.items():
        if s["finding_id"] is None and s["title"] == title and s["url"] == url:
            return sid
    return None


def sources_prompt_block(sources: dict[str, dict], limit: int = 60) -> str:
    """Plain-text source list to put in an LLM prompt, grouped under one heading
    per severity (sources are already most-severe first).

    The headings stop the model from filing similar-looking findings (e.g. the
    JS_* patterns, which span high to low) under one severity.
    """
    counts: dict[str, int] = {}
    for s in sources.values():
        counts[s["severity"]] = counts.get(s["severity"], 0) + 1
    lines: list[str] = []
    current = None
    for sid, s in list(sources.items())[:limit]:
        if s["severity"] != current:
            current = s["severity"]
            n = counts[current]
            label = "INFORMATIONAL" if current == "info" else current.upper()
            if lines:
                lines.append("")
            lines.append(f"{label} severity ({n} finding{'s' if n != 1 else ''}; cite these only "
                         f"as {label.lower()}):")
        extra = ", ".join(x for x in (s["cwe"], s["url"]) if x)
        lines.append(f"[{sid}] {s['severity'].upper()}: {s['title']}" + (f" ({extra})" if extra else ""))
    if len(sources) > limit:
        lines.append(f"... {len(sources) - limit} more lower-severity sources not shown")
    return "\n".join(lines) or "(no sources: the scan produced no findings)"


def sanitize(text: str, sources: dict[str, dict],
             allowed_urls: tuple[str, ...] | list[str] = ()) -> tuple[str, list[str], list[str]]:
    """Drop unknown citations and unknown URLs.

    Returns ``(clean_text, valid_ids_used, invalid_ids_removed)``. Valid
    citations are normalised to ``[S1, S2]`` form.
    """
    used: list[str] = []
    invalid: list[str] = []

    def fix(m: re.Match) -> str:
        keep = []
        for sid in citation_ids(m.group(1)):
            if sid in sources:
                if sid not in keep:
                    keep.append(sid)
                if sid not in used:
                    used.append(sid)
            elif sid not in invalid:
                invalid.append(sid)
        return f"[{', '.join(keep)}]" if keep else ""

    out = _PAREN_CITATION_RE.sub(r"[\1]", text or "")  # (S1) -> [S1]
    out = CITATION_RE.sub(fix, out)
    known_urls = {s["url"] for s in sources.values() if s["url"]} | {
        s["cwe_url"] for s in sources.values() if s["cwe_url"]} | known_extra(allowed_urls)
    # LLMs often write non-breaking hyphens (U+2011) inside host names; restore them so the
    # real target URL is not mistaken for an invented one.
    out = _URL_RE.sub(lambda m: m.group(0).translate(_URL_HYPHENS)
                      if normalize_url(m.group(0)) in known_urls else "", out)
    out = re.sub(r"[ \t]+([.,;:])", r"\1", out)  # tidy spaces left by removals
    out = re.sub(r"[ \t]{2,}", " ", out).strip()
    return out, used, invalid


def find_urls(text: str) -> list[str]:
    """URLs in free text, without trailing sentence punctuation."""
    return [normalize_url(u) for u in _URL_RE.findall(text or "")]


_URL_HYPHENS = str.maketrans({"‐": "-", "‑": "-"})


def normalize_url(url: str) -> str:
    return url.translate(_URL_HYPHENS).rstrip(".,;:!?")


def known_extra(urls) -> set[str]:
    """Extra allowed URLs (e.g. the scan target) in both trailing-slash forms."""
    out: set[str] = set()
    for u in urls or ():
        if safe_url(u):
            out |= {u.rstrip("/"), u.rstrip("/") + "/"}
    return out


def _link_target(s: dict, anchor_prefix: str | None) -> str:
    if anchor_prefix is not None:
        return f"#{anchor_prefix}{s['id']}"
    return s["url"] or s["cwe_url"] or f"#src-{s['id']}"


def to_markdown(text: str, sources: dict[str, dict], anchor_prefix: str | None = "src-") -> str:
    """Replace ``[Sn]`` markers with markdown links from the dictionary.

    By default each citation links to the report's own Sources section
    (``#src-Sn``); pass ``anchor_prefix=None`` to link straight to the URL.
    Unknown ids are dropped.
    """
    def rep(m: re.Match) -> str:
        ids = citation_ids(m.group(1))
        links = [f"[{sid}]({_link_target(sources[sid], anchor_prefix)})" for sid in ids if sid in sources]
        return f"[{', '.join(links)}]" if links else ""
    return CITATION_RE.sub(rep, text or "")


def to_html(text: str, sources: dict[str, dict], anchor_prefix: str = "src-") -> str:
    """HTML-escape ``text`` and replace ``[Sn]`` markers with anchor links."""
    def rep(m: re.Match) -> str:
        ids = citation_ids(m.group(1))
        links = [f'<a class="cite" href="#{anchor_prefix}{sid}">{sid}</a>' for sid in ids if sid in sources]
        return f"[{', '.join(links)}]" if links else ""
    escaped = html.escape(text or "", quote=False)  # [S1] survives escaping unchanged
    return CITATION_RE.sub(rep, escaped)


def strip_markers(text: str) -> str:
    """Turn ``[[S1](#src-S1)]`` style links back into plain ``[S1]`` (for docx)."""
    return re.sub(r"\[([Ss]\d+)\]\([^)]*\)", r"\1", text or "")


def sources_markdown(sources: dict[str, dict]) -> list[str]:
    lines = []
    for sid, s in sources.items():
        parts = [f'- <a id="src-{sid}"></a>**[{sid}]** [{s["severity"].upper()}] {s["title"]}']
        if s["url"]:
            parts.append(f"[{s['url']}]({s['url']})")
        if s["cwe_url"]:
            parts.append(f"[{s['cwe']}]({s['cwe_url']})")
        lines.append(" · ".join(parts))
    return lines


def attack_coverage_markdown(summary: dict | None) -> list[str]:
    """Markdown lines summarising which attacks/checks were run and what they found.
    ``summary`` is engine ``attack_summary`` ({check: {tested, findings, notes}})."""
    if not summary:
        return []
    lines = ["## Attack coverage", "",
             "What the scanner tested and what it found (0 findings = tested, nothing detected).", "",
             "| Check / attack | Tests run | Findings | Notes |", "|---|---|---|---|"]
    for name in sorted(summary):
        c = summary[name] or {}
        notes = "; ".join((c.get("notes") or [])[:4])
        if len(c.get("notes") or []) > 4:
            notes += f" (+{len(c['notes']) - 4} more)"
        lines.append(f"| {name} | {c.get('tested', 0)} | {c.get('findings', 0)} | {notes[:300]} |")
    return lines + [""]


def deterministic_summary(target: str, sources: dict[str, dict], pages: int, red_flags: int,
                          top: int = 5) -> str:
    """Fact-only summary that cites its sources (used when no LLM is available,
    or when an LLM answer carries no valid citations)."""
    counts: dict[str, int] = {}
    for s in sources.values():
        counts[s["severity"]] = counts.get(s["severity"], 0) + 1
    tally = ", ".join(f"{counts[k]} {k}" for k in _SEVERITY_RANK if counts.get(k)) or "no findings"
    text = (f"Automated scan of {target} crawled {pages} in-scope page(s) and produced "
            f"{len(sources)} finding(s) ({tally}).")
    head = list(sources.items())[:top]
    if head:
        text += " Most severe: " + "; ".join(f"{s['title']} [{sid}]" for sid, s in head) + "."
    if red_flags:
        text += f" {red_flags} red flag(s) were raised; see the Red Flags section."
    return text


# --------------------------------------------------------------------------- severity grounding
# Shared by the executive summary (graph.generate_executive_summary: self-check + repair) and the
# golden drift check (model checks severity_consistent_citations / severity_numbers_grounded).
# Severity words as an executive summary uses them ("high-severity", "Medium findings",
# "Lower-severity items", "informational headers") -> the SOURCES severities they cover.
_SEVERITY_WORDS = {"critical": {"critical"}, "high": {"high"}, "medium": {"medium"}, "moderate": {"medium"},
                   "low": {"low"}, "lower": {"low", "info"}, "info": {"info"},
                   "informational": {"info"}}
_SEVERITY_RE = re.compile(r"\b(" + "|".join(sorted(_SEVERITY_WORDS, key=len, reverse=True)) + r")\b",
                          re.IGNORECASE)
# Sentence ends and line breaks: LLM answers often use markdown paragraphs/lists
# ("items.\n\n**High-severity findings** include ..."), so both end a sentence.
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+|\s*\n\s*")
_NUMBER_WORDS = {w: i for i, w in enumerate((
    "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
    "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen",
    "twenty"))} | {"no": 0}
_COUNT_RE = re.compile(r"\b(\d+|" + "|".join(_NUMBER_WORDS) + r")\s+(critical|high|medium|low|informational|info)\b",
                       re.IGNORECASE)


def _sentences(text: str) -> list[str]:
    return [s for s in _SENTENCE_RE.split(text.strip()) if s]


def severity_mismatches(raw: str, sources: dict[str, dict]) -> list[str]:
    """A sentence that names severity levels may only cite findings of those levels.

    Catches e.g. "High findings include ... [S16]" where S16 is a medium finding:
    every citation is a valid id (so the grounding checks pass) but the claim about
    it is wrong. Sentences that name no severity are not constrained.
    """
    out = []
    for sentence in _sentences(raw):
        named = set().union(*[_SEVERITY_WORDS[m.lower()] for m in _SEVERITY_RE.findall(sentence)])
        if not named:
            continue
        for m in CITATION_RE.finditer(sentence):
            for sid in citation_ids(m.group(1)):
                sev = (sources.get(sid) or {}).get("severity", "").lower()
                if sev and sev not in named:
                    out.append(f"{sid} is {sev} but cited in a sentence about {'/'.join(sorted(named))}")
    return out


def severity_number_errors(raw: str, sources: dict[str, dict]) -> list[str]:
    """Counts like "11 high-severity" / "nine medium" must not exceed the real count
    for that severity, and "no high" needs zero high findings. (A smaller number
    may describe a subset, e.g. "four high-severity CORS issues".)"""
    counts: dict[str, int] = {}
    for s in sources.values():
        counts[s["severity"].lower()] = counts.get(s["severity"].lower(), 0) + 1
    out = []
    for m in _COUNT_RE.finditer(CITATION_RE.sub("", raw)):
        word, sev = m.group(1).lower(), m.group(2).lower()
        sev = "info" if sev.startswith("info") else sev
        n = int(word) if word.isdigit() else _NUMBER_WORDS[word]
        real = counts.get(sev, 0)
        if (n == 0 and real) or n > real:
            out.append(f"'{m.group(0)}' but SOURCES have {real} {sev}")
    return out
