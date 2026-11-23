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
CITATION_RE = re.compile(rf"\[\s*({_ITEM}(?:\s*[,;]\s*{_ITEM})*)\s*\]")
# LLMs sometimes cite as (S1) / (S1, S3-S5). Only parentheses that hold nothing
# but source ids are treated as citations; ordinary parenthesised text is untouched.
_PAREN_CITATION_RE = re.compile(rf"\(\s*({_ITEM}(?:\s*[,;]\s*{_ITEM})*)\s*\)")
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
    """Plain-text source list to put in an LLM prompt."""
    lines = []
    for sid, s in list(sources.items())[:limit]:
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
    out = _URL_RE.sub(lambda m: m.group(0) if normalize_url(m.group(0)) in known_urls else "", out)
    out = re.sub(r"[ \t]+([.,;:])", r"\1", out)  # tidy spaces left by removals
    out = re.sub(r"[ \t]{2,}", " ", out).strip()
    return out, used, invalid


def find_urls(text: str) -> list[str]:
    """URLs in free text, without trailing sentence punctuation."""
    return [normalize_url(u) for u in _URL_RE.findall(text or "")]


def normalize_url(url: str) -> str:
    return url.rstrip(".,;:!?")


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
