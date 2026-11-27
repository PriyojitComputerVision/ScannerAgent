"""Markdown / JSON / HTML / (optional) DOCX report writer. Stdlib; python-docx optional.

Report prose cites findings as [Sn]; markers are resolved against the source
dictionary from scopeguard.citations. The HTML view escapes every value that
came from the target or a model, so a served report cannot run injected markup.
"""
from __future__ import annotations

import datetime as dt
import html
import json
import re
from pathlib import Path

from scopeguard import citations

ORDER = ["critical", "high", "medium", "low", "info"]

# Files are stored as report.<ext>; downloads are offered as <session-id>.<ext>.
DOWNLOADABLE = ("report.md", "report.json", "report.docx")
_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def download_name(report_name: str, filename: str) -> str:
    """'abc-123', 'report.docx' -> 'abc-123.docx' (safe for Content-Disposition)."""
    base = _UNSAFE_NAME.sub("_", report_name).strip("._") or "report"
    return f"{base[:120]}{Path(filename).suffix}"

_CSS = """
:root{--bg:#fff;--fg:#1d2330;--mut:#5b6475;--line:#e3e6ec;--card:#f7f8fa;--link:#1f5fbf;
--critical:#8e1b1b;--high:#c0392b;--medium:#b8660b;--low:#2f6f9f;--info:#5b6475}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--fg:#e6e9ef;--mut:#9aa3b2;--line:#2b313b;
--card:#1b1f26;--link:#7fb0ff;--critical:#ff8a8a;--high:#ff7a6b;--medium:#f0b25a;--low:#7fb6e0;--info:#9aa3b2}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:.2em 0 .6em;overflow-wrap:anywhere}h2{margin-top:2em;border-bottom:1px solid var(--line);padding-bottom:.3em}
a{color:var(--link)}a.cite{font-weight:600;text-decoration:none}
.meta{color:var(--mut);margin:0;padding-left:1.1em}
table{border-collapse:collapse;margin:.6em 0}td,th{border:1px solid var(--line);padding:4px 12px;text-align:left}
.finding{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
.finding h3{margin:0 0 .4em;font-size:1.02rem;overflow-wrap:anywhere}
.sev{display:inline-block;min-width:4.6em;font-size:.75rem;font-weight:700;text-transform:uppercase;color:var(--sev)}
.critical{--sev:var(--critical)}.high{--sev:var(--high)}.medium{--sev:var(--medium)}.low{--sev:var(--low)}.info{--sev:var(--info)}
.small{color:var(--mut);font-size:.88rem;overflow-wrap:anywhere}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere}
ol.sources li{margin:4px 0;overflow-wrap:anywhere}:target{outline:2px solid var(--link);outline-offset:2px}
"""


def _e(x) -> str:
    return html.escape("" if x is None else str(x))


def html_page(title: str, body: str) -> str:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{_e(title)}</title><style>{_CSS}</style></head><body><main>{body}</main></body></html>")


def _link(url: str | None, text: str | None = None) -> str:
    u = citations.safe_url(url)
    if not u:
        return _e(text or url or "n/a")
    return f'<a href="{_e(u)}" rel="noopener noreferrer nofollow" target="_blank">{_e(text or u)}</a>'


def _val(x, key):
    v = x.get(key) if isinstance(x, dict) else getattr(x, key, None)
    return getattr(v, "value", v)


# --------------------------------------------------------------------------- code locations
_LOC_LINE = re.compile(r"#L(\d+)$")
MAX_LISTED_LOCATION_FILES = 60


def location_groups(rec: dict) -> list[tuple[str, list[int]]]:
    """A recommendation's locations grouped per file: [(file, [line, ...])], file order kept.
    Falls back to the single ``example`` for recommendations built before ``locations`` existed."""
    locs = rec.get("locations")
    if locs is None and rec.get("example"):
        text = str(rec["example"])
        m = _LOC_LINE.search(text)
        locs = [{"file": text[:m.start()] if m else text, "line": int(m.group(1)) if m else None}]
    groups: dict[str, list[int]] = {}
    for loc in locs or []:
        lines = groups.setdefault(str(loc.get("file") or "?"), [])
        if isinstance(loc.get("line"), int) and loc["line"] not in lines:
            lines.append(loc["line"])
    return [(f, sorted(lines)) for f, lines in groups.items()]


def where_heading(rec: dict) -> str:
    """'Where (12 in 5 files)' for a recommendation."""
    groups = location_groups(rec)
    total = rec.get("locations_total") or sum(max(1, len(lines)) for _, lines in groups)
    return f"Where ({total} location{'s' if total != 1 else ''} in {len(groups)} file{'s' if len(groups) != 1 else ''})"


def location_lines(rec: dict, max_files: int = MAX_LISTED_LOCATION_FILES) -> list[tuple[str, str]]:
    """[(file, 'line 12' / 'lines 12, 40')] for display, plus a final ('', '+N more ...') row when cut."""
    groups = location_groups(rec)
    rows = [(f, ("line " if len(lines) == 1 else "lines ") + ", ".join(map(str, lines)) if lines else "")
            for f, lines in groups[:max_files]]
    listed = sum(max(1, len(lines)) for _, lines in groups[:max_files])
    more = (rec.get("locations_total") or listed) - listed
    if more > 0:
        rows.append(("", f"+{more} more location(s): full list in report.json (code_upload.recommendations)"))
    return rows


def distinct_steps(rem: dict, summary: str | None = None) -> list[str]:
    """Remediation steps without the one that only repeats the summary (rules without a full
    playbook carry their one-line advice as both summary and step 1)."""
    said = " ".join(str(summary if summary is not None else rem.get("summary") or "").split())
    return [str(s) for s in rem.get("steps") or [] if " ".join(str(s).split()) != said]


def location_markdown(rec: dict) -> list[str]:
    return [f"- `{f}`: {lines}" if f else f"- {lines}" for f, lines in location_lines(rec)]


def render_html(*, title: str, meta: list[tuple[str, str]], summary: str | None, findings: list,
                sources: dict[str, dict], red_flags: list[str], blocked: list[str],
                downloads: list[tuple[str, str]] | None = None, download_base: str | None = None,
                recommendations: list[dict] | None = None, guardrails: dict | None = None) -> str:
    """Self-contained HTML report. `findings` may be dicts or pydantic Findings."""
    counts = {s: sum(1 for f in findings if str(_val(f, "severity")).lower() == s) for s in ORDER}
    b = [f"<h1>{_e(title)}</h1>", '<ul class="meta">']
    b += [f"<li><b>{_e(k)}:</b> {_e(v)}</li>" for k, v in meta]
    b.append("</ul>")
    if downloads:
        b.append('<p class="small">Download: ' + " · ".join(
            f'<a href="{_e(href)}"'
            + (f' download="{_e(download_name(download_base, href))}"' if download_base else "")
            + f">{_e(label)}</a>" for label, href in downloads) + "</p>")
    if summary:
        b += ["<h2>Summary</h2>", f"<p>{citations.to_html(summary, sources)}</p>"]
    b += ["<h2>Findings by severity</h2>", "<table><tr><th>Severity</th><th>Count</th></tr>"]
    b += [f'<tr><td><span class="sev {s}">{s}</span></td><td>{counts[s]}</td></tr>' for s in ORDER]
    b.append("</table>")
    if red_flags:
        b += ["<h2>Red flags</h2>", "<ul>"] + [f"<li>{_e(r)}</li>" for r in red_flags] + ["</ul>"]
    if recommendations:
        b += ["<h2>Recommendations</h2>",
              "<table><tr><th>Severity</th><th>Issue</th><th>Count</th><th>What to do</th></tr>"]
        b += [f'<tr><td><span class="sev {_e(r.get("severity"))}">{_e(r.get("severity"))}</span></td>'
              f'<td>{_e(r.get("rule"))}<div class="small">{_e(r.get("cwe") or "")}</div>'
              f'<div class="small"><b>{_e(where_heading(r))}:</b></div><ul class="small">'
              + "".join(f"<li><code>{_e(f)}</code>{': ' if f and lines else ''}{_e(lines)}</li>"
                        for f, lines in location_lines(r))
              + f'</ul></td><td>{_e(r.get("count"))}</td><td>{_e(r.get("recommendation"))}</td></tr>'
              for r in recommendations]
        b.append("</table>")
        b += _remediation_html(recommendations)
    if guardrails:
        b += ["<h2>Guardrails</h2>", "<table><tr><th>Stage</th><th>Check</th><th>Result</th><th>Detail</th></tr>"]
        for stage in ("pre", "post"):
            for c in guardrails.get(stage) or []:
                ok = "passed" if c.get("passed") else "FAILED"
                b.append(f"<tr><td>{_e(stage)}</td><td>{_e(c.get('name'))}</td><td>{_e(ok)}</td>"
                         f"<td>{_e(c.get('detail'))}</td></tr>")
        b.append("</table>")
    b.append("<h2>Detailed findings</h2>")
    ranked = sorted(findings, key=lambda f: ORDER.index(str(_val(f, "severity")).lower())
                    if str(_val(f, "severity")).lower() in ORDER else 9)
    for f in ranked:
        sev = str(_val(f, "severity")).lower()
        sid = citations.source_for_finding(sources, f)
        ref = f' <a class="cite" href="#src-{sid}">[{sid}]</a>' if sid else ""
        cwe = _val(f, "cwe")
        cwe_html = (_link(citations.cwe_url(cwe), f"CWE-{citations.cwe_id(cwe)}")
                    if citations.cwe_id(cwe) else _e(cwe or "n/a"))
        b += ['<div class="finding">',
              f'<h3><span class="sev {_e(sev)}">{_e(sev)}</span> {_e(_val(f, "title"))}{ref}</h3>',
              (f'<div class="small">Category: {_e(_val(f, "category"))} · CWE: {cwe_html} · '
              f'Confidence: {_e(_val(f, "confidence"))} · Source: {_e(_val(f, "source"))}</div>'),
              (f'<div class="small">URL: {_link(_val(f, "affected_url"))}</div>'
               if str(_val(f, "affected_url") or "").startswith(("http://", "https://"))
               else f'<div class="small">File and line: <code>{_e(_val(f, "affected_url"))}</code></div>'),
              f"<p>{_e(_val(f, 'description'))}</p>"]
        if _val(f, "evidence"):
            b.append(f"<pre>{_e(_val(f, 'evidence'))}</pre>")
        if _val(f, "recommendation"):
            b.append(f"<p><b>Fix:</b> {_e(_val(f, 'recommendation'))}</p>")
        b.append("</div>")
    if sources:
        b += ["<h2>Sources</h2>", '<ol class="sources">']
        for sid, s in sources.items():
            parts = [f'<b>[{sid}]</b> <span class="sev {_e(s["severity"])}">{_e(s["severity"])}</span> {_e(s["title"])}']
            if s["url"]:
                parts.append(_link(s["url"]))
            if s["cwe_url"]:
                parts.append(_link(s["cwe_url"], s["cwe"]))
            b.append(f'<li id="src-{sid}" value="{sid[1:]}">' + " · ".join(parts) + "</li>")
        b.append("</ol>")
    if blocked:
        b += ["<h2>Out-of-scope links (never fetched)</h2>", "<ul>"]
        b += [f"<li>{_e(u)}</li>" for u in blocked[:200]] + ["</ul>"]
    b.append('<p class="small">Generated automatically. Findings can include false positives; '
             "triage before remediation or disclosure.</p>")
    return html_page(title, "".join(b))


def _remediation_html(recommendations: list[dict]) -> list[str]:
    """Per-rule remediation: summary, steps, a before/after fix, OWASP references (all escaped)."""
    b = ["<h2>Remediation</h2>"]
    for r in recommendations:
        rem = r.get("remediation") or {}
        if not rem.get("steps") and not rem.get("example"):
            continue
        group = f' <span class="small">({_e(rem["group"])})</span>' if rem.get("group") else ""
        b += ['<div class="finding">',
              (f'<h3><span class="sev {_e(r.get("severity"))}">{_e(r.get("severity"))}</span> '
              f'{_e(r.get("rule"))}{group}</h3>'), f"<p>{_e(rem.get('summary'))}</p>"]
        steps = distinct_steps(rem)
        if steps:
            b += ["<ol>"] + [f"<li>{_e(step)}</li>" for step in steps] + ["</ol>"]
        ex = rem.get("example")
        if ex:
            b += [f'<p class="small">Vulnerable ({_e(ex.get("language"))}):</p><pre>{_e(ex.get("before"))}</pre>',
                  f'<p class="small">Fixed:</p><pre>{_e(ex.get("after"))}</pre>']
        refs = [u for u in rem.get("references") or [] if str(u).startswith("https://")]
        if refs:
            b.append('<p class="small">References: ' + " · ".join(_link(u) for u in refs) + "</p>")
        b.append("</div>")
    return b if len(b) > 1 else []


def remediation_markdown(recommendations: list[dict]) -> list[str]:
    L = []
    for r in recommendations:
        rem = r.get("remediation") or {}
        if not rem.get("steps") and not rem.get("example"):
            continue
        group = f" ({rem['group']})" if rem.get("group") else ""
        L += [f"### [{str(r.get('severity', '')).upper()}] {r.get('rule')}{group}", "", str(rem.get("summary") or ""), ""]
        L += [f"{i}. {step}" for i, step in enumerate(distinct_steps(rem), 1)] + [""]
        ex = rem.get("example")
        if ex:
            lang = {"js": "js", "py": "python", "php": "php"}.get(ex.get("language"), "")
            L += [f"Vulnerable ({ex.get('language')}):", "", f"```{lang}", str(ex.get("before")), "```", "",
                  "Fixed:", "", f"```{lang}", str(ex.get("after")), "```", ""]
        refs = [u for u in rem.get("references") or [] if str(u).startswith("https://")]
        if refs:
            L += ["References: " + ", ".join(refs), ""]
    return (["", "## Remediation", ""] + L) if L else []


def render_markdown(target: str, result: dict, mode: str, sources: dict[str, dict] | None = None) -> str:
    f = result["findings"]
    sources = sources if sources is not None else citations.build_sources(f)
    counts = {s: sum(1 for x in f if x["severity"] == s) for s in ORDER}
    summary = citations.deterministic_summary(target, sources, len(result["crawled_pages"]),
                                              len(result["red_flags"]))
    L = [f"# Security Scan Report: {target}", "",
         f"- **Generated:** {dt.datetime.now(dt.UTC).isoformat(timespec='seconds')}",
         f"- **Mode:** {mode}  |  **Profile:** {result['profile']}",
         (f"- **Pages crawled:** {len(result['crawled_pages'])}  |  **Requests:** {result['requests_made']}"
         f"  |  **Duration:** {result['duration_seconds']}s"),
         f"- **Out-of-scope links blocked (never fetched):** {len(result['external_links_blocked'])}",
         "", "## Summary", "", citations.to_markdown(summary, sources),
         "", "## Findings by severity", "", "| Severity | Count |", "|---|---|"]
    L += [f"| {s.upper()} | {counts[s]} |" for s in ORDER]
    cov = citations.attack_coverage_markdown(result.get("attack_summary"))
    if cov:
        L += ["", *cov]
    if result.get("endpoints"):
        L += ["## Backend/API endpoints referenced", ""] + [f"- {e}" for e in result["endpoints"][:50]] + [""]
    if result["red_flags"]:
        L += ["", "## Red flags", ""] + [f"- {x}" for x in result["red_flags"]]
    L += ["", "## Detailed findings", ""]
    for x in f:
        sid = citations.source_for_finding(sources, x)
        ref = f" [{sid}](#src-{sid})" if sid else ""
        L += [f"### [{x['severity'].upper()}] {x['title']}{ref}", "",
              (f"- **Category:** {x['category']}  |  **CWE:** {x.get('cwe') or 'n/a'}  |  "
              f"**Confidence:** {x['confidence']}  |  **Source:** {x['source']}"),
              f"- **URL:** {x.get('affected_url') or 'n/a'}", "", x["description"], ""]
        if x.get("evidence"):
            L += ["```", x["evidence"], "```", ""]
        if x.get("recommendation"):
            L += [f"**Fix:** {x['recommendation']}", ""]
    if sources:
        L += ["## Sources", ""] + citations.sources_markdown(sources) + [""]
    return "\n".join(L)


def write_reports(out_dir: str, target: str, result: dict, mode: str) -> dict:
    d = Path(out_dir)
    d.mkdir(parents=True, exist_ok=True)
    sources = citations.build_sources(result["findings"])
    md = render_markdown(target, result, mode, sources)
    paths = {"md": d / "report.md", "json": d / "report.json", "html": d / "report.html"}
    paths["md"].write_text(md, encoding="utf-8")
    paths["json"].write_text(json.dumps({**result, "sources": sources}, indent=2), encoding="utf-8")
    meta = [("Generated", dt.datetime.now(dt.UTC).isoformat(timespec="seconds")),
            ("Mode / profile", f"{mode} / {result['profile']}"),
            ("Pages crawled", str(len(result["crawled_pages"]))),
            ("Requests", str(result["requests_made"])),
            ("Duration", f"{result['duration_seconds']}s"),
            ("Out-of-scope links blocked", str(len(result["external_links_blocked"])))]
    summary = citations.deterministic_summary(target, sources, len(result["crawled_pages"]),
                                              len(result["red_flags"]))
    paths["html"].write_text(render_html(
        title=f"Security Scan Report: {target}",
        meta=meta,
        summary=summary,
        findings=result["findings"], sources=sources, red_flags=result["red_flags"],
        blocked=result["external_links_blocked"],
        downloads=[("Markdown", "report.md"), ("JSON", "report.json"), ("DOCX", "report.docx")],
        download_base=d.name),
        encoding="utf-8")
    try:
        from scopeguard.docx_report import build_docx
        build_docx(d / "report.docx", title="Security Scan Report", target=target, meta=meta,
                   summary=summary, findings=result["findings"], sources=sources,
                   red_flags=result["red_flags"], blocked=result["external_links_blocked"],
                   summary_heading="Summary")
        paths["docx"] = d / "report.docx"
    except ImportError:  # python-docx is optional for the stdlib CLI
        pass
    return {k: str(v) for k, v in paths.items()}


def render_index(reports_dir: str | Path) -> str:
    """HTML list of every report folder under `reports_dir` (newest first)."""
    root = Path(reports_dir)
    rows = []
    dirs = [p for p in root.iterdir() if p.is_dir()] if root.is_dir() else []
    for p in sorted(dirs, key=lambda x: x.stat().st_mtime, reverse=True):
        files = [n for n in ("report.html", "report.md", "report.json", "report.docx") if (p / n).exists()]
        if not files:
            continue
        main = files[0]
        when = dt.datetime.fromtimestamp(p.stat().st_mtime).isoformat(sep=" ", timespec="seconds")
        others = " · ".join(f'<a href="{_e(p.name)}/{n}" download="{_e(download_name(p.name, n))}">'
                            f'{n.split(".")[1]}</a>' for n in files[1:])
        rows.append(f'<li><a href="{_e(p.name)}/{main}"><b>{_e(p.name)}</b></a> '
                    f'<span class="small">{when} {("· " + others) if others else ""}</span></li>')
    body = "<h1>Scan reports</h1>" + (f"<ul>{''.join(rows)}</ul>" if rows else "<p>No reports yet.</p>")
    return html_page("Scan reports", body)


