"""Source citations ([Sn]) — grounding of LLM prose and safe link rendering."""
from __future__ import annotations

import datetime as dt
import json
import re
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from pentest_agent import graph
from pentest_agent.schemas import (
    FinalReport,
    Finding,
    OwaspCategory,
    ScanProfile,
    Severity,
)
from pentest_agent.tools import report_tool
from scopeguard import citations
from scopeguard.report import render_html, write_reports

FINDINGS = [
    {"id": "low1", "title": "Missing HSTS", "severity": "low", "affected_url": "https://example.com/",
     "cwe": None},
    {"id": "hi1", "title": "Reflected XSS", "severity": "high",
     "affected_url": "https://example.com/search?q=x", "cwe": "79"},
    {"id": "bad", "title": "Weird URL", "severity": "medium", "affected_url": "javascript:alert(1)",
     "cwe": "CWE-200"},
]


@pytest.fixture
def sources():
    return citations.build_sources(FINDINGS)


def test_sources_ordered_by_severity_with_validated_links(sources):
    assert list(sources) == ["S1", "S2", "S3"]
    assert sources["S1"]["title"] == "Reflected XSS"
    assert sources["S1"]["cwe"] == "CWE-79"
    assert sources["S1"]["cwe_url"] == "https://cwe.mitre.org/data/definitions/79.html"
    assert sources["S2"]["url"] is None  # javascript: URL rejected
    assert sources["S2"]["cwe_url"] == "https://cwe.mitre.org/data/definitions/200.html"
    assert sources["S3"]["cwe_url"] is None


def test_target_url_with_non_breaking_hyphens_is_kept(sources):
    # gpt-oss writes U+2011 hyphens, also inside host names
    text = "The scan of https://syslab‑blond.vercel.app/ found XSS [S1]."
    clean, _, _ = citations.sanitize(text, sources, ("https://syslab-blond.vercel.app/",))
    assert clean == "The scan of https://syslab-blond.vercel.app/ found XSS [S1]."
    clean, _, _ = citations.sanitize("See https://evil‑site.test/ [S1].", sources, ())
    assert "evil" not in clean


def test_prompt_block_groups_sources_under_severity_headings(sources):
    more = citations.build_sources(FINDINGS + [{"title": "Server banner", "severity": "info"},
                                               {"title": "Missing CSP", "severity": "low"}])
    block = citations.sources_prompt_block(more)
    assert block.splitlines() == [
        "HIGH severity (1 finding; cite these only as high):",
        "[S1] HIGH: Reflected XSS (CWE-79, https://example.com/search?q=x)",
        "",
        "MEDIUM severity (1 finding; cite these only as medium):",
        "[S2] MEDIUM: Weird URL (CWE-200)",
        "",
        "LOW severity (2 findings; cite these only as low):",
        "[S3] LOW: Missing HSTS (https://example.com/)",
        "[S4] LOW: Missing CSP",
        "",
        "INFORMATIONAL severity (1 finding; cite these only as informational):",
        "[S5] INFO: Server banner",
    ]
    # the cut-off note still follows a limited list; empty input keeps its message
    assert citations.sources_prompt_block(more, limit=2).endswith("3 more lower-severity sources not shown")
    assert citations.sources_prompt_block({}).startswith("(no sources")


@pytest.mark.parametrize("url,ok", [
    ("https://example.com/a?b=1", True), ("http://127.0.0.1:3000/", True),
    ("javascript:alert(1)", False), ("https://user:pw@example.com/", False),
    ("https://exa mple.com/", False), ("//example.com", False), ("", False), (None, False),
])
def test_safe_url(url, ok):
    assert (citations.safe_url(url) is not None) is ok


def test_sanitize_removes_hallucinated_ids_and_urls(sources):
    text = ("XSS was found [S1]. A critical RCE exists [S9]. See [S1, S7, s3] and "
            "https://evil.example/x for details, or https://example.com/search?q=x.")
    clean, used, invalid = citations.sanitize(text, sources)
    assert "[S9]" not in clean and "S7" not in clean
    assert "[S1, S3]" in clean
    assert "evil.example" not in clean
    assert "https://example.com/search?q=x" in clean  # known source URL kept
    assert used == ["S1", "S3"] and invalid == ["S9", "S7"]


def test_to_markdown_and_html_replace_markers_from_dictionary(sources):
    md = citations.to_markdown("XSS [S1] and [S1, S2] and bogus [S8].", sources)
    assert md == "XSS [[S1](#src-S1)] and [[S1](#src-S1), [S2](#src-S2)] and bogus ."
    direct = citations.to_markdown("[S1]", sources, anchor_prefix=None)
    assert direct == "[[S1](https://example.com/search?q=x)]"
    h = citations.to_html("<b>x</b> [S2]", sources)
    assert "&lt;b&gt;" in h and '<a class="cite" href="#src-S2">S2</a>' in h
    assert citations.strip_markers(md).startswith("XSS [S1] and [S1, S2]")


def test_deterministic_summary_only_cites_known_sources(sources):
    text = citations.deterministic_summary("https://example.com", sources, pages=4, red_flags=1)
    ids = re.findall(r"S\d+", text)
    assert ids and set(ids) <= set(sources)
    assert "1 high, 1 medium, 1 low" in text


# ---------------------------------------------------------------- agent graph
def _aggregate_state():
    return {
        "session_id": "cite-1",
        "target": {"url": "https://example.com", "authorization_confirmed": True, "session_id": "cite-1"},
        "profile": "standard",
        "crawled_pages": ["https://example.com/"],
        "started_at": dt.datetime(2026, 1, 1, tzinfo=dt.UTC).isoformat(),
        "findings": [
            Finding(source="t", category=OwaspCategory.XSS, severity=Severity.HIGH, title="Reflected XSS",
                    description="d", affected_url="https://example.com/s", cwe="79").model_dump(mode="json"),
        ],
    }


def _run_aggregate(monkeypatch, llm_text):
    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "get_llm", lambda **_: None)
    monkeypatch.setattr(graph, "invoke_with_backoff", lambda *_a, **_k: SimpleNamespace(content=llm_text))
    state = _aggregate_state()
    aggregated = graph.aggregate_node(state)              # deterministic, no LLM
    assert aggregated.goto == "summarize"
    cmd = graph.summarize_node({**state, **aggregated.update})  # LLM summary step
    assert cmd.goto == "report"
    return FinalReport.model_validate_json(cmd.update["_final_report_json"])


def test_aggregate_keeps_valid_citations_and_strips_hallucinations(monkeypatch):
    rep = _run_aggregate(monkeypatch, "One high XSS issue [S1]. Also SQLi [S4] at https://made.up/x.")
    assert "[S1]" in rep.executive_summary
    assert "S4" not in rep.executive_summary and "made.up" not in rep.executive_summary
    assert rep.sources["S1"]["url"] == "https://example.com/s"


def test_aggregate_replaces_uncited_llm_answer_with_grounded_summary(monkeypatch):
    rep = _run_aggregate(monkeypatch, "Everything is critical and the server is hacked.")
    assert "hacked" not in rep.executive_summary
    assert "Reflected XSS [S1]" in rep.executive_summary


def test_aggregate_offline_summary_is_cited(monkeypatch):
    monkeypatch.setattr(graph, "llm_available", lambda: False)
    rep = FinalReport.model_validate_json(graph.aggregate_node(_aggregate_state()).update["_final_report_json"])
    assert "[S1]" in rep.executive_summary


# ---------------------------------------------------------------- rendering
def _report(summary="XSS found [S1].", evidence="<script>alert(1)</script>"):
    f = Finding(source="t", category=OwaspCategory.XSS, severity=Severity.HIGH, title="Reflected <XSS>",
                description="<img src=x onerror=alert(1)>", affected_url="https://example.com/s?q=1",
                evidence=evidence, cwe="79")
    return FinalReport(session_id="r1", target_url="https://example.com", profile=ScanProfile.STANDARD,
                       jwt_provided=False, auth_tested=False, pages_crawled=1,
                       started_at=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
                       finished_at=dt.datetime(2026, 1, 1, 0, 5, tzinfo=dt.UTC),
                       findings=[f], executive_summary=summary,
                       sources=citations.build_sources([f]))


def test_markdown_report_links_citations_and_lists_sources():
    md = report_tool._render_markdown(_report())
    assert "XSS found [[S1](#src-S1)]." in md
    assert "## Sources" in md and '<a id="src-S1"></a>**[S1]**' in md
    assert "(https://cwe.mitre.org/data/definitions/79.html)" in md


def test_html_report_escapes_target_content_and_links_sources():
    page = report_tool.render_report_html(_report())
    assert "<script>alert(1)" not in page and "<img src=x" not in page
    assert "&lt;script&gt;" in page
    assert 'href="#src-S1"' in page and 'id="src-S1"' in page
    assert 'href="https://cwe.mitre.org/data/definitions/79.html"' in page


def test_render_final_report_writes_html(tmp_path, monkeypatch):
    monkeypatch.setattr(report_tool.settings, "reports_dir", str(tmp_path))
    cmd = report_tool.render_final_report.invoke({"final_report_json": _report().model_dump_json()})
    assert (tmp_path / "r1" / "report.html").exists()
    assert cmd.update["report_html_path"].endswith("report.html")


def test_cli_reports_include_sources_and_html(tmp_path):
    result = {"findings": [dict(f, category="A05", confidence="medium", source="t", description="d")
                           for f in FINDINGS],
              "crawled_pages": ["https://example.com/"], "requests_made": 3, "duration_seconds": 1.0,
              "external_links_blocked": [], "red_flags": [], "profile": "standard"}
    paths = write_reports(str(tmp_path / "r"), "https://example.com", result, "live")
    md = (tmp_path / "r" / "report.md").read_text(encoding="utf-8")
    assert "## Sources" in md and "Reflected XSS [S1]" in md
    page = (tmp_path / "r" / "report.html").read_text(encoding="utf-8")
    assert 'id="src-S1"' in page and "javascript:alert" not in page.split("<h2>Sources</h2>")[1].split("href")[0]
    assert "href=\"javascript:" not in page
    assert json.loads((tmp_path / "r" / "report.json").read_text(encoding="utf-8"))["sources"]["S1"]
    assert "html" in paths


def test_render_html_never_emits_unsafe_href():
    page = render_html(title="t", meta=[], summary=None, sources={}, red_flags=[], blocked=[],
                       findings=[{"title": "x", "severity": "low", "affected_url": "javascript:alert(1)",
                                  "category": "c", "confidence": "low", "source": "s", "description": "d"}])
    assert 'href="javascript:' not in page


# ---------------------------------------------------------------- report viewer
def test_report_viewer_routes(tmp_path, monkeypatch):
    from pentest_agent import config
    from pentest_agent.websocket_server import app

    monkeypatch.setattr(config.settings, "reports_dir", str(tmp_path))
    (tmp_path / "sess1").mkdir()
    (tmp_path / "sess1" / "report.html").write_text("<p>hello</p>", encoding="utf-8")
    (tmp_path / "sess1" / "report.md").write_text("# md", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("nope", encoding="utf-8")

    c = TestClient(app)
    idx = c.get("/reports/")
    assert idx.status_code == 200 and 'href="sess1/report.html"' in idx.text
    view = c.get("/reports/sess1/")
    assert view.status_code == 200 and "hello" in view.text
    assert "default-src 'none'" in view.headers["content-security-policy"]
    assert c.get("/reports/sess1/report.md").text == "# md"
    for bad in ("/reports/sess1/secret.txt", "/reports/../secret.txt", "/reports/..%2Fsecret.txt/report.md",
                "/reports/sess1/..%2F..%2Fsecret.txt", "/reports/nope/"):
        assert c.get(bad).status_code == 404, bad


# ---------------------------------------------------------------- CLI
def test_cli_refuses_unreachable_target_quickly(capsys):
    import socket

    from scopeguard import cli

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens on this port now
    rc = cli.main(["--url", f"http://127.0.0.1:{port}", "--i-have-authorization"])
    assert rc == 4
    assert "Target not reachable" in capsys.readouterr().out


def test_cli_index_lists_reports(tmp_path):
    from scopeguard.report import render_index

    (tmp_path / "live-1").mkdir()
    (tmp_path / "live-1" / "report.html").write_text("x", encoding="utf-8")
    (tmp_path / "empty").mkdir()
    page = render_index(tmp_path)
    assert 'href="live-1/report.html"' in page and "empty" not in page


def test_citation_ranges_are_expanded():
    """LLMs write ranges such as [S2‑S5] (U+2011 hyphen); they must count as citations,
    otherwise a well-cited answer is thrown away as 'no valid source citations'."""
    srcs = {f"S{i}": {"id": f"S{i}", "url": None, "cwe_url": None} for i in range(1, 8)}
    text, used, invalid = citations.sanitize(
        "A [S1, S2\u2011S4]. B [S5\u2013S6]. C [S7-9]. D [S1-S5000].", srcs)
    assert text == "A [S1, S2, S3, S4]. B [S5, S6]. C [S7]. D [S1]."
    assert used == [f"S{i}" for i in range(1, 8)] and invalid == ["S8", "S9", "S5000"]
    assert citations.citation_ids("S3-S1") == ["S3", "S1"]  # reversed: endpoints only


def test_parenthesised_citations_are_accepted():
    """gpt-oss sometimes cites as (S1) instead of [S1]; only id-only parentheses count."""
    srcs = {f"S{i}": {"id": f"S{i}", "url": None, "cwe_url": None} for i in range(1, 4)}
    text, used, invalid = citations.sanitize(
        "XSS on search (S1). Header missing (S2, S3). Bad (S9). Prose (see S1 above) stays.", srcs)
    assert text == "XSS on search [S1]. Header missing [S2, S3]. Bad. Prose (see S1 above) stays."
    assert used == ["S1", "S2", "S3"] and invalid == ["S9"]
