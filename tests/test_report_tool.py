
from __future__ import annotations

import datetime as dt
from pathlib import Path

import docx
import pytest

from pentest_agent.schemas import (
    Finding,
    FinalReport,
    OwaspCategory,
    RedFlag,
    ScanProfile,
    Severity,
)
from pentest_agent.tools import report_tool
from pentest_agent.tools.report_tool import (
    _render_markdown,
    render_final_report,
    render_report_docx,
)


def _sample_report() -> FinalReport:
    return FinalReport(
        session_id="s1",
        target_url="https://example.com",
        profile=ScanProfile.STANDARD,
        jwt_provided=True,
        auth_tested=True,
        pages_crawled=5,
        external_links_blocked=[
            "https://third-party.example.net/track"
        ],
        started_at=dt.datetime(
            2026, 1, 1, tzinfo=dt.timezone.utc
        ),
        finished_at=dt.datetime(
            2026, 1, 1, 0, 10, tzinfo=dt.timezone.utc
        ),
        findings=[
            Finding(
                source="zap",
                category=OwaspCategory.XSS,
                severity=Severity.HIGH,
                title="Reflected XSS",
                description="Unsanitized input reflected in response.",
                affected_url="https://example.com/search?q=x",
                cwe="79",
                recommendation="Encode output.",
            ),
            Finding(
                source="recon",
                category=OwaspCategory.A05_SECURITY_MISCONFIG,
                severity=Severity.LOW,
                title="Missing HSTS header",
                description="No Strict-Transport-Security header.",
                affected_url="https://example.com/",
            ),
        ],
        red_flags=[
            RedFlag(
                reason="Login form detected but JWT was not supplied.",
                severity=Severity.HIGH,
            )
        ],
        executive_summary="This is a test executive summary.",
    )


def test_render_markdown_contains_key_sections():
    md = _render_markdown(_sample_report())

    assert "# Security Test Report" in md
    assert "## Executive Summary" in md
    assert "This is a test executive summary." in md

    assert "## 🚩 Red Flags" in md
    assert "Login form detected but JWT was not supplied." in md

    assert "Reflected XSS" in md
    assert "Missing HSTS header" in md
    assert "third-party.example.net/track" in md

    assert "| HIGH | 1 |" in md
    assert "| LOW | 1 |" in md


def test_render_markdown_omits_red_flags_section_when_none():
    report = _sample_report()
    report.red_flags = []

    md = _render_markdown(report)

    assert "Red Flags" not in md


def test_render_markdown_preserves_unicode():
    report = _sample_report()

    md = _render_markdown(report)

    assert "🚩" in md
    assert "Security Test Report" in md

    # Ensure Markdown can be encoded using UTF-8.
    encoded = md.encode("utf-8")

    assert encoded.decode("utf-8") == md


def test_docx_report_is_structured(tmp_path):
    out_path = render_report_docx(_sample_report(), tmp_path / "report.docx")
    document = docx.Document(str(out_path))
    text = "\n".join(p.text for p in document.paragraphs)
    headings = [p.text for p in document.paragraphs if p.style.name.startswith("Heading")]

    assert "Security Test Report" in text
    assert "Executive Summary" in headings and "Detailed Findings" in headings
    assert "Sources" in headings and "Red Flags" in headings
    assert any("F-01" in h and "Reflected XSS" in h for h in headings)  # most severe first
    # real tables (facts, severity strip, overview, per-finding details), not "| a | b |" text
    assert len(document.tables) >= 5 and "|---" not in text
    xml = document.element.xml
    assert 'w:anchor="src_S1"' in xml and 'w:name="src_S1"' in xml  # citation -> bookmark
    rels = [r.target_ref for r in document.part.rels.values() if r.reltype.endswith("/hyperlink")]
    assert "https://example.com/search?q=x" in rels
    assert "https://cwe.mitre.org/data/definitions/79.html" in rels
    footer_xml = document.sections[0].footer._element.xml
    assert "PAGE" in footer_xml and "NUMPAGES" in footer_xml


def test_docx_survives_hostile_content(tmp_path):
    report = _sample_report()
    report.findings[0].evidence = "nul\x00 bell\x07 <script>alert(1)</script>"
    report.findings[0].affected_url = "javascript:alert(1)"
    out_path = render_report_docx(report, tmp_path / "report.docx")
    document = docx.Document(str(out_path))
    rels = [r.target_ref for r in document.part.rels.values() if r.reltype.endswith("/hyperlink")]
    assert not any(r.startswith("javascript:") for r in rels)
    assert "<script>alert(1)</script>" in document.element.xml.replace("&lt;", "<").replace("&gt;", ">")


def test_render_final_report_tool_writes_md_and_docx(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        report_tool.settings,
        "reports_dir",
        str(tmp_path),
    )


    report = _sample_report()

    cmd = render_final_report.invoke(
        {
            "final_report_json": report.model_dump_json()
        }
    )

    assert cmd.update["phase"] == "report_complete"

    md_path = Path(cmd.update["report_md_path"])
    docx_path = Path(cmd.update["report_docx_path"])

    assert md_path.exists()
    assert docx_path.exists()

    assert md_path.stat().st_size > 0
    assert docx_path.stat().st_size > 0

    # Explicit UTF-8 reading avoids Windows CP1252 issues.
    md_content = md_path.read_text(encoding="utf-8")

    assert "Reflected XSS" in md_content
    assert "Executive Summary" in md_content
    assert "🚩" in md_content

    # Verify that the generated DOCX is readable.
    document = docx.Document(str(docx_path))

    full_text = "\n".join(
        paragraph.text for paragraph in document.paragraphs
    )

    assert "Security Test Report" in full_text
    assert "Reflected XSS" in full_text


@pytest.mark.parametrize(
    "severity",
    list(Severity),
)
def test_all_severities_render_without_error(severity):
    report = _sample_report()

    report.findings.append(
        Finding(
            source="x",
            category=OwaspCategory.OTHER,
            severity=severity,
            title=f"{severity.value} case",
            description="Test severity rendering.",
        )
    )

    md = _render_markdown(report)

    assert f"{severity.value.upper()}" in md
