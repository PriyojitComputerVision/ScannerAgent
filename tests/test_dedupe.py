"""Findings from recon, DAST and probes that describe the same issue are merged."""
from __future__ import annotations

from pentest_agent.dedupe import dedupe_findings, issue_key, url_key
from pentest_agent.schemas import Finding

URL = "https://app.example.test/"


def _f(title, source, severity="medium", cwe=None, url=URL, confidence="medium"):
    return Finding(source=source, category="A05:2021-Security Misconfiguration", severity=severity,
                   title=title, description=f"{source} says {title}", affected_url=url, cwe=cwe,
                   confidence=confidence)


def test_same_missing_header_from_three_checks_becomes_one_finding():
    # The exact titles a real scan produced (recon, dast_native, codegen_probe).
    findings = [
        _f("Missing Content-Security-Policy header", "recon"),
        _f("Missing Strict-Transport-Security (HSTS) header", "recon"),
        _f("Missing Referrer-Policy header", "recon", severity="info"),
        _f("Missing Content-Security-Policy header", "dast_native", cwe="CWE-693", confidence="high"),
        _f("Missing Strict-Transport-Security (HSTS) header", "dast_native", cwe="CWE-693"),
        _f("Missing clickjacking protection (X-Frame-Options/frame-ancestors)", "dast_native", "low", "CWE-693"),
        _f("Missing Referrer-Policy header", "dast_native", severity="info", cwe="CWE-693"),
        _f("Missing HTTP Strict Transport Security", "codegen_probe"),
        _f("Missing Content Security Policy", "codegen_probe"),
        _f("Missing Referrer-Policy", "codegen_probe", severity="low"),
        _f("Missing clickjacking protection header", "codegen_probe", severity="low"),
        _f("Missing X-Frame-Options header (clickjacking risk)", "recon", severity="low"),
    ]
    out = dedupe_findings(findings)
    assert len(out) == 4
    by_key = {issue_key(f.title): f for f in out}
    csp = by_key["missing-header:content-security-policy"]
    assert csp.source == "dast_native" and csp.cwe == "CWE-693" and csp.confidence == "high"
    assert "Also reported by: codegen_probe, recon." in csp.description
    # the highest severity of the group wins (probe rated Referrer-Policy low, DAST info)
    assert by_key["missing-header:referrer-policy"].severity.value == "low"
    assert by_key["missing-header:referrer-policy"].source == "dast_native"


def test_different_urls_and_different_issues_stay_separate():
    findings = [
        _f("Missing Content-Security-Policy header", "dast_native", url=URL),
        _f("Missing Content-Security-Policy header", "dast_native", url=URL + "login"),
        _f("Reflected input without output encoding (possible XSS)", "dast_native", url=URL + "search?q=1"),
        _f("Reflected input without output encoding (possible XSS)", "dast_native", url=URL + "search?q=2"),
        _f("Content-Security-Policy allows unsafe-inline", "dast_native"),  # not a missing header
    ]
    assert len(dedupe_findings(findings)) == 5


def test_url_key_ignores_trailing_slash_case_and_fragment():
    assert url_key("HTTPS://App.Example.test") == url_key("https://app.example.test/#top")
    assert url_key("https://a.test/x?q=1") != url_key("https://a.test/x?q=2")


def test_code_findings_on_different_lines_stay_separate():
    """A '#L<n>' anchor is part of a code location: the same rule on two lines is two findings."""
    assert url_key("app/views.py#L12") != url_key("app/views.py#L40")
    assert url_key("app/views.py#L12") == url_key("app/views.py#L12")
    assert url_key("https://a.test/x#L5") != url_key("https://a.test/x#L6")
    assert url_key("https://a.test/x#Lazy") == url_key("https://a.test/x")  # not a line anchor
    two = [_f("PY_EVAL_EXEC: eval()/exec() runs dynamic code.", "sandbox_source", url="app/a.py#L3"),
           _f("PY_EVAL_EXEC: eval()/exec() runs dynamic code.", "sandbox_source", url="app/a.py#L9")]
    assert len(dedupe_findings(two)) == 2


def test_single_findings_are_unchanged():
    f = _f("Open redirect", "dast_native", cwe="CWE-601")
    assert dedupe_findings([f]) == [f]
