from __future__ import annotations

import pytest

from pentest_agent.schemas import OwaspCategory, Severity
from pentest_agent.tools.code_exec import probe_finding_to_finding
from pentest_agent.tools.probe_models import ProbeFinding
from pentest_agent.tools.probe_runner import build_target_url, host_is_allowed


def test_host_allowlist_accepts_host_and_netloc_forms():
    assert host_is_allowed("example.com", {"example.com"})
    assert host_is_allowed("127.0.0.1", {"127.0.0.1:8080"})
    assert host_is_allowed("api.example.com", {"example.com"})
    assert not host_is_allowed("evil.com", {"example.com"})
    assert not host_is_allowed("notexample.com", {"example.com"})


def test_build_target_url_rejects_escape_attempts():
    allowed = {"example.com"}
    assert build_target_url("https://example.com", "/a?b=1", allowed).startswith("https://example.com/a")
    for bad in ("//evil.com/x", "http://evil.com", "/../etc/passwd", "a/b"):
        with pytest.raises(ValueError):
            build_target_url("https://example.com", bad, allowed)
    with pytest.raises(ValueError):
        build_target_url("https://evil.com", "/", allowed)


def test_probe_finding_maps_onto_strict_finding_schema():
    pf = ProbeFinding(title="Missing CSP", description="no csp header", severity="Medium",
                      category="security_headers", url="https://example.com/", confidence=0.85)
    f = probe_finding_to_finding(pf)
    assert f.severity == Severity.MEDIUM
    assert f.category == OwaspCategory.A05_SECURITY_MISCONFIG
    assert f.affected_url == "https://example.com/"
    assert f.confidence == "high" and f.source == "codegen_probe"


def test_informational_severity_maps_to_info():
    pf = ProbeFinding(title="Marker reflected", description="reflected marker", severity="Informational",
                      category="input_reflection", url="https://example.com/?q=x", confidence=0.4)
    f = probe_finding_to_finding(pf)
    assert f.severity == Severity.INFO and f.category == OwaspCategory.XSS and f.confidence == "low"
