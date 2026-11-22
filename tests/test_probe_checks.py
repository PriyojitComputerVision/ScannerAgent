"""Hand-written probe checks and the probe result cache. No real network:
responses are built in memory or served by httpx.MockTransport."""

from __future__ import annotations

import httpx
import pytest

from pentest_agent.subagents import codegen_subagent as cg
from pentest_agent.tools import probe_runner as pr
from pentest_agent.tools.code_exec import probe_finding_to_finding
from pentest_agent.tools.probe_models import MAX_PROBES, ProbeCase, ProbePlan, ProbeType

URL = "https://example.com/"


def _resp(status=200, headers=None, text="", url=URL, request_headers=None):
    return httpx.Response(status, headers=headers or {}, text=text,
                          request=httpx.Request("GET", url, headers=request_headers or {}))


# ---------------------------------------------------------------- analyzers
def test_cache_control_flags_cookie_response_without_no_store():
    found = pr.analyze_cache_control(_resp(headers={"set-cookie": "sid=1", "cache-control": "max-age=60"}), URL)
    assert [f.category for f in found] == ["cache_control"]
    assert not pr.analyze_cache_control(_resp(headers={"set-cookie": "sid=1", "cache-control": "no-store"}), URL)
    assert not pr.analyze_cache_control(_resp(headers={"cache-control": "max-age=60"}), URL)  # nothing sensitive
    assert pr.analyze_cache_control(_resp(request_headers={"authorization": "Bearer x"}), URL)


def test_server_banner_needs_version_or_revealing_header():
    found = pr.analyze_server_banner(_resp(headers={"server": "nginx/1.18.0", "x-powered-by": "Express"}), URL)
    assert found and "nginx/1.18.0" in found[0].evidence and "Express" in found[0].evidence
    assert not pr.analyze_server_banner(_resp(headers={"server": "nginx"}), URL)


@pytest.mark.parametrize("policy, weak", [
    ("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'", "'unsafe-inline'"),
    ("script-src 'self' 'unsafe-eval'; object-src 'none'", "'unsafe-eval'"),
    ("script-src *; object-src 'none'", "any source"),
    ("img-src 'self'", "no script-src"),
])
def test_csp_weakness_detected(policy, weak):
    found = pr.analyze_csp_weakness(_resp(headers={"content-security-policy": policy}), URL)
    assert found and weak in found[0].description


def test_csp_weakness_quiet_for_strict_or_missing_policy():
    strict = "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'"
    assert not pr.analyze_csp_weakness(_resp(headers={"content-security-policy": strict}), URL)
    assert not pr.analyze_csp_weakness(_resp(), URL)  # missing CSP is security_headers' job


def test_directory_listing():
    assert pr.analyze_directory_listing(_resp(text="<html><title>Index of /backup</title>"), URL)
    assert not pr.analyze_directory_listing(_resp(404, text="<title>Index of /x</title>"), URL)
    assert not pr.analyze_directory_listing(_resp(text="<title>Home</title>"), URL)


def test_mixed_content_splits_active_and_passive():
    body = ('<script src="http://cdn.test/a.js"></script><img src="http://img.test/b.png">'
            '<link rel="canonical" href="http://example.com/"><link rel="stylesheet" href="http://c.test/s.css">')
    found = {f.title: f for f in pr.analyze_mixed_content(_resp(text=body), URL)}
    active = found["Active mixed content on HTTPS page"]
    assert "a.js" in active.evidence and "s.css" in active.evidence and "canonical" not in active.evidence
    assert "b.png" in found["Passive mixed content on HTTPS page"].evidence
    assert not pr.analyze_mixed_content(_resp(text=body, url="http://example.com/"), "http://example.com/")


def test_open_redirect_via_location_and_meta_refresh():
    url = "https://example.com/login?next=" + pr.REDIRECT_CANARY_URL
    loc = _resp(302, headers={"location": pr.REDIRECT_CANARY_URL}, url=url)
    assert pr.analyze_open_redirect(loc, url)[0].severity == "Medium"
    meta = _resp(text=f'<meta http-equiv="refresh" content="0; url={pr.REDIRECT_CANARY_URL}">', url=url)
    assert pr.analyze_open_redirect(meta, url)
    assert not pr.analyze_open_redirect(_resp(302, headers={"location": "/home"}, url=url), url)


def test_insecure_transport():
    http_url = "http://example.com/"
    assert pr.analyze_insecure_transport(_resp(url=http_url), http_url)[0].severity == "Medium"
    ok = _resp(301, headers={"location": "https://example.com/"}, url=http_url)
    assert not pr.analyze_insecure_transport(ok, http_url)
    assert not pr.analyze_insecure_transport(None, http_url)  # nothing on port 80
    local = "http://127.0.0.1:8080/"
    assert pr.analyze_insecure_transport(_resp(url=local), local)[0].severity == "Informational"
    assert pr.plain_http_url("https://example.com:8443/") is None


def test_new_categories_map_onto_owasp():
    f = pr.analyze_open_redirect(_resp(302, headers={"location": pr.REDIRECT_CANARY_URL}), URL)[0]
    assert probe_finding_to_finding(f).category.value.startswith("A01")


# ---------------------------------------------------------------- execution
def _client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)


def test_open_redirect_probe_replaces_parameter_and_never_follows():
    seen = []

    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={"location": request.url.params["next"]})

    probe = ProbeCase(probe_type=ProbeType.OPEN_REDIRECT, path="/login?next=/home",
                      query_parameter="next", reason="t")
    found = pr.execute_probe(client=_client(handler), base_url="https://example.com", probe=probe,
                             allowed_domains={"example.com"})
    assert found and len(seen) == 1 and "next=%2Fhome" not in seen[0]


def test_parameter_probe_without_parameter_sends_nothing():
    def handler(request):
        raise AssertionError("no request expected")

    probe = ProbeCase(probe_type=ProbeType.OPEN_REDIRECT, path="/", reason="t")
    assert pr.execute_probe(client=_client(handler), base_url="https://example.com", probe=probe,
                            allowed_domains={"example.com"}) == []


def test_insecure_transport_probe_tolerates_closed_port():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    probe = ProbeCase(probe_type=ProbeType.INSECURE_TRANSPORT, path="/", reason="t")
    assert pr.execute_probe(client=_client(handler), base_url="https://example.com", probe=probe,
                            allowed_domains={"example.com"}) == []


# ---------------------------------------------------------------- cache
@pytest.fixture
def counting_target(monkeypatch):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, headers={"server": "Apache/2.4.1"}, text="ok")

    monkeypatch.setattr(pr, "rate_limited_client",
                        lambda stats, verify=True, limits=None, **kw: httpx.Client(
                            transport=httpx.MockTransport(handler), **kw))
    return calls


def _run(probes, token=None):
    return pr.run_probe_plan(target_url="https://example.com", allowed_domains=["example.com"],
                             probes=probes, bearer_token=token)


def test_same_url_and_type_within_ttl_is_served_from_cache(counting_target):
    probe = ProbeCase(probe_type=ProbeType.SERVER_BANNER, path="/", reason="t")
    first, _ = _run([probe])
    second, _ = _run([probe])
    assert len(counting_target) == 1 and first == second and first

    _run([ProbeCase(probe_type=ProbeType.SECURITY_HEADERS, path="/", reason="t")])  # other type
    _run([ProbeCase(probe_type=ProbeType.SERVER_BANNER, path="/a", reason="t")])    # other URL
    _run([probe], token="secret")                                                   # other credentials
    assert len(counting_target) == 4


def test_cache_expires_after_ttl(counting_target, monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(pr.probe_cache, "_clock", lambda: now[0])
    probe = ProbeCase(probe_type=ProbeType.SERVER_BANNER, path="/", reason="t")
    _run([probe])
    now[0] += 299
    _run([probe])
    now[0] += 2
    _run([probe])
    assert len(counting_target) == 2


def test_cache_disabled_with_zero_ttl(counting_target, monkeypatch):
    from pentest_agent.config import settings

    monkeypatch.setattr(settings, "cache_ttl_seconds", 0)
    probe = ProbeCase(probe_type=ProbeType.SERVER_BANNER, path="/", reason="t")
    _run([probe])
    _run([probe])
    assert len(counting_target) == 2


# ---------------------------------------------------------------- planning
def test_default_plan_covers_new_checks_and_prioritises_redirect_params():
    pages = ["https://x.test/login?next=/a&q=1", "https://x.test/files/", "https://x.test/s?q=2"]
    plan = cg.default_probe_plan(pages)
    kinds = [p.probe_type for p in plan.probes]
    for t in cg.BASELINE_PROBES:
        assert t in kinds
    redirect = [p for p in plan.probes if p.probe_type == ProbeType.OPEN_REDIRECT]
    assert [(p.path, p.query_parameter) for p in redirect] == [("/login", "next")]
    assert any(p.probe_type == ProbeType.DIRECTORY_LISTING and p.path == "/files/" for p in plan.probes)
    assert len(plan.probes) <= MAX_PROBES


def test_llm_plan_drops_parameter_probes_without_parameter():
    plan = ProbePlan(probes=[ProbeCase(probe_type=ProbeType.OPEN_REDIRECT, path="/", reason="t"),
                             ProbeCase(probe_type=ProbeType.CORS, path="/", reason="t")])
    assert [p.probe_type for p in cg.drop_unusable_probes(plan).probes] == [ProbeType.CORS]
