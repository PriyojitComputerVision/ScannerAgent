from __future__ import annotations

import httpx

from pentest_agent.schemas import Severity
from pentest_agent.tools.recon import _retryable, _security_header_findings


def test_security_header_findings_flags_missing_headers():
    headers = httpx.Headers({"content-type": "text/html"})
    findings = _security_header_findings("https://example.com/", headers)
    titles = {f.title for f in findings}
    assert "Missing Content-Security-Policy header" in titles
    assert "Missing Strict-Transport-Security (HSTS) header" in titles
    assert "Missing X-Frame-Options header (clickjacking risk)" in titles


def test_security_header_findings_no_flag_when_present():
    headers = httpx.Headers(
        {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "strict-transport-security": "max-age=63072000",
            "referrer-policy": "no-referrer",
        }
    )
    findings = _security_header_findings("https://example.com/", headers)
    assert findings == []


def test_security_header_findings_flags_server_disclosure():
    headers = httpx.Headers(
        {
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "strict-transport-security": "max-age=63072000",
            "referrer-policy": "no-referrer",
            "server": "nginx/1.18.0",
        }
    )
    findings = _security_header_findings("https://example.com/", headers)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "nginx/1.18.0" in findings[0].description


def test_retryable_on_5xx():
    req = httpx.Request("GET", "https://example.com")
    for status in (502, 503, 504):
        resp = httpx.Response(status_code=status, request=req)
        exc = httpx.HTTPStatusError("err", request=req, response=resp)
        assert _retryable(exc) is True


def test_429_left_to_rate_limit_transport():
    # 429 is retried once, honouring Retry-After, by http_retry.RateLimitRetryTransport;
    # tenacity must not multiply those retries.
    req = httpx.Request("GET", "https://example.com")
    exc = httpx.HTTPStatusError("err", request=req, response=httpx.Response(429, request=req))
    assert _retryable(exc) is False


def test_not_retryable_on_404():
    req = httpx.Request("GET", "https://example.com")
    resp = httpx.Response(status_code=404, request=req)
    exc = httpx.HTTPStatusError("err", request=req, response=resp)
    assert _retryable(exc) is False


def test_retryable_on_timeout_and_connect_error():
    assert _retryable(httpx.TimeoutException("timeout")) is True
    assert _retryable(httpx.ConnectError("refused")) is True
    assert _retryable(ValueError("unrelated")) is False
