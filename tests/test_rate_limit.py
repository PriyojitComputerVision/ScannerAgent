"""HTTP 429 handling: target links (engine + httpx transport), LLM retries, backend limits."""
from __future__ import annotations

import datetime as dt
import http.server
import threading
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from pentest_agent import llm, websocket_server
from pentest_agent.http_retry import RateLimitRetryTransport
from pentest_agent.rate_limit import ConcurrencyLimiter, SlidingWindowLimiter
from scopeguard import ratelimit
from scopeguard.engine import ScopedClient


# ---------------------------------------------------------------- Retry-After parsing
def test_parse_retry_after_forms_and_cap():
    now = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    assert ratelimit.parse_retry_after("5") == 5.0
    assert ratelimit.parse_retry_after("9999", cap=30) == 30.0
    assert ratelimit.parse_retry_after("-3") == 0.0
    assert ratelimit.parse_retry_after("Thu, 01 Jan 2026 00:00:10 GMT", now=now) == 10.0
    assert ratelimit.parse_retry_after("Thu, 01 Jan 2025 00:00:10 GMT", now=now) == 0.0
    for bad in (None, "", "soon", "nan"):
        assert ratelimit.parse_retry_after(bad) is None
    assert ratelimit.should_retry(429, None) and ratelimit.should_retry(503, "1")
    assert not ratelimit.should_retry(503, None) and not ratelimit.should_retry(200, "1")
    assert [ratelimit.backoff_delay(i) for i in range(3)] == [1.0, 2.0, 4.0]


# ---------------------------------------------------------------- target link: engine client
class _Throttling(http.server.BaseHTTPRequestHandler):
    plan: list = []

    def do_GET(self):  # noqa: N802
        status, headers = (self.plan.pop(0) if self.plan else (200, {}))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>ok</html>")

    def log_message(self, *a):
        pass


@pytest.fixture
def throttling_server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Throttling)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def test_engine_retries_429_honouring_retry_after(throttling_server):
    _Throttling.plan = [(429, {"Retry-After": "2"}), (429, {}), (200, {})]
    netloc = f"127.0.0.1:{throttling_server.server_address[1]}"
    slept = []
    c = ScopedClient([netloc], delay=0, sleep=slept.append)
    r = c.get(f"http://{netloc}/")
    assert r.status == 200
    assert slept == [2.0, 2.0]  # Retry-After honoured, then exponential backoff (attempt 1 -> 2s)
    assert c.count == 3 and c.rate_limit.retries == 2 and c.rate_limit.gave_up == 0
    assert c.delay >= 0.5  # slowed down after being throttled
    assert "all succeeded" in c.rate_limit.red_flag()


def test_engine_gives_up_and_flags_incomplete_results(throttling_server):
    _Throttling.plan = [(429, {"Retry-After": "1"})] * 10
    netloc = f"127.0.0.1:{throttling_server.server_address[1]}"
    c = ScopedClient([netloc], delay=0, max_retries=2, sleep=lambda s: None)
    r = c.get(f"http://{netloc}/x")
    assert r.status == 429 and c.count == 3
    assert c.rate_limit.gave_up == 1 and c.rate_limit.urls == [f"http://{netloc}/x"]
    assert "incomplete" in c.rate_limit.red_flag()


# ---------------------------------------------------------------- target link: httpx transport
def _mock(responses):
    calls = []

    def handler(request):
        calls.append(str(request.url))
        status, headers = responses.pop(0) if responses else (200, {})
        return httpx.Response(status, headers=headers, text="x")
    return httpx.MockTransport(handler), calls


def test_transport_retries_then_succeeds():
    inner, calls = _mock([(429, {"Retry-After": "3"}), (503, {"Retry-After": "1"}), (200, {})])
    slept = []
    t = RateLimitRetryTransport(inner, sleep=slept.append)
    with httpx.Client(transport=t) as c:
        assert c.get("https://example.com/").status_code == 200
    assert slept == [3.0, 1.0] and len(calls) == 3 and t.stats.retries == 2


def test_transport_does_not_retry_plain_503_or_404():
    inner, calls = _mock([(503, {}), (404, {})])
    t = RateLimitRetryTransport(inner, sleep=lambda s: None)
    with httpx.Client(transport=t) as c:
        assert c.get("https://example.com/a").status_code == 503
        assert c.get("https://example.com/b").status_code == 404
    assert len(calls) == 2 and t.stats.throttled == 0


def test_transport_gives_up_after_max_retries():
    inner, calls = _mock([(429, {})] * 10)
    t = RateLimitRetryTransport(inner, max_retries=2, sleep=lambda s: None)
    with httpx.Client(transport=t) as c:
        assert c.get("https://example.com/").status_code == 429
    assert len(calls) == 3 and t.stats.gave_up == 1 and "incomplete" in t.stats.red_flag()


# ---------------------------------------------------------------- LLM (Groq) 429
def _retry_state(exc):
    return SimpleNamespace(outcome=SimpleNamespace(exception=lambda: exc), attempt_number=1,
                           idle_for=0, seconds_since_start=0, upcoming_sleep=0)


def test_llm_wait_honours_retry_after_header():
    exc = Exception("Error code: 429 rate limit")
    exc.response = SimpleNamespace(status_code=429, headers={"retry-after": "7"})
    exc.status_code = 429
    assert llm._is_rate_limit_or_transient(exc)
    assert llm._wait_rate_limit(_retry_state(exc)) == pytest.approx(7.25)
    exc.response.headers = {"retry-after": "9999"}
    assert llm._wait_rate_limit(_retry_state(exc)) == pytest.approx(llm.LLM_MAX_RETRY_AFTER + 0.25)


def test_llm_wait_falls_back_to_backoff_and_classifies_statuses():
    exc = Exception("boom")
    exc.status_code = 503
    assert llm._is_rate_limit_or_transient(exc)
    assert 0 < llm._wait_rate_limit(_retry_state(exc)) <= 30
    bad_request = Exception("400 invalid")
    bad_request.status_code = 400
    assert not llm._is_rate_limit_or_transient(bad_request)


def test_invoke_with_backoff_retries_on_429():
    attempts = []

    class FakeLLM:
        def invoke(self, messages):
            attempts.append(1)
            if len(attempts) < 3:
                e = Exception("429 rate limit")
                e.status_code = 429
                e.response = SimpleNamespace(status_code=429, headers={"retry-after": "0"})
                raise e
            return "ok"

    assert llm.invoke_with_backoff.retry_with(sleep=lambda s: None)(FakeLLM(), []) == "ok"
    assert len(attempts) == 3


# ---------------------------------------------------------------- backend limits
def test_sliding_window_and_concurrency_limiters():
    t = [0.0]
    lim = SlidingWindowLimiter(2, window=60, clock=lambda: t[0])
    assert lim.hit("a")[0] and lim.hit("a")[0]
    allowed, retry = lim.hit("a")
    assert not allowed and retry == 60
    assert lim.hit("b")[0]  # per-client
    t[0] = 61
    assert lim.hit("a")[0]
    assert SlidingWindowLimiter(0).hit("x") == (True, 0)  # 0 disables

    import asyncio

    async def run():
        c = ConcurrencyLimiter(1)
        async with c.slot("ip") as first:
            async with c.slot("ip") as second:
                assert first and not second
        assert c.active("ip") == 0
    asyncio.run(run())


def test_http_routes_return_429_with_retry_after(monkeypatch):
    monkeypatch.setattr(websocket_server.http_limiter, "limit", 2)
    c = TestClient(websocket_server.app)
    assert c.get("/reports/").status_code == 200
    assert c.get("/reports/").status_code == 200
    r = c.get("/reports/")
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert r.json()["detail"] == "Too Many Requests"
    assert c.get("/healthz").status_code == 200  # exempt


def test_ws_sessions_rate_limited_with_4429(monkeypatch):
    monkeypatch.setattr(websocket_server.ws_session_limiter, "limit", 1)
    c = TestClient(websocket_server.app)
    with c.websocket_connect("/ws") as ws:  # no session_id: rejected, but counts
        assert ws.receive_json()["type"] == "error"
    with c.websocket_connect("/ws?session_id=x") as ws:
        msg = ws.receive_json()
        assert msg["code"] == 429 and msg["retry_after"] >= 1
        with pytest.raises(Exception) as info:
            ws.receive_json()
        assert getattr(info.value, "code", None) == 4429
