"""LangSmith tracing: enable/disable logic and secret redaction of uploaded runs."""
from __future__ import annotations

import json

import pytest

from pentest_agent import tracing

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3OCJ9.c2lnbmF0dXJl"


def test_redact_keys_and_values():
    data = {
        "target": {"url": "https://example.com", "jwt": JWT, "authorization_confirmed": True,
                   "auth": {"username": "bob", "password": "hunter2"}},
        "auth_session_headers": {"Authorization": "Bearer abc"},
        "jwt_provided": True,
        "notes": f"saw header Bearer abcdefghijklmnop and token {JWT}",
        "findings": [{"title": "JS_STORAGE_TOKEN", "evidence": "key gsk_" + "a" * 30}],
    }
    out = json.dumps(tracing.redact(data))
    for secret in ("hunter2", JWT, "abcdefghijklmnop", "Bearer abc", "gsk_aaaa"):
        assert secret not in out
    red = tracing.redact(data)
    assert red["target"]["url"] == "https://example.com"
    assert red["target"]["authorization_confirmed"] is True and red["jwt_provided"] is True
    assert red["target"]["auth"] == {"username": "bob", "password": tracing.REDACTED}
    assert red["auth_session_headers"] == tracing.REDACTED
    assert red["findings"][0]["title"] == "JS_STORAGE_TOKEN"


@pytest.mark.parametrize("flag,key,expected", [
    (False, "lsv2_pt_real", False), (True, "", False), (True, "test-key", False), (True, "lsv2_pt_real", True),
])
def test_tracing_enabled(monkeypatch, flag, key, expected):
    monkeypatch.setattr(tracing.settings, "langsmith_tracing", flag)
    monkeypatch.setattr(tracing.settings, "langsmith_api_key", key)
    assert tracing.tracing_enabled() is expected


def test_disabled_trace_scan_sends_nothing(monkeypatch):
    monkeypatch.setattr(tracing.settings, "langsmith_tracing", False)
    with tracing.trace_scan("s", "https://example.com", "quick") as on:
        assert on is False


def test_uploaded_runs_are_redacted_and_nested(monkeypatch):
    from langchain_core.runnables import RunnableLambda

    monkeypatch.setattr(tracing.settings, "langsmith_tracing", True)
    monkeypatch.setattr(tracing.settings, "langsmith_api_key", "lsv2_pt_" + "f" * 32)
    monkeypatch.setattr(tracing.settings, "langsmith_endpoint", "http://127.0.0.1:9")
    tracing.get_client.cache_clear()
    client = tracing.get_client()
    sent: list[bytes] = []

    class _Resp:
        status_code = 200
        text = "{}"
        headers: dict = {}

        def raise_for_status(self):
            pass

        def json(self):
            return {}

    def fake_request(method, url, *args, **kwargs):  # capture instead of uploading
        body = kwargs.get("data") or kwargs.get("json") or b""
        sent.append(body if isinstance(body, bytes) else json.dumps(body, default=str).encode())
        return _Resp()

    monkeypatch.setattr(client.session, "request", fake_request)

    @tracing.traceable("inner_span")
    def inner(x):
        return {"echo": x, "token": "abc123secret"}

    try:
        with tracing.trace_scan("sess-9", "https://example.com/p?q=1", "quick") as on:
            assert on is True
            RunnableLambda(inner).invoke(
                {"target": {"jwt": JWT, "auth": {"password": "hunter2"}}, "note": "Bearer abcdefghijklmnop"},
                config=tracing.graph_config("sess-9", "https://example.com", "quick"))
        tracing.flush()
    finally:
        tracing.get_client.cache_clear()

    blob = b"".join(sent)
    assert blob, "nothing was uploaded"
    for secret in (b"hunter2", JWT.encode(), b"abcdefghijklmnop", b"abc123secret"):
        assert secret not in blob
    assert b"sess-9" in blob and b"pentest-scan:example.com" in blob and b"inner_span" in blob
    assert b"/p?q=1" not in blob  # metadata carries host only
