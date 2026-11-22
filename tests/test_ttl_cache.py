"""TTL caching of LLM calls and whole scans (5-minute default)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from pentest_agent import graph, websocket_server
from pentest_agent.schemas import Finding, OwaspCategory, Severity
from pentest_agent.subagents import codegen_subagent as cg
from pentest_agent.tools.probe_models import ProbeCase, ProbePlan, ProbeType
from pentest_agent.ttl_cache import TTLCache, make_key, without_ids


def test_ttl_cache_basics():
    now = [0.0]
    cache = TTLCache("t", ttl_seconds=300, max_entries=2, clock=lambda: now[0])
    cache.put("a", {"v": [1]})
    got = cache.get("a")
    got["v"].append(2)                       # callers get copies
    assert cache.get("a") == {"v": [1]}
    now[0] = 299.9
    assert cache.age("a") == 299.9
    now[0] = 300
    assert cache.get("a") is None            # expired
    cache.put("b", 1)
    cache.put("c", 2)
    cache.put("d", 3)                        # evicts the oldest
    assert len(cache) == 2 and cache.get("b") is None


def test_keys_ignore_random_finding_ids():
    def f():
        return Finding(source="t", category=OwaspCategory.XSS, severity=Severity.HIGH, title="XSS",
                       description="d", affected_url="https://x.test/")
    a, b = f(), f()
    assert a.id != b.id
    assert make_key(without_ids([a])) == make_key(without_ids([b]))


def _findings():
    return [Finding(source="t", category=OwaspCategory.XSS, severity=Severity.HIGH, title="Reflected XSS",
                    description="d", affected_url="https://x.test/s")]


def test_executive_summary_llm_call_is_cached(monkeypatch):
    calls = []

    class Msg:
        content = "One high XSS issue [S1]."

    def fake_invoke(llm, messages):
        calls.append(1)
        return Msg()

    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "get_llm", lambda temperature=0.0: object())
    monkeypatch.setattr(graph, "invoke_with_backoff", fake_invoke)
    first = graph.generate_executive_summary("https://x.test", "quick", 3, _findings(), [])
    second = graph.generate_executive_summary("https://x.test", "quick", 3, _findings(), [])  # new ids
    assert len(calls) == 1 and first.text == second.text and first.llm_used
    graph.generate_executive_summary("https://x.test", "standard", 3, _findings(), [])
    assert len(calls) == 2                   # different input -> new call


def test_ungrounded_summary_is_not_cached(monkeypatch):
    calls = []

    class Msg:
        content = "No citations here."

    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "get_llm", lambda temperature=0.0: object())
    monkeypatch.setattr(graph, "invoke_with_backoff", lambda llm, m: calls.append(1) or Msg())
    graph.generate_executive_summary("https://x.test", "quick", 3, _findings(), [])
    graph.generate_executive_summary("https://x.test", "quick", 3, _findings(), [])
    assert len(calls) == 2


def test_probe_plan_llm_call_is_cached_across_sessions(monkeypatch):
    calls = []
    plan = ProbePlan(probes=[ProbeCase(probe_type=ProbeType.CORS, path="/", reason="r")])

    class Structured:
        def with_structured_output(self, _):
            return self

    monkeypatch.setattr(cg, "llm_available", lambda: True)
    monkeypatch.setattr(cg, "get_llm", lambda temperature=0.0: Structured())
    monkeypatch.setattr(cg, "invoke_with_backoff", lambda llm, m: calls.append(1) or plan)
    kwargs = {"target_url": "https://x.test", "allowed_domains": ["x.test"],
              "findings_summary": '[{"id": "aaaa", "title": "t"}]'}
    assert cg.generate_probe_plan(session_id="s1", **kwargs) == plan
    kwargs["findings_summary"] = '[{"id": "bbbb", "title": "t"}]'   # same findings, new ids
    assert cg.generate_probe_plan(session_id="s2", **kwargs) == plan
    assert len(calls) == 1


# ---------------------------------------------------------------- whole scans
def _start(ws, session_extra=None):
    payload = {"url": "https://example.com", "authorization_confirmed": True, "profile": "quick"}
    payload.update(session_extra or {})
    ws.send_json(payload)
    messages = []
    while True:
        msg = ws.receive_json()
        messages.append(msg)
        if msg["type"] in ("complete", "error"):
            return messages


def test_same_scan_request_within_ttl_is_served_instantly(monkeypatch, tmp_path):
    report = tmp_path / "report.md"
    report.write_text("# report", encoding="utf-8")
    runs = []

    class FakeGraph:
        async def astream(self, inputs, config, stream_mode):
            runs.append(inputs["session_id"])
            yield {"report": {"phase": "done"}}

        async def aget_state(self, config):
            return SimpleNamespace(values={"report_md_path": str(report), "phase": "done"})

    monkeypatch.setattr(websocket_server, "get_graph", lambda: FakeGraph())
    with TestClient(websocket_server.app) as client:
        with client.websocket_connect("/ws?session_id=scan-a") as ws:
            first = _start(ws)[-1]
        with client.websocket_connect("/ws?session_id=scan-b") as ws:
            second = _start(ws)[-1]
        with client.websocket_connect("/ws?session_id=scan-c") as ws:
            third = _start(ws, {"force_refresh": True})[-1]
        with client.websocket_connect("/ws?session_id=scan-d") as ws:
            fourth = _start(ws, {"profile": "standard"})[-1]

    assert first["type"] == "complete" and not first.get("cached")
    assert second["cached"] is True and second["cached_from_session"] == "scan-a"
    assert second["session_id"] == "scan-b" and second["report_md"] == "# report"
    assert not third.get("cached") and not fourth.get("cached")
    assert runs == ["scan-a", "scan-c", "scan-d"]
    assert Path(second["report_md_path"]) == report
