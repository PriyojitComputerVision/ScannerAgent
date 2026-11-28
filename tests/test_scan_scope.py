"""What a scan tests (graph choose_scope step): website + code, the website only, or the code only.

Human in the loop before any request (interrupt + resume), the rules for requests that name the
scope, code-only runs that never reach the website steps, the WebSocket question/answer, MCP /
ScanService checks, the audit record and the report. No network: DNS is stubbed by conftest."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, Interrupt

from pentest_agent import (
    audit_log,
    code_source,
    code_upload,
    graph,
    rbac,
    scan_scope,
    websocket_server,
)
from pentest_agent.config import settings
from pentest_agent.scan_service import (
    AccessPolicy,
    PolicyError,
    ScanService,
    check_scope,
)
from pentest_agent.schemas import HumanScopeResponse, ScanScope, TargetInput

ADMIN = rbac.Principal(sub="op", roles=["admin"])
SCANNER = rbac.Principal(sub="sc", roles=["scanner"])
VULN_PY = ("from flask import request\nimport os\n\n@app.route('/run')\ndef run():\n"
           "    os.system(request.args['cmd'])\n")


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "code_upload_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path / "reports"))
    monkeypatch.setattr(settings, "sandbox_backend", "process")
    monkeypatch.setattr(settings, "sandbox_check_enabled", True)
    code_upload._STATUS_CACHE.clear()


# ------------------------------------------------------------------ request rules
def test_requests_that_name_a_scope_must_be_consistent():
    url = "http://app.test/"
    with pytest.raises(ValueError, match="tests no source code"):
        TargetInput(url=url, scan_scope="website", upload_id="0" * 32)
    with pytest.raises(ValueError, match="tests no source code"):
        TargetInput(url=url, scan_scope="website", ask_for_code=True)
    for scope in ("code", "website_and_code"):
        with pytest.raises(ValueError, match="needs the source code"):
            TargetInput(url=url, scan_scope=scope)
        assert TargetInput(url=url, scan_scope=scope, ask_for_code=True).scan_scope == ScanScope(scope)
        assert TargetInput(url=url, scan_scope=scope, git_url="https://github.com/o/r.git")
    with pytest.raises(ValueError, match="source_path"):
        TargetInput(url=url, scan_scope="code", upload_id="0" * 32, source_path="/srv/app")
    with pytest.raises(ValueError):
        TargetInput(url=url, scan_scope="everything")
    with pytest.raises(ValueError):
        HumanScopeResponse.model_validate({"scope": "code", "extra": 1})


def test_default_scope_keeps_the_old_behaviour():
    assert scan_scope.default_scope(TargetInput(url="http://app.test/")) == ScanScope.WEBSITE
    assert scan_scope.default_scope(TargetInput(url="http://app.test/", ask_for_code=True)) == ScanScope.WEBSITE_AND_CODE
    assert scan_scope.default_scope(TargetInput(url="http://app.test/", upload_id="0" * 32)) == ScanScope.WEBSITE_AND_CODE
    assert scan_scope.allowed_scopes(ADMIN) == list(ScanScope)
    assert scan_scope.allowed_scopes(SCANNER) == [ScanScope.WEBSITE]  # no scan:source: website only


def test_resolve_answer_accepts_only_offered_scopes():
    allowed = [ScanScope.WEBSITE_AND_CODE, ScanScope.WEBSITE]
    assert scan_scope.resolve_answer({"scope": "website"}, allowed, ScanScope.WEBSITE_AND_CODE) == (
        ScanScope.WEBSITE, "operator")
    assert scan_scope.resolve_answer({"scope": "code"}, allowed, ScanScope.WEBSITE)[1] == "not offered"
    assert scan_scope.resolve_answer({"scope": "x"}, allowed, ScanScope.WEBSITE)[1] == "invalid answer"
    assert scan_scope.resolve_answer({"timeout": True}, allowed, ScanScope.WEBSITE) == (ScanScope.WEBSITE, "timeout")


# ------------------------------------------------------------------ graph
def _state(sid: str, principal=ADMIN, **target):
    return {"session_id": sid, "principal": principal.state_dict(), "allowed_domains": ["app.test"],
            "findings": [], "target": {"url": "http://app.test/", "session_id": sid,
                                       "authorization_confirmed": True, **target}}


@pytest.fixture(autouse=True)
def _no_website(monkeypatch):
    """Every tool that would talk to a website fails the test if a scan calls it."""
    def touched(*_a, **_k):
        raise AssertionError("a website tool was called")
    for tool in ("authenticate", "run_sandbox_check", "run_native_dast", "plan_probes", "run_probes",
                 "recon_and_crawl"):
        monkeypatch.setattr(graph, tool, SimpleNamespace(invoke=touched))


def _mini_graph():
    """choose_scope, sign-in, the code steps, sandbox check, DAST and the probes for real (their
    website tools fail the test when called); recon (website only / website + code) is a stub that
    ends the run, aggregate a stub."""
    g = StateGraph(graph.AgentState)
    g.add_node("choose_scope", graph.choose_scope_node)
    g.add_node("recon", lambda s: {"phase": "website_steps", "red_flags": ["WEBSITE_TOUCHED"]})
    g.add_node("auth", graph.auth_node)
    g.add_node("auth_challenge", graph.auth_challenge_node)
    g.add_node("code_source", graph.code_source_node)
    g.add_node("code_sast", graph.code_sast_node)
    g.add_node("sandbox_check", graph.sandbox_check_node)
    g.add_node("sast", lambda s: {"phase": "sast_complete"})
    g.add_node("dast", graph.dast_node)
    g.add_node("plan_probes", graph.plan_probes_node, defer=True)  # the join of the parallel scans
    g.add_node("run_probes", graph.run_probes_node)
    g.add_node("aggregate", lambda s: {"phase": "aggregated"})
    g.add_edge(START, "choose_scope")
    g.add_edge("sast", "plan_probes")
    for n in ("recon", "aggregate"):
        g.add_edge(n, END)
    return g.compile(checkpointer=InMemorySaver())



def test_scan_pauses_and_the_operator_picks_code_only():
    app, cfg = _mini_graph(), {"configurable": {"thread_id": "sc-1"}}
    paused = app.invoke(_state("sc-1", ask_scan_scope=True), cfg)
    (intr,) = paused["__interrupt__"]
    assert intr.value["type"] == "scan_scope" and intr.value["default"] == "website"
    assert [o["value"] for o in intr.value["options"]] == ["website_and_code", "website", "code"]
    assert app.get_state(cfg).next == ("choose_scope",)  # checkpointed before any request
    # code only: the next pause is the code step itself, marked as a code-only scan
    paused = app.invoke(Command(resume={"scope": "code"}), cfg)
    (intr,) = paused["__interrupt__"]
    assert intr.value["type"] == "code_source" and intr.value["scan_scope"] == "code"
    meta = code_source.store_files(ADMIN, [{"name": "app/views.py", "content": VULN_PY}])
    done = app.invoke(Command(resume={"action": "upload", "upload_id": meta["upload_id"]}), cfg)
    assert done["scan_scope"] == "code" and done["scope_choice"]["decided_by"] == "operator"
    assert done["phase"] == "aggregated" and done["findings"]
    assert "WEBSITE_TOUCHED" not in done.get("red_flags", [])  # recon never ran
    # every other step is in the path, the website steps passing straight on (no tool called)
    for step in ("auth", "sandbox_check", "dast", "plan_probes", "run_probes"):
        assert graph.with_iteration_limit(step, getattr(graph, f"{step}_node"))(
            {**_state("x", scan_scope="code", upload_id="0" * 32), "scan_scope": "code"}
        ).update["phase"] == f"{step}_code_only"


def test_code_only_without_code_reports_that_nothing_was_analysed():
    app, cfg = _mini_graph(), {"configurable": {"thread_id": "sc-2"}}
    app.invoke(_state("sc-2", ask_scan_scope=True), cfg)
    app.invoke(Command(resume={"scope": "code"}), cfg)
    done = app.invoke(Command(resume={"action": "skip"}), cfg)
    assert done["phase"] == "aggregated" and not done["findings"]
    assert any("no source code was analysed" in f for f in done["red_flags"])
    assert "WEBSITE_TOUCHED" not in done["red_flags"]


def test_website_only_skips_the_code_step():
    app, cfg = _mini_graph(), {"configurable": {"thread_id": "sc-3"}}
    app.invoke(_state("sc-3", ask_scan_scope=True), cfg)
    done = app.invoke(Command(resume={"scope": "website"}), cfg)
    assert done["scan_scope"] == "website" and done["phase"] == "website_steps"
    # code_source on its own passes straight on for a website-only scan
    cmd = graph.code_source_node({**_state("sc-3", ask_scan_scope=True), "scan_scope": "website"})
    assert [s.node for s in cmd.goto] == [graph._js_sast_step(), "dast"]   # no code_sast
    assert cmd.update["phase"] == "code_source_none"


def test_named_scope_and_no_permission_do_not_pause():
    named = graph.choose_scope_node(_state("sc-4", scan_scope="code", upload_id="0" * 32))
    assert named.goto == "auth" and named.update["scope_choice"]["decided_by"] == "request"
    plain = graph.choose_scope_node(_state("sc-5"))
    assert plain.goto == "recon" and plain.update["scan_scope"] == "website"
    # a scanner (no scan:source) has only one scope: no pause, the website is tested
    scanner = graph.choose_scope_node(_state("sc-6", principal=SCANNER, ask_scan_scope=True))
    assert scanner.goto == "recon" and scanner.update["scan_scope"] == "website"


def test_rbac_refuses_a_code_scope_without_scan_source():
    target = TargetInput(url="http://app.test/", scan_scope="code", ask_for_code=True)
    assert "RBAC" in (graph._rbac_check_scan({"principal": SCANNER.state_dict()}, target) or "")
    assert graph._rbac_check_scan({"principal": ADMIN.state_dict()}, target) is None


def test_audit_record_and_report_show_the_scope():
    rec = audit_log.record_from_state({"session_id": "a", "scope_choice": {"scope": "code", "decided_by": "operator"}})
    assert rec["scope"] == {"scope": "code", "decided_by": "operator"}
    assert audit_log.record_from_state({"session_id": "b"})["scope"] is None

    from pentest_agent.tools.report_tool import _render_markdown, _report_meta
    state = {**_state("sc-r", scan_scope="code", upload_id="0" * 32), "scan_scope": "code",
             "profile": "quick", "started_at": "2026-01-01T00:00:00+00:00"}
    report = graph.FinalReport.model_validate_json(graph.aggregate_node(state).update["_final_report_json"])
    assert report.scan_scope == ScanScope.CODE
    assert "**Scope:** Source code only" in _render_markdown(report)
    assert ("Scope", "Source code only (no request sent to the website)") in _report_meta(report)


# ------------------------------------------------------------------ WebSocket human in the loop
class FakeGraph:
    """Pauses once at choose_scope, then finishes."""

    def __init__(self):
        self.resumes, self.calls = [], 0

    async def aget_state(self, config):
        return SimpleNamespace(values={"session_id": "s1"}, interrupts=())

    async def astream(self, inputs, config, stream_mode):
        self.calls += 1
        if self.calls == 1:
            req = scan_scope.scope_request("http://app.test/", [ScanScope.WEBSITE_AND_CODE, ScanScope.WEBSITE],
                                           ScanScope.WEBSITE)
            yield ("updates", {"__interrupt__": (Interrupt(value=req),)})
        else:
            self.resumes.append(inputs.resume)
            yield ("updates", {"choose_scope": {"phase": "scope_done"}})


def _scan(monkeypatch, answers):
    fake = FakeGraph()
    monkeypatch.setattr(websocket_server, "_graph", fake)
    seen = []
    c = TestClient(websocket_server.app)  # no lifespan: it would replace the fake graph
    with c.websocket_connect("/ws?session_id=s1") as ws:
        ws.send_text(json.dumps({"url": "http://app.test/", "authorization_confirmed": True, "ask_scan_scope": True}))
        answers = list(answers)
        while True:
            msg = json.loads(ws.receive_text())
            seen.append(msg)
            if msg["type"] in ("input_required", "input_invalid") and answers:
                ws.send_text(json.dumps(answers.pop(0)))
            if msg["type"] in ("complete", "error"):
                break
    return fake, seen


def test_websocket_asks_what_to_test_and_accepts_only_offered_scopes(monkeypatch):
    fake, msgs = _scan(monkeypatch, [
        {"type": "code_response", "action": "skip"},  # wrong message type
        {"type": "scope_response", "scope": "code"},   # not offered here
        {"type": "scope_response", "scope": "all"},    # not a scope
        {"type": "scope_response", "scope": "website_and_code"},
    ])
    req = next(m for m in msgs if m["type"] == "input_required")
    assert req["request"]["type"] == "scan_scope" and req["request"]["default"] == "website"
    assert req["timeout_seconds"] == settings.scope_input_timeout_seconds
    assert sum(m["type"] == "input_invalid" for m in msgs) == 3
    assert fake.resumes == [{"scope": "website_and_code"}]


def test_websocket_scope_timeout_keeps_the_default(monkeypatch):
    monkeypatch.setattr(settings, "scope_input_timeout_seconds", 0.3)
    fake, msgs = _scan(monkeypatch, [])
    assert fake.resumes == [{"timeout": True}]
    assert any(m.get("event") == "input_timeout" for m in msgs)


# ------------------------------------------------------------------ MCP / A2A (ScanService)
def test_scan_service_checks_the_scope_before_starting():
    assert check_scope(None) is None and check_scope("code") == "code"
    with pytest.raises(PolicyError, match="Unknown scan_scope"):
        check_scope("everything")
    svc = ScanService(AccessPolicy(via="mcp", roles="admin", allowed_targets="app.test"))
    import asyncio

    with pytest.raises(PolicyError, match="needs the source code"):
        asyncio.run(svc.start_scan("http://app.test/", authorization_confirmed=True, scan_scope="code"))
    with pytest.raises(PolicyError, match="tests no source code"):
        asyncio.run(svc.start_scan("http://app.test/", authorization_confirmed=True, scan_scope="website",
                                   upload_id="0" * 32))
    scopes = {s["value"]: s["allowed"] for s in svc.describe_policy()["scan_scopes"]}
    assert scopes == {"website_and_code": True, "website": True, "code": True}
    scanner = ScanService(AccessPolicy(via="mcp", roles="scanner", allowed_targets="app.test"))
    assert {s["value"]: s["allowed"] for s in scanner.describe_policy()["scan_scopes"]}["code"] is False


# ------------------------------------------------------------------ code only, no website at all
def test_code_only_scan_needs_no_url(monkeypatch):
    t = TargetInput(scan_scope="code", upload_id="0" * 32)
    assert t.url is None and t.target_label == "source code (no website)"
    with pytest.raises(ValueError) as exc:  # every other scope needs the website; the error points at "url"
        TargetInput(scan_scope="website_and_code", upload_id="0" * 32)
    assert exc.value.errors()[0]["loc"] == ("url",)
    with pytest.raises(ValueError):
        TargetInput(upload_id="0" * 32)
    with pytest.raises(ValueError, match="no extra hosts or target credentials"):
        TargetInput(scan_scope="code", upload_id="0" * 32, jwt="a.b.c")

    # validate: no DNS / network-policy check and no scope for a scan that contacts no website
    def no_network(*_a, **_k):
        raise AssertionError("a code-only scan must not resolve or check any host")
    monkeypatch.setattr(graph, "pre_run_guardrail", no_network)
    cmd = graph.validate_input_node({"session_id": "nu-1", "principal": ADMIN.state_dict(),
                                     "target": t.model_dump(mode="json")})
    assert cmd.goto == "choose_scope" and cmd.update["allowed_domains"] == []
    state = {"session_id": "nu-1", "principal": ADMIN.state_dict(), "target": t.model_dump(mode="json"),
             "scan_scope": "code", "profile": "standard", "started_at": "2026-01-01T00:00:00+00:00"}
    assert graph.choose_scope_node(state).goto == "auth"  # code only skips the recon layer
    report = graph.FinalReport.model_validate_json(graph.aggregate_node(state).update["_final_report_json"])
    assert report.target_url == "source code (no website)"


def test_scan_service_code_only_without_target_url():
    import asyncio

    svc = ScanService(AccessPolicy(via="mcp", roles="admin", allowed_targets="app.test"))
    with pytest.raises(PolicyError, match="target_url is required"):
        asyncio.run(svc.start_scan(None, authorization_confirmed=True, upload_id="0" * 32))
    with pytest.raises(PolicyError, match="no credentials or extra domains"):
        asyncio.run(svc.start_scan("", authorization_confirmed=True, upload_id="0" * 32, scan_scope="code",
                                   credentials="staging"))
    target = svc._target(None, "standard", True, [], {"upload_id": "0" * 32, "scan_scope": "code"})
    svc.policy.check_target(target)  # no website: nothing to allowlist
    assert target.url is None


@pytest.mark.parametrize("sandbox_check_enabled, js_step", [(True, "sandbox_check"), (False, "sast")])
def test_code_only_path_skips_only_recon(monkeypatch, sandbox_check_enabled, js_step):
    monkeypatch.setattr(settings, "sandbox_check_enabled", sandbox_check_enabled)
    meta = code_source.store_files(ADMIN, [{"name": "app/views.py", "content": VULN_PY}])
    app, cfg = _mini_graph(), {"configurable": {"thread_id": f"sc-path-{sandbox_check_enabled}"}}
    order = [n for chunk in app.stream(_state("sc-path", scan_scope="code", upload_id=meta["upload_id"]), cfg,
                                       stream_mode="updates") for n in chunk]
    # the three scan branches run in one step (parallel, any order), then the sequential rest
    assert order[:3] == ["choose_scope", "auth", "code_source"]
    assert sorted(order[3:6]) == sorted(["code_sast", js_step, "dast"])
    assert order[6:] == ["plan_probes", "run_probes", "aggregate"]
    final = app.get_state(cfg).values
    assert final["findings"] and not final.get("crawled_pages")  # only the code was analysed
