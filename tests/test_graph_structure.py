"""Graph wiring: the SAST sub-agent as a subgraph node, edges declared for
drawing, and message compaction with LangChain's SummarizationMiddleware."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from pentest_agent import graph
from pentest_agent.subagents import sast_subagent


def _edges():
    g = graph.build_graph().get_graph(xray=True)
    return {(e.source, e.target) for e in g.edges}, set(g.nodes)


def test_every_route_is_visible_in_the_drawn_graph():
    edges, nodes = _edges()
    assert "sast:run_sast" in nodes  # the SAST sub-agent is drawn inside the main graph
    expected = {
        ("__start__", "validate"), ("validate", "choose_scope"), ("validate", "audit"),
        # human in the loop before any request: website + code / website only -> recon;
        # code only skips the recon layer (-> auth; the website steps then pass straight on)
        ("choose_scope", "recon"), ("choose_scope", "auth"),
        ("recon", "auth"), ("auth", "code_source"),
        # human in the loop: auth pauses in auth_challenge for SSO / MFA, then continues
        ("auth", "auth_challenge"), ("auth_challenge", "code_source"),
        # human in the loop at the SAST step: code_source pauses for code files / a .zip / a git
        # link, then starts the scans in parallel (Send): code_sast, the website's JavaScript
        # check (sandbox_check, or sast while it is off) and dast; all meet at plan_probes
        ("code_source", "code_sast"), ("code_source", "sast:run_sast"), ("code_source", "sandbox_check"),
        ("code_source", "dast"),
        ("code_sast", "plan_probes"), ("sast:run_sast", "plan_probes"), ("sandbox_check", "plan_probes"),
        ("dast", "plan_probes"), ("plan_probes", "run_probes"),
        ("plan_probes", "aggregate"), ("run_probes", "aggregate"),
        ("aggregate", "report"), ("report", "audit"),   # no summarize step: the report comes straight
        ("audit", "__end__"),  # the audit record is the last step of every run
        # safety stop (AGENT_MAX_ITERATIONS): any step can jump to aggregate (a scan branch to its join)
        ("recon", "aggregate"), ("aggregate", "audit"),
    }
    assert expected <= edges
    # the scan branches never wait for each other: no edge between them
    branches = {"code_sast", "sast:run_sast", "sandbox_check", "dast"}
    assert not {(a, b) for a, b in edges if a in branches and b in branches}
    assert ("choose_scope", "code_source") not in edges  # code only keeps every step but recon
    assert "flowchart" in graph.build_graph().get_graph(xray=True).draw_mermaid()


def test_wrapped_nodes_keep_their_declared_targets():
    run = graph.with_iteration_limit("recon", graph.recon_node)
    assert set(graph.command_destinations(run)) == {"auth", "aggregate"}
    run = graph.with_iteration_limit("report", graph.report_node)
    assert set(graph.command_destinations(run)) == {"audit"}
    run = graph.with_iteration_limit("audit", graph.audit_node)
    assert set(graph.command_destinations(run)) == {"__end__"}
    edges, _ = _edges()
    assert not {(s, t) for s, t in edges if t == "__end__"} - {("audit", "__end__")},         "every route must end through the audit node"


def _parent_with_sast():
    """A tiny parent graph using the real subgraph and the main graph's state."""
    g = StateGraph(graph.AgentState)
    g.add_node("sast", sast_subagent.build_sast_subgraph())
    g.add_edge(START, "sast")
    g.add_edge("sast", END)
    return g.compile(checkpointer=InMemorySaver())


def test_sast_subgraph_adds_findings_without_duplicating_parent_lists(monkeypatch):
    calls = []

    def fake_invoke(args):
        calls.append(args)
        return SimpleNamespace(update={"findings": [{"title": "eval"}], "notes": "scanned"})

    monkeypatch.setattr(sast_subagent, "run_sast_on_client_assets", SimpleNamespace(invoke=fake_invoke))
    app = _parent_with_sast()
    out = app.invoke({"crawled_pages": ["https://a.example/"], "allowed_domains": ["a.example"],
                      "findings": [{"title": "earlier"}], "node_runs": {"recon": 1}},
                     config={"configurable": {"thread_id": "t1"}})
    assert calls == [{"crawled_pages": ["https://a.example/"], "allowed_domains": ["a.example"]}]
    assert out["crawled_pages"] == ["https://a.example/"]            # not appended twice
    assert out["findings"] == [{"title": "earlier"}, {"title": "eval"}]
    assert out["node_runs"] == {"recon": 1, "sast": 1}
    assert out["phase"] == "sast_complete" and out["notes"] == "scanned"


def test_sast_subgraph_respects_the_iteration_cap(monkeypatch):
    monkeypatch.setattr(graph.settings, "agent_max_iterations", 1)
    must_not_run = SimpleNamespace(invoke=lambda args: (_ for _ in ()).throw(AssertionError("ran")))
    monkeypatch.setattr(sast_subagent, "run_sast_on_client_assets", must_not_run)
    out = _parent_with_sast().invoke({"node_runs": {"sast": 1}, "crawled_pages": []},
                                     config={"configurable": {"thread_id": "t2"}})
    assert out["phase"] == "iteration_limit" and out["node_runs"] == {"sast": 1}
    assert any("Safety stop" in f for f in out["red_flags"])


def _long_transcript(n=8, size=2500):
    return [(HumanMessage if i % 2 == 0 else AIMessage)(content=f"m{i} " + "x" * size, id=f"id{i}")
            for i in range(n)]


def test_maybe_summarize_uses_the_middleware_and_really_drops_old_messages(monkeypatch):
    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "get_llm", lambda **_: FakeListChatModel(responses=["unused"]))
    seen = []

    def fake_summary(messages):
        seen.append(len(messages))
        return "condensed history"

    monkeypatch.setattr(graph, "summarize_transcript", fake_summary)
    msgs = _long_transcript()
    update = graph.maybe_summarize({"messages": msgs})
    assert update["summary"] == "condensed history" and seen == [len(msgs) - graph.SUMMARY_KEEP_MESSAGES]

    # Applied through the real add_messages reducer, only summary + kept messages remain.
    from langgraph.graph.message import add_messages
    after = add_messages(msgs, update["messages"])
    assert len(after) == graph.SUMMARY_KEEP_MESSAGES + 1
    assert "condensed history" in after[0].content
    assert [m.id for m in after[1:]] == [m.id for m in msgs[-graph.SUMMARY_KEEP_MESSAGES:]]


def test_maybe_summarize_is_a_no_op_when_short_offline_or_failing(monkeypatch):
    assert graph.maybe_summarize({"messages": _long_transcript(n=2)}) == {}
    monkeypatch.setattr(graph, "llm_available", lambda: False)
    assert graph.maybe_summarize({"messages": _long_transcript()}) == {}
    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "get_llm", lambda **_: FakeListChatModel(responses=["unused"]))
    monkeypatch.setattr(graph, "summarize_transcript",
                        lambda m: (_ for _ in ()).throw(RuntimeError("429")))
    assert graph.maybe_summarize({"messages": _long_transcript()}) == {}


# ---------------------------------------------------------------- split steps
def _probe_state(profile="standard"):
    from pentest_agent import rbac
    return {"session_id": "p1", "principal": rbac.Principal(sub="a", roles=["admin"]).state_dict(),
            "allowed_domains": ["example.com"], "profile": profile, "findings": [],
            "crawled_pages": ["https://example.com/"],
            "target": {"url": "https://example.com", "authorization_confirmed": True,
                       "session_id": "p1", "profile": profile}}


def test_plan_probes_stores_the_plan_then_run_probes_executes_it(monkeypatch):
    from pentest_agent.tools import code_exec
    from pentest_agent.tools.probe_models import ProbePlan

    planned = ProbePlan.model_validate({"probes": [{"probe_type": "security_headers", "path": "/",
                                                    "reason": "check headers"}]})
    monkeypatch.setattr(code_exec, "generate_probe_plan", lambda **_: planned)
    state = _probe_state()
    cmd = graph.plan_probes_node(state)
    assert cmd.goto == "run_probes" and cmd.update["phase"] == "probe_plan_ready"
    assert cmd.update["probe_plan"]["probes"][0]["probe_type"] == "security_headers"

    ran = {}

    def fake_run(**kw):
        ran.update(kw)
        return [], []

    monkeypatch.setattr(code_exec, "run_probe_plan", fake_run)
    out = graph.run_probes_node({**state, **cmd.update})
    assert out.goto == "aggregate" and out.update["phase"] == "codegen_probe_complete"
    assert [p.probe_type.value for p in ran["probes"]] == ["security_headers"]


def test_plan_probes_without_a_plan_goes_straight_to_aggregate():
    cmd = graph.plan_probes_node(_probe_state(profile="quick"))
    assert cmd.goto == "aggregate" and cmd.update["phase"] == "codegen_probe_skipped"


def test_run_probes_refuses_a_tampered_stored_plan(monkeypatch):
    from pentest_agent.tools import code_exec
    monkeypatch.setattr(code_exec, "run_probe_plan",
                        lambda **_: (_ for _ in ()).throw(AssertionError("must not run")))
    state = {**_probe_state(), "probe_plan": {"probes": [{"probe_type": "rm_rf", "path": "/"}]}}
    out = graph.run_probes_node(state)
    assert out.update["phase"] == "codegen_probe_failed" and out.goto == "aggregate"


def test_aggregate_never_calls_the_llm(monkeypatch):
    import datetime as dt
    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "invoke_with_backoff",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("LLM called")))
    state = {**_probe_state(), "started_at": dt.datetime(2026, 1, 1, tzinfo=dt.UTC).isoformat()}
    cmd = graph.aggregate_node(state)
    assert cmd.goto == "report" and cmd.update["phase"] == "aggregated"


def test_there_is_no_summarize_node_the_report_follows_aggregate():
    nodes = graph.build_graph().get_graph().nodes
    assert "summarize" not in nodes and "summarize" not in graph.NODE_NAMES
    assert set(graph.command_destinations(graph.aggregate_node)) == {"report"}


# ---------------------------------------------------------------- sast vs sandbox_check
def _auth_state():
    return {**_probe_state(), "crawled_pages": ["https://example.com/"]}


def _sent(cmd) -> list[str]:
    return [s.node for s in cmd.goto]


@pytest.mark.parametrize("enabled, expected", [(True, "sandbox_check"), (False, "sast")])
def test_code_steps_skip_sast_while_the_sandbox_check_is_on(monkeypatch, enabled, expected):
    monkeypatch.setattr(graph.settings, "sandbox_check_enabled", enabled)
    monkeypatch.setattr(graph, "authenticate",
                        SimpleNamespace(invoke=lambda args: SimpleNamespace(update={"phase": "auth_complete"})))
    assert graph.auth_node(_auth_state()).goto == "code_source"
    assert _sent(graph.code_source_node(_auth_state())) == [expected, "dast"]   # no code: no code_sast
    assert graph.code_sast_node(_auth_state()).goto == "plan_probes"            # nothing to analyse


def test_code_source_sends_the_scans_out_in_parallel_with_its_own_update(monkeypatch):
    monkeypatch.setattr(graph.settings, "sandbox_check_enabled", True)
    monkeypatch.setattr(graph.code_source, "pre_code_checks", lambda **_k: [{"name": "x", "passed": True}])
    monkeypatch.setattr(graph.code_source, "resolve_answer", lambda *_a, **_k: {
        "code_source": {"status": "ready", "upload_id": "0" * 32}, "red_flags": ["note from code_source"]})
    state = {**_auth_state(), "scan_scope": "website_and_code", "red_flags": ["earlier"],
             "target": {**_auth_state()["target"], "upload_id": "0" * 32}}
    cmd = graph.code_source_node(state)
    assert _sent(cmd) == ["code_sast", "sandbox_check", "dast"]
    for send in cmd.goto:  # every branch starts from the same input: the state + code_source's update
        assert send.arg["code_source"]["upload_id"] == "0" * 32
        assert send.arg["red_flags"] == ["earlier", "note from code_source"]


def test_parallel_branches_run_together_and_the_join_runs_once():
    """Send fan-out + deferred join on the real reducers: phase / notes written by all branches in
    one step do not conflict, findings add up, plan_probes runs once after the slowest branch."""
    import threading
    import time

    from langgraph.graph import END, START, StateGraph

    running, peak, joins = set(), [0], []
    lock = threading.Lock()

    def branch(name, delay):
        def run(state):
            with lock:
                running.add(name)
                peak[0] = max(peak[0], len(running))
            time.sleep(delay)
            with lock:
                running.discard(name)
            return graph.Command(update={"phase": f"{name}_done", "notes": f"{name} ran.",
                                         "findings": [{"title": name}]}, goto="plan_probes")
        return run

    g = StateGraph(graph.AgentState)
    g.add_node("fan", lambda s: graph.Command(goto=[graph.Send(n, s) for n in ("code_sast", "sandbox_check",
                                                                               "dast")]))
    g.add_node("code_sast", branch("code_sast", 0.3))
    g.add_node("sandbox_check", branch("sandbox_check", 0.3))
    g.add_node("dast", branch("dast", 0.3))
    g.add_node("plan_probes", lambda s: joins.append(sorted(f["title"] for f in s["findings"])) or {},
               defer=True)
    g.add_edge(START, "fan")
    g.add_edge("plan_probes", END)
    out = g.compile().invoke({"findings": []}, {"max_concurrency": 4})
    assert peak[0] == 3                                   # all three at the same time
    assert joins == [["code_sast", "dast", "sandbox_check"]]  # one join, after all three
    assert all(f"{n} ran." in out["notes"] for n in ("code_sast", "sandbox_check", "dast"))


@pytest.mark.parametrize("cpus, expected", [(None, 1), (1, 1), (2, 2), (4, 4), (32, 4)])
def test_max_concurrency_follows_the_cpu_count_between_one_and_four(monkeypatch, cpus, expected):
    monkeypatch.setattr(graph.os, "cpu_count", lambda: cpus)
    cfg = graph.run_config("s1")
    assert cfg["max_concurrency"] == expected and cfg["configurable"]["thread_id"] == "s1"
    assert cfg["recursion_limit"] == graph.recursion_limit()


def test_failed_sandbox_check_falls_back_to_in_process_js_sast(monkeypatch):
    monkeypatch.setattr(graph.settings, "sandbox_check_enabled", True)
    monkeypatch.setattr(graph, "run_sandbox_check", SimpleNamespace(invoke=lambda args: SimpleNamespace(
        update={"phase": "sandbox_check_failed", "red_flags": ["Sandbox check failed: boom"]})))
    monkeypatch.setattr(graph, "run_sast_on_client_assets", SimpleNamespace(invoke=lambda args: SimpleNamespace(
        update={"findings": [{"title": "JS_EVAL"}], "notes": "scanned"})))
    cmd = graph.sandbox_check_node(_auth_state())
    assert cmd.goto == "plan_probes" and cmd.update["findings"] == [{"title": "JS_EVAL"}]
    assert any("in-process" in f for f in cmd.update["red_flags"])


def test_sandbox_analyzer_has_the_insert_adjacent_html_rule():
    from scopeguard.engine import JS_RECOMMENDATIONS, JS_RULES
    rule = next(r for r in JS_RULES if r[0] == "JS_INSERT_ADJACENT_HTML")
    assert rule[1].search("el.insertAdjacentHTML('beforeend', userHtml)")
    assert "JS_INSERT_ADJACENT_HTML" in JS_RECOMMENDATIONS
