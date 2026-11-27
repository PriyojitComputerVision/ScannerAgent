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
        # human in the loop before any request: website + code / website only -> recon,
        # code only -> straight to the code steps, which then end in aggregate
        ("choose_scope", "recon"), ("choose_scope", "code_source"),
        ("code_source", "aggregate"), ("code_sast", "aggregate"),
        ("recon", "auth"), ("auth", "code_source"),
        # human in the loop: auth pauses in auth_challenge for SSO / MFA, then continues
        ("auth", "auth_challenge"), ("auth_challenge", "code_source"),
        # human in the loop at the SAST step: code_source pauses for code files / a .zip / a git
        # link; code_sast analyses that code in the sandbox, then the website's JavaScript SAST
        ("code_source", "code_sast"), ("code_source", "sast:run_sast"), ("code_source", "sandbox_check"),
        ("code_sast", "sast:run_sast"), ("code_sast", "sandbox_check"),
        ("sast:run_sast", "sandbox_check"),
        ("sandbox_check", "dast"), ("dast", "plan_probes"), ("plan_probes", "run_probes"),
        ("plan_probes", "aggregate"), ("run_probes", "aggregate"),
        ("aggregate", "summarize"), ("summarize", "report"), ("report", "audit"),
        ("audit", "__end__"),  # the audit record is the last step of every run
        # safety stop (AGENT_MAX_ITERATIONS): any step can jump to aggregate
        ("recon", "aggregate"), ("dast", "aggregate"), ("aggregate", "audit"),
    }
    assert expected <= edges
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
    assert cmd.goto == "summarize" and cmd.update["phase"] == "aggregated"


def test_summarize_safety_stop_goes_to_report_not_back_to_aggregate():
    run = graph.with_iteration_limit("summarize", graph.summarize_node)
    assert set(graph.command_destinations(run)) == {"report"}
    cmd = run({"node_runs": {"summarize": graph.settings.agent_max_iterations}})
    assert cmd.goto == "report" and cmd.update["phase"] == "iteration_limit"


# ---------------------------------------------------------------- sast vs sandbox_check
def _auth_state():
    return {**_probe_state(), "crawled_pages": ["https://example.com/"]}


@pytest.mark.parametrize("enabled, expected", [(True, "sandbox_check"), (False, "sast")])
def test_code_steps_skip_sast_while_the_sandbox_check_is_on(monkeypatch, enabled, expected):
    monkeypatch.setattr(graph.settings, "sandbox_check_enabled", enabled)
    monkeypatch.setattr(graph, "authenticate",
                        SimpleNamespace(invoke=lambda args: SimpleNamespace(update={"phase": "auth_complete"})))
    assert graph.auth_node(_auth_state()).goto == "code_source"
    assert graph.code_source_node(_auth_state()).goto == expected   # no code asked for or named
    assert graph.code_sast_node(_auth_state()).goto == expected     # nothing to analyse


def test_failed_sandbox_check_falls_back_to_in_process_js_sast(monkeypatch):
    monkeypatch.setattr(graph.settings, "sandbox_check_enabled", True)
    monkeypatch.setattr(graph, "run_sandbox_check", SimpleNamespace(invoke=lambda args: SimpleNamespace(
        update={"phase": "sandbox_check_failed", "red_flags": ["Sandbox check failed: boom"]})))
    monkeypatch.setattr(graph, "run_sast_on_client_assets", SimpleNamespace(invoke=lambda args: SimpleNamespace(
        update={"findings": [{"title": "JS_EVAL"}], "notes": "scanned"})))
    cmd = graph.sandbox_check_node(_auth_state())
    assert cmd.goto == "dast" and cmd.update["findings"] == [{"title": "JS_EVAL"}]
    assert any("in-process" in f for f in cmd.update["red_flags"])


def test_sandbox_analyzer_has_the_insert_adjacent_html_rule():
    from scopeguard.engine import JS_RECOMMENDATIONS, JS_RULES
    rule = next(r for r in JS_RULES if r[0] == "JS_INSERT_ADJACENT_HTML")
    assert rule[1].search("el.insertAdjacentHTML('beforeend', userHtml)")
    assert "JS_INSERT_ADJACENT_HTML" in JS_RECOMMENDATIONS
