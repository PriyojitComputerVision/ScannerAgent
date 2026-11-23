from __future__ import annotations

from pentest_agent.subagents import codegen_subagent as cg
from pentest_agent.tools.probe_models import MAX_PROBES, ProbePlan, ProbeType


def test_default_plan_has_baseline_and_observed_params():
    plan = cg.default_probe_plan(["https://x.test/search?q=1", "https://x.test/p?id=2&id=3"])
    kinds = [p.probe_type for p in plan.probes]
    assert ProbeType.SECURITY_HEADERS in kinds and ProbeType.CORS in kinds
    reflected = {(p.path, p.query_parameter) for p in plan.probes if p.probe_type == ProbeType.REFLECTED_MARKER}
    assert reflected == {("/search", "q"), ("/p", "id")}
    assert len(plan.probes) <= MAX_PROBES


def test_plan_falls_back_without_llm(monkeypatch):
    monkeypatch.setattr(cg, "llm_available", lambda: False)
    plan = cg.generate_probe_plan(session_id="s", target_url="https://x.test", allowed_domains=["x.test"],
                                  findings_summary="[]", crawled_pages=["https://x.test/s?q=1"])
    assert isinstance(plan, ProbePlan) and plan.probes


def test_plan_falls_back_when_llm_raises(monkeypatch):
    monkeypatch.setattr(cg, "llm_available", lambda: True)

    class Boom:
        def with_structured_output(self, _, **kw):
            raise RuntimeError("llm down")

    monkeypatch.setattr(cg, "get_llm", lambda temperature=0.0: Boom())
    plan = cg.generate_probe_plan(session_id="s", target_url="https://x.test", allowed_domains=["x.test"],
                                  findings_summary="[]")
    assert plan.probes  # deterministic baseline, not an empty plan


def test_plan_tries_json_schema_then_function_calling(monkeypatch):
    """gpt-oss sometimes calls the tool as 'probePlan' (Groq 400 tool_use_failed):
    json_schema is tried first, tool calling is the fallback."""
    from pentest_agent.tools.probe_models import ProbeCase, ProbeType

    calls = []
    plan = ProbePlan(probes=[ProbeCase(probe_type=ProbeType.CORS, path="/", reason="r")])

    class FakeLLM:
        def with_structured_output(self, schema, method):
            calls.append(method)
            return method

    def invoke(method, _messages):
        if method == "json_schema":
            raise RuntimeError("json_schema not supported")
        return plan

    monkeypatch.setattr(cg, "llm_available", lambda: True)
    monkeypatch.setattr(cg, "get_llm", lambda temperature=0.0: FakeLLM())
    monkeypatch.setattr(cg, "invoke_with_backoff", invoke)
    got = cg.generate_probe_plan(session_id="s", target_url="https://x.test", allowed_domains=["x.test"],
                                 findings_summary="[]")
    assert got == plan
    assert calls == ["json_schema", "function_calling"]
