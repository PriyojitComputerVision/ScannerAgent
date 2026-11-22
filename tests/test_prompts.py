"""Prompts live in a gitignored folder; a missing prompt must degrade to the
deterministic fallbacks instead of crashing."""

from __future__ import annotations

import pytest

from pentest_agent import guardrails, prompts
from pentest_agent.config import settings


def test_load_fills_placeholders():
    text = guardrails.content_injection_system_reminder()
    assert guardrails.UNTRUSTED_WRAP_START in text and guardrails.UNTRUSTED_WRAP_END in text


def test_missing_prompt_raises_and_reports_unavailable(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "prompts_dir", str(tmp_path))
    with pytest.raises(prompts.PromptMissing):
        prompts.load("executive_summary")
    assert not prompts.available("executive_summary")


def test_missing_prompts_use_deterministic_fallbacks(monkeypatch, tmp_path):
    from pentest_agent import graph
    from pentest_agent.subagents import codegen_subagent as cg

    monkeypatch.setattr(settings, "prompts_dir", str(tmp_path))
    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(cg, "llm_available", lambda: True)

    def no_llm(*a, **k):
        raise AssertionError("LLM must not be called without its prompt")

    monkeypatch.setattr(graph, "invoke_with_backoff", no_llm)
    monkeypatch.setattr(cg, "invoke_with_backoff", no_llm)

    res = graph.generate_executive_summary("https://x.test", "quick", 1, [], [])
    assert not res.llm_used and "not found" in res.fallback_reason
    plan = cg.generate_probe_plan(session_id="s", target_url="https://x.test",
                                  allowed_domains=["x.test"], findings_summary="")
    assert plan == cg.default_probe_plan(None, "https://x.test")
