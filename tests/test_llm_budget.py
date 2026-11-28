"""Every LLM call fits the model: chunk, summarize, extract; a 413 shrinks the request (tenacity)."""
from __future__ import annotations

import itertools

from langchain_core.messages import AIMessage
from langchain_text_splitters import RecursiveCharacterTextSplitter

from pentest_agent import context_fit, graph, llm_budget
from pentest_agent.config import settings
from pentest_agent.schemas import Finding
from pentest_agent.subagents import codegen_subagent
from pentest_agent.tools.probe_models import ProbePlan
from scopeguard import citations


class TooLarge(Exception):
    status_code = 413

    def __init__(self, limit=8000, requested=9683):
        super().__init__(f"Error code: 413 - Request too large for model `m` on tokens per minute (TPM): "
                         f"Limit {limit}, Requested {requested}, please reduce your message size")


def test_too_large_is_recognised_and_not_a_rate_limit():
    from pentest_agent import llm

    assert llm_budget.too_large(TooLarge())
    assert not llm_budget.too_large(RuntimeError("429 rate limit"))
    assert not llm._is_rate_limit_or_transient(TooLarge())  # waiting never helps a 413


def test_learn_limit_reads_the_413_and_lowers_the_chunk(monkeypatch):
    monkeypatch.setattr(settings, "probe_context_chunk_chars", 60000)
    monkeypatch.setattr(settings, "groq_max_tokens", 4096)
    learned = llm_budget.learn_limit("m", TooLarge(8000, 9683), sent_chars=22000)
    assert learned.limit == 8000 and learned.counts_output
    chunk = llm_budget.chunk_chars("m", overhead_chars=3000)
    # (8000 - 4096) tokens * 0.85 * (22000 / 5587 chars per token) - 3000
    assert 8000 < chunk < 11000
    assert llm_budget.chunk_chars("other-model") == 60000  # per model


def test_invoke_fitting_retries_smaller_with_tenacity():
    budgets, sent = [], []

    def build(budget):
        budgets.append(budget)
        data = "x" * min(budget, 30000)
        return [AIMessage(content="p" * 2000 + data)], len(data)

    def call(messages):
        sent.append(len(messages[0].content))
        if len(sent) == 1:
            raise TooLarge(8000, 12000)
        return "ok"

    assert llm_budget.invoke_fitting(build, call, model="m") == "ok"
    assert len(budgets) == 2 and budgets[1] < budgets[0] and sent[1] < sent[0]


def test_invoke_fitting_gives_up_after_three_tries():
    calls = []

    def call(_messages):
        calls.append(1)
        raise TooLarge()

    try:
        llm_budget.invoke_fitting(lambda b: ([AIMessage(content="x" * b)], b), call, model="m")
    except TooLarge:
        pass
    else:  # pragma: no cover
        raise AssertionError("must re-raise")
    assert len(calls) == llm_budget.MAX_FIT_TRIES


def test_other_errors_are_not_retried():
    calls = []

    def call(_m):
        calls.append(1)
        raise ValueError("bad")

    try:
        llm_budget.invoke_fitting(lambda b: ([], 0), call, model="m")
    except ValueError:
        pass
    assert calls == [1]


def test_split_chunks_is_langchains_recursive_splitter(monkeypatch):
    made = []
    real = RecursiveCharacterTextSplitter.__init__

    def spy(self, *a, **k):
        made.append(k)
        real(self, *a, **k)

    monkeypatch.setattr(RecursiveCharacterTextSplitter, "__init__", spy)
    context_fit.split_chunks("line\n" * 2000, 1000)
    assert made and made[0]["chunk_size"] == 1000 and made[0]["separators"][0] == "\n\n"
    assert made[0]["chunk_overlap"] == 100                       # 10% overlap


def test_neighbouring_chunks_overlap_by_ten_percent():
    text = "\n".join(f"finding {i:04d}: parameter p{i} reflected" for i in range(2000))
    chunks = context_fit.split_chunks(text, 8000)
    assert len(chunks) > 2 and all(len(c) <= 8000 for c in chunks)
    for a, b in itertools.pairwise(chunks):
        shared = b.split("\n")[0]
        assert shared in a                                       # b starts with lines from the end of a
        tail = a[a.index(shared):]
        assert 0.07 * 8000 <= len(tail) <= 0.10 * 8000           # ~10% (whole lines only)


def test_planner_413_rechunks_and_does_not_try_the_second_method(monkeypatch):
    monkeypatch.setattr(codegen_subagent, "llm_available", lambda: True)
    monkeypatch.setattr(settings, "probe_context_chunk_chars", 60000)
    methods, sizes = [], []

    class FakeLLM:
        def with_structured_output(self, schema, method):
            methods.append(method)
            return self

    def fake_invoke(_llm, messages):
        sizes.append(sum(len(str(m.content)) for m in messages))
        if len(sizes) == 1:
            raise TooLarge(8000, 9683)
        return ProbePlan(probes=[{"probe_type": "security_headers", "path": "/", "reason": "r"}])

    monkeypatch.setattr(codegen_subagent, "get_llm", lambda **_: FakeLLM())
    monkeypatch.setattr(codegen_subagent, "invoke_with_backoff", fake_invoke)
    monkeypatch.setattr(context_fit, "llm_ready", lambda *_a, **_k: False)  # chunk summaries: deterministic
    findings = "\n".join(f"[high] Finding {i}: reflected q{i} on /search?q{i}=x" for i in range(800))
    plan = codegen_subagent.generate_probe_plan(
        session_id="s", target_url="https://app.example.com/", allowed_domains=["app.example.com"],
        findings_summary=findings, crawled_pages=["https://app.example.com/search?q=1"])
    assert plan.probes[0].probe_type.value == "security_headers"
    assert methods == ["json_schema", "json_schema"]          # no function_calling after a 413
    assert len(sizes) == 2 and sizes[1] < sizes[0]
    assert llm_budget.learned(settings.groq_model).limit == 8000


def _sources(n_high=40, n_low=200):
    findings = ([{"title": f"Reflected XSS in q{i}", "severity": "high",
                  "affected_url": f"https://app.example.com/s?q{i}=1"} for i in range(n_high)]
                + [{"title": "Missing header X-Frame-Options", "severity": "low",
                    "affected_url": f"https://app.example.com/p{i}"} for i in range(n_low)])
    return citations.build_sources(findings)


def test_fit_sources_keeps_every_id_without_llm(monkeypatch):
    monkeypatch.setattr(context_fit, "llm_ready", lambda *_a, **_k: False)
    sources = _sources()
    block = context_fit.fit_sources(sources, 4000)
    assert context_fit._ids_in(block) == set(sources)
    assert "HIGH severity (40 findings" in block and "LOW severity (200 findings" in block


def test_fit_sources_extract_drops_invented_ids_and_restores_dropped_ones(monkeypatch):
    monkeypatch.setattr(context_fit, "llm_ready", lambda *_a, **_k: True)
    sources = _sources(n_high=30, n_low=0)

    def lazy_llm(_llm, _messages):
        return AIMessage(content="Reflected XSS on many parameters [S1] [S999]")

    monkeypatch.setattr("pentest_agent.llm.invoke_with_backoff", lazy_llm)
    monkeypatch.setattr("pentest_agent.llm.get_llm", lambda **_: object())
    block = context_fit.fit_sources(sources, 1500)
    assert "S999" not in block
    assert context_fit._ids_in(block) == set(sources)


def test_full_sources_block_is_unchanged_when_it_fits():
    sources = _sources(n_high=2, n_low=2)
    assert context_fit.fit_sources(sources, 8000) == citations.sources_prompt_block(sources, limit=4)


def test_executive_summary_fits_the_budget_and_shrinks_on_413(monkeypatch):
    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(settings, "probe_context_chunk_chars", 6000)
    monkeypatch.setattr(context_fit, "llm_ready", lambda *_a, **_k: False)
    sizes = []

    def fake_invoke(_llm, messages):
        sizes.append(sum(len(str(m.content)) for m in messages))
        if len(sizes) == 1:
            raise TooLarge(4000, 6000)
        return AIMessage(content="High: reflected XSS [S1].")

    monkeypatch.setattr(graph, "invoke_with_backoff", fake_invoke)
    monkeypatch.setattr(graph, "get_llm", lambda **_: object())
    findings = [Finding(title=f"Reflected XSS in q{i}", severity="high", category="Cross-Site Scripting",
                        affected_url=f"https://app.example.com/s?q{i}=1", description="d",
                        source="dast") for i in range(300)]
    r = graph.generate_executive_summary("https://app.example.com", "standard", 3, findings, [],
                                         use_cache=False)
    assert r.llm_used and len(sizes) >= 2 and sizes[1] < sizes[0] and sizes[0] < 6000 + 4000
    assert "[S1]" in r.text or r.fallback_used


def test_run_summary_chunks_and_wraps_a_long_transcript(monkeypatch):
    monkeypatch.setattr(settings, "probe_context_chunk_chars", 3000)
    monkeypatch.setattr(context_fit, "llm_ready", lambda *_a, **_k: False)
    seen = []

    def fake_invoke(_llm, messages):
        seen.append(messages)
        return AIMessage(content="condensed")

    monkeypatch.setattr(graph, "invoke_with_backoff", fake_invoke)
    monkeypatch.setattr(graph, "get_llm", lambda **_: object())
    msgs = [AIMessage(content=f"[high] step {i}: " + "detail " * 40) for i in range(200)]
    assert graph.summarize_transcript(msgs) == "condensed"
    human = seen[0][-1].content
    assert "<<<UNTRUSTED" in human and len(human) < 3000 + 800


def test_many_distinct_titles_collapse_to_id_ranges_within_budget(monkeypatch):
    monkeypatch.setattr(context_fit, "llm_ready", lambda *_a, **_k: False)
    sources = _sources(n_high=300, n_low=0)        # 300 different titles: no grouping possible
    block = context_fit.fit_sources(sources, 3000)
    assert context_fit._ids_in(block) == set(sources) and len(block) <= 3200
    assert "[S1-S200], [S201-S300]" in block


def test_summarizes_recursively_until_one_chunk_with_nothing_left_out(monkeypatch):
    monkeypatch.setattr(context_fit, "llm_ready", lambda *_a, **_k: True)
    calls = []

    def fake_summary(chunk, *, limit, **_k):  # a model that answers longer than asked: still converges
        calls.append(len(chunk))
        return chunk[: limit * 2], True

    text = "\n".join(f"[medium] finding {i}: parameter p{i} on /page/{i}?p{i}=1 " + "evidence " * 10
                     for i in range(5000))                       # ~500k characters
    stats = context_fit.FitStats()
    out = context_fit.fit_text(text, 8000, prompt="probe_context_summary", label="findings",
                               stats=stats, summarize=fake_summary)
    assert len(out) <= 8000 and stats.rounds >= 2
    assert not any("left out" in n or "cut" in n for n in stats.notes)
    assert all(size <= 8000 for size in calls)                   # every chunk from the splitter fits
