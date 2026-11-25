"""Golden dataset: schema, deterministic data checks, model checks, judge gate, drift verdict.

Offline by default (judge and generator are stubbed). Set GOLDEN_LIVE=1 with a real
GROQ_API_KEY to also run the full evaluation against the real LLM judge.
"""
from __future__ import annotations

import json
import os

import pytest

from pentest_agent.evals import golden
from pentest_agent.graph import SummaryResult
from pentest_agent.schemas import Finding
from scopeguard import citations

DATASET = golden.load_dataset()


def _case(case_id):
    return next(c for c in DATASET.cases if c.id == case_id)


def _good_judge(score=8.5):
    def judge(messages):
        assert "CANDIDATE" in messages[-1].content and "SOURCES" in messages[-1].content
        return golden.JudgeVerdict(faithfulness=score, coverage=score, citation_accuracy=score,
                                   clarity=score, overall=score, rationale="grounded")
    return judge


def _summarizer(text):
    """Stub generator returning `text` as if the LLM wrote it, grounded like production."""
    def summarize(target_url, profile, pages_crawled, findings, red_flags):
        sources = citations.build_sources(findings)
        clean, used, invalid = citations.sanitize(text, sources, (target_url,))
        return SummaryResult(text=clean, sources=sources, raw_llm_output=text, used_citations=used,
                             invalid_citations=invalid, llm_used=True, fallback_used=False)
    return summarize


# ---------------------------------------------------------------- dataset file
def test_dataset_file_is_valid_and_covers_both_kinds():
    assert DATASET.thresholds.min_judge_score >= 7.0
    kinds = {c.kind for c in DATASET.cases}
    assert kinds == {"simulated_scan", "static_findings"}
    assert DATASET.thresholds.judge_runs >= 3, "a single judge call is too noisy to decide drift"
    for c in DATASET.cases:
        assert c.reference_summary.strip()
        assert golden.reference_is_current(c), f"{c.id}: review the reference, then --approve-references"
        if c.kind == "static_findings":
            assert c.baseline.input_sha256 == golden.fingerprint(c), f"{c.id}: stale fingerprint"
        else:
            assert c.baseline.titles and c.baseline.severity_counts, f"{c.id}: baseline not recorded"


def test_dataset_rejects_duplicate_ids_and_bad_scores():
    raw = json.loads(golden.DEFAULT_DATASET.read_text(encoding="utf-8"))
    raw["cases"].append(raw["cases"][0])
    with pytest.raises(ValueError):
        golden.GoldenDataset.model_validate(raw)
    with pytest.raises(ValueError):
        golden.JudgeVerdict(faithfulness=11, coverage=1, citation_accuracy=1, clarity=1, overall=1, rationale="x")


# ---------------------------------------------------------------- data side (real pipeline)
@pytest.mark.parametrize("case_id", [c.id for c in DATASET.cases])
def test_current_pipeline_matches_golden_data_baseline(case_id):
    case = _case(case_id)
    obs = golden.observed_features(golden.collect_case_data(case))
    failed = [c for c in golden.data_checks(case, obs) if not c.passed]
    assert not failed, failed


def test_changed_scanner_output_is_detected_as_data_drift():
    case = _case("sim-standard")
    obs = golden.observed_features(golden.collect_case_data(case))
    obs["titles"] = [t for t in obs["titles"] if "SQL" not in t and "traversal" not in t]
    obs["severity_counts"]["high"] -= 2
    names = {c.name for c in golden.data_checks(case, obs) if not c.passed}
    assert {"required_titles", "severity_histogram"} <= names


def test_edited_static_input_is_detected_as_data_drift():
    case = _case("static-two-findings").model_copy(deep=True)
    case.input_findings[0]["severity"] = "high"
    obs = golden.observed_features(golden.collect_case_data(case))
    assert not next(c for c in golden.data_checks(case, obs) if c.name == "input_fingerprint").passed


# ---------------------------------------------------------------- model side
GOOD_TWO = ("An automated standard-profile test crawled 3 in-scope pages and produced two findings, none "
            "critical or high. A medium-severity issue: the search parameter is reflected without output "
            "encoding, which may allow cross-site scripting [S1]. A low-severity hardening gap: responses "
            "omit the X-Content-Type-Options header [S2]. No red flags were raised. Encode untrusted output, "
            "add a Content-Security-Policy and send nosniff; validate the XSS manually before disclosure.")


def test_grounded_summary_passes_model_checks_and_judge():
    case = _case("static-two-findings")
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True, judge=_good_judge(),
                             summarize=_summarizer(GOOD_TWO))
    assert r.data_ok and r.model_ok, [c for c in r.model_checks if not c.passed]
    assert r.judge_score == 8.5


@pytest.mark.parametrize("bad_text,failed_check", [
    (GOOD_TWO + " See https://evil.example/report.", "no_invented_urls"),
    (GOOD_TWO.replace("A low-severity hardening gap: responses omit the X-Content-Type-Options header [S2]. ", ""),
     "required_findings_reported"),
    (GOOD_TWO + " This could lead to a data breach.", "must_not_mention"),
    ("XSS [S1] and headers [S2].", "length_words"),
])
def test_hallucinated_or_ungrounded_summary_fails(bad_text, failed_check):
    case = _case("static-two-findings")
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True, judge=_good_judge(),
                             summarize=_summarizer(bad_text))
    assert failed_check in {c.name for c in r.model_checks if not c.passed}
    assert not r.model_ok


@pytest.mark.parametrize("bad_text,failed_check,detail", [
    # valid ids, wrong severity: S2 is low, cited in a sentence about medium findings
    (GOOD_TWO.replace("cross-site scripting [S1]", "cross-site scripting [S1, S2]"),
     "severity_attribution", "S2 is low"),
    (GOOD_TWO.replace("none critical or high", "one critical and two medium"),
     "severity_counts_grounded", "'two medium' but SOURCES have 1 medium"),
    (GOOD_TWO.replace("none critical or high", "no medium findings"),
     "severity_counts_grounded", "'no medium'"),
])
def test_wrong_severity_claims_fail_deterministically(bad_text, failed_check, detail):
    case = _case("static-two-findings")
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True, judge=_good_judge(),
                             summarize=_summarizer(bad_text))
    failed = {c.name: c.detail for c in r.model_checks if not c.passed}
    assert failed_check in failed and detail in failed[failed_check], failed
    assert not r.model_ok


def test_severity_checks_allow_subsets_and_mixed_sentences():
    sources = {"S1": {"severity": "high"}, "S2": {"severity": "high"}, "S3": {"severity": "low"},
               "S4": {"severity": "info"}}
    text = ("The scan found two high-severity issues, one of them in two high places [S1]. Fix the high "
            "issue [S2] before the low one [S3]. Lower-severity items include a header gap [S4]. "
            "Nothing else was cited [S3].")
    assert golden.severity_mismatches(text, sources) == []
    assert golden.severity_number_errors(text, sources) == []


def test_severity_check_splits_markdown_paragraphs():
    sources = {"S1": {"severity": "high"}, "S16": {"severity": "medium"}, "S22": {"severity": "low"},
               "S29": {"severity": "info"}}
    # The format of a real gpt-oss answer: markdown paragraphs, non-breaking hyphens.
    text = ("The scan identified 1 high‑severity finding, 1 medium, 1 low and 1 informational item.  \n\n"
            "**High‑severity findings (1)** include JavaScript patterns [S1, S16].  \n\n"
            "**Medium‑severity findings (1)** include a form without a token [S22]  \n"
            "- **Low‑severity findings** cover header omissions [S29]")
    wrong = golden.severity_mismatches(text, sources)
    assert [w.split()[0] for w in wrong] == ["S16", "S22", "S29"], wrong


def test_stale_reference_is_not_evaluated_not_model_drift():
    case = _case("static-two-findings").model_copy(deep=True)
    case.reference_summary += " Edited without review."  # stamp no longer matches
    calls = []
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True,
                             judge=lambda m: calls.append(m) or _good_judge()(m),
                             summarize=_summarizer(GOOD_TWO))
    assert not calls and not r.model_evaluated and "approve-references" in r.model_error
    assert golden.classify([r])[0] is golden.Verdict.NOT_EVALUATED


def test_approve_references_stamps_dataset(tmp_path):
    p = tmp_path / "ds.json"
    raw = json.loads(golden.DEFAULT_DATASET.read_text(encoding="utf-8"))
    raw["cases"][0]["reference_summary"] += " Edited."
    p.write_text(json.dumps(raw), encoding="utf-8")
    assert not golden.reference_is_current(golden.load_dataset(p).cases[0])
    golden.approve_references(p)
    assert all(golden.reference_is_current(c) for c in golden.load_dataset(p).cases)


def test_judge_median_ignores_one_outlier_run():
    scores = iter([2.0, 9.0, 8.0])

    def judge(messages):
        s = next(scores)
        return golden.JudgeVerdict(faithfulness=s, coverage=s, citation_accuracy=s, clarity=s, overall=s,
                                   rationale=f"run {s}")
    case = _case("static-two-findings")
    r = golden.evaluate_case(case, golden.Thresholds(min_judge_score=7, judge_runs=3), use_llm=True,
                             judge=judge, summarize=_summarizer(GOOD_TWO))
    assert r.judge_scores == [2.0, 9.0, 8.0] and r.judge_score == 8.0 and r.judge_passed
    assert r.judge.rationale == "run 8.0"


def test_judge_sees_every_source_and_severity_counts():
    findings = [{"title": f"Missing header {i}", "severity": "low",
                 "affected_url": "https://golden.example.test/"} for i in range(70)]
    sources = citations.build_sources(findings)
    summary = SummaryResult(text="x", sources=sources, raw_llm_output="x [S70]", used_citations=["S70"],
                            invalid_citations=[], llm_used=True, fallback_used=False)
    data = {"target_url": "https://golden.example.test", "pages_crawled": 1, "red_flags": []}
    msg = golden.judge_messages(_case("static-two-findings"), data, summary)[-1].content
    assert "[S70]" in msg and "more lower-severity sources not shown" not in msg
    assert "Findings: 70 in total (critical 0, high 0, medium 0, low 70, info 0)" in msg


def test_judge_score_below_threshold_is_model_drift():
    case = _case("static-two-findings")
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True, judge=_good_judge(6.5),
                             summarize=_summarizer(GOOD_TWO))
    assert r.judge_passed is False and not r.model_ok
    verdict, parts = golden.classify([r])
    assert verdict is golden.Verdict.MODEL_DRIFT and parts["model_drift_cases"] == [case.id]


def test_correct_results_without_citations_are_not_drift():
    """Drift is about the reported results: the right findings at the right severities pass even
    when the model left out the [Sn] tags (and production fell back to its cited summary)."""
    plain = citations.CITATION_RE.sub("", GOOD_TWO)

    def uncited(**kw):
        s = citations.build_sources(kw["findings"])
        return SummaryResult(text="fallback", sources=s, raw_llm_output=plain, llm_used=True,
                             fallback_used=True, fallback_reason="LLM output had no valid source citations")
    case = _case("static-two-findings")
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True, judge=_good_judge(),
                             summarize=lambda **kw: uncited(**kw))
    by = {c.name: c for c in r.model_checks}
    assert by["required_findings_reported"].passed and by["llm_answer_produced"].passed
    assert not by["citations_present"].passed and by["citations_present"].kind == "citation"
    assert not by["citations_present"].blocking and r.model_ok and r.status == "ok"


def test_unknown_citation_id_is_reported_but_not_drift():
    case = _case("static-two-findings")
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True, judge=_good_judge(),
                             summarize=_summarizer(GOOD_TWO + " See also [S7]."))
    bad = next(c for c in r.model_checks if c.name == "no_unknown_citation_ids")
    assert not bad.passed and not bad.blocking and r.model_ok


def test_missing_required_finding_is_drift_even_with_citations():
    case = _case("static-two-findings")
    text = GOOD_TWO.replace("A low-severity hardening gap: responses omit the X-Content-Type-Options header [S2]. ",
                            "")
    r = golden.evaluate_case(case, DATASET.thresholds, use_llm=True, judge=_good_judge(),
                             summarize=_summarizer(text))
    assert not r.model_ok and r.status == "model_drift"
    detail = next(c.detail for c in r.model_checks if c.name == "required_findings_reported")
    assert "X-Content-Type-Options" in detail


def test_named_finding_counts_as_reported():
    title_to_ids = {"Possible SQL injection": {"S1"}, "Exposed environment file": {"S2"}}
    assert golden.finding_reported("Possible SQL injection", "The login form is SQL-injectable.", set(), title_to_ids)
    assert golden.finding_reported("Exposed environment file", "An .env environment file is public.", set(),
                                   title_to_ids)
    assert not golden.finding_reported("Exposed environment file", "Cookies lack flags.", set(), title_to_ids)
    assert golden.finding_reported("Exposed environment file", "see [S2]", {"S2"}, title_to_ids)


# ---------------------------------------------------------------- strict verdict
def _result(case_id, data_ok=True, model_ok=True, evaluated=True):
    r = golden.CaseResult(case_id=case_id,
                          data_checks=[golden.Check(name="d", passed=data_ok)],
                          model_checks=[golden.Check(name="m", passed=model_ok)] if evaluated else [],
                          judge_passed=True if evaluated else None, model_evaluated=evaluated)
    return r


@pytest.mark.parametrize("results,expected", [
    ([_result("a"), _result("b")], golden.Verdict.NO_DRIFT),
    ([_result("a", data_ok=False), _result("b")], golden.Verdict.DATA_DRIFT),
    ([_result("a"), _result("b", model_ok=False)], golden.Verdict.MODEL_DRIFT),
    ([_result("a", data_ok=False), _result("b", model_ok=False)], golden.Verdict.DATA_AND_MODEL_DRIFT),
    # model failing only where data drifted is NOT attributed to the model
    ([_result("a", data_ok=False, model_ok=False), _result("b")], golden.Verdict.DATA_DRIFT),
    ([_result("a", evaluated=False)], golden.Verdict.NOT_EVALUATED),
])
def test_verdict_truth_table(results, expected):
    verdict, parts = golden.classify(results)
    assert verdict is expected
    if expected is golden.Verdict.DATA_DRIFT and len(results) == 2 and not results[0].model_ok:
        assert parts["unattributed_model_failures"] == ["a"]
    assert golden.EXIT_CODES[verdict] in (0, 2, 10, 20, 30)


def test_full_offline_run_writes_results(tmp_path):
    texts = {"static-two-findings": GOOD_TWO}

    def summarize(**kw):
        f = kw["findings"]
        text = texts.get("static-two-findings") if len(f) == 2 else citations.deterministic_summary(
            kw["target_url"], citations.build_sources(f), kw["pages_crawled"], len(kw["red_flags"])) + (
            " This automated result should be validated manually before any disclosure or remediation "
            "decision, and a periodic re-test is recommended.")
        return _summarizer(text)(**kw)

    ds = DATASET.model_copy(deep=True)
    ds.cases = [c for c in ds.cases if c.kind == "static_findings"]
    for c in ds.cases:
        c.expectations.must_report_titles = []
        c.expectations.must_not_mention = []
    rep = golden.run(ds, use_llm=True, judge=_good_judge(9), summarize=summarize)
    out = golden.write_results(rep, tmp_path)
    assert rep.verdict is golden.Verdict.NO_DRIFT and rep.exit_code == 0, rep.reasons
    assert (out / "golden_report.json").exists() and (out / "golden_report.md").exists()
    assert json.loads((tmp_path / "latest.json").read_text(encoding="utf-8"))["verdict"] == "NO_DRIFT"


def test_no_llm_is_not_evaluated_not_drift(tmp_path):
    ds = DATASET.model_copy(deep=True)
    ds.cases = [c for c in ds.cases if c.kind == "static_findings"]
    assert golden.run(ds, use_llm=False).verdict is golden.Verdict.NOT_EVALUATED
    assert golden.run(ds, use_llm=False, require_model=False).verdict is golden.Verdict.NO_DRIFT


# ---------------------------------------------------------------- live (opt-in)
@pytest.mark.skipif(os.getenv("GOLDEN_LIVE") != "1", reason="set GOLDEN_LIVE=1 and GROQ_API_KEY for live judge")
def test_live_golden_dataset_with_llm_judge():
    from pentest_agent.llm import llm_available

    assert llm_available(), "GOLDEN_LIVE=1 requires a real GROQ_API_KEY"
    rep = golden.run(DATASET, use_llm=True)
    assert rep.verdict is golden.Verdict.NO_DRIFT, rep.reasons
    assert all(c.judge_score >= DATASET.thresholds.min_judge_score for c in rep.cases)


# ---------------------------------------------------------------- regressions from the live run
def test_url_in_markdown_bold_is_not_invented():
    assert citations.find_urls("scan of **https://clean.example.test** done.") == ["https://clean.example.test"]
    clean, _, _ = citations.sanitize("Target **https://clean.example.test**.", {}, ("https://clean.example.test",))
    assert "https://clean.example.test" in clean


def test_empty_llm_answer_is_retried_then_reported(monkeypatch):
    from types import SimpleNamespace

    from pentest_agent import graph

    answers = iter(["", "Medium XSS [S1]."])
    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "get_llm", lambda **_: None)
    monkeypatch.setattr(graph, "invoke_with_backoff", lambda *_a, **_k: SimpleNamespace(content=next(answers)))
    f = [Finding.model_validate(x) for x in _case("static-two-findings").input_findings]
    r = graph.generate_executive_summary("https://golden.example.test", "standard", 3, f, [], use_cache=False)
    assert r.raw_llm_output == "Medium XSS [S1]." and not r.fallback_used

    monkeypatch.setattr(graph, "invoke_with_backoff", lambda *_a, **_k: SimpleNamespace(content=""))
    r = graph.generate_executive_summary("https://golden.example.test", "standard", 3, f, [], use_cache=False)
    assert r.fallback_used and r.fallback_reason == "LLM returned an empty answer"


def test_judge_falls_back_to_function_calling(monkeypatch):
    from pentest_agent import llm

    calls = []

    class FakeLLM:
        def with_structured_output(self, schema, method):
            calls.append(method)

            class Runnable:
                def invoke(self, messages):
                    if method == "json_schema":
                        raise RuntimeError("json_schema not supported by this model")
                    return {"faithfulness": 8, "coverage": 8, "citation_accuracy": 8, "clarity": 8,
                            "overall": 8, "rationale": "ok"}
            return Runnable()

    monkeypatch.setattr(llm, "get_judge_llm", lambda: FakeLLM())
    v = golden.default_judge([])
    assert isinstance(v, golden.JudgeVerdict) and v.overall == 8
    assert calls == ["json_schema", "function_calling"]


def test_judge_uses_json_schema_first(monkeypatch):
    """gpt-oss sometimes calls the tool as 'judgeVerdict' (Groq 400 tool_use_failed);
    json_schema must be tried first so that path is normally never hit."""
    from pentest_agent import llm

    calls = []

    class FakeLLM:
        def with_structured_output(self, schema, method):
            calls.append(method)

            class Runnable:
                def invoke(self, messages):
                    return {"faithfulness": 9, "coverage": 9, "citation_accuracy": 9, "clarity": 9,
                            "overall": 9, "rationale": "ok"}
            return Runnable()

    monkeypatch.setattr(llm, "get_judge_llm", lambda: FakeLLM())
    assert golden.default_judge([]).overall == 9
    assert calls == ["json_schema"]


# ------------------------------------------------------------ JWT + RBAC per run
@pytest.fixture
def golden_auth(tmp_path, monkeypatch):
    from pentest_agent import api_auth
    from pentest_agent.config import settings

    keys = tmp_path / "keys"
    monkeypatch.setattr(settings, "jwt_private_key_path", str(keys / "jwt_private.pem"))
    monkeypatch.setattr(settings, "jwt_public_key_path", str(keys / "jwt_public.pem"))
    monkeypatch.setattr(settings, "auth_client_roles", "admin")
    yield settings
    api_auth.revoked_refresh_tokens.clear()


def _static_ds():
    ds = DATASET.model_copy(deep=True)
    ds.cases = [c for c in ds.cases if c.kind == "static_findings"]
    return ds


def test_run_uses_a_fresh_verified_jwt(golden_auth, tmp_path):
    rep = golden.run(_static_ds(), use_llm=False, require_model=False, auth=True)
    assert rep.verdict is golden.Verdict.NO_DRIFT, rep.reasons
    assert rep.auth["subject"] == "golden-check" and rep.auth["roles"] == ["admin"]
    assert (tmp_path / "keys" / "jwt_private.pem").exists()          # keys created automatically
    dumped = json.dumps(rep.model_dump(mode="json"))
    assert "eyJ" not in dumped                                        # the token is never stored
    assert "Auth: fresh JWT for 'golden-check'" in golden.render_markdown(rep)


def test_run_without_permission_is_not_evaluated(golden_auth, monkeypatch):
    monkeypatch.setattr(golden_auth, "auth_client_roles", "viewer")  # viewer cannot run scans
    rep = golden.run(_static_ds(), use_llm=False, require_model=False, auth=True)
    assert rep.verdict is golden.Verdict.NOT_EVALUATED and rep.exit_code == 2
    assert all("scan:run" in (r.model_error or "") for r in rep.cases)


def test_run_auto_refreshes_a_token_near_expiry(golden_auth, monkeypatch):
    monkeypatch.setattr(golden_auth, "jwt_access_ttl_minutes", 5)    # inside the 10-min window
    rep = golden.run(_static_ds(), use_llm=False, require_model=False, auth=True)
    assert rep.verdict is golden.Verdict.NO_DRIFT and rep.auth["refreshed"] >= 1


# ---------------------------------------------------------------- attribution + consistency (pydantic)
def test_case_status_names_the_attribution():
    assert _result("a").status == "ok"
    assert _result("a", data_ok=False).status == "data_drift"
    assert _result("a", data_ok=False, model_ok=False).status == "unattributed_model_failure"
    assert _result("a", model_ok=False).status == "model_drift"
    assert _result("a", evaluated=False).status == "not_evaluated"
    dumped = _result("a", data_ok=False, model_ok=False).model_dump()
    assert dumped["status"] == "unattributed_model_failure" and dumped["data_ok"] is False  # computed fields


def _report(results, verdict=None, **over):
    v, parts = golden.classify(results)
    verdict = verdict or v
    fields = dict(dataset_version="1", generated_at="t", generator_model=None, judge_model=None,
                  min_judge_score=7, verdict=verdict, exit_code=golden.EXIT_CODES[verdict],
                  mean_judge_score=None, reasons=[], cases=results, **parts)
    fields.update(over)
    return golden.GoldenReport(**fields)


def test_data_drift_with_model_failures_is_exit_10_and_says_why():
    """The case behind 'exit 10 but it shows model drift': the model failed only where the data drifted."""
    rep = _report([_result("a", data_ok=False, model_ok=False), _result("b")])
    assert rep.verdict is golden.Verdict.DATA_DRIFT and rep.exit_code == 10
    assert not rep.model_drift and rep.unattributed_model_failures == ["a"]
    assert "NOT counted as model drift because their data drifted: a" in rep.verdict_explanation
    md = golden.render_markdown(rep)
    assert "| a | unattributed_model_failure | FAIL | FAIL (unattributed) |" in md
    assert "**Why:** DATA_DRIFT (exit 10)" in md


@pytest.mark.parametrize("over", [
    {"verdict": golden.Verdict.MODEL_DRIFT, "exit_code": 20},     # verdict contradicts the cases
    {"exit_code": 20},                                            # exit code contradicts the verdict
    {"model_drift": True},                                        # flag contradicts the cases
    {"model_drift_cases": ["a"]},
])
def test_inconsistent_report_cannot_be_built(over):
    with pytest.raises(ValueError, match="inconsistent golden report"):
        _report([_result("a", data_ok=False, model_ok=False)], **over)


def test_unattributed_reasons_are_labelled(tmp_path):
    def summarize(**kw):
        return _summarizer("High severity issue: reflected input [S1] and a missing X-Content-Type-Options "
                           "header [S2].")(**kw)   # wrong severities (a result error)

    case = _case("static-two-findings")
    drifted = case.model_copy(deep=True)
    drifted.baseline.input_sha256 = "0" * 64                              # force data drift
    drifted.baseline.reference_sha256 = golden.reference_stamp(drifted)   # reference still approved
    ds =DATASET.model_copy(update={"cases": [drifted]})
    rep = golden.run(ds, use_llm=True, judge=_good_judge(), summarize=summarize, auth=False)
    assert rep.exit_code == 10 and rep.unattributed_model_failures == [case.id]
    assert any(r.startswith("[model, unattributed: data drifted/result]") for r in rep.reasons)
    assert not any(r.startswith("[model] ") for r in rep.reasons)


# ---------------------------------------------------------------- severity self-check + repair
def _fake_llm(monkeypatch, answers):
    from types import SimpleNamespace

    from pentest_agent import graph

    calls = []
    it = iter(answers)

    def invoke(_llm, messages):
        calls.append(messages)
        return SimpleNamespace(content=next(it))

    monkeypatch.setattr(graph, "llm_available", lambda: True)
    monkeypatch.setattr(graph, "get_llm", lambda **_: None)
    monkeypatch.setattr(graph, "invoke_with_backoff", invoke)
    return graph, calls


def _two_findings():
    return [Finding.model_validate(x) for x in _case("static-two-findings").input_findings]


def test_misfiled_severities_get_one_targeted_repair(monkeypatch):
    bad = "High-severity findings include reflected input [S1] and a missing header [S2]."
    good = "A medium finding is reflected input [S1]. A low finding is a missing header [S2]."
    graph, calls = _fake_llm(monkeypatch, [bad, good])
    r = graph.generate_executive_summary("https://golden.example.test", "standard", 3, _two_findings(), [],
                                         use_cache=False)
    assert r.raw_llm_output == good and r.first_raw_llm_output == bad
    assert r.severity_repair_attempted and r.severity_issues == []
    assert len(calls) == 2 and "S1 is medium but cited in a sentence about high" in calls[1][-1].content
    assert golden.severity_mismatches(r.raw_llm_output, r.sources) == []


def test_repair_never_makes_the_answer_worse(monkeypatch):
    bad = "High finding: reflected input [S1]. A low finding is a missing header [S2]."
    worse = "High findings: reflected input [S1] and a missing header [S2]."
    graph, _ = _fake_llm(monkeypatch, [bad, worse])
    r = graph.generate_executive_summary("https://golden.example.test", "standard", 3, _two_findings(), [],
                                         use_cache=False)
    assert r.raw_llm_output == bad and r.severity_issues == ["S1 is medium but cited in a sentence about high"]


def test_correct_answer_is_not_repaired(monkeypatch):
    good = "A medium finding is reflected input [S1]. A low finding is a missing header [S2]."
    graph, calls = _fake_llm(monkeypatch, [good])
    r = graph.generate_executive_summary("https://golden.example.test", "standard", 3, _two_findings(), [],
                                         use_cache=False)
    assert len(calls) == 1 and not r.severity_repair_attempted and r.first_raw_llm_output is None


def test_repair_that_drops_citations_is_rejected(monkeypatch):
    bad = "High-severity findings include reflected input [S1] and a missing header [S2]."
    no_cites = "A medium finding is reflected input. A low finding is a missing header."
    graph, calls = _fake_llm(monkeypatch, [bad, no_cites])
    r = graph.generate_executive_summary("https://golden.example.test", "standard", 3, _two_findings(), [],
                                         use_cache=False)
    assert r.raw_llm_output == bad and r.severity_repair_attempted and r.severity_issues
    assert "never drop them" in calls[1][-1].content


def test_uncited_answer_gets_a_repair_instead_of_the_fallback(monkeypatch):
    plain = "A medium finding is reflected input. A low finding is a missing header."
    cited = "A medium finding is reflected input [S1]. A low finding is a missing header [S2]."
    graph, calls = _fake_llm(monkeypatch, [plain, cited])
    r = graph.generate_executive_summary("https://golden.example.test", "standard", 3, _two_findings(), [],
                                         use_cache=False)
    assert not r.fallback_used and r.raw_llm_output == cited and r.used_citations == ["S1", "S2"]
    assert "cites no SOURCES" in calls[1][-1].content


def test_uncited_high_finding_is_a_repair_issue():
    from pentest_agent import graph

    sources = {"S1": {"severity": "high", "title": "SQLi"}, "S2": {"severity": "low", "title": "hdr"}}
    assert graph.severity_issues("A low finding is a header [S2].", sources) == ["S1 is high but not cited"]
    assert graph.severity_issues("A high finding is SQLi [S1]. A low one [S2].", sources) == []
