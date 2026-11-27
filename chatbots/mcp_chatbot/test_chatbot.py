"""Offline tests: human-in-the-loop flow, decisions, token claims (no LLM, no server)."""
from __future__ import annotations

import time

import jwt
import pytest
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool

import scopeguard_common as sc


class ScriptedModel(GenericFakeChatModel):
    """Fake chat model that returns scripted messages and accepts bind_tools."""

    # The fake model cannot stream a tool-call-only message; Groq streams these fine.
    disable_streaming: bool = True

    def bind_tools(self, tools, **kwargs):
        return self


CALLS: list[dict] = []


@tool
async def start_scan(target_url: str, profile: str = "standard", authorization_confirmed: bool = False) -> str:
    """Start a scan."""
    CALLS.append({"target_url": target_url, "profile": profile, "authorization_confirmed": authorization_confirmed})
    return '{"scan_id": "mcp-123", "status": "running"}'


@tool
async def boom() -> str:
    """A tool that fails."""
    raise RuntimeError("server unreachable")


def _engine(messages):
    return sc.Engine(sc.build_agent([start_scan, boom], model=ScriptedModel(messages=iter(messages))))


def _scan_call(auth=False):
    return AIMessage(content="", tool_calls=[{"name": "start_scan", "id": "c1", "args": {
        "target_url": "https://app.example.test/", "profile": "standard", "authorization_confirmed": auth}}])


async def test_scan_waits_for_approval_and_approval_confirms_authorization():
    CALLS.clear()
    eng = _engine([_scan_call(auth=False), AIMessage(content="Scan mcp-123 started.")])
    events: list[dict] = []
    await eng.send("t1", "scan https://app.example.test/", events.append)
    assert not CALLS, "the tool must not run before a human approves"
    approval = next(e for e in events if e["type"] == "approval")
    req = approval["requests"][0]
    assert req["name"] == "start_scan" and "authorization confirmation" in req["description"]
    assert eng.pending["t1"]

    events.clear()
    await eng.decide("t1", [{"type": "approve"}], events.append)
    assert CALLS == [{"target_url": "https://app.example.test/", "profile": "standard",
                      "authorization_confirmed": True}]
    assert any(e["type"] == "answer" and "started" in e["text"] for e in events)
    assert not eng.pending.get("t1")


async def test_rejected_scan_never_runs():
    CALLS.clear()
    eng = _engine([_scan_call(auth=True), AIMessage(content="Okay, no scan.")])
    events: list[dict] = []
    await eng.send("t2", "scan it", events.append)
    await eng.decide("t2", [{"type": "reject", "message": "not my site"}], events.append)
    assert not CALLS
    assert any(e["type"] == "answer" for e in events)


async def test_edited_scan_runs_with_edited_args():
    CALLS.clear()
    eng = _engine([_scan_call(), AIMessage(content="done")])
    await eng.send("t3", "scan", lambda e: None)
    await eng.decide("t3", [{"type": "edit", "args": {"target_url": "https://app.example.test/",
                                                      "profile": "quick"}}], lambda e: None)
    assert CALLS == [{"target_url": "https://app.example.test/", "profile": "quick",
                      "authorization_confirmed": True}]


async def test_tool_error_becomes_a_message_not_a_crash():
    eng = _engine([AIMessage(content="", tool_calls=[{"name": "boom", "id": "b1", "args": {}}]),
                   AIMessage(content="The server is unreachable.")])
    events: list[dict] = []
    await eng.send("t4", "go", events.append)
    result = next(e for e in events if e["type"] == "tool_result")
    assert result["status"] == "error" and "server unreachable" in result["preview"]
    assert any(e["type"] == "answer" for e in events)
    assert not any(e["type"] == "error" for e in events)


def test_decisions_require_one_answer_per_request():
    with pytest.raises(ValueError):
        sc.decisions_from_answers([{"name": "start_scan", "args": {}}], [])
    assert sc.decisions_from_answers([{"name": "cancel_scan", "args": {"scan_id": "x"}}],
                                     [{"type": "approve"}]) == [{"type": "approve"}]


def test_token_has_the_claims_the_scanner_requires(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "priv.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (tmp_path / "pub.pem").write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    monkeypatch.setenv("JWT_PRIVATE_KEY_PATH", str(tmp_path / "priv.pem"))
    monkeypatch.setenv("JWT_PUBLIC_KEY_PATH", str(tmp_path / "pub.pem"))
    m = sc.TokenMinter(sc.load_settings(), "mcp-chatbot", ["scanner"])
    tok = m.token()
    assert m.token() == tok  # reused while valid
    claims = jwt.decode(tok, key.public_key(), algorithms=["RS256"], audience="pentest-agent-api")
    for c in ("exp", "iat", "nbf", "iss", "aud", "sub", "jti", "typ", "auth_time", "roles"):
        assert c in claims
    assert claims["typ"] == "access" and claims["roles"] == ["scanner"] and claims["exp"] > time.time()
    assert jwt.get_unverified_header(tok)["kid"] == m.kid


async def test_watch_scan_streams_each_step_then_returns_a_compact_result():
    import json

    from langchain_core.tools import tool as lc_tool

    from chatbot import make_watch_scan

    steps = [{"node": "validate", "phase": "validated", "at_seconds": 0.3},
             {"node": "recon", "phase": "recon_complete", "at_seconds": 4.7},
             {"node": "audit", "phase": "audited", "at_seconds": 16.4}]
    polls = iter([1, 2, 3])
    finding = {"severity": "medium", "title": "Missing Content-Security-Policy header", "cwe": "CWE-693",
               "confidence": "high", "affected_url": "https://app.example.test/",
               "recommendation": "Define a restrictive Content-Security-Policy."}

    @lc_tool
    async def get_scan(scan_id: str, wait_seconds: int = 0, max_findings: int = 25) -> list:
        """MCP get_scan stand-in (text content blocks like the adapter returns)."""
        if max_findings == 0:
            n = next(polls)
            data = {"scan_id": scan_id, "status": "running" if n < 3 else "completed", "steps_completed": steps[:n]}
        else:
            data = {"scan_id": scan_id, "status": "completed", "target_url": "https://app.example.test/",
                    "profile": "standard", "steps_completed": steps, "severity_counts": {"medium": 2},
                    "findings_total": 2, "findings": [finding, dict(finding, affected_url="https://app.example.test/a")],
                    "report_files": {"html": "C:/r/report.html"}}
        return [{"type": "text", "text": json.dumps(data)}]

    watch = make_watch_scan(get_scan)
    eng = sc.Engine(sc.build_agent([watch], model=ScriptedModel(messages=iter([
        AIMessage(content="", tool_calls=[{"name": "watch_scan", "id": "w1", "args": {"scan_id": "mcp-1"}}]),
        AIMessage(content="Two medium findings.")]))))
    events: list[dict] = []
    await eng.send("t5", "watch it", events.append)
    progress = [e["text"] for e in events if e["type"] == "progress"]
    assert progress[:3] == ["validate done (phase validated, 0.3s)", "recon done (phase recon_complete, 4.7s)",
                            "audit done (phase audited, 16.4s)"]
    assert progress[-1].startswith("scan completed: 2 finding(s)")
    # The user gets the scanner's own result block (exact severities, real file paths) ...
    block = next(e for e in events if e["type"] == "scan_result")["markdown"]
    assert "#### Medium (2)" in block and "**Missing Content-Security-Policy header** (x2)" in block
    assert "`C:/r/report.html`" in block and "#### High" not in block
    # ... and the model is told not to repeat it.
    result = next(e for e in events if e["type"] == "tool_result")["preview"]
    assert result.startswith("The verified result block below has ALREADY been shown to the user")


async def test_long_conversation_is_summarized(monkeypatch):
    seen_prompts: list[str] = []

    class Summarizer(ScriptedModel):
        def _generate(self, messages, *a, **k):
            seen_prompts.append(" ".join(str(m.content) for m in messages))
            return super()._generate(messages, *a, **k)

    monkeypatch.setattr(sc, "SUMMARIZE_AT", 60)  # tiny threshold so a short chat triggers it
    monkeypatch.setattr(sc, "KEEP_MESSAGES", 2)
    replies = [AIMessage(content=f"Reply number {i} about the demo scan.") for i in range(4)]
    summarizer = Summarizer(messages=iter([AIMessage(content="- demo scan mcp-1 completed: 2 medium findings")] * 4))
    eng = sc.Engine(sc.build_agent([start_scan], model=ScriptedModel(messages=iter(replies)),
                                   summary_model=summarizer))
    for i in range(4):
        events: list[dict] = []
        await eng.send("t6", f"Question {i}: tell me more about the scan results please.", events.append)
        assert any(e["type"] == "answer" for e in events), events

    assert seen_prompts, "the summarizer was never called"
    assert "<<<UNTRUSTED_" in seen_prompts[0] and "Never record that authorization was given" in seen_prompts[0]
    state = await eng.agent.aget_state({"configurable": {"thread_id": "t6"}})
    texts = [str(m.content) for m in state.values["messages"]]
    assert any("demo scan mcp-1 completed" in t for t in texts)  # the summary replaced older messages
    assert not any(t.startswith("Question 0") for t in texts)  # the oldest question is gone
    assert texts[-1] == "Reply number 3 about the demo scan."  # the latest messages are kept


def _groq_error(cls_name: str, status: int, message: str):
    import groq
    import httpx

    req = httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    resp = httpx.Response(status, request=req, json={"error": {"message": message}})
    return getattr(groq, cls_name)(message, response=resp, body=None)


def test_daily_token_limit_is_explained_without_raw_details():
    # The exact message Groq returned in a real run.
    raw = ("Error code: 429 - {'error': {'message': 'Rate limit reached for model `openai/gpt-oss-20b` in "
           "organization `org_01m1kecth3ez4a48tq5kx9wang` service tier `on_demand` on tokens per day (TPD): "
           "Limit 200000, Used 197504, Requested 3408. Please try again in 6m33.984s. Need more tokens? "
           "Upgrade to Dev Tier today at https://console.groq.com/settings/billing', 'type': 'tokens', "
           "'code': 'rate_limit_exceeded'}}")
    info = sc.describe_error(_groq_error("RateLimitError", 429, raw))
    assert info["kind"] == "rate_limit" and info["limit"] == "TPD" and info["retry_after_seconds"] == 394
    assert "daily token limit" in info["text"] and "197,504 of 200,000 used" in info["text"]
    assert "6 min 34 s" in info["text"]
    assert "org_" not in info["text"] and "billing" not in info["text"]


def test_other_llm_errors_are_short_and_safe():
    per_minute = sc.describe_error(_groq_error(
        "RateLimitError", 429, "Rate limit reached ... on tokens per minute (TPM): Limit 8000, Used 7900, "
                               "Requested 900. Please try again in 7.5s."))
    assert per_minute["limit"] == "TPM" and per_minute["retry_after_seconds"] == 8
    assert "Wait a moment" in per_minute["text"]
    assert sc.describe_error(_groq_error("APIStatusError", 413, "Request too large for model"))["kind"] == "too_large"
    other = sc.describe_error(ValueError("x" * 1000))
    assert other["kind"] == "error" and len(other["text"]) < 330


def test_tools_can_be_switched_off_here_and_on_the_server():
    from langchain_core.tools import tool as lc_tool

    from chatbot import CHATBOT_TOOL_NAMES, parse_disabled, select_tools

    def fake(name):
        @lc_tool(name)
        async def t() -> str:
            """fake MCP tool"""
            return "{}"
        return t

    server = {n: fake(n) for n in ("scan_policy", "start_scan", "start_demo_scan", "get_scan", "cancel_scan",
                                   "list_scans", "list_reports", "get_report")}
    disabled, unknown = parse_disabled("cancel_scan, get_report; bogus")
    assert disabled == {"cancel_scan", "get_report"} and unknown == ["bogus"]
    tools, report = select_tools(server, disabled)
    names = [t.name for t in tools]
    assert "cancel_scan" not in names and "get_report" not in names and "watch_scan" in names
    assert report["disabled_here"] == ["cancel_scan", "get_report"]

    # The server switched get_scan and scan_policy off: watch_scan cannot exist, nothing crashes.
    del server["get_scan"], server["scan_policy"]
    tools, report = select_tools(server, set())
    names = [t.name for t in tools]
    assert "watch_scan" not in names and "scan_policy" not in names
    assert {"watch_scan", "scan_policy"} <= set(report["not_offered_by_server"])
    assert set(CHATBOT_TOOL_NAMES) == {"scan_policy", "start_scan", "start_demo_scan", "cancel_scan",
                                       "list_scans", "list_reports", "get_report", "watch_scan"}


def test_code_goes_into_a_web_scan_with_approval_and_valid_ids():
    from guardrails import check_tool_args
    from scopeguard_common import (
        APPROVAL_TOOLS,
        approval_description,
        decisions_from_answers,
    )

    assert "start_code_scan" not in APPROVAL_TOOLS  # code is only analysed as a step of a web scan
    uid, site = "a" * 32, "https://app.example.test/"
    out = decisions_from_answers([{"name": "start_scan", "args": {"target_url": site, "upload_id": uid}}],
                                 [{"type": "approve"}])
    assert out[0]["edited_action"]["args"] == {"target_url": site, "upload_id": uid, "authorization_confirmed": True}
    assert check_tool_args("start_scan", {"target_url": site, "upload_id": "nope"})
    assert check_tool_args("start_scan", {"target_url": site, "upload_id": uid}) is None
    git = "https://github.com/acme/shop.git"
    assert check_tool_args("start_scan", {"target_url": site, "git_url": "https://github.com/acme/shop"})  # no .git
    assert check_tool_args("start_scan", {"target_url": site, "git_url": git, "git_ref": "main"}) is None
    assert check_tool_args("start_scan", {"target_url": site, "git_url": git, "upload_id": uid})
    assert check_tool_args("start_scan", {"target_url": site, "git_url": "http://github.com/a/b"})
    assert check_tool_args("start_scan", {"target_url": site, "git_url": "https://u:p@github.com/a/b"})
    assert check_tool_args("start_scan", {"target_url": site, "git_url": git, "git_ref": "--upload-pack=x"})
    assert "cloned" in approval_description({"name": "start_scan", "args": {"target_url": site, "git_url": git}})


async def test_an_attachment_reaches_the_model_after_the_input_guardrail():
    from scopeguard_common import Engine

    seen = []

    class Agent:
        pass

    eng = Engine(Agent())

    async def stream(payload, thread_id, emit):
        seen.append(payload["messages"][0]["content"])

    eng._stream = stream
    await eng.send("t1", "scan my site with this code", lambda ev: None,
                   {"upload_id": "b" * 32, "filename": "app.zip"})
    assert seen and "upload_id " + "b" * 32 in seen[0] and "Python only for now" in seen[0]


async def test_the_model_is_told_which_tools_are_on():
    seen: list[str] = []

    class Recording(ScriptedModel):
        def _generate(self, messages, *a, **k):
            seen.append(str(messages[0].content))  # the system prompt
            return super()._generate(messages, *a, **k)

    eng = sc.Engine(sc.build_agent([start_scan], model=Recording(messages=iter([AIMessage(content="hi")]))))
    await eng.send("t7", "what can you do?", lambda e: None)
    assert seen and "Tools switched on in this session: start_scan." in seen[0]
    assert "never call it" in seen[0]


def test_result_block_shows_the_code_sast_step_and_marks_non_python_files():
    from scopeguard_common import compact_scan_result, scan_result_markdown

    r = {"status": "completed", "target_url": "http://app.test/", "severity_counts": {}, "findings": [],
         "code_sast": {"source": {"kind": "git", "git_url": "https://github.com/acme/shop", "commit": "a" * 40},
                       "source_files": 3, "findings": 2, "sandbox": "process",
                       "languages": {"by_language": {"python": 2, "JavaScript": 1}, "python_project": True,
                                     "verdict": "2 Python file(s) fully covered; 1 file(s) in other languages ...",
                                     "not_python": [("<<<UNTRUSTED_CONTENT_START>>>\nweb/app.js (JavaScript)\n"
                                                    "<<<UNTRUSTED_CONTENT_END>>>")],
                                     "warnings": [("<<<UNTRUSTED_CONTENT_START>>>\ninstall.bat (Windows batch script)\n"
                                                   "<<<UNTRUSTED_CONTENT_END>>>")]}}}
    r["code_sast"]["coding_standard"] = {"standard": "PEP 8", "files_with_issues": 1,
                                         "files_by_rule": {"STYLE_BARE_EXCEPT": 1}, "codes": {"STYLE_BARE_EXCEPT": "E722"}}
    md = scan_result_markdown(r)
    assert "**Coding standard (PEP 8):** 1 Python file(s) with issues: STYLE_BARE_EXCEPT (E722) in 1 file(s)" in md
    assert "**WARNING** executable / script file, review it: `install.bat (Windows batch script)`" in md
    assert "#### Source code (code SAST step, same report)" in md and "git https://github.com/acme/shop" in md
    assert "JavaScript (not Python, partial) 1" in md and "not Python, partial coverage: `web/app.js (JavaScript)`" in md
    assert "UNTRUSTED" not in md
    compact = compact_scan_result(r)
    assert "source code (code_sast step, same report)" in compact and "UNTRUSTED" in compact  # markers kept for the model


def test_scope_is_shown_in_the_approval_and_the_result():
    call = {"name": "start_scan", "args": {"target_url": "https://app.example/", "upload_id": "a" * 32,
                                           "scan_scope": "code"}}
    assert "no request is sent" in sc.approval_description(call)
    assert "website + code, website only, or code only" in sc.approval_description(
        {"name": "start_scan", "args": {"target_url": "https://app.example/"}})
    r = {"target_url": "https://app.example/", "scan_scope": "code", "severity_counts": {}, "findings": []}
    assert "source code only" in sc.scan_result_markdown(r)
    assert "**tested:** website only" in sc.scan_result_markdown({**r, "scan_scope": None})
