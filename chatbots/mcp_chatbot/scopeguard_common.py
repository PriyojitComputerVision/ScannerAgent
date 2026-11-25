"""Plumbing for the ScopeGuard MCP chatbot (LangChain create_agent).

It provides:

* settings from the repo's .env (the same GROQ_API_KEY and JWT key the scanner uses);
* sign-in: an API JWT signed with the repo's private key (keys/), renewed before it expires;
* the Groq chat model;
* an optional private pentest-agent server for this run (only the hosts you allow);
* the turn engine: streams a LangChain ``create_agent`` run, pauses on the
  human-in-the-loop interrupt, turns the reviewer's answers into decisions, resumes;
* a console loop (CLI) and a small JSON API (``--serve``) used by chatbots/ui.

A scan only starts after a human approves it. Approving ``start_scan`` is the
authorization confirmation: the engine sets ``authorization_confirmed=true`` on the
approved call itself, so the model never confirms authorization on its own.
"""
from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import guardrails

log = logging.getLogger("scopeguard.chatbot")

HERE = Path(__file__).resolve().parent
REPO = Path(os.environ.get("SCOPEGUARD_HOME") or HERE.parents[1]).resolve()

# Tools that start or stop real network activity: a human approves every call.
APPROVAL_TOOLS = ("start_scan", "start_demo_scan", "cancel_scan", "start_code_scan")
MAX_UPLOAD_BYTES = 10 * 1024 * 1024   # the scanner's MCP_MAX_UPLOAD_MB default
UPLOAD_ID_RE = re.compile(r"^[a-f0-9]{32}$")
LANGUAGE_NOTICE = "Python only for now: other languages are only partly covered."
# Groq's on_demand tier allows 8,000 tokens per request (prompt + reply budget), so tool
# results are kept compact and old tool outputs are cleared from the history.
MAX_TOOL_TEXT = 9_000      # chars of one tool result shown to the model
MAX_FINDINGS = 100         # findings fetched when a scan ends (the server maximum)
CLEAR_TOOLS_AT = 3_000     # approx. tokens of history before old tool outputs are cleared
SUMMARIZE_AT = 3_500       # approx. tokens of history before older messages are summarized
KEEP_MESSAGES = 6          # most recent messages kept word for word after a summary
SUMMARY_MAX_TOKENS = 600   # reply budget of the summarizer call


# =============================================================================
# Settings (repo .env; process environment wins)
# =============================================================================
@dataclass
class Settings:
    groq_api_key: str
    groq_model: str
    groq_max_tokens: int
    groq_reasoning_effort: str
    jwt_private_key: Path
    jwt_public_key: Path
    jwt_issuer: str
    jwt_audience: str
    jwt_ttl_minutes: int
    env: dict = field(default_factory=dict, repr=False)


def load_settings() -> Settings:
    from dotenv import dotenv_values

    # Precedence: process environment > this folder's .env > the repo's main .env. An empty
    # value in a .env file never overrides a set one; a variable set in the environment always
    # wins, even when empty (e.g. CHATBOT_ALLOW=). Only the chatbot's own settings are read,
    # never the rest of the repo's .env.
    # The Groq settings (GROQ_API_KEY, GROQ_MODEL, GROQ_REASONING_EFFORT) come only from the
    # repo's main .env, the same key and model as the scanner: GROQ_* in this folder's .env or
    # in the environment is ignored.
    prefixes = ("GROQ_", "JWT_", "SCOPEGUARD_", "CHATBOT_")
    env: dict[str, str] = {}
    for env_file in (REPO / ".env", HERE / ".env"):
        if env_file.is_file():
            env.update({k: v for k, v in dotenv_values(env_file).items()
                        if v and k.startswith(prefixes) and not (env_file.parent == HERE and k.startswith("GROQ_"))})
    env.update({k: v for k, v in os.environ.items() if k.startswith(prefixes) and not k.startswith("GROQ_")})

    def path(key: str, default: str) -> Path:
        p = Path(env.get(key) or default)
        return p if p.is_absolute() else (REPO / p).resolve()

    return Settings(
        groq_api_key=env.get("GROQ_API_KEY", ""),
        groq_model=env.get("GROQ_MODEL") or "openai/gpt-oss-20b",
        # reply budget for the chat model; Groq counts it against the per-request limit
        groq_max_tokens=int(env.get("CHATBOT_MAX_TOKENS") or 3000),
        groq_reasoning_effort=(env.get("GROQ_REASONING_EFFORT") or "low").strip().lower(),
        jwt_private_key=path("JWT_PRIVATE_KEY_PATH", "./keys/jwt_private.pem"),
        jwt_public_key=path("JWT_PUBLIC_KEY_PATH", "./keys/jwt_public.pem"),
        jwt_issuer=env.get("JWT_ISSUER") or "pentest-agent",
        jwt_audience=env.get("JWT_AUDIENCE") or "pentest-agent-api",
        jwt_ttl_minutes=min(int(env.get("JWT_ACCESS_TTL_MINUTES") or 60), 60),
        env=env,
    )


# =============================================================================
# Sign-in: API JWT signed with the repo's key, exactly like `uv run pentest-auth token`
# =============================================================================
class TokenMinter:
    """Mints RS256 access tokens the scanner's API accepts (same claims, ``kid``).

    Whoever can read the private key is the operator, so this is the same as the
    repo's own test clients. Tokens are renewed 5 minutes before they expire."""

    def __init__(self, s: Settings, subject: str, roles: list[str]):
        from cryptography.hazmat.primitives import serialization

        if not s.jwt_private_key.is_file() or not s.jwt_public_key.is_file():
            raise SystemExit(f"JWT keys not found in {s.jwt_private_key.parent}. Create them in the repo "
                             f"root with: uv run pentest-auth keys")
        self.s, self.subject, self.roles = s, subject, roles
        self._private = serialization.load_pem_private_key(s.jwt_private_key.read_bytes(), password=None)
        public = serialization.load_pem_public_key(s.jwt_public_key.read_bytes())
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        import hashlib

        self.kid = hashlib.sha256(der).hexdigest()[:16]
        self._token, self._exp = "", 0
        self._lock = threading.Lock()

    def token(self) -> str:
        import jwt

        with self._lock:
            now = int(time.time())
            if self._exp - now > 300:
                return self._token
            self._exp = now + self.s.jwt_ttl_minutes * 60
            claims = {"iss": self.s.jwt_issuer, "aud": self.s.jwt_audience, "sub": self.subject,
                      "typ": "access", "jti": uuid.uuid4().hex, "iat": now, "nbf": now, "exp": self._exp,
                      "auth_time": now, "roles": self.roles}
            self._token = jwt.encode(claims, self._private, algorithm="RS256",
                                     headers={"kid": self.kid, "typ": "JWT"})
            return self._token


def bearer_auth(minter: TokenMinter):
    """httpx.Auth that always sends a fresh token (long chats outlive one token)."""
    import httpx

    class _FreshBearer(httpx.Auth):
        def auth_flow(self, request):
            request.headers["Authorization"] = f"Bearer {minter.token()}"
            yield request

    return _FreshBearer()


# =============================================================================
# LLM
# =============================================================================
def make_llm(s: Settings, max_tokens: int | None = None):
    from langchain_groq import ChatGroq

    key = s.groq_api_key.strip()
    if not key or key.lower().startswith(("test-key", "your_", "changeme")):
        raise SystemExit("GROQ_API_KEY is not set in the repo's .env; the chatbot needs it.")
    kwargs: dict[str, Any] = {"max_tokens": max_tokens or s.groq_max_tokens}
    if s.groq_reasoning_effort and s.groq_model.lower().startswith("openai/gpt-oss"):
        kwargs["reasoning_effort"] = s.groq_reasoning_effort
    # Few retries: a per-minute limit clears quickly, and a daily limit will not clear by retrying;
    # the UI shows the wait instead (describe_error).
    return ChatGroq(model=s.groq_model, api_key=key, temperature=0.0, max_retries=2, **kwargs)


def load_prompt(name: str = "system_prompt") -> str:
    return (HERE / f"{name}.md").read_text(encoding="utf-8")


# =============================================================================
# The scanner server (pentest-agent): use a running one, or start a private one
# =============================================================================
def healthy(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base.rstrip('/')}/healthz", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def scanner_server(url: str, allow: list[str], start: bool, scanner_llm: bool = True):
    """Yield the scanner base URL.

    * ``allow`` given: start a private pentest-agent on a free loopback port with only
      those hosts on MCP_ALLOWED_TARGETS / A2A_ALLOWED_TARGETS (the repo's .env is not
      edited; env vars beat .env). Stopped when the chatbot exits.
    * else ``url`` if it answers, or (with ``start``) a pentest-agent started on its port.

    ``scanner_llm=False`` starts that server without GROQ_API_KEY: the scan's own LLM
    steps (executive summary, probe plan) use their deterministic fallbacks, which is
    faster for a quick check. The chatbot's agent still uses the LLM.
    """
    base = url.rstrip("/")
    if not allow and healthy(base):
        if not scanner_llm:
            print(f"Note: using the running server at {base}; --no-scanner-llm only applies to a server "
                  "this chatbot starts (--allow / --start-server).", file=sys.stderr)
        yield base
        return
    if not allow and not start:
        raise SystemExit(f"No ScopeGuard server at {base}. Start one in the repo root with "
                         f"`uv run pentest-agent`, or pass --start-server (or --allow HOST).")
    from urllib.parse import urlsplit

    port = free_port() if allow else (urlsplit(base).port or 8765)
    base = f"http://127.0.0.1:{port}"
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "PYTHONPATH")}
    env["PYTHONIOENCODING"] = "utf-8"
    if not scanner_llm:
        env["GROQ_API_KEY"] = ""  # env beats .env: the scanner runs its deterministic fallbacks
    if allow:
        hosts = ",".join(allow)
        env["MCP_ALLOWED_TARGETS"] = env["A2A_ALLOWED_TARGETS"] = hosts
    log_path = REPO / "data" / "logs" / f"chatbot-server-{port}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["uv", "run", "--project", str(REPO), "python", "-m", "pentest_agent.main",
           "--no-browser", "--no-target", "--host", "127.0.0.1", "--port", str(port)]
    print(f"Starting a private ScopeGuard server on {base}"
          + (f" (allowlisted: {', '.join(allow)})" if allow else "")
          + ("" if scanner_llm else " without the scanner's LLM steps") + f"; log: {log_path}", file=sys.stderr)
    with log_path.open("w", encoding="utf-8") as log:
        group = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
                 else {"start_new_session": True})
        proc = subprocess.Popen(cmd, cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT, **group)
        try:
            deadline = time.monotonic() + 180
            while not healthy(base):
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise SystemExit(f"The ScopeGuard server did not start; see {log_path}")
                time.sleep(0.5)
            yield base
        finally:
            stop_tree(proc)


def stop_tree(proc: subprocess.Popen) -> None:
    """Stop a `uv run` child and everything under it (uv wraps the real Python process)."""
    if proc.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, check=False)
    else:
        import signal

        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGTERM)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


def host_of(target: str) -> str:
    from urllib.parse import urlsplit

    return urlsplit(target if "://" in target else f"https://{target}").netloc


# =============================================================================
# Agent pieces shared by both chatbots
# =============================================================================
def approval_description(tool_call: dict, state: Any = None, runtime: Any = None) -> str:
    name, args = tool_call["name"], tool_call.get("args") or {}
    if name == "start_scan":
        code = (" The attached source code is analysed in its SAST step and reported with the web findings."
                if args.get("upload_id") else "")
        return (f"Scan {args.get('target_url')} with the {args.get('profile', 'standard')} profile. "
                "It sends real HTTP requests to that site. Approve only if you own the site or are "
                f"authorized to test it: your approval is the authorization confirmation.{code}")
    if name == "start_code_scan":
        return ("Analyse the attached source code in the sandbox (static analysis; nothing is run). Approve only "
                f"if you own this code or may analyse it: your approval is the authorization confirmation. "
                f"{LANGUAGE_NOTICE}")
    if name == "start_demo_scan":
        return (f"Scan the built-in, deliberately vulnerable demo app ({args.get('profile', 'quick')} "
                "profile, loopback only).")
    if name == "cancel_scan":
        return f"Cancel scan {args.get('scan_id')}."
    return f"Run {name}."


def hitl_middleware():
    from langchain.agents.middleware import HumanInTheLoopMiddleware

    cfg = {"allowed_decisions": ["approve", "edit", "reject"], "description": approval_description}
    return HumanInTheLoopMiddleware(interrupt_on={name: dict(cfg) for name in APPROVAL_TOOLS},
                                    description_prefix="Human approval needed")


def tool_guard_middleware():
    """Pre-guardrail on every tool call's arguments (the model's own calls and calls a
    reviewer edited), then: tool errors become messages the model can explain (instead
    of ending the turn), and very long tool results are clipped (token limits)."""
    from langchain.agents.middleware import wrap_tool_call
    from langchain_core.messages import ToolMessage

    @wrap_tool_call
    async def guard(request, handler):
        call = request.tool_call
        problem = guardrails.check_tool_args(call["name"], call.get("args"))
        if problem:
            log.warning("Guardrail refused tool call %s: %s", call["name"], problem)
            return ToolMessage(content=f"Refused by the guardrail: {problem}. Tell the user; do not retry with "
                                       "different values unless they ask.",
                               tool_call_id=call["id"], name=call["name"], status="error")
        try:
            result = await handler(request)
        except Exception as exc:  # noqa: BLE001 - reported to the model as the tool result
            return ToolMessage(content=f"Tool error: {type(exc).__name__}: {str(exc)[:500]}",
                               tool_call_id=request.tool_call["id"], name=request.tool_call["name"],
                               status="error")
        if isinstance(result, ToolMessage):
            text = result.content if isinstance(result.content, str) else _content_text(result.content)
            if len(text) > MAX_TOOL_TEXT:
                result.content = text[:MAX_TOOL_TEXT] + (
                    f"\n... [clipped: {len(text) - MAX_TOOL_TEXT} more characters; the full text is "
                    "in the report files]")
        return result

    return guard


def _content_text(content) -> str:
    if isinstance(content, str):
        return content
    parts = []
    for block in content or []:
        if isinstance(block, dict):
            parts.append(str(block.get("text", "")))
        else:
            parts.append(str(block))
    return "\n".join(parts)


def mcp_json(result) -> dict:
    """An MCP tool result (text content blocks) -> its JSON object, or {"text": ...}."""
    text = _content_text(result).strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else {"text": text}
    except json.JSONDecodeError:
        return {"text": text}


_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _short_url(url: str, root_netloc: str) -> str:
    from urllib.parse import urlsplit

    u = urlsplit(url)
    return (u.path or "/") + (f"?{u.query}" if u.query else "") if u.netloc == root_netloc else url


def _grouped(r: dict) -> list[tuple[str, list[tuple[str, dict]]]]:
    """Findings grouped by severity (most severe first), then by title with count and URLs."""
    from urllib.parse import urlsplit

    root = urlsplit(str(r.get("target_url") or "")).netloc
    by_sev: dict[str, dict[str, dict]] = {}
    for f in r.get("findings") or []:
        sev = str(f.get("severity") or "info").lower()
        g = by_sev.setdefault(sev, {}).setdefault(str(f.get("title")), {"n": 0, "urls": [], "f": f})
        g["n"] += 1
        short = _short_url(str(f.get("affected_url") or ""), root)
        if short and short not in g["urls"]:
            g["urls"].append(short)
    order = sorted(by_sev, key=lambda s: _SEV_ORDER.index(s) if s in _SEV_ORDER else 9)
    return [(sev, sorted(by_sev[sev].items())) for sev in order]


def scan_result_markdown(r: dict) -> str:
    """The verified result block shown to the user exactly as the scanner returned it
    (not written by the model): counts, every finding under its own severity, red flags,
    report files and the audit record."""
    counts = r.get("severity_counts") or {}
    out = ["### Scan result (verified, from the scanner)",
           (f"**Target:** `{r.get('target_url')}` | **profile:** {r.get('profile')} | **status:** {r.get('status')} | "
           f"**pages crawled:** {r.get('pages_crawled')} | **duration:** {r.get('elapsed_seconds')}s | "
           f"**signed in:** {'yes' if r.get('signed_in') else 'no'}"),
           "",
           "| Critical | High | Medium | Low | Info | Total |",
           "|---|---|---|---|---|---|",
           "| " + " | ".join(str(counts.get(s, 0)) for s in _SEV_ORDER) + f" | {r.get('findings_total', 0)} |"]
    if r.get("findings_omitted"):
        out.append(f"\n{r['findings_omitted']} more finding(s) were not returned; see the report files.")
    for sev, items in _grouped(r):
        n = sum(g["n"] for _, g in items)
        out += ["", f"#### {sev.capitalize()} ({n})"]
        for title, g in items:
            f = g["f"]
            urls = ", ".join(f"`{u}`" for u in g["urls"][:3]) + (f" +{len(g['urls']) - 3} more" if len(g["urls"]) > 3 else "")
            fix = " ".join(str(f.get("recommendation") or "").split())[:200]
            out.append(f"- **{title}**" + (f" (x{g['n']})" if g["n"] > 1 else "") + f" - {urls or '-'}"
                       + (f" - {f['cwe']}" if f.get("cwe") else "") + (f" - fix: {fix}" if fix else ""))
    if r.get("red_flags"):
        out += ["", "#### Red flags"] + [f"- {flag}" for flag in r["red_flags"]]
    files = r.get("report_files") or {}
    if files:
        out += ["", "#### Report files"] + [f"- {k.upper()}: `{v}`" for k, v in files.items()]
    a = r.get("audit")
    if isinstance(a, dict):
        out += ["", f"**Audit record:** seq {a.get('seq')}, outcome {a.get('outcome')}, hash `{str(a.get('hash'))[:16]}...`"]
    if r.get("error"):
        out += ["", f"**Error:** {r['error']}"]
    return "\n".join(out)


def compact_scan_result(r: dict) -> str:
    """A finished get_scan result in a compact text form for the model.

    Findings with the same severity and title are one line (count, CWE, up to three
    URLs, the fix); evidence stays in the report files. Executive summary and evidence
    come from the scanned site, so the untrusted-content markers are kept."""
    from urllib.parse import urlsplit

    target = str(r.get("target_url") or "")
    root = urlsplit(target)
    lines = [(f"scan_id: {r.get('scan_id')} | status: {r.get('status')} | target: {target} | "
              f"profile: {r.get('profile')} | pages crawled: {r.get('pages_crawled')} | "
              f"duration: {r.get('elapsed_seconds')}s | signed in: {r.get('signed_in')}"),
             f"severity counts: {r.get('severity_counts')} | findings total: {r.get('findings_total')}"
             + (f" | not returned: {r['findings_omitted']}" if r.get("findings_omitted") else "")]
    if r.get("error"):
        lines.append(f"error: {r['error']}")
    groups: dict[tuple, dict] = {}
    for f in r.get("findings") or []:
        g = groups.setdefault((f.get("severity"), f.get("title")), {"n": 0, "urls": [], "f": f})
        g["n"] += 1
        u = urlsplit(str(f.get("affected_url") or ""))
        short = (u.path or "/") + (f"?{u.query}" if u.query else "") if u.netloc == root.netloc else str(
            f.get("affected_url") or "")
        if short and short not in g["urls"]:
            g["urls"].append(short)
    lines.append(f"findings ({len(groups)} distinct issues), grouped by severity:")
    current = None
    for (sev, title), g in sorted(groups.items(), key=lambda kv: (
            _SEV_ORDER.index(kv[0][0]) if kv[0][0] in _SEV_ORDER else 9, str(kv[0][1]))):
        if sev != current:  # a heading per severity keeps the model from mixing levels
            current = sev
            n = sum(x["n"] for (s2, _), x in groups.items() if s2 == sev)
            lines.append(f"{str(sev).upper()} severity ({n} finding(s); report these only as {sev}):")
        f = g["f"]
        urls = ", ".join(g["urls"][:3]) + (f" (+{len(g['urls']) - 3} more)" if len(g["urls"]) > 3 else "")
        fix = " ".join(str(f.get("recommendation") or "").split())[:160]
        lines.append(f"- [{str(sev).upper()}] {title}" + (f" x{g['n']}" if g["n"] > 1 else "")
                     + f" | {f.get('cwe') or 'no CWE'} | confidence {f.get('confidence')} | at {urls or '-'}"
                     + (f" | fix: {fix}" if fix else ""))
    for flag in r.get("red_flags") or []:
        lines.append(f"red flag: {flag}")
    if r.get("executive_summary"):
        lines.append("executive summary: " + " ".join(str(r["executive_summary"]).split())[:1500])
    if r.get("report_files"):
        lines.append("report files: " + json.dumps(r["report_files"], ensure_ascii=False))
    if r.get("audit"):
        a = r["audit"]
        lines.append(f"audit record: seq {a.get('seq')}, outcome {a.get('outcome')}" if isinstance(a, dict)
                     else f"audit record: {a}")
    return "\n".join(lines)


def summarization_middleware(summary_model=None):
    """Long conversations: older messages are replaced by a short summary (own prompt file,
    small reply budget) once the history passes SUMMARIZE_AT tokens; the latest
    KEEP_MESSAGES stay word for word. Tool calls are never split from their results."""
    from langchain.agents.middleware import SummarizationMiddleware

    model = summary_model or make_llm(load_settings(), max_tokens=SUMMARY_MAX_TOKENS)
    return SummarizationMiddleware(model=model, trigger=("tokens", SUMMARIZE_AT),
                                   keep=("messages", KEEP_MESSAGES), summary_prompt=load_prompt("summary_prompt"),
                                   trim_tokens_to_summarize=3_000)


def build_agent(tools: list, extra_middleware: list | None = None, model=None, summary_model=None):
    """create_agent with AgentState, an in-memory checkpointer, human approval and
    summarization of long conversations."""
    from langchain.agents import AgentState, create_agent
    from langchain.agents.middleware import ClearToolUsesEdit, ContextEditingMiddleware
    from langgraph.checkpoint.memory import InMemorySaver

    names = [getattr(t, "name", str(t)) for t in tools]
    tool_note = (f"\n\nTools switched on in this session: {', '.join(names) or 'none'}. Any other tool named "
                 "above is switched off by the operator: never call it; if the user needs it, say it is "
                 "unavailable.")
    return create_agent(
        model=model or make_llm(load_settings()),
        tools=tools,
        system_prompt=load_prompt() + tool_note,
        middleware=[summarization_middleware(summary_model or model), hitl_middleware(), tool_guard_middleware(),
                    # keep only the latest tool output once the history grows (token limit)
                    ContextEditingMiddleware(edits=[ClearToolUsesEdit(trigger=CLEAR_TOOLS_AT, keep=1)]),
                    *(extra_middleware or [])],
        state_schema=AgentState,
        checkpointer=InMemorySaver(),
    )


# =============================================================================
# Turn engine: stream, pause for approval, resume
# =============================================================================
Emit = Callable[[dict], None]


def decisions_from_answers(requests: list[dict], answers: list[dict]) -> list[dict]:
    """Reviewer answers -> HumanInTheLoopMiddleware decisions.

    answer = {"type": "approve"} | {"type": "reject", "message": "..."} |
             {"type": "edit", "args": {...}}
    Approving or editing start_scan sets authorization_confirmed=true: the human's
    approval is the confirmation, never the model's own argument."""
    out = []
    for req, ans in zip(requests, answers, strict=True):
        kind = ans.get("type")
        name, args = req["name"], dict(req.get("args") or {})
        if kind == "reject":
            out.append({"type": "reject", "message": ans.get("message")
                        or f"The user rejected {name}. Do not retry it unless they ask."})
            continue
        if kind == "edit":
            args = dict(ans.get("args") or args)
        elif kind != "approve":
            raise ValueError(f"unknown decision {kind!r}")
        if name in ("start_scan", "start_code_scan"):
            args["authorization_confirmed"] = True
            out.append({"type": "edit", "edited_action": {"name": name, "args": args}})
        elif kind == "edit":
            out.append({"type": "edit", "edited_action": {"name": name, "args": args}})
        else:
            out.append({"type": "approve"})
    return out


_LIMIT_RE = re.compile(r"(requests|tokens) per (minute|day) \((RPM|RPD|TPM|TPD)\): Limit (\d+), Used (\d+)"
                       r"(?:, Requested (\d+))?", re.IGNORECASE)
_WAIT_RE = re.compile(r"try again in (?:(\d+)h)?(?:(\d+)m)?(?:([\d.]+)s)?", re.IGNORECASE)
_LIMIT_NAMES = {"TPD": "daily token limit", "TPM": "per-minute token limit", "RPD": "daily request limit",
                "RPM": "per-minute request limit"}


def _wait_text(seconds: float) -> str:
    seconds = max(0, round(seconds))
    if seconds >= 3600:
        return f"{seconds // 3600} h {seconds % 3600 // 60} min"
    if seconds >= 60:
        return f"{seconds // 60} min {seconds % 60} s"
    return f"{seconds} s"


def describe_error(exc: BaseException) -> dict:
    """A turn's error as a short, safe message for the user.

    Groq rate limits become {"kind": "rate_limit", "limit": "TPD", "retry_after_seconds": ...}
    with a plain explanation; the provider's raw text (organization id, billing links) is
    never shown. Other errors keep only their type and a clipped message."""
    status = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
    raw = str(exc)
    if status == 429 or "rate_limit_exceeded" in raw or type(exc).__name__ == "RateLimitError":
        retry = None
        headers = getattr(getattr(exc, "response", None), "headers", None) or {}
        with contextlib.suppress(TypeError, ValueError):
            retry = float(headers.get("retry-after")) if headers.get("retry-after") else None
        m = _WAIT_RE.search(raw)
        if m and any(m.groups()):
            retry = int(m.group(1) or 0) * 3600 + int(m.group(2) or 0) * 60 + float(m.group(3) or 0)
        lim = _LIMIT_RE.search(raw)
        code = lim.group(3).upper() if lim else None
        name = _LIMIT_NAMES.get(code, "rate limit")
        usage = f" ({int(lim.group(5)):,} of {int(lim.group(4)):,} used)" if lim else ""
        if code in ("TPD", "RPD"):
            text = f"Groq's {name} for this API key is used up{usage}. The chat model cannot answer until it resets."
        else:
            text = f"Groq's {name} was reached{usage}. Wait a moment, then send your message again."
        if retry:
            text += f" Try again in about {_wait_text(retry)}."
        return {"kind": "rate_limit", "limit": code, "retry_after_seconds": round(retry) if retry else None,
                "text": text}
    if status == 413 or "Request too large" in raw:
        return {"kind": "too_large", "text": "That request was too large for the model's token limit. "
                                             "Start a new chat (New chat) or ask for less at once."}
    if status in (401, 403) and "groq" in type(exc).__module__:
        return {"kind": "llm_auth", "text": "Groq rejected the API key. Check GROQ_API_KEY in the repo's .env."}
    if type(exc).__name__ in ("APIConnectionError", "APITimeoutError"):
        return {"kind": "llm_unreachable", "text": "Could not reach Groq (network or timeout). Try again."}
    return {"kind": "error", "text": f"{type(exc).__name__}: {raw[:300]}"}


class Engine:
    """Runs one chat thread at a time per thread_id; emits UI-neutral events:

    tool_call, tool_result, progress, approval, answer, error, done."""

    def __init__(self, agent, recursion_limit: int = 80):
        self.agent = agent
        self.recursion_limit = recursion_limit
        self.pending: dict[str, list[dict]] = {}  # thread -> action requests awaiting review
        self.policy = None  # optional async () -> dict: the scanner's scan_policy (no LLM)
        # optional async (filename, base64) -> dict: MCP upload_code, called by the UI directly (the
        # archive never passes through the model)
        self.upload = None
        # What the output guardrail checks answers against (no prompt leakage).
        self.prompts = [load_prompt(), load_prompt("summary_prompt")]

    def _config(self, thread_id: str) -> dict:
        return {"configurable": {"thread_id": thread_id}, "recursion_limit": self.recursion_limit}

    async def send(self, thread_id: str, text: str, emit: Emit, attachment: dict | None = None) -> None:
        if self.pending.get(thread_id):
            emit({"type": "error", "text": "Answer the pending approval first."})
            return
        # Pre-guardrail: a blocked message never reaches the model or the conversation history.
        verdict = guardrails.check_input(text)
        if not verdict.allowed:
            log.warning("Guardrail blocked a message in %s: %s", thread_id[:12], verdict.category)
            emit({"type": "guardrail", "stage": "input", "category": verdict.category, "text": verdict.message})
            emit({"type": "done", "waiting_for_approval": False})
            return
        content = verdict.text
        if attachment:  # added after the input guardrail: these values come from the server, not the user
            content += (f"\n\n[Attached source code: {attachment['filename']} (upload_id {attachment['upload_id']}). "
                        "For a web scan plus this code call start_scan with this upload_id (analysed in the SAST "
                        "step, one report); for the code alone call start_code_scan, then get_code_scan. "
                        f"{LANGUAGE_NOTICE}]")
        await self._stream({"messages": [{"role": "user", "content": content}]}, thread_id, emit)

    async def decide(self, thread_id: str, answers: list[dict], emit: Emit) -> None:
        from langgraph.types import Command

        requests = self.pending.get(thread_id)
        if not requests:
            emit({"type": "error", "text": "Nothing is waiting for approval."})
            return
        decisions = decisions_from_answers(requests, answers)
        self.pending.pop(thread_id, None)
        await self._stream(Command(resume={"decisions": decisions}), thread_id, emit)

    async def _stream(self, payload, thread_id: str, emit: Emit) -> None:
        from langchain_core.messages import AIMessage, ToolMessage

        try:
            async for mode, chunk in self.agent.astream(payload, self._config(thread_id),
                                                        stream_mode=["updates", "custom", "messages"]):
                if mode == "messages":  # the model's reply, token by token
                    msg, meta = chunk
                    if meta.get("langgraph_node") == "model" and isinstance(msg.content, str) and msg.content:
                        emit({"type": "token", "text": msg.content})
                    continue
                if mode == "custom":
                    if isinstance(chunk, dict) and "scan_result" in chunk:  # verified block, not model text
                        emit({"type": "scan_result", "markdown": chunk["scan_result"]})
                    else:
                        emit({"type": "progress", "text": str(chunk.get("text") if isinstance(chunk, dict)
                                                              else chunk)})
                    continue
                for node, update in (chunk or {}).items():
                    if node == "__interrupt__":
                        value = update[0].value
                        self.pending[thread_id] = value["action_requests"]
                        emit({"type": "approval", "requests": value["action_requests"]})
                        return
                    for msg in (update or {}).get("messages", []) if isinstance(update, dict) else []:
                        if isinstance(msg, AIMessage):
                            for call in msg.tool_calls:
                                emit({"type": "tool_call", "name": call["name"], "args": call["args"]})
                            text = _content_text(msg.content).strip()
                            if text and not msg.tool_calls:
                                # Post-guardrail: no prompt leakage, no secrets in the answer.
                                safe, reason = guardrails.check_output(text, self.prompts)
                                if reason:
                                    log.warning("Guardrail changed an answer in %s: %s", thread_id[:12], reason)
                                    emit({"type": "guardrail", "stage": "output", "category": reason,
                                          "text": "The reply was changed by the output guardrail ("
                                                  + reason.replace("_", " ") + ")."})
                                emit({"type": "answer", "text": safe, "replaced": bool(reason)})
                        elif isinstance(msg, ToolMessage):
                            emit({"type": "tool_result", "name": msg.name,
                                  "status": getattr(msg, "status", "success"),
                                  "preview": _content_text(msg.content)[:400]})
        except Exception as exc:  # noqa: BLE001 - shown to the user; the thread stays usable
            emit({"type": "error", **describe_error(exc)})
        finally:
            emit({"type": "done", "waiting_for_approval": bool(self.pending.get(thread_id))})


# =============================================================================
# Console loop
# =============================================================================
class _Printer:
    """Console output: scan updates as they stream, the reply token by token."""

    def __init__(self):
        self.streaming = False  # in the middle of a streamed reply

    def __call__(self, ev: dict) -> None:
        kind = ev["type"]
        if kind == "token":
            if not self.streaming:
                print("\nAssistant:\n", end="", flush=True)
                self.streaming = True
            print(ev["text"], end="", flush=True)
            return
        if self.streaming:  # reply finished (its full text was already shown)
            print("\n", flush=True)
            self.streaming = False
            if kind == "answer":
                if ev.get("replaced"):  # the streamed text was withdrawn by the output guardrail
                    print(f"[guardrail] The reply above is withdrawn. Instead:\n{ev['text']}\n", flush=True)
                return
        _print_event(ev)


def _print_event(ev: dict) -> None:
    kind = ev["type"]
    if kind == "tool_call":
        args = json.dumps(ev["args"], ensure_ascii=False)
        print(f"  -> {ev['name']}({args[:300]})", flush=True)
    elif kind == "tool_result":
        mark = "!" if ev.get("status") == "error" else "<-"
        print(f"  {mark} {ev['name']}: {ev['preview'][:160].replace(chr(10), ' ')}", flush=True)
    elif kind == "progress":
        print(f"  >> {ev['text']}", flush=True)
    elif kind == "scan_result":
        print("\n" + ev["markdown"] + "\n", flush=True)
    elif kind == "answer":
        print(f"\nAssistant:\n{ev['text']}\n", flush=True)
    elif kind == "error":
        label = "Groq limit" if ev.get("kind") == "rate_limit" else "error"
        print(f"\n[{label}] {ev['text']}\n", flush=True)
    elif kind == "guardrail":
        print(f"\n[guardrail: {ev.get('category')}] {ev['text']}\n", flush=True)


def _ask_review(requests: list[dict]) -> list[dict]:
    answers = []
    for req in requests:
        print("\n" + "=" * 70)
        print(f"APPROVAL NEEDED: {req['name']}")
        print(req.get("description", ""))
        print(f"arguments: {json.dumps(req.get('args'), indent=2, ensure_ascii=False)}")
        while True:
            choice = input("[a]pprove / [e]dit arguments / [r]eject? ").strip().lower()
            if choice in ("a", "approve", "y", "yes"):
                answers.append({"type": "approve"})
            elif choice in ("r", "reject", "n", "no"):
                answers.append({"type": "reject", "message": input("reason (optional): ").strip() or None})
            elif choice in ("e", "edit"):
                raw = input("new arguments as JSON (empty = keep): ").strip()
                try:
                    answers.append({"type": "edit", "args": json.loads(raw) if raw else req.get("args")})
                except json.JSONDecodeError as exc:
                    print(f"not valid JSON: {exc}")
                    continue
            else:
                continue
            break
    print("=" * 70)
    return answers


async def console_loop(engine: Engine, title: str) -> None:
    thread = uuid.uuid4().hex
    print(f"{title}\nType a message (e.g. 'scan https://your-site.example/ with the standard profile', "
          f"'run a demo scan'). Commands: /new (new conversation), /quit.\n")
    while True:
        try:
            text = (await asyncio.to_thread(input, "You: ")).strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not text:
            continue
        if text in ("/quit", "/exit"):
            break
        if text == "/new":
            thread = uuid.uuid4().hex
            print("(new conversation)\n")
            continue
        printer = _Printer()
        await engine.send(thread, text, printer)
        while engine.pending.get(thread):
            answers = await asyncio.to_thread(_ask_review, engine.pending[thread])
            await engine.decide(thread, answers, printer)


# =============================================================================
# JSON API for chatbots/ui (loopback only, shared secret from the UI launcher)
# =============================================================================
class ApiServer:
    """POST /api/send {thread_id, message}, POST /api/decide {thread_id, answers},
    POST /api/upload?thread_id=..&filename=x.zip (raw .zip body; attached to the thread's next
    message), POST /api/detach {thread_id}, GET /api/events?thread_id=..&after=N, GET /api/info.

    Every request needs the header X-Chatbot-Key (CHATBOT_API_KEY, set by the UI
    launcher). Turns run in the background; the UI polls /api/events."""

    def __init__(self, engine: Engine, info: dict, loop: asyncio.AbstractEventLoop):
        self.engine, self.info, self.loop = engine, info, loop
        self.key = os.environ.get("CHATBOT_API_KEY") or ""
        if len(self.key) < 32:
            raise SystemExit("--serve needs CHATBOT_API_KEY (32+ chars); chatbots/ui/serve_ui.py sets it.")
        self.events: dict[str, list[dict]] = {}
        self.busy: set[str] = set()
        self.attachments: dict[str, dict] = {}  # thread -> uploaded archive for its next message
        self.lock = threading.Lock()

    def _emitter(self, thread_id: str) -> Emit:
        def emit(ev: dict) -> None:
            with self.lock:
                if ev["type"] == "done":
                    self.busy.discard(thread_id)
                self.events.setdefault(thread_id, []).append(ev)
        return emit

    def start_turn(self, thread_id: str, coro_factory) -> str | None:
        with self.lock:
            if thread_id in self.busy:
                return "a turn is already running for this conversation"
            self.busy.add(thread_id)
        asyncio.run_coroutine_threadsafe(coro_factory(self._emitter(thread_id)), self.loop)
        return None

    def serve(self, port: int) -> None:
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _reply(self, code: int, body: dict) -> None:
                data = json.dumps(body, ensure_ascii=False, default=str).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _authorized(self) -> bool:
                if not secrets.compare_digest(self.headers.get("X-Chatbot-Key", ""), api.key):
                    self._reply(401, {"error": "unauthorized"})
                    return False
                return True

            def do_GET(self):
                if not self._authorized():
                    return
                from urllib.parse import parse_qs, urlsplit

                u = urlsplit(self.path)
                q = parse_qs(u.query)
                if u.path == "/api/info":
                    with api.lock:
                        busy = bool(api.busy)
                    self._reply(200, {**api.info, "busy": busy})
                elif u.path == "/api/policy":
                    if api.engine.policy is None:
                        self._reply(404, {"error": "no policy source"})
                        return
                    try:
                        data = asyncio.run_coroutine_threadsafe(api.engine.policy(), api.loop).result(30)
                    except Exception as exc:  # noqa: BLE001 - reported to the UI
                        self._reply(502, {"error": f"scan_policy failed: {type(exc).__name__}"})
                        return
                    profiles = [{"profile": p.get("profile"), "allowed": bool(p.get("allowed")),
                                 "description": str(p.get("description") or "")[:300]}
                                for p in data.get("profiles") or [] if isinstance(p, dict)]
                    self._reply(200, {"allowed_targets": data.get("allowed_targets") or [],
                                      "allowed_targets_setting": data.get("allowed_targets_setting"),
                                      "profiles": profiles})
                elif u.path == "/api/events":
                    tid = (q.get("thread_id") or [""])[0][:64]
                    after = int((q.get("after") or ["0"])[0] or 0)
                    with api.lock:
                        evs = api.events.get(tid, [])[after:]
                        busy = tid in api.busy
                    self._reply(200, {"events": evs, "next": after + len(evs), "busy": busy,
                                      "pending": api.engine.pending.get(tid) or []})
                else:
                    self._reply(404, {"error": "not found"})

            def _upload(self) -> None:
                """Raw .zip -> MCP upload_code (checks again on the server: name, MIME, signature)."""
                from urllib.parse import parse_qs, urlsplit

                q = parse_qs(urlsplit(self.path).query)
                tid = (q.get("thread_id") or [""])[0][:64]
                name = (q.get("filename") or [""])[0][:120]
                length = int(self.headers.get("Content-Length") or 0)
                if not tid or not name.lower().endswith(".zip"):
                    self._reply(400, {"error": "thread_id and a .zip filename are required"})
                    return
                if length <= 0 or length > MAX_UPLOAD_BYTES:
                    self._reply(413, {"error": f"the archive must be 1 byte to {MAX_UPLOAD_BYTES // 1048576} MB"})
                    return
                data = self.rfile.read(length)
                if not data.startswith(b"PK\x03\x04"):
                    self._reply(415, {"error": "not a zip archive"})
                    return
                if api.engine.upload is None:
                    self._reply(404, {"error": "the scanner does not offer upload_code (admin role needed, or "
                                               "the tool is switched off)"})
                    return
                try:
                    meta = asyncio.run_coroutine_threadsafe(
                        api.engine.upload(name, base64.b64encode(data).decode()), api.loop).result(120)
                except Exception as exc:  # noqa: BLE001 - reported to the UI
                    self._reply(502, {"error": f"upload failed: {str(exc)[:300]}"})
                    return
                if not isinstance(meta, dict) or not UPLOAD_ID_RE.match(str(meta.get("upload_id") or "")):
                    self._reply(502, {"error": str((meta or {}).get("error") or "upload refused")[:300]})
                    return
                att = {"upload_id": meta["upload_id"], "filename": str(meta.get("filename") or name)[:120],
                       "sha256": str(meta.get("sha256") or "")[:64], "size": length,
                       "language_notice": LANGUAGE_NOTICE}
                with api.lock:
                    api.attachments[tid] = att
                self._reply(201, att)

            def do_POST(self):
                if not self._authorized():
                    return
                if self.path.startswith("/api/upload?"):
                    self._upload()
                    return
                try:
                    length = min(int(self.headers.get("Content-Length") or 0), 64_000)
                    body = json.loads(self.rfile.read(length) or b"{}")
                except (ValueError, json.JSONDecodeError):
                    self._reply(400, {"error": "invalid JSON"})
                    return
                tid = str(body.get("thread_id") or "")[:64]
                if not tid:
                    self._reply(400, {"error": "thread_id required"})
                    return
                if self.path == "/api/send":
                    text = str(body.get("message") or "").strip()[:4000]
                    if not text:
                        self._reply(400, {"error": "message required"})
                        return
                    with api.lock:
                        att = api.attachments.pop(tid, None)  # one message per attachment
                    err = api.start_turn(tid, lambda emit: api.engine.send(tid, text, emit, att))
                    if err and att:
                        with api.lock:
                            api.attachments.setdefault(tid, att)
                elif self.path == "/api/detach":
                    with api.lock:
                        api.attachments.pop(tid, None)
                    err = None
                elif self.path == "/api/decide":
                    answers = body.get("answers")
                    if not isinstance(answers, list) or len(answers) != len(api.engine.pending.get(tid) or []):
                        self._reply(400, {"error": "one answer per pending request is required"})
                        return
                    err = api.start_turn(tid, lambda emit: api.engine.decide(tid, answers, emit))
                else:
                    self._reply(404, {"error": "not found"})
                    return
                self._reply(409 if err else 202, {"error": err} if err else {"ok": True})

        class _Server(ThreadingHTTPServer):
            allow_reuse_address = os.name != "nt"  # never share a port silently on Windows

            def server_bind(self):
                if os.name == "nt":
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                super().server_bind()

        server = _Server(("127.0.0.1", port), Handler)
        print(f"{self.info.get('name')} API on http://127.0.0.1:{port}", file=sys.stderr, flush=True)
        server.serve_forever()


def run_api(engine_factory, info: dict, port: int) -> None:
    """Run the asyncio loop (agent, tools) in a thread and the HTTP API in the main thread."""
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    holder: dict = {}

    async def setup():
        holder["engine"] = await engine_factory()
        ready.set()

    def run_loop():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(setup())
        loop.run_forever()

    threading.Thread(target=run_loop, daemon=True).start()
    if not ready.wait(300):
        raise SystemExit("chatbot did not start")
    ApiServer(holder["engine"], info, loop).serve(port)
