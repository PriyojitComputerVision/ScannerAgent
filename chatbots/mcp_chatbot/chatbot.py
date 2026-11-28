"""ScopeGuard chatbot over MCP: LangChain create_agent + langchain-mcp-adapters.

The ScopeGuard MCP server (Streamable HTTP at <server>/mcp, part of `pentest-agent`)
is loaded as LangChain tools with MultiServerMCPClient. The agent uses AgentState
and an InMemorySaver checkpointer; HumanInTheLoopMiddleware pauses before every
start_scan / start_demo_scan / cancel_scan until a human approves, edits or rejects.

Run from this folder (its own venv, MCP 1.x client):

    uv run python chatbot.py                                   # chat in the console
    uv run python chatbot.py --allow syslab-blond.vercel.app   # private server allowlisting your host
    uv run python chatbot.py --allow HOST --no-scanner-llm      # quick check: scanner without its LLM steps
    uv run python chatbot.py --url http://127.0.0.1:8765        # an already running pentest-agent
    uv run python chatbot.py --serve --port 8801                # JSON API for chatbots/ui

Sign-in is automatic: an API JWT signed with the repo's key (keys/), the same
GROQ_API_KEY and settings as the scanner (repo .env).
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys

from scopeguard_common import (
    MAX_FINDINGS,
    REPO,
    Engine,
    TokenMinter,
    bearer_auth,
    build_agent,
    compact_scan_result,
    console_loop,
    fetch_report,
    host_of,
    load_settings,
    log,
    mcp_json,
    run_api,
    scan_result_markdown,
    scanner_server,
)

NAME = "ScopeGuard MCP chatbot"


# MCP tools the model may call directly. get_scan is used through watch_scan, which
# streams progress and returns a compact result (Groq's per-request token limit).
MODEL_TOOLS = ("scan_policy", "start_scan", "start_demo_scan", "cancel_scan", "list_scans", "list_reports",
               "get_report")
# upload_code is never given to the model (a base64 archive in the prompt): the UI calls it directly.
POLL_SECONDS = 5


async def load_mcp_tools(base: str, minter: TokenMinter) -> list:
    """The scanner's MCP tools as LangChain tools (Streamable HTTP, fresh JWT per request)."""
    from langchain_mcp_adapters.client import MultiServerMCPClient

    client = MultiServerMCPClient({
        "scopeguard": {"transport": "streamable_http", "url": f"{base}/mcp", "auth": bearer_auth(minter)},
    })
    return await client.get_tools()


def make_watch_scan(get_scan):
    """A tool on top of the MCP get_scan tool: streams each finished scan step as an
    update while the scan runs, then returns the full result in compact form."""
    from langchain_core.tools import tool
    from langgraph.config import get_stream_writer

    @tool
    async def watch_scan(scan_id: str) -> str:
        """Follow a running scan until it ends, streaming each finished step to the user, and
        return the full result: severity counts, every finding (grouped), red flags, the
        executive summary, report files and the audit record. Call it right after a scan starts."""
        write = get_stream_writer()
        seen = 0
        announced = None  # the sign-in pause already shown to the user
        methods_shown = False
        parallel_shown = None  # the parallel steps already announced
        while True:
            data = mcp_json(await get_scan.ainvoke({"scan_id": scan_id, "wait_seconds": POLL_SECONDS,
                                                    "max_findings": 0}))
            if "steps_completed" not in data:  # refusal / unknown scan: hand the text to the model
                return str(data.get("text") or data)[:2000]
            for step in data["steps_completed"][seen:]:
                seen += 1
                write({"text": f"{step.get('node')} done (phase {step.get('phase')}, "
                               f"{step.get('at_seconds')}s)"})
            running = [str(r) for r in data.get("running_steps") or []]
            if running and parallel_shown is None:  # code check, website check and DAST run together
                parallel_shown = running
                write({"text": "running in parallel: " + ", ".join(running)})
            methods = data.get("login_methods") or {}
            if methods and not methods_shown and methods.get("kind") not in (None, "none"):
                methods_shown = True
                kinds = {"password": "a password form only", "sso": "SSO only",
                         "password_and_sso": "both a password form and SSO"}
                write({"text": f"sign-in found: {kinds.get(methods.get('kind'), methods.get('kind'))}"
                               + (f" (identity provider {methods['idp_host']})" if methods.get("idp_host") else "")})
            if data.get("status") == "input_required":
                # SSO / MFA: the UI shows a sign-in card (open the page, enter a code or a session
                # profile, or skip; Esc skips). Its answer goes straight to MCP, never through the model.
                pause = data.get("sign_in") or {}
                if pause and pause != announced:
                    announced = pause
                    write({"sign_in": {"scan_id": scan_id, **pause}})
                    write({"text": f"scan waits for sign-in ({pause.get('kind')}): {pause.get('evidence') or ''}"})
                await asyncio.sleep(POLL_SECONDS)
                continue
            if data.get("status") != "running":
                break
        final = mcp_json(await get_scan.ainvoke({"scan_id": scan_id, "wait_seconds": 0,
                                                 "max_findings": MAX_FINDINGS}))
        write({"text": f"scan {final.get('status')}: {final.get('findings_total', 0)} finding(s) "
                       f"{final.get('severity_counts', {})}"})
        # The user sees the scanner's own result (exact severities, real file paths); the model
        # gets the same data compactly and writes only the analysis.
        write({"scan_result": scan_result_markdown(final)})
        return ("The verified result block below has ALREADY been shown to the user (all findings under "
                "their severities, report files, audit record). Do not repeat that list.\n\n"
                + compact_scan_result(final))

    return watch_scan


# Every tool the chat agent can have; switch any of them off with CHATBOT_DISABLED_TOOLS
# (chatbot .env) or --disable-tool. The server can also switch MCP tools off for everyone
# (MCP_DISABLED_TOOLS in the main .env); those are simply not offered.
CHATBOT_TOOL_NAMES = (*MODEL_TOOLS, "watch_scan")


def parse_disabled(raw: str | list[str] | None) -> tuple[set[str], list[str]]:
    items = raw if isinstance(raw, list) else (raw or "").replace(";", ",").split(",")
    names = {n.strip() for n in items if n and n.strip()}
    return {n for n in names if n in CHATBOT_TOOL_NAMES}, sorted(n for n in names if n not in CHATBOT_TOOL_NAMES)


def select_tools(server_tools: dict, disabled: set[str]) -> tuple[list, dict]:
    """The chat agent's tools: what the server offers, minus what is switched off here.
    watch_scan needs the server's get_scan. Returns (tools, report for the UI/log)."""
    tools = [server_tools[n] for n in MODEL_TOOLS if n in server_tools and n not in disabled]
    if "watch_scan" not in disabled and "get_scan" in server_tools:
        tools.append(make_watch_scan(server_tools["get_scan"]))
    on = [t.name for t in tools]
    report = {"enabled": on,
              "disabled_here": sorted(disabled),
              "not_offered_by_server": sorted(n for n in CHATBOT_TOOL_NAMES
                                              if n not in on and n not in disabled)}
    if ({"start_scan", "start_demo_scan"} & set(on)) and "watch_scan" not in on:
        log.warning("Scans can start but cannot be followed: watch_scan is off or the server disabled get_scan.")
    return tools, report


async def make_engine(base: str, roles: list[str], disabled: set[str] | None = None) -> Engine:
    minter = TokenMinter(load_settings(), "mcp-chatbot", roles)
    server_tools = {t.name: t for t in await load_mcp_tools(base, minter)}
    tools, report = select_tools(server_tools, disabled or set())
    log.warning("Chatbot tools on: %s", ", ".join(report["enabled"]) or "none")
    engine = Engine(build_agent(tools))
    engine.tools_report = report

    if "scan_policy" in server_tools:
        async def policy() -> dict:  # for the UI's Allowed targets bar: straight from MCP, no LLM
            return mcp_json(await server_tools["scan_policy"].ainvoke({}))

        engine.policy = policy
    if "upload_code" in server_tools:
        async def upload(filename: str, content_base64: str, idempotency_key: str | None = None) -> dict:
            args = {"filename": filename, "content_base64": content_base64}
            if idempotency_key:
                args["idempotency_key"] = idempotency_key
            return mcp_json(await server_tools["upload_code"].ainvoke(args))

        engine.upload = upload
    if "submit_sign_in" in server_tools:
        async def sign_in(scan_id: str, action: str, code: str | None = None,
                          credentials: str | None = None) -> dict:
            """The user's answer to a scan's sign-in pause, straight to MCP (never via the model)."""
            if action == "skip" and "skip_sign_in" in server_tools:
                return mcp_json(await server_tools["skip_sign_in"].ainvoke({"scan_id": scan_id}))
            args = {"scan_id": scan_id, "action": action}
            if code:
                args["code"] = code
            if credentials:
                args["credentials"] = credentials
            return mcp_json(await server_tools["submit_sign_in"].ainvoke(args))

        engine.sign_in = sign_in
    engine.report = lambda session_id, filename: fetch_report(base, minter, session_id, filename)
    return engine


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        with contextlib.suppress(AttributeError, ValueError):
            stream.reconfigure(encoding="utf-8", errors="replace")
    env = load_settings().env  # defaults: this folder's .env, then the repo's .env
    ap = argparse.ArgumentParser(description=NAME)
    ap.add_argument("--url", default=env.get("SCOPEGUARD_URL") or "http://127.0.0.1:8765",
                    help="ScopeGuard server (pentest-agent) base URL (SCOPEGUARD_URL)")
    ap.add_argument("--allow", action="append", default=None, metavar="HOST_OR_URL",
                    help="start a private server that allowlists only these hosts (repeatable; CHATBOT_ALLOW)")
    ap.add_argument("--allow-none", action="store_true",
                    help="never start a private server (ignore CHATBOT_ALLOW); used by the UI, which runs the scanner")
    ap.add_argument("--start-server", action="store_true", help="start pentest-agent at --url if none answers")
    ap.add_argument("--no-scanner-llm", action="store_true",
                    help="the server this chatbot starts runs without its own LLM steps (faster check); "
                         "the chat agent still uses the LLM")
    ap.add_argument("--roles", default=env.get("CHATBOT_ROLES") or "scanner",
                    help="token roles, e.g. scanner or admin (CHATBOT_ROLES, default scanner)")
    ap.add_argument("--disable-tool", action="append", default=None, metavar="TOOL",
                    help="switch a chat tool off (repeatable; default CHATBOT_DISABLED_TOOLS). Tools: "
                         + ", ".join(CHATBOT_TOOL_NAMES))
    ap.add_argument("--serve", action="store_true", help="serve the JSON API for chatbots/ui instead of the console")
    ap.add_argument("--port", type=int, default=8801, help="API port with --serve (default 8801)")
    a = ap.parse_args(argv)
    a.no_scanner_llm = a.no_scanner_llm or env.get("CHATBOT_NO_SCANNER_LLM", "").lower() == "true"
    roles = [r.strip() for r in a.roles.split(",") if r.strip()]
    hosts = [] if a.allow_none else (a.allow if a.allow is not None else (env.get("CHATBOT_ALLOW") or "").split(","))
    allow = [host_of(h.strip()) for h in hosts if h.strip()]
    disabled, unknown = parse_disabled(a.disable_tool if a.disable_tool is not None
                                       else env.get("CHATBOT_DISABLED_TOOLS", ""))
    if unknown:
        print(f"Unknown tool name(s) ignored: {', '.join(unknown)}. Valid: {', '.join(CHATBOT_TOOL_NAMES)}",
              file=sys.stderr)

    with scanner_server(a.url, allow, a.start_server, scanner_llm=not a.no_scanner_llm) as base:
        info = {"name": NAME, "kind": "mcp", "server": base, "endpoint": f"{base}/mcp", "roles": roles,
                "allowlisted": allow or "from the server's .env", "repo": str(REPO),
                "scanner_llm": not a.no_scanner_llm}
        async def build() -> Engine:
            engine = await make_engine(base, roles, disabled)
            info["tools"] = engine.tools_report  # shown in the UI
            return engine

        if a.serve:
            run_api(build, info, a.port)
            return 0

        async def chat():
            engine = await build()
            print(f"Tools on: {', '.join(engine.tools_report['enabled']) or 'none'}")
            await console_loop(engine, f"{NAME} - tools from {base}/mcp (roles {', '.join(roles)})")

        asyncio.run(chat())
    return 0


if __name__ == "__main__":
    sys.exit(main())
