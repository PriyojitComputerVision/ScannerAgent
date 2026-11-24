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
    host_of,
    load_settings,
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
        while True:
            data = mcp_json(await get_scan.ainvoke({"scan_id": scan_id, "wait_seconds": POLL_SECONDS,
                                                    "max_findings": 0}))
            if "steps_completed" not in data:  # refusal / unknown scan: hand the text to the model
                return str(data.get("text") or data)[:2000]
            for step in data["steps_completed"][seen:]:
                seen += 1
                write({"text": f"{step.get('node')} done (phase {step.get('phase')}, "
                               f"{step.get('at_seconds')}s)"})
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


async def make_engine(base: str, roles: list[str]) -> Engine:
    minter = TokenMinter(load_settings(), "mcp-chatbot", roles)
    mcp_tools = {t.name: t for t in await load_mcp_tools(base, minter)}
    tools = [mcp_tools[n] for n in MODEL_TOOLS if n in mcp_tools] + [make_watch_scan(mcp_tools["get_scan"])]
    engine = Engine(build_agent(tools))

    async def policy() -> dict:  # for the UI's Allowed targets bar: straight from MCP, no LLM
        return mcp_json(await mcp_tools["scan_policy"].ainvoke({}))

    engine.policy = policy
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
    ap.add_argument("--serve", action="store_true", help="serve the JSON API for chatbots/ui instead of the console")
    ap.add_argument("--port", type=int, default=8801, help="API port with --serve (default 8801)")
    a = ap.parse_args(argv)
    a.no_scanner_llm = a.no_scanner_llm or env.get("CHATBOT_NO_SCANNER_LLM", "").lower() == "true"
    roles = [r.strip() for r in a.roles.split(",") if r.strip()]
    hosts = [] if a.allow_none else (a.allow if a.allow is not None else (env.get("CHATBOT_ALLOW") or "").split(","))
    allow = [host_of(h.strip()) for h in hosts if h.strip()]

    with scanner_server(a.url, allow, a.start_server, scanner_llm=not a.no_scanner_llm) as base:
        info = {"name": NAME, "kind": "mcp", "server": base, "endpoint": f"{base}/mcp", "roles": roles,
                "allowlisted": allow or "from the server's .env", "repo": str(REPO),
                "scanner_llm": not a.no_scanner_llm}
        if a.serve:
            run_api(lambda: make_engine(base, roles), info, a.port)
            return 0

        async def chat():
            engine = await make_engine(base, roles)
            await console_loop(engine, f"{NAME} - tools from {base}/mcp (roles {', '.join(roles)})")

        asyncio.run(chat())
    return 0


if __name__ == "__main__":
    sys.exit(main())
