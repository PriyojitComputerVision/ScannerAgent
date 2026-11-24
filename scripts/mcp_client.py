"""Watch the ScopeGuard MCP server work, one event at a time.

Runs a scan through MCP exactly as a coding assistant would and prints every
step as a numbered event with a pause in between.

Two transports:

* stdio (default): starts `scopeguard-mcp` as a child process. No login exists
  on stdio: only the process that started the server can talk to it.
* --http: talks to http://127.0.0.1:8765/mcp, the endpoint that starts with
  `uv run pentest-agent`. Sign-in is automatic: the script mints an API JWT with
  this machine's key (keys/). If no pentest-agent is running it starts one
  headless for this run and stops it afterwards. If one is running but its .env
  does not allowlist --target, it starts a private agent on a free port for this
  run instead; --own-server always does that.

Without --target it scans the built-in, deliberately vulnerable demo app (no
allowlist entry needed). With --target you are the operator: the script puts
that host on the allowlist (MCP_ALLOWED_TARGETS, for this run only, unless a
pentest-agent is already running with its own .env) and confirms authorization
because you passed --i-am-authorized.

Examples (from the repo root):

    uv run python scripts/mcp_client.py                              # stdio, demo app, quick
    uv run python scripts/mcp_client.py --http                       # same over HTTP (autostarted agent)
    uv run python scripts/mcp_client.py --profile standard --delay 2
    uv run python scripts/mcp_client.py --sign-in --profile standard # demo app, signed in automatically
    uv run python scripts/mcp_client.py --target http://localhost:3000 --i-am-authorized
    uv run python scripts/mcp_client.py --target http://localhost:3000 --i-am-authorized --credentials local
    uv run python scripts/mcp_client.py --no-llm --findings 5        # offline, show 5 findings

Authenticated scans: --sign-in uses the demo app's public, fake account; --credentials
names a profile you stored once with `uv run scopeguard-mcp credentials add` (the
password is prompted for and stays on the server side). Signing in needs the
scan:authenticated permission, so the script uses the admin role for that run.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import anyio
import httpx2  # the MCP SDK's HTTP client package
from _client_common import (
    NODE_NOTES,
    REPO,
    Events,
    agent_server,
    allowlist_hint,
    allowlisted,
    free_port,
    mint_token,
    short,
)
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client


def payload(result) -> dict | list:
    text = result.content[0].text if result.content else ""
    try:
        return json.loads(text)
    except ValueError:
        return {"text": text}


NEED_PRIVATE = 3  # session() result: target not allowlisted on the shared agent


def server_env(a: argparse.Namespace) -> dict[str, str]:
    env = {"PYTHONPATH": str(REPO / "src"), "PYTHONIOENCODING": "utf-8"}
    if a.target:
        env["MCP_ALLOWED_TARGETS"] = urlparse(a.target).netloc
    if a.sign_in or a.credentials:
        env["MCP_ROLE"] = "admin"  # stdio: signing in to a target needs scan:authenticated
    if a.no_llm:
        env["GROQ_API_KEY"] = ""
    return env


async def run(a: argparse.Namespace) -> int:
    ev = Events(a.delay)
    env = server_env(a)
    if not a.http:
        params = StdioServerParameters(command=sys.executable, args=["-m", "pentest_agent.mcp_server.server"],
                                       cwd=str(REPO), env=env)
        server_log = REPO / "data" / "logs" / "mcp-client-server.log"
        server_log.parent.mkdir(parents=True, exist_ok=True)
        await ev.emit("launch", "Starting the MCP server as a child process (stdio transport)",
                      f"{Path(sys.executable).name} -m pentest_agent.mcp_server.server   (cwd: {REPO})"
                      f"\nserver stderr -> {server_log}\nauth: none needed (only this process can talk to it)"
                      + (f"\nMCP_ALLOWED_TARGETS={env['MCP_ALLOWED_TARGETS']}   (set by you, the operator)"
                         if a.target else "\nno allowlist needed: scanning the built-in demo app")
                      + ("\nMCP_ROLE=admin for this run (authenticated scan)" if "MCP_ROLE" in env else ""))
        with server_log.open("w", encoding="utf-8") as errlog, contextlib.redirect_stderr(errlog):
            return await session(a, ev, Client(stdio_client(params, errlog=errlog)))

    base = a.url.rstrip("/")
    roles = ["admin"] if (a.sign_in or a.credentials) else ["scanner"]
    token = mint_token("mcp-test-client", roles)
    await ev.emit("auth", "Automatic sign-in: API JWT minted with this machine's key",
                  {"subject": "mcp-test-client", "roles": roles, "token": token[:16] + "… (not shown)"})
    if not a.own_server:
        code = await http_session(a, ev, env, token, base, urlparse(base).port or 8765)
        if code != NEED_PRIVATE:
            return code
    # Like stdio: a private agent for this run, with only the target allowlisted.
    port = free_port()
    return await http_session(a, ev, env, token, f"http://127.0.0.1:{port}", port)


async def http_session(a: argparse.Namespace, ev: Events, env: dict, token: str, base: str, port: int) -> int:
    with agent_server(base, port, env) as (started, log_path):
        a.server_started = started
        await ev.emit("launch", "pentest-agent " + ("started for this run (headless)" if started
                                                    else "already running: using it"),
                      f"MCP endpoint: {base}/mcp" + (f"\nserver log -> {log_path}" if log_path else
                                                     "\nits .env decides MCP_ALLOWED_TARGETS"))
        http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=httpx2.Timeout(120))
        async with http:
            return await session(a, ev, Client(streamable_http_client(f"{base}/mcp", http_client=http)))


async def session(a: argparse.Namespace, ev: Events, client_cm) -> int:
    async with client_cm as client:
        info = client.server_info
        await ev.emit("connect", "Handshake done (initialize)", {
            "server": getattr(info, "name", None), "title": getattr(info, "title", None),
            "protocol_version": client.protocol_version, "transport": "http" if a.http else "stdio"})
        await ev.emit("instructions", "What the server tells every assistant", client.instructions or "")

        tools = (await client.list_tools()).tools
        await ev.emit("tools", f"{len(tools)} tools available",
                      "\n".join(f"- {t.name}: {short(t.description, 110)}" for t in tools))

        policy = payload(await client.call_tool("scan_policy", {}))
        auth_info = policy.get("authenticated_scans", {})
        await ev.emit("policy", "scan_policy: what this caller may do", {
            "principal": policy.get("principal", {}).get("sub"),
            "roles": policy.get("principal", {}).get("roles"),
            "allowed_targets": policy.get("allowed_targets"),
            "profiles_allowed": [p["profile"] for p in policy.get("profiles", []) if p.get("allowed")],
            "llm_available": policy.get("llm_available"),
            "authenticated_scans": auth_info.get("allowed"),
            "credential_profiles": [p.get("name") for p in auth_info.get("credential_profiles", [])]})

        if a.target and not allowlisted(a.target, policy.get("allowed_targets") or []):
            if a.http and not getattr(a, "server_started", True):
                await ev.emit("switch", f"{urlparse(a.target).netloc} is not on the running agent's allowlist",
                              "Starting a private pentest-agent for this run (free port, only this host "
                              "allowlisted, stopped afterwards). To scan it on the shared agent:\n"
                              + allowlist_hint(a.target, "MCP_ALLOWED_TARGETS", False).split("\nOr ")[0])
                return NEED_PRIVATE
            await ev.emit("setup", f"{urlparse(a.target).netloc} is not on this server's allowlist",
                          allowlist_hint(a.target, "MCP_ALLOWED_TARGETS", getattr(a, "server_started", True)))
            return 2

        known = [p.get("name") for p in auth_info.get("credential_profiles", [])]
        if a.credentials and a.credentials not in known:
            host = urlparse(a.target).netloc
            await ev.emit("setup", f"Credential profile {a.credentials!r} does not exist yet",
                          "Store it once (the password/token is asked for in a hidden prompt), then run again:\n"
                          f"  uv run scopeguard-mcp credentials add {a.credentials} --target {host} "
                          f"--login-url {a.target.rstrip('/')}/login --username YOUR_USER "
                          "--username-field username --password-field password\n"
                          "Field names = the name=\"...\" of the login form's inputs. "
                          "For a bearer-token API, leave out --login-url/--username.\n"
                          f"Existing profiles: {', '.join(known) or 'none'}")
            return 2

        if a.show_refusal:
            res = await client.call_tool("start_scan", {"target_url": "https://example.com/",
                                                        "authorization_confirmed": True, "profile": "quick"})
            await ev.emit("guardrail", "Trying a host that is NOT allowlisted (expected refusal)",
                          short(res.content[0].text if res.content else "", 400))

        if a.target:
            args = {"target_url": a.target, "authorization_confirmed": True, "profile": a.profile}
            if a.credentials:
                args["credentials"] = a.credentials  # only the name; the secret stays on the server
            start = await client.call_tool("start_scan", args)
        else:
            start = await client.call_tool("start_demo_scan", {"profile": a.profile, "sign_in": a.sign_in})
        started = payload(start)
        if start.is_error:
            await ev.emit("refused", "The server refused the scan",
                          started.get("text") if isinstance(started, dict) else started)
            return 1
        if a.sign_in or a.credentials:
            await ev.emit("auth", "Authenticated scan requested",
                          "demo account (public, fake): the server signs in, the client never sees a secret"
                          if a.sign_in else f"credential profile {a.credentials!r}: only its name was sent")
        scan_id = started["scan_id"]
        await ev.emit("scan", f"Scan started: {scan_id}", {
            "target": started["target_url"], "profile": started["profile"], "status": started["status"]})

        seen, last_phase, deadline = 0, None, time.monotonic() + a.timeout
        while True:
            status = payload(await client.call_tool(
                "get_scan", {"scan_id": scan_id, "wait_seconds": a.poll, "max_findings": a.findings}))
            for step in status["steps_completed"][seen:]:
                seen += 1
                note = NODE_NOTES.get(step["node"], "")
                if step["phase"] != last_phase:
                    note += f"\nphase -> {step['phase']}"
                last_phase = step["phase"]
                await ev.emit("step", f"{step['node']}  (scan time {step['at_seconds']}s)", note.strip() or None)
            if status["status"] != "running":
                break
            if time.monotonic() > deadline:
                await ev.emit("timeout", f"Still running after {a.timeout}s: cancelling",
                              payload(await client.call_tool("cancel_scan", {"scan_id": scan_id})))
                return 1

        await ev.emit("done", f"Scan {status['status']} in {status['elapsed_seconds']}s", {
            "signed_in": status.get("signed_in"), "credentials": status.get("credentials"),
            "pages_crawled": status.get("pages_crawled"), "severity_counts": status.get("severity_counts"),
            "findings_total": status.get("findings_total"), "error": status.get("error")})
        findings = status.get("findings") or []
        for i, f in enumerate(findings, 1):
            await ev.finding(i, len(findings), f)
        if status.get("findings_omitted"):
            await ev.emit("more", f"{status['findings_omitted']} more finding(s) not returned",
                          "See the full list in the report files below.")
        for flag in status.get("red_flags") or []:
            await ev.emit("red flag", short(flag, 300))
        if status.get("executive_summary"):
            await ev.emit("summary", "Executive summary (wrapped as untrusted target content)",
                          short(status["executive_summary"], 900))
        if status.get("report_files"):
            await ev.emit("report", "Report files", status["report_files"])
        if status.get("audit"):
            await ev.emit("audit", "Tamper-evident audit record written", status["audit"])
    await ev.emit("exit", "MCP session closed")
    return 0 if status["status"] == "completed" else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--http", action="store_true",
                    help="use the /mcp endpoint of pentest-agent (auto JWT; starts the agent if needed)")
    ap.add_argument("--url", default="http://127.0.0.1:8765", help="pentest-agent base URL for --http")
    ap.add_argument("--own-server", action="store_true",
                    help="with --http: always start a private agent for this run, even if one is running")
    ap.add_argument("--target", help="URL to scan (default: the built-in demo app)")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="required with --target: you own the target or may test it")
    ap.add_argument("--sign-in", action="store_true",
                    help="demo app only: sign in with its public fake account (authenticated scan)")
    ap.add_argument("--credentials", metavar="PROFILE",
                    help="with --target: credential profile to sign in with "
                         "(create it first: uv run scopeguard-mcp credentials add ...)")
    ap.add_argument("--profile", default="quick", choices=["quick", "standard"],
                    help="scan profile (default quick)")
    ap.add_argument("--delay", type=float, default=1.0, help="pause after each event, seconds (default 1)")
    ap.add_argument("--poll", type=float, default=1.0, help="how long each get_scan waits, seconds (default 1)")
    ap.add_argument("--findings", type=int, default=100,
                    help="findings to show one by one (default 100 = all, the server maximum)")
    ap.add_argument("--timeout", type=int, default=900, help="cancel the scan after this many seconds")
    ap.add_argument("--no-llm", action="store_true", help="run without the LLM (no Groq calls)")
    ap.add_argument("--show-refusal", action="store_true",
                    help="also show the allowlist refusing a host that is not listed")
    a = ap.parse_args(argv)
    if a.target and not a.i_am_authorized:
        ap.error("--target needs --i-am-authorized: only scan systems you own or may test")
    if a.target and urlparse(a.target).scheme not in ("http", "https"):
        ap.error("--target must be an http(s) URL")
    if a.sign_in and a.target:
        ap.error("--sign-in is for the demo app; use --credentials PROFILE with --target")
    if a.credentials and not a.target:
        ap.error("--credentials needs --target (the demo app uses --sign-in)")
    try:
        return anyio.run(run, a)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
