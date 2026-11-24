"""Watch the ScopeGuard A2A agent work, one event at a time.

Talks to the A2A endpoint that starts with `uv run pentest-agent`
(http://127.0.0.1:8765/a2a), the way another agent would: it reads the public
agent card, then sends a scan request and streams the task's events (SSE).

Setup is automatic:

* Sign-in: the script mints an API JWT with this machine's key (keys/), so no
  token has to be copied anywhere. Role scanner, or admin for --sign-in /
  --credentials (signing in to a target needs scan:authenticated).
* Server: if no pentest-agent is running it starts one headless for this run
  and stops it afterwards (log: data/logs/agent-server-for-clients.log).
* Target: without --target it scans the built-in, deliberately vulnerable demo
  app. With --target the host goes on A2A_ALLOWED_TARGETS for the server this
  script starts. If a pentest-agent is already running and its .env does not
  allowlist the host, the script automatically starts a private agent on a free
  port for this run instead (like stdio MCP); --own-server always does that.

Examples (from the repo root):

    uv run python scripts/a2a_client.py                              # demo app, quick, streamed
    uv run python scripts/a2a_client.py --profile standard --delay 2
    uv run python scripts/a2a_client.py --sign-in --profile standard # demo app, signed in
    uv run python scripts/a2a_client.py --target http://localhost:3000 --i-am-authorized
    uv run python scripts/a2a_client.py --target http://localhost:3000 --i-am-authorized --credentials local
    uv run python scripts/a2a_client.py --no-llm --show-refusal
"""
from __future__ import annotations

import argparse
import sys
import uuid
from urllib.parse import urlparse

import anyio
import httpx
from _client_common import (
    NODE_NOTES,
    Events,
    agent_server,
    allowlist_hint,
    allowlisted,
    free_port,
    mint_token,
    short,
)
from a2a.client import ClientConfig, create_client
from a2a.helpers.proto_helpers import get_data_parts, get_message_text, new_data_part
from a2a.types.a2a_pb2 import Message, Role, SendMessageRequest, TaskState
from google.protobuf.json_format import MessageToDict

NEED_PRIVATE = 3  # session() result: target not allowlisted on the shared agent
TERMINAL = {TaskState.TASK_STATE_COMPLETED: "completed", TaskState.TASK_STATE_FAILED: "failed",
            TaskState.TASK_STATE_CANCELED: "canceled", TaskState.TASK_STATE_REJECTED: "rejected"}


def request(data: dict) -> SendMessageRequest:
    return SendMessageRequest(message=Message(message_id=uuid.uuid4().hex, role=Role.ROLE_USER,
                                              parts=[new_data_part(data)]))


async def ask(client, data: dict) -> list:
    """One request; returns every streamed event."""
    return [event async for event in client.send_message(request(data))]


def message_data(events) -> tuple[str, dict]:
    for ev in events:
        if ev.HasField("message"):
            data = next((d for d in get_data_parts(ev.message.parts) if isinstance(d, dict)), {})
            return get_message_text(ev.message), data
    return "", {}


async def run(a: argparse.Namespace) -> int:
    ev = Events(a.delay)
    env = {}
    if a.target:
        env["A2A_ALLOWED_TARGETS"] = urlparse(a.target).netloc
    if a.no_llm:
        env["GROQ_API_KEY"] = ""
    roles = ["admin"] if (a.sign_in or a.credentials) else ["scanner"]
    token = mint_token("a2a-test-client", roles)
    await ev.emit("auth", "Automatic sign-in: API JWT minted with this machine's key",
                  {"subject": "a2a-test-client", "roles": roles, "token": token[:16] + "… (not shown)"})

    if not a.own_server:
        base = a.url.rstrip("/")
        with agent_server(base, urlparse(base).port or 8765, env) as (started, log_path):
            code = await session(a, ev, token, base, started, log_path)
        if code != NEED_PRIVATE:
            return code
    # Like stdio MCP: a private agent for this run, with only the target allowlisted.
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    with agent_server(base, port, env) as (started, log_path):
        return await session(a, ev, token, base, started, log_path)


async def session(a: argparse.Namespace, ev: Events, token: str, base: str, started: bool, log_path) -> int:
    await ev.emit("launch", "pentest-agent " + ("started for this run (headless)" if started
                                                else "already running: using it"),
                  f"A2A endpoint: {base}/a2a" + (f"\nserver log -> {log_path}" if log_path else
                                                 "\nits .env decides A2A_ALLOWED_TARGETS"))
    async with httpx.AsyncClient(headers={"Authorization": f"Bearer {token}"},
                                 timeout=httpx.Timeout(60, read=None)) as http:
        client = await create_client(base, ClientConfig(httpx_client=http, streaming=True))
        card = client._card
        await ev.emit("card", f"Agent card: {card.name}", {
            "url": [i.url for i in card.supported_interfaces],
            "streaming": card.capabilities.streaming,
            "security": list(card.security_schemes),
            "skills": [f"{s.id}: {s.name}" for s in card.skills]})

        text, policy = message_data(await ask(client, {"action": "policy"}))
        await ev.emit("policy", text or "Scan policy", {
            "principal": policy.get("principal", {}).get("sub"),
            "roles": policy.get("principal", {}).get("roles"),
            "allowed_targets": policy.get("allowed_targets"),
            "profiles_allowed": [p["profile"] for p in policy.get("profiles", []) if p.get("allowed")],
            "credential_profiles": [p.get("name") for p in
                                    policy.get("authenticated_scans", {}).get("credential_profiles", [])]})

        if a.target and not allowlisted(a.target, policy.get("allowed_targets") or []):
            if not started:  # the shared agent's .env does not list it: use a private agent instead
                await ev.emit("switch", f"{urlparse(a.target).netloc} is not on the running agent's allowlist",
                              "Starting a private pentest-agent for this run (free port, only this host "
                              "allowlisted, stopped afterwards). To scan it on the shared agent:\n"
                              + allowlist_hint(a.target, "A2A_ALLOWED_TARGETS", started).split("\nOr ")[0])
                return NEED_PRIVATE
            await ev.emit("setup", f"{urlparse(a.target).netloc} is not on this server's allowlist",
                          allowlist_hint(a.target, "A2A_ALLOWED_TARGETS", started))
            return 2

        if a.show_refusal:
            events = await ask(client, {"action": "scan", "target_url": "https://example.com/",
                                        "authorization_confirmed": True, "profile": "quick"})
            await ev.emit("guardrail", "A host that is NOT allowlisted (expected: task rejected)",
                          short(_last_status_text(events), 400))

        if a.target:
            req = {"action": "scan", "target_url": a.target, "authorization_confirmed": True,
                   "profile": a.profile, "max_findings": a.findings}
            if a.credentials:
                req["credentials"] = a.credentials  # only the profile name travels
        else:
            req = {"action": "demo_scan", "profile": a.profile, "sign_in": a.sign_in,
                   "max_findings": a.findings}
        await ev.emit("send", "SendStreamingMessage", req)

        final, result = None, {}
        async for event in client.send_message(request(req)):
            if event.HasField("task"):
                await ev.emit("task", f"Task created: {event.task.id}",
                              f"state: {TaskState.Name(event.task.status.state)}")
            elif event.HasField("status_update"):
                st = event.status_update.status
                meta = MessageToDict(event.status_update.metadata) if event.status_update.metadata else {}
                text = get_message_text(st.message) if st.HasField("message") else ""
                if meta.get("node"):
                    await ev.emit("step", f"{meta['node']}  (scan time {meta.get('at_seconds')}s)",
                                  (NODE_NOTES.get(meta["node"], "") + f"\nphase -> {meta.get('phase')}").strip())
                else:
                    await ev.emit("status", TaskState.Name(st.state), text or None)
                if st.state in TERMINAL:
                    final = TERMINAL[st.state]
            elif event.HasField("artifact_update"):
                art = event.artifact_update.artifact
                result = next((d for d in get_data_parts(art.parts) if isinstance(d, dict)), {})
                await ev.emit("artifact", f"Artifact: {art.name}", {
                    "status": result.get("status"), "signed_in": result.get("signed_in"),
                    "credentials": result.get("credentials"), "severity_counts": result.get("severity_counts"),
                    "findings_total": result.get("findings_total")})
            elif event.HasField("message"):
                await ev.emit("message", get_message_text(event.message))

        findings = result.get("findings") or []
        for i, f in enumerate(findings, 1):
            await ev.finding(i, len(findings), f)
        if result.get("findings_omitted"):
            await ev.emit("more", f"{result['findings_omitted']} more finding(s) not returned",
                          "See the full list in the report files below.")
        for flag in result.get("red_flags") or []:
            await ev.emit("red flag", short(flag, 300))
        if result.get("report_files"):
            await ev.emit("report", "Report files", result["report_files"])
        if result.get("audit"):
            await ev.emit("audit", "Tamper-evident audit record written", result["audit"])
        await client.close()
    await ev.emit("exit", f"Task finished: {final}")
    return 0 if final == "completed" else 1


def _last_status_text(events) -> str:
    for event in reversed(events):
        if event.HasField("status_update") and event.status_update.status.HasField("message"):
            return f"{TaskState.Name(event.status_update.status.state)}: " \
                   f"{get_message_text(event.status_update.status.message)}"
        if event.HasField("message"):
            return get_message_text(event.message)
    return ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--url", default="http://127.0.0.1:8765", help="pentest-agent base URL")
    ap.add_argument("--own-server", action="store_true",
                    help="always start a private agent for this run (like stdio MCP), even if one is running")
    ap.add_argument("--target", help="URL to scan (default: the built-in demo app)")
    ap.add_argument("--i-am-authorized", action="store_true",
                    help="required with --target: you own the target or may test it")
    ap.add_argument("--sign-in", action="store_true", help="demo app: sign in with its public fake account")
    ap.add_argument("--credentials", metavar="PROFILE", help="with --target: credential profile name")
    ap.add_argument("--profile", default="quick", choices=["quick", "standard"], help="scan profile")
    ap.add_argument("--delay", type=float, default=1.0, help="pause after each event, seconds (default 1)")
    ap.add_argument("--findings", type=int, default=100,
                    help="findings to show one by one (default 100 = all, the server maximum)")
    ap.add_argument("--no-llm", action="store_true", help="no Groq calls (only for a server this script starts)")
    ap.add_argument("--show-refusal", action="store_true", help="also show the allowlist rejecting a host")
    a = ap.parse_args(argv)
    if a.target and not a.i_am_authorized:
        ap.error("--target needs --i-am-authorized: only scan systems you own or may test")
    if a.sign_in and a.target:
        ap.error("--sign-in is for the demo app; use --credentials PROFILE with --target")
    if a.credentials and not a.target:
        ap.error("--credentials needs --target")
    try:
        return anyio.run(run, a)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
