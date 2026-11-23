"""Command-line WebSocket client: the Postman flow, without Postman.

Start the server in one terminal, then run scans from another:

    uv run pentest-agent
    uv run python scripts/ws_client.py --simulate                     # built-in vulnerable target
    uv run python scripts/ws_client.py https://your-app.example --profile quick
    uv run python scripts/ws_client.py --session-id demo-1 --resume   # resume a checkpointed run
    uv run python scripts/ws_client.py --payload body.json            # send a Postman-style JSON body

What it does, like a Postman session:
1. Checks GET /healthz.
2. Gets an access token: --token, else POST /auth/token with AUTH_CLIENT_ID /
   AUTH_CLIENT_SECRET from .env, else a token signed locally with keys/ (like
   scripts/get_token.py). --no-auth skips this (server with AUTH_ENABLED=false).
3. Connects to ws://<host>:<port>/ws?session_id=<id>, sending the token in the
   first message (default), the Authorization header, or ?access_token=.
4. Sends the scan request, prints every server message as it arrives, adopts
   "token_refreshed" tokens, and prints the report URLs at the end.
5. With --interactive-auth, answers a sign-in pause (SSO / MFA, human in the
   loop): it asks for the one-time code, or for the session cookie / bearer
   token after you signed in in your browser, with hidden input. Empty = skip.

Exit codes: 0 complete, 1 server error / rejected, 2 socket closed early,
3 server not reachable or no token. Only scan sites you own or are authorized to test.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import sys
import time
import urllib.error
import urllib.request
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import urlencode

import websockets

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pentest_agent import api_auth, rbac
from pentest_agent.auth_client import AuthenticationFailed, TokenManager
from pentest_agent.config import settings


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run a scan over the agent WebSocket (Postman replacement).")
    p.add_argument("url", nargs="?", help="target URL (omit with --simulate, --resume or --payload)")
    p.add_argument("--profile", default="standard", choices=["quick", "standard", "aggressive", "auth_deep"])
    p.add_argument("--simulate", action="store_true", help="scan the built-in vulnerable target")
    p.add_argument("--session-id", help="session id (default: ws-<timestamp>)")
    p.add_argument("--resume", action="store_true", help='send {"resume": true} for --session-id')
    p.add_argument("--force-refresh", action="store_true", help="ignore a cached result for the same request")
    p.add_argument("--allow-domain", action="append", default=[], metavar="DOMAIN",
                   help="extra in-scope domain (repeatable)")
    p.add_argument("--notes", help="free-text notes stored with the scan")
    p.add_argument("--interactive-auth", action="store_true",
                   help="pause for SSO / MFA sign-in and ask here (admin; human in the loop)")
    p.add_argument("--payload", type=Path, metavar="FILE",
                   help="JSON file sent as the request body (overrides the scan options above)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=settings.ws_port)
    p.add_argument("--token", help="access token to use as-is (e.g. from scripts/get_token.py)")
    p.add_argument("--token-in", default="message", choices=["message", "header", "query"],
                   help="where to send the token (default: first JSON message)")
    p.add_argument("--no-auth", action="store_true", help="send no token (server has AUTH_ENABLED=false)")
    p.add_argument("--raw", action="store_true", help="print every message as full JSON")
    p.add_argument("--save-md", type=Path, metavar="FILE", help="write the markdown report here")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="confirm you own or may test the target (not needed with --simulate/--resume)")
    args = p.parse_args(argv)
    if not (args.url or args.simulate or args.resume or args.payload):
        p.error("give a target URL, --simulate, --resume or --payload")
    if args.resume and not args.session_id:
        p.error("--resume needs the --session-id of the run to resume")
    if args.url and not (args.i_have_authorization or args.payload):
        p.error("scanning a real target needs --i-have-authorization (only scan sites you own "
                "or are authorized to test)")
    return args


def _check_health(base: str) -> None:
    try:
        with urllib.request.urlopen(f"{base}/healthz", timeout=5) as r:
            health = json.load(r)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SystemExit(_fail(3, f"server not reachable at {base} ({exc}). Start it with: "
                                  "uv run pentest-agent"))
    if not health.get("graph_initialized", True):
        print(f"[warn] server is up but the graph is not initialized: {health}")


def _fail(code: int, message: str) -> int:
    print(f"[error] {message}", file=sys.stderr)
    return code


def _token_source(args: argparse.Namespace, base: str):
    """Returns (initial token or None, TokenManager or None)."""
    if args.no_auth:
        return None, None
    if args.token:
        return args.token.strip(), None
    if settings.auth_client_secret:
        tm = TokenManager(base, settings.auth_client_id, settings.auth_client_secret)
        try:
            token = tm.get_token()
        except (AuthenticationFailed, OSError) as exc:
            raise SystemExit(_fail(3, f"sign-in at {base}/auth/token failed: {exc}"))
        print(f"[auth] signed in as '{settings.auth_client_id}' via /auth/token, roles: {', '.join(tm.roles)}")
        return token, tm
    if api_auth.keys_present():
        roles = rbac.parse_roles(settings.auth_client_roles)
        pair = api_auth.issue_tokens(settings.auth_client_id, roles)
        print(f"[auth] token signed locally with keys/ for '{settings.auth_client_id}', roles: {', '.join(roles)}")
        return pair.access_token, None
    raise SystemExit(_fail(3, "no token: pass --token, set AUTH_CLIENT_SECRET in .env, create keys "
                              "with scripts/get_token.py, or use --no-auth"))


def _build_payload(args: argparse.Namespace, target_url: str | None) -> dict:
    if args.payload:
        body = json.loads(args.payload.read_text(encoding="utf-8"))
        if not isinstance(body, dict):
            raise SystemExit(_fail(1, f"{args.payload} must hold a JSON object"))
        return body
    if args.resume:
        return {"resume": True}
    body: dict = {"url": target_url, "profile": args.profile, "authorization_confirmed": True,
                  "additional_allowed_domains": args.allow_domain}
    if args.notes:
        body["notes"] = args.notes
    if args.force_refresh:
        body["force_refresh"] = True
    if args.interactive_auth:
        body["interactive_auth"] = True
    return body


def _ask_sign_in(msg: dict) -> dict:
    """Terminal answer to a sign-in pause. Secrets are read with getpass (not echoed)."""
    req = msg.get("request") or {}
    print(f"\n[sign-in] {msg.get('message', '')}")
    for key in ("evidence", "idp_host", "login_url", "target_url"):
        if req.get(key):
            print(f"          {key}: {req[key]}")
    print(f"          answer within {msg.get('timeout_seconds')}s; leave empty to skip")
    if not sys.stdin.isatty():
        print("          (stdin is not a terminal: skipping)")
        return {"action": "skip"}
    if req.get("kind") == "mfa":
        code = getpass.getpass("          one-time code: ").strip()
        return {"action": "mfa_code", "code": code} if code else {"action": "skip"}
    cookie = getpass.getpass("          Cookie header for the target (name=value; ...): ").strip()
    bearer = getpass.getpass("          or bearer token: ").strip()
    if not (cookie or bearer):
        return {"action": "skip"}
    return {"action": "session", **({"cookie": cookie} if cookie else {}), **({"bearer": bearer} if bearer else {})}


def _print_message(msg: dict, raw: bool) -> None:
    if raw:
        print(json.dumps(msg, indent=2, default=str))
        return
    kind = msg.get("type")
    if kind == "status":
        print(f"[status] {msg.get('message', '')}")
    elif kind == "queued":
        print(f"[queue]  #{msg.get('position')} of {msg.get('queue_length')}: {msg.get('message', '')}")
    elif kind == "phase_update":
        data = msg.get("data") or {}
        extra = []
        for key in ("findings", "red_flags", "crawled_pages"):
            if isinstance(data.get(key), list) and data[key]:
                extra.append(f"+{len(data[key])} {key}")
        print(f"[phase]  node={msg.get('node', ''):<15} phase={data.get('phase', '')} {' '.join(extra)}")
    elif kind == "error":
        print(f"[error]  {msg.get('code', '')} {msg.get('message', msg)}")
    elif kind != "complete":
        print(f"[{kind}] {json.dumps(msg, default=str)[:300]}")


async def _run(args: argparse.Namespace, target_url: str | None) -> int:
    base = f"http://{args.host}:{args.port}"
    _check_health(base)
    session_id = args.session_id or f"ws-{int(time.time())}"
    payload = _build_payload(args, target_url)
    # A token inside the --payload body (Postman style) is used as-is; no sign-in.
    body_token = payload.pop("access_token", None)
    if body_token and not args.token:
        args.token = body_token
        print("[auth]   using the access_token from the payload file")
    token, tm = _token_source(args, base)

    query = {"session_id": session_id}
    headers = {}
    if token and args.token_in == "query":
        query["access_token"] = token
    elif token and args.token_in == "header":
        headers["Authorization"] = f"Bearer {token}"
    elif token:
        payload = {"access_token": token, **payload}
    uri = f"ws://{args.host}:{args.port}/ws?{urlencode(query)}"
    shown = {k: v for k, v in payload.items() if k != "access_token"}
    print(f"[ws]     connect ws://{args.host}:{args.port}/ws?session_id={session_id} (token in {args.token_in})")
    print(f"[ws]     send {json.dumps(shown)}")

    try:
        ws = await websockets.connect(uri, max_size=None, additional_headers=headers or None)
    except (OSError, websockets.exceptions.InvalidHandshake) as exc:
        return _fail(3, f"WebSocket connect failed: {exc}")
    async with ws:
        await ws.send(json.dumps(payload))
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg.get("type") == "token_refreshed":
                    if tm:
                        tm.observe_ws_message(msg)
                    print(f"[auth]   server renewed the token (expires {msg.get('expires_at')})")
                    continue
                if msg.get("type") == "input_required":
                    answer = await asyncio.to_thread(_ask_sign_in, msg)
                    await ws.send(json.dumps({"type": "auth_response", **answer}))
                    continue
                if msg.get("type") == "input_invalid":
                    print(f"[sign-in] answer rejected: {msg.get('message')} "
                          f"{'; '.join(d.get('msg', '') for d in msg.get('detail') or [])}")
                    answer = await asyncio.to_thread(_ask_sign_in, {"request": {}, "message": "Try again."})
                    await ws.send(json.dumps({"type": "auth_response", **answer}))
                    continue
                _print_message(msg, args.raw)
                if msg.get("type") == "error":
                    return 1
                if msg.get("type") == "complete":
                    return _report(msg, args)
        except websockets.exceptions.ConnectionClosedError:
            pass
    reason = f"code {ws.close_code} {ws.close_reason or ''}".strip()
    print(f"[ws]     closed before completion ({reason}). Resume with: "
          f"uv run python scripts/ws_client.py --session-id {session_id} --resume",
          file=sys.stderr)
    return 2


def _report(msg: dict, args: argparse.Namespace) -> int:
    if msg.get("cached"):
        print(f"[done]   cached result of session {msg.get('cached_from_session')} "
              f"({msg.get('cache_age_seconds')}s old; --force-refresh for a new scan)")
    else:
        print(f"[done]   session {msg.get('session_id')} complete")
    for key in ("report_url", "report_md_url", "report_json_url", "report_docx_url"):
        if msg.get(key):
            print(f"         {key:<16} {msg[key]}")
    if not args.no_auth and msg.get("report_url"):
        print("         (open reports with ?access_token=<token>; get one with scripts/get_token.py)")
    md = msg.get("report_md") or ""
    if args.save_md and md:
        args.save_md.write_text(md, encoding="utf-8")
        print(f"         markdown saved to {args.save_md}")
    if args.simulate:
        ok = all(k in md for k in ("SQL injection", "Open redirect", "Path traversal"))
        print("SIMULATION PASSED" if ok else "SIMULATION FAILED: expected findings missing in report")
        return 0 if ok else 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    ctx = nullcontext(None)
    if args.simulate:
        from scopeguard.simulated_target import SimulatedTarget
        ctx = SimulatedTarget()
    try:
        with ctx as target:
            url = target.url if target else args.url
            if target:
                print(f"[sim]    built-in vulnerable target at {url}")
            return asyncio.run(_run(args, url))
    except KeyboardInterrupt:
        print("\n[ws]     interrupted; the run can be resumed with --session-id <id> --resume",
              file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
