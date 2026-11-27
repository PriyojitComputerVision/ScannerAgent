"""Command-line WebSocket client: the Postman flow, without Postman.

Start the server in one terminal, then run scans from another (guide: docs/WEBSOCKET.md):

    uv run pentest-agent
    uv run python scripts/ws_client.py                                # interactive: numbered menus ask for everything
    uv run python scripts/ws_client.py -i                             # same, forced (other flags become defaults)
    uv run python scripts/ws_client.py --simulate                     # built-in vulnerable target
    uv run python scripts/ws_client.py --simulate --frames            # + every received frame as pretty JSON
    uv run python scripts/ws_client.py https://your-app.example --profile quick --i-have-authorization
    uv run python scripts/ws_client.py --session-id demo-1 --resume   # resume a checkpointed run
    uv run python scripts/ws_client.py --payload body.json            # send a Postman-style JSON body
    uv run python scripts/ws_client.py --simulate --origin http://localhost:5173   # test CORS_ALLOWED_ORIGINS

What it does, like a Postman session:
0. With no arguments in a terminal (or -i), asks for the target, profile, source code,
   pauses and output as numbered menus, shows the request and asks before starting.
1. Checks GET /healthz.
2. Gets an access token automatically (never asked for): --token, else POST /auth/token
   with AUTH_CLIENT_ID / AUTH_CLIENT_SECRET from .env, else a token signed locally with
   keys/ (like scripts/get_token.py; the key pair is created when missing).
   --no-auth skips this (server with AUTH_ENABLED=false).
3. Connects to ws://<host>:<port>/ws?session_id=<id>, sending the token in the
   first message (default), the Authorization header, or ?access_token=.
4. Prints every frame it SENDS as indented, coloured JSON (tokens and secrets
   masked), then every server message as it arrives: a one-line summary, or with
   --frames the whole frame as pretty JSON (long strings shortened unless --full).
   --raw prints received frames as plain full JSON (for pipes / jq).
5. Answers the scan's pauses (human in the loop) on the same socket:
   - scan_scope  (--ask-scope):        what to test -> scope_response
   - code_source (--ask-for-code):     upload id / git link / skip -> code_response
   - sign_in     (--interactive-auth): MFA code or session, hidden input -> auth_response
   --scope-answer / --code-answer-* answer without a prompt. Without a terminal
   (stdin not a TTY) the default (scope) or "skip" is sent.
6. Adopts "token_refreshed" tokens and prints the report URLs at the end.

Source code never travels over the WebSocket: it is stored first over HTTP
(POST /api/uploads raw .zip body, or POST /api/uploads/files JSON text files)
and only the returned upload_id (or a git_url) is sent. --code-path DIR_OR_ZIP
does that upload for you (a folder is zipped in memory, .git/node_modules/venvs skipped).

Exit codes: 0 complete, 1 server error / rejected, 2 socket closed early,
3 server not reachable or no token. Only scan sites you own or are authorized to test.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import getpass
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import zipfile
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import urlencode

import websockets

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pentest_agent import api_auth, rbac
from pentest_agent.auth_client import AuthenticationFailed, TokenManager
from pentest_agent.config import settings

SCOPES = ("website_and_code", "website", "code")
# Keys whose values are never printed (tokens, target credentials, session handover).
SECRET_KEYS = frozenset({"access_token", "refresh_token", "jwt", "password", "client_secret",
                         "cookie", "bearer", "token"})
# In a sign-in answer "code" is the one-time MFA code; elsewhere "code" is an HTTP status.
_SECRET_IN_AUTH_RESPONSE = frozenset({"code"})
ANSWER_TYPES = {"scan_scope": "scope_response", "code_source": "code_response", "sign_in": "auth_response"}


# --------------------------------------------------------------------------- pretty printing
class Style:
    """ANSI colours, off when stdout is not a terminal, NO_COLOR is set or --no-color."""

    def __init__(self, enabled: bool):
        self.enabled = enabled

    def __call__(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text


def _enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    # Classic Windows consoles need VT processing switched on; newer terminals have it. Cosmetic only.
    with contextlib.suppress(Exception):
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)


def make_style(no_color: bool) -> Style:
    enabled = not no_color and not os.environ.get("NO_COLOR") and sys.stdout.isatty()
    if enabled:
        _enable_windows_ansi()
    return Style(enabled)


def mask_secrets(value, *, frame_type: str | None = None):
    """Copy of ``value`` with secret values replaced by '***' (length kept as a hint)."""
    secret = SECRET_KEYS | (_SECRET_IN_AUTH_RESPONSE if frame_type == "auth_response" else frozenset())
    if isinstance(value, dict):
        return {k: (f"*** ({len(str(v))} chars)" if k in secret and v not in (None, "")
                    else mask_secrets(v, frame_type=frame_type)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_secrets(v, frame_type=frame_type) for v in value]
    return value


def shorten(value, max_str: int | None):
    """Long strings (report markdown, evidence) cut to ``max_str`` characters."""
    if max_str is None:
        return value
    if isinstance(value, dict):
        return {k: shorten(v, max_str) for k, v in value.items()}
    if isinstance(value, list):
        return [shorten(v, max_str) for v in value]
    if isinstance(value, str) and len(value) > max_str:
        return f"{value[:max_str]}... (+{len(value) - max_str} chars)"
    return value


_TOKEN_RE = re.compile(r'("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b')


def colorize_json(text: str, style: Style) -> str:
    if not style.enabled:
        return text

    def paint(m: re.Match) -> str:
        if m.group(1):
            return style("36", m.group(1)) + m.group(2) if m.group(2) else style("32", m.group(1))
        if m.group(3):
            return style("33", m.group(3))
        return style("35", m.group(4))

    return _TOKEN_RE.sub(paint, text)


def _frame_label(payload: dict) -> str:
    kind = payload.get("type")
    if kind == "phase_update":
        return f"phase_update  node={payload.get('node')}"
    if kind == "input_required":
        return f"input_required  request={(payload.get('request') or {}).get('type')}"
    if kind:
        return str(kind)
    if payload.get("resume") is True:
        return "resume request"
    return "scan request"


def format_frame(direction: str, payload: dict, style: Style, *, max_str: int | None = 400) -> str:
    """A framed, indented JSON block: header (direction, time, type, size), body, rule."""
    size = len(json.dumps(payload, default=str).encode("utf-8"))
    shown = shorten(mask_secrets(payload, frame_type=payload.get("type")), max_str)
    body = colorize_json(json.dumps(shown, indent=2, ensure_ascii=False, default=str), style)
    arrow, colour = (">>> SENT", "1;34") if direction == "sent" else ("<<< RECV", "1;35")
    stamp = dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    header = f"{style(colour, arrow)}  {style('2', stamp)}  {style('1', _frame_label(payload))}  {style('2', f'({size} bytes)')}"
    rule = style("2", "-" * 72)
    indented = "\n".join("    " + line for line in body.splitlines())
    return f"{rule}\n{header}\n{indented}\n{rule}"


# --------------------------------------------------------------------------- arguments
def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run a scan over the agent WebSocket (Postman replacement). "
                                            "Guide: docs/WEBSOCKET.md")
    p.add_argument("url", nargs="?", help="target URL (omit with --simulate, --resume, --payload or a code-only scan)")
    p.add_argument("--profile", default="standard", choices=["quick", "standard", "aggressive", "auth_deep"])
    p.add_argument("--simulate", action="store_true", help="scan the built-in vulnerable target")
    p.add_argument("--session-id", help="session id (default: ws-<timestamp>)")
    p.add_argument("--resume", action="store_true", help='send {"resume": true} for --session-id')
    p.add_argument("--force-refresh", action="store_true", help="ignore a cached result for the same request")
    p.add_argument("--allow-domain", action="append", default=[], metavar="DOMAIN",
                   help="extra in-scope domain (repeatable)")
    p.add_argument("--notes", help="free-text notes stored with the scan")
    p.add_argument("--payload", type=Path, metavar="FILE",
                   help="JSON file sent as the request body (overrides the scan options above)")

    hitl = p.add_argument_group("human in the loop (pauses answered on the same socket)")
    hitl.add_argument("--interactive-auth", action="store_true",
                      help="pause for SSO / MFA sign-in and ask here (admin; scan:authenticated)")
    hitl.add_argument("--ask-scope", action="store_true",
                      help="pause before any request and ask what to test (scan:source)")
    hitl.add_argument("--scope-answer", choices=SCOPES, help="answer the scope pause with this, no prompt")
    hitl.add_argument("--ask-for-code", action="store_true",
                      help="pause at the SAST step and ask for source code (scan:source)")
    hitl.add_argument("--code-answer-upload", metavar="UPLOAD_ID", help="answer the code pause with this upload id")
    hitl.add_argument("--code-answer-git", metavar="URL", help="answer the code pause with this .git link")

    code = p.add_argument_group("source code named up front (admin, scan:source)")
    code.add_argument("--scope", choices=SCOPES, help="what the scan tests (default: derived by the server)")
    code.add_argument("--upload-id", help="id from POST /api/uploads or /api/uploads/files")
    code.add_argument("--code-path", type=Path, metavar="ZIP_OR_DIR",
                      help="local .zip or project folder: uploaded over HTTP first, then its upload_id is sent")
    code.add_argument("--git-url", help="public repository .git clone link")
    code.add_argument("--git-ref", help="branch or tag for --git-url")

    conn = p.add_argument_group("connection")
    conn.add_argument("--host", default="127.0.0.1")
    conn.add_argument("--port", type=int, default=settings.ws_port)
    conn.add_argument("--origin", help="send this Origin header (browser-like; must be same-origin "
                                       "or on CORS_ALLOWED_ORIGINS, else close 4403)")
    conn.add_argument("--token", help="access token to use as-is (e.g. from scripts/get_token.py)")
    conn.add_argument("--token-in", default="message", choices=["message", "header", "query"],
                      help="where to send the token (default: first JSON message)")
    conn.add_argument("--no-auth", action="store_true", help="send no token (server has AUTH_ENABLED=false)")

    out = p.add_argument_group("output")
    out.add_argument("--frames", action="store_true",
                     help="print every received frame as pretty JSON (not just a summary line)")
    out.add_argument("--full", action="store_true", help="with --frames: do not shorten long strings")
    out.add_argument("--raw", action="store_true", help="print received frames as plain full JSON")
    out.add_argument("--no-color", action="store_true", help="no ANSI colours (also: NO_COLOR=1)")
    out.add_argument("--save-md", type=Path, metavar="FILE", help="write the markdown report here")
    p.add_argument("--i-have-authorization", action="store_true",
                   help="confirm you own or may test the target (not needed with --simulate/--resume)")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="ask for everything in the terminal as numbered menus (default with no arguments)")
    argv = sys.argv[1:] if argv is None else argv
    args = p.parse_args(argv)
    if args.interactive or (not argv and _interactive()):
        try:
            wizard(args)
        except (EOFError, KeyboardInterrupt):
            print("\n[cancel] nothing was sent")
            raise SystemExit(130) from None
    code_only = args.scope == "code" and (args.upload_id or args.git_url or args.code_path)
    if not (args.url or args.simulate or args.resume or args.payload or code_only):
        p.error("give a target URL, --simulate, --resume, --payload, or --scope code with "
                "--upload-id/--git-url/--code-path")
    if args.resume and not args.session_id:
        p.error("--resume needs the --session-id of the run to resume")
    if sum(bool(x) for x in (args.upload_id, args.git_url, args.code_path)) > 1:
        p.error("pass only one of --upload-id, --git-url, --code-path")
    if args.code_path and not args.code_path.exists():
        p.error(f"--code-path {args.code_path} does not exist")
    if (args.url or code_only) and not (args.i_have_authorization or args.payload):
        p.error("scanning a real target or code needs --i-have-authorization (only scan what you own "
                "or are authorized to test)")
    return args


# --------------------------------------------------------------------------- interactive wizard
UPLOAD_ID_RE = re.compile(r"[a-f0-9]{32}")
PROFILES = [("quick", "quick       passive checks only, fastest"),
            ("standard", "standard    passive + safe active checks (recommended)"),
            ("aggressive", "aggressive  more payloads and pages (admin role)"),
            ("auth_deep", "auth_deep   deeper authenticated checks (admin role)")]


def choose(question: str, options: list[tuple[str, str]], default: int = 1) -> str:
    """Numbered menu; Enter = default. Accepts the number or the option's value."""
    print(f"\n{question}")
    for n, (_, label) in enumerate(options, 1):
        print(f"  {n}) {label}" + ("   [default]" if n == default else ""))
    values = [v for v, _ in options]
    while True:
        raw = input(f"Choice [{default}]: ").strip()
        if not raw:
            return values[default - 1]
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return values[int(raw) - 1]
        if raw in values:
            return raw
        print(f"  please type a number from 1 to {len(options)}")


def ask_text(prompt: str, *, default: str | None = None, check=None) -> str:
    """Free text with an optional default; ``check`` returns an error message or None."""
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"{prompt}{suffix}: ").strip() or (default or "")
        problem = check(value) if check else (None if value else "a value is required")
        if not problem:
            return value
        print(f"  {problem}")


def _check_url(value: str) -> str | None:
    return None if re.fullmatch(r"https?://[^\s/]+(/\S*)?", value) else "must start with http:// or https://"


def _check_upload_id(value: str) -> str | None:
    return None if UPLOAD_ID_RE.fullmatch(value) else "an upload id is 32 lowercase hex characters"


def _check_git(value: str) -> str | None:
    return None if re.fullmatch(r"https://\S+\.git", value) else "must be an https://... .git clone link"


def _check_session(value: str) -> str | None:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value) and ".." not in value:
        return None
    return "letters, digits, '.', '_' or '-' (max 128), starting with a letter or digit"


def _check_code_path(value: str) -> str | None:
    path = Path(value.strip('"')).expanduser()
    if path.is_dir() or (path.is_file() and path.suffix.lower() == ".zip"):
        return None
    return "give an existing folder or .zip file"


def _check_domains(value: str) -> str | None:
    bad = [d for d in value.replace(",", " ").split() if not re.fullmatch(r"[a-z0-9.-]+(:\d{1,5})?", d.lower())]
    return f"not a host name: {', '.join(bad)}" if bad else None


def _check_hostport(value: str) -> str | None:
    return None if re.fullmatch(r"[\w.-]+:\d{1,5}", value) else "format host:port, e.g. 127.0.0.1:8765"


def _confirm_authorization(what: str) -> None:
    answer = choose(f"Do you own {what}, or have permission to test it?",
                    [("yes", "Yes, I own it or I am authorized to test it"), ("no", "No")], default=2)
    if answer != "yes":
        print("\n[stop] Only scan what you own or are authorized to test. Nothing was sent.")
        raise SystemExit(1)


def _ask_code(args: argparse.Namespace, *, required: bool) -> None:
    options = [("path", "A local .zip file or project folder (uploaded for you)"),
               ("git", "A public git repository (.git link)"),
               ("upload", "I already have an upload id (from POST /api/uploads)")]
    if not required:
        options = [("none", "No source code (website only)"),
                   ("ask", "Ask me during the scan (pause at the SAST step)"), *options]
    kind = choose("Source code for the code SAST step (admin role, Python projects):", options)
    if kind == "path":
        args.code_path = Path(ask_text("Path to the .zip file or folder", check=_check_code_path)).expanduser()
    elif kind == "upload":
        args.upload_id = ask_text("Upload id", check=_check_upload_id)
    elif kind == "git":
        args.git_url = ask_text("Git clone link (https://.../repo.git)", check=_check_git)
        args.git_ref = input("Branch or tag [default branch]: ").strip() or None
    elif kind == "ask":
        args.ask_for_code = True


def wizard(args: argparse.Namespace) -> None:
    """Fill ``args`` from numbered terminal menus. The API token is never asked for."""
    print("ScopeGuard WebSocket client: answer with a number, Enter keeps the default.")
    print("The API token (JWT) is handled automatically.")
    if choose("Server:", [("keep", f"{args.host}:{args.port}"), ("other", "Another host:port")]) == "other":
        host, port = ask_text("host:port", check=_check_hostport).rsplit(":", 1)
        args.host, args.port = host, int(port)

    mode = choose("What do you want to do?", [
        ("simulate", "Scan the built-in vulnerable demo target (local, safe; self-test)"),
        ("website", "Scan my own website"),
        ("code", "Analyse source code only (nothing is sent to a website)"),
        ("resume", "Resume an earlier session")])
    args.simulate, args.resume = mode == "simulate", mode == "resume"
    if mode == "resume":
        args.session_id = ask_text("Session id to resume", default=args.session_id, check=_check_session)
    else:
        if mode == "website":
            args.url = ask_text("Website URL", default=args.url, check=_check_url)
            _confirm_authorization(args.url)
            args.i_have_authorization = True
            _ask_code(args, required=False)
            if args.upload_id or args.git_url or args.ask_for_code:
                args.scope = choose("What should the scan test?", [
                    ("website_and_code", "The website, then the code"),
                    ("website", "Only the website (ignore the code)"),
                    ("code", "Only the code (no request to the website)")])
            domains = ask_text("Extra in-scope domains (comma-separated, Enter for none)", default="",
                               check=_check_domains)
            args.allow_domain = [d.lower() for d in domains.replace(",", " ").split()]
            if choose("Does the site need SSO or an MFA code to sign in during the scan?",
                      [("no", "No"), ("yes", "Yes: pause and ask me here (admin role)")]) == "yes":
                args.interactive_auth = True
        elif mode == "code":
            args.scope = "code"
            _ask_code(args, required=True)
            _confirm_authorization("this source code")
            args.i_have_authorization = True
        if mode != "code":
            args.profile = choose("Scan profile:", PROFILES, default=2)
        if choose("Use a cached result of the same request if there is one?",
                  [("yes", "Yes (faster)"), ("no", "No, always scan again")]) == "no":
            args.force_refresh = True
        args.notes = input("Notes stored with the scan [none]: ").strip()[:2000] or None
        args.session_id = ask_text("Session id", default=args.session_id or f"ws-{int(time.time())}",
                                   check=_check_session)

    output = choose("How should messages be shown?", [
        ("frames", "Every frame sent and received as pretty JSON"),
        ("summary", "Frames sent as pretty JSON, one line per received message"),
        ("raw", "Received frames as plain full JSON (for pipes)")])
    args.frames, args.raw = output == "frames", output == "raw"

    preview = build_payload(args, "<built-in demo target>" if args.simulate else args.url)
    print()
    print(format_frame("sent", preview, make_style(args.no_color), max_str=None).replace(">>> SENT", ">>> WILL SEND"))
    if choose("Start?", [("yes", "Yes, connect and send"), ("no", "No, cancel")]) != "yes":
        print("[cancel] nothing was sent")
        raise SystemExit(0)


# --------------------------------------------------------------------------- code upload (HTTP)
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
                       ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", "dist", "build"})


def zip_code(path: Path) -> tuple[bytes, str]:
    """(zip bytes, file name) for a .zip file or a folder (zipped in memory, no symlinks)."""
    if path.is_file():
        return path.read_bytes(), path.name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in sorted(path.rglob("*")):
            rel = item.relative_to(path)
            if any(part in SKIP_DIRS for part in rel.parts) or item.is_symlink() or not item.is_file():
                continue
            zf.write(item, rel.as_posix())
    name = re.sub(r"[^A-Za-z0-9._-]", "_", path.resolve().name) or "code"
    return buf.getvalue(), f"{name}.zip"


def upload_code(base: str, token: str | None, path: Path) -> str:
    """POST /api/uploads with the raw zip body (not base64); returns the upload_id."""
    data, name = zip_code(path)
    print(f"[upload] {path} -> POST {base}/api/uploads?filename={name} ({len(data):,} bytes, application/zip)")
    headers = {"Content-Type": "application/zip", **({"Authorization": f"Bearer {token}"} if token else {})}
    req = urllib.request.Request(f"{base}/api/uploads?{urlencode({'filename': name})}", data=data,
                                 headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            body = json.load(r)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise SystemExit(_fail(1, f"upload refused ({exc.code}): {detail}")) from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SystemExit(_fail(3, f"upload failed: {exc}")) from None
    upload_id = str(body.get("upload_id") or "")
    if not UPLOAD_ID_RE.fullmatch(upload_id):
        raise SystemExit(_fail(1, f"unexpected upload reply: {json.dumps(body)[:300]}"))
    print(f"[upload] stored as upload_id {upload_id}")
    return upload_id


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
    if not api_auth.keys_present():
        priv, pub = api_auth.generate_keypair()
        print(f"[auth]   no API keys yet: created {priv} and {pub} (the server reads the same keys/ folder)")
    if api_auth.keys_present():
        roles = rbac.parse_roles(settings.auth_client_roles)
        pair = api_auth.issue_tokens(settings.auth_client_id, roles)
        print(f"[auth] token signed locally with keys/ for '{settings.auth_client_id}', roles: {', '.join(roles)}")
        return pair.access_token, None
    raise SystemExit(_fail(3, "no token: pass --token, set AUTH_CLIENT_SECRET in .env, create keys "
                              "with scripts/get_token.py, or use --no-auth"))


def build_payload(args: argparse.Namespace, target_url: str | None) -> dict:
    if args.payload:
        body = json.loads(args.payload.read_text(encoding="utf-8"))
        if not isinstance(body, dict):
            raise SystemExit(_fail(1, f"{args.payload} must hold a JSON object"))
        return body
    if args.resume:
        return {"resume": True}
    body: dict = {"profile": args.profile, "authorization_confirmed": True,
                  "additional_allowed_domains": args.allow_domain}
    if target_url:
        body = {"url": target_url, **body}
    upload_id = args.upload_id
    if not upload_id and getattr(args, "code_path", None):
        upload_id = f"<id returned by uploading {Path(args.code_path).name}>"
    optional = {"notes": args.notes, "scan_scope": args.scope, "upload_id": upload_id,
                "git_url": args.git_url, "git_ref": args.git_ref}
    body.update({k: v for k, v in optional.items() if v})
    for flag, key in ((args.force_refresh, "force_refresh"), (args.interactive_auth, "interactive_auth"),
                      (args.ask_scope, "ask_scan_scope"), (args.ask_for_code, "ask_for_code")):
        if flag:
            body[key] = True
    return body


# --------------------------------------------------------------------------- pauses
def _interactive() -> bool:
    return sys.stdin.isatty()


def answer_scope(msg: dict, args: argparse.Namespace) -> dict:
    req = msg.get("request") or {}
    offered = [str(o.get("value")) for o in req.get("options") or [] if isinstance(o, dict)]
    default = str(req.get("default") or "website")
    print(f"\n[scope]  {msg.get('message', '')}")
    for opt in req.get("options") or []:
        mark = " (default)" if opt.get("value") == default else ""
        print(f"         - {opt.get('value')}{mark}: {opt.get('description') or opt.get('label', '')}")
    if args.scope_answer:
        choice = args.scope_answer
    elif _interactive():
        choice = input(f"         scope [{default}]: ").strip() or default
    else:
        print("         (stdin is not a terminal: sending the default)")
        choice = default
    if offered and choice not in offered:
        print(f"         '{choice}' is not offered; sending the default '{default}'")
        choice = default
    return {"scope": choice}


def answer_code(msg: dict, args: argparse.Namespace) -> dict:
    req = msg.get("request") or {}
    print(f"\n[code]   {msg.get('message', '')}")
    print(f"         accepts: {', '.join(req.get('accepts') or [])}; max {req.get('max_upload_mb')} MB")
    if req.get("git_enabled"):
        print(f"         git hosts: {', '.join(req.get('git_hosts') or [])}")
    print("         (store code first: POST /api/uploads raw .zip or /api/uploads/files JSON -> upload_id)")
    if args.code_answer_upload:
        return {"action": "upload", "upload_id": args.code_answer_upload}
    if args.code_answer_git:
        return {"action": "git", "git_url": args.code_answer_git}
    if not _interactive():
        print("         (stdin is not a terminal: skipping)")
        return {"action": "skip"}
    value = input("         local .zip/folder path, upload id (32 hex), .git link, or empty to skip: ").strip()
    if not value:
        return {"action": "skip"}
    uploader = getattr(args, "uploader", None)
    if uploader and not _check_code_path(value):
        try:
            return {"action": "upload", "upload_id": uploader(Path(value.strip('"')).expanduser())}
        except SystemExit:
            return {"action": "skip"}
    if value.startswith(("http://", "https://")):
        ref = input("         branch/tag (empty = default branch): ").strip()
        return {"action": "git", "git_url": value, **({"git_ref": ref} if ref else {})}
    return {"action": "upload", "upload_id": value}


def answer_sign_in(msg: dict, args: argparse.Namespace) -> dict:
    """Terminal answer to a sign-in pause. Secrets are read with getpass (not echoed)."""
    req = msg.get("request") or {}
    print(f"\n[sign-in] {msg.get('message', '')}")
    for key in ("evidence", "idp_host", "login_url", "target_url"):
        if req.get(key):
            print(f"          {key}: {req[key]}")
    print(f"          answer within {msg.get('timeout_seconds')}s; leave empty to skip")
    if not _interactive():
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


_ANSWERERS = {"scan_scope": answer_scope, "code_source": answer_code, "sign_in": answer_sign_in}


def answer_pause(msg: dict, args: argparse.Namespace) -> dict:
    """The reply frame for an ``input_required`` message, by request type."""
    kind = (msg.get("request") or {}).get("type") or "sign_in"
    answer = _ANSWERERS.get(kind, answer_sign_in)(msg, args)
    return {"type": ANSWER_TYPES.get(kind, "auth_response"), **answer}


# --------------------------------------------------------------------------- messages
def summary_line(msg: dict) -> str | None:
    kind = msg.get("type")
    if kind == "status":
        return f"[status] {msg.get('message', '')}"
    if kind == "queued":
        return f"[queue]  #{msg.get('position')} of {msg.get('queue_length')}: {msg.get('message', '')}"
    if kind == "phase_update":
        data = msg.get("data") or {}
        extra = [f"+{len(data[key])} {key}" for key in ("findings", "red_flags", "crawled_pages")
                 if isinstance(data.get(key), list) and data[key]]
        return f"[phase]  node={msg.get('node', ''):<15} phase={data.get('phase', '')} {' '.join(extra)}"
    if kind == "error":
        return f"[error]  {msg.get('code', '')} {msg.get('message', msg)}"
    if kind == "complete":
        return None
    return f"[{kind}] {json.dumps(mask_secrets(msg), default=str)[:300]}"


class Printer:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.style = make_style(args.no_color)
        self.max_str = None if args.full else 400

    def sent(self, payload: dict) -> None:
        print(format_frame("sent", payload, self.style, max_str=None))

    def received(self, msg: dict) -> None:
        if self.args.raw:
            print(json.dumps(mask_secrets(msg, frame_type=msg.get("type")), indent=2, default=str))
        elif self.args.frames:
            print(format_frame("received", msg, self.style, max_str=self.max_str))
        else:
            line = summary_line(msg)
            if line:
                print(line)


async def _run(args: argparse.Namespace, target_url: str | None) -> int:
    base = f"http://{args.host}:{args.port}"
    _check_health(base)
    session_id = args.session_id or f"ws-{int(time.time())}"
    if args.payload:
        # A token inside the --payload body (Postman style) is used as-is; no sign-in.
        body_token = build_payload(args, target_url).get("access_token")
        if body_token and not args.token:
            args.token = body_token
            print("[auth]   using the access_token from the payload file")
    token, tm = _token_source(args, base)
    args.uploader = lambda path: upload_code(base, tm.get_token() if tm else token, path)
    if args.code_path and not args.upload_id:
        args.upload_id = args.uploader(args.code_path)
    payload = build_payload(args, target_url)
    payload.pop("access_token", None)

    query = {"session_id": session_id}
    headers = {}
    if token and args.token_in == "query":
        query["access_token"] = token
    elif token and args.token_in == "header":
        headers["Authorization"] = f"Bearer {token}"
    elif token:
        payload = {"access_token": token, **payload}
    if args.origin:
        headers["Origin"] = args.origin
    uri = f"ws://{args.host}:{args.port}/ws?{urlencode(query)}"
    out = Printer(args)
    print(f"[ws]     connect ws://{args.host}:{args.port}/ws?session_id={session_id} (token in {args.token_in}"
          + (f", Origin {args.origin}" if args.origin else "") + ")")

    try:
        ws = await websockets.connect(uri, max_size=None, additional_headers=headers or None)
    except (OSError, websockets.exceptions.InvalidHandshake) as exc:
        return _fail(3, f"WebSocket connect failed: {exc}")

    async def send(frame: dict) -> None:
        out.sent(frame)
        await ws.send(json.dumps(frame))

    last_pause: dict | None = None
    async with ws:
        await send(payload)
        try:
            async for raw in ws:
                msg = json.loads(raw)
                full_frames = args.frames or args.raw
                if full_frames:  # every frame in full; else only the summary line further down
                    out.received(msg)
                kind = msg.get("type")
                if kind == "token_refreshed":
                    if tm:
                        tm.observe_ws_message(msg)
                    print(f"[auth]   server renewed the token (expires {msg.get('expires_at')})")
                    continue
                if kind == "input_required":
                    last_pause = msg
                    await send(await asyncio.to_thread(answer_pause, msg, args))
                    continue
                if kind == "input_invalid":
                    detail = "; ".join(d.get("msg", "") for d in msg.get("detail") or [])
                    print(f"[pause]  answer rejected: {msg.get('message')} {detail}".rstrip())
                    retry = {**(last_pause or {"request": {"type": "sign_in"}}), "message": "Try again."}
                    await send(await asyncio.to_thread(answer_pause, retry, args))
                    continue
                if not full_frames:
                    out.received(msg)
                if kind == "error":
                    return 1
                if kind == "complete":
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
