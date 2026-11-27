"""One command for the ScopeGuard MCP chatbot: scanner + chatbot backend + browser UI.

Standard library only. It starts, all on 127.0.0.1:

1. the scanner (pentest-agent from this repo) on a free port, with the allowlist you
   manage in the UI (MCP_ALLOWED_TARGETS, set per process; no .env is edited);
2. the chatbot backend (chatbots/mcp_chatbot, `chatbot.py --serve`, its own venv),
   which uses that scanner's MCP server as its tools;
3. this page server, which forwards the page's API calls to the backend with a per-run
   secret the browser never sees.

Adding or removing an allowed host in the UI restarts only the scanner (same port), so
the chatbot and the conversation keep running. Every scan still needs your approval.

    uv run --project chatbots/mcp_chatbot python chatbots/ui/serve_ui.py
    uv run --project chatbots/mcp_chatbot python chatbots/ui/serve_ui.py --allow site-a.example --allow site-b.example
    uv run --project chatbots/mcp_chatbot python chatbots/ui/serve_ui.py --url http://127.0.0.1:8765  # own scanner

Security: loopback only, Host header checked (no DNS rebinding), strict CSP (no inline
code, no third-party loads), a single-use launch link (10 min) swapped for an HttpOnly
SameSite=Strict cookie, POSTs must come from this origin, host names strictly validated.
The page never sees a token or the backend secret.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

HERE = Path(__file__).resolve().parent
CHATBOTS = HERE.parent
REPO = CHATBOTS.parent
BACKEND_DIR = CHATBOTS / "mcp_chatbot"
STATIC = HERE / "static"
LOGS = REPO / "data" / "logs"
# The console's own icon, used directly (replace that file to change both).
FAVICON = REPO / "src" / "pentest_agent" / "webui" / "favicon" / "favicon.png"
FILES = {  # whitelist: URL path -> (file, content type)
    "/": (STATIC / "index.html", "text/html; charset=utf-8"),
    "/app.js": (STATIC / "app.js", "text/javascript; charset=utf-8"),
    "/app.css": (STATIC / "app.css", "text/css; charset=utf-8"),
    "/favicon.png": (FAVICON, "image/png"),
    "/favicon.ico": (FAVICON, "image/png"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
COOKIE = "sg_chatbot"
API_GET = ("info", "events", "policy")
API_POST = ("send", "decide", "detach")
# Report links in the chat: /reports/<session id>/[report.<ext>], served through the backend.
REPORT_PATH_RE = re.compile(r"/reports/([A-Za-z0-9][A-Za-z0-9._-]{0,127})/(report\.(?:html|md|json|docx))?")
REPORT_TYPES = {  # file -> (content type, shown inline)
    "report.html": ("text/html; charset=utf-8", True),
    "report.md": ("text/markdown; charset=utf-8", False),
    "report.json": ("application/json", False),
    "report.docx": ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", False),
}
# Reports hold text from the scanned site: no scripts, frames or remote loads (as on the scanner).
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ZIP_TYPES = ("application/zip", "application/x-zip-compressed")
MAX_ALLOWED_HOSTS = 20
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
HOST_RE = re.compile(rf"^(?=.{{1,253}}(?::\d+)?$){_LABEL}(?:\.{_LABEL})*(?::(\d{{1,5}}))?$")


def normalize_host(value: str) -> str:
    """'https://Site.example/path' or 'site.example:3000' -> 'site.example[:port]'.
    Raises ValueError for anything that is not a plain host name (no user info, no
    wildcards, no paths outside a URL)."""
    raw = (value or "").strip().lower()
    if not raw or len(raw) > 300:
        raise ValueError("enter a host name or URL")
    netloc = urlsplit(raw if "://" in raw else f"//{raw}").netloc
    if "@" in netloc or not HOST_RE.match(netloc):
        raise ValueError(f"not a valid host name: {value!r}")
    port = HOST_RE.match(netloc).group(1)
    if port and not 0 < int(port) < 65536:
        raise ValueError(f"invalid port in {value!r}")
    return netloc


def read_env_file(path: Path) -> dict[str, str]:
    """Minimal KEY=VALUE reader (this launcher is stdlib only)."""
    out: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                out[key.strip()] = value.split(" #", 1)[0].strip().strip('"').strip("'")
    return out


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def healthy(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/healthz", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


def child_env(extra: dict[str, str]) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in ("VIRTUAL_ENV", "PYTHONPATH")}
    env.update({"PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1", **extra})
    return env


# Children are `uv run ...` wrappers around Python: stop the whole tree, or the real
# scanner/backend processes would keep running (and keep their ports) after we exit.
POPEN_GROUP = ({"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt"
               else {"start_new_session": True})


def stop(proc: subprocess.Popen | None) -> None:
    if not proc or proc.poll() is not None:
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


class ExclusiveServer(ThreadingHTTPServer):
    """Fail if the port is taken. (Windows SO_REUSEADDR would let a second server share
    the port silently, so requests could reach a stale instance.)"""

    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


# =============================================================================
# The scanner (pentest-agent), restarted with a new allowlist when you change it
# =============================================================================
class Scanner:
    def __init__(self, port: int, hosts: list[str], scanner_llm: bool):
        self.port, self.hosts, self.scanner_llm = port, list(hosts), scanner_llm
        self.base = f"http://127.0.0.1:{port}"
        self.proc: subprocess.Popen | None = None
        self.lock = threading.Lock()

    def start(self) -> None:
        env = {"MCP_ALLOWED_TARGETS": ",".join(self.hosts), "A2A_ALLOWED_TARGETS": ",".join(self.hosts)}
        if not self.scanner_llm:
            env["GROQ_API_KEY"] = ""  # env beats .env: the scan's own LLM steps use their fallbacks
        LOGS.mkdir(parents=True, exist_ok=True)
        log = (LOGS / "chatbot-scanner.log").open("a", encoding="utf-8")
        cmd = ["uv", "run", "--project", str(REPO), "python", "-m", "pentest_agent.main",
               "--no-browser", "--no-target", "--host", "127.0.0.1", "--port", str(self.port)]
        self.proc = subprocess.Popen(cmd, cwd=REPO, env=child_env(env), stdout=log, stderr=subprocess.STDOUT,
                                     **POPEN_GROUP)
        deadline = time.monotonic() + 180
        while not healthy(self.base):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"the scanner did not start; see {LOGS / 'chatbot-scanner.log'}")
            time.sleep(0.5)

    def set_hosts(self, hosts: list[str]) -> None:
        with self.lock:
            self.hosts = list(hosts)
            stop(self.proc)
            for _ in range(60):  # wait until the port is free again
                with socket.socket() as sock:
                    if sock.connect_ex(("127.0.0.1", self.port)) != 0:
                        break
                time.sleep(0.25)
            self.start()


# =============================================================================
# Page server
# =============================================================================
class State:
    def __init__(self, port: int, backend_port: int, scanner: Scanner | None, external_url: str | None):
        self.port, self.backend_port = port, backend_port
        self.scanner, self.external_url = scanner, external_url
        self.api_key = secrets.token_urlsafe(32)
        self.sessions: set[str] = set()
        self.launch_codes: dict[str, float] = {}  # sha256(code) -> expiry
        self.lock = threading.Lock()

    def arm(self) -> str:
        code = secrets.token_urlsafe(24)
        with self.lock:
            self.launch_codes[hashlib.sha256(code.encode()).hexdigest()] = time.time() + 600
        return code

    def redeem(self, code: str) -> str | None:
        with self.lock:
            exp = self.launch_codes.pop(hashlib.sha256(code.encode()).hexdigest(), 0)  # single use
            if exp < time.time():
                return None
            session = secrets.token_urlsafe(32)
            self.sessions.add(session)
            return session

    def allowlist(self) -> dict:
        if self.scanner is None:
            status, data = backend_call(self, "GET", "/api/policy")
            hosts = data.get("allowed_targets", []) if status == 200 else []
            setting = data.get("allowed_targets_setting") or "MCP_ALLOWED_TARGETS"
            return {"editable": False, "hosts": hosts,
                    "note": f"Set by the running pentest-agent ({setting} in its .env; restart it to change)."
                            if status == 200 else "The chatbot is still starting..."}
        return {"editable": True, "hosts": list(self.scanner.hosts)}


def start_backend(state: State, scanner_url: str, roles: str | None,
                  disable_tools: list[str] | None = None) -> subprocess.Popen:
    cmd = ["uv", "run", "--project", str(BACKEND_DIR), "python", "chatbot.py", "--serve",
           "--port", str(state.backend_port), "--url", scanner_url, "--allow-none"]
    if roles:
        cmd += ["--roles", roles]
    for tool in disable_tools or []:
        cmd += ["--disable-tool", tool]
    LOGS.mkdir(parents=True, exist_ok=True)
    log = (LOGS / "chatbot-mcp-api.log").open("w", encoding="utf-8")
    return subprocess.Popen(cmd, cwd=BACKEND_DIR, env=child_env({"CHATBOT_API_KEY": state.api_key}),
                            stdout=log, stderr=subprocess.STDOUT, **POPEN_GROUP)


def backend_call(state: State, method: str, path: str, body: bytes | None = None,
                 content_type: str = "application/json", timeout: float = 30) -> tuple[int, dict]:
    req = urllib.request.Request(f"http://127.0.0.1:{state.backend_port}{path}", data=body, method=method,
                                 headers={"X-Chatbot-Key": state.api_key, "Content-Type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as exc:
        with contextlib.suppress(ValueError):
            return exc.code, json.loads(exc.read() or b"{}")
        return exc.code, {"error": f"backend error {exc.code}"}
    except OSError:
        return 502, {"error": "the chatbot is starting (or stopped); see data/logs/chatbot-mcp-api.log"}


def backend_raw(state: State, path: str, timeout: float = 60) -> tuple[int, bytes, str]:
    """GET a non-JSON body (a report file) from the backend: (status, body, content type)."""
    req = urllib.request.Request(f"http://127.0.0.1:{state.backend_port}{path}",
                                 headers={"X-Chatbot-Key": state.api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), r.headers.get("Content-Type", "application/octet-stream")
    except urllib.error.HTTPError as exc:
        return exc.code, b"", "text/plain"
    except OSError:
        return 502, b"", "text/plain"


def make_handler(state: State):
    allowed_hosts = {f"127.0.0.1:{state.port}", f"localhost:{state.port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _headers(self, code: int, ctype: str, length: int, extra: dict | None = None) -> None:
            self.send_response(code)
            for k, v in {"Content-Type": ctype, "Content-Length": str(length), "Content-Security-Policy": CSP,
                         "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                         "X-Frame-Options": "DENY", "Cache-Control": "no-store", **(extra or {})}.items():
                self.send_header(k, v)
            self.end_headers()

        def _json(self, code: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False).encode()
            self._headers(code, "application/json; charset=utf-8", len(data))
            self.wfile.write(data)

        def _host_ok(self) -> bool:
            if self.headers.get("Host", "") not in allowed_hosts:
                self._json(421, {"error": "wrong host"})
                return False
            return True

        def _session_ok(self) -> bool:
            jar = SimpleCookie(self.headers.get("Cookie", ""))
            if COOKIE not in jar or jar[COOKIE].value not in state.sessions:
                self._json(401, {"error": "open the link printed by serve_ui.py"})
                return False
            return True

        def do_GET(self):
            if not self._host_ok():
                return
            u = urlsplit(self.path)
            if u.path == "/start":
                session = state.redeem((parse_qs(u.query).get("code") or [""])[0])
                if not session:
                    self._json(403, {"error": "this launch link was used or expired; restart serve_ui.py"})
                    return
                self._headers(303, "text/plain", 0, {
                    "Location": "/", "Set-Cookie": f"{COOKIE}={session}; HttpOnly; SameSite=Strict; Path=/"})
                return
            if u.path in FILES:
                if u.path == "/" and not self._session_ok():
                    return
                path, ctype = FILES[u.path]
                data = path.read_bytes()
                self._headers(200, ctype, len(data))
                self.wfile.write(data)
                return
            if not self._session_ok():
                return
            if u.path == "/api/allowlist":
                self._json(200, state.allowlist())
                return
            m = REPORT_PATH_RE.fullmatch(u.path)
            if m and ".." not in m.group(1):
                self._report(m.group(1), m.group(2) or "report.html")
                return
            name = u.path.removeprefix("/api/")
            if u.path.startswith("/api/") and name in API_GET:
                self._json(*backend_call(state, "GET", f"/api/{name}" + (f"?{u.query}" if u.query else "")))
                return
            self._json(404, {"error": "not found"})

        def _report(self, session_id: str, filename: str) -> None:
            """A scan report, fetched by the backend with the chatbot's token (the scanner checks
            that the report is this chatbot's). HTML opens inline under the report CSP (no scripts),
            md/json/docx download as <session_id>.<ext>."""
            status, body, ctype = backend_raw(state, f"/api/report?{urlencode({'id': session_id, 'file': filename})}")
            if status != 200:
                self._json(404 if status in (401, 403, 404) else 502,
                           {"error": "report not found" if status in (401, 403, 404) else "scanner unavailable"})
                return
            ctype, inline = REPORT_TYPES[filename]
            extra = {"Content-Security-Policy": REPORT_CSP}
            if not inline:
                ext = filename.rsplit(".", 1)[1]
                extra["Content-Disposition"] = f'attachment; filename="{session_id}.{ext}"'
            self._headers(200, ctype, len(body), extra)
            self.wfile.write(body)

        def do_POST(self):
            if not self._host_ok() or not self._session_ok():
                return
            if self.headers.get("Origin", "") not in allowed_origins:
                self._json(403, {"error": "cross-origin request refused"})
                return
            if self.path.startswith("/api/upload?"):
                self._upload()
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._json(415, {"error": "JSON only"})
                return
            length = min(int(self.headers.get("Content-Length") or 0), 64_000)
            raw = self.rfile.read(length)
            if self.path == "/api/allowlist":
                self._allowlist(raw)
                return
            name = self.path.removeprefix("/api/")
            if not (self.path.startswith("/api/") and name in API_POST):
                self._json(404, {"error": "not found"})
                return
            self._json(*backend_call(state, "POST", f"/api/{name}", raw))

        def _upload(self) -> None:
            """Raw .zip (MIME + size + signature checked here, again in the backend and on the
            scanner), forwarded with ?thread_id=&filename=."""
            from urllib.parse import parse_qs, urlencode, urlsplit

            ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if ctype not in ZIP_TYPES:
                self._json(415, {"error": "only .zip archives (application/zip) are accepted"})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_UPLOAD_BYTES:
                self._json(413, {"error": f"the archive must be at most {MAX_UPLOAD_BYTES // 1048576} MB"})
                return
            q = parse_qs(urlsplit(self.path).query)
            query = urlencode({"thread_id": (q.get("thread_id") or [""])[0][:64],
                               "filename": (q.get("filename") or [""])[0][:120]})
            self._json(*backend_call(state, "POST", f"/api/upload?{query}", self.rfile.read(length),
                                     content_type=ctype, timeout=150))

        def _allowlist(self, raw: bytes) -> None:
            """{"add": "host or URL"} or {"remove": "host"}: restarts the scanner with the new list."""
            if state.scanner is None:
                self._json(409, state.allowlist())
                return
            try:
                body = json.loads(raw or b"{}")
                hosts = list(state.scanner.hosts)
                if body.get("add"):
                    host = normalize_host(str(body["add"]))
                    if host not in hosts:
                        if len(hosts) >= MAX_ALLOWED_HOSTS:
                            raise ValueError(f"at most {MAX_ALLOWED_HOSTS} hosts")
                        hosts.append(host)
                elif body.get("remove"):
                    hosts = [h for h in hosts if h != str(body["remove"]).lower()]
                else:
                    raise ValueError("send {\"add\": host} or {\"remove\": host}")
            except (ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})
                return
            status, info = backend_call(state, "GET", "/api/info")
            if status == 200 and info.get("busy"):
                self._json(409, {"error": "a scan or reply is in progress; change the allowlist when it ends"})
                return
            if hosts == state.scanner.hosts:
                self._json(200, state.allowlist())
                return
            try:
                state.scanner.set_hosts(hosts)
            except RuntimeError as exc:
                self._json(500, {"error": str(exc)})
                return
            print(f"[ui] scanner restarted; allowed targets: {', '.join(hosts) or '(demo app only)'}",
                  file=sys.stderr, flush=True)
            self._json(200, state.allowlist())

    return Handler


def main(argv: list[str] | None = None) -> int:
    env = {**read_env_file(REPO / ".env"), **read_env_file(BACKEND_DIR / ".env")}
    ap = argparse.ArgumentParser(description="ScopeGuard MCP chatbot: scanner + chatbot + UI in one command")
    ap.add_argument("--host", default=os.environ.get("CHATBOT_UI_HOST") or "127.0.0.1",
                    help="bind address (default 127.0.0.1; the Docker image uses 0.0.0.0 inside the container)")
    ap.add_argument("--port", type=int, default=8800, help="UI port (default 8800)")
    ap.add_argument("--backend-port", type=int, default=8801, help="chatbot API port (default 8801)")
    ap.add_argument("--scanner-port", type=int, default=0, help="scanner port (default: a free port)")
    ap.add_argument("--allow", action="append", default=None, metavar="HOST_OR_URL",
                    help="hosts allowed from the start (repeatable; default CHATBOT_ALLOW in .env). "
                         "More can be added in the UI.")
    ap.add_argument("--url", default=os.environ.get("SCOPEGUARD_URL") or None,
                    help="use a scanner you run yourself instead of starting one (its .env decides the allowlist)")
    ap.add_argument("--no-scanner-llm", action="store_true",
                    help="the scanner skips its own LLM steps (faster); the chat agent still uses the LLM")
    ap.add_argument("--roles", default=None, help="token roles (default: CHATBOT_ROLES in .env, else scanner)")
    ap.add_argument("--disable-tool", action="append", default=None, metavar="TOOL",
                    help="switch a chat tool off (repeatable; default: CHATBOT_DISABLED_TOOLS in .env)")
    ap.add_argument("--no-browser", action="store_true", help="print the link instead of opening a browser")
    a = ap.parse_args(argv)

    scanner = None
    procs: list[subprocess.Popen] = []
    try:
        if a.url:
            scanner_url = a.url.rstrip("/")
            if not healthy(scanner_url):
                print(f"[ui] no ScopeGuard server at {scanner_url}", file=sys.stderr)
                return 2
            print(f"[ui] using the scanner at {scanner_url}", file=sys.stderr)
        else:
            initial = a.allow if a.allow is not None else (env.get("CHATBOT_ALLOW") or "").split(",")
            hosts = []
            for h in initial:
                if h.strip():
                    try:
                        hosts.append(normalize_host(h))
                    except ValueError as exc:
                        print(f"[ui] {exc}", file=sys.stderr)
                        return 2
            scanner_llm = not (a.no_scanner_llm or env.get("CHATBOT_NO_SCANNER_LLM", "").lower() == "true")
            scanner = Scanner(a.scanner_port or free_port(), hosts, scanner_llm)
            print(f"[ui] starting the scanner on {scanner.base} (allowed: {', '.join(hosts) or 'demo app only'}"
                  f"{'' if scanner_llm else '; without its own LLM steps'}) - log: {LOGS / 'chatbot-scanner.log'}",
                  file=sys.stderr, flush=True)
            scanner.start()
            scanner_url = scanner.base
        for port in (a.port, a.backend_port):
            with socket.socket() as sock:
                if sock.connect_ex(("127.0.0.1", port)) == 0:
                    print(f"[ui] port {port} is already in use (another chatbot running?). Stop it, or pass "
                          f"--port / --backend-port.", file=sys.stderr)
                    return 2
        state = State(a.port, a.backend_port, scanner, a.url)
        print(f"[ui] starting the chatbot backend on 127.0.0.1:{a.backend_port} - log: "
              f"{LOGS / 'chatbot-mcp-api.log'}", file=sys.stderr, flush=True)
        procs.append(start_backend(state, scanner_url, a.roles, a.disable_tool))
        try:
            server = ExclusiveServer((a.host, a.port), make_handler(state))
        except OSError:
            print(f"[ui] port {a.port} is already in use (another chatbot UI running?). Stop it or pass "
                  f"--port.", file=sys.stderr)
            return 2
        link = f"http://127.0.0.1:{a.port}/start?code={state.arm()}"
        print(f"[ui] ScopeGuard MCP chatbot: {link}\n[ui] (single-use link, valid 10 minutes; Ctrl+C stops "
              f"everything)", file=sys.stderr, flush=True)
        print(f"LAUNCH LINK: {link}", flush=True)  # stdout too, so `docker compose logs` shows it
        if not a.no_browser:
            webbrowser.open(link)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            stop(p)
        if scanner:
            stop(scanner.proc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
