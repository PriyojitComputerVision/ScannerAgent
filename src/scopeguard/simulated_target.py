"""Deliberately vulnerable LOCAL target for self-testing the scanner.

Binds to 127.0.0.1 only. Every "vulnerability" is simulated with static,
fake data: nothing reads real files, runs a database, or executes input.
"""
from __future__ import annotations

import html
import threading
import urllib.parse as up
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_JS = """// simulated client code (fake data)
var API_KEY = "sk_live_FAKEFAKEFAKEFAKE1234";
var awsKey = "AKIAIOSFODNN7EXAMPLE";
function render(x){ document.getElementById('out').innerHTML = x; }
function run(code){ return eval(code); }
localStorage.setItem('auth_token', 'abc');
var token = Math.random();
fetch("http://legacy.example.invalid/api");
"""

# Public, fake demo account (the demo app is loopback-only and holds no real data).
DEMO_USERNAME = "demo"
DEMO_PASSWORD = "demo-password"
DEMO_SESSION = "demo-session-0001"

PAGE = """<!doctype html><html><head><title>SimShop</title>
<script src="/app.js"></script><script>console.log("inline");</script></head><body>
<h1>SimShop (simulated target)</h1>
<a href="/search?q=shoes">Search</a> <a href="/product?id=1">Product</a>
<a href="/redirect?next=/">Go</a> <a href="/download?file=readme.txt">Download</a>
<a href="/static/">Static</a> <a href="/login">Login</a> <a href="/api/data">API</a>
<a href="https://third-party.example.invalid/ad">external</a>
<form action="/search" method="get"><input name="q" value="shoes"><input type="submit"></form>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "SimHTTP/0.1"
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):  # silence
        pass

    def _send(self, status=200, body="", ctype="text/html; charset=utf-8", extra=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(200, "", extra={"Allow": "GET, POST, PUT, DELETE, OPTIONS, TRACE"})

    def do_TRACE(self):
        self._send(200, "TRACE " + self.path, ctype="message/http")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = up.urlparse(self.path)
        q = dict(up.parse_qsl(u.query))
        p = u.path
        if p == "/":
            page = PAGE.replace("</body>", "<a href='/account'>My account</a></body>") if self._signed_in() else PAGE
            self._send(200, page, extra={"Set-Cookie": "sessionid=abc123; Path=/"})
        elif p == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif p == "/search":  # reflected XSS, no encoding
            self._send(200, f"<html><body><h2>Results for {q.get('q', '')}</h2><a href='/'>home</a></body></html>")
        elif p == "/product":  # error-based SQLi (simulated message)
            pid = q.get("id", "1")
            if "'" in pid:
                self._send(500, "<html><body>You have an error in your SQL syntax near ''' at line 1</body></html>")
            else:
                self._send(200, f"<html><body>Product {html.escape(pid)}</body></html>")
        elif p == "/redirect":  # open redirect
            self._send(302, "", extra={"Location": q.get("next", "/")})
        elif p == "/download":  # path traversal (simulated)
            f = q.get("file", "")
            if "etc/passwd" in f.replace("%2f", "/"):
                self._send(200, "root:x:0:0:root:/root:/bin/bash\n", "text/plain")
            else:
                self._send(200, "readme", "text/plain")
        elif p == "/.env":
            self._send(200, "DB_PASSWORD=fake\nSECRET_KEY=fake\n", "text/plain")
        elif p == "/static/":
            self._send(200, "<html><head><title>Index of /static</title></head><body>"
                            "<a href='../'>Parent Directory</a></body></html>")
        elif p == "/login":
            self._send(200, "<html><body><form action='/login' method='post'>"
                            "<input name='user'><input type='password' name='pw'>"
                            "<input type='submit'></form></body></html>")
        elif p == "/api/data":
            origin = self.headers.get("Origin", "")
            extra = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} if origin else {}
            self._send(200, '{"ok": true}', "application/json", extra)
        elif p == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
        elif p == "/account":  # only for a signed-in demo session
            if not self._signed_in():
                self._send(302, "", extra={"Location": "/login"})
            else:
                self._send(200, "<html><body><h2>Account of demo</h2>"
                                "<a href='/account/profile?name=demo'>Profile</a></body></html>")
        elif p == "/account/profile":  # reflected XSS, reachable only when signed in
            if not self._signed_in():
                self._send(302, "", extra={"Location": "/login"})
            else:
                self._send(200, f"<html><body><h2>Profile of {q.get('name', '')}</h2></body></html>")
        else:
            self._send(404, "<html><body>Not found</body></html>")

    def _signed_in(self) -> bool:
        cookies = self.headers.get("Cookie", "")
        return any(c.strip() == f"demo_session={DEMO_SESSION}" for c in cookies.split(";"))

    def do_POST(self):
        """Demo sign-in with the public, fake DEMO_USERNAME / DEMO_PASSWORD."""
        if up.urlparse(self.path).path != "/login":
            self._send(404, "<html><body>Not found</body></html>")
            return
        length = min(int(self.headers.get("Content-Length") or 0), 10_000)
        form = dict(up.parse_qsl(self.rfile.read(length).decode("utf-8", "replace")))
        if form.get("user") == DEMO_USERNAME and form.get("pw") == DEMO_PASSWORD:
            self._send(302, "", extra={"Location": "/account",
                                       "Set-Cookie": f"demo_session={DEMO_SESSION}; Path=/; HttpOnly"})
        else:
            self.do_GET()  # wrong credentials: the login form comes back


class SimulatedTarget:
    """Context manager: starts the vulnerable app on a free loopback port."""

    def __init__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.netloc = f"127.0.0.1:{self.port}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._t.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()
