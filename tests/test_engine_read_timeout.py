"""A page whose body stalls after the headers must not abort the whole scan.

Regression: ``resp.read()`` raised ``TimeoutError: The read operation timed out``
outside the guarded ``open()`` call, the worker died and DAST reported
"Native DAST failed" with no findings.
"""
from __future__ import annotations

import http.server
import threading
import time

import pytest

from scopeguard import engine


@pytest.fixture
def stalling_site():
    release = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/slow":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", "1000")
                self.end_headers()
                self.wfile.write(b"<p>partial")
                self.wfile.flush()
                release.wait(5)  # stall the body past the client timeout
                return
            body = b'<a href="/slow">s</a><a href="/ok">o</a>' if self.path == "/" else b"<p>ok</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{httpd.server_address[1]}"
    release.set()
    httpd.shutdown()
    httpd.server_close()


def test_body_read_timeout_becomes_error_response(stalling_site):
    client = engine.ScopedClient([stalling_site], delay=0, timeout=0.5)
    start = time.monotonic()
    slow = client.get(f"http://{stalling_site}/slow")
    assert time.monotonic() - start < 4
    assert slow.status == 0 and slow.body == ""
    assert "timed out" in slow.error.lower()
    assert client.log[-1] == ("GET", f"http://{stalling_site}/slow", 0)
    ok = client.get(f"http://{stalling_site}/ok")
    assert ok.status == 200 and ok.body == "<p>ok</p>"


def test_crawl_survives_a_stalling_page(stalling_site):
    scanner = engine.Scanner(f"http://{stalling_site}/", [stalling_site], "quick", None, 0, None, None)
    scanner.client.timeout = 0.5
    scanner.crawl()
    assert ("GET", f"http://{stalling_site}/ok", 200) in scanner.client.log
