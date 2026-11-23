"""Scans never download files (scopeguard/contentpolicy.py): attachments and
binaries are discarded unread, file links are not crawled, text is capped."""
from __future__ import annotations

import gzip
import http.server
import threading

import httpx
import pytest

from pentest_agent.http_retry import RateLimitRetryTransport
from pentest_agent.tools import sandbox_check
from scopeguard import contentpolicy, engine

MZ = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 64


# ----------------------------------------------------------------- decision table
@pytest.mark.parametrize("ctype, disposition, encoding, mode", [
    ("text/html; charset=utf-8", None, None, "read"),
    ("application/json", None, None, "read"),
    ("application/javascript", None, None, "read"),
    ("application/vnd.api+json", None, None, "read"),
    ("text/html", "attachment; filename=setup.exe", None, "drop"),
    ("text/plain", "Attachment", None, "drop"),
    ("image/png", None, None, "drop"),
    ("image/svg+xml", None, None, "drop"),
    ("application/zip", None, None, "drop"),
    ("application/pdf", None, None, "drop"),
    ("application/x-msdownload", None, None, "drop"),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml.document", None, None, "drop"),
    ("text/html", None, "br", "drop"),
    ("text/html", None, "zstd", "drop"),
    ("text/html", None, "gzip", "read"),
    ("application/octet-stream", None, None, "sniff"),
    (None, None, None, "sniff"),
    ("text/html", "inline", None, "read"),
])
def test_body_policy(ctype, disposition, encoding, mode):
    assert contentpolicy.body_policy(ctype, disposition, encoding)[0] == mode


@pytest.mark.parametrize("head, binary", [
    (MZ, True), (b"\x7fELF\x02\x01", True), (b"PK\x03\x04rest", True), (b"%PDF-1.7", True),
    (b"\x1f\x8b\x08", True), (b"abc\x00def", True), (b"\x89PNG\r\n", True),
    (b"<!doctype html><p>hi</p>", False), (b"\xef\xbb\xbf{\"a\": 1}", False), (b"DB_PASSWORD=x\n", False),
])
def test_looks_binary(head, binary):
    assert contentpolicy.looks_binary(head) is binary


@pytest.mark.parametrize("url, is_file", [
    ("https://x.test/downloads/setup.exe", True), ("https://x.test/a/B.ZIP", True),
    ("https://x.test/report.pdf?v=2", True), ("https://x.test/evil%2Eexe", True),
    ("https://x.test/img/logo.png", True), ("https://x.test/app.apk/", True),
    ("https://x.test/", False), ("https://x.test/about", False), ("https://x.test/static/app.js", False),
    ("https://x.test/api/files/42", False), ("https://x.test/style.css", False),
])
def test_is_file_link(url, is_file):
    assert contentpolicy.is_file_link(url) is is_file


# ----------------------------------------------------------------- agent transport
class _Tracked(httpx.SyncByteStream):
    """Response body that records whether anyone read it."""

    def __init__(self, data: bytes, chunk: int = 65536):
        self.data, self.chunk, self.read = data, chunk, 0

    def __iter__(self):
        for i in range(0, len(self.data), self.chunk):
            self.read += 1
            yield self.data[i:i + self.chunk]


def _client(handler):
    return httpx.Client(transport=RateLimitRetryTransport(httpx.MockTransport(handler)))


def _serve(headers: dict, body: bytes, status: int = 200):
    stream = _Tracked(body)
    seen = {}

    def handler(request):
        seen["accept_encoding"] = request.headers.get("accept-encoding")
        return httpx.Response(status, headers=headers, stream=stream)
    return handler, stream, seen


def test_attachment_is_never_read():
    handler, stream, _ = _serve({"content-type": "text/html", "content-disposition": "attachment; filename=a.html"},
                                b"<p>secret</p>" * 1000)
    with _client(handler) as c:
        r = c.get("http://t.test/export")
    assert r.status_code == 200 and r.content == b"" and stream.read == 0
    assert "attachment" in r.headers[contentpolicy.DROPPED_HEADER]


@pytest.mark.parametrize("ctype", ["application/x-msdownload", "application/zip", "image/png", "video/mp4"])
def test_binary_types_are_never_read(ctype):
    handler, stream, _ = _serve({"content-type": ctype}, MZ * 1000)
    with _client(handler) as c:
        r = c.get("http://t.test/f")
    assert r.content == b"" and stream.read == 0 and r.headers[contentpolicy.DROPPED_HEADER]


@pytest.mark.parametrize("ctype", ["application/octet-stream", "text/html", ""])
def test_executable_bytes_are_discarded_even_when_mislabelled(ctype):
    handler, _, _ = _serve({"content-type": ctype} if ctype else {}, MZ * 5000)
    with _client(handler) as c:
        assert c.get("http://t.test/setup").content == b""


def test_unknown_type_is_sniffed_and_capped():
    handler, stream, _ = _serve({"content-type": "application/octet-stream"}, b"DB_PASSWORD=x\n" * 50_000)
    with _client(handler) as c:
        body = c.get("http://t.test/.env").content
    assert body.startswith(b"DB_PASSWORD=x") and len(body) == contentpolicy.SNIFF_BYTES
    assert stream.read <= 2   # stopped reading once the sniff limit was reached


def test_text_is_capped():
    handler, _, _ = _serve({"content-type": "text/html"}, b"a" * (contentpolicy.TEXT_LIMIT_BYTES + 500_000))
    with _client(handler) as c:
        assert len(c.get("http://t.test/").content) == contentpolicy.TEXT_LIMIT_BYTES


def test_gzip_bomb_is_bounded():
    bomb = gzip.compress(b"a" * 40_000_000)          # ~40 KB on the wire, 40 MB if fully expanded
    handler, _, _ = _serve({"content-type": "text/html", "content-encoding": "gzip"}, bomb)
    with _client(handler) as c:
        r = c.get("http://t.test/")
        assert len(r.content) == contentpolicy.TEXT_LIMIT_BYTES
    assert "content-encoding" not in r.headers       # already decoded, exactly once


def test_unsupported_encoding_is_dropped_and_only_safe_encodings_are_requested():
    handler, stream, seen = _serve({"content-type": "text/html", "content-encoding": "br"}, b"\x1b\x00" * 100)
    with _client(handler) as c:
        r = c.get("http://t.test/")
    assert r.content == b"" and stream.read == 0
    assert seen["accept_encoding"] == "gzip, deflate"


def test_head_and_status_only_probes_keep_headers():
    handler, _, _ = _serve({"content-type": "application/zip", "content-length": "999999"}, b"")
    with _client(handler) as c:
        r = c.get("http://t.test/backup.zip")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"


def test_rate_limited_body_is_not_read():
    bodies = [_Tracked(b"slow down" * 10_000), _Tracked(b"<p>ok</p>")]
    calls = iter([429, 200])

    def handler(request):
        status = next(calls)
        return httpx.Response(status, headers={"retry-after": "0", "content-type": "text/html"},
                              stream=bodies[0] if status == 429 else bodies[1])
    with httpx.Client(transport=RateLimitRetryTransport(httpx.MockTransport(handler), sleep=lambda s: None)) as c:
        assert c.get("http://t.test/").text == "<p>ok</p>"
    assert bodies[0].read == 0


def test_code_check_staging_skips_dropped_bodies(tmp_path):
    def handler(request):
        if request.url.path == "/":
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  content=b'<script src="/app.js"></script><script src="/payload.js"></script>'
                                          b'<script src="/tool.exe"></script>')
        if request.url.path == "/app.js":
            return httpx.Response(200, headers={"content-type": "application/javascript"}, content=b"let a = 1;")
        return httpx.Response(200, headers={"content-type": "application/javascript"}, content=MZ * 10)

    real = sandbox_check.rate_limited_client
    sandbox_check.rate_limited_client = lambda *a, **kw: httpx.Client(
        transport=RateLimitRetryTransport(httpx.MockTransport(handler)))
    try:
        stats = sandbox_check.collect_site_content(["http://t.test/"], ["t.test"], tmp_path, [])
    finally:
        sandbox_check.rate_limited_client = real
    staged = sorted(p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file())
    assert stats["scripts"] == 1
    assert staged == ["manifest.json", "pages/0001.html", "scripts/0001.js"]
    assert (tmp_path / "scripts/0001.js").read_text(encoding="utf-8") == "let a = 1;"


# ----------------------------------------------------------------- sandbox engine
@pytest.fixture
def file_site():
    hits = []
    routes = {
        "/": ("text/html", None, (b'<a href="/about">a</a><a href="/dl/setup.exe">x</a>'
                                  b'<a href="/docs/r.pdf">p</a><a href="/export">e</a>')),
        "/about": ("text/html", None, b"<p>about</p>"),
        "/export": ("text/csv", "attachment; filename=users.csv", b"id,email\n1,a@b.c\n"),
        "/blob": ("application/octet-stream", None, MZ * 100),
        "/dl/setup.exe": ("application/x-msdownload", None, MZ),
        "/docs/r.pdf": ("application/pdf", None, b"%PDF-1.7"),
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            ctype, disp, body = routes.get(self.path, ("text/plain", None, b"nf"))
            self.send_response(200 if self.path in routes else 404)
            self.send_header("Content-Type", ctype)
            if disp:
                self.send_header("Content-Disposition", disp)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"127.0.0.1:{httpd.server_address[1]}", hits
    httpd.shutdown()
    httpd.server_close()


def test_engine_client_discards_files(file_site):
    netloc, _ = file_site
    client = engine.ScopedClient([netloc], delay=0)
    export = client.get(f"http://{netloc}/export")
    blob = client.get(f"http://{netloc}/blob")
    page = client.get(f"http://{netloc}/about")
    assert export.body == "" and "attachment" in export.dropped and export.status == 200
    assert blob.body == "" and "binary" in blob.dropped
    assert page.body == "<p>about</p>" and not page.dropped
    assert [u.rsplit("/", 1)[1] for u, _ in client.dropped] == ["export", "blob"]


def test_engine_crawler_never_requests_file_links(file_site):
    netloc, hits = file_site
    scanner = engine.Scanner(f"http://{netloc}/", [netloc], "quick", None, 0, None, None)
    scanner.crawl()
    assert "/dl/setup.exe" not in hits and "/docs/r.pdf" not in hits
    assert "/about" in hits
