"""DAST covers the pages recon found (up to MAX_CRAWL_PAGES), also when the site's links are built by
JavaScript and the engine alone would find only the home page. Local server only."""
from __future__ import annotations

import threading
import typing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pentest_agent.tools import dast_native
from scopeguard import engine


class _NoLinks(BaseHTTPRequestHandler):
    """A JavaScript-built site: no <a href> in any page's HTML."""

    def log_message(self, *_a):
        pass

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/page"):
            body = b"<html><body><div id='app'></div><script>/* links built here */</script></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
        else:
            body = b"nope"
            self.send_response(404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def site():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _NoLinks)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _pages(result: dict) -> list[str]:
    return result["crawled_pages"]


def test_without_seeds_the_engine_finds_only_the_home_page(site):
    out = engine.run_scan(f"{site}/", [site.split("//")[1]], profile="quick", delay=0)
    assert _pages(out) == [f"{site}/"]


def test_seeds_from_recon_are_crawled_in_scope_only_and_once(site):
    host = site.split("//")[1]
    seeds = [f"{site}/page{i}" for i in range(5)] + [f"{site}/page1#faq", "https://elsewhere.test/x",
                                                    f"{site}/setup.exe"]
    out = engine.run_scan(f"{site}/", [host], profile="quick", delay=0, seed_urls=seeds)
    assert _pages(out) == [f"{site}/"] + [f"{site}/page{i}" for i in range(5)]   # no #faq copy, no file
    assert "https://elsewhere.test/x" in out["external_links_blocked"]               # recorded, never fetched


def test_the_page_cap_still_holds(site):
    host = site.split("//")[1]
    seeds = [f"{site}/page{i}" for i in range(20)]
    out = engine.run_scan(f"{site}/", [host], profile="quick", delay=0, seed_urls=seeds, max_pages=6)
    assert len(_pages(out)) == 6


def test_dast_sends_recon_pages_and_max_crawl_pages_to_the_sandbox(monkeypatch):
    seen = {}

    def fake_run(scan_args, **_kw):
        seen.update(scan_args)
        return {"findings": [], "red_flags": [], "crawled_pages": scan_args["seed_urls"], "requests_made": 1}

    monkeypatch.setattr(dast_native, "run_sandboxed_scan", fake_run)
    monkeypatch.setattr(dast_native.settings, "max_crawl_pages", 60)
    pages = [f"https://app.example.com/p{i}" for i in range(60)]
    out = dast_native.execute_native_dast("https://app.example.com/", "standard", ["app.example.com"],
                                          seed_pages=pages)
    assert seen["seed_urls"] == pages and seen["max_pages"] == 60       # standard's own cap is 40
    assert "60 pages" in out["notes"]
    dast_native.execute_native_dast("https://app.example.com/", "aggressive", ["app.example.com"], seed_pages=pages)
    assert seen["max_pages"] == 80                                       # a higher profile cap stays


class _Flaky(BaseHTTPRequestHandler):
    """/p2 answers 503 twice, then 200; every other page answers at once."""

    hits: typing.ClassVar[dict] = {}

    def log_message(self, *_a):
        pass

    def do_GET(self):
        n = _Flaky.hits[self.path] = _Flaky.hits.get(self.path, 0) + 1
        if self.path == "/p2" and n <= 2:
            body, status = b"busy", 503
        elif self.path == "/" or self.path.startswith("/p"):
            body, status = b"<html><body>page</body></html>", 200
        else:
            body, status = b"nope", 404
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def flaky():
    _Flaky.hits = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Flaky)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_dast_retries_a_failed_page_up_to_three_times(flaky, monkeypatch):
    slept = []
    monkeypatch.setattr(engine.Scanner, "_sleep", staticmethod(slept.append))
    out = engine.run_scan(f"{flaky}/", [flaky.split("//")[1]], profile="quick", delay=0,
                          seed_urls=[f"{flaky}/p1", f"{flaky}/p2"])
    assert f"{flaky}/p2" in out["crawled_pages"] and _Flaky.hits["/p2"] == 3   # two 503s, then the page
    assert slept == [engine.PAGE_RETRY_DELAY, engine.PAGE_RETRY_DELAY * 2]     # growing pauses


def test_sandbox_check_retries_a_failed_page(flaky, monkeypatch):
    from pentest_agent.http_retry import rate_limited_client
    from pentest_agent.tools import sandbox_check
    from scopeguard.ratelimit import RateLimitStats

    slept = []
    monkeypatch.setattr(sandbox_check, "_pause", slept.append)
    with rate_limited_client(RateLimitStats()) as client:
        got = sandbox_check._fetch(client, f"{flaky}/p2", {flaky.split("//")[1]}, [])
    assert got and "page" in got[0] and slept == [1.0, 2.0]
