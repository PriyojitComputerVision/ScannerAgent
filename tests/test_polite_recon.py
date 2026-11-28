"""Recon is faster without straining the target: a few requests at once, one at a time on strain,
pages in crawl order, every page (and #fragment of it) fetched once. Local server only."""
from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from pentest_agent.tools import polite_fetch, recon
from pentest_agent.tools.polite_fetch import PoliteFetcher


# ------------------------------------------------------------------ the fetcher
def test_map_keeps_input_order_and_caps_the_width():
    active, peak, lock = [0], [0], threading.Lock()

    def work(i):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        time.sleep(0.05)
        with lock:
            active[0] -= 1
        return i * 10

    out = PoliteFetcher(width=3).map(work, range(9))
    assert [r for r, _, _ in out] == [i * 10 for i in range(9)]
    assert peak[0] == 3


@pytest.mark.parametrize("status, seconds, failed", [(429, 0.1, False), (503, 0.1, False), (500, 0.1, False),
                                                     (200, 9.0, False), (None, 0.1, True)])
def test_strain_drops_to_one_request_at_a_time_for_good(status, seconds, failed):
    f = PoliteFetcher(width=3)
    f.note(200, 0.1)
    f.note(404, 0.1)                         # a missing page is not strain
    assert f.current == 3
    f.note(status, seconds, failed=failed)
    assert f.current == 1 and f.strained and f.reason
    f.note(200, 0.1)
    assert f.current == 1                    # never undone


def test_a_429_the_transport_handled_counts_as_strain():
    stats = SimpleNamespace(throttled=2)
    f = PoliteFetcher(width=3, rate_stats=stats)
    assert f.current == 3                    # throttles before this crawl do not count
    stats.throttled = 3
    assert f.current == 1


def test_width_follows_the_cpu_count_up_to_three(monkeypatch):
    for cpus, width in ((None, 1), (1, 1), (2, 2), (12, 3)):
        monkeypatch.setattr(polite_fetch.os, "cpu_count", lambda c=cpus: c)
        assert polite_fetch.default_width() == width


def test_page_url_drops_the_fragment():
    assert recon.page_url("https://a.test/p#faq") == "https://a.test/p"
    assert recon.page_url("https://a.test/p?q=1") == "https://a.test/p?q=1"


# ------------------------------------------------------------------ the crawl
class _Site:
    """Ten linked pages (with #fragment links to the same pages); counts requests in flight."""

    def __init__(self, delay=0.15, status=200):
        self.delay, self.status = delay, status
        self.paths: list[str] = []
        self.active = self.peak = 0
        self.lock = threading.Lock()

    def handler(self):
        site = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_GET(self):
                with site.lock:
                    site.paths.append(self.path)
                    site.active += 1
                    site.peak = max(site.peak, site.active)
                try:
                    time.sleep(site.delay)
                    if self.path in ("/", "/index") or self.path.startswith("/p"):
                        links = "".join(f'<a href="/p{i}">p{i}</a><a href="/p{i}#top">top</a>' for i in range(10))
                        body = f"<html><body>{links}</body></html>".encode()
                        self.send_response(site.status if self.path != "/" else 200)
                        self.send_header("Content-Type", "text/html")
                    else:
                        body = b"not found"
                        self.send_response(404)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    with site.lock:
                        site.active -= 1
        return H


@pytest.fixture
def site():
    s = _Site()
    server = ThreadingHTTPServer(("127.0.0.1", 0), s.handler())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    s.url = f"http://127.0.0.1:{server.server_address[1]}/"
    s.host = f"127.0.0.1:{server.server_address[1]}"
    yield s
    server.shutdown()


def _crawl(site, monkeypatch, width=3, max_pages=20):
    monkeypatch.setattr(polite_fetch, "default_width", lambda: width)
    monkeypatch.setattr(recon.settings, "max_crawl_pages", max_pages)
    return recon.recon_and_crawl.invoke({"target_url": site.url, "allowed_domains": [site.host]}).update


def test_crawl_is_parallel_but_polite_and_fetches_each_page_once(site, monkeypatch):
    start = time.monotonic()
    out = _crawl(site, monkeypatch, width=3)
    parallel = time.monotonic() - start
    pages = [p for p in site.paths if p == "/" or p.startswith("/p")]
    assert len(pages) == len(set(pages)) == 11            # / and p0..p9, each once, no #fragment copies
    assert 1 < site.peak <= 3                             # a few at once, never more than 3
    assert out["crawled_pages"] == [site.url] + [f"{site.url}p{i}" for i in range(10)]  # crawl order kept

    site.paths.clear()
    site.peak = 0
    start = time.monotonic()
    again = _crawl(site, monkeypatch, width=1)
    sequential = time.monotonic() - start
    assert site.peak == 1 and again["crawled_pages"] == out["crawled_pages"]   # same result
    assert parallel < sequential


def test_crawl_never_fetches_more_pages_than_allowed(site, monkeypatch):
    out = _crawl(site, monkeypatch, width=3, max_pages=4)
    assert len(out["crawled_pages"]) == 4
    assert len([p for p in site.paths if p == "/" or p.startswith("/p")]) == 4


def test_a_struggling_site_gets_one_request_at_a_time(site, monkeypatch):
    site.status = 503                         # every page but the home page answers 503
    out = _crawl(site, monkeypatch, width=3)
    crawl_paths = [p for p in site.paths if p.startswith("/p")]
    assert crawl_paths                        # the crawl went on, slowly
    assert any("one request at a time" in f for f in out.get("red_flags", []))
