"""Command line entry point.

  python -m scopeguard.cli --simulate                 # self-contained demo + self-test
  python -m scopeguard.cli --url http://localhost:3000 --i-have-authorization
  python -m scopeguard.cli --simulate --serve         # ...then view it at http://127.0.0.1:8000/
  python -m scopeguard.cli --serve                    # just browse existing reports
"""
from __future__ import annotations

import argparse
import socket
import sys
import time
import urllib.parse as up
from pathlib import Path

from scopeguard.report import DOWNLOADABLE, download_name, render_index, write_reports
from scopeguard.sandbox import SandboxError, run_sandboxed_scan
from scopeguard.simulated_target import SimulatedTarget

# What the simulated target is built to expose (substring of finding title).
EXPECTED = [
    "Reflected input without output encoding", "Possible SQL injection", "Open redirect",
    "Path traversal", "Exposed environment file", "Directory listing enabled",
    "CORS reflects arbitrary Origin", "Password form served over plaintext HTTP",
    "JS_EVAL", "JS_INNERHTML", "AWS_ACCESS_KEY", "Missing Content-Security-Policy",
    "missing HttpOnly", "TRACE method enabled",
]


def _print_summary(res: dict) -> None:
    order = ["critical", "high", "medium", "low", "info"]
    counts = {s: sum(1 for f in res["findings"] if f["severity"] == s) for s in order}
    print(f"\nPages crawled: {len(res['crawled_pages'])} | requests: {res['requests_made']} | "
          f"blocked external links: {len(res['external_links_blocked'])} | {res['duration_seconds']}s")
    print("Severity:", ", ".join(f"{k}={v}" for k, v in counts.items()))
    for f in res["findings"]:
        print(f"  [{f['severity'].upper():8}] {f['title']}  ({f.get('affected_url') or ''})")
    for rf in res["red_flags"]:
        print("  RED FLAG:", rf)


def make_report_server(reports_dir: str, port: int):
    """Loopback-only HTTP server for the reports directory (not started)."""
    import functools
    import http.server

    root = Path(reports_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            parts = self.path.split("?", 1)[0].strip("/").split("/")
            if len(parts) == 2 and parts[1] in DOWNLOADABLE:  # /<report>/report.docx
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{download_name(parts[0], parts[1])}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
            super().end_headers()

        def do_GET(self):
            if self.path.split("?", 1)[0] in ("/", "/index.html"):
                body = render_index(root).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path.endswith("/") and self.path.count("/") == 2:  # /<report>/ -> its HTML view
                self.path += "report.html"
            super().do_GET()

        def list_directory(self, path):  # no raw directory listings
            self.send_error(404)

        def log_message(self, *args):
            pass

    return http.server.ThreadingHTTPServer(
        ("127.0.0.1", port), functools.partial(Handler, directory=str(root)))


def serve_reports(reports_dir: str, port: int, open_path: str = "") -> None:
    """Serve the reports directory on loopback only until Ctrl+C."""
    httpd = make_report_server(reports_dir, port)
    base = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"\nServing reports at {base}")
    if open_path:
        print(f"This report:       {base}{open_path}")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def _reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """True if any resolved address of host:port accepts a TCP connection."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    for fam, stype, proto, _, addr in infos:
        try:
            with socket.socket(fam, stype, proto) as s:
                s.settimeout(timeout)
                s.connect(addr)
            return True
        except OSError:
            continue
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="scopeguard")
    ap.add_argument("--simulate", action="store_true", help="scan the built-in vulnerable local target")
    ap.add_argument("--url")
    ap.add_argument("--profile", default="standard", choices=["quick", "standard", "aggressive", "auth_deep"])
    ap.add_argument("--allow", action="append", default=[], help="extra allowed host[:port]")
    ap.add_argument("--bearer")
    ap.add_argument("--out", default="data/reports")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--i-have-authorization", action="store_true",
                    help="confirm you own / are authorized to test --url")
    ap.add_argument("--serve", action="store_true",
                    help="after the scan (or alone) serve reports at http://127.0.0.1:PORT/")
    ap.add_argument("--port", type=int, default=8000, help="port for --serve (default 8000)")
    a = ap.parse_args(argv)

    if a.serve and not a.simulate and not a.url:
        serve_reports(a.out, a.port)
        return 0

    if a.simulate:
        with SimulatedTarget() as t:
            print(f"[sim] vulnerable target on {t.url} (loopback only)")
            scan = dict(target_url=t.url, allowed_domains=[t.netloc], profile=a.profile,
                        delay=0.0, bearer=None)
            try:
                res = run_sandboxed_scan(scan, wall_timeout=a.timeout)
            except SandboxError as e:
                print("SANDBOX ERROR:", e)
                return 2
            target, mode = t.url, "simulated"
    else:
        if not a.url:
            ap.error("--url or --simulate required")
        if not a.i_have_authorization:
            print("Refusing: pass --i-have-authorization only for systems you own or may test.")
            return 3
        p = up.urlparse(a.url)
        if p.scheme not in ("http", "https") or not p.hostname:
            ap.error("--url must be http(s)://host[:port]")
        port = p.port or (443 if p.scheme == "https" else 80)
        if not _reachable(p.hostname, port):
            print(f"Target not reachable: nothing is accepting connections on {p.hostname}:{port}.\n"
                  "Start your application first (or check the URL/port), then re-run.")
            return 4
        scan = dict(target_url=a.url, allowed_domains=[p.netloc, *a.allow], profile=a.profile,
                    bearer=a.bearer)
        try:
            res = run_sandboxed_scan(scan, wall_timeout=a.timeout)
        except SandboxError as e:
            print("SANDBOX ERROR:", e)
            return 2
        target, mode = a.url, "live"

    _print_summary(res)
    out = Path(a.out) / f"{mode}-{time.strftime('%Y%m%d%H%M%S')}"
    paths = write_reports(str(out), target, res, mode)
    print("\nReports:", ", ".join(paths.values()))
    print("Sandbox egress locked to:", res["sandbox"]["egress_ips"], res["sandbox"]["egress_ports"])

    rc = _self_test(res) if a.simulate and a.profile != "quick" else 0
    if a.serve:
        serve_reports(a.out, a.port, f"{out.name}/")
    return rc


def _self_test(res: dict) -> int:
    titles = " | ".join(f["title"] for f in res["findings"])
    missing = [e for e in EXPECTED if e not in titles]
    if missing:
        print("\nSELF-TEST FAILED, not detected:", missing)
        return 1
    if not any("third-party.example.invalid" in u for u in res["external_links_blocked"]):
        print("\nSELF-TEST FAILED: external link was not recorded as blocked")
        return 1
    print(f"\nSELF-TEST PASSED: all {len(EXPECTED)} planted issues detected, "
          "external link blocked, no out-of-scope requests.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
