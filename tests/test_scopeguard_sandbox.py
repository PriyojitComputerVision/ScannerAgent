"""Verifies the Docker-free sandbox really blocks escapes. Stdlib only (runs under pytest or directly)."""
import json
import subprocess
import sys
import textwrap
from pathlib import Path

SRC = str(Path(__file__).resolve().parent.parent / "src")
sys.path.insert(0, SRC)

from scopeguard.engine import ScopedClient, ScopeViolation
from scopeguard.sandbox import run_sandboxed_scan
from scopeguard.simulated_target import SimulatedTarget


def _escape_attempt(code: str, allowed: str = "127.0.0.1:9") -> str:
    """Run `code` inside a process with the worker's audit hook installed; return its stdout."""
    boot = textwrap.dedent(f"""
        import sys, os, tempfile
        sys.path.insert(0, {SRC!r})
        from scopeguard.worker import _install_audit_hook
        import socket, subprocess, urllib.request  # preload
        d = tempfile.mkdtemp()
        os.chdir(d)
        _install_audit_hook({{"127.0.0.1"}}, {{"127.0.0.1"}}, {{9}}, d)
    """) + textwrap.dedent(code)
    p = subprocess.run([sys.executable, "-c", boot], capture_output=True, text=True, timeout=30, check=False)
    return p.stdout + p.stderr


def test_blocks_subprocess():
    assert "sandbox: subprocess.Popen blocked" in _escape_attempt(
        "import subprocess\ntry:\n subprocess.run(['echo','x'])\nexcept PermissionError as e: print(e)")


def test_blocks_os_system():
    assert "os.system blocked" in _escape_attempt(
        "import os\ntry:\n os.system('echo x')\nexcept PermissionError as e: print(e)")


def test_blocks_egress_to_other_ip_raw_connect():
    assert "egress to 8.8.8.8:53 blocked" in _escape_attempt(
        "import socket\ns=socket.socket()\ntry:\n s.connect(('8.8.8.8',53))\nexcept PermissionError as e: print(e)")


def test_blocks_egress_to_other_ip_create_connection():
    assert "blocked" in _escape_attempt(
        "import socket\ntry:\n socket.create_connection(('8.8.8.8',53),timeout=1)\nexcept PermissionError as e: print(e)")


def test_blocks_wrong_port_on_allowed_ip():
    assert "egress to 127.0.0.1:22 blocked" in _escape_attempt(
        "import socket\ntry:\n socket.create_connection(('127.0.0.1',22),timeout=1)\nexcept PermissionError as e: print(e)")


def test_blocks_dns_exfil():
    assert "DNS lookup for evil.example blocked" in _escape_attempt(
        "import socket\ntry:\n socket.getaddrinfo('evil.example',80)\nexcept PermissionError as e: print(e)")


def test_blocks_write_outside_sandbox():
    out = _escape_attempt("try:\n open('/tmp/scopeguard_should_not_exist','w')\nexcept PermissionError as e: print(e)")
    assert "write blocked" in out and not Path("/tmp/scopeguard_should_not_exist").exists()


def test_allows_write_inside_sandbox():
    assert "ok" in _escape_attempt("open('inside.txt','w').write('x'); print('ok')")


def test_blocks_listening_socket():
    assert "listening sockets blocked" in _escape_attempt(
        "import socket\ns=socket.socket()\ntry:\n s.bind(('127.0.0.1',0))\nexcept PermissionError as e: print(e)")


def test_scoped_client_rejects_out_of_scope_and_bad_methods():
    c = ScopedClient({"127.0.0.1:1234"})
    for fn in (lambda: c.get("http://evil.example/"), lambda: c.request("POST", "http://127.0.0.1:1234/"),
               lambda: c.get("http://user:pw@127.0.0.1:1234/")):
        try:
            fn()
            assert False, "should have raised"
        except ScopeViolation:
            pass


def test_env_secrets_not_inherited(monkeypatch=None):
    import os
    os.environ["GROQ_API_KEY"] = "SECRET-SHOULD-NOT-LEAK"
    with SimulatedTarget() as t:
        res = run_sandboxed_scan({"target_url": t.url, "allowed_domains": [t.netloc], "profile": "quick", "delay": 0})
    assert "SECRET-SHOULD-NOT-LEAK" not in json.dumps(res)


def test_full_simulated_scan_finds_expected():
    with SimulatedTarget() as t:
        res = run_sandboxed_scan({"target_url": t.url, "allowed_domains": [t.netloc], "profile": "standard", "delay": 0})
    titles = " | ".join(f["title"] for f in res["findings"])
    for expected in ("Possible SQL injection", "Open redirect", "Path traversal", "Reflected input", "JS_EVAL"):
        assert expected in titles
    assert any("third-party.example.invalid" in u for u in res["external_links_blocked"])
    assert all(u.startswith(t.url) for u in res["crawled_pages"])


def test_unresolvable_allowed_host_does_not_abort_scan():
    # e.g. a "www." twin that has no DNS record: skipped, scan still runs.
    with SimulatedTarget() as t:
        res = run_sandboxed_scan({"target_url": t.url, "profile": "quick", "delay": 0,
                                  "allowed_domains": [t.netloc, "no-such-host.invalid"]})
    assert res["crawled_pages"] and all(u.startswith(t.url) for u in res["crawled_pages"])


def test_quick_profile_sends_no_active_payloads():
    with SimulatedTarget() as t:
        res = run_sandboxed_scan({"target_url": t.url, "allowed_domains": [t.netloc], "profile": "quick", "delay": 0})
    assert not any(f["title"].startswith(("Possible SQL", "Path traversal", "Open redirect")) for f in res["findings"])


if __name__ == "__main__":
    fails = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            try:
                fn(); print("PASS", name)
            except Exception as e:  # noqa: BLE001
                fails += 1; print("FAIL", name, repr(e)[:200])
    sys.exit(1 if fails else 0)


def test_js_http_url_rule_ignores_xml_namespaces():
    from scopeguard.engine import JS_RULES
    rx = next(r[1] for r in JS_RULES if r[0] == "JS_HTTP_URL")
    assert not rx.search('const svgNS = "http://www.w3.org/2000/svg";')
    assert not rx.search("el.setAttribute('xmlns:xlink', 'http://www.w3.org/1999/xlink')")
    assert rx.search('fetch("http://api.example.com/data")')
