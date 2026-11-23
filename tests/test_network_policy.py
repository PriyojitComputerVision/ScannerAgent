"""Network policy (scopeguard/netpolicy.py): metadata/link-local blocking, DNS
rebinding protection at connect time, and enforcement in every layer."""
from __future__ import annotations

import http.server
import threading

import httpcore
import httpx
import pytest

from pentest_agent.config import settings
from pentest_agent.guardrails import GuardrailViolation, pre_run_guardrail
from pentest_agent.http_retry import rate_limited_client
from pentest_agent.schemas import TargetInput
from scopeguard import netpolicy
from scopeguard.sandbox import SandboxError, run_sandboxed_scan
from scopeguard.simulated_target import SimulatedTarget


# ----------------------------------------------------------------- address table
@pytest.mark.parametrize("ip", [
    "169.254.169.254",            # AWS / GCP / Azure / OpenStack metadata
    "169.254.170.2",              # ECS task metadata
    "fd00:ec2::254",              # AWS IPv6 metadata
    "100.100.100.200",            # Alibaba metadata
    "192.0.0.192",                # Oracle metadata
    "fe80::1", "fe80::1%eth0",    # IPv6 link-local (with zone id)
    "0.0.0.0", "0.1.2.3", "::",
    "224.0.0.1", "ff02::1", "240.0.0.1", "255.255.255.255",
    "::ffff:169.254.169.254",     # IPv4-mapped
    "64:ff9b::a9fe:a9fe",         # NAT64 embedding 169.254.169.254
    "2002:a9fe:a9fe::1",          # 6to4 embedding 169.254.169.254
])
def test_always_blocked(ip):
    assert netpolicy.blocked_reason(ip)
    assert netpolicy.blocked_reason(ip, block_private=True)


@pytest.mark.parametrize("ip", ["127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
                                "100.64.0.1", "fc00::1", "::ffff:127.0.0.1"])
def test_private_allowed_by_default_but_blockable(ip):
    assert netpolicy.blocked_reason(ip) is None
    assert netpolicy.blocked_reason(ip, block_private=True)


@pytest.mark.parametrize("ip", ["8.8.8.8", "93.184.215.14", "2606:4700::1111"])
def test_public_addresses_allowed(ip):
    assert netpolicy.blocked_reason(ip, block_private=True) is None


def test_check_host_names(monkeypatch):
    with pytest.raises(netpolicy.BlockedAddress, match="metadata host name"):
        netpolicy.check_host("metadata.google.internal")
    with pytest.raises(netpolicy.BlockedAddress, match="metadata host name"):
        netpolicy.check_host("Metadata.Google.Internal.")
    answers = {"mixed.test": ["93.184.215.14", "169.254.169.254"],   # one bad answer taints the name
               "2852039166": ["169.254.169.254"],                    # decimal IPv4 form
               "ok.test": ["93.184.215.14"]}
    monkeypatch.setattr(netpolicy, "resolve", lambda host, port=None: answers[host])
    with pytest.raises(netpolicy.BlockedAddress, match="mixed.test resolves to 169.254.169.254"):
        netpolicy.check_host("mixed.test")
    with pytest.raises(netpolicy.BlockedAddress):
        netpolicy.check_host("2852039166")
    assert netpolicy.check_host("ok.test") == ["93.184.215.14"]
    assert netpolicy.check_host("[::1]") == ["::1"]
    with pytest.raises(netpolicy.BlockedAddress, match="local host"):
        netpolicy.check_host("app.localhost", block_private=True)


def test_unresolvable_name_returns_empty():
    assert netpolicy.check_host("does-not-exist.invalid") == []  # conftest: no DNS in tests


# ----------------------------------------------------------------- pre-scan guardrail
def _target(url, **kw):
    return TargetInput(url=url, session_id="np-1", authorization_confirmed=True, **kw)


@pytest.mark.parametrize("url", ["http://169.254.169.254/latest/meta-data/", "http://[fd00:ec2::254]/",
                                 "http://metadata.google.internal/computeMetadata/v1/",
                                 "http://0xA9FEA9FE/", "http://0.0.0.0:8080/"])
def test_guardrail_refuses_blocked_targets(url):
    with pytest.raises(GuardrailViolation, match="Refusing to scan"):
        pre_run_guardrail(_target(url))


def test_guardrail_refuses_blocked_extra_host(monkeypatch):
    monkeypatch.setattr(netpolicy, "resolve",
                        lambda host, port=None: {"cdn.example.com": ["169.254.169.254"]}[host])
    with pytest.raises(GuardrailViolation, match="cdn.example.com"):
        pre_run_guardrail(_target("http://127.0.0.1:8080/", additional_allowed_domains=["cdn.example.com"]))


def test_guardrail_private_targets(monkeypatch):
    pre_run_guardrail(_target("http://127.0.0.1:8080/"))          # dev targets allowed by default
    pre_run_guardrail(_target("http://localhost:3000/"))
    monkeypatch.setattr(settings, "block_private_targets", True)
    for url in ("http://127.0.0.1:8080/", "http://localhost:3000/", "http://10.0.0.5/"):
        with pytest.raises(GuardrailViolation, match="BLOCK_PRIVATE_TARGETS=true"):
            pre_run_guardrail(_target(url))


# ----------------------------------------------------------------- connect-time pinning
@pytest.fixture
def local_server():
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Host"))
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1], seen
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def connect_spy(monkeypatch):
    calls = []
    real = httpcore.SyncBackend.connect_tcp

    def spy(self, host, port, *args, **kwargs):
        calls.append(host)
        return real(self, host, port, *args, **kwargs)

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", spy)
    return calls


def test_connects_to_the_checked_ip_and_keeps_the_host_header(monkeypatch, local_server, connect_spy):
    port, seen = local_server
    monkeypatch.setattr(netpolicy, "resolve", lambda host, p=None: {"app.test": ["127.0.0.1"]}[host])
    with rate_limited_client() as client:
        assert client.get(f"http://app.test:{port}/").text == "ok"
    assert connect_spy == ["127.0.0.1"]          # the socket went to the vetted IP
    assert seen == [f"app.test:{port}"]          # the request still names the host


def test_dns_rebinding_to_metadata_is_refused(monkeypatch, local_server, connect_spy):
    """First answer passes the check, the next one points at the metadata service."""
    port, seen = local_server
    answers = iter([["127.0.0.1"], ["169.254.169.254"]])
    monkeypatch.setattr(netpolicy, "resolve", lambda host, p=None: next(answers))
    with rate_limited_client() as client:
        assert client.get(f"http://rebind.test:{port}/", headers={"Connection": "close"}).status_code == 200
        with pytest.raises(httpx.ConnectError, match="blocked by network policy"):
            client.get(f"http://rebind.test:{port}/")
    assert connect_spy == ["127.0.0.1"]          # no socket was ever opened to 169.254.169.254
    assert len(seen) == 1


@pytest.mark.parametrize("url", ["http://169.254.169.254/", "http://[::ffff:169.254.169.254]/",
                                 "http://metadata.google.internal/", "http://0.0.0.0:9/"])
def test_client_refuses_blocked_urls_without_connecting(url, connect_spy):
    with rate_limited_client() as client, pytest.raises(httpx.ConnectError, match="network policy"):
        client.get(url)
    assert connect_spy == []


def test_client_honours_block_private(monkeypatch, local_server, connect_spy):
    port, _ = local_server
    monkeypatch.setattr(settings, "block_private_targets", True)
    with rate_limited_client() as client, pytest.raises(httpx.ConnectError, match="network policy"):
        client.get(f"http://127.0.0.1:{port}/")
    assert connect_spy == []


def test_environment_proxies_cannot_bypass_the_policy(monkeypatch, local_server):
    port, seen = local_server
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")    # nothing listens there
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    with rate_limited_client() as client:
        assert client.get(f"http://127.0.0.1:{port}/").status_code == 200   # direct, checked connection
    assert seen


# ----------------------------------------------------------------- sandbox worker + CLI
def test_sandbox_refuses_metadata_target():
    with pytest.raises(SandboxError, match="network policy"):
        run_sandboxed_scan({"target_url": "http://169.254.169.254/", "allowed_domains": ["169.254.169.254"],
                            "profile": "quick", "delay": 0}, wall_timeout=60)


def test_sandbox_drops_blocked_extra_hosts_from_egress():
    with SimulatedTarget() as t:
        res = run_sandboxed_scan({"target_url": t.url, "allowed_domains": [t.netloc, "169.254.169.254:80"],
                                  "profile": "quick", "delay": 0}, wall_timeout=120)
    assert "169.254.169.254" not in res["sandbox"]["egress_ips"]
    assert "127.0.0.1" in res["sandbox"]["egress_ips"]


def test_sandbox_block_private():
    with SimulatedTarget() as t, pytest.raises(SandboxError, match="network policy"):
        run_sandboxed_scan({"target_url": t.url, "allowed_domains": [t.netloc], "profile": "quick",
                            "delay": 0}, wall_timeout=60, block_private=True)


def test_cli_refuses_metadata_target(capsys):
    from scopeguard import cli

    assert cli.main(["--url", "http://169.254.169.254/latest/meta-data/", "--i-have-authorization"]) == 5
    assert "Refusing to scan 169.254.169.254" in capsys.readouterr().out


def test_dast_passes_the_block_private_setting(monkeypatch):
    from pentest_agent.tools import dast_native

    seen = {}

    def fake(scan_args, **kw):
        seen.update(kw)
        return {"findings": [], "red_flags": [], "attack_summary": {}, "endpoints": [],
                "requests_made": 0, "crawled_pages": []}

    monkeypatch.setattr(dast_native, "run_sandboxed_scan", fake)
    monkeypatch.setattr(settings, "block_private_targets", True)
    dast_native.execute_native_dast("http://127.0.0.1:1/", "quick", ["127.0.0.1:1"])
    assert seen["block_private"] is True


def test_guardrail_refuses_unresolvable_target():
    with pytest.raises(GuardrailViolation, match="Cannot resolve nothing.invalid"):
        pre_run_guardrail(_target("http://nothing.invalid/"))
