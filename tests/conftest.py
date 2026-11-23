"""Pytest bootstrap.

Everything in this module's top level runs before pytest collects any test
module, which is what lets us point `pentest_agent.config.settings` at a
throwaway temp directory and a dummy Groq key *before* `pentest_agent.config`
(a module-level singleton) gets imported anywhere. No test in this suite
makes a real network call, hits a real Groq/LangSmith endpoint, or needs a
running Docker daemon -- external interactions are monkeypatched or the
underlying pure-logic helper is tested directly instead of the tool wrapper.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP_ROOT = Path(tempfile.mkdtemp(prefix="pentest-agent-test-"))

os.environ.setdefault("GROQ_API_KEY", "test-key-not-a-real-credential")
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ["LANGSMITH_TRACING"] = "false"
os.environ["LANGSMITH_API_KEY"] = ""
os.environ.setdefault("CHECKPOINT_DB_PATH", str(_TMP_ROOT / "checkpoints" / "main.sqlite"))
os.environ.setdefault("SUBAGENT_CHECKPOINT_DB_PATH", str(_TMP_ROOT / "checkpoints" / "subagents.sqlite"))
os.environ.setdefault("REPORTS_DIR", str(_TMP_ROOT / "reports"))
os.environ.setdefault("LOG_FILE", str(_TMP_ROOT / "logs" / "pentest-agent.log"))
# API auth is tested explicitly in test_api_auth.py; other tests run without it.
os.environ["AUTH_ENABLED"] = "false"
os.environ.setdefault("JWT_PRIVATE_KEY_PATH", str(_TMP_ROOT / "keys" / "jwt_private.pem"))
os.environ.setdefault("JWT_PUBLIC_KEY_PATH", str(_TMP_ROOT / "keys" / "jwt_public.pem"))
os.environ.setdefault("AUTH_CLIENTS_FILE", str(_TMP_ROOT / "keys" / "clients.json"))
os.environ["AUTH_CLIENT_SECRET"] = ""
os.environ.setdefault("SQUID_CONF_PATH", str(_TMP_ROOT / "squid" / "squid.conf"))
os.environ.setdefault("SQUID_ACL_TARGET_FILE", str(_TMP_ROOT / "squid" / "allowed_target.acl"))

# The real prompts/ folder is gitignored; tests use stub prompts so they pass on
# any checkout. GOLDEN_LIVE=1 (live LLM judge) uses the real ./prompts instead.
if not os.environ.get("GOLDEN_LIVE"):
    _PROMPTS = _TMP_ROOT / "prompts"
    _PROMPTS.mkdir()
    for _name in ("run_summary", "executive_summary", "probe_plan_system", "golden_judge"):
        (_PROMPTS / f"{_name}.md").write_text(f"stub {_name} prompt", encoding="utf-8")
    (_PROMPTS / "content_injection_reminder.md").write_text(
        "stub reminder {{start}} {{end}}", encoding="utf-8")
    os.environ.setdefault("PROMPTS_DIR", str(_PROMPTS))

import pytest  # noqa: E402


@pytest.fixture
def valid_target_dict() -> dict:
    """Minimal, authorized, schema-valid TargetInput payload."""
    return {
        "url": "https://example.com",
        "session_id": "test-session-1",
        "authorization_confirmed": True,
        "profile": "quick",
    }


@pytest.fixture
def tmp_data_root(tmp_path) -> Path:
    return tmp_path


@pytest.fixture(autouse=True)
def _offline_dns(monkeypatch):
    """The network policy resolves host names (scopeguard.netpolicy.resolve).
    Tests make no real DNS lookups: localhost is 127.0.0.1, names under the
    reserved .invalid TLD do not resolve, and any other name resolves to a
    public documentation-style address, unless a test patches ``resolve``."""
    import socket

    from scopeguard import netpolicy

    def fake_resolve(host, port=None):
        name = str(host).lower().rstrip(".")
        if name == "localhost":
            return ["127.0.0.1"]
        if name.endswith(".invalid"):
            raise socket.gaierror(f"no DNS in tests: {host}")
        return ["93.184.215.14"]

    monkeypatch.setattr(netpolicy, "resolve", fake_resolve)


@pytest.fixture(autouse=True)
def _no_docker_sweep(monkeypatch):
    """The server's startup sweep for leftover sandbox containers must not
    call a real Docker daemon from tests."""
    from scopeguard import container

    monkeypatch.setattr(container, "remove_leftover_containers", lambda *a, **k: [])


@pytest.fixture(autouse=True)
def _reset_backend_rate_limits():
    """Each test starts with fresh per-client backend limits (all TestClient
    requests share the 'testclient' key)."""
    from pentest_agent import llm, websocket_server

    websocket_server.http_limiter.reset()
    websocket_server.ws_queue.reset()
    websocket_server.http_queue.reset()
    llm.reset_rate_limit_cooldown()


@pytest.fixture(autouse=True)
def _clear_ttl_caches():
    """No cached LLM answer, probe result or scan leaks between tests."""
    from pentest_agent import ttl_cache

    ttl_cache.clear_all()
    yield
    ttl_cache.clear_all()
