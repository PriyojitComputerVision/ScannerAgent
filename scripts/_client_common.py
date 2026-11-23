"""Shared bits of the MCP / A2A test clients: paced event output, automatic
sign-in (a locally minted API JWT) and starting pentest-agent when needed."""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import textwrap
import time
import urllib.request
from pathlib import Path

import anyio

REPO = Path(__file__).resolve().parent.parent
os.chdir(REPO)  # .env, keys/ and data/ are resolved from the repo root

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
SEV_COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37"}
NODE_NOTES = {
    "validate": "Guardrails: authorization flag, RBAC, network policy, scope.",
    "recon": "Crawled in-scope pages; out-of-scope links recorded, never fetched.",
    "auth": "Login forms detected; signs in if credentials were given (server-side, secret never returned).",
    "auth_challenge": "SSO/MFA pause (not used by these integrations).",
    "sast": "JavaScript static analysis of the pages and scripts.",
    "sandbox_check": "Code check of page/script text in the sandbox (Docker or process).",
    "dast": "DAST engine in the sandboxed worker (GET/HEAD/OPTIONS/TRACE only).",
    "plan_probes": "Probe plan (LLM or built-in default; skipped for quick).",
    "run_probes": "Ran the whitelisted probes.",
    "aggregate": "Deduplicated findings and wrote the cited summary.",
    "summarize": "Executive summary (LLM if configured, else the built-in one).",
    "report": "Wrote report.md / .html / .json / .docx.",
    "audit": "Appended the hash-chained audit record.",
}


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def short(text, limit: int = 220) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Events:
    """Numbered, paced output: one event, then a pause."""

    def __init__(self, delay: float):
        self.delay, self.n, self.t0 = delay, 0, time.monotonic()

    async def emit(self, kind: str, title: str, detail=None) -> None:
        self.n += 1
        stamp = f"{time.monotonic() - self.t0:6.1f}s"
        print(f"\n{color(f'[{self.n:02d}]', '1;35')} {color(stamp, '2')} {color(kind.upper(), '1;34')}  {title}")
        if detail is not None:
            text = detail if isinstance(detail, str) else json.dumps(detail, indent=2, ensure_ascii=False)
            print(textwrap.indent(text, "      "))
        sys.stdout.flush()
        await anyio.sleep(self.delay)

    async def finding(self, i: int, total: int, f: dict) -> None:
        sev = str(f.get("severity"))
        await self.emit("finding", f"{i}/{total} {color(sev.upper(), SEV_COLORS.get(sev, '0'))}  {f.get('title')}",
                        f"url: {f.get('affected_url')}\ncwe: {f.get('cwe')}   confidence: {f.get('confidence')}"
                        f"\nfix: {short(f.get('recommendation'))}")


def allowlisted(target_url: str, allowed: list[str]) -> bool:
    """Same matching as the server: a bare host allows any port, host:port only that port."""
    from urllib.parse import urlparse

    p = urlparse(target_url)
    host, netloc = (p.hostname or "").lower(), p.netloc.lower()
    return netloc in allowed or host in allowed


def allowlist_hint(target_url: str, setting: str, started_here: bool) -> str:
    from urllib.parse import urlparse

    host = urlparse(target_url).hostname or target_url
    how = ("Add it to .env and restart pentest-agent:" if not started_here else "Add it to .env:")
    return (f"{how}\n  {setting}={host}\n"
            "Or stop the running pentest-agent (Ctrl+C) and run this script again: it then starts its "
            "own server with only this host allowlisted for the run.")


def mint_token(subject: str, roles: list[str]) -> str:
    """Automatic sign-in: an API access token signed with this machine's key
    (keys/, created on first use). Whoever can read the private key is the
    operator, so this is the same as `uv run pentest-auth token`."""
    from pentest_agent import api_auth

    if not api_auth.keys_present():
        api_auth.generate_keypair()
    return api_auth.issue_tokens(subject, roles).access_token


def free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _healthy(base: str) -> bool:
    try:
        with urllib.request.urlopen(f"{base}/healthz", timeout=2) as r:
            return r.status == 200
    except OSError:
        return False


@contextlib.contextmanager
def agent_server(base: str, port: int, env_extra: dict[str, str], autostart: bool = True):
    """Use the running pentest-agent at ``base``, or start one (headless) for this run.
    Yields (started_here, log_path)."""
    log_path = REPO / "data" / "logs" / "agent-server-for-clients.log"
    if _healthy(base) or not autostart:
        yield False, None
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "PYTHONIOENCODING": "utf-8", **env_extra}
    with log_path.open("w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            [sys.executable, "-m", "pentest_agent.main", "--no-browser", "--no-target", "--host", "127.0.0.1",
             "--port", str(port)], cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 120
            while not _healthy(base):
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise SystemExit(f"pentest-agent did not start; see {log_path}")
                time.sleep(0.5)
            yield True, log_path
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.kill()
