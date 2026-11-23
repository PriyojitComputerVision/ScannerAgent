"""Full-pipeline simulation: LangGraph agent + WebSocket server + vulnerable local target.

Fully offline: no Groq key, no ZAP, no Java, no Docker. Run with:
    uv run python scripts/simulate_full.py
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websockets

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from pentest_agent.auth_client import TokenManager
from scopeguard.simulated_target import SimulatedTarget  # noqa: E402

WS_PORT = int(os.getenv("SIM_WS_PORT", "8765"))


def _wait_healthy(timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{WS_PORT}/healthz", timeout=2) as r:
                if json.load(r).get("graph_initialized"):
                    return
        except Exception:
            time.sleep(0.5)
    raise SystemExit("agent server did not become healthy")


async def _run(target_url: str, tm: TokenManager) -> dict:
    uri = f"ws://127.0.0.1:{WS_PORT}/ws?session_id=sim-{int(time.time())}"
    async with websockets.connect(uri, max_size=None, additional_headers=tm.auth_headers()) as ws:
        await ws.send(json.dumps({"url": target_url, "profile": "standard",
                                  "authorization_confirmed": True,
                                  "notes": "built-in simulated target"}))
        async for raw in ws:
            msg = json.loads(raw)
            if tm.observe_ws_message(msg):
                continue
            if msg["type"] == "phase_update":
                print(f"  node={msg['node']:<15} phase={msg['data'].get('phase', '')}")
            elif msg["type"] == "complete":
                return msg
            elif msg["type"] == "error":
                raise SystemExit(f"ERROR: {msg}")
    raise SystemExit("socket closed before completion")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="pentest-sim-")
    # Auth is on, with throwaway keys and credentials, so the full JWT + RBAC flow runs too.
    secret = secrets.token_urlsafe(32)
    env = {**os.environ, "GROQ_API_KEY": "", "WS_HOST": "127.0.0.1", "WS_PORT": str(WS_PORT),
           "CHECKPOINT_DB_PATH": f"{tmp}/main.sqlite", "SUBAGENT_CHECKPOINT_DB_PATH": f"{tmp}/sub.sqlite",
           "REPORTS_DIR": str(ROOT / "data" / "reports"), "LANGCHAIN_TRACING_V2": "false",
           "AUTH_ENABLED": "true", "JWT_PRIVATE_KEY_PATH": f"{tmp}/keys/jwt_private.pem",
           "JWT_PUBLIC_KEY_PATH": f"{tmp}/keys/jwt_public.pem", "AUTH_CLIENTS_FILE": f"{tmp}/keys/clients.json",
           "AUTH_CLIENT_ID": "sim-client", "AUTH_CLIENT_SECRET": secret, "AUTH_CLIENT_ROLES": "scanner"}
    subprocess.run([sys.executable, "-m", "pentest_agent.api_auth", "keys"], env=env, cwd=ROOT,
                   check=True, stdout=subprocess.DEVNULL)
    server = subprocess.Popen([sys.executable, "-m", "pentest_agent.main"], env=env, cwd=ROOT)
    tm = TokenManager(f"http://127.0.0.1:{WS_PORT}", "sim-client", secret)
    try:
        with SimulatedTarget() as t:
            print(f"[sim] target {t.url}; waiting for agent on :{WS_PORT} ...")
            _wait_healthy()
            result = asyncio.run(_run(t.url, tm))
        print("\nREPORT:", result.get("report_url"), "|", result.get("report_docx_url"))
        md = result.get("report_md", "")
        ok = all(k in md for k in ("SQL injection", "Open redirect", "Path traversal"))
        print("SIMULATION PASSED" if ok else "SIMULATION FAILED: expected findings missing in report")
        return 0 if ok else 1
    finally:
        server.terminate()
        server.wait(10)


if __name__ == "__main__":
    sys.exit(main())
