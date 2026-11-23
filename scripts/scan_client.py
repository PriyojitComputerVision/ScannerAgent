"""Minimal authenticated scan client.

    uv run python scripts/scan_client.py https://your-site.example quick

Signs in with AUTH_CLIENT_ID / AUTH_CLIENT_SECRET from .env, sends the token on
the WebSocket, and adopts tokens the server renews during long scans. Only scan
sites you own or are authorized to test.
"""
import asyncio
import json
import sys
import time

import websockets

from pentest_agent.auth_client import TokenManager
from pentest_agent.config import settings

BASE = f"http://127.0.0.1:{settings.ws_port}"


async def main(url: str, profile: str) -> None:
    tm = TokenManager(BASE, settings.auth_client_id, settings.auth_client_secret)
    uri = f"ws://127.0.0.1:{settings.ws_port}/ws?session_id=scan-{int(time.time())}"
    token = tm.get_token()
    async with websockets.connect(uri, max_size=None) as ws:
        print("signed in with roles:", ", ".join(tm.roles))
        await ws.send(json.dumps({
            "access_token": token,            # token travels in the first JSON message
            "url": url,
            "profile": profile,
            "authorization_confirmed": True,  # only if you own or may test this site
            "additional_allowed_domains": [],
        }))
        async for raw in ws:
            m = json.loads(raw)
            if tm.observe_ws_message(m):
                print("token renewed by the server")
                continue
            print(m["type"], m.get("node", ""), m.get("data", {}).get("phase", ""))
            if m["type"] == "complete":
                print(m["report_url"])
                break
            if m["type"] == "error":
                print(m)
                break


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "https://example.com",
                     sys.argv[2] if len(sys.argv) > 2 else "quick"))
