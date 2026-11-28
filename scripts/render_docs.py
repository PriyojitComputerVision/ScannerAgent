"""Render the hand-written docs diagrams to PNG, locally:

    uv run python scripts/render_docs.py            # docs/src/*.html -> docs/*.png
    uv run python scripts/render_docs.py mcp-tools  # only the named diagram(s)

Sources: docs/src/architecture.html -> docs/architecture.png and
docs/src/scan-story.html -> docs/scan-story.png, docs/src/mcp-tools.html ->
docs/mcp-tools.png. Edit the HTML, then re-run.
Rendering uses a local headless Edge/Chrome over the DevTools protocol; the
pages load no remote resources, so nothing leaves this machine. The agent
graph (docs/agent-tree.png) comes from scripts/draw_graph.py instead.
"""
from __future__ import annotations

import asyncio
import base64
import json
import shutil
import socket
import subprocess  # nosec B404 - fixed argument lists only, never a shell
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import websockets

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
PAGES = {"architecture.html": "architecture.png", "scan-story.html": "scan-story.png",
         "mcp-tools.html": "mcp-tools.png"}
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "msedge", "google-chrome", "chromium", "chromium-browser",
]
SCALE = 2  # device pixels per CSS pixel


def _browser() -> str:
    for b in BROWSERS:
        if Path(b).exists() or shutil.which(b):
            return b
    raise SystemExit("No Edge/Chrome found to render the docs.")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _render(ws_url: str, html: Path, png: Path) -> None:
    async with websockets.connect(ws_url, max_size=None) as ws:
        counter = 0

        async def cmd(method: str, **params):
            nonlocal counter
            counter += 1
            my_id = counter
            await ws.send(json.dumps({"id": my_id, "method": method, "params": params}))
            while True:
                msg = json.loads(await ws.recv())
                if msg.get("id") == my_id:
                    if "error" in msg:
                        raise RuntimeError(f"{method}: {msg['error']}")
                    return msg.get("result", {})

        await cmd("Page.enable")
        await cmd("Emulation.setDeviceMetricsOverride", width=1200, height=800, deviceScaleFactor=SCALE, mobile=False)
        await cmd("Page.navigate", url=html.resolve().as_uri())
        await asyncio.sleep(1.5)
        size = await cmd("Runtime.evaluate", returnByValue=True,
                         expression="[document.documentElement.scrollWidth, document.documentElement.scrollHeight]")
        width, height = size["result"]["value"]
        await cmd("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=SCALE,
                  mobile=False)
        await asyncio.sleep(0.5)
        shot = await cmd("Page.captureScreenshot", format="png", captureBeyondViewport=True)
        png.write_bytes(base64.b64decode(shot["data"]))
        print(f"wrote {png.relative_to(ROOT)} ({width * SCALE}x{height * SCALE})")


def main(argv: list[str] | None = None) -> int:
    names = sys.argv[1:] if argv is None else argv
    pages = {src: out for src, out in PAGES.items() if not names or Path(src).stem in names}
    if not pages:
        raise SystemExit(f"Unknown diagram(s) {names}; choose from: {', '.join(Path(p).stem for p in PAGES)}")
    port = _free_port()
    profile = tempfile.mkdtemp(prefix="render-docs-")
    proc = subprocess.Popen([_browser(), "--headless=new", "--disable-gpu", "--hide-scrollbars",  # nosec B603 - a local browser binary, fixed flags
                             f"--remote-debugging-port={port}", "--remote-allow-origins=*",
                             f"--user-data-dir={profile}", "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 20
        while True:
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json", timeout=2))  # nosec B310 - fixed http://127.0.0.1 URL
                page = next(t for t in tabs if t.get("type") == "page")
                break
            except Exception:  # noqa: BLE001 - browser still starting
                if time.time() > deadline:
                    raise SystemExit("The browser did not start.") from None
                time.sleep(0.3)
        for src, out in pages.items():
            asyncio.run(_render(page["webSocketDebuggerUrl"], DOCS / "src" / src, DOCS / out))
    finally:
        proc.terminate()
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(profile, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
