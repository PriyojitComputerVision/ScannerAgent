"""Draw the agent graph the way LangGraph does: get_graph(xray=True).draw_mermaid().

    uv run python scripts/draw_graph.py            # writes docs/agent-graph.mmd + docs/agent-tree.png

The Mermaid text comes straight from the compiled LangGraph (nodes, the SAST
subgraph, solid static edges, dashed Command routes from the nodes'
Command[Literal[...]] annotations). The PNG is rendered locally in a headless
Edge/Chrome with mermaid.js; LangGraph's draw_mermaid_png() would send the
graph to the external mermaid.ink service instead, so it is not used.
"""
from __future__ import annotations

import html
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")

from pentest_agent.graph import build_graph

MERMAID_JS = "https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.min.js"
BROWSERS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    "msedge", "google-chrome", "chromium", "chromium-browser",
]


def mermaid_text() -> str:
    return build_graph().get_graph(xray=True).draw_mermaid()


def _browser() -> str | None:
    for candidate in BROWSERS:
        path = candidate if Path(candidate).is_file() else shutil.which(candidate)
        if path:
            return path
    return None


def _page(mermaid: str) -> str:
    # useMaxWidth=false: the SVG keeps its natural size, so it can be measured.
    return f"""<!doctype html><html><head><meta charset="utf-8">
<style>html,body{{margin:0;background:#fff}} .mermaid{{margin:0;padding:{PADDING}px;display:inline-block}}</style>
<script src="{MERMAID_JS}"></script></head><body>
<pre class="mermaid">{html.escape(mermaid)}</pre>
<script>mermaid.initialize({{startOnLoad: true, theme: "default", flowchart: {{useMaxWidth: false}}}});</script>
</body></html>"""


PADDING = 24


def _svg_size(browser: str, page_uri: str) -> tuple[int, int] | None:
    """Rendered diagram size in CSS pixels (first headless pass: dump the DOM)."""
    dom = subprocess.run([browser, "--headless=new", "--disable-gpu", "--virtual-time-budget=8000",
                          "--dump-dom", page_uri], check=False, capture_output=True, text=True,
                         timeout=120).stdout
    match = re.search(r'<svg[^>]*viewBox="[\d.\-]+ [\d.\-]+ ([\d.]+) ([\d.]+)"', dom)
    if not match:
        return None
    return math.ceil(float(match.group(1))), math.ceil(float(match.group(2)))


def render_png(mermaid: str, out: Path) -> bool:
    browser = _browser()
    if not browser:
        print("No Edge/Chrome found: wrote the .mmd only (paste it into any Mermaid viewer).")
        return False
    with tempfile.TemporaryDirectory() as tmp:
        page_path = Path(tmp) / "graph.html"
        page_path.write_text(_page(mermaid), encoding="utf-8")
        size = _svg_size(browser, page_path.as_uri()) or (900, 1500)
        width, height = (dim + 2 * PADDING + 8 for dim in size)
        subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                        "--force-device-scale-factor=2", f"--window-size={width},{height}",
                        "--virtual-time-budget=8000", f"--screenshot={out}",
                        page_path.as_uri()], check=True, capture_output=True, timeout=120)
    return out.is_file()


def main() -> int:
    docs = ROOT / "docs"
    docs.mkdir(exist_ok=True)
    mermaid = mermaid_text()
    (docs / "agent-graph.mmd").write_text(mermaid, encoding="utf-8")
    print(f"wrote {docs / 'agent-graph.mmd'}")
    if render_png(mermaid, docs / "agent-tree.png"):
        print(f"wrote {docs / 'agent-tree.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
