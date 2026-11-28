"""Chat requests fit the model: chunk (10% overlap), summarize recursively, extract; 413 retried smaller."""
from __future__ import annotations

import asyncio
import itertools

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

import context_fit


class TooLarge(Exception):
    status_code = 413

    def __init__(self, limit=8000, requested=9683):
        super().__init__(f"Error code: 413 - Request too large for model: Limit {limit}, Requested {requested}")


def _report(n=600) -> str:
    return "\n".join(f"[S{i}] HIGH: Reflected XSS in q{i} (CWE-79, /search?q{i}=1) scan mcp-1a2b3c" for i in range(1, n))


def test_chunks_overlap_by_ten_percent():
    chunks = context_fit.split_chunks(_report(), 8000)
    assert len(chunks) > 2 and all(len(c) <= 8000 for c in chunks)
    for a, b in itertools.pairwise(chunks):
        first = b.split("\n")[0]
        assert first in a and 0.07 * 8000 <= len(a[a.index(first):]) <= 0.10 * 8000


def test_chunk_size_is_the_scanners_setting():
    class S:
        def __init__(self):
            self.env = {"PROBE_CONTEXT_CHUNK_CHARS": "6000"}

    assert context_fit.chunk_chars(S()) == 6000 and context_fit.chunk_chars(None) == 8000


def test_summarized_recursively_until_it_fits_without_a_model():
    text = _report(3000)
    out = asyncio.run(context_fit.fit_text(text, 4000))
    assert len(out) <= 4000 and "[S1]" in out


def test_extract_drops_invented_ids_and_restores_dropped_ones():
    chunk = "[S1] HIGH: XSS\n[S2] HIGH: XSS\nscan mcp-abcd1234"
    out = context_fit.extract(chunk, "XSS twice [S1] [S99]")
    assert "[S99]" not in out and "[S2]" in out and "mcp-abcd1234" in out


def test_413_shrinks_tool_results_and_retries():
    seen = []

    class Request:
        def __init__(self, messages):
            self.messages = messages
            self.system_message = None

        def override(self, messages):
            return Request(messages)

    async def handler(req):
        seen.append(sum(len(str(m.content)) for m in req.messages))
        if len(seen) == 1:
            raise TooLarge(8000, 12000)
        return AIMessage(content="ok")

    mw = context_fit.fit_model_call_middleware(None, max_tokens=3000)
    req = Request([HumanMessage(content="scan it"), AIMessage(content="", tool_calls=[
        {"name": "get_scan", "args": {}, "id": "c1"}]), ToolMessage(content=_report(800), tool_call_id="c1")])
    out = asyncio.run(mw.awrap_model_call(req, handler))
    assert out.content == "ok" and len(seen) == 2 and seen[1] < seen[0]


def test_413_gives_up_after_three_tries():
    calls = []

    class Request:
        def __init__(self):
            self.messages = [HumanMessage(content="x" * 20000)]
            self.system_message = None

        def override(self, messages):
            return self

    async def handler(_req):
        calls.append(1)
        raise TooLarge()

    mw = context_fit.fit_model_call_middleware(None)
    try:
        asyncio.run(mw.awrap_model_call(Request(), handler))
    except TooLarge:
        pass
    assert len(calls) == context_fit.MAX_FIT_TRIES
