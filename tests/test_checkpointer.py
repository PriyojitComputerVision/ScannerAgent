"""LangGraph checkpoints in SQLite, async only: connection setup for several concurrent writers,
the separate sub-agent database, encryption at rest."""
from __future__ import annotations

import asyncio
import sqlite3
from typing import TypedDict

from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

from pentest_agent import checkpointer as cp
from pentest_agent.config import settings


class S(TypedDict, total=False):
    secret: str
    answer: dict
    n: int


def _ask(state: S):
    return {"answer": interrupt({"kind": "mfa"})}


def _hitl_graph(saver):
    g = StateGraph(S)
    g.add_node("ask", _ask)
    g.add_edge(START, "ask")
    g.add_edge("ask", END)
    return g.compile(checkpointer=saver)


def _counter_graph(saver, steps: int):
    """A graph that writes one checkpoint per step."""
    g = StateGraph(S)
    g.add_node("step", lambda s: {"n": s.get("n", 0) + 1})
    g.add_edge(START, "step")
    g.add_conditional_edges("step", lambda s: END if s["n"] >= steps else "step")
    return g.compile(checkpointer=saver)


def test_subagent_thread_id_format():
    assert cp.subagent_thread_id("session-123", "codegen_planner") == "session-123::codegen_planner"
    assert cp.subagent_thread_id("s", "sast_subagent") == "s::sast_subagent"


async def test_connection_is_set_up_for_concurrent_writers(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "checkpoint_busy_timeout_seconds", 12.5)
    db = tmp_path / "nested" / "main.sqlite"  # the folder is created
    async with cp.async_main_checkpointer(str(db)) as saver:
        assert isinstance(saver, AsyncSqliteSaver)
        pragmas = {}
        for name in ("journal_mode", "busy_timeout", "synchronous", "foreign_keys"):
            async with saver.conn.execute(f"PRAGMA {name}") as cur:
                pragmas[name] = (await cur.fetchone())[0]
        async with saver.conn.execute("select name from sqlite_master where type='table'") as cur:
            tables = {r[0] for r in await cur.fetchall()}
    assert pragmas == {"journal_mode": "wal", "busy_timeout": 12500, "synchronous": 1, "foreign_keys": 1}
    assert {"checkpoints", "writes"} <= tables  # set up before the first write
    assert db.exists()


async def test_subagent_checkpointer_is_a_separate_async_db(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "subagent_checkpoint_db_path", str(tmp_path / "sub.sqlite"))
    assert settings.checkpoint_db_path != settings.subagent_checkpoint_db_path
    async with cp.async_subagent_checkpointer() as saver:
        assert isinstance(saver, AsyncSqliteSaver)
        out = await _counter_graph(saver, 3).ainvoke({"n": 0}, {"configurable": {"thread_id": "s::sast"}})
    assert out["n"] == 3 and (tmp_path / "sub.sqlite").exists()


async def test_two_connections_write_the_same_db_concurrently(tmp_path):
    """The WebSocket server and an MCP / A2A scan each hold a connection to one checkpoint file:
    many scans on both, at the same time, without "database is locked"."""
    db = str(tmp_path / "main.sqlite")
    async with cp.async_main_checkpointer(db) as server, cp.async_main_checkpointer(db) as mcp_scan:
        runs = [_counter_graph(saver, 25).ainvoke({"n": 0}, {"configurable": {"thread_id": f"{name}-{i}"}})
                for name, saver in (("ws", server), ("mcp", mcp_scan)) for i in range(4)]
        results = await asyncio.gather(*runs)
        assert [r["n"] for r in results] == [25] * 8
        # every run's final state is readable from the other connection too
        state = await _counter_graph(mcp_scan, 25).aget_state({"configurable": {"thread_id": "ws-3"}})
        assert state.values["n"] == 25


async def test_checkpoints_are_encrypted_at_rest(tmp_path, monkeypatch):
    """With CHECKPOINT_ENCRYPTION_KEY, state and human-in-the-loop resume values
    (e.g. an MFA code) never reach the SQLite file in plaintext."""
    db = tmp_path / "cp.sqlite"
    monkeypatch.setattr(settings, "checkpoint_encryption_key", "test-only-key")
    cfg = {"configurable": {"thread_id": "t1"}}
    async with cp.async_main_checkpointer(str(db)) as saver:
        app = _hitl_graph(saver)
        await app.ainvoke({"secret": "SESSION-COOKIE-XYZ"}, cfg)
        done = await app.ainvoke(Command(resume={"code": "987654"}), cfg)
    assert done == {"secret": "SESSION-COOKIE-XYZ", "answer": {"code": "987654"}}
    raw = db.read_bytes() + b"".join(p.read_bytes() for p in tmp_path.glob("cp.sqlite-*"))
    assert b"SESSION-COOKIE-XYZ" not in raw and b"987654" not in raw
    conn = sqlite3.connect(db)
    types = {r[0] for r in conn.execute("select type from checkpoints")}
    conn.close()
    assert types and all("+aes" in t for t in types)
    async with cp.async_main_checkpointer(str(db)) as saver:  # same key: state reads back
        assert (await _hitl_graph(saver).aget_state(cfg)).values["secret"] == "SESSION-COOKIE-XYZ"


def test_without_a_key_checkpoints_stay_plaintext(monkeypatch):
    monkeypatch.setattr(settings, "checkpoint_encryption_key", "")
    assert cp.make_serde() is None


# ---------------------------------------------------------------- retention (CHECKPOINT_RETENTION_HOURS)
def test_checkpoint_time_reads_the_uuid6_id():
    import time as _time

    from langgraph.checkpoint.base.id import uuid6

    assert abs(cp.checkpoint_time(str(uuid6())) - _time.time()) < 5
    assert cp.checkpoint_time("not-a-uuid") is None
    assert cp.checkpoint_time("12345678-1234-4234-8234-123456789abc") is None  # v4: no time in it


async def test_old_threads_are_deleted_and_the_file_compacted(tmp_path, monkeypatch):
    db = str(tmp_path / "main.sqlite")
    monkeypatch.setattr(settings, "checkpoint_db_path", db)
    monkeypatch.setattr(settings, "subagent_checkpoint_db_path", str(tmp_path / "absent.sqlite"))
    monkeypatch.setattr(settings, "checkpoint_retention_hours", 24)
    async with cp.async_main_checkpointer(db) as saver:
        for thread in ("old-1", "old-2", "running", "fresh"):
            await _counter_graph(saver, 40).ainvoke({"n": 0, "secret": "x" * 2000},
                                                    {"configurable": {"thread_id": thread}})
        # Two days later: every thread is older than 24 h, except "fresh", which ran just now.
        later = cp.time.time() + 2 * 86400
        monkeypatch.setattr(cp.time, "time", lambda: later)
        monkeypatch.setattr(cp, "checkpoint_time",
                            lambda cid, real=cp.checkpoint_time: real(cid) + (2 * 86400 if fresh_ids.get(cid) else 0))
        async with saver.conn.execute("SELECT checkpoint_id FROM checkpoints WHERE thread_id='fresh'") as cur:
            fresh_ids = {r[0]: True for r in await cur.fetchall()}
        result = await cp.cleanup_checkpoints(saver, protect=frozenset({"running"}), force=True)
        async with saver.conn.execute("SELECT DISTINCT thread_id FROM checkpoints") as cur:
            left = {r[0] for r in await cur.fetchall()}
        async with saver.conn.execute("SELECT COUNT(*) FROM writes WHERE thread_id LIKE 'old-%'") as cur:
            writes_left = (await cur.fetchone())[0]
    assert left == {"running", "fresh"} and writes_left == 0  # protected + recent stay
    assert result["threads"] == 2 and result["bytes_after"] < result["bytes_before"]  # compacted


async def test_retention_zero_keeps_everything_and_cleanup_is_throttled(tmp_path, monkeypatch):
    db = str(tmp_path / "main.sqlite")
    monkeypatch.setattr(settings, "checkpoint_db_path", db)
    async with cp.async_main_checkpointer(db) as saver:
        await _counter_graph(saver, 3).ainvoke({"n": 0}, {"configurable": {"thread_id": "t"}})
        assert await cp.prune_old_checkpoints(saver, 0) == 0
        monkeypatch.setattr(settings, "checkpoint_retention_hours", 0)
        assert await cp.cleanup_checkpoints(saver, force=True) is None
        monkeypatch.setattr(settings, "checkpoint_retention_hours", 24)
        monkeypatch.setattr(cp, "_last_cleanup", {})
        assert await cp.cleanup_checkpoints(saver) is not None   # first round runs
        assert await cp.cleanup_checkpoints(saver) is None       # within the interval: skipped


def test_old_codecheck_files_are_removed(tmp_path, monkeypatch):
    import os
    import time as _time

    monkeypatch.setattr(settings, "checkpoint_db_path", str(tmp_path / "main.sqlite"))
    folder = tmp_path / "codecheck"
    folder.mkdir()
    old, new = folder / "old.json", folder / "new.json"
    old.write_text("{}"), new.write_text("{}")
    os.utime(old, (_time.time() - 3 * 86400,) * 2)
    assert cp.prune_codecheck_files(24) == 1
    assert not old.exists() and new.exists()
    assert cp.prune_codecheck_files(0) == 0
