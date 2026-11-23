from __future__ import annotations

from langgraph.checkpoint.sqlite import SqliteSaver

from pentest_agent.checkpointer import (
    get_main_checkpointer_sync,
    get_subagent_checkpointer_sync,
    subagent_thread_id,
)


def test_subagent_thread_id_format():
    assert subagent_thread_id("session-123", "codegen_planner") == "session-123::codegen_planner"
    assert subagent_thread_id("s", "sast_subagent") == "s::sast_subagent"


def test_main_checkpointer_is_sqlite_saver():
    saver = get_main_checkpointer_sync()
    assert isinstance(saver, SqliteSaver)


def test_subagent_checkpointer_is_separate_db_from_main():
    from pentest_agent.config import settings

    assert settings.checkpoint_db_path != settings.subagent_checkpoint_db_path
    saver = get_subagent_checkpointer_sync()
    assert isinstance(saver, SqliteSaver)


def test_checkpoints_are_encrypted_at_rest(tmp_path, monkeypatch):
    """With CHECKPOINT_ENCRYPTION_KEY, state and human-in-the-loop resume values
    (e.g. an MFA code) never reach the SQLite file in plaintext."""
    import sqlite3
    from typing import TypedDict

    from langgraph.graph import END, START, StateGraph
    from langgraph.types import Command, interrupt

    from pentest_agent import checkpointer as cp
    from pentest_agent.config import settings

    class S(TypedDict, total=False):
        secret: str
        answer: dict

    def ask(state: S):
        return {"answer": interrupt({"kind": "mfa"})}

    def build(saver):
        g = StateGraph(S)
        g.add_node("ask", ask)
        g.add_edge(START, "ask")
        g.add_edge("ask", END)
        return g.compile(checkpointer=saver)

    db = tmp_path / "cp.sqlite"
    monkeypatch.setattr(settings, "checkpoint_db_path", str(db))
    monkeypatch.setattr(settings, "checkpoint_encryption_key", "test-only-key")
    cfg = {"configurable": {"thread_id": "t1"}}
    with cp.main_checkpointer_ctx() as saver:
        app = build(saver)
        app.invoke({"secret": "SESSION-COOKIE-XYZ"}, cfg)
        done = app.invoke(Command(resume={"code": "987654"}), cfg)
    assert done == {"secret": "SESSION-COOKIE-XYZ", "answer": {"code": "987654"}}
    raw = db.read_bytes() + b"".join(p.read_bytes() for p in tmp_path.glob("cp.sqlite-*"))
    assert b"SESSION-COOKIE-XYZ" not in raw and b"987654" not in raw
    conn = sqlite3.connect(db)
    types = {r[0] for r in conn.execute("select type from checkpoints")}
    conn.close()
    assert types and all("+aes" in t for t in types)
    with cp.main_checkpointer_ctx() as saver:  # same key: state reads back
        assert build(saver).get_state(cfg).values["secret"] == "SESSION-COOKIE-XYZ"


def test_without_a_key_checkpoints_stay_plaintext(monkeypatch):
    from pentest_agent import checkpointer as cp
    from pentest_agent.config import settings

    monkeypatch.setattr(settings, "checkpoint_encryption_key", "")
    assert cp.make_serde() is None
