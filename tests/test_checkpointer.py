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
