"""Old and checkpoint-less report folders are deleted with the checkpoint cleanup, and audited."""
from __future__ import annotations

import os
import time

import pytest

from pentest_agent import audit_log, report_retention
from pentest_agent import checkpointer as cp
from pentest_agent.config import settings
from scopeguard import audit

HOUR = 3600


@pytest.fixture
def reports(tmp_path, monkeypatch):
    root = tmp_path / "reports"
    root.mkdir()
    monkeypatch.setattr(settings, "reports_dir", str(root))
    monkeypatch.setattr(settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    monkeypatch.setattr(settings, "audit_hmac_key", "k" * 32)
    return root


def _report(root, name: str, age_hours: float, *, audited: bool = True):
    folder = root / name
    folder.mkdir()
    for fn, body in (("report.md", f"# {name}\n"), ("report.json", "{}")):
        (folder / fn).write_text(body, encoding="utf-8")
    then = time.time() - age_hours * HOUR
    for path in (*folder.iterdir(), folder):
        os.utime(path, (then, then))
    if audited:  # the scan's own audit record, with the report hashes (as the graph's audit node writes)
        audit_log.write({"session_id": name, "outcome": "completed",
                         "report": {"folder": name, "files": {p.name: audit.file_sha256(p) for p in folder.iterdir()}}})
    return folder


def _verify():
    return audit.verify(settings.audit_log_path, settings.audit_hmac_key, settings.reports_dir)


def test_expired_reports_are_deleted_and_the_audit_still_verifies(reports):
    old, fresh = _report(reports, "old-1", 30), _report(reports, "fresh-1", 1)
    assert report_retention.prune_old_reports(24) == 1
    assert not old.exists() and fresh.exists()
    v = _verify()
    assert v["ok"], v["problems"]
    assert v["report_files_removed_by_retention"] == 2
    deletion = audit.read(settings.audit_log_path)[-1]
    assert deletion["event"] == "report.deleted" and deletion["session_id"] == "old-1"
    assert set(deletion["report.deleted"]["files"]) == {"report.md", "report.json"}
    assert deletion["report.deleted"]["why"] == "expired"


def test_a_report_deleted_by_hand_is_still_flagged(reports):
    import shutil

    shutil.rmtree(_report(reports, "gone", 1))
    v = _verify()
    assert not v["ok"] and any("gone/report" in p and "missing" in p for p in v["problems"])


def test_a_modified_report_is_flagged_even_if_listed_as_deleted(reports):
    folder = _report(reports, "x", 30)
    files = {p.name: audit.file_sha256(p) for p in folder.iterdir()}
    audit_log.write({"event": "report.deleted", "report.deleted": {"folder": "x", "files": files}})
    (folder / "report.md").write_text("changed", encoding="utf-8")  # still there, but altered
    assert any("was modified" in p for p in _verify()["problems"])


def test_reports_without_a_checkpoint_are_deleted_after_the_grace_period(reports):
    _report(reports, "live", 5)
    orphan = _report(reports, "orphan", 5)
    just_written = _report(reports, "brand-new", 0.1)
    assert report_retention.prune_old_reports(24, live_sessions={"live"}) == 1
    assert not orphan.exists() and (reports / "live").exists() and just_written.exists()
    assert audit.read(settings.audit_log_path)[-1]["report.deleted"]["why"] == "no_checkpoint"
    assert _verify()["ok"]


def test_unknown_checkpoints_only_use_age(reports):
    _report(reports, "a", 5)
    assert report_retention.prune_old_reports(24, live_sessions=None) == 0


def test_running_scans_hidden_entries_and_retention_zero_are_kept(reports):
    _report(reports, "running", 30)
    (reports / ".gitkeep").write_text("", encoding="utf-8")
    hidden = reports / ".cache"
    hidden.mkdir()
    os.utime(hidden, (0, 0))
    assert report_retention.prune_old_reports(24, protect=frozenset({"running"}), live_sessions=set()) == 0
    assert report_retention.prune_old_reports(0, live_sessions=set()) == 0
    assert (reports / "running").exists() and hidden.exists()


def test_a_report_is_kept_when_its_deletion_cannot_be_audited(reports, monkeypatch):
    folder = _report(reports, "old", 30)
    monkeypatch.setattr(audit_log, "write", lambda record: None)
    assert report_retention.prune_old_reports(24) == 0 and folder.exists()


def test_there_is_no_separate_report_retention_setting():
    assert not any("report_retention" in name for name in type(settings).model_fields)


async def test_cleanup_round_deletes_orphan_and_expired_reports(reports, tmp_path, monkeypatch):
    from langgraph.graph import END, START, StateGraph

    db = str(tmp_path / "main.sqlite")
    monkeypatch.setattr(settings, "checkpoint_db_path", db)
    monkeypatch.setattr(settings, "subagent_checkpoint_db_path", str(tmp_path / "absent.sqlite"))
    monkeypatch.setattr(settings, "checkpoint_retention_hours", 24)
    g = StateGraph(dict)
    g.add_node("n", lambda s: {"x": 1})
    g.add_edge(START, "n")
    g.add_edge("n", END)
    _report(reports, "has-checkpoint", 5)
    _report(reports, "no-checkpoint", 5)
    _report(reports, "too-old", 30)
    async with cp.async_main_checkpointer(db) as saver:
        await g.compile(checkpointer=saver).ainvoke({"x": 0}, {"configurable": {"thread_id": "has-checkpoint"}})
        result = await cp.cleanup_checkpoints(saver, force=True)
    assert result["reports"] == 2
    assert sorted(p.name for p in reports.iterdir()) == ["has-checkpoint"]
    assert _verify()["ok"]


async def test_retention_zero_keeps_every_report_too(reports, tmp_path, monkeypatch):
    db = str(tmp_path / "main.sqlite")
    monkeypatch.setattr(settings, "checkpoint_db_path", db)
    monkeypatch.setattr(settings, "checkpoint_retention_hours", 0)    # keep everything
    _report(reports, "too-old", 30 * 24)
    _report(reports, "no-checkpoint", 5)
    async with cp.async_main_checkpointer(db) as saver:
        assert await cp.cleanup_checkpoints(saver, force=True) is None
    assert sorted(p.name for p in reports.iterdir()) == ["no-checkpoint", "too-old"]
