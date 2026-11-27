"""Who may read a saved report (pentest_agent/report_access.py)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pentest_agent import graph, rbac, report_access
from pentest_agent.config import settings
from scopeguard import audit

ALICE = rbac.Principal(sub="alice", roles=["scanner"])
BOB = rbac.Principal(sub="bob", roles=["scanner"])
VIEWER = rbac.Principal(sub="alice", roles=["viewer"])
ADMIN = rbac.Principal(sub="root", roles=["admin"])


@pytest.fixture(autouse=True)
def _fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path / "reports"))
    monkeypatch.setattr(settings, "audit_log_path", str(tmp_path / "audit.jsonl"))
    report_access.clear_cache()
    yield
    report_access.clear_cache()


def _folder(name: str) -> Path:
    folder = Path(settings.reports_dir) / name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "report.md").write_text("# r", encoding="utf-8")
    return folder


def test_owner_reads_others_do_not_admin_reads_all():
    folder = _folder("s1")
    report_access.write_owner(folder, ALICE.state_dict())
    assert report_access.can_read(ALICE, folder) and report_access.can_read(VIEWER, folder)
    assert not report_access.can_read(BOB, folder)
    assert report_access.can_read(ADMIN, folder)
    assert rbac.Permission.REPORTS_ANY not in rbac.permissions_for(["viewer", "scanner"])


def test_report_without_known_owner_is_admin_only():
    folder = _folder("legacy")
    assert not report_access.can_read(ALICE, folder)
    assert report_access.can_read(ADMIN, folder)


def test_legacy_report_owner_comes_from_the_first_audit_record():
    folder = _folder("old")
    for sub in ("alice", "bob"):  # a later record (e.g. a cache hit) never moves the owner
        audit.append({"event": "scan", "actor": {"sub": sub}, "report": {"folder": "old", "files": {}}},
                     settings.audit_log_path)
    assert report_access.report_owner(folder) == "alice"
    assert report_access.can_read(ALICE, folder) and not report_access.can_read(BOB, folder)


def test_write_owner_is_idempotent_and_never_transfers():
    folder = _folder("s2")
    first = report_access.write_owner(folder, ALICE.state_dict())
    before = first.read_bytes()
    assert report_access.write_owner(folder, ALICE.state_dict()) == first  # re-run (resume)
    assert first.read_bytes() == before
    with pytest.raises(PermissionError):
        report_access.write_owner(folder, BOB.state_dict())
    assert json.loads(first.read_text(encoding="utf-8"))["sub"] == "alice"
    assert report_access.write_owner(folder, None) is None


def test_broken_or_oversized_owner_file_counts_as_unknown():
    folder = _folder("s3")
    (folder / "owner.json").write_text("{not json", encoding="utf-8")
    assert report_access.report_owner(folder) is None
    (folder / "owner.json").write_text(json.dumps({"sub": "alice", "pad": "x" * 5000}), encoding="utf-8")
    assert report_access.report_owner(folder) is None


def test_report_node_refuses_to_overwrite_another_users_report():
    folder = _folder("taken")
    report_access.write_owner(folder, ALICE.state_dict())
    cmd = graph.report_node({"session_id": "taken", "principal": BOB.state_dict(), "_final_report_json": "{}"})
    assert cmd.goto == "audit" and cmd.update["phase"] == "report_refused"
    assert (folder / "report.md").read_text(encoding="utf-8") == "# r"  # untouched
