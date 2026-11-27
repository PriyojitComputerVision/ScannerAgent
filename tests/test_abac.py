"""ABAC on top of RBAC (pentest_agent/abac.py): per-subject attributes from ABAC_SUBJECTS_FILE."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pentest_agent import abac, api_auth, graph, rbac, report_access, scan_scope
from pentest_agent.config import settings
from pentest_agent.schemas import ScanScope, TargetInput

ALICE = rbac.Principal(sub="alice", roles=["admin"])
BOB = rbac.Principal(sub="bob", roles=["admin"])


@pytest.fixture(autouse=True)
def subjects_file(tmp_path, monkeypatch):
    path = tmp_path / "abac_subjects.json"
    monkeypatch.setattr(settings, "abac_subjects_file", str(path))
    monkeypatch.setattr(settings, "abac_enabled", True)
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path / "reports"))
    abac.clear_cache()
    report_access.clear_cache()
    yield path
    abac.clear_cache()


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")
    abac.clear_cache()


def _target(url="https://staging.team-a.dev/", **kw) -> TargetInput:
    return TargetInput.model_validate({"url": url, "authorization_confirmed": True, "session_id": "s1", **kw})


def _decide(principal=ALICE, **kw):
    args = {"via": "mcp", "hosts": ["https://staging.team-a.dev/"], "profile": "standard"} | kw
    return abac.decide_scan(principal, **args)


def test_no_file_means_rbac_alone():
    assert _decide().allowed
    assert abac.policy_view(ALICE) == {"enabled": True, "subject": "alice", "attributes": {}}


def test_each_rule_refuses_with_its_id(subjects_file):
    _write(subjects_file, {"subjects": {"alice": {
        "allowed_targets": ["staging.team-a.dev", "localhost:3000"], "allowed_profiles": ["quick", "standard"],
        "allowed_scan_scopes": ["website"], "allowed_via": ["mcp"], "allowed_credentials": ["staging"]}}})
    assert _decide().allowed
    assert _decide(hosts=["http://localhost:3000/"]).allowed
    cases = {
        "abac.via": {"via": "a2a"},
        "abac.target": {"hosts": ["https://prod.team-a.dev/"]},
        "abac.profile": {"profile": "aggressive"},
        "abac.scope": {"scan_scope": "code"},
        "abac.credentials": {"credentials": "prod-admin"},
    }
    for rule, kw in cases.items():
        d = _decide(**kw)
        assert not d.allowed and d.rule == rule, (rule, d)
    assert not _decide(hosts=["http://localhost:8080/"]).allowed  # host:port entry = that port only
    assert _decide(hosts=["https://anything.example/"], demo=True).allowed  # built-in demo target


def test_extra_allowed_domains_are_checked_too(subjects_file):
    _write(subjects_file, {"subjects": {"alice": {"allowed_targets": ["staging.team-a.dev"]}}})
    with pytest.raises(abac.Denied, match="cdn.other.dev"):
        abac.check_target(ALICE, _target(additional_allowed_domains=["cdn.other.dev"]), via="ws")


def test_default_entry_applies_to_subjects_without_their_own(subjects_file):
    _write(subjects_file, {"default": {"allowed_profiles": ["quick"]},
                           "subjects": {"alice": {"allowed_profiles": ["standard"]}}})
    assert _decide(ALICE).allowed
    assert _decide(BOB).rule == "abac.profile"
    assert _decide(BOB, profile="quick").allowed


def test_invalid_file_refuses_every_scan(subjects_file):
    subjects_file.write_text('{"subjects": {"alice": {"allowed_profiles": ["turbo"]}}}', encoding="utf-8")
    abac.clear_cache()
    d = _decide()
    assert not d.allowed and d.rule == "abac.config"
    assert scan_scope.allowed_scopes(ALICE) == []
    assert not abac.profile_allowed(ALICE, "quick")
    subjects_file.write_text("{not json", encoding="utf-8")
    abac.clear_cache()
    assert _decide().rule == "abac.config"
    _write(subjects_file, {"unknown_key": {}})
    assert _decide().rule == "abac.config"


def test_changes_apply_without_a_new_token(subjects_file):
    _write(subjects_file, {"subjects": {"alice": {"allowed_via": ["mcp"]}}})
    assert _decide().allowed
    _write(subjects_file, {"subjects": {"alice": {"allowed_via": ["ws"]}}})
    assert _decide().rule == "abac.via"


def test_abac_off_or_local_principal_adds_no_limits(subjects_file, monkeypatch):
    _write(subjects_file, {"default": {"allowed_via": []}})
    assert _decide().rule == "abac.via"
    assert abac.decide_scan(rbac.ANONYMOUS_ADMIN, via="ws", hosts=[], profile="quick").allowed
    monkeypatch.setattr(settings, "abac_enabled", False)
    assert _decide().allowed


def test_scope_narrowing_and_asked_scope(subjects_file):
    _write(subjects_file, {"subjects": {"alice": {"allowed_scan_scopes": ["website", "code"]}}})
    assert [s.value for s in scan_scope.allowed_scopes(ALICE)] == ["website", "code"]
    # asked at choose_scope: only allowed scopes are offered, so the request itself passes
    abac.check_target(ALICE, _target(ask_scan_scope=True), via="ws")
    _write(subjects_file, {"subjects": {"alice": {"allowed_scan_scopes": ["code"]}}})
    with pytest.raises(abac.Denied, match="website"):  # default scope of a plain URL scan
        abac.check_target(ALICE, _target(), via="ws")


def test_code_only_scan_touches_no_host(subjects_file):
    _write(subjects_file, {"subjects": {"alice": {"allowed_targets": []}}})
    assert abac.target_hosts(_target(scan_scope=ScanScope.CODE, upload_id="a" * 32)) == []
    with pytest.raises(abac.Denied):
        abac.check_target(ALICE, _target(), via="ws")


def test_graph_validate_rechecks_attributes(subjects_file):
    _write(subjects_file, {"subjects": {"alice": {"allowed_via": ["mcp"]}}})
    state = {"principal": ALICE.state_dict(), "client": {"via": "websocket"}}
    assert graph._rbac_check_scan(state, _target()).startswith("ABAC:")
    assert graph._rbac_check_scan({**state, "client": {"via": "mcp"}}, _target()) is None


def test_tenant_shares_reports_only_when_both_opt_in(subjects_file):
    folder = Path(settings.reports_dir) / "s-team"
    folder.mkdir(parents=True)
    report_access.write_owner(folder, {"sub": "alice"})
    carol = rbac.Principal(sub="carol", roles=["scanner"])
    _write(subjects_file, {"subjects": {"alice": {"tenant": "team-a", "share_reports_with_tenant": True},
                                        "carol": {"tenant": "team-a", "share_reports_with_tenant": True},
                                        "dave": {"tenant": "team-b", "share_reports_with_tenant": True}}})
    assert report_access.can_read(carol, folder)
    assert not report_access.can_read(rbac.Principal(sub="dave", roles=["scanner"]), folder)
    _write(subjects_file, {"subjects": {"alice": {"tenant": "team-a"},
                                        "carol": {"tenant": "team-a", "share_reports_with_tenant": True}}})
    assert not report_access.can_read(carol, folder)  # the owner did not opt in


def test_policy_view_and_narrowed_targets(subjects_file):
    _write(subjects_file, {"subjects": {"alice": {"allowed_targets": ["staging.team-a.dev"], "tenant": "team-a"}}})
    assert abac.narrow_targets(ALICE, ["staging.team-a.dev", "localhost:3000", "staging.team-a.dev:8443"]) == [
        "staging.team-a.dev", "staging.team-a.dev:8443"]
    view = abac.policy_view(ALICE)
    assert view["attributes"] == {"tenant": "team-a", "allowed_targets": ["staging.team-a.dev"]}


def test_cli_set_check_show_remove(subjects_file, capsys):
    assert api_auth.main(["attrs", "set", "team-a-ci", "--tenant", "team-a", "--allowed-targets",
                          "https://Staging.Team-A.dev/, localhost:3000", "--via", "mcp,a2a"]) == 0
    stored = json.loads(subjects_file.read_text(encoding="utf-8"))["subjects"]["team-a-ci"]
    assert stored == {"tenant": "team-a", "allowed_targets": ["staging.team-a.dev", "localhost:3000"],
                      "allowed_via": ["mcp", "a2a"], "share_reports_with_tenant": False}
    assert api_auth.main(["attrs", "check"]) == 0
    assert api_auth.main(["attrs", "set", "x", "--profiles", "turbo"]) == 1  # validated, not stored
    assert "x" not in json.loads(subjects_file.read_text(encoding="utf-8"))["subjects"]
    assert api_auth.main(["attrs", "remove", "team-a-ci"]) == 0
    subjects_file.write_text("{broken", encoding="utf-8")
    abac.clear_cache()
    assert api_auth.main(["attrs", "check"]) == 1
    capsys.readouterr()


def test_file_is_created_at_startup_with_no_limits_and_never_overwritten(subjects_file, monkeypatch):
    assert not subjects_file.exists()
    assert abac.ensure_file() == subjects_file
    assert json.loads(subjects_file.read_text(encoding="utf-8")) == abac.STARTER
    assert _decide().allowed  # no limits until entries are added
    _write(subjects_file, {"subjects": {"alice": {"allowed_via": ["ws"]}}})
    assert abac.ensure_file() is None
    assert "alice" in json.loads(subjects_file.read_text(encoding="utf-8"))["subjects"]
    subjects_file.unlink()
    monkeypatch.setattr(settings, "abac_enabled", False)
    assert abac.ensure_file() is None and not subjects_file.exists()


def test_file_is_created_when_the_settings_load(subjects_file, tmp_path, monkeypatch):
    """Any entry point (CLI, scripts, pentest-auth, servers) loads config first; ensure_dirs() then
    creates the no-limits file, so it exists from the start, also in a fresh keys/ folder."""
    fresh = tmp_path / "new-keys" / "abac_subjects.json"
    monkeypatch.setattr(settings, "abac_subjects_file", str(fresh))
    settings.ensure_dirs()
    assert json.loads(fresh.read_text(encoding="utf-8")) == abac.STARTER
    fresh.write_text('{"default": {}, "subjects": {"bob": {}}}', encoding="utf-8")
    settings.ensure_dirs()  # never overwrites
    assert "bob" in json.loads(fresh.read_text(encoding="utf-8"))["subjects"]
    other = tmp_path / "import-keys" / "abac_subjects.json"
    src = str(Path(__file__).resolve().parents[1] / "src")
    env = {**os.environ, "ABAC_SUBJECTS_FILE": str(other), "PYTHONPATH": src}
    subprocess.run([sys.executable, "-c", "import pentest_agent.config"], env=env, check=True, timeout=120)
    assert json.loads(other.read_text(encoding="utf-8")) == abac.STARTER


def test_defaults_hold_data_and_change_nothing(subjects_file):
    """The starter spells out every attribute and the repo's own subjects; nothing is refused."""
    data = abac.STARTER
    assert set(data["default"]["allowed_via"]) == set(abac.VIA)
    assert set(data["default"]["allowed_profiles"]) == set(abac.PROFILES)
    assert set(data["default"]["allowed_scan_scopes"]) == set(abac.SCOPES)
    assert {"mcp", "mcp-chatbot", "mcp-test-client", "a2a-test-client", "demo-console"} <= set(data["subjects"])
    abac.AttributesFile.model_validate(data)  # a valid attributes file
    abac.ensure_file()
    for via in abac.VIA:  # any other subject: every entry point, profile and scope
        assert _decide(via=via, profile="auth_deep").allowed
    mcp = rbac.Principal(sub="mcp", roles=["admin"])
    assert _decide(mcp, via="mcp").allowed and not _decide(mcp, via="a2a").allowed


@pytest.mark.parametrize("content", ["", "  \n", "{}", '{"default": {}}', '{"default": {}, "subjects": {}}',
                                     '{"default": null, "subjects": {}}'])
def test_an_empty_file_is_filled_with_the_defaults_at_start(subjects_file, content):
    subjects_file.write_text(content, encoding="utf-8")
    assert abac.ensure_file() == subjects_file
    assert json.loads(subjects_file.read_text(encoding="utf-8")) == abac.STARTER


@pytest.mark.parametrize("content", ['{"subjects": {"bob": {}}}', '{"default": {"tenant": "x"}}', "{broken"])
def test_a_file_with_data_or_an_invalid_one_is_never_touched(subjects_file, content):
    subjects_file.write_text(content, encoding="utf-8")
    assert abac.ensure_file() is None
    assert subjects_file.read_text(encoding="utf-8") == content


def test_a_relative_path_is_the_one_file_under_the_repo_root(monkeypatch, tmp_path):
    from pentest_agent import config

    monkeypatch.setattr(settings, "abac_subjects_file", "./keys/abac_subjects.json")
    monkeypatch.chdir(tmp_path)  # started from another folder: still the repo's file
    assert abac.subjects_file() == (config.REPO_ROOT / "keys" / "abac_subjects.json").resolve()
