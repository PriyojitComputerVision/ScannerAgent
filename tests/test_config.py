from __future__ import annotations

from pathlib import Path

from pentest_agent.config import settings


def test_settings_picked_up_test_env_overrides():
    # set via tests/conftest.py before any pentest_agent import happened
    assert settings.groq_api_key == "test-key-not-a-real-credential"
    assert "pentest-agent-test-" in settings.checkpoint_db_path


def test_ensure_dirs_creates_expected_directories():
    settings.ensure_dirs()
    assert Path(settings.checkpoint_db_path).parent.is_dir()
    assert Path(settings.subagent_checkpoint_db_path).parent.is_dir()
    assert Path(settings.reports_dir).is_dir()


def test_scan_limit_defaults_are_sane():
    assert settings.max_crawl_pages > 0
    assert settings.max_active_scan_minutes > 0
    assert settings.sandbox_exec_timeout_seconds > 0


def test_blank_values_from_env_example_fall_back_to_defaults(monkeypatch):
    from pentest_agent.config import Settings

    monkeypatch.setenv("GROQ_MODEL", "")
    monkeypatch.setenv("LANGSMITH_PROJECT", "  ")
    s = Settings(_env_file=None)
    assert s.groq_model == "llama-3.3-70b-versatile"
    assert s.langsmith_project == "pentest-agent"
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-20b")
    assert Settings(_env_file=None).groq_model == "openai/gpt-oss-20b"
