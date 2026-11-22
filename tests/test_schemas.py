from __future__ import annotations

import pytest
from pydantic import ValidationError

from pentest_agent.schemas import (
    AuthCredentials,
    Finding,
    FinalReport,
    OwaspCategory,
    ScanProfile,
    Severity,
    TargetInput,
)


def test_target_input_defaults(valid_target_dict):
    target = TargetInput.model_validate(valid_target_dict)
    assert target.profile == ScanProfile.QUICK
    assert target.authorization_confirmed is True
    assert target.jwt is None
    assert target.auth is None
    assert target.additional_allowed_domains == []


def test_target_input_default_profile_is_standard():
    target = TargetInput.model_validate(
        {"url": "https://example.com", "authorization_confirmed": True}
    )
    assert target.profile == ScanProfile.STANDARD
    # session_id auto-generated when omitted
    assert target.session_id


def test_target_input_rejects_unknown_fields(valid_target_dict):
    bad = dict(valid_target_dict)
    bad["totally_made_up_field"] = "x"
    with pytest.raises(ValidationError):
        TargetInput.model_validate(bad)


def test_target_input_rejects_empty_session_id(valid_target_dict):
    bad = dict(valid_target_dict)
    bad["session_id"] = "   "
    with pytest.raises(ValidationError):
        TargetInput.model_validate(bad)


def test_target_input_rejects_non_http_url(valid_target_dict):
    bad = dict(valid_target_dict)
    bad["url"] = "ftp://example.com/file"
    with pytest.raises(ValidationError):
        TargetInput.model_validate(bad)


def test_auth_credentials_optional_fields():
    creds = AuthCredentials(username="alice", password="hunter2")
    assert creds.username_field == "username"
    assert creds.password_field == "password"
    assert creds.extra_form_fields == {}


def test_finding_requires_valid_enum_values():
    f = Finding(
        source="unit-test",
        category=OwaspCategory.A03_INJECTION,
        severity=Severity.HIGH,
        title="Example SQLi",
        description="example",
    )
    assert f.id  # auto-generated short id
    with pytest.raises(ValidationError):
        Finding(
            source="unit-test",
            category="not-a-real-category",
            severity=Severity.HIGH,
            title="x",
            description="x",
        )


def test_final_report_severity_counts():
    findings = [
        Finding(source="s", category=OwaspCategory.OTHER, severity=Severity.HIGH, title="a", description="a"),
        Finding(source="s", category=OwaspCategory.OTHER, severity=Severity.HIGH, title="b", description="b"),
        Finding(source="s", category=OwaspCategory.OTHER, severity=Severity.LOW, title="c", description="c"),
    ]
    report = FinalReport(
        session_id="s1",
        target_url="https://example.com",
        profile=ScanProfile.STANDARD,
        jwt_provided=False,
        auth_tested=False,
        pages_crawled=3,
        started_at="2026-01-01T00:00:00+00:00",
        finished_at="2026-01-01T00:05:00+00:00",
        findings=findings,
        executive_summary="test summary",
    )
    counts = report.severity_counts
    assert counts["high"] == 2
    assert counts["low"] == 1
    assert counts["critical"] == 0
