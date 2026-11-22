from __future__ import annotations

from pentest_agent.tools.dast_native import execute_native_dast
from scopeguard.simulated_target import SimulatedTarget


def test_native_dast_end_to_end_against_simulated_target():
    with SimulatedTarget() as t:
        update = execute_native_dast(t.url, "standard", [t.netloc])
    assert update["phase"] == "dast_complete"
    titles = " | ".join(f["title"] for f in update["findings"])
    for expected in ("Possible SQL injection", "Open redirect", "Path traversal"):
        assert expected in titles
    # every finding must already satisfy the strict Finding schema (validated inside)
    assert all(f["severity"] in {"critical", "high", "medium", "low", "info"} for f in update["findings"])


def test_native_dast_rejects_unknown_profile():
    update = execute_native_dast("http://127.0.0.1:1", "nope", ["127.0.0.1:1"])
    assert update["phase"] == "dast_failed"


def test_native_dast_reports_unreachable_target_as_red_flag():
    update = execute_native_dast("http://127.0.0.1:9", "quick", ["127.0.0.1:9"])
    assert update["phase"] == "dast_complete"
    assert any("unreachable" in r.lower() or "no pages" in r.lower() for r in update["red_flags"])
