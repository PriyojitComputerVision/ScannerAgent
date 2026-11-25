"""Memory sizing (x5 / x10 of the content), hard memory caps, OOM detection, checkpoints."""
from __future__ import annotations

import json

import pytest

from scopeguard import container, limits
from scopeguard.checkpoint import CheckpointState

MIB = 1024 * 1024


# ------------------------------------------------------------------ sizing
@pytest.mark.parametrize("content, mult, expected", [
    (100 * MIB, 5, 500),          # x5 on the first attempt
    (100 * MIB, 10, 1000),        # x10 on the retry after an OOM
    (1, 5, limits.MEMORY_FLOOR_MB),  # tiny inputs still get room for the interpreter
    (2000 * MIB, 10, limits.MEMORY_CEILING_MB),  # capped
])
def test_memory_is_sized_from_content(content, mult, expected):
    assert limits.memory_for_content(content, mult) == expected


def test_floor_and_ceiling_are_configurable():
    assert limits.memory_for_content(10 * MIB, 5, floor_mb=512) == 512
    assert limits.memory_for_content(300 * MIB, 10, ceiling_mb=1024) == 1024


def test_content_bytes_skip_vendored_and_oversized(tmp_path):
    (tmp_path / "app.py").write_bytes(b"x" * 1000)
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "big.js").write_bytes(b"x" * 50_000)
    (tmp_path / "huge.sql").write_bytes(b"x" * 2_000_000)  # > MAX_FILE_BYTES: skipped unread
    assert container.content_bytes(str(tmp_path), None) == 1000


# ------------------------------------------------------------------ OOM detection
@pytest.mark.parametrize("code, stderr, reason, oom", [
    (limits.OOM_EXIT_CODE, "", "", True),
    (137, "", "", True),            # Docker / Kubernetes SIGKILL
    (-9, "", "", True),             # POSIX SIGKILL
    (1, "Traceback ...\nMemoryError", "", True),
    (1, "ValueError: x", "OOMKilled", True),
    (1, "ValueError: x", "", False),
    (0, "", "", False),
])
def test_looks_oom(code, stderr, reason, oom):
    assert limits.looks_oom(code, stderr, reason=reason) is oom


def test_memory_cap_is_enforced_on_this_os():
    """A child that allocates far beyond its limit dies as out-of-memory (POSIX rlimit /
    Windows Job Object), instead of taking the host's memory."""
    run = limits.run_limited([limits.sandbox_python(), "-I", "-c", "b = bytearray(900 * 1024 * 1024)"],
                             timeout=60, memory_mb=128)
    assert run.returncode != 0 and run.oom, (run.returncode, run.stderr[-300:])


def test_same_allocation_passes_without_a_tight_cap():
    run = limits.run_limited([limits.sandbox_python(), "-I", "-c", "b = bytearray(32 * 1024 * 1024); print('ok')"],
                             timeout=60, memory_mb=512)
    assert run.returncode == 0 and run.stdout.strip() == "ok"


def test_output_read_back_is_bounded():
    run = limits.run_limited([limits.sandbox_python(), "-I", "-c", "print('x' * 3_000_000)"], timeout=60,
                             memory_mb=256, max_output=1000)
    assert run.truncated and len(run.stdout) == 1000


def test_timeout_kills_the_child():
    run = limits.run_limited([limits.sandbox_python(), "-I", "-c", "import time; time.sleep(30)"], timeout=1,
                             memory_mb=256)
    assert run.timed_out and not run.oom


# ------------------------------------------------------------------ checkpoints
def _lines(*objs):
    return "\n".join(json.dumps(o) for o in objs)


def _finding(title, url="source/a.py#L1"):
    return {"source": "sandbox_source", "title": f"{title}: x", "affected_url": url, "severity": "high",
            "category": "A03:2021-Injection", "description": "d", "evidence": "e", "cwe": "CWE-1",
            "confidence": "medium", "recommendation": "fix"}


def test_checkpoint_absorbs_partial_output_and_ignores_a_cut_line():
    st = CheckpointState("fp")
    st.begin_attempt()
    out = _lines({"type": "checkpoint", "done": ["source:a.py"], "findings": [_finding("R1")],
                  "stats": {"source_files": 1}}) + '\n{"type": "checkpoint", "done": ["source:b.p'
    assert st.absorb(out) is None
    assert st.done == {"source:a.py"} and len(st.findings) == 1


def test_attempts_merge_without_duplicates_and_stats_add_up(tmp_path):
    st = CheckpointState("fp")
    st.begin_attempt()
    st.absorb(_lines({"type": "checkpoint", "done": ["source:a.py"], "findings": [_finding("R1")],
                      "stats": {"source_files": 1}}))
    st.attempts.append({"outcome": "oom", "memory_mb": 256})
    path = tmp_path / "ck.json"
    st.save(str(path))

    again = CheckpointState.load(str(path), "fp")
    assert again.done == {"source:a.py"} and again.last_attempt_oom
    again.begin_attempt()
    final = again.absorb(_lines({"type": "result", "ok": True, "findings": [_finding("R1"), _finding("R2", "b")],
                                 "stats": {"source_files": 1}, "violations": []}))
    merged = again.merged(final)
    assert sorted(f["title"] for f in merged["findings"]) == ["R1: x", "R2: x"]
    assert merged["stats"]["source_files"] == 2
    assert merged["recommendations"][0]["recommendation"] == "fix"


def test_checkpoint_of_other_input_is_not_resumed(tmp_path):
    st = CheckpointState("one")
    st.done = {"source:a.py"}
    st.save(str(tmp_path / "ck.json"))
    assert CheckpointState.load(str(tmp_path / "ck.json"), "two").done == set()


# ------------------------------------------------------------------ code check: retry + resume
@pytest.fixture
def many_files(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for i in range(12):
        (src / f"m{i:02d}.py").write_text(f"def f{i}(c, n): c.execute(f\"SELECT {{n}}\")\n", encoding="utf-8")
    return src


def test_codecheck_resumes_after_oom_with_ten_times_memory(many_files, monkeypatch):
    calls = []
    real = container._process_attempt

    def attempt(**kw):
        calls.append(kw)
        if len(calls) == 1:  # first attempt dies after 5 files
            kw["extra_args"] = [*kw["extra_args"], "--simulate-oom-after", "5", "--checkpoint-every", "2"]
        return real(**kw)

    monkeypatch.setattr(container, "_process_attempt", attempt)
    r = container.run_codecheck(source_dir=str(many_files), site_dir=None, allowed_hosts=[],
                                memory_mb=64, ceiling_mb=4096)
    assert [a["outcome"] for a in r["sandbox"]["attempts"]] == ["oom", "ok"]
    assert [a["multiplier"] for a in r["sandbox"]["attempts"]] == [5, 10]
    assert "--resume-file" in calls[1]["extra_args"] and "--resume-file" not in calls[0]["extra_args"]
    assert r["stats"]["source_files"] == 12                  # 5 before the crash + 7 resumed, none twice
    assert len([f for f in r["findings"] if f["title"].startswith("SQL_STRING_BUILD")]) == 12
    assert r["sandbox"]["oom_retries"] == 1 and r["recommendations"]


def test_codecheck_gives_up_after_the_retry_and_keeps_the_checkpoint(many_files, monkeypatch, tmp_path):
    real = container._process_attempt

    def attempt(**kw):
        return real(**{**kw, "extra_args": [*kw["extra_args"], "--simulate-oom-after", "3",
                                            "--checkpoint-every", "1"]})

    monkeypatch.setattr(container, "_process_attempt", attempt)
    ck = tmp_path / "ck.json"
    with pytest.raises(container.CodecheckError, match=r"out of memory \(limit \d+ MB\) even at 10x"):
        container.run_codecheck(source_dir=str(many_files), site_dir=None, allowed_hosts=[],
                                checkpoint_path=str(ck))
    saved = json.loads(ck.read_text(encoding="utf-8"))
    assert len(saved["done"]) == 6 and [a["outcome"] for a in saved["attempts"]] == ["oom", "oom"]

    # A later run (e.g. after more memory was granted) resumes from file 7 at x10 directly.
    monkeypatch.setattr(container, "_process_attempt", real)
    r = container.run_codecheck(source_dir=str(many_files), site_dir=None, allowed_hosts=[],
                                checkpoint_path=str(ck))
    assert r["sandbox"]["resumed_files"] == 6 and r["stats"]["source_files"] == 12
    assert r["sandbox"]["attempts"][-1]["multiplier"] == 10 and not ck.exists()
