"""Local process sandbox for ``scopeguard.codecheck``, and helpers shared with the
Kubernetes Job sandbox (scopeguard.k8s). Stdlib only. No Docker is ever used.

The isolated sandbox is a Kubernetes Job (scopeguard.k8s / scopeguard.codescan). This
module is the local fallback, used automatically whenever Kubernetes cannot run (or chosen with
``SANDBOX_BACKEND=process``): an isolated child interpreter (``-I``)
with a scrubbed environment and throwaway cwd, a hard memory cap (POSIX rlimits /
Windows Job Object), and the analyzer's own audit hook (no network, DNS, processes or
writes; reads only under the inputs).

Memory is sized from the content (x5, x10 after an out-of-memory crash) and the retry
resumes from the checkpoint lines the crashed run printed (scopeguard.checkpoint).
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path

from scopeguard.checkpoint import CheckpointState
from scopeguard.limits import (
    MEMORY_CEILING_MB,
    MEMORY_MULTIPLIER,
    RETRY_MEMORY_MULTIPLIER,
    RunResult,
    directory_content_bytes,
    looks_oom,
    memory_for_content,
    oom_message,
    run_limited,
    sandbox_python,
)

SRC_DIR = str(Path(__file__).resolve().parent.parent)  # folder that contains scopeguard/
# Same rule as the API's session ids (pentest_agent.schemas.SESSION_ID_RE).
_SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_BOOT = ("import sys;sys.path.insert(0,{app!r});"
         "from scopeguard.codecheck import main;raise SystemExit(main())")


class CodecheckError(RuntimeError):
    pass


# --------------------------------------------------------------------------- ownership
def owner_id() -> str:
    """``<host>:<pid>`` of this server process, stored on every sandbox Job so the startup
    sweep removes only Jobs whose server is gone (never another server's running scan)."""
    import socket

    return f"{socket.gethostname()}:{os.getpid()}"


def _pid_alive(pid: int) -> bool:
    """Whether a process exists. (Not os.kill(pid, 0): on Windows that terminates it.)"""
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.GetLastError() == 5  # access denied: it exists
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _orphaned(owner: str) -> bool:
    """True if the owning server process is gone (or the owner is missing). Jobs owned by
    another host are kept: we cannot see that host's processes."""
    import socket

    host, _, pid = (owner or "").rpartition(":")
    if not owner or not pid.isdigit():
        return True
    if host != socket.gethostname():
        return False
    return int(pid) != os.getpid() and not _pid_alive(int(pid))


# --------------------------------------------------------------------------- process sandbox
def _parse(stdout: str, stderr: str, returncode: int) -> dict:
    if returncode != 0:
        if looks_oom(returncode, stderr):
            raise CodecheckError(f"analyzer {oom_message(None)} (exit {returncode})")
        raise CodecheckError(f"analyzer exited {returncode}: {stderr.strip()[-500:]}")
    try:
        out = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CodecheckError(f"analyzer returned invalid output: {stdout[:200]!r}") from exc
    if not out.get("ok"):
        raise CodecheckError(out.get("error", "unknown analyzer error"))
    return out


def _process_attempt(*, source_dir, site_dir, allowed_hosts, timeout, memory_mb, extra_args) -> RunResult:
    """Isolated child interpreter, scrubbed env, throwaway cwd, audit hook, hard memory cap."""
    work = tempfile.mkdtemp(prefix="scopeguard-codecheck-")
    env = {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "PATH": os.environ.get("PATH", "")}
    for k in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP"):
        if k in os.environ:
            env[k] = os.environ[k]
    cmd = [sandbox_python(), "-I", "-B", "-c", _BOOT.format(app=SRC_DIR), "--sandbox-kind", "process"]
    if source_dir:
        cmd += ["--source", source_dir]
    if site_dir:
        cmd += ["--site", site_dir]
    for h in allowed_hosts:
        cmd += ["--allowed-host", h]
    cmd += list(extra_args or [])
    try:
        return run_limited(cmd, cwd=work, env=env, timeout=timeout, memory_mb=memory_mb)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run_in_process(*, source_dir: str | None, site_dir: str | None, allowed_hosts: list[str],
                   timeout: int = 180, extra_args: list[str] | None = None, memory_mb: int = 512) -> dict:
    """One analyzer run in the process sandbox (no retry)."""
    run = _process_attempt(source_dir=source_dir, site_dir=site_dir, allowed_hosts=allowed_hosts,
                           timeout=timeout, memory_mb=memory_mb, extra_args=extra_args)
    if run.timed_out:
        raise CodecheckError(f"process sandbox exceeded {timeout}s and was killed")
    out = _parse(run.stdout, run.stderr, run.returncode)
    out["sandbox"] = process_info(memory_mb)
    return out


def process_info(memory_mb: int) -> dict:
    return {"kind": "process", "network": "blocked by audit hook", "guard": "audit-hook", "memory_mb": memory_mb,
            "memory_limit": "rlimit" if os.name == "posix" else "job object"}


def content_bytes(source_dir: str | None, site_dir: str | None) -> int:
    """Bytes the analyzer will read: the memory limit is sized from this."""
    from scopeguard.codecheck import MAX_FILE_BYTES, SKIP_DIRS

    return (directory_content_bytes(source_dir, skip_dirs=SKIP_DIRS, max_file_bytes=MAX_FILE_BYTES)
            + directory_content_bytes(site_dir, max_file_bytes=MAX_FILE_BYTES))


def inputs_fingerprint(source_dir: str | None, site_dir: str | None) -> str:
    """Changes when any input file is added, removed, resized or modified (checkpoints of
    other inputs are never resumed)."""
    import hashlib

    h = hashlib.sha256()
    for label, root in (("source", source_dir), ("site", site_dir)):
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames.sort()
            for name in sorted(filenames):
                path = os.path.join(dirpath, name)
                try:
                    st = os.stat(path, follow_symlinks=False)
                except OSError:
                    continue
                rel = os.path.relpath(path, root).replace(os.sep, "/")
                h.update(f"{label}:{rel}:{st.st_size}:{st.st_mtime_ns}\n".encode())
    return h.hexdigest()


def run_codecheck(*, source_dir: str | None, site_dir: str | None, allowed_hosts: list[str],
                  timeout: int = 180, memory_mb: int = 512, extra_args: list[str] | None = None,
                  memory_multiplier: int = MEMORY_MULTIPLIER, retry_multiplier: int = RETRY_MEMORY_MULTIPLIER,
                  ceiling_mb: int = MEMORY_CEILING_MB, checkpoint_path: str | None = None,
                  attempt_cb=None) -> dict:
    """The code check in the process sandbox, sized from the content.

    Memory = ``memory_multiplier`` (5) x the bytes the analyzer reads, never below
    ``memory_mb`` nor above ``ceiling_mb``. Out of memory: one retry with
    ``retry_multiplier`` (10) x that resumes from the checkpoint lines the crashed run
    printed (files already analysed are skipped). With ``checkpoint_path`` the state is
    also kept on disk, so a later call resumes too.
    """
    content = content_bytes(source_dir, site_dir)
    state = CheckpointState.load(checkpoint_path, inputs_fingerprint(source_dir, site_dir))
    resumed_from = len(state.done)
    plan = [retry_multiplier] if state.last_attempt_oom else [memory_multiplier, retry_multiplier]
    resume_dir = tempfile.mkdtemp(prefix="scopeguard-resume-")
    final = None
    try:
        for mult in plan:
            mem = memory_for_content(content, mult, floor_mb=memory_mb, ceiling_mb=ceiling_mb)
            args = ["--stream", *list(extra_args or [])]
            if state.done:
                resume_file = os.path.join(resume_dir, "resume.json")
                with open(resume_file, "w", encoding="utf-8") as fh:
                    json.dump(state.resume_payload(), fh)
                args += ["--resume-file", resume_file]
            state.begin_attempt()
            run = _process_attempt(source_dir=source_dir, site_dir=site_dir, allowed_hosts=allowed_hosts,
                                   timeout=timeout, memory_mb=mem, extra_args=args)
            final = state.absorb(run.stdout)
            attempt = {"memory_mb": mem, "multiplier": mult, "exit_code": run.returncode,
                       "files_done_total": len(state.done)}
            if final is not None and run.returncode == 0:
                state.attempts.append({**attempt, "outcome": "ok"})
                _notify(attempt_cb, state.attempts[-1])
                break
            final = None
            outcome = "timeout" if run.timed_out else "oom" if run.oom else "error"
            state.attempts.append({**attempt, "outcome": outcome})
            _notify(attempt_cb, state.attempts[-1])
            if checkpoint_path:
                state.save(checkpoint_path)
            if outcome == "timeout":
                raise CodecheckError(f"process sandbox exceeded {timeout}s and was killed")
            if outcome == "error":
                raise CodecheckError(f"analyzer exited {run.returncode}: {run.stderr.strip()[-500:]}")
    finally:
        shutil.rmtree(resume_dir, ignore_errors=True)
    if final is None:
        raise CodecheckError(f"analyzer {oom_message(state.attempts[-1]['memory_mb'])} even at "
                             f"{retry_multiplier}x the content size; {len(state.done)} file(s) are "
                             "checkpointed")
    out = state.merged(final)
    mem = state.attempts[-1]["memory_mb"]
    out["sandbox"] = process_info(mem)
    out["sandbox"].update({"content_bytes": content, "attempts": state.attempts, "resumed_files": resumed_from,
                           "oom_retries": sum(1 for a in state.attempts if a["outcome"] == "oom")})
    if checkpoint_path and os.path.exists(checkpoint_path):
        os.remove(checkpoint_path)
    return out


def _notify(attempt_cb, attempt: dict) -> None:
    """Report one attempt (audit trail); a broken listener never breaks the check."""
    if attempt_cb:
        with contextlib.suppress(Exception):  # a broken listener must not break the scan
            attempt_cb(dict(attempt), process_info(int(attempt.get("memory_mb") or 0)))
