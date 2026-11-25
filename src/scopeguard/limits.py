"""Memory sizing, hard resource limits and OOM detection for sandbox children. Stdlib only.

* :func:`memory_for_content` sizes a sandbox from the bytes it will analyse:
  ``MEMORY_MULTIPLIER`` (5) x content size on the first attempt and
  ``RETRY_MEMORY_MULTIPLIER`` (10) x after an out-of-memory crash, between a
  floor (the Python runtime itself) and a ceiling.
* :func:`run_limited` runs a child with a hard memory cap on every platform:
  POSIX ``RLIMIT_AS`` (+ CPU, file size, open files, no core dumps, own session),
  Windows a Job Object (per-process committed memory, one active process, killed
  when the job handle closes). Its stdout goes to a temp file and only
  ``max_output`` bytes are read back, so a chatty child can't exhaust the parent.
* :func:`looks_oom` tells an out-of-memory death apart from other failures:
  the workers exit with ``OOM_EXIT_CODE`` after catching ``MemoryError``; a
  SIGKILL (cgroup OOM killer, Docker exit 137) or a ``MemoryError`` in stderr
  also counts.
"""
from __future__ import annotations

import math
import os
import subprocess
import tempfile
from dataclasses import dataclass

MIB = 1024 * 1024
MEMORY_MULTIPLIER = 5
RETRY_MEMORY_MULTIPLIER = 10
MEMORY_FLOOR_MB = 256       # interpreter + stdlib + regex tables, before any content
MEMORY_CEILING_MB = 4096
OOM_EXIT_CODE = 86          # worker caught MemoryError and exited on purpose
DEFAULT_MAX_OUTPUT = 32 * MIB
_SIGKILL_CODES = {-9, 137}  # POSIX signal 9 / Docker and Kubernetes 128+9


def memory_for_content(content_bytes: int, multiplier: int = MEMORY_MULTIPLIER, *,
                       floor_mb: int = MEMORY_FLOOR_MB, ceiling_mb: int = MEMORY_CEILING_MB) -> int:
    """Memory limit in MB: ``multiplier`` x the content size, clamped to [floor, ceiling]."""
    want = math.ceil(max(0, int(content_bytes)) * max(1, int(multiplier)) / MIB)
    return int(min(max(want, floor_mb), max(floor_mb, ceiling_mb)))


def directory_content_bytes(root: str | None, *, skip_dirs: set[str] | frozenset[str] = frozenset(),
                            max_file_bytes: int | None = None) -> int:
    """Bytes the analyzer will actually read under ``root`` (no symlinks, skipped dirs left out,
    each file counted up to ``max_file_bytes`` since larger files are skipped unread)."""
    total = 0
    if not root or not os.path.isdir(root):
        return 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            path = os.path.join(dirpath, name)
            try:
                if os.path.islink(path):
                    continue
                size = os.path.getsize(path)
            except OSError:
                continue
            if max_file_bytes is not None and size > max_file_bytes:
                continue
            total += size
    return total


# --------------------------------------------------------------------------- running
def sandbox_python() -> str:
    """The real interpreter for sandbox children. A venv launcher (e.g. uv's python.exe
    trampoline on Windows) starts a second process, which the Job Object's one-process
    limit forbids; the workers are stdlib-only and put ``src`` on sys.path themselves,
    so the base interpreter is enough."""
    import sys

    base = getattr(sys, "_base_executable", None)
    return base if base and os.path.isfile(base) else sys.executable


@dataclass
class RunResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    truncated: bool = False
    memory_mb: int | None = None
    reason: str = ""            # e.g. Kubernetes termination reason ("OOMKilled")

    @property
    def oom(self) -> bool:
        return (not self.timed_out) and looks_oom(self.returncode, self.stderr, reason=self.reason)


def looks_oom(returncode: int | None, stderr: str = "", *, reason: str = "") -> bool:
    if reason == "OOMKilled":
        return True
    if returncode == OOM_EXIT_CODE or returncode in _SIGKILL_CODES:
        return True
    tail = (stderr or "")[-2000:]
    return "MemoryError" in tail or "Cannot allocate memory" in tail or "out of memory" in tail.lower()


def oom_message(memory_mb: int | None) -> str:
    return (f"ran out of memory (limit {memory_mb} MB)" if memory_mb else "ran out of memory")


def posix_limits(cpu_seconds: int, mem_bytes: int | None, fsize_bytes: int = 20 * MIB):
    """preexec_fn for POSIX children: rlimits + own session (whole group killable)."""
    def apply():  # runs in the child between fork and exec
        import resource
        limits = [("RLIMIT_CPU", cpu_seconds), ("RLIMIT_FSIZE", fsize_bytes),
                  ("RLIMIT_NOFILE", 256), ("RLIMIT_CORE", 0)]
        if mem_bytes:
            limits.append(("RLIMIT_AS", mem_bytes))
        for name, val in limits:
            try:
                resource.setrlimit(getattr(resource, name), (val, val))
            except (ValueError, OSError, AttributeError):
                pass
        os.setsid()
    return apply


class _WindowsJob:
    """A Job Object capping committed memory per process; the child is killed when
    the handle closes (KILL_ON_JOB_CLOSE) and may not start further processes."""

    def __init__(self, mem_bytes: int) -> None:
        import ctypes
        from ctypes import wintypes

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_ulonglong) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class EXTENDED(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", BASIC), ("IoInfo", IO_COUNTERS),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateJobObjectW.restype = wintypes.HANDLE
        k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._k32 = k32
        self.handle = k32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
        info = EXTENDED()
        info.BasicLimitInformation.LimitFlags = 0x100 | 0x2000 | 0x8  # PROCESS_MEMORY | KILL_ON_CLOSE | ACTIVE_PROCESS
        info.BasicLimitInformation.ActiveProcessLimit = 1
        info.ProcessMemoryLimit = int(mem_bytes)
        if not k32.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(err, "SetInformationJobObject failed")

    def assign(self, proc: subprocess.Popen) -> None:
        import ctypes

        if not self._k32.AssignProcessToJobObject(self.handle, int(proc._handle)):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")

    def close(self) -> None:
        if self.handle:
            self._k32.CloseHandle(self.handle)
            self.handle = None


def run_limited(cmd: list[str], *, stdin: bytes | None = None, cwd: str | None = None,
                env: dict[str, str] | None = None, timeout: float, memory_mb: int | None,
                cpu_seconds: int | None = None, max_output: int = DEFAULT_MAX_OUTPUT,
                fsize_bytes: int = 20 * MIB) -> RunResult:
    """Run ``cmd`` with a hard memory cap (``memory_mb``; None = no cap, e.g. Docker/K8s
    enforce it themselves). Never raises on a non-zero exit; ``timed_out`` is set on expiry
    (the child, and on POSIX its whole session, is killed)."""
    kwargs: dict = {}
    job: _WindowsJob | None = None
    mem_bytes = memory_mb * MIB if memory_mb else None
    if os.name == "posix":
        kwargs["preexec_fn"] = posix_limits(int(cpu_seconds or timeout + 30), mem_bytes, fsize_bytes)
    else:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if mem_bytes:
            job = _WindowsJob(mem_bytes)
    with tempfile.TemporaryFile() as out_f, tempfile.TemporaryFile() as err_f:
        try:
            return _run(cmd, stdin, cwd, env, kwargs, job, out_f, err_f, timeout, max_output, memory_mb)
        finally:
            if job is not None:
                job.close()


def _run(cmd, stdin, cwd, env, kwargs, job, out_f, err_f, timeout, max_output, memory_mb) -> RunResult:
    timed_out = False
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                            stdout=out_f, stderr=err_f, cwd=cwd, env=env, **kwargs)
    try:
        if job is not None:
            try:
                job.assign(proc)
            except OSError:
                proc.kill()
                raise
        try:
            proc.communicate(input=stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill(proc)
            proc.wait(timeout=30)
        except BrokenPipeError:  # child died (e.g. OOM) before reading all of stdin
            proc.wait(timeout=timeout)
    finally:
        if proc.poll() is None:
            _kill(proc)
            proc.wait(timeout=30)
    stdout, truncated = _read_back(out_f, max_output)
    stderr, _ = _read_back(err_f, 64 * 1024, tail=True)
    return RunResult(proc.returncode, stdout, stderr, timed_out=timed_out, truncated=truncated,
                     memory_mb=memory_mb)


def _kill(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            import signal
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def _read_back(fh, limit: int, *, tail: bool = False) -> tuple[str, bool]:
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    truncated = size > limit
    fh.seek(max(0, size - limit) if (tail and truncated) else 0)
    return fh.read(limit).decode("utf-8", errors="replace"), truncated
