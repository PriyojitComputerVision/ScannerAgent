"""Docker-free sandbox: runs the scan in a locked-down child Python process.

Layers (all native Python/OS, no containers):
  1. Fresh interpreter in isolated mode (-I) with a scrubbed environment
     (API keys etc. are NOT inherited).
  2. Throwaway working directory; writes anywhere else are blocked.
  3. Audit hook: no subprocess/exec/fork, egress only to allow-listed IPs/ports,
     DNS only for allow-listed names.
  4. POSIX rlimits: CPU time, address space, file size, open files, processes.
  5. Hard wall-clock timeout; whole process group is killed on expiry.
  6. In-engine ScopedClient: scope check on every request, budget, size caps.
On Windows layer 4 is unavailable (no `resource` module); the rest still apply.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SRC_DIR = str(Path(__file__).resolve().parent.parent)


class SandboxError(RuntimeError):
    pass


def _limits(cpu_seconds: int, mem_bytes: int):
    def apply():  # runs in the child between fork and exec (POSIX only)
        import resource
        for name, val in (("RLIMIT_CPU", cpu_seconds), ("RLIMIT_AS", mem_bytes),
                          ("RLIMIT_FSIZE", 20 * 1024 * 1024), ("RLIMIT_NOFILE", 256),
                          ("RLIMIT_CORE", 0)):
            try:
                resource.setrlimit(getattr(resource, name), (val, val))
            except (ValueError, OSError):
                pass
        os.setsid()
    return apply


def run_sandboxed_scan(scan_args: dict, wall_timeout: int = 900, memory_mb: int = 1024) -> dict:
    """scan_args: kwargs for scopeguard.engine.run_scan. Returns the scan result dict."""
    sandbox_dir = tempfile.mkdtemp(prefix="scopeguard-sbx-")
    env = {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": os.environ.get("PATH", "")}
    for k in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP"):  # required by Windows sockets/ssl
        if k in os.environ:
            env[k] = os.environ[k]
    boot = f"import sys;sys.path.insert(0,{SRC_DIR!r});from scopeguard.worker import main;main()"
    kwargs = {}
    if os.name == "posix":
        kwargs["preexec_fn"] = _limits(wall_timeout + 30, memory_mb * 1024 * 1024)
    else:
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        proc = subprocess.run(
            [sys.executable, "-I", "-c", boot],
            input=json.dumps({"scan": scan_args, "sandbox_dir": sandbox_dir}),
            capture_output=True, text=True, timeout=wall_timeout, cwd=sandbox_dir, env=env, **kwargs)
    except subprocess.TimeoutExpired as exc:
        raise SandboxError(f"scan exceeded wall-clock limit of {wall_timeout}s") from exc
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    if proc.returncode != 0:
        raise SandboxError(f"sandbox worker exited {proc.returncode}: {proc.stderr.strip()[-600:]}")
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SandboxError(f"worker returned invalid output: {proc.stdout[:200]!r}") from exc
    if not payload.get("ok"):
        raise SandboxError(payload.get("error", "unknown worker error"))
    result = payload["result"]
    result["sandbox"] = payload["sandbox"]
    return result
