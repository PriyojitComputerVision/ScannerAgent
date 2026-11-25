"""Docker-free sandbox: runs the scan in a locked-down child Python process.

Layers (all native Python/OS, no containers):
  1. Fresh interpreter in isolated mode (-I) with a scrubbed environment
     (API keys etc. are NOT inherited).
  2. Throwaway working directory; writes anywhere else are blocked.
  3. Audit hook: no subprocess/exec/fork, egress only to allow-listed IPs/ports,
     DNS only for allow-listed names.
  4. Hard memory cap: POSIX rlimits (CPU, address space, file size, open files),
     Windows a Job Object (committed memory, no child processes) - scopeguard.limits.
  5. Hard wall-clock timeout; whole process group is killed on expiry.
  6. In-engine ScopedClient: scope check on every request, budget, size caps.
Out of memory ends with a clear SandboxError (the worker exits limits.OOM_EXIT_CODE).
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path

from scopeguard.limits import oom_message, run_limited, sandbox_python

SRC_DIR = str(Path(__file__).resolve().parent.parent)


class SandboxError(RuntimeError):
    pass


def run_sandboxed_scan(scan_args: dict, wall_timeout: int = 900, memory_mb: int = 1024,
                       block_private: bool = False) -> dict:
    """scan_args: kwargs for scopeguard.engine.run_scan. Returns the scan result dict.

    Cloud-metadata / link-local / multicast / reserved addresses are always kept
    out of the worker's egress allowlist; ``block_private`` also removes
    loopback and private ranges (scopeguard.netpolicy)."""
    sandbox_dir = tempfile.mkdtemp(prefix="scopeguard-sbx-")
    env = {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1",
           "PATH": os.environ.get("PATH", "")}
    for k in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP"):  # required by Windows sockets/ssl
        if k in os.environ:
            env[k] = os.environ[k]
    boot = f"import sys;sys.path.insert(0,{SRC_DIR!r});from scopeguard.worker import main;main()"
    try:
        # Hard memory cap on every OS (POSIX rlimits / Windows Job Object), bounded output.
        proc = run_limited([sandbox_python(), "-I", "-c", boot],
                           stdin=json.dumps({"scan": scan_args, "sandbox_dir": sandbox_dir,
                                             "block_private": bool(block_private)}).encode(),
                           cwd=sandbox_dir, env=env, timeout=wall_timeout, memory_mb=memory_mb,
                           cpu_seconds=wall_timeout + 30)
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)
    if proc.timed_out:
        raise SandboxError(f"scan exceeded wall-clock limit of {wall_timeout}s")
    if proc.oom:
        raise SandboxError(f"sandbox worker {oom_message(memory_mb)}; lower the profile's page/request "
                           "budget or raise the limit")
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
