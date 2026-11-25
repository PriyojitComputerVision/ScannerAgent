"""Scan source code in the Kubernetes Job sandbox, with OOM retry + checkpoint resume. Stdlib only.

Used for uploaded archives (:func:`scan_archive`) and for the agent's code check of a
backend folder + staged website text (:func:`scan_dirs`, which packs them into a zip).

1. Size: memory = ``memory_multiplier`` (5) x the content size (archive + the text it
   holds), at least ``floor_mb``, at most ``ceiling_mb`` (scopeguard.limits).
2. Run ``scopeguard.upload_worker`` as a Kubernetes Job (scopeguard.k8s; no Docker, no
   custom image). Kubernetes unavailable -> an error when ``require_kubernetes`` (the
   default), else the process sandbox with ``fallback_reason``. ``backend="process"``
   uses the process sandbox on purpose (development, tests).
3. Out of memory (exit 86, OOMKilled, SIGKILL): the checkpoint lines the run printed
   are kept, the state is saved to ``checkpoint_path`` and the next attempt runs with
   ``retry_multiplier`` (10) x memory and skips every file already analysed. A later
   call with the same archive and checkpoint resumes as well (e.g. after a restart).
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import time
import zipfile

from scopeguard import archive, k8s, limits
from scopeguard.checkpoint import CheckpointState

SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_BOOT = ("import sys;sys.path.insert(0,{app!r});"
         "from scopeguard.upload_worker import main;raise SystemExit(main())")
BACKENDS = ("kubernetes", "process")


class CodescanError(RuntimeError):
    pass


def _payload(state: CheckpointState, data: bytes, header: dict | None = None) -> bytes:
    return json.dumps({**(header or {}), **state.resume_payload()}).encode() + b"\n" + data


def _run_process(stdin: bytes, *, memory_mb: int, timeout: int, args: list[str]) -> limits.RunResult:
    work = tempfile.mkdtemp(prefix="scopeguard-upload-")
    env = {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "PATH": os.environ.get("PATH", "")}
    for k in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP"):
        if k in os.environ:
            env[k] = os.environ[k]
    cmd = [limits.sandbox_python(), "-I", "-B", "-c", _BOOT.format(app=SRC_DIR), "--workdir", work,
           "--sandbox-kind", "process", *args]
    try:
        # RLIMIT_FSIZE also caps the extracted files: allow the extraction budget.
        return limits.run_limited(cmd, stdin=stdin, cwd=work, env=env, timeout=timeout, memory_mb=memory_mb,
                                  fsize_bytes=archive.MAX_EXTRACT_BYTES + limits.DEFAULT_MAX_OUTPUT)
    finally:
        import shutil

        shutil.rmtree(work, ignore_errors=True)


def scan_archive(data: bytes, *, backend: str = "kubernetes", k8s_config: k8s.K8sConfig | None = None,
                 require_kubernetes: bool = True, header: dict | None = None, checkpoint_path: str | None = None, timeout: int = 300,
                 memory_multiplier: int = limits.MEMORY_MULTIPLIER,
                 retry_multiplier: int = limits.RETRY_MEMORY_MULTIPLIER,
                 floor_mb: int = limits.MEMORY_FLOOR_MB, ceiling_mb: int = limits.MEMORY_CEILING_MB,
                 session_id: str | None = None, simulate_oom_after: int = 0,
                 progress_cb=None) -> dict:
    """Analyse the zip in ``data``; returns findings, recommendations, archive stats and
    a ``sandbox`` block (backend, attempts with memory used, resume info).
    ``simulate_oom_after`` (tests) makes the *first* attempt die after N files."""
    if backend not in BACKENDS:
        raise CodescanError(f"unknown sandbox backend {backend!r} (use {', '.join(BACKENDS)})")
    if len(data) > archive.MAX_ARCHIVE_BYTES:
        raise CodescanError(f"archive larger than {archive.MAX_ARCHIVE_BYTES} bytes")
    fingerprint = hashlib.sha256(data).hexdigest()
    state = CheckpointState.load(checkpoint_path, fingerprint)
    resumed_from = len(state.done)

    sandbox: dict = {"kind": backend}
    cfg = k8s_config or k8s.K8sConfig()
    if backend == "kubernetes":
        ok, why = k8s.cluster_status(cfg)
        if not ok:
            if require_kubernetes:
                raise CodescanError(f"Kubernetes sandbox unavailable: {why}")
            backend = "process"
            sandbox = {"kind": "process", "fallback_reason": f"Kubernetes sandbox unavailable: {why}"}
        else:
            sandbox.update({"namespace": cfg.namespace, "image": cfg.image, "network": "deny-all NetworkPolicy",
                            "runtime_class": cfg.runtime_class or None, "workload": "Job"})
    if backend == "process":
        sandbox.setdefault("network", "blocked by audit hook")

    content = archive.archive_content_bytes(data)
    plan = [memory_multiplier, retry_multiplier]
    if state.last_attempt_oom:  # an earlier call already crashed at x5: go straight to x10
        plan = [retry_multiplier]
    final = None
    for i, mult in enumerate(plan):
        memory_mb = limits.memory_for_content(content, mult, floor_mb=floor_mb, ceiling_mb=ceiling_mb)
        args = ["--simulate-oom-after", str(simulate_oom_after)] if (simulate_oom_after and i == 0) else []
        if progress_cb:
            progress_cb({"attempt": len(state.attempts) + 1, "memory_mb": memory_mb, "multiplier": mult,
                         "resume_files": len(state.done)})
        state.begin_attempt()
        started = time.monotonic()
        stdin = _payload(state, data, header)
        try:
            if backend == "kubernetes":
                run = k8s.run_job(stdin, cfg=cfg, memory_mb=memory_mb, timeout=timeout, args=args,
                                  session_id=session_id)
            else:
                run = _run_process(stdin, memory_mb=memory_mb, timeout=timeout, args=args)
        except k8s.K8sError as exc:
            state.attempts.append({"memory_mb": memory_mb, "multiplier": mult, "outcome": "error",
                                   "error": str(exc)[:300]})
            _save(state, checkpoint_path)
            raise CodescanError(f"Kubernetes sandbox failed: {exc}") from exc
        final = state.absorb(run.stdout)
        attempt = {"memory_mb": memory_mb, "multiplier": mult, "seconds": round(time.monotonic() - started, 1),
                   "files_done_total": len(state.done), "exit_code": run.returncode, "reason": run.reason or None}
        if final is not None and final.get("ok"):
            attempt["outcome"] = "ok"
            state.attempts.append(attempt)
            break
        if final is not None:  # the worker refused the input (bad zip, limits)
            attempt["outcome"] = "refused"
            state.attempts.append(attempt)
            _save(state, checkpoint_path)
            raise CodescanError(str(final.get("error") or "archive refused"))
        if run.timed_out:
            attempt["outcome"] = "timeout"
            state.attempts.append(attempt)
            _save(state, checkpoint_path)
            raise CodescanError(f"sandbox exceeded {timeout}s; {len(state.done)} file(s) are checkpointed "
                                "and a new run resumes from there")
        if run.oom:
            attempt["outcome"] = "oom"
            state.attempts.append(attempt)
            _save(state, checkpoint_path)  # survive a server restart too
            continue
        attempt["outcome"] = "error"
        state.attempts.append(attempt)
        _save(state, checkpoint_path)
        raise CodescanError(f"analyzer exited {run.returncode}: {run.stderr.strip()[-400:]}")
    if final is None:
        last = state.attempts[-1]["memory_mb"] if state.attempts else None
        raise CodescanError(f"sandbox {limits.oom_message(last)} even at {retry_multiplier}x the content size; "
                            f"{len(state.done)} file(s) are checkpointed and a new run resumes from there")

    out = state.merged(final)
    out["archive"] = state.archive or final.get("archive")
    sandbox.update({"attempts": state.attempts, "content_bytes": content, "resumed_files": resumed_from,
                    "memory_mb": state.attempts[-1]["memory_mb"], "guard": "audit-hook",
                    "oom_retries": sum(1 for a in state.attempts if a.get("outcome") == "oom")})
    out["sandbox"] = sandbox
    out["archive_sha256"] = fingerprint
    if checkpoint_path and os.path.exists(checkpoint_path):
        os.remove(checkpoint_path)  # complete: nothing left to resume
    return out


def _save(state: CheckpointState, path: str | None) -> None:
    if path:
        state.save(path)


# --------------------------------------------------------------------------- agent code check
_FIXED_DATE = (1980, 1, 1, 0, 0, 0)  # same files -> same zip -> same checkpoint fingerprint


def pack_dirs(source_dir: str | None, site_dir: str | None) -> bytes:
    """Zip the text files the analyzer reads (``source/...``, ``site/...``) for the Job's stdin.
    Vendored/build folders, binaries, oversized files and symlinks are left out."""
    from scopeguard.codecheck import MAX_FILE_BYTES, SKIP_DIRS, _is_text

    buf = io.BytesIO()
    total = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for prefix, root in (("source", source_dir), ("site", site_dir)):
            if not root or not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
                for name in sorted(filenames):
                    path = os.path.join(dirpath, name)
                    if os.path.islink(path) or not _is_text(path, name):
                        continue
                    try:
                        if os.path.getsize(path) > MAX_FILE_BYTES:
                            continue
                        with open(path, "rb") as fh:
                            body = fh.read(MAX_FILE_BYTES + 1)
                    except OSError:
                        continue
                    total += len(body)
                    if total > archive.MAX_EXTRACT_BYTES:
                        raise CodescanError(f"code check input larger than {archive.MAX_EXTRACT_BYTES} bytes")
                    rel = os.path.relpath(path, root).replace(os.sep, "/")
                    zf.writestr(zipfile.ZipInfo(f"{prefix}/{rel}", date_time=_FIXED_DATE), body)
    data = buf.getvalue()
    if len(data) > archive.MAX_ARCHIVE_BYTES:
        raise CodescanError(f"code check input larger than {archive.MAX_ARCHIVE_BYTES} bytes once packed")
    return data


def scan_dirs(source_dir: str | None, site_dir: str | None, allowed_hosts: list[str], **kwargs) -> dict:
    """The agent's code check (backend folder + staged website text) as a Kubernetes Job.
    Same keyword arguments as :func:`scan_archive`; returns codecheck's result format."""
    data = pack_dirs(source_dir, site_dir)
    out = scan_archive(data, header={"mode": "codecheck", "allowed_hosts": list(allowed_hosts)}, **kwargs)
    out.pop("archive_sha256", None)
    return out
