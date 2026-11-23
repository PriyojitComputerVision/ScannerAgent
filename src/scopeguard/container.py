"""Run ``scopeguard.codecheck`` in a locked-down Docker container. Stdlib only.

Container settings (see :func:`docker_command`):

* ``--network none``             no network at all: nothing can be downloaded or searched
* ``--read-only`` + inputs mounted read-only, small ``noexec`` tmpfs for /tmp
* ``--cap-drop ALL``, ``no-new-privileges``, non-root user (65534 = nobody)
* ``--pids-limit``, ``--memory`` (no swap), ``--cpus``, wall-clock timeout (container killed)
* the analyzer's own audit hook records any attempted network/DNS/process/write

The image (default ``python:3.12-slim``) is never pulled during a scan: run
``python -m scopeguard.container --setup`` once. When Docker or the image is
missing, the same analyzer runs in the process sandbox and the result says why
(``sandbox.fallback_reason``) so the caller can raise a red flag.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

SRC_DIR = str(Path(__file__).resolve().parent.parent)  # folder that contains scopeguard/
CONTAINER_APP = "/app"
CONTAINER_SOURCE = "/input/source"
CONTAINER_SITE = "/input/site"
DEFAULT_IMAGE = "python:3.12-slim"
# Every sandbox container carries this label, so leftovers can be found and
# removed, and cleanup never touches containers that aren't ours.
CONTAINER_LABEL = "scopeguard.codecheck=1"
SESSION_LABEL = "scopeguard.session"
CONTAINER_PREFIX = "scopeguard-"
# Same rule as the API's session ids (pentest_agent.schemas.SESSION_ID_RE), which
# is also a valid Docker container name.
_SESSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_BOOT = ("import sys;sys.path.insert(0,{app!r});"
         "from scopeguard.codecheck import main;raise SystemExit(main())")


class CodecheckError(RuntimeError):
    pass


def _docker() -> str | None:
    return shutil.which("docker")


def docker_status(image: str = DEFAULT_IMAGE, timeout: float = 8.0) -> tuple[bool, str]:
    """(usable, reason). Usable means the daemon answers and the image is present."""
    exe = _docker()
    if not exe:
        return False, "docker CLI not found"
    try:
        info = subprocess.run([exe, "info", "--format", "{{.OSType}}"], check=False, capture_output=True, text=True,
                              timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker daemon not reachable ({exc.__class__.__name__})"
    if info.returncode != 0:
        return False, "docker daemon not running"
    if info.stdout.strip() != "linux":
        return False, f"docker engine is {info.stdout.strip() or 'unknown'}, need linux containers"
    img = subprocess.run([exe, "image", "inspect", image], check=False, capture_output=True, text=True, timeout=timeout)
    if img.returncode != 0:
        return False, f"image {image} not present (run: python -m scopeguard.container --setup)"
    return True, "ok"


def container_name(session_id: str | None) -> str:
    """``scopeguard-<session_id>``, so a container maps straight to its scan.
    Without a usable session id (direct CLI use): ``scopeguard-adhoc-<random>``."""
    if session_id and _SESSION_RE.fullmatch(session_id) and ".." not in session_id:
        return f"{CONTAINER_PREFIX}{session_id}"
    return f"{CONTAINER_PREFIX}adhoc-{uuid.uuid4().hex[:12]}"


def remove_container(name: str, timeout: float = 30.0) -> bool:
    """Force-remove the sandbox container called ``name`` (stopping it if it
    still runs). Only a container carrying CONTAINER_LABEL is touched, never an
    unrelated one with the same name. Never raises; True if one was removed."""
    exe = _docker()
    if not exe:
        return False
    try:
        listed = subprocess.run([exe, "ps", "-aq", "--filter", f"label={CONTAINER_LABEL}",
                                 # names are [A-Za-z0-9._-]: only "." needs escaping
                                 "--filter", f"name=^/{name.replace('.', chr(92) + '.')}$"],
                                check=False, capture_output=True, text=True, timeout=timeout)
        ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
        if listed.returncode != 0 or not ids:
            return False
        subprocess.run([exe, "rm", "-f", *ids], check=False, capture_output=True, timeout=timeout)
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def remove_leftover_containers(timeout: float = 30.0) -> list[str]:
    """Force-remove every sandbox container still present (labelled
    ``CONTAINER_LABEL``), e.g. after the server was killed mid-scan. Returns the
    removed container ids. Call it only when no scan is running (startup)."""
    exe = _docker()
    if not exe:
        return []
    try:
        listed = subprocess.run([exe, "ps", "-aq", "--filter", f"label={CONTAINER_LABEL}"],
                                check=False, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return []
    ids = [line.strip() for line in listed.stdout.splitlines() if line.strip()] if listed.returncode == 0 else []
    if ids:
        try:
            subprocess.run([exe, "rm", "-f", *ids], check=False, capture_output=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            return []
    return ids


def docker_command(*, name: str, image: str, source_dir: str | None, site_dir: str | None,
                   allowed_hosts: list[str], memory_mb: int = 512, cpus: float = 1.0,
                   pids: int = 64, extra_args: list[str] | None = None,
                   session_id: str | None = None) -> list[str]:
    """The exact ``docker run`` command line (kept separate so tests can assert it)."""
    cmd = [_docker() or "docker", "run", "--rm", "--name", name,
           "--label", CONTAINER_LABEL,
           "--label", f"{SESSION_LABEL}={session_id or ''}",
           "--network", "none",
           "--read-only",
           "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges",
           "--user", "65534:65534",
           "--pids-limit", str(pids),
           "--memory", f"{memory_mb}m", "--memory-swap", f"{memory_mb}m",
           "--cpus", str(cpus),
           "--ipc", "none",
           "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
           "--workdir", "/tmp",
           "--env", "PYTHONDONTWRITEBYTECODE=1", "--env", "PYTHONIOENCODING=utf-8",
           "--mount", f"type=bind,src={os.path.join(SRC_DIR, 'scopeguard')},dst={CONTAINER_APP}/scopeguard,readonly"]
    if source_dir:
        cmd += ["--mount", f"type=bind,src={source_dir},dst={CONTAINER_SOURCE},readonly"]
    if site_dir:
        cmd += ["--mount", f"type=bind,src={site_dir},dst={CONTAINER_SITE},readonly"]
    cmd += [image, "python", "-I", "-B", "-c", _BOOT.format(app=CONTAINER_APP), "--sandbox-kind", "docker"]
    if source_dir:
        cmd += ["--source", CONTAINER_SOURCE]
    if site_dir:
        cmd += ["--site", CONTAINER_SITE]
    for h in allowed_hosts:
        cmd += ["--allowed-host", h]
    return cmd + list(extra_args or [])


def _parse(stdout: str, stderr: str, returncode: int) -> dict:
    if returncode != 0:
        raise CodecheckError(f"analyzer exited {returncode}: {stderr.strip()[-500:]}")
    try:
        out = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise CodecheckError(f"analyzer returned invalid output: {stdout[:200]!r}") from exc
    if not out.get("ok"):
        raise CodecheckError(out.get("error", "unknown analyzer error"))
    return out


def run_in_docker(*, source_dir: str | None, site_dir: str | None, allowed_hosts: list[str],
                  image: str = DEFAULT_IMAGE, timeout: int = 180, memory_mb: int = 512,
                  extra_args: list[str] | None = None, session_id: str | None = None) -> dict:
    name = container_name(session_id)
    # A container of the same session left by a killed earlier attempt would
    # block the name: remove it first (only ours, see remove_container).
    remove_container(name)
    cmd = docker_command(name=name, image=image, source_dir=source_dir, site_dir=site_dir,
                         allowed_hosts=allowed_hosts, memory_mb=memory_mb, extra_args=extra_args,
                         session_id=session_id)
    # ``--rm`` deletes the container when it exits normally. If we leave early
    # (timeout, Ctrl+C, server shutdown, any error), killing the docker CLI
    # would NOT stop the container, so it is force-removed here as well.
    finished = False
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout)
        finished = True
    except subprocess.TimeoutExpired as exc:
        raise CodecheckError(f"sandbox container exceeded {timeout}s and was killed") from exc
    finally:
        if not finished:
            remove_container(name)
    out = _parse(proc.stdout, proc.stderr, proc.returncode)
    out["sandbox"] = {"kind": "docker", "image": image, "network": "none", "read_only": True,
                      "user": "65534", "memory_mb": memory_mb, "guard": "audit-hook",
                      "container": name, "removed_after_run": True}
    return out


def run_in_process(*, source_dir: str | None, site_dir: str | None, allowed_hosts: list[str],
                   timeout: int = 180, extra_args: list[str] | None = None) -> dict:
    """Fallback: isolated child interpreter, scrubbed env, throwaway cwd, audit hook."""
    work = tempfile.mkdtemp(prefix="scopeguard-codecheck-")
    env = {"PYTHONIOENCODING": "utf-8", "PYTHONDONTWRITEBYTECODE": "1", "PATH": os.environ.get("PATH", "")}
    for k in ("SYSTEMROOT", "SystemRoot", "TEMP", "TMP"):
        if k in os.environ:
            env[k] = os.environ[k]
    cmd = [sys.executable, "-I", "-B", "-c", _BOOT.format(app=SRC_DIR), "--sandbox-kind", "process"]
    if source_dir:
        cmd += ["--source", source_dir]
    if site_dir:
        cmd += ["--site", site_dir]
    for h in allowed_hosts:
        cmd += ["--allowed-host", h]
    cmd += list(extra_args or [])
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, cwd=work, env=env)
    except subprocess.TimeoutExpired as exc:
        raise CodecheckError(f"process sandbox exceeded {timeout}s and was killed") from exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
    out = _parse(proc.stdout, proc.stderr, proc.returncode)
    out["sandbox"] = {"kind": "process", "network": "blocked by audit hook", "guard": "audit-hook"}
    return out


def run_codecheck(*, source_dir: str | None, site_dir: str | None, allowed_hosts: list[str],
                  use_docker: bool = True, image: str = DEFAULT_IMAGE, timeout: int = 180,
                  memory_mb: int = 512, extra_args: list[str] | None = None,
                  session_id: str | None = None) -> dict:
    """Docker first; process sandbox when Docker is off or unavailable.

    ``sandbox.fallback_reason`` (which callers turn into a red flag) is set only when
    Docker was wanted but could not be used. Turning Docker off on purpose is recorded
    as ``sandbox.docker_disabled`` instead.
    """
    reason = ""
    if use_docker:
        ok, reason = docker_status(image)
        if ok:
            return run_in_docker(source_dir=source_dir, site_dir=site_dir, allowed_hosts=allowed_hosts,
                                 image=image, timeout=timeout, memory_mb=memory_mb, extra_args=extra_args,
                                 session_id=session_id)
    out = run_in_process(source_dir=source_dir, site_dir=site_dir, allowed_hosts=allowed_hosts,
                         timeout=timeout, extra_args=extra_args)
    if use_docker:
        out["sandbox"]["fallback_reason"] = f"Docker sandbox unavailable: {reason}"
    else:
        out["sandbox"]["docker_disabled"] = True
    return out


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m scopeguard.container",
                                 description="Docker sandbox for backend code / website content checks")
    ap.add_argument("--setup", action="store_true", help="pull the sandbox image once (not done during scans)")
    ap.add_argument("--status", action="store_true", help="show whether the Docker sandbox can be used")
    ap.add_argument("--image", default=os.environ.get("CODECHECK_IMAGE") or DEFAULT_IMAGE)
    a = ap.parse_args(argv)
    if a.setup:
        exe = _docker()
        if not exe:
            print("docker CLI not found")
            return 1
        return subprocess.run([exe, "pull", a.image], check=False).returncode
    ok, reason = docker_status(a.image)
    print(f"Docker sandbox: {'ready' if ok else 'NOT available'} ({reason}); image {a.image}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
