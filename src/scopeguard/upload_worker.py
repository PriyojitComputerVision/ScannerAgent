"""Analyse a source archive inside the sandbox. Stdlib only.

Runs in the Kubernetes Job (stock Python image; this code arrives as a read-only
ConfigMap, scopeguard.k8s) or, when the operator allows it, in the process sandbox.
For the agent's code check the header also holds {"mode": "codecheck",
"allowed_hosts": [...]} and the archive holds source/... and site/manifest.json ...:

    stdin  = one JSON header line ({"done": [...]} from an earlier attempt) + "\\n" + zip bytes
    stdout = JSON lines: checkpoints, then {"type": "result", ...}
    exit   = 0 ok, 2 bad input, ``limits.OOM_EXIT_CODE`` out of memory

Phase 1 (extract): an audit hook blocks network, DNS, processes and native code,
and allows writes only under ``<workdir>/src``. ``scopeguard.archive`` inspects
every entry and writes only the text files the analyzer reads.
Phase 2 (analyse): ``codecheck.install_guard`` adds a second hook: no writes at all,
reads only under the extracted tree and the Python runtime. The code is never run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

MAX_HEADER_BYTES = 4 * 1024 * 1024


def _install_extract_guard(root: str) -> None:
    root = os.path.realpath(root)

    def inside(p) -> bool:
        try:
            rp = os.path.realpath(os.fsdecode(p))
        except (TypeError, ValueError):
            return False
        return rp == root or rp.startswith(root + os.sep)

    def hook(event: str, args: tuple) -> None:
        if event.startswith(("socket.", "urllib.", "http.client.", "ftplib.", "smtplib.")):
            raise PermissionError(f"sandbox: {event} blocked")
        if event in ("subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn", "os.fork",
                     "os.forkpty", "pty.spawn", "os.startfile", "ctypes.dlopen", "os.symlink", "os.link",
                     "os.chmod", "os.chown", "shutil.rmtree", "os.rename"):
            raise PermissionError(f"sandbox: {event} blocked")
        if event in ("os.mkdir", "os.remove", "os.rmdir") and args and not inside(args[0]):
            raise PermissionError(f"sandbox: {event} outside the extraction folder blocked")
        if event == "open" and args:
            path, mode = args[0], args[1] if len(args) > 1 else "r"
            flags = args[2] if len(args) > 2 else 0
            if isinstance(path, int):
                return
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC))
            if writing and not inside(path):
                raise PermissionError("sandbox: writes outside the extraction folder are blocked")

    sys.addaudithook(hook)


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    reserve = [bytearray(4 * 1024 * 1024)]  # freed on MemoryError so the handler can still write
    ap = argparse.ArgumentParser(prog="scopeguard-upload-worker")
    ap.add_argument("--workdir", default="/work")
    ap.add_argument("--sandbox-kind", default="process")
    ap.add_argument("--checkpoint-every", type=int, default=25)
    ap.add_argument("--simulate-oom-after", type=int, default=0, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)

    # Everything both phases need is imported before the first hook.
    import bz2  # noqa: F401
    import lzma  # noqa: F401
    import zipfile  # noqa: F401
    import zlib  # noqa: F401

    from scopeguard import archive, codecheck, limits, textsafe  # noqa: F401

    stdin = sys.stdin.buffer
    header = stdin.readline(MAX_HEADER_BYTES + 1)
    if not header.endswith(b"\n"):
        _emit({"type": "result", "ok": False, "error": "missing or oversized header line"})
        return 2
    try:
        hdr = json.loads(header)
    except ValueError:
        _emit({"type": "result", "ok": False, "error": "header is not JSON"})
        return 2
    data = stdin.read(archive.MAX_ARCHIVE_BYTES + 1)
    if len(data) > archive.MAX_ARCHIVE_BYTES:
        _emit({"type": "result", "ok": False, "error": f"archive larger than {archive.MAX_ARCHIVE_BYTES} bytes"})
        return 2
    done = {str(k) for k in hdr.get("done") or [] if isinstance(k, str)}
    codecheck_mode = hdr.get("mode") == "codecheck"
    allowed = {str(h).lower().strip() for h in hdr.get("allowed_hosts") or [] if isinstance(h, str) and h.strip()}

    workdir = os.path.realpath(a.workdir)
    root = os.path.join(workdir, "src")
    os.makedirs(root, exist_ok=True)
    os.chdir(workdir)
    _install_extract_guard(root)

    res = codecheck.Results()
    progress = codecheck.Progress(stream=True, every=a.checkpoint_every, done=done,
                                  oom_after=a.simulate_oom_after)
    try:
        if codecheck_mode:  # "source:a.py" -> source/a.py, "site:pages/1.html" -> site/pages/1.html
            skip = {k.replace(":", "/", 1) for k in done if k.startswith(("source:", "site:"))}
        else:
            skip = {k.split(":", 1)[1] for k in done if k.startswith("source:")}
        try:
            rep = archive.inspect_and_extract(data, root, skip=skip)
        except archive.ArchiveError as exc:
            _emit({"type": "result", "ok": False, "error": f"archive refused: {exc}"})
            return 2
        del data  # the analysis phase needs the memory more than the zip
        for f in rep.findings if not codecheck_mode else ():  # our own staging: no archive flags
            res.add_raw(f)
        for n in rep.notices:
            res.notice(n["kind"], n["detail"])
        archive_info = {"stats": rep.stats, "aborted": rep.aborted}
        _emit({"type": "checkpoint", "stage": "archive", "done": [], "findings": res.findings,
               "notices": res.notices, "archive": archive_info})
        progress.mark_sent(res)  # already emitted above

        runtime = [sys.prefix, sys.base_prefix, os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
        codecheck.install_guard([root, *runtime])
        if codecheck_mode:
            if os.path.isdir(os.path.join(root, "source")):
                codecheck.scan_source(res, os.path.join(root, "source"), progress)
            if os.path.isfile(os.path.join(root, "site", "manifest.json")):
                codecheck.scan_site(res, os.path.join(root, "site"), allowed, progress)
        else:
            codecheck.scan_source(res, root, progress)
        out = codecheck.result_payload(res, a.sandbox_kind, stream=True)
        out["archive"] = archive_info
    except MemoryError:
        return codecheck.oom_exit(res, progress, reserve)
    _emit(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
