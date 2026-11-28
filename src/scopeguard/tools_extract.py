"""Unpack an uploaded archive for the code SAST step's tools (ruff, mypy, bandit, radon, semgrep,
pip-audit). Stdlib only; runs as an isolated child interpreter on the server (``python -I``,
scrubbed env, memory cap, ``pentest_agent.code_tools``), never in the server process.

    stdin  = the zip bytes
    stdout = one JSON line {"ok", "extracted", "stats", "aborted", "dependencies"}
    exit   = 0 ok, 2 refused

Same archive checks as the sandbox (``scopeguard.archive.inspect_and_extract``: Zip Slip, links,
bombs, binaries, nested archives, .gitignore, pytest files and documents left out), plus the
requirements-type files the SAST skips (``keep_requirements``). The extract phase runs under the
sandbox worker's audit hook: no network, DNS, processes or native code, writes only under
``<workdir>/src``. Then ``scopeguard.deps`` reads the dependency files (declarations only).
Nothing from the archive is ever run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

MAX_LISTED = 5000


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="scopeguard-tools-extract")
    ap.add_argument("--workdir", required=True)
    a = ap.parse_args(argv)

    # Everything this worker needs is imported before the hook.
    import bz2  # noqa: F401
    import configparser  # noqa: F401
    import lzma  # noqa: F401
    import tomllib  # noqa: F401
    import zipfile  # noqa: F401
    import zlib  # noqa: F401

    from scopeguard import archive, codecheck, deps, gitignore  # noqa: F401
    from scopeguard.upload_worker import _install_extract_guard

    data = sys.stdin.buffer.read(archive.MAX_ARCHIVE_BYTES + 1)
    if len(data) > archive.MAX_ARCHIVE_BYTES:
        sys.stdout.write(json.dumps({"ok": False, "error": "archive too large"}) + "\n")
        return 2
    workdir = os.path.realpath(a.workdir)
    root = os.path.join(workdir, "src")
    os.makedirs(root, exist_ok=True)
    os.chdir(workdir)
    _install_extract_guard(root)
    try:
        rep = archive.inspect_and_extract(data, root, keep_requirements=True)
    except archive.ArchiveError as exc:
        sys.stdout.write(json.dumps({"ok": False, "error": f"archive refused: {exc}"}) + "\n")
        return 2
    del data
    out = {"ok": True, "extracted": rep.extracted[:MAX_LISTED], "stats": rep.stats, "aborted": rep.aborted,
           "dependencies": deps.collect(root)}
    sys.stdout.write(json.dumps(out) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
