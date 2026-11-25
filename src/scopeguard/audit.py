"""Tamper-evident audit log of finished scans (stdlib only).

One JSON object per line in ``AUDIT_LOG_PATH`` (default
``data/audit/audit.jsonl``), append-only. Every record carries:

* ``seq``: 1, 2, 3, ... with no gaps;
* ``prev``: the ``hash`` of the record before it ("" for the first);
* ``hash``: SHA-256 of the record's canonical JSON (without ``hash``), or an
  HMAC-SHA256 with ``AUDIT_HMAC_KEY`` when that is set (``alg`` says which).

``verify`` recomputes the chain, so an edited, reordered or deleted record is
detected; with the HMAC key, records cannot be forged or the chain rewritten
without the key either. Records also hold the SHA-256 of every report file, so
``verify --reports-dir`` detects altered reports.

Records never contain secrets: no access/refresh tokens, cookies, target JWTs
or passwords (only "was provided" flags), URLs lose credentials, query and
fragment, and free text goes through :func:`scrub`.

CLI (``uv run pentest-audit``)::

    pentest-audit verify [--reports-dir data/reports]   exit 0 = intact, 1 = tampered
    pentest-audit list [--limit 20]
    pentest-audit show <session_id>
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import threading
import urllib.parse as up
from contextlib import contextmanager
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_PATH = "./data/audit/audit.jsonl"
MAX_TEXT = 500
_thread_lock = threading.Lock()

_SECRET_PATTERNS = (
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [redacted]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"), "[jwt redacted]"),
    (re.compile(r"\b(?:gsk|lsv2|sk|pk|ghp|gho|xox[abp])_[A-Za-z0-9_-]{10,}"), "[key redacted]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|authorization|cookie)"
                r"(\s*[=:]\s*|\"\s*:\s*\")[^\s\"',;&]+"), r"\1\2[redacted]"),
)
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


# --------------------------------------------------------------------------- redaction
def sanitize_url(url: str | None) -> str:
    """scheme://host[:port]/path only: no credentials, query or fragment."""
    if not url:
        return ""
    try:
        p = up.urlsplit(str(url))
        host = p.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = host + (f":{p.port}" if p.port else "")
    except ValueError:
        return "[unparseable url]"
    return up.urlunsplit((p.scheme, netloc, p.path, "", ""))[:MAX_TEXT]


def scrub(text, limit: int = MAX_TEXT) -> str:
    """Free text safe for the audit log: secrets redacted, URLs sanitized, capped."""
    if text is None:
        return ""
    out = str(text)
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    out = _URL_RE.sub(lambda m: sanitize_url(m.group(0)), out)
    out = "".join(ch if ch.isprintable() or ch == " " else " " for ch in out)
    return out[:limit]


def file_sha256(path: str | Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                h.update(block)
        return h.hexdigest()
    except OSError:
        return None


# --------------------------------------------------------------------------- chain
def _canonical(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _digest(record: dict, key: bytes | None) -> str:
    body = _canonical({k: v for k, v in record.items() if k != "hash"})
    if key:
        return hmac.new(key, body, hashlib.sha256).hexdigest()
    return hashlib.sha256(body).hexdigest()


@contextmanager
def _file_lock(lock_path: Path):
    """Exclusive lock across threads and processes (server + CLI share the log)."""
    with _thread_lock:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.name == "nt":
                import msvcrt

                while True:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                        break
                    except OSError:  # LK_LOCK gives up after ~10 s; keep waiting
                        continue
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                if os.name == "nt":
                    import msvcrt

                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _last_record(path: Path) -> dict | None:
    """The last line of the log, read from the end of the file."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if not size:
        return None
    with open(path, "rb") as f:
        chunk = 1 << 16
        data = b""
        pos = size
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            f.seek(pos)
            data = f.read(step) + data
            lines = data.rstrip(b"\r\n").split(b"\n")
            if len(lines) > 1 or pos == 0:
                last = lines[-1].strip()
                return json.loads(last) if last else None
    return None


def append(record: dict, path: str | Path = DEFAULT_PATH, key: str | bytes | None = None) -> dict:
    """Append ``record`` to the chain and return it with seq/prev/hash filled in."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    lock = path.with_name(path.name + ".lock")
    with _file_lock(lock):
        last = _last_record(path)
        entry = {
            **record,
            "v": SCHEMA_VERSION,
            "seq": (int(last["seq"]) + 1) if last else 1,
            "logged_at": dt.datetime.now(dt.UTC).isoformat(timespec="seconds"),
            "prev": last["hash"] if last else "",
            "alg": "hmac-sha256" if key_bytes else "sha256",
        }
        entry["hash"] = _digest(entry, key_bytes)
        new_file = not path.exists()
        with open(path, "a", encoding="utf-8", newline="\n") as f:
            f.write(_canonical(entry).decode("utf-8") + "\n")
            f.flush()
            os.fsync(f.fileno())
        if new_file and os.name != "nt":
            os.chmod(path, 0o600)
    return entry


def read(path: str | Path = DEFAULT_PATH) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    out.append({"_unparseable": line[:200]})
    return out


def verify(path: str | Path = DEFAULT_PATH, key: str | bytes | None = None,
           reports_dir: str | Path | None = None) -> dict:
    """Check the whole chain (and, with ``reports_dir``, the report file hashes)."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    problems: list[str] = []
    prev_hash, expected_seq, count, unverifiable = "", 1, 0, 0
    for rec in read(path):
        count += 1
        if "_unparseable" in rec:
            problems.append(f"line {count}: not valid JSON")
            prev_hash = ""
            expected_seq += 1
            continue
        seq = rec.get("seq")
        if seq != expected_seq:
            problems.append(f"record {seq}: expected seq {expected_seq} (records missing or reordered)")
        if rec.get("prev") != prev_hash:
            problems.append(f"record {seq}: chain broken (prev does not match the hash of record {expected_seq - 1})")
        if rec.get("alg") == "hmac-sha256" and not key_bytes:
            unverifiable += 1
        elif rec.get("hash") != _digest(rec, key_bytes if rec.get("alg") == "hmac-sha256" else None):
            problems.append(f"record {seq}: content altered (hash mismatch)")
        if reports_dir and isinstance(rec.get("report"), dict):
            folder = Path(reports_dir) / str(rec["report"].get("folder", ""))
            for name, digest in (rec["report"].get("files") or {}).items():
                actual = file_sha256(folder / name)
                if actual is None:
                    problems.append(f"record {seq}: report file {folder.name}/{name} is missing")
                elif actual != digest:
                    problems.append(f"record {seq}: report file {folder.name}/{name} was modified")
        prev_hash = rec.get("hash", "")
        expected_seq = (seq if isinstance(seq, int) else expected_seq) + 1
    return {"ok": not problems and not unverifiable, "records": count, "problems": problems,
            "unverifiable_hmac_records": unverifiable,
            "last_hash": prev_hash or None}


# --------------------------------------------------------------------------- CLI
def _dotenv_value(name: str) -> str:
    """os.environ, else a plain NAME=value line in ./.env (no expansion)."""
    if os.environ.get(name):
        return os.environ[name]
    try:
        for line in Path(".env").read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and k.strip() == name:
                return v.strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


CODE_TRAIL_PATH = "./data/audit/code_audit.jsonl"


def log_path(trail: str = "scans") -> str:
    if trail == "code":
        return _dotenv_value("CODE_AUDIT_LOG_PATH") or CODE_TRAIL_PATH
    return _dotenv_value("AUDIT_LOG_PATH") or DEFAULT_PATH


def hmac_key() -> str:
    return _dotenv_value("AUDIT_HMAC_KEY")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pentest-audit", description="Check and read the scan audit log.")
    ap.add_argument("--path", default=None, help="audit log (default AUDIT_LOG_PATH or data/audit/audit.jsonl)")
    ap.add_argument("--trail", choices=("scans", "code"), default="scans",
                    help="scans: one record per scan; code: uploads, guardrails, sandbox attempts "
                         "(CODE_AUDIT_LOG_PATH)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify the hash chain (exit 1 if tampered)")
    v.add_argument("--reports-dir", default=None, help="also check report file hashes (e.g. data/reports)")
    ls = sub.add_parser("list", help="newest records first")
    ls.add_argument("--limit", type=int, default=20)
    sh = sub.add_parser("show", help="all records of one session as JSON")
    sh.add_argument("session_id")
    a = ap.parse_args(argv)
    path = a.path or log_path(a.trail)

    if a.cmd == "verify":
        res = verify(path, hmac_key() or None, a.reports_dir)
        print(f"{path}: {res['records']} record(s)")
        for p in res["problems"]:
            print("  TAMPERED:", p)
        if res["unverifiable_hmac_records"]:
            print(f"  {res['unverifiable_hmac_records']} HMAC record(s) need AUDIT_HMAC_KEY to verify")
        print("OK: chain intact" if res["ok"] else "FAILED")
        return 0 if res["ok"] else 1
    records = read(path)
    if a.cmd == "list":
        for r in reversed(records[-max(1, a.limit):]):
            if r.get("trail") == "code":
                d = r.get("detail") or {}
                print(f"#{r.get('seq', '?'):<5} {r.get('logged_at', '')[:19]:19}  {r.get('event', '?'):<16} "
                      f"{r.get('outcome', '?'):<9} {r.get('upload_id') or r.get('session_id') or '':<34} "
                      f"{(r.get('actor') or {}).get('sub', ''):<12} {r.get('client', {}).get('via', ''):<6} "
                      f"{d.get('job') or d.get('reason') or d.get('sha256') or ''}"[:200])
                continue
            res = r.get("results") or {}
            print(f"#{r.get('seq', '?'):<5} {r.get('finished_at', '')[:19]:19}  {r.get('outcome', '?'):<12} "
                  f"{r.get('session_id', ''):<34} {(r.get('actor') or {}).get('sub', ''):<16} "
                  f"{res.get('findings', '-'):>4} findings  {(r.get('target') or {}).get('url', '')}")
        return 0
    matches = [r for r in records if a.session_id in (r.get("session_id"), r.get("upload_id"))]
    print(json.dumps(matches, indent=2, ensure_ascii=False))
    return 0 if matches else 1


if __name__ == "__main__":
    sys.exit(main())
