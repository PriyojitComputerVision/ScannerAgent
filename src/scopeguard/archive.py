"""Inspect and safely extract an uploaded source archive (.zip). Stdlib only.

Runs inside the upload sandbox (Kubernetes pod or process sandbox), never in
the API server. Every entry is inspected; only the files the analyzer reads
(text, at most ``codecheck.MAX_FILE_BYTES``) are written, under the extraction
root, with fresh names checked against that root. Nothing is ever executed.

Flagged (``upload_archive`` findings) and never extracted:

* entries escaping the root (``../``, absolute paths, drive letters: Zip Slip)
* symlinks / special files, setuid/setgid bits, encrypted entries
* zip bombs (compression ratio, or more bytes than the header declared)
* duplicate names (two entries that map to the same file)
* binaries / executables, nested archives, control or bidi characters in names
* sensitive files: ``.env``, private keys, keystores, ``.htpasswd``, Terraform
  state, database files, a committed ``.git`` folder
"""
from __future__ import annotations

import hashlib
import io
import os
import posixpath
import re
import stat
import unicodedata
import zipfile
from dataclasses import dataclass, field
from typing import Any

A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A05 = "A05:2021-Security Misconfiguration"
A08 = "A08:2021-Software and Data Integrity Failures"
OTHER = "Other"

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_UNCOMPRESSED_BYTES = 500 * 1024 * 1024   # declared total; real bytes are counted too
MAX_EXTRACT_BYTES = 120 * 1024 * 1024        # bytes actually written (text files only)
MAX_RATIO = 200                              # file_size / compress_size above this = bomb
MAX_NAME = 1024
MAX_FINDINGS = 300
CHUNK = 64 * 1024
SNIFF = 4096
# Bundled zips (e.g. a packaged skill / plugin) are compared with the source in the same upload:
# at most this many bytes per bundle (compressed and uncompressed) and this many files in it.
MAX_BUNDLE_BYTES = 16 * 1024 * 1024
MAX_BUNDLE_FILES = 2000

_ARCHIVE_EXT = (".zip", ".jar", ".war", ".ear", ".apk", ".whl", ".egg", ".tar", ".tgz", ".gz", ".bz2",
                ".xz", ".7z", ".rar", ".zst", ".nupkg", ".aar")
_BIN_MAGIC = ((b"\x7fELF", "ELF executable"), (b"MZ", "Windows PE executable"),
              (b"\xcf\xfa\xed\xfe", "Mach-O executable"), (b"\xce\xfa\xed\xfe", "Mach-O executable"),
              (b"\xca\xfe\xba\xbe", "Mach-O universal binary / Java class"), (b"\x00asm", "WebAssembly module"))
_ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf", b"Rar!", b"BZh", b"\xfd7zXZ")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069\u200e\u200f]")
_CTRL = re.compile(r"[\x00-\x1f\x7f]")
_DRIVE = re.compile(r"^[A-Za-z]:")

# (regex on the lower-case base name or path, rule id, severity, category, description, cwe, recommendation)
_SENSITIVE = [
    (re.compile(r"(^|/)\.env(\.(?!example$|sample$|template$|dist$)[\w.-]+)?$"), "SENSITIVE_ENV_FILE", "high", A02,
     "Environment file committed to the source archive (usually holds secrets).", "CWE-538",
     ("Remove .env files from the repository and archive, rotate every secret they held, and keep "
     "only a .env.example with placeholders.")),
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|key|ppk)$"), "SENSITIVE_PRIVATE_KEY",
     "critical", A02, "Private key file in the source archive.", "CWE-321",
     "Revoke and reissue the key, purge it from history, and load keys from a secret manager."),
    (re.compile(r"\.(p12|pfx|jks|keystore|kdbx)$"), "SENSITIVE_KEYSTORE", "high", A02,
     "Keystore / password database in the source archive.", "CWE-522",
     "Remove the keystore, rotate what it protects, and provision it at deploy time."),
    (re.compile(r"(^|/)\.htpasswd$|(^|/)(credentials|secrets?)\.(json|ya?ml|xml|ini)$|(^|/)\.(npmrc|pypirc|netrc|git-credentials)$"),
     "SENSITIVE_CREDENTIALS_FILE", "high", A02, "Credentials file in the source archive.",
     "CWE-522", "Remove the file, rotate the credentials, and inject them at runtime."),
    (re.compile(r"(^|/)terraform\.tfstate(\.backup)?$"), "SENSITIVE_TF_STATE", "high", A02,
     "Terraform state committed (contains resource secrets in plain text).", "CWE-312",
     "Keep state in an encrypted remote backend and rotate secrets it contained."),
    (re.compile(r"\.(sqlite3?|db|mdb|bak|dump)$"), "SENSITIVE_DATA_FILE", "medium", A05,
     "Database / backup file in the source archive.", "CWE-530",
     "Do not ship data files with source code; check them for personal data and remove them."),
]


@dataclass
class ArchiveReport:
    findings: list[dict] = field(default_factory=list)
    notices: list[dict] = field(default_factory=list)
    extracted: list[str] = field(default_factory=list)
    stats: dict = field(default_factory=lambda: {
        "entries": 0, "files": 0, "extracted_files": 0, "extracted_bytes": 0, "declared_bytes": 0,
        "compressed_bytes": 0, "skipped_binary": 0, "skipped_large": 0, "skipped_resumed": 0, "refused": 0})
    aborted: str | None = None
    _seen: set = field(default_factory=set)

    def flag(self, rid: str, severity: str, category: str, description: str, where: str, cwe: str,
             recommendation: str, evidence: str = "", confidence: str = "high") -> None:
        key = (rid, where)
        if key in self._seen or len(self.findings) >= MAX_FINDINGS:
            return
        self._seen.add(key)
        self.findings.append({"source": "upload_archive", "category": category, "severity": severity,
                              "title": f"{rid}: {description}", "description": description,
                              "affected_url": f"upload/{where}", "evidence": evidence[:300] or None,
                              "cwe": cwe, "confidence": confidence, "recommendation": recommendation})

    def notice(self, kind: str, detail: str) -> None:
        if len(self.notices) < 200:
            self.notices.append({"kind": kind, "detail": detail[:300]})


class ArchiveError(ValueError):
    """The archive is unreadable or breaks a hard limit; nothing more is extracted."""


def _display(name: str) -> str:
    """Printable form of an entry name for reports (control / bidi characters made visible)."""
    clean = _BIDI.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", name)
    return _CTRL.sub(lambda m: f"<0x{ord(m.group(0)):02X}>", clean)[:300]


def normalize_entry(name: str) -> str | None:
    """Safe relative POSIX path for an entry, or None when it escapes the root."""
    raw = name.replace("\\", "/")
    if not raw or raw.startswith("/") or _DRIVE.match(raw) or "\x00" in raw:
        return None
    parts = []
    for part in raw.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return posixpath.join(*parts)


def _is_text_name(rel: str) -> bool:
    from scopeguard.codecheck import _is_text  # same rule the analyzer uses

    return _is_text(rel, posixpath.basename(rel))


def _open_archive(data: bytes, rep: ArchiveReport) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    """The zip and its entries, after the whole-archive limits (size, entry count, declared bytes)."""
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ArchiveError(f"archive is larger than {MAX_ARCHIVE_BYTES} bytes")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        raise ArchiveError(f"not a readable zip archive: {exc}") from exc
    infos = zf.infolist()
    rep.stats["entries"] = len(infos)
    if len(infos) > MAX_ENTRIES:
        raise ArchiveError(f"archive has {len(infos)} entries (limit {MAX_ENTRIES})")
    declared = sum(max(0, i.file_size) for i in infos)
    rep.stats["declared_bytes"] = declared
    rep.stats["compressed_bytes"] = sum(max(0, i.compress_size) for i in infos)
    if declared > MAX_UNCOMPRESSED_BYTES:
        rep.flag("ZIP_BOMB", "high", A05, "Archive declares more uncompressed data than allowed (zip bomb?).",
                 "(archive)", "CWE-409", "Upload only the source tree; split very large repositories.",
                 evidence=f"{declared} bytes declared, limit {MAX_UNCOMPRESSED_BYTES}")
        raise ArchiveError("archive declares too much uncompressed data")
    return zf, infos


@dataclass
class _Extraction:
    """One extraction run: the report, what was taken so far and the per-run settings."""
    rep: ArchiveReport
    zf: zipfile.ZipFile
    root: str
    max_file: int
    skip: set[str] | frozenset[str]
    keep_requirements: bool
    ignore: Any
    written_total: int = 0
    taken: dict[str, str] = field(default_factory=dict)
    by_size: dict[int, list[tuple[str, zipfile.ZipInfo]]] = field(default_factory=dict)  # to compare bundles
    bundles: list[tuple[str, zipfile.ZipInfo]] = field(default_factory=list)


def _entry_path(x: _Extraction, info: zipfile.ZipInfo) -> str | None:
    """The entry's safe relative path, or None when it is refused or not a file (name length,
    deceptive characters, Zip Slip, directories, links / special files, encrypted, duplicates)."""
    rep, name = x.rep, info.filename
    shown = _display(name)
    if len(name) > MAX_NAME:
        rep.stats["refused"] += 1
        rep.notice("name", f"entry name longer than {MAX_NAME} characters skipped: {shown[:80]}...")
        return None
    if _BIDI.search(name) or _CTRL.search(name):
        rep.flag("ARCHIVE_DECEPTIVE_NAME", "medium", OTHER,
                 "Entry name contains control or bidirectional characters (can disguise the real name).",
                 shown, "CWE-451", "Rename the file using plain characters; check where it came from.",
                 evidence=shown)
    rel = normalize_entry(name)
    if rel is None:
        rep.stats["refused"] += 1
        rep.flag("ZIP_SLIP", "high", A01,
                 "Archive entry path escapes the extraction folder (Zip Slip / path traversal).",
                 shown, "CWE-22",
                 "Never extract archives without normalising entry paths; rebuild this archive from the "
                 "source tree and check how the entry got there.", evidence=shown)
        return None
    mode = (info.external_attr >> 16) & 0xFFFF
    if info.is_dir():
        return None
    rep.stats["files"] += 1
    if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG):
        rep.stats["refused"] += 1
        kind = "symlink" if stat.S_ISLNK(mode) else "special file"
        rep.flag("ARCHIVE_SYMLINK", "medium", A01,
                 f"Archive contains a {kind}; it was not extracted (symlinks can point outside the tree).",
                 rel, "CWE-59", "Replace links with real files or remove them from the upload.", evidence=shown)
        return None
    if mode & (stat.S_ISUID | stat.S_ISGID):
        rep.flag("ARCHIVE_SETUID", "medium", A05, "File carries a setuid/setgid bit.", rel, "CWE-250",
                 "Remove setuid/setgid bits from files in the source tree.", evidence=oct(mode))
    if info.flag_bits & 0x1:
        rep.stats["refused"] += 1
        rep.notice("encrypted", f"encrypted entry not analysed: {rel}")
        return None
    key = unicodedata.normalize("NFC", rel).casefold()
    if key in x.taken:
        rep.flag("ARCHIVE_DUPLICATE_ENTRY", "medium", A08,
                 "Two archive entries map to the same file (different tools would extract different content).",
                 rel, "CWE-436", "Rebuild the archive so each path appears once.",
                 evidence=f"also {x.taken[key]}")
        return None
    x.taken[key] = rel
    return rel


def _entry_flags(x: _Extraction, info: zipfile.ZipInfo, rel: str) -> bool:
    """Name-based flags (.git metadata, sensitive files) and the per-entry compression ratio.
    False = refused as a zip bomb."""
    from scopeguard.codecheck import is_model_weight

    rep = x.rep
    if not is_model_weight(rel):  # weights are never opened, not even to compare
        x.by_size.setdefault(info.file_size, []).append((rel, info))
    low = rel.lower()
    if ".git" in low.split("/")[:-1]:
        rep.flag("GIT_METADATA", "low", A05, "Archive includes .git metadata (history can hold removed secrets).",
                 ".git/", "CWE-527", "Upload an export (git archive) instead of the working copy.")
    for rx, rid, sev, cat, desc, cwe, rec in _SENSITIVE:
        if rx.search(low):
            rep.flag(rid, sev, cat, desc, rel, cwe, rec)
            break
    if info.compress_size > 0 and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 1024 * 1024:
        rep.flag("ZIP_BOMB", "high", A05, "Entry has an extreme compression ratio (zip bomb?); not extracted.",
                 rel, "CWE-409", "Remove generated or padded files from the upload.",
                 evidence=f"{info.file_size} / {info.compress_size} bytes")
        rep.stats["refused"] += 1
        return False
    return True


def _analysed_here(x: _Extraction, rel: str, wanted: bool) -> bool:
    """Skipped folders, files the analyzer never reads (unless a wanted requirements file), and
    whatever the project's .gitignore excludes are not written."""
    from scopeguard.codecheck import ANALYSIS_SKIP_DIRS, is_not_analysed

    if any(p in ANALYSIS_SKIP_DIRS for p in rel.split("/")[:-1]) or (
            is_not_analysed(rel.rsplit("/", 1)[-1]) and not wanted):
        return False  # the analyzer skips vendored / build / .claude folders, pytest, Markdown and images anyway
    if x.ignore and x.ignore.ignored(rel):
        x.rep.stats["gitignored"] = x.rep.stats.get("gitignored", 0) + 1
        return False  # excluded by the project's .gitignore
    return True


def _text_content(x: _Extraction, info: zipfile.ZipInfo, rel: str, wanted: bool) -> bool:
    """Read the entry's first bytes: zips (compared with the source later), nested archives and
    binaries are not written; only text files the analyzer reads are."""
    rep = x.rep
    try:
        head = _read_head(x.zf, info)
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError) as exc:
        rep.notice("read-error", f"{rel}: {exc}")
        return False
    if head.startswith(b"PK\x03\x04"):
        x.bundles.append((rel, info))  # a zip: compared with the source after the loop
        rep.stats["skipped_binary"] += 1
        return False
    if rel.lower().endswith(_ARCHIVE_EXT):
        rep.flag("NESTED_ARCHIVE", "low", A08, "Nested archive inside the upload; it was not unpacked or analysed.",
                 rel, "CWE-829", "Upload the source of bundled archives, or verify their checksums/signatures.")
        return False
    magic = next((desc for sig, desc in _BIN_MAGIC if head.startswith(sig)), None)
    if magic or head.startswith(_ARCHIVE_MAGIC):
        rep.stats["skipped_binary"] += 1
        if magic:
            rep.flag("ARCHIVE_BINARY_EXECUTABLE", "medium", A08,
                     f"Compiled binary in the source upload ({magic}); it cannot be reviewed as source.",
                     rel, "CWE-506", "Build binaries in CI from reviewed source instead of committing them; "
                     "verify where this one came from.", evidence=magic)
        else:
            rep.flag("NESTED_ARCHIVE", "low", A08, "Nested archive inside the upload; not unpacked or analysed.",
                     rel, "CWE-829", "Upload the source of bundled archives, or verify their checksums.")
        return False
    if not _is_text_name(rel) and not wanted:
        return False
    if b"\x00" in head:
        rep.stats["skipped_binary"] += 1
        return False
    return True


def _write_entry(x: _Extraction, info: zipfile.ZipInfo, rel: str) -> bool:
    """Write one checked text file (size cap, resume skip, total cap, confinement). False = stop:
    the total extraction limit was reached."""
    rep = x.rep
    if info.file_size > x.max_file:
        rep.stats["skipped_large"] += 1
        rep.notice("large", f"{rel} is larger than {x.max_file} bytes; not analysed")
        return True
    if rel in x.skip:
        rep.stats["skipped_resumed"] += 1
        return True
    if x.written_total + info.file_size > MAX_EXTRACT_BYTES:
        rep.aborted = f"extraction stopped at {MAX_EXTRACT_BYTES} bytes"
        rep.notice("limit", rep.aborted)
        return False
    target = os.path.realpath(os.path.join(x.root, *rel.split("/")))
    if not (target == x.root or target.startswith(x.root + os.sep)):
        rep.flag("ZIP_SLIP", "high", A01, "Archive entry resolves outside the extraction folder.", rel,
                 "CWE-22", "Rebuild the archive from the source tree.", evidence=_display(info.filename))
        return True
    try:
        n = _extract_one(x.zf, info, target, x.max_file)
    except _SizeMismatch:
        rep.flag("ZIP_BOMB", "high", A05,
                 "Entry decompresses to more data than its header declares (zip bomb / tampered archive).",
                 rel, "CWE-409", "Rebuild the archive with a standard tool and check it was not tampered with.")
        return True
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError) as exc:
        rep.notice("read-error", f"{rel}: {exc}")
        return True
    x.written_total += n
    rep.stats["extracted_files"] += 1
    rep.stats["extracted_bytes"] = x.written_total
    rep.extracted.append(rel)
    return True


def inspect_and_extract(data: bytes, dest: str, *, skip: set[str] | frozenset[str] = frozenset(),
                        max_file_bytes: int | None = None, keep_requirements: bool = False) -> ArchiveReport:
    """Inspect every entry of the zip in ``data``; write the text files the analyzer needs
    into ``dest`` (created). ``skip`` holds relative paths already analysed by an earlier
    attempt (checkpoint resume): they are inspected but not written again. ``keep_requirements``
    also writes requirements-type files (``scopeguard.deps.is_requirements_file``: requirements*.txt,
    lock files, Pipfile, ...) that the SAST itself skips; the SAST step's tools use it for pip-audit."""
    from scopeguard.codecheck import MAX_FILE_BYTES
    from scopeguard.deps import is_requirements_file
    from scopeguard.gitignore import GitIgnore

    rep = ArchiveReport()
    zf, infos = _open_archive(data, rep)
    os.makedirs(dest, exist_ok=True)
    x = _Extraction(rep=rep, zf=zf, root=os.path.realpath(dest), max_file=max_file_bytes or MAX_FILE_BYTES,
                    skip=skip, keep_requirements=keep_requirements,
                    ignore=_project_gitignore(zf, infos, GitIgnore()))  # .gitignore'd files are not analysed
    for info in infos:
        rel = _entry_path(x, info)
        if rel is None or not _entry_flags(x, info, rel):
            continue
        wanted = keep_requirements and is_requirements_file(rel)  # dependency declarations only, never code
        if not _analysed_here(x, rel, wanted) or not _text_content(x, info, rel, wanted):
            continue
        if not _write_entry(x, info, rel):
            break
    for rel, info in x.bundles:
        same, why = _bundle_is_source(zf, info, x.by_size)
        if same:
            rep.notice("bundle", f"{rel}: a bundled zip whose files are all in this upload as source "
                                 f"(same SHA-256); not reported as a nested archive")
        else:
            rep.flag("NESTED_ARCHIVE", "low", A08, "Nested archive inside the upload; not unpacked or analysed.",
                     rel, "CWE-829", "Upload the source of bundled archives, or verify their checksums.",
                     evidence=why)
    return rep


def _project_gitignore(zf: zipfile.ZipFile, infos: list[zipfile.ZipInfo], ignore):
    """The upload's .gitignore files (each at most 256 KB, at most 200 of them) as one matcher."""
    count = 0
    for info in infos:
        rel = normalize_entry(info.filename)
        if not rel or info.is_dir() or rel.rsplit("/", 1)[-1] != ".gitignore" or info.file_size > 256 * 1024:
            continue
        if info.flag_bits & 0x1 or count >= 200:
            continue
        try:
            with zf.open(info) as fh:
                text = fh.read(256 * 1024).decode("utf-8", errors="replace")
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError):
            continue
        ignore.add(text, rel.rsplit("/", 1)[0] if "/" in rel else "")
        count += 1
    return ignore


def low_name(rel: str) -> str:
    return rel.rsplit("/", 1)[-1].lower()


def _sha256(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    """SHA-256 of one entry (zipfile checks its CRC while reading)."""
    h = hashlib.sha256()
    with zf.open(info) as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _bundle_is_source(zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                      by_size: dict[int, list[tuple[str, zipfile.ZipInfo]]]) -> tuple[bool, str]:
    """(True, "") when every file of the bundled zip ``info`` is also in the upload at a matching path
    with the same SHA-256 (CRC-32 alone can be forged); else (False, why). Read in memory only and
    bounded by MAX_BUNDLE_BYTES / MAX_BUNDLE_FILES; nothing is extracted."""
    if info.file_size > MAX_BUNDLE_BYTES:
        return False, f"larger than {MAX_BUNDLE_BYTES // 1048576} MB; not compared"
    try:
        inner = zipfile.ZipFile(io.BytesIO(zf.read(info)))
        entries = [e for e in inner.infolist() if not e.is_dir()]
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError):
        return False, "not a readable zip"
    if not entries:
        return False, "empty"
    if len(entries) > MAX_BUNDLE_FILES:
        return False, f"more than {MAX_BUNDLE_FILES} files; not compared"
    if sum(max(0, e.file_size) for e in entries) > MAX_BUNDLE_BYTES:
        return False, f"unpacks to more than {MAX_BUNDLE_BYTES // 1048576} MB; not compared"
    from scopeguard.codecheck import is_model_weight

    if any(is_model_weight(e.filename) for e in entries):
        return False, "contains model weight files; they are not read, so it was not compared"
    for e in entries:
        name = normalize_entry(e.filename)
        if name is None or e.flag_bits & 0x1 or _BIDI.search(name) or _CTRL.search(name):
            return False, "an entry is encrypted or has an unsafe name"
        copies = [(r, i) for r, i in by_size.get(e.file_size, []) if r == name or r.endswith("/" + name)]
        if not copies:
            return False, f"{_display(name)[:120]} is not in the upload as source"
        try:
            digest = _sha256(inner, e)
            if not any(_sha256(zf, i) == digest for _, i in copies):
                return False, f"{_display(name)[:120]} differs from the source copy"
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, EOFError):
            return False, "an entry could not be read"
    return True, ""


class _SizeMismatch(Exception):
    pass


def _read_head(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with zf.open(info) as fh:
        return fh.read(SNIFF)


def _extract_one(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: str, max_file: int) -> int:
    """Stream one entry to ``target``, counting real bytes (headers can lie)."""
    os.makedirs(os.path.dirname(target), exist_ok=True)
    limit = min(info.file_size, max_file)
    written = 0
    with zf.open(info) as src, open(target, "xb") as out:
        while True:
            chunk = src.read(CHUNK)
            if not chunk:
                break
            written += len(chunk)
            if written > limit:
                out.close()
                os.remove(target)
                raise _SizeMismatch
            out.write(chunk)
    return written


def archive_content_bytes(data: bytes) -> int:
    """Bytes to size the sandbox by: archive size + declared size of what the analyzer reads.
    Header values are only an estimate here; the sandbox counts real bytes."""
    from scopeguard.codecheck import MAX_FILE_BYTES

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()[:MAX_ENTRIES]
    except (zipfile.BadZipFile, OSError, ValueError):
        return len(data)
    text = sum(min(i.file_size, MAX_FILE_BYTES) for i in infos
               if not i.is_dir() and normalize_entry(i.filename) and _is_text_name(i.filename))
    return len(data) + min(text, MAX_EXTRACT_BYTES)
