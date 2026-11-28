"""Requirements-type files of a Python project and the versions they pin. Stdlib only.

Only dependency declarations are read, never code: ``requirements*.txt`` / ``*.in`` (also inside a
``requirements/`` folder), ``constraints*.txt``, ``pyproject.toml`` (PEP 621, PEP 735 groups,
Poetry), ``setup.cfg`` (``install_requires``), ``Pipfile`` / ``Pipfile.lock`` and the lock files
``uv.lock``, ``poetry.lock``, ``pdm.lock``, ``pylock*.toml``. Nothing is installed or resolved:
an entry counts as *pinned* only when it names one exact version (``==1.2.3``, ``===1.2.3``,
Poetry's bare ``1.2.3``, or a lock file entry). pip-audit (``pentest_agent.code_tools``) audits
exactly those pins; the rest is listed as "not pinned, not audited".
"""
from __future__ import annotations

import configparser
import json
import os
import posixpath
import re
import tomllib

MAX_FILES = 50
MAX_PACKAGES = 2000
MAX_FILE_BYTES = 2 * 1024 * 1024

LOCK_NAMES = {"uv.lock", "poetry.lock", "pdm.lock", "pipfile.lock"}
_NOT_INDEX = {"editable", "virtual", "git", "path", "directory", "url", "file"}
_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+!_-]{0,63}$")
# name [extras] specifiers ; markers   (PEP 508, without direct "@ url" references)
_REQ = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;@]*?)\s*(?:;.*)?$")
_EXACT = re.compile(r"^===?\s*(?P<v>[^\s,*]+)$")
_POETRY_EXACT = re.compile(r"^=?=?\s*(?P<v>[0-9][^\s,*^~<>=!]*)$")


def normalize(name: str) -> str:
    """PEP 503 name: lower case, runs of - _ . become one -."""
    return re.sub(r"[-_.]+", "-", name).lower()


def is_requirements_file(rel: str) -> bool:
    """A dependency declaration / lock file, by path only."""
    rel = rel.replace("\\", "/")
    base = posixpath.basename(rel).lower()
    parent = posixpath.basename(posixpath.dirname(rel)).lower()
    if base in LOCK_NAMES or base in ("pyproject.toml", "pipfile", "setup.cfg"):
        return True
    if base.startswith("pylock") and base.endswith(".toml"):
        return True
    return base.endswith((".txt", ".in")) and ("requirements" in base or base.startswith("constraints")
                                               or parent == "requirements")


def _kind(base: str) -> str:
    if base in LOCK_NAMES or base.startswith("pylock"):
        return "lock"
    if base in ("pyproject.toml", "pipfile", "setup.cfg"):
        return base
    return "requirements"


def _entry(name: str, spec: str, file: str, line: int | None, *, pinned_version: str | None = None) -> dict | None:
    name = name.strip()
    if not _NAME.match(name):
        return None
    version = pinned_version
    if version is None:
        m = _EXACT.match(spec.strip())
        version = m.group("v") if m else None
    if version is not None and not _VERSION.match(version):
        version = None
    return {"name": normalize(name), "version": version, "pinned": version is not None,
            "spec": spec.strip()[:80], "file": file, "line": line}


def parse_requirement(text: str, file: str, line: int | None) -> dict | None:
    """One PEP 508 requirement string; None for options, URLs and unreadable lines."""
    text = text.strip()
    if not text or text.startswith(("-", "#")) or "://" in text or "@" in text.split(";", 1)[0]:
        return None
    m = _REQ.match(text)
    if not m:
        return None
    return _entry(m.group("name"), m.group("spec"), file, line)


def _line_of(text: str, needle: str) -> int | None:
    pos = text.find(needle)
    return text.count("\n", 0, pos) + 1 if pos >= 0 else None


def _requirements_txt(text: str, file: str) -> list[dict]:
    out = []
    pending, start = "", 0
    for no, raw in enumerate(text.splitlines(), 1):
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not pending:
            start = no
        if line.endswith("\\"):
            pending += line[:-1] + " "
            continue
        full, pending = (pending + line).strip(), ""
        # "--hash=..." options after a requirement belong to it
        full = re.sub(r"\s--hash[=\s]\S+", "", full).strip()
        e = parse_requirement(full, file, start)
        if e:
            out.append(e)
    return out


def _pep508_list(values: object, text: str, file: str) -> list[dict]:
    out = []
    for v in values if isinstance(values, list) else []:
        if isinstance(v, str):
            e = parse_requirement(v, file, _line_of(text, v))
            if e:
                out.append(e)
    return out


def _poetry_table(table: object, text: str, file: str) -> list[dict]:
    out = []
    for name, value in (table or {}).items() if isinstance(table, dict) else []:
        if name.lower() == "python":
            continue
        version = value.get("version") if isinstance(value, dict) else value
        if not isinstance(version, str) or (isinstance(value, dict) and
                                            any(k in value for k in ("git", "path", "url"))):
            continue
        m = _POETRY_EXACT.match(version.strip())
        e = _entry(name, version, file, _line_of(text, f"{name}"),
                   pinned_version=m.group("v") if m else None)
        if e:
            out.append(e)
    return out


def _pyproject(text: str, file: str) -> list[dict]:
    data = tomllib.loads(text)
    project = data.get("project") or {}
    out = _pep508_list(project.get("dependencies"), text, file)
    for values in (project.get("optional-dependencies") or {}).values():
        out += _pep508_list(values, text, file)
    for values in (data.get("dependency-groups") or {}).values():
        out += _pep508_list(values, text, file)  # {include-group = ...} tables are skipped
    poetry = (data.get("tool") or {}).get("poetry") or {}
    out += _poetry_table(poetry.get("dependencies"), text, file)
    out += _poetry_table(poetry.get("dev-dependencies"), text, file)
    for group in (poetry.get("group") or {}).values():
        if isinstance(group, dict):
            out += _poetry_table(group.get("dependencies"), text, file)
    return out


def _pipfile(text: str, file: str) -> list[dict]:
    data = tomllib.loads(text)
    out = []
    for section in ("packages", "dev-packages"):
        for name, value in (data.get(section) or {}).items():
            spec = value.get("version") if isinstance(value, dict) else value
            if isinstance(spec, str) and not (isinstance(value, dict) and any(k in value for k in ("git", "path", "file"))):
                e = _entry(name, "" if spec == "*" else spec, file, _line_of(text, name))
                if e:
                    out.append(e)
    return out


def _pipfile_lock(text: str, file: str) -> list[dict]:
    data = json.loads(text)
    out = []
    for section in ("default", "develop"):
        for name, value in (data.get(section) or {}).items():
            spec = value.get("version") if isinstance(value, dict) else None
            if isinstance(spec, str):
                e = _entry(name, spec, file, _line_of(text, f'"{name}"'))
                if e:
                    out.append(e)
    return out


def _lock_packages(text: str, file: str) -> list[dict]:
    """[[package]] tables with name + version (uv.lock, poetry.lock, pdm.lock, pylock.toml). The
    project itself and packages from git / a path / a URL are not on the index: skipped."""
    data = tomllib.loads(text)
    out = []
    for pkg in data.get("packages") or data.get("package") or []:
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str) or not isinstance(pkg.get("version"), str):
            continue
        source = pkg.get("source")
        if isinstance(source, dict) and (_NOT_INDEX & set(source) or source.get("type") in _NOT_INDEX):
            continue  # uv: {editable|virtual|git|path|directory|url = ...}; poetry: type = "git" | ...
        if any(k in pkg for k in ("vcs", "directory", "archive")):  # pylock.toml non-index sources
            continue
        e = _entry(pkg["name"], f"=={pkg['version']}", file,
                   _line_of(text, f'name = "{pkg["name"]}"'), pinned_version=pkg["version"])
        if e:
            out.append(e)
    return out


def _setup_cfg(text: str, file: str) -> list[dict]:
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_string(text)
    out = []
    for section, key in (("options", "install_requires"),):
        if cp.has_option(section, key):
            for item in cp.get(section, key).splitlines():
                e = parse_requirement(item, file, _line_of(text, item.strip()) if item.strip() else None)
                if e:
                    out.append(e)
    if cp.has_section("options.extras_require"):
        for _, value in cp.items("options.extras_require"):
            for item in value.splitlines():
                e = parse_requirement(item, file, _line_of(text, item.strip()) if item.strip() else None)
                if e:
                    out.append(e)
    return out


def parse_file(rel: str, text: str) -> list[dict]:
    """Every dependency the file declares (pinned or not). Raises ValueError on a broken file."""
    base = posixpath.basename(rel.replace("\\", "/")).lower()
    try:
        if base == "pyproject.toml":
            return _pyproject(text, rel)
        if base == "pipfile":
            return _pipfile(text, rel)
        if base == "pipfile.lock":
            return _pipfile_lock(text, rel)
        if base == "setup.cfg":
            return _setup_cfg(text, rel)
        if base in LOCK_NAMES or base.startswith("pylock"):
            return _lock_packages(text, rel)
        return _requirements_txt(text, rel)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError, configparser.Error, AttributeError, TypeError) as exc:
        raise ValueError(f"{type(exc).__name__}: {str(exc)[:120]}") from exc


def collect(root: str) -> dict:
    """Every requirements-type file under ``root`` (already extracted by the archive checks):
    {"files": [{file, kind, packages, pinned, error?}], "packages": [{name, version, pinned, spec,
    file, line}], "truncated": bool}."""
    files, packages, truncated = [], [], False
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if not is_requirements_file(rel) or os.path.islink(path):
                continue
            if len(files) >= MAX_FILES:
                truncated = True
                break
            info = {"file": rel, "kind": _kind(name.lower()), "packages": 0, "pinned": 0}
            files.append(info)
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    info["error"] = f"larger than {MAX_FILE_BYTES} bytes; not read"
                    continue
                found = parse_file(rel, raw.decode("utf-8", errors="replace"))
            except (OSError, ValueError) as exc:
                info["error"] = str(exc)[:200]
                continue
            if name.lower() == "pyproject.toml" and not found:
                files.pop()  # a pyproject.toml with only tool settings declares no dependencies
                continue
            room = MAX_PACKAGES - len(packages)
            truncated = truncated or len(found) > room
            found = found[:max(0, room)]
            info["packages"] = len(found)
            info["pinned"] = sum(1 for e in found if e["pinned"])
            packages += found
    return {"files": files, "packages": packages, "truncated": truncated}


def audit_set(packages: list[dict]) -> list[tuple[str, str]]:
    """The unique (name, version) pins to audit, sorted."""
    return sorted({(p["name"], p["version"]) for p in packages if p.get("pinned") and p.get("version")})
