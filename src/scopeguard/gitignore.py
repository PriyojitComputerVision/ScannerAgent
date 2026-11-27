"""The project's own .gitignore rules: what the code SAST leaves out (stdlib only, sandbox-safe).

Supported (git's documented rules, the common subset): blank lines and ``#`` comments, ``!``
negation, a trailing ``/`` (directories only), a leading or inner ``/`` (anchored to the folder of
the .gitignore), ``*`` / ``?`` / ``[...]`` globs and ``**`` (any number of folders). Nested
.gitignore files apply to their own folder. As in git, a file inside an ignored folder cannot be
re-included by a later ``!`` rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_RULES = 2000
MAX_LINE = 400


@dataclass(frozen=True)
class _Rule:
    base: str          # folder of the .gitignore ("" = root), POSIX, no trailing slash
    regex: re.Pattern  # matched against the path relative to ``base``
    negate: bool
    dir_only: bool


def _glob_to_regex(pattern: str, anchored: bool) -> re.Pattern:
    """A gitignore glob as a regex over a relative POSIX path."""
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if pattern.startswith("/**", i) and i + 3 == len(pattern):
            out.append("/.*")
            i += 3
            continue
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            end = pattern.find("]", i + 1)
            if end == -1:
                out.append(re.escape(c))
            else:
                body = pattern[i + 1:end].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append(f"[{body}]")
                i = end
        elif c == "\\" and i + 1 < len(pattern):
            i += 1
            out.append(re.escape(pattern[i]))
        else:
            out.append(re.escape(c))
        i += 1
    body = "".join(out)
    prefix = "" if anchored else "(?:.*/)?"
    return re.compile(f"^{prefix}{body}$")


def parse(text: str, base: str = "") -> list[_Rule]:
    """Rules of one .gitignore found in folder ``base`` (relative POSIX path, "" for the root)."""
    rules: list[_Rule] = []
    base = base.strip("/")
    for raw in text.splitlines()[:MAX_RULES]:
        line = raw[:MAX_LINE].rstrip()
        if line.endswith("\\ "):  # escaped trailing space stays
            line = raw[:MAX_LINE]
        if not line or line.startswith("#"):
            continue
        negate = line.startswith("!")
        if negate or line.startswith(("\\!", "\\#")):  # "!x" negates; "\!x" / "\#x" are literal names
            line = line[1:]
        dir_only = line.endswith("/")
        line = line.rstrip("/")
        if not line:
            continue
        anchored = "/" in line
        line = line.lstrip("/")
        if not line:
            continue
        rules.append(_Rule(base, _glob_to_regex(line, anchored), negate, dir_only))
    return rules


class GitIgnore:
    """Every .gitignore of a tree; ``ignored(path)`` answers like ``git check-ignore``."""

    def __init__(self) -> None:
        self.rules: list[_Rule] = []

    def add(self, text: str, base: str = "") -> None:
        if len(self.rules) < MAX_RULES * 5:
            self.rules.extend(parse(text, base))

    def __bool__(self) -> bool:
        return bool(self.rules)

    def _match(self, path: str, is_dir: bool) -> bool | None:
        """The last rule that matches ``path`` decides (True = ignored); None when none matches."""
        verdict = None
        for rule in self.rules:
            if rule.dir_only and not is_dir:
                continue
            if rule.base:
                if not path.startswith(rule.base + "/"):
                    continue
                rel = path[len(rule.base) + 1:]
            else:
                rel = path
            if rule.regex.match(rel):
                verdict = not rule.negate
        return verdict

    def ignored(self, path: str, is_dir: bool = False) -> bool:
        """Whether ``path`` (relative POSIX path) is ignored, itself or through a parent folder."""
        if not self.rules:
            return False
        parts = path.strip("/").split("/")
        for depth in range(1, len(parts)):
            if self._match("/".join(parts[:depth]), True):
                return True  # a file in an ignored folder cannot be re-included
        return bool(self._match("/".join(parts), is_dir))
