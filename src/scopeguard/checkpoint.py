"""Checkpoint state for resumable code checks. Stdlib only.

The analyzers (``codecheck --stream``, ``upload_worker``) print JSON lines:
``{"type": "checkpoint", "done": [...], "findings": [...], ...}`` after every batch
of finished files, and ``{"type": "result", ...}`` at the end. When a run dies (out
of memory, pod evicted, timeout) the lines it printed before dying are still read
back here, so the next attempt receives ``done`` and skips those files instead of
re-running the whole check. :meth:`CheckpointState.save` persists the state, so a
later run (e.g. after a server restart) resumes too.
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile

VERSION = 1
_NUMERIC_STATS = ("source_files", "source_bytes", "site_files", "skipped_files", "symlinks_outside")


def _fkey(f: dict) -> tuple:
    return (f.get("source"), str(f.get("title", "")).split(":", 1)[0], f.get("affected_url"),
            (f.get("evidence") or "")[:120])


class CheckpointState:
    def __init__(self, fingerprint: str = "") -> None:
        self.fingerprint = fingerprint        # e.g. archive sha256: never resume a different input
        self.done: set[str] = set()
        self.findings: list[dict] = []
        self.notices: list[dict] = []
        self.refs: dict[tuple, dict] = {}
        self.violations: list[dict] = []
        self.attempts: list[dict] = []
        self.archive: dict | None = None
        self._stats_prev: dict = {}           # finished attempts, summed
        self._stats_cur: dict = {}            # latest stats of the running attempt
        self._keys: set[tuple] = set()

    # ------------------------------------------------------------------ absorbing output
    def begin_attempt(self) -> None:
        for k, v in self._stats_cur.items():
            if isinstance(v, int):
                self._stats_prev[k] = self._stats_prev.get(k, 0) + v
        self._stats_cur = {}

    def _add_findings(self, items) -> None:
        for f in items or []:
            if not isinstance(f, dict):
                continue
            k = _fkey(f)
            if k not in self._keys:
                self._keys.add(k)
                self.findings.append(f)

    def _add_common(self, line: dict) -> None:
        self._add_findings(line.get("findings"))
        for n in line.get("notices") or []:
            if isinstance(n, dict) and n not in self.notices and len(self.notices) < 400:
                self.notices.append(n)
        for r in line.get("external_references") or []:
            if isinstance(r, dict) and r.get("host"):
                self.refs[(r["host"], r.get("kind"))] = r
        if isinstance(line.get("stats"), dict):
            self._stats_cur = dict(line["stats"])
        if isinstance(line.get("archive"), dict):
            self.archive = line["archive"]

    def absorb(self, stdout: str) -> dict | None:
        """Read every complete JSON line; return the ``result`` line when the run finished."""
        final = None
        for raw in (stdout or "").splitlines():
            raw = raw.strip()
            if not raw.startswith("{"):
                continue
            try:
                line = json.loads(raw)
            except ValueError:
                continue  # a line cut off by the crash
            kind = line.get("type")
            if kind == "checkpoint":
                self.done.update(str(k) for k in line.get("done") or [] if isinstance(k, str))
                self._add_common(line)
            elif kind == "result":
                self._add_common(line)
                for v in line.get("violations") or []:
                    if v not in self.violations:
                        self.violations.append(v)
                final = line
        return final

    # ------------------------------------------------------------------ result
    def stats(self) -> dict:
        out = dict(self._stats_cur)
        for k in _NUMERIC_STATS:
            if k in self._stats_prev or k in out:
                out[k] = self._stats_prev.get(k, 0) + int(out.get(k, 0) or 0)
        return out

    def merged(self, final: dict) -> dict:
        """The final result over every attempt (findings de-duplicated)."""
        from scopeguard.codecheck import build_recommendations

        out = dict(final)
        out["findings"] = list(self.findings)
        out["notices"] = list(self.notices)
        out["violations"] = list(self.violations)
        out["external_references"] = sorted(self.refs.values(), key=lambda r: (not r.get("risky"), r["host"]))
        out["stats"] = self.stats()
        out["recommendations"] = build_recommendations(self.findings)
        out.pop("type", None)
        out["ok"] = True
        return out

    # ------------------------------------------------------------------ persistence
    def to_json(self) -> dict:
        return {"version": VERSION, "fingerprint": self.fingerprint, "done": sorted(self.done),
                "findings": self.findings, "notices": self.notices, "refs": list(self.refs.values()),
                "violations": self.violations, "attempts": self.attempts, "archive": self.archive,
                "stats_prev": self._stats_prev, "stats_cur": self._stats_cur}

    @classmethod
    def from_json(cls, data: dict, fingerprint: str = "") -> CheckpointState:
        st = cls(fingerprint)
        if data.get("version") != VERSION or (fingerprint and data.get("fingerprint") != fingerprint):
            return st  # different input or format: start over
        st.done = {str(k) for k in data.get("done") or []}
        st._add_findings(data.get("findings"))
        st.notices = list(data.get("notices") or [])
        st.refs = {(r["host"], r.get("kind")): r for r in data.get("refs") or [] if r.get("host")}
        st.violations = list(data.get("violations") or [])
        st.attempts = list(data.get("attempts") or [])
        st.archive = data.get("archive")
        st._stats_prev = dict(data.get("stats_prev") or {})
        st._stats_cur = dict(data.get("stats_cur") or {})
        return st

    def save(self, path: str) -> None:
        """Atomic write (temp file + replace), owner-only permissions."""
        folder = os.path.dirname(os.path.abspath(path))
        os.makedirs(folder, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".checkpoint-", dir=folder)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.to_json(), fh)
            with contextlib.suppress(OSError):
                os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.remove(tmp)
            raise

    @classmethod
    def load(cls, path: str | None, fingerprint: str = "") -> CheckpointState:
        if not path or not os.path.isfile(path):
            return cls(fingerprint)
        try:
            with open(path, encoding="utf-8") as fh:
                return cls.from_json(json.load(fh), fingerprint)
        except (OSError, ValueError, TypeError, KeyError):
            return cls(fingerprint)

    def resume_payload(self) -> dict:
        return {"done": sorted(self.done)}

    @property
    def last_attempt_oom(self) -> bool:
        return bool(self.attempts) and self.attempts[-1].get("outcome") == "oom"
