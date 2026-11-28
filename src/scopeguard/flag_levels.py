"""How serious a red flag is (stdlib only): ``error``, ``warn`` or ``note``.

Red flags are plain sentences from many steps. Most are not failures: a page that links to 34
other sites, or loads Stripe's script, is recorded and never contacted because of the scan scope.
This classifier gives every flag a level, so reports, the console and the chatbot label it right:

* ``error``: something failed: a sign-in ("SSO login failed: ..."), a step, the sandbox, a guardrail.
* ``warn``: coverage is reduced: no credentials for a login form, an unproven session, a
  role without a permission, rate limiting, a partial code scan.
* ``note``: information about the scope: hosts outside it (not visited / not downloaded), an
  expected sandbox fallback, a sign-in the operator chose to skip.

The rules are tried in order; the first match wins; no match = ``warn``. The browser console
mirrors ``RULES`` (``FLAG_RULES`` in webui/app.js; ``tests/test_flag_levels.py`` keeps them equal),
so every pattern must be valid in both Python and JavaScript (no inline flags, no named groups).
"""
from __future__ import annotations

import re

ERROR, WARN, NOTE = "error", "warn", "note"
LEVELS = (ERROR, WARN, NOTE)
LABELS = {ERROR: "Error", WARN: "Warning", NOTE: "Note"}

RULES: tuple[tuple[str, str], ...] = (
    (ERROR, (r"\b(failed|crashed|violation)\b|not accepted|raised an error|safety stop|could not be written"
            r"|prompt injection|unreachable|refused")),
    (WARN, r"^login url .* outside the scan scope"),
    (NOTE, (r"outside the scan scope|not visited|not downloaded|not fetched|sandbox notice"
           r"|in the process sandbox instead|operator skipped|redirects to another host"
           r"|slowed down to [0-9]+ request")),
)
_COMPILED = tuple((lvl, re.compile(src, re.IGNORECASE)) for lvl, src in RULES)


def level(text: object) -> str:
    """``error`` | ``warn`` | ``note`` for one red-flag sentence."""
    s = str(text or "")
    for lvl, rx in _COMPILED:
        if rx.search(s):
            return lvl
    return WARN


def label(text: object) -> str:
    """"Error" / "Warning" / "Note" for a red-flag sentence."""
    return LABELS[level(text)]


def ordered(flags) -> list[str]:
    """Errors first, then warnings, then notes (stable within a level)."""
    items = [str(f) for f in flags or []]
    return sorted(items, key=lambda f: LEVELS.index(level(f)))


def by_level(flags) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {lvl: [] for lvl in LEVELS}
    for f in flags or []:
        out[level(f)].append(str(f))
    return out
