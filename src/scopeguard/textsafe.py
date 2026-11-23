"""Remove hyperlinks from text read from scanned websites. Stdlib only.

Page text, script excerpts and response snippets are attacker-controlled. Links
inside them could be clicked in a report, auto-linked by Markdown/Word, or
followed by an LLM, so every piece of site-derived text (finding evidence, page
content given to an LLM) goes through :func:`strip_hyperlinks` first:

* ``<a href="...">text</a>``      -> ``text``
* ``[text](url)`` / ``![alt](url)`` -> ``text`` / ``alt``
* ``href=/src=/action=`` values   -> ``"[link removed]"``
* bare URLs (any scheme, ``www.``, protocol-relative ``//host``) -> ``[link removed]``

Scan metadata such as a finding's ``affected_url`` is not site text and is
handled separately (validated by ``citations.safe_url``).
"""
from __future__ import annotations

import re

LINK_REMOVED = "[link removed]"

_ANCHOR = re.compile(r"<a\b[^>]*>(.*?)</a\s*>", re.IGNORECASE | re.DOTALL)
_MD_LINK = re.compile(r"!?\[([^\]\n]*)\]\(\s*[^)\s]*(?:\s+\"[^\"]*\")?\s*\)")
_LINK_ATTR = re.compile(r"\b(href|src|action|formaction|xlink:href|srcset|poster|data)\s*=\s*"
                        r"(\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_END = r"[^\s<>\"'`)\]}]+"
_URL = re.compile(
    rf"\b(?:https?|ftp|wss?|file|javascript|data|mailto|vbscript):{_END}"   # scheme:...
    rf"|\bwww\.[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:/{_END})?"                     # www.host/path
    rf"|(?<![\w:/])//[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:/{_END})?",     # //host/path
    re.IGNORECASE,
)


def strip_hyperlinks(text: str | None) -> str | None:
    """Return ``text`` with every hyperlink removed (None/empty unchanged)."""
    if not text:
        return text
    out = _ANCHOR.sub(lambda m: m.group(1), text)
    out = _MD_LINK.sub(lambda m: m.group(1), out)
    out = _LINK_ATTR.sub(lambda m: f'{m.group(1)}="{LINK_REMOVED}"', out)
    out = _URL.sub(_replace_url, out)
    return out


def _replace_url(m: re.Match) -> str:
    """Replace the URL but keep sentence punctuation that followed it."""
    url = m.group(0)
    trail = url[len(url.rstrip(".,;:!?")):]
    return LINK_REMOVED + trail
