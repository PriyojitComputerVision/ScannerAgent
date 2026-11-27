"""Red-flag levels (scopeguard/flag_levels.py): errors, warnings and scope notes, the same in the
reports, get_scan and the browser console (its FLAG_RULES mirror)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from scopeguard import flag_levels

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("text, level", [
    (("Website content loads code or submits data to other hosts outside the scan scope (not downloaded): "
     "groqstatus.com (fetch), js.stripe.com (script)"), "note"),
    ("Website links to 34 other host(s) outside the scan scope (not visited): anchorbrowser.io", "note"),
    ("robots.txt/sitemaps/security.txt point to 3 other site(s) outside the scan scope (not fetched): x", "note"),
    ("Sandbox notice (bundle): the zip is a copy of the source", "note"),
    ("Kubernetes is not available; the checks ran in the process sandbox instead.", "note"),
    ("Operator skipped the sso step; only unauthenticated coverage runs.", "note"),
    ("SSO login failed: the session handed over after sign-in was not accepted (HTTP 401)", "error"),
    ("MFA sign-in failed: the one-time code was not accepted (HTTP 200)", "error"),
    ("SANDBOX VIOLATION: 2 blocked attempt(s) to reach outside the sandbox.", "error"),
    ("Native DAST failed: boom", "error"),
    ("Safety stop: step 'dast' already ran 3 time(s)", "error"),
    ("Login URL https://idp.test/login is outside the scan scope; it was not requested.", "warn"),
    ("A login form was detected but no JWT or credentials were supplied as input.", "warn"),
    ("Signed in with the stored session, but it could not be proven (HTTP 200).", "warn"),
    ("Custom probes skipped: role(s) scanner lack permission 'scan:probes'.", "warn"),
])
def test_each_flag_gets_its_level(text, level):
    assert flag_levels.level(text) == level


def test_order_and_grouping():
    flags = ["Website links to 2 other host(s) outside the scan scope (not visited): a, b",
             "A login form was detected but no JWT", "SSO login failed: x"]
    assert flag_levels.ordered(flags) == [flags[2], flags[1], flags[0]]
    assert flag_levels.by_level(flags) == {"error": [flags[2]], "warn": [flags[1]], "note": [flags[0]]}
    assert flag_levels.label(flags[0]) == "Note"


def test_the_console_mirrors_the_rules():
    js = (ROOT / "src" / "pentest_agent" / "webui" / "app.js").read_text(encoding="utf-8")
    mirrored = re.findall(r"\['(error|warn|note)', String\.raw`([^`]*)`\]", js)
    assert mirrored == list(flag_levels.RULES)


def test_reports_label_flags_instead_of_calling_everything_red():
    from scopeguard.report import render_html

    html = render_html(title="t", meta=[], summary=None, findings=[], sources={}, blocked=[],
                       red_flags=["Website links to 2 other host(s) outside the scan scope (not visited): a",
                                  "SSO login failed: x"])
    assert html.index("SSO login failed") < html.index("not visited")
    assert '<li class="flag note"><b>Note</b>' in html and '<li class="flag error"><b>Error</b>' in html
