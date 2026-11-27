"""PEP 8 coding-standard check for uploaded Python code (scopeguard.codestyle): rules, one finding
per rule and file, caps, the sandbox analyzer path, remediation and the report section."""
from __future__ import annotations

import pytest

from scopeguard import codecheck, codestyle, k8s, remediation

BAD = (
    "import os, sys\n"                          # E401
    "from helpers import *\n"                   # F403
    "class order_service:\n"                    # N801
    "    def LoadAll(self, items=[]):\n"        # N802 + B006
    "        try:\n"
    "            pass\n"
    "        except:\n"                         # E722
    "            pass\n"
    "        if items == None:\n"               # E711
    "            return True == items\n"        # E712
    "square = lambda x: x * x\n"                # E731
    "value = 1   \n"                            # W291
    "\tprint(value)\n"                          # W191 (removed below where the file must parse)
)


def test_every_rule_is_found_once_per_file():
    good = BAD.replace("\tprint(value)\n", "")
    hits = codestyle.check_python(good + "x = '" + "a" * 90 + "'")  # long line, no final newline
    assert set(hits) == {"STYLE_MULTIPLE_IMPORTS", "STYLE_WILDCARD_IMPORT", "STYLE_CLASS_NAME", "STYLE_FUNCTION_NAME",
                         "STYLE_MUTABLE_DEFAULT", "STYLE_BARE_EXCEPT", "STYLE_COMPARE_TO_NONE",
                         "STYLE_COMPARE_TO_BOOL", "STYLE_LAMBDA_ASSIGNMENT", "STYLE_TRAILING_WHITESPACE",
                         "STYLE_LINE_TOO_LONG", "STYLE_NO_FINAL_NEWLINE",
                         "STYLE_UNUSED_IMPORT"}  # ruff F401: os and sys are never used
    findings = codestyle.findings_for_file("\n".join(["x = '" + "a" * 90 + "'"] * 20) + "\n", "source/a.py")
    (long_lines,) = findings
    assert long_lines["rid"] == "STYLE_LINE_TOO_LONG" and "20 time(s)" in long_lines["description"]
    assert "(+12 more)" in long_lines["description"] and long_lines["line"] == 1


def test_clean_code_and_framework_names_are_not_flagged():
    clean = ("import os\n\n\nclass OrderService:\n    def visit_Name(self, node):\n        return os.sep\n\n"
             "    def setUp(self):\n        self.items = None\n")
    assert codestyle.check_python(clean) == {}


def test_bugs_hidden_by_style_are_low_and_the_rest_info():
    by = {f["rid"]: f for f in codestyle.findings_for_file(BAD.replace("\tprint(value)\n", ""), "source/a.py")}
    assert {r for r, f in by.items() if f["severity"] == "low"} == {
        "STYLE_BARE_EXCEPT", "STYLE_MUTABLE_DEFAULT", "STYLE_WILDCARD_IMPORT", "STYLE_UNUSED_IMPORT"}
    assert by["STYLE_BARE_EXCEPT"]["cwe"] == "CWE-396" and "(PEP 8 E722)" in by["STYLE_BARE_EXCEPT"]["title"]
    assert "(flake8-bugbear B006)" in by["STYLE_MUTABLE_DEFAULT"]["title"]  # not a PEP 8 code: said so


def test_a_file_that_does_not_parse_gets_line_checks_only():
    hits = codestyle.check_python("def broken(:\n\tpass   \n")
    assert set(hits) == {"STYLE_SYNTAX_ERROR", "STYLE_TAB_INDENT", "STYLE_TRAILING_WHITESPACE"}


def test_indentation_that_is_not_four_spaces():
    assert codestyle.check_python("if True:\n  x = 1\n")["STYLE_INDENT_NOT_4"] == [2]


def test_style_findings_are_capped_so_security_findings_keep_room(tmp_path):
    for i in range(80):
        (tmp_path / f"m{i}.py").write_text("import os, sys\nx = 1   \n", encoding="utf-8")
    (tmp_path / "zz_app.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    res = codecheck.Results()
    codecheck.scan_source(res, str(tmp_path))
    style = [f for f in res.findings if f["title"].startswith("STYLE_")]
    assert len(style) == codestyle.MAX_STYLE_FINDINGS
    assert any(not f["title"].startswith("STYLE_") for f in res.findings)  # security still reported
    assert any("coding-standard" in n["detail"] for n in res.notices)


def test_only_python_files_are_style_checked(tmp_path):
    (tmp_path / "a.js").write_text("var x = 1;   \n", encoding="utf-8")
    res = codecheck.Results()
    codecheck.scan_source(res, str(tmp_path))
    assert not [f for f in res.findings if f["title"].startswith("STYLE_")]


def test_shipped_to_the_sandbox_and_remediated():
    assert "codestyle" in k8s.ANALYZER_MODULES
    assert set(codestyle.STYLE_RULES) <= set(codecheck.RECOMMENDATIONS)
    for rid in codestyle.STYLE_RULES:
        block = remediation.for_rule(rid)
        assert block["group"] == "Coding standard (PEP 8)" and block["references"] == [codestyle.PEP8_URL]
        assert block["summary"] and block["steps"], rid
    assert remediation.for_rule("STYLE_BARE_EXCEPT")["example"]["language"] == "py"


@pytest.mark.parametrize("name", ["app.py", "tools/cli.pyw"])
def test_summary_counts_files_per_rule(name):
    findings = [{"title": "STYLE_BARE_EXCEPT: x", "affected_url": f"source/{name}#L3"},
                {"title": "STYLE_BARE_EXCEPT: x", "affected_url": "source/other.py#L9"},
                {"title": "SQL_STRING_BUILD: y", "affected_url": "source/db.py#L1"}]
    s = codestyle.summary(findings)
    assert s["files_by_rule"] == {"STYLE_BARE_EXCEPT": 2} and s["files_with_issues"] == 2
    assert s["codes"] == {"STYLE_BARE_EXCEPT": "E722"} and s["standard"] == "PEP 8"
