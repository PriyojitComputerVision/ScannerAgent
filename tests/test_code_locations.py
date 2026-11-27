"""Per-rule file + line lists in code recommendations, and project paths without internal folders."""
from __future__ import annotations

from pentest_agent import code_upload
from scopeguard import codecheck, report


def _f(rule: str, loc: str, sev: str = "high") -> dict:
    return {"title": f"{rule}: x", "severity": sev, "affected_url": loc}


def test_recommendations_list_every_location_sorted_and_deduplicated():
    recs = codecheck.build_recommendations([
        _f("PY_EVAL_EXEC", "source/b.py#L9"), _f("PY_EVAL_EXEC", "source/a.py#L30"),
        _f("PY_EVAL_EXEC", "source/a.py#L4"), _f("PY_EVAL_EXEC", "source/a.py#L4"),
        _f("PIPE_TO_SHELL", "source/README.md")])
    by = {r["rule"]: r for r in recs}
    assert by["PY_EVAL_EXEC"]["locations"] == [{"file": "source/a.py", "line": 4}, {"file": "source/a.py", "line": 30},
                                               {"file": "source/b.py", "line": 9}]
    assert by["PY_EVAL_EXEC"]["locations_total"] == 3 and by["PY_EVAL_EXEC"]["count"] == 4
    assert by["PIPE_TO_SHELL"]["locations"] == [{"file": "source/README.md", "line": None}]


def test_locations_are_capped_but_counted(monkeypatch):
    monkeypatch.setattr(codecheck, "MAX_LOCATIONS_PER_RULE", 2)
    rec = codecheck.build_recommendations([_f("R", f"source/x.py#L{n}") for n in range(1, 6)])[0]
    assert len(rec["locations"]) == 2 and rec["locations_total"] == 5
    rows = report.location_lines(rec)
    assert rows[0] == ("source/x.py", "lines 1, 2") and rows[-1][1].startswith("+3 more location(s)")


def test_project_location_drops_only_internal_folders():
    assert code_upload.project_location("source/source/src/app.py#L82", "git") == "src/app.py#L82"
    assert code_upload.project_location("source/app/x.py#L3", "zip") == "app/x.py#L3"
    assert code_upload.project_location("source/app/x.py#L3", "files") == "app/x.py#L3"
    # a real top-level "source" folder in your own zip stays
    assert code_upload.project_location("source/source/x.py#L1", "zip") == "source/x.py#L1"
    assert code_upload.project_location("upload/evil.zip", "zip") == "evil.zip"
    assert code_upload.project_location(None, "git") is None


def test_project_recommendations_rewrite_example_and_locations():
    recs = codecheck.build_recommendations([_f("R", "source/source/a.py#L2"), _f("R", "source/source/b.py#L7")])
    out = code_upload.project_recommendations(recs, "git")[0]
    assert out["example"] == "a.py#L2"
    assert [loc["file"] for loc in out["locations"]] == ["a.py", "b.py"]
    assert recs[0]["example"] == "source/source/a.py#L2"  # input left unchanged


def test_where_heading_and_markdown_group_lines_per_file():
    rec = {"locations": [{"file": "a.py", "line": 4}, {"file": "a.py", "line": 30}, {"file": "b.py", "line": 9}],
           "locations_total": 3}
    assert report.where_heading(rec) == "Where (3 locations in 2 files)"
    assert report.location_markdown(rec) == ["- `a.py`: lines 4, 30", "- `b.py`: line 9"]


def test_older_recommendations_without_locations_use_the_example():
    assert report.location_groups({"example": "app/x.py#L12"}) == [("app/x.py", [12])]
    assert report.location_groups({}) == []


def test_html_escapes_file_names():
    html = report.render_html(title="t", meta=[], summary=None, findings=[], sources={}, red_flags=[], blocked=[],
                              recommendations=[{"rule": "R", "severity": "high", "count": 1,
                                                "locations": [{"file": "<img src=x>.py", "line": 1}]}])
    assert "<img src=x>" not in html and "&lt;img src=x&gt;.py" in html


def test_a_step_that_repeats_the_summary_is_not_printed_twice(tmp_path):
    from docx import Document

    from scopeguard.docx_report import build_docx

    rem = {"summary": "Revoke the key pair.", "steps": ["Revoke the key pair.", "Keep keys server-side."]}
    assert report.distinct_steps(rem) == ["Keep keys server-side."]
    assert report.distinct_steps({"summary": "A", "steps": ["A"]}) == []
    rec = {"rule": "PRIVATE_KEY", "severity": "critical", "count": 1, "cwe": "CWE-321",
           "recommendation": "Revoke the key pair.", "remediation": rem,
           "locations": [{"file": "app/k.py", "line": 3}], "locations_total": 1}
    md = "\n".join(report.remediation_markdown([rec]))
    assert md.count("Revoke the key pair.") == 1 and "1. Keep keys server-side." in md
    html = report.render_html(title="t", meta=[], summary=None, findings=[], sources={}, red_flags=[], blocked=[],
                              recommendations=[rec])
    assert html.count("<li>Revoke the key pair.</li>") == 0
    path = build_docx(tmp_path / "r.docx", title="t", target="x", meta=[], summary=None, findings=[], sources={},
                      red_flags=[], blocked=[], recommendations=[rec])
    text = [p.text for p in Document(str(path)).paragraphs]
    assert text.count("Revoke the key pair.") == 1 and "app/k.py: line 3" in text
