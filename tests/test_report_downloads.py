"""Report downloads are named after the session id / report folder, not report.*."""
from __future__ import annotations

import threading
import urllib.request

import pytest
from fastapi.testclient import TestClient

from scopeguard.report import download_name, render_index


@pytest.mark.parametrize("name,filename,expected", [
    ("money-dynocde-001", "report.docx", "money-dynocde-001.docx"),
    ("abc123", "report.md", "abc123.md"),
    ("live-20261122195658", "report.json", "live-20261122195658.json"),
    ('we"ird name/..\\x', "report.docx", "we_ird_name_.._x.docx"),
    ("...", "report.docx", "report.docx"),
])
def test_download_name(name, filename, expected):
    assert download_name(name, filename) == expected


def _make_report(root, name):
    d = root / name
    d.mkdir(parents=True)
    for f, body in (("report.html", "<p>hi</p>"), ("report.md", "# md"), ("report.json", "{}"),
                    ("report.docx", "PK")):
        (d / f).write_text(body, encoding="utf-8")


def test_ws_server_downloads_use_session_id(tmp_path, monkeypatch):
    from pentest_agent import config
    from pentest_agent.websocket_server import app

    monkeypatch.setattr(config.settings, "reports_dir", str(tmp_path))
    _make_report(tmp_path, "sess-42")
    c = TestClient(app)
    for ext in ("docx", "md", "json"):
        r = c.get(f"/reports/sess-42/report.{ext}")
        assert r.status_code == 200
        cd = r.headers["content-disposition"]
        assert cd.startswith("attachment") and f'filename="sess-42.{ext}"' in cd
    view = c.get("/reports/sess-42/")
    assert "content-disposition" not in view.headers  # HTML view stays inline
    assert 'download="sess-42.docx"' in c.get("/reports/").text


def test_cli_server_downloads_use_folder_name(tmp_path):
    from scopeguard.cli import make_report_server

    _make_report(tmp_path, "live-20261122200736")
    httpd = make_report_server(str(tmp_path), 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        with urllib.request.urlopen(f"{base}/live-20261122200736/report.docx") as r:
            assert r.headers["Content-Disposition"] == 'attachment; filename="live-20261122200736.docx"'
        with urllib.request.urlopen(f"{base}/live-20261122200736/") as r:
            assert r.headers.get("Content-Disposition") is None and b"hi" in r.read()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_index_and_html_report_links_carry_download_names(tmp_path):
    _make_report(tmp_path, "s1")
    assert 'download="s1.json"' in render_index(tmp_path)

    from scopeguard.report import write_reports

    result = {"findings": [], "crawled_pages": [], "requests_made": 0, "duration_seconds": 0,
              "external_links_blocked": [], "red_flags": [], "profile": "quick"}
    write_reports(str(tmp_path / "my-session"), "https://example.com", result, "live")
    page = (tmp_path / "my-session" / "report.html").read_text(encoding="utf-8")
    assert 'href="report.docx" download="my-session.docx"' in page
