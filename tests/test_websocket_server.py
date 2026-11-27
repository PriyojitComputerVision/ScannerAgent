"""These tests only exercise the WebSocket endpoint's *rejection* paths
(missing session_id, malformed JSON, schema validation errors, the
authorization gate). They deliberately never send a valid+authorized
payload, because that would kick off `graph.astream(...)`, which fans out
into real recon/DAST/LLM calls -- out of scope for a unit test. The
graph's own node logic (e.g. the authorization gate) is covered directly in
`test_graph_validate_node.py`.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pentest_agent import websocket_server
from pentest_agent.websocket_server import app


def test_ws_rejects_missing_session_id():
    with TestClient(app) as client, client.websocket_connect("/ws") as ws:
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert "session_id" in msg["message"]


def test_ws_rejects_malformed_json():
    with TestClient(app) as client, client.websocket_connect("/ws?session_id=test-ws-1") as ws:
        ws.send_text("{not valid json")
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert "invalid initial message" in msg["message"].lower()



def test_ws_rejects_schema_validation_errors():
    with TestClient(app) as client, client.websocket_connect("/ws?session_id=test-ws-2") as ws:
        ws.send_text(
            json.dumps({"profile": "quick"})
        )

        msg = json.loads(ws.receive_text())

        assert msg["type"] == "error"
        assert msg["message"].lower() == "invalid input"

        # JSON converts tuples into lists.
        assert any(
            tuple(err.get("loc", [])) == ("url",)
            for err in msg["detail"]
        )



def test_ws_rejects_unauthorized_target():
    with TestClient(app) as client, client.websocket_connect("/ws?session_id=test-ws-3") as ws:
        ws.send_text(
            json.dumps(
                {
                    "url": "https://example.com",
                    "profile": "quick",
                    "authorization_confirmed": False,
                }
            )
        )
        msg = json.loads(ws.receive_text())
        assert msg["type"] == "error"
        assert "authorization_confirmed" in msg["message"]  # gate message


def test_healthz():
    # `with` runs the FastAPI lifespan, which builds the LangGraph + checkpointer.
    with TestClient(app) as client:
        resp = client.get("/healthz")
        assert resp.status_code == 200
        ws_idle = {"active": 0, "max_active": 1, "waiting": 0, "max_queue": 50}
        http_idle = {"active": 0, "max_active": 1, "waiting": 0, "max_queue": 50}
        assert resp.json() == {"status": "ok", "graph_initialized": True, "langsmith_tracing": False,
                               "queues": {"websocket": ws_idle, "http": http_idle},
                               "integrations": {"mcp_http": True, "a2a": True}, "cors": False}


def _reports_dir(tmp_path, monkeypatch):
    from pentest_agent.config import settings

    monkeypatch.setattr(settings, "reports_dir", str(tmp_path))
    return tmp_path


def test_report_links_are_validated_urls_of_existing_files(tmp_path, monkeypatch):
    d = _reports_dir(tmp_path, monkeypatch) / "23Nov 0001"
    d.mkdir()
    for name in ("report.html", "report.md", "report.docx"):  # no report.json on disk
        (d / name).write_text("x", encoding="utf-8")
    links = websocket_server.report_links("http://127.0.0.1:8765", "23Nov 0001")
    assert links == {
        "report_url": "http://127.0.0.1:8765/reports/23Nov%200001/",
        "report_html_url": "http://127.0.0.1:8765/reports/23Nov%200001/report.html",
        "report_md_url": "http://127.0.0.1:8765/reports/23Nov%200001/report.md",
        "report_docx_url": "http://127.0.0.1:8765/reports/23Nov%200001/report.docx",
    }


@pytest.mark.parametrize("base, name", [
    ("http://127.0.0.1:8765", "missing-report"),      # nothing on disk
    ("http://127.0.0.1:8765", "../outside"),          # path traversal
    ("ftp://127.0.0.1:8765", "r1"),                   # not http(s)
    ("http://user:pw@127.0.0.1:8765", "r1"),          # credentials in URL
    ("http://", "r1"),                                # no host
])
def test_report_links_send_nothing_when_invalid(tmp_path, monkeypatch, base, name):
    d = _reports_dir(tmp_path, monkeypatch) / "r1"
    d.mkdir()
    (d / "report.html").write_text("x", encoding="utf-8")
    assert websocket_server.report_links(base, name) == {}


def test_report_links_schema_rejects_foreign_file_urls():
    from pydantic import ValidationError

    from pentest_agent.schemas import ReportLinks

    with pytest.raises(ValidationError):
        ReportLinks(report_url="http://127.0.0.1:8765/reports/r1/",
                    report_md_url="http://evil.test/reports/r1/report.md")
    with pytest.raises(ValidationError):
        ReportLinks(report_url="http://127.0.0.1:8765/reports/r1/?x=1")


def test_log_file_receives_warnings_and_errors(tmp_path, monkeypatch):
    import logging

    from pentest_agent import logging_setup

    log = tmp_path / "logs" / "agent.log"
    monkeypatch.setattr(logging_setup.settings, "log_file", str(log))
    path = logging_setup.configure_logging()
    try:
        logging.getLogger("pentest_agent.test").info("info line")
        logging.getLogger("pentest_agent.test").warning("warn line")
        logging.getLogger("uvicorn.error").error("uvicorn line")
        for h in logging.getLogger().handlers:
            h.flush()
        text = log.read_text(encoding="utf-8")
        assert path == log.resolve()
        assert "warn line" in text and "uvicorn line" in text and "info line" not in text
    finally:
        for name in ("", "uvicorn"):
            lg = logging.getLogger(name)
            for h in [h for h in lg.handlers if getattr(h, "baseFilename", "") == str(log.resolve())]:
                lg.removeHandler(h)
                h.close()


def test_no_api_documentation_endpoints():
    """No Swagger UI, ReDoc, OpenAPI schema or OAuth2 redirect page (the API is documented in docs/)."""
    assert app.docs_url is None and app.redoc_url is None and app.openapi_url is None
    client = TestClient(app)
    for path in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect", "/swagger", "/graphql"):
        assert client.get(path).status_code in (401, 404), path
    routes = {getattr(r, "path", "") for r in app.routes}
    assert not routes & {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}


def test_mcp_accepts_bodies_as_large_as_mcp_max_upload_mb_allows(monkeypatch):
    """upload_code sends the .zip base64-encoded: the /mcp body limit follows MCP_MAX_UPLOAD_MB
    (the SDK's 4 MiB default answered HTTP 413 for zips above ~3 MB)."""
    from pentest_agent import websocket_server as ws
    from pentest_agent.config import settings

    monkeypatch.setattr(settings, "mcp_max_upload_mb", 10)
    limit = ws.mcp_request_body_limit()
    assert limit >= 10 * 1024 * 1024 * 4 // 3 + 1024 * 1024
    monkeypatch.setattr(settings, "mcp_max_upload_mb", 1)
    assert ws.mcp_request_body_limit() == 4 * 1024 * 1024  # never below the SDK default
    monkeypatch.setattr(settings, "mcp_max_upload_mb", 10)
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    with TestClient(app) as client:
        big = b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "pad": "' + b"A" * (6 * 1024 * 1024) + b'"}'
        assert client.post("/mcp", content=big, headers=headers).status_code != 413
        huge = b'{"pad": "' + b"A" * (limit + 10) + b'"}'
        assert client.post("/mcp", content=huge, headers=headers).status_code == 413
