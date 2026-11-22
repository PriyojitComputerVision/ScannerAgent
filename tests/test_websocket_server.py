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

from fastapi.testclient import TestClient

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
        assert resp.json() == {"status": "ok", "graph_initialized": True, "langsmith_tracing": False}
