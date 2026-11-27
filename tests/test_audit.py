"""Audit log: hash chain, HMAC, report hashes, redaction, the graph's last node,
server-side records for requests that never reach the graph, API and CLIs."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pentest_agent import api_auth, audit_log, graph, websocket_server
from pentest_agent.config import settings
from scopeguard import audit


@pytest.fixture
def log(tmp_path, monkeypatch):
    path = tmp_path / "audit" / "audit.jsonl"
    monkeypatch.setattr(settings, "audit_log_path", str(path))
    monkeypatch.setattr(settings, "audit_hmac_key", "")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", "")
    return path


def _lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


# ----------------------------------------------------------------- chain
def test_chain_appends_and_verifies(log):
    for i in range(3):
        entry = audit.append({"event": "scan", "session_id": f"s{i}"}, log)
    assert entry["seq"] == 3 and len(entry["hash"]) == 64
    records = audit.read(log)
    assert [r["seq"] for r in records] == [1, 2, 3]
    assert records[1]["prev"] == records[0]["hash"] and records[0]["prev"] == ""
    assert audit.verify(log) == {"ok": True, "records": 3, "problems": [], "unverifiable_hmac_records": 0,
                                 "report_files_removed_by_retention": 0, "last_hash": records[2]["hash"]}


@pytest.mark.parametrize("tamper, problem", [
    (lambda ls: [ls[0], ls[1].replace('"s1"', '"evil"'), ls[2]], "content altered"),
    (lambda ls: [ls[0], ls[2]], "missing or reordered"),
    (lambda ls: [ls[1], ls[0], ls[2]], "chain broken"),
    (lambda ls: [ls[0], "{not json", ls[2]], "not valid JSON"),
])
def test_tampering_is_detected(log, tamper, problem):
    for i in range(3):
        audit.append({"event": "scan", "session_id": f"s{i}"}, log)
    log.write_text("\n".join(tamper(_lines(log))) + "\n", encoding="utf-8")
    result = audit.verify(log)
    assert not result["ok"] and any(problem in p for p in result["problems"])


def test_hmac_records_need_the_key(log):
    audit.append({"event": "scan"}, log, key="k1")
    audit.append({"event": "scan"}, log, key="k1")
    assert audit.verify(log, "k1")["ok"]
    assert audit.verify(log, "wrong")["problems"]
    no_key = audit.verify(log)
    assert not no_key["ok"] and no_key["unverifiable_hmac_records"] == 2
    # Recomputing the plain SHA-256 after an edit is not enough to forge an HMAC record.
    rec = json.loads(_lines(log)[1])
    rec["outcome"] = "completed"
    rec["hash"] = audit._digest(rec, None)
    log.write_text(_lines(log)[0] + "\n" + json.dumps(rec) + "\n", encoding="utf-8")
    assert "content altered" in " ".join(audit.verify(log, "k1")["problems"])


def test_report_hashes_detect_modified_reports(log, tmp_path):
    folder = tmp_path / "reports" / "sess-1"
    folder.mkdir(parents=True)
    (folder / "report.html").write_text("<p>ok</p>", encoding="utf-8")
    audit.append({"event": "scan", "report": {"folder": "sess-1",
                                              "files": {"report.html": audit.file_sha256(folder / "report.html")}}},
                 log)
    assert audit.verify(log, reports_dir=tmp_path / "reports")["ok"]
    (folder / "report.html").write_text("<p>edited</p>", encoding="utf-8")
    assert "was modified" in audit.verify(log, reports_dir=tmp_path / "reports")["problems"][0]
    (folder / "report.html").unlink()
    assert "is missing" in audit.verify(log, reports_dir=tmp_path / "reports")["problems"][0]


# ----------------------------------------------------------------- redaction
@pytest.mark.parametrize("text, secret", [
    ("Authorization: Bearer abc.def.ghi-123456", "abc.def.ghi-123456"),
    ("token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig_value", "eyJzdWIiOiJ4In0"),
    ("password=hunter2&x=1", "hunter2"),
    ('{"api_key": "sk_live_1234567890abcdef"}', "1234567890abcdef"),
    ("GROQ gsk_ABCDEFGHIJKLMNOP1234", "gsk_ABCDEFGHIJKLMNOP1234"),
    ("see https://user:pw@app.test/login?token=s3cret#frag", "s3cret"),
])
def test_scrub_removes_secrets(text, secret):
    assert secret not in audit.scrub(text)


def test_sanitize_url():
    assert audit.sanitize_url("https://u:p@App.test:8443/a/b?x=1#f") == "https://app.test:8443/a/b"


def test_record_has_no_secret_values(tmp_path):
    state = {
        "session_id": "s1", "principal": {"sub": "alice", "roles": ["admin"]},
        "target": {"url": "https://app.test/?api_key=SECRET1", "profile": "standard",
                   "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.SECRET2",
                   "auth": {"username": "bob", "password": "SECRET3"}, "notes": "SECRET4"},
        "error": "login failed with password=SECRET5",
        "findings": [{"severity": "high"}, {"severity": "low"}],
    }
    rec = audit_log.record_from_state(state)
    blob = json.dumps(rec)
    for secret in ("SECRET1", "SECRET2", "SECRET3", "SECRET4", "SECRET5"):
        assert secret not in blob
    assert rec["target"]["jwt_provided"] and rec["target"]["login_provided"]
    assert rec["outcome"] == "failed" and rec["results"]["by_severity"]["high"] == 1


# ----------------------------------------------------------------- graph: last node
def test_audit_node_records_and_ends_the_run(log, tmp_path):
    report = tmp_path / "rep" / "report.md"
    report.parent.mkdir()
    report.write_text("# r", encoding="utf-8")
    cmd = graph.audit_node({"session_id": "g1", "principal": {"sub": "alice", "roles": ["scanner"]},
                            "target": {"url": "http://127.0.0.1:1/"}, "report_md_path": str(report),
                            "node_runs": {"validate": 1, "report": 1}, "phase": "report_complete",
                            "client": {"ip": "127.0.0.1", "via": "websocket"}})
    assert cmd.goto == graph.END and cmd.update["audit"]["outcome"] == "completed"
    (rec,) = audit.read(log)
    assert rec["session_id"] == "g1" and rec["actor"]["sub"] == "alice"
    assert rec["report"] == {"folder": "rep", "files": {"report.md": audit.file_sha256(report)}}
    assert rec["client"]["via"] == "websocket" and rec["steps"] == {"validate": 1, "report": 1}


def test_refused_run_goes_through_the_audit_node(log):
    """A run refused by the guardrails still ends with an audit record (no network)."""
    app = graph.build_graph()
    final = app.invoke({"session_id": "g2", "principal": {"sub": "alice", "roles": ["admin"]},
                        "target": {"url": "http://169.254.169.254/", "session_id": "g2",
                                   "authorization_confirmed": True}},
                       {"recursion_limit": graph.recursion_limit()})
    assert final["phase"] == "blocked" and final["audit"]["outcome"] == "refused"
    (rec,) = audit.read(log)
    assert rec["outcome"] == "refused" and "link-local" in rec["reason"]
    assert rec["steps"] == {"validate": 1, "audit": 1} or rec["steps"].get("validate") == 1


# ----------------------------------------------------------------- server-side records
def test_rejected_websocket_requests_are_audited(log):
    with TestClient(websocket_server.app) as c:  # lifespan: the graph is initialized
        with c.websocket_connect("/ws?session_id=x1", headers={"origin": "http://evil.example"}) as ws:
            ws.receive_text()
        with c.websocket_connect("/ws?session_id=x2") as ws:
            ws.send_text(json.dumps({"url": "https://example.com", "authorization_confirmed": True, "bogus": 1}))
            ws.receive_text()
    records = audit.read(log)
    assert [(r["session_id"], r["outcome"]) for r in records] == [("x1", "rejected"), ("x2", "rejected")]
    assert "cross-origin" in records[0]["reason"] and "bogus" in records[1]["reason"]
    assert audit.verify(log)["ok"]


def test_server_error_before_the_graph_is_audited(log):
    c = TestClient(websocket_server.app)  # no lifespan: the graph is not initialized
    with c.websocket_connect("/ws?session_id=x3") as ws:
        ws.receive_text()
    (rec,) = audit.read(log)
    assert rec["outcome"] == "failed" and "server error" in rec["reason"]


@pytest.fixture
def auth_on(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    for name, value in {"auth_enabled": True, "jwt_private_key_path": str(keys / "p.pem"),
                        "jwt_public_key_path": str(keys / "pub.pem"),
                        "auth_clients_file": str(keys / "c.json"), "reports_dir": str(tmp_path / "reports")}.items():
        monkeypatch.setattr(settings, name, value)
    api_auth.generate_keypair()


def test_api_audit_is_admin_only(log, auth_on):
    audit.append({"event": "scan", "session_id": "a1"}, log)
    c = TestClient(websocket_server.app)
    scanner = {"Authorization": f"Bearer {api_auth.issue_tokens('bob', ['scanner']).access_token}"}
    admin = {"Authorization": f"Bearer {api_auth.issue_tokens('root', ['admin']).access_token}"}
    assert c.get("/api/audit").status_code == 401
    assert c.get("/api/audit", headers=scanner).status_code == 403
    body = c.get("/api/audit", headers=admin).json()
    assert body["verification"]["ok"] and body["records"][0]["session_id"] == "a1"


# ----------------------------------------------------------------- CLIs
def test_cli_scan_attempts_are_audited(log, capsys):
    from scopeguard import cli

    assert cli.main(["--url", "http://169.254.169.254/", "--i-have-authorization"]) == 5
    assert cli.main(["--url", "http://127.0.0.1:9/"]) == 3
    records = audit.read(log)
    assert [r["outcome"] for r in records] == ["refused", "refused"]
    assert "network policy" in records[0]["reason"] and records[0]["client"]["via"] == "cli"
    assert "--i-have-authorization" in records[1]["reason"]


def test_pentest_audit_cli(log, capsys):
    audit.append({"event": "scan", "session_id": "c1", "outcome": "completed"}, log)
    assert audit.main(["verify"]) == 0
    assert "chain intact" in capsys.readouterr().out
    assert audit.main(["show", "c1"]) == 0 and '"c1"' in capsys.readouterr().out
    log.write_text(_lines(log)[0].replace("completed", "refused") + "\n", encoding="utf-8")
    assert audit.main(["verify"]) == 1
    assert "TAMPERED" in capsys.readouterr().out
