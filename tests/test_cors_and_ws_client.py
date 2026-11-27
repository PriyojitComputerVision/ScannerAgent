"""CORS (pentest_agent/cors.py), its WebSocket Origin rule, and the ws_client pretty printer."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from pentest_agent import cors, websocket_server
from pentest_agent.config import settings

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def origins(monkeypatch):
    def set_origins(value: str) -> None:
        monkeypatch.setattr(settings, "cors_allowed_origins", value)
    yield set_origins
    cors._cached.cache_clear()


# ------------------------------------------------------------------ parsing
@pytest.mark.parametrize("value, expected", [
    ("http://localhost:5173", "http://localhost:5173"),
    ("HTTPS://App.Example.COM/", "https://app.example.com"),
    ("https://app.example.com:443", "https://app.example.com"),
    ("http://[::1]:8080", "http://[::1]:8080"),
    ("*", None), ("null", None), ("", None),
    ("https://*.example.com", None), ("https://app.example.com/path", None),
    ("https://user:pw@app.example.com", None), ("ftp://app.example.com", None),
    ("app.example.com", None), ("https://app.example.com?x=1", None),
])
def test_normalize_origin(value, expected):
    assert cors.normalize_origin(value) == expected


def test_parse_origins_dedupes_and_reports_refused():
    valid, refused = cors.parse_origins("http://a.test, *, HTTP://A.test/, https://b.test:8443, null")
    assert valid == ["http://a.test", "https://b.test:8443"]
    assert refused == ["*", "null"]


def test_cors_is_off_by_default(origins):
    origins("")
    assert cors.status() == {"enabled": False, "allowed_origins": []}
    assert cors.install(FastAPI()) == []
    assert not cors.origin_allowed("http://localhost:5173")


# ------------------------------------------------------------------ HTTP
def _app_with_cors(origins_fixture, value: str) -> TestClient:
    origins_fixture(value)
    app = FastAPI()

    @app.middleware("http")
    async def deny_everything(request, call_next):  # stands in for require_auth
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "missing bearer token"}, status_code=401)

    assert cors.install(app) == [cors.normalize_origin(v) for v in value.split(",")]
    return TestClient(app)


def test_preflight_is_answered_before_auth(origins):
    client = _app_with_cors(origins, "http://localhost:5173")
    r = client.options("/api/integrations", headers={
        "Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "authorization" in r.headers["access-control-allow-headers"].lower()
    assert "access-control-allow-credentials" not in r.headers


def test_error_responses_carry_cors_headers_for_allowed_origin_only(origins):
    client = _app_with_cors(origins, "http://localhost:5173")
    ok = client.get("/x", headers={"Origin": "http://localhost:5173"})
    assert ok.status_code == 401 and ok.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert "x-new-access-token" in ok.headers["access-control-expose-headers"].lower()
    evil = client.get("/x", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in evil.headers
    refused = client.options("/x", headers={"Origin": "http://evil.example",
                                            "Access-Control-Request-Method": "GET"})
    assert refused.status_code == 400


# ------------------------------------------------------------------ WebSocket origin
def test_ws_accepts_only_listed_cross_origins(origins):
    def err(origin):
        return websocket_server.cross_origin_error(
            SimpleNamespace(headers={"host": "127.0.0.1:8765", "origin": origin}))

    origins("")
    assert err("http://localhost:5173") is not None
    origins("http://localhost:5173")
    assert err("http://localhost:5173") is None
    assert err("http://LOCALHOST:5173/") is None
    assert err("http://evil.example") is not None
    assert err("null") is not None
    assert err("http://127.0.0.1:8765") is None  # same origin as before


def test_healthz_shows_only_the_cors_flag(origins):
    origins("http://localhost:5173")
    body = TestClient(websocket_server.app).get("/healthz").json()
    assert body["cors"] is True and "localhost:5173" not in json.dumps(body)


# ------------------------------------------------------------------ ws_client
@pytest.fixture(scope="module")
def ws_client():
    spec = importlib.util.spec_from_file_location("ws_client", ROOT / "scripts" / "ws_client.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sent_frames_mask_secrets_and_keep_shape(ws_client):
    frame = {"access_token": "eyJ.secret.sig", "url": "http://t.test/", "authorization_confirmed": True,
             "auth": {"username": "u", "password": "hunter2"}, "profile": "quick"}
    text = ws_client.format_frame("sent", frame, ws_client.Style(False), max_str=None)
    assert ">>> SENT" in text and "scan request" in text
    assert "eyJ.secret.sig" not in text and "hunter2" not in text
    assert '"url": "http://t.test/"' in text and '"profile": "quick"' in text
    assert "\033[" not in text  # no colour codes when disabled


def test_mfa_code_masked_only_in_auth_response(ws_client):
    answer = ws_client.mask_secrets({"type": "auth_response", "action": "mfa_code", "code": "123456"},
                                    frame_type="auth_response")
    assert answer["code"].startswith("***")
    error = ws_client.mask_secrets({"type": "error", "code": 422}, frame_type="error")
    assert error["code"] == 422


def test_received_frames_shorten_long_strings(ws_client):
    msg = {"type": "complete", "report_md": "x" * 1000}
    text = ws_client.format_frame("received", msg, ws_client.Style(False), max_str=50)
    assert "<<< RECV" in text and "(+950 chars)" in text


def test_colour_output_is_valid_json_once_stripped(ws_client):
    import re
    msg = {"type": "phase_update", "node": "recon", "data": {"n": 3, "ok": True, "x": None}}
    text = ws_client.colorize_json(json.dumps(msg, indent=2), ws_client.Style(True))
    assert "\033[" in text
    assert json.loads(re.sub(r"\033\[[0-9;]*m", "", text)) == msg


@pytest.mark.parametrize("request_type, expected", [
    ("scan_scope", {"type": "scope_response", "scope": "website"}),
    ("code_source", {"type": "code_response", "action": "skip"}),
    ("sign_in", {"type": "auth_response", "action": "skip"}),
])
def test_pauses_get_the_matching_answer_type(ws_client, monkeypatch, request_type, expected):
    monkeypatch.setattr(ws_client, "_interactive", lambda: False)
    args = argparse.Namespace(scope_answer=None, code_answer_upload=None, code_answer_git=None)
    msg = {"type": "input_required", "request": {"type": request_type, "default": "website",
                                                 "options": [{"value": "website"}, {"value": "code"}]}}
    assert ws_client.answer_pause(msg, args) == expected


def test_pause_flags_answer_without_prompt(ws_client, monkeypatch):
    monkeypatch.setattr(ws_client, "_interactive", lambda: False)
    args = argparse.Namespace(scope_answer="code", code_answer_upload="a" * 32, code_answer_git=None)
    scope = {"request": {"type": "scan_scope", "default": "website",
                         "options": [{"value": "website"}, {"value": "code"}]}}
    assert ws_client.answer_pause(scope, args) == {"type": "scope_response", "scope": "code"}
    code = {"request": {"type": "code_source"}}
    assert ws_client.answer_pause(code, args) == {"type": "code_response", "action": "upload",
                                                  "upload_id": "a" * 32}


def test_build_payload_code_only_has_no_url(ws_client):
    args = ws_client._parse_args(["--scope", "code", "--upload-id", "b" * 32, "--i-have-authorization"])
    body = ws_client.build_payload(args, None)
    assert "url" not in body and body["scan_scope"] == "code" and body["upload_id"] == "b" * 32
    assert body["authorization_confirmed"] is True


def test_real_target_needs_authorization_flag(ws_client):
    with pytest.raises(SystemExit):
        ws_client._parse_args(["https://app.example"])


def test_integrations_list_the_websocket_and_cors(origins):
    origins("http://localhost:5173")
    info = websocket_server.integrations_status("http://127.0.0.1:8765")["websocket"]
    assert info["url"] == "ws://127.0.0.1:8765/ws?session_id=<id>"
    assert info["cors"] == {"enabled": True, "allowed_origins": ["http://localhost:5173"]}
    assert websocket_server.integrations_status("https://scan.example")["websocket"]["url"].startswith("wss://")
    assert any(line.startswith("CORS") for line in websocket_server.integrations_summary("http://127.0.0.1:8765"))


def _feed(monkeypatch, module, answers):
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))


def test_wizard_website_and_git_code(ws_client, monkeypatch):
    _feed(monkeypatch, ws_client, [
        "", "2", "https://app.example", "1",          # server, website, URL, authorized
        "4", "https://github.com/o/r.git", "main",    # git code + branch
        "", "shop.app.example", "",                  # website + code, extra domain, no SSO
        "1", "2", "hello", "t-1", "", ""])           # quick, no cache, notes, session, frames, start
    args = ws_client._parse_args(["-i"])
    body = ws_client.build_payload(args, args.url)
    assert body["url"] == "https://app.example" and body["git_url"] == "https://github.com/o/r.git"
    assert body["git_ref"] == "main" and body["scan_scope"] == "website_and_code"
    assert body["additional_allowed_domains"] == ["shop.app.example"] and body["profile"] == "quick"
    assert body["force_refresh"] is True and body["notes"] == "hello" and body["authorization_confirmed"]
    assert args.session_id == "t-1" and args.frames


def test_wizard_code_only_from_local_folder(ws_client, monkeypatch, tmp_path):
    (tmp_path / "app.py").write_text("print(1)\n")
    _feed(monkeypatch, ws_client, ["", "3", "1", str(tmp_path), "1", "", "", "s-2", "2", ""])
    args = ws_client._parse_args(["-i"])
    body = ws_client.build_payload(args, None)
    assert "url" not in body and body["scan_scope"] == "code" and args.code_path == tmp_path
    assert body["upload_id"].startswith("<id returned by uploading")  # real id after the upload


def test_wizard_stops_without_authorization(ws_client, monkeypatch):
    _feed(monkeypatch, ws_client, ["", "2", "https://app.example", ""])  # default answer is "No"
    with pytest.raises(SystemExit) as exc:
        ws_client._parse_args(["-i"])
    assert exc.value.code == 1


def test_menus_reject_bad_input_and_accept_values(ws_client, monkeypatch, capsys):
    _feed(monkeypatch, ws_client, ["9", "x", "standard"])
    assert ws_client.choose("Profile", ws_client.PROFILES) == "standard"
    assert "number from 1 to 4" in capsys.readouterr().out


def test_zip_code_skips_vcs_and_dependencies(ws_client, tmp_path):
    import io
    import zipfile
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "main.py").write_text("x = 1\n")
    for junk in (".git", "node_modules", ".venv"):
        (tmp_path / junk).mkdir()
        (tmp_path / junk / "f.txt").write_text("no")
    data, name = ws_client.zip_code(tmp_path)
    assert name.endswith(".zip")
    assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["pkg/main.py"]
