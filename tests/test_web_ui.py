"""Browser console (pentest_agent/web_ui.py): static files, demo login, JSON routes, origin check."""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from pentest_agent import api_auth, main, web_ui, websocket_server
from pentest_agent.config import settings
from pentest_agent.websocket_server import app


@pytest.fixture
def auth_on(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    for name, value in {
        "auth_enabled": True,
        "jwt_private_key_path": str(keys / "jwt_private.pem"),
        "jwt_public_key_path": str(keys / "jwt_public.pem"),
        "auth_clients_file": str(keys / "clients.json"),
        "reports_dir": str(tmp_path / "reports"),
    }.items():
        monkeypatch.setattr(settings, name, value)
    api_auth.generate_keypair()
    report = tmp_path / "reports" / "r1"
    report.mkdir(parents=True)
    (report / "report.html").write_text("<p>report</p>", encoding="utf-8")
    (report / "owner.json").write_text('{"v": 1, "sub": "alice"}', encoding="utf-8")  # bearer()'s subject
    (report / "report.json").write_text(json.dumps({
        "target_url": "http://127.0.0.1:9/", "profile": "standard", "pages_crawled": 3,
        "findings": [{"severity": "high"}, {"severity": "low"}, {"severity": "low"}, {"severity": "bogus"}],
    }), encoding="utf-8")
    yield tmp_path
    web_ui.disarm_demo_login()


def bearer(roles=("scanner",), sub="alice") -> dict:
    return {"Authorization": f"Bearer {api_auth.issue_tokens(sub, list(roles)).access_token}"}


# ----------------------------------------------------------------- static files
@pytest.mark.parametrize("path, media", [
    ("/", "text/html"), ("/ui/app.css", "text/css"), ("/ui/app.js", "text/javascript"),
    ("/ui/favicon.png", "image/png"), ("/favicon.ico", "image/png"),
])
def test_ui_files_are_public_with_strict_headers(auth_on, path, media):
    r = TestClient(app).get(path)
    assert r.status_code == 200 and r.headers["content-type"].startswith(media)
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert "connect-src 'self' ws://testserver wss://testserver" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"


@pytest.mark.parametrize("path", ["/ui/", "/ui/index.html", "/ui/../pyproject.toml", "/ui/favicon/favicon.png",
                                  "/ui/%2e%2e/web_ui.py", "/webui/app.js"])
def test_only_whitelisted_files_are_served(path):
    assert TestClient(app).get(path).status_code == 404


def test_hostile_host_header_is_not_reflected_into_csp():
    r = TestClient(app).get("/", headers={"host": "evil.example; script-src *"})
    assert "evil" not in r.headers["content-security-policy"]


def test_ui_has_no_inline_code_and_no_html_sinks():
    html = (web_ui.UI_DIR / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", html), "inline <script> breaks the CSP"
    assert not re.search(r"\sstyle=|\son[a-z]+=", html), "inline style/handler attributes break the CSP"
    assert not re.search(r"""(?:src|href)=["']?(?:https?:)?//""", html), "no third-party resources"
    js = (web_ui.UI_DIR / "app.js").read_text(encoding="utf-8")
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in js, f"{sink} must not be used: render untrusted text with textContent"
    assert "access_token=" not in js, "tokens must never be put in URLs"


def test_favicon_is_a_png():
    assert web_ui.FAVICON_PATH.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"


# ----------------------------------------------------------------- demo login
def test_meta_is_public_and_minimal(auth_on):
    c = TestClient(app)
    assert c.get("/ui/meta").json() == {"auth_enabled": True, "demo_login": False}
    web_ui.arm_demo_login(["admin"])
    assert c.get("/ui/meta").json()["demo_login"] is True


def test_demo_code_is_single_use(auth_on):
    c = TestClient(app)
    code = web_ui.arm_demo_login(["scanner"])
    r = c.post("/ui/demo-login", json={"code": code})
    assert r.status_code == 200
    claims = api_auth.verify_token(r.json()["access_token"])
    assert claims["roles"] == ["scanner"] and claims["sub"] == "demo-console"
    assert c.post("/ui/demo-login", json={"code": code}).status_code == 401  # used up


def test_demo_code_rejects_wrong_and_expired(auth_on, monkeypatch):
    c = TestClient(app)
    code = web_ui.arm_demo_login(["admin"])
    assert c.post("/ui/demo-login", json={"code": "x" * 43}).status_code == 401
    assert c.post("/ui/demo-login", json={"code": code, "extra": 1}).status_code == 422
    assert c.post("/ui/demo-login", json={"code": code}).status_code == 200  # a wrong guess does not burn it
    code = web_ui.arm_demo_login(["admin"], ttl=-1)
    assert c.post("/ui/demo-login", json={"code": code}).status_code == 401


def test_demo_login_is_off_without_auth():
    code = web_ui.arm_demo_login(["admin"])
    try:
        assert TestClient(app).post("/ui/demo-login", json={"code": code}).status_code == 404
    finally:
        web_ui.disarm_demo_login()


# ----------------------------------------------------------------- JSON routes
def test_api_routes_need_a_token(auth_on):
    c = TestClient(app)
    for path in ("/api/info", "/api/reports"):
        assert c.get(path).status_code == 401
    assert c.post("/api/report-cookie").status_code == 401


def test_api_reports_lists_report_summaries(auth_on):
    r = TestClient(app).get("/api/reports", headers=bearer(("viewer",)))
    assert r.status_code == 200
    (item,) = r.json()["reports"]
    assert item["name"] == "r1" and item["files"] == ["report.html", "report.json"]
    assert item["severity_counts"] == {"critical": 0, "high": 1, "medium": 0, "low": 2, "info": 0}
    assert item["target_url"] == "http://127.0.0.1:9/" and item["pages_crawled"] == 3
    # another user's reports are not listed
    assert TestClient(app).get("/api/reports", headers=bearer(("scanner",), sub="bob")).json()["reports"] == []


def test_api_info_reports_caller_permissions(auth_on):
    web_ui.set_demo_target("http://127.0.0.1:5555")
    try:
        info = TestClient(app).get("/api/info", headers=bearer(("scanner",))).json()
    finally:
        web_ui.set_demo_target(None)
    assert info["subject"] == "alice" and info["roles"] == ["scanner"]
    assert "scan:run" in info["permissions"] and "scan:aggressive" not in info["permissions"]
    assert info["demo_target"] == "http://127.0.0.1:5555"
    assert "groq_api_key" not in json.dumps(info)


def test_report_cookie_opens_report_views_without_a_token_in_the_url(auth_on):
    c = TestClient(app)
    assert c.get("/reports/r1/").status_code == 401
    r = c.post("/api/report-cookie", headers=bearer(("viewer",)))
    assert r.status_code == 204
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/reports" in cookie
    assert c.get("/reports/r1/").status_code == 200  # cookie only


# ----------------------------------------------------------------- WebSocket origin
@pytest.mark.parametrize("origin, ok", [
    (None, True), ("http://testserver", True), ("https://testserver", True),
    ("http://evil.example", False), ("http://testserver.evil.example", False), ("null", False),
])
def test_cross_origin_error(origin, ok):
    headers = {"host": "testserver", **({"origin": origin} if origin else {})}
    assert (websocket_server.cross_origin_error(SimpleNamespace(headers=headers)) is None) is ok


def test_cross_origin_websocket_is_rejected():
    c = TestClient(app)
    with c.websocket_connect("/ws?session_id=s1", headers={"origin": "http://evil.example"}) as ws:
        msg = json.loads(ws.receive_text())
        assert msg["code"] == 403 and "cross-origin" in msg["message"]
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_text()
    assert exc.value.code == websocket_server.WS_FORBIDDEN_CLOSE_CODE


# ----------------------------------------------------------------- launcher
def test_pentest_agent_starts_the_console(monkeypatch):
    calls = []
    monkeypatch.setattr("pentest_agent.demo.launch", lambda **kw: calls.append(kw) or 0)
    assert main.run([]) == 0
    assert calls[-1] == {"host": settings.ws_host, "port": settings.ws_port,
                         "open_browser": True, "start_target": True}
    main.run(["--no-browser", "--no-target", "--port", "9999"])
    assert calls[-1]["port"] == 9999 and not calls[-1]["open_browser"] and not calls[-1]["start_target"]


def test_live_findings_merge_like_the_report():
    """The console counts one finding per issue + URL, like pentest_agent/dedupe.py: its header
    list must match the report's, and the grade explains its score."""
    from pathlib import Path

    from pentest_agent import dedupe

    js = (Path(web_ui.__file__).parent / "webui" / "app.js").read_text(encoding="utf-8")
    block = js[js.index("const HEADER_KEYS = ["):js.index("];", js.index("const HEADER_KEYS = ["))]
    assert re.findall(r"\['([a-z-]+)'", block) == [key for key, _ in dedupe._HEADER_KEYS]
    assert "missing|absent|no|not set|lacks?" in js and "if (addFinding(f)) addBlip(f);" in js
    assert "Risk score = " in js and "$('grade').title" in js
