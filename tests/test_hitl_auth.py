"""SSO / MFA sign-in with a human in the loop (LangGraph interrupt).

Detection is pure; the login flow and the answer handling talk to an
in-memory target (httpx.MockTransport). No real network."""
from __future__ import annotations

import http.server
import json
import threading
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, Interrupt

from pentest_agent import audit_log, graph, rbac, websocket_server
from pentest_agent.config import settings
from pentest_agent.http_retry import RateLimitRetryTransport
from pentest_agent.tools import auth_flow
from pentest_agent.tools.auth_detect import detect_mfa, detect_sso
from scopeguard import engine

ALLOWED = {"app.test"}
LOGIN = "http://app.test/login"
LOGIN_FORM = ('<form method="post" action="/login"><input type="hidden" name="csrf" value="c1">'
              '<input name="username"><input type="password" name="password"></form>')
MFA_FORM = ('<p>Enter the 6-digit code from your authenticator app</p><form method="post" action="/mfa">'
            '<input type="hidden" name="csrf" value="m1"><input name="otp" autocomplete="one-time-code"></form>')


# ----------------------------------------------------------------- detection
@pytest.mark.parametrize("status, location, html, idp", [
    (302, "https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize?client_id=x", "", "login.microsoftonline.com"),
    (302, "https://acme.okta.com/app/sso/saml", "", "acme.okta.com"),
    (200, None, ('<form method="post" action="https://idp.acme.com/sso"><input type="hidden" name="SAMLRequest" '
                 'value="PHNhbWw+"></form>'), "idp.acme.com"),
    (200, None, '<a href="https://accounts.google.com/o/oauth2/v2/auth?client_id=1&redirect_uri=x">Google</a>',
     "accounts.google.com"),
    (200, None, "<h1>Welcome</h1><button>Sign in with SSO</button>", ""),
    (302, "/realms/acme/protocol/openid-connect/auth?client_id=web", "", "app.test"),
])
def test_detect_sso(status, location, html, idp):
    found = detect_sso(LOGIN, status, location, html, ALLOWED)
    assert found and found["kind"] == "sso" and found["idp_host"] == idp


@pytest.mark.parametrize("status, location, html", [
    (200, None, LOGIN_FORM), (302, "/dashboard", ""), (200, None, "<p>Welcome back</p>"),
])
def test_no_sso_on_plain_logins(status, location, html):
    assert detect_sso(LOGIN, status, location, html, ALLOWED) is None


def test_detect_mfa_form_and_redirect():
    mfa = detect_mfa(LOGIN, 200, None, MFA_FORM, ALLOWED)
    assert mfa["action"] == "http://app.test/mfa" and mfa["field"] == "otp" and mfa["hidden"] == {"csrf": "m1"}
    assert detect_mfa(LOGIN, 302, "/account/2fa", "", ALLOWED)["follow"] == "http://app.test/account/2fa"
    assert detect_mfa(LOGIN, 200, None, MFA_FORM.replace('action="/mfa"', 'action="https://evil.test/mfa"'),
                      ALLOWED)["out_of_scope"]
    assert detect_mfa(LOGIN, 200, None, LOGIN_FORM, ALLOWED) is None
    assert detect_mfa(LOGIN, 302, "/dashboard", "", ALLOWED) is None


# ----------------------------------------------------------------- in-memory target
class Target:
    """Password + TOTP login. Records every request (method, path, cookies, form)."""

    def __init__(self, *, mfa=True, sso_redirect=None, good_code="123456"):
        self.mfa, self.sso_redirect, self.good_code = mfa, sso_redirect, good_code
        self.requests = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode())) if request.method == "POST" else {}
        self.requests.append((request.method, request.url.path, request.headers.get("cookie", ""),
                              request.headers.get("authorization", ""), form))
        html = {"content-type": "text/html"}
        if request.url.path == "/login" and request.method == "GET":
            if self.sso_redirect:
                return httpx.Response(302, headers={"location": self.sso_redirect})
            return httpx.Response(200, headers=html, text=LOGIN_FORM)
        if request.url.path == "/login":
            if form.get("password") != "pw":
                return httpx.Response(200, headers=html, text=LOGIN_FORM)
            if self.mfa:
                return httpx.Response(200, headers={**html, "set-cookie": "pre=step1; Path=/"}, text=MFA_FORM)
            return httpx.Response(302, headers={"location": "/", "set-cookie": "sid=full; Path=/"})
        if request.url.path == "/mfa":
            if "pre=step1" in request.headers.get("cookie", "") and form.get("otp") == self.good_code \
                    and form.get("csrf") == "m1":
                return httpx.Response(302, headers={"location": "/", "set-cookie": "sid=full; Path=/"})
            return httpx.Response(200, headers=html, text=MFA_FORM)
        if request.url.path == "/":
            signed_in = "sid=full" in request.headers.get("cookie", "") or request.headers.get("authorization")
            return httpx.Response(200, headers=html, text="<p>dashboard</p>") if signed_in else \
                httpx.Response(302, headers={"location": "/login"})
        return httpx.Response(404)


@pytest.fixture
def target(monkeypatch):
    t = Target()

    def client(*args, **kwargs):
        kwargs.pop("verify", None), kwargs.pop("limits", None)
        return httpx.Client(transport=RateLimitRetryTransport(httpx.MockTransport(t)), **kwargs)

    monkeypatch.setattr(auth_flow, "rate_limited_client", client)
    return t


def _login(interactive, password="pw"):
    return auth_flow.authenticate.invoke({
        "login_form_detected": True, "signup_form_detected": False, "jwt": None,
        "auth_creds": {"username": "u", "password": password}, "login_url": LOGIN,
        "interactive": interactive, "allowed_domains": sorted(ALLOWED)}).update


# ----------------------------------------------------------------- login flow
def test_mfa_page_is_not_counted_as_logged_in(target):
    """Bug fix: HTTP 200 on an MFA page used to be treated as a successful login."""
    up = _login(interactive=False)
    assert up["auth_performed"] is False and up["auth_session_cookies"] == {}
    assert any("Multi-factor authentication is required" in f for f in up["red_flags"])
    assert up["auth_challenge"] == {} and up["phase"] == "auth_complete"


def test_mfa_with_interactive_sign_in_pauses(target):
    up = _login(interactive=True)
    assert up["phase"] == "auth_needs_human" and up["auth_challenge"]["kind"] == "mfa"
    assert up["auth_challenge"]["status"] == "pending" and up["auth_performed"] is False
    assert up["auth_pending"]["cookies"] == {"pre": "step1"}
    assert up["auth_pending"]["form"]["action"] == "http://app.test/mfa"
    assert "step1" not in json.dumps(up["auth_challenge"])  # the public challenge has no secrets


def test_wrong_password_is_not_a_login(target):
    up = _login(interactive=False, password="nope")
    assert up["auth_performed"] is False and any("did not go through" in f for f in up["red_flags"])


def test_login_without_mfa_succeeds(target):
    target.mfa = False
    up = _login(interactive=False)
    assert up["auth_performed"] is True and up["auth_session_cookies"] == {"sid": "full"}


def test_sso_login(target):
    target.sso_redirect = "https://acme.okta.com/oauth2/v1/authorize?client_id=1"
    up = _login(interactive=False)
    assert up["auth_performed"] is False and any("signs in with SSO" in f for f in up["red_flags"])
    assert not any(r[1] == "/login" and r[0] == "POST" for r in target.requests)  # password never sent
    up = _login(interactive=True)
    assert up["auth_challenge"]["kind"] == "sso" and up["auth_challenge"]["idp_host"] == "acme.okta.com"


# ----------------------------------------------------------------- answering the pause
def _pending(target):
    up = _login(interactive=True)
    return up["auth_challenge"], up["auth_pending"]


def test_mfa_code_is_submitted_with_the_pre_mfa_session(target):
    challenge, pending = _pending(target)
    up = auth_flow.resolve_challenge(challenge, pending, {"action": "mfa_code", "code": "123456"},
                                     "http://app.test/", sorted(ALLOWED))
    assert up["auth_performed"] is True and up["auth_session_cookies"]["sid"] == "full"
    assert up["auth_challenge"]["status"] == "signed_in" and up["auth_pending"] == {}
    method, path, cookie, _, form = target.requests[-1]
    assert (method, path) == ("POST", "/mfa") and "pre=step1" in cookie
    assert form == {"csrf": "m1", "otp": "123456"}
    logins = [r for r in target.requests if r[:2] == ("POST", "/login")]
    assert len(logins) == 1  # the password step was not repeated


def test_wrong_mfa_code_fails_closed(target):
    challenge, pending = _pending(target)
    up = auth_flow.resolve_challenge(challenge, pending, {"action": "mfa_code", "code": "000000"},
                                     "http://app.test/", sorted(ALLOWED))
    assert up.get("auth_performed") is not True and up["auth_challenge"]["status"] == "failed"
    assert "000000" not in json.dumps(up)


def test_session_handover_is_verified(target):
    challenge = {"kind": "sso", "status": "pending"}
    ok = auth_flow.resolve_challenge(challenge, {}, {"action": "session", "cookie": "sid=full"},
                                     "http://app.test/", sorted(ALLOWED))
    assert ok["auth_performed"] is True and ok["auth_session_cookies"] == {"sid": "full"}
    bad = auth_flow.resolve_challenge(challenge, {}, {"action": "session", "cookie": "sid=stale"},
                                      "http://app.test/", sorted(ALLOWED))
    assert bad.get("auth_performed") is not True and bad["auth_challenge"]["status"] == "failed"
    assert "stale" not in json.dumps(bad)
    bearer = auth_flow.resolve_challenge(challenge, {}, {"action": "session", "bearer": "tok_abcdefgh123"},
                                         "http://app.test/", sorted(ALLOWED))
    assert bearer["auth_session_headers"] == {"Authorization": "Bearer tok_abcdefgh123"}


@pytest.mark.parametrize("answer", [{"action": "skip"}, {"action": "session", "cookie": "a=1\r\nX: y"},
                                    {"action": "mfa_code"}, {"action": "nope"}, "skip", None])
def test_skip_and_invalid_answers_continue_unauthenticated(target, answer):
    up = auth_flow.resolve_challenge({"kind": "mfa", "status": "pending"}, {}, answer, "http://app.test/",
                                     sorted(ALLOWED))
    assert up.get("auth_performed") is not True and up["auth_challenge"]["status"] == "skipped"
    assert up["red_flags"] and "X: y" not in json.dumps(up)


# ----------------------------------------------------------------- LangGraph interrupt + resume
def _mini_graph():
    g = StateGraph(graph.AgentState)
    g.add_node("auth_challenge", graph.auth_challenge_node)
    g.add_node("sandbox_check", lambda s: {"phase": "next_step"})
    g.add_node("sast", lambda s: {"phase": "next_step"})
    g.add_edge(START, "auth_challenge")
    g.add_edge("sandbox_check", END)
    g.add_edge("sast", END)
    return g.compile(checkpointer=InMemorySaver())


def test_graph_pauses_for_mfa_and_resumes_with_the_code(target):
    challenge, pending = _pending(target)
    app, cfg = _mini_graph(), {"configurable": {"thread_id": "hitl-1"}}
    state = {"session_id": "hitl-1", "target": {"url": "http://app.test/", "session_id": "hitl-1",
                                                "authorization_confirmed": True},
             "allowed_domains": sorted(ALLOWED), "auth_challenge": challenge, "auth_pending": pending}
    paused = app.invoke(state, cfg)
    (intr,) = paused["__interrupt__"]
    assert intr.value["kind"] == "mfa" and intr.value["type"] == "sign_in"
    assert "step1" not in json.dumps(intr.value)          # no secret in what the operator is shown
    assert app.get_state(cfg).next == ("auth_challenge",)  # checkpointed, waiting
    done = app.invoke(Command(resume={"action": "mfa_code", "code": "123456"}), cfg)
    assert done["auth_performed"] is True and done["phase"] == "next_step"
    assert done["auth_challenge"]["status"] == "signed_in" and done["auth_pending"] == {}


def test_auth_routes_to_the_challenge_only_when_needed(monkeypatch):
    calls = {}

    class Tool:
        def __init__(self, challenge):
            self.challenge = challenge

        def invoke(self, args):
            calls.update(args)
            return SimpleNamespace(update={"auth_challenge": self.challenge, "phase": "x"})

    state = {"session_id": "s", "allowed_domains": ["app.test"],
             "principal": rbac.Principal(sub="a", roles=["admin"]).state_dict(),
             "target": {"url": "http://app.test/", "session_id": "s", "authorization_confirmed": True,
                        "interactive_auth": True}}
    monkeypatch.setattr(graph, "authenticate", Tool({"kind": "mfa", "status": "pending"}))
    assert graph.auth_node(state).goto == "auth_challenge" and calls["interactive"] is True
    monkeypatch.setattr(graph, "authenticate", Tool({}))
    assert graph.auth_node(state).goto in ("sandbox_check", "sast")
    state["principal"] = rbac.Principal(sub="b", roles=["scanner"]).state_dict()  # never interactive
    graph.auth_node(state)
    assert calls["interactive"] is False


# ----------------------------------------------------------------- WebSocket human in the loop
class FakeGraph:
    """Pauses once for MFA, then finishes with a signed-in session."""

    def __init__(self):
        self.resumes, self.calls = [], 0

    async def aget_state(self, config):
        return SimpleNamespace(values={"session_id": "h1"}, interrupts=())

    async def astream(self, inputs, config, stream_mode):
        self.calls += 1
        if self.calls == 1:
            yield ("updates", {"auth": {"phase": "auth_needs_human", "auth_pending": {"cookies": {"pre": "SECRET1"}},
                                        "auth_challenge": {"kind": "mfa", "status": "pending"}}})
            yield ("updates", {"__interrupt__": (Interrupt(value={
                "type": "sign_in", "kind": "mfa", "login_url": "http://app.test/login",
                "target_url": "http://app.test/", "timeout_seconds": 300}),)})
        else:
            self.resumes.append(inputs.resume)
            yield ("updates", {"auth_challenge": {"phase": "auth_complete", "auth_performed": True,
                                                  "auth_session_cookies": {"sid": "SECRET2"},
                                                  "auth_session_headers": {"Authorization": "Bearer SECRET3"}}})


def _scan(fake, monkeypatch, answers):
    monkeypatch.setattr(websocket_server, "_graph", fake)
    seen = []
    c = TestClient(websocket_server.app)
    with c.websocket_connect("/ws?session_id=h1") as ws:
        ws.send_text(json.dumps({"url": "http://app.test/", "authorization_confirmed": True,
                                 "interactive_auth": True, "force_refresh": True}))
        answers = list(answers)
        while True:
            raw = ws.receive_text()
            seen.append(raw)
            msg = json.loads(raw)
            if msg["type"] in ("input_required", "input_invalid") and answers:
                ws.send_text(json.dumps(answers.pop(0)))
            if msg["type"] in ("complete", "error"):
                break
    return [json.loads(s) for s in seen], "\n".join(seen)


def test_websocket_asks_the_operator_and_resumes(monkeypatch):
    fake = FakeGraph()
    msgs, raw = _scan(fake, monkeypatch, [
        {"type": "auth_response", "action": "mfa_code", "code": "1"},        # invalid: too short
        {"type": "auth_response", "action": "mfa_code", "code": "123456"},
    ])
    kinds = [m["type"] for m in msgs]
    assert "input_required" in kinds and "input_invalid" in kinds and kinds[-1] == "complete"
    req = next(m for m in msgs if m["type"] == "input_required")
    assert req["request"]["kind"] == "mfa" and req["timeout_seconds"] == settings.auth_input_timeout_seconds
    assert fake.resumes == [{"action": "mfa_code", "code": "123456"}]
    for secret in ("SECRET1", "SECRET2", "SECRET3", "123456"):
        assert secret not in raw, f"{secret} was streamed to the client"


def test_websocket_timeout_continues_unauthenticated(monkeypatch):
    monkeypatch.setattr(settings, "auth_input_timeout_seconds", 0.3)
    fake = FakeGraph()
    msgs, _ = _scan(fake, monkeypatch, [])
    assert fake.resumes == [{"action": "skip"}]
    assert any(m.get("event") == "input_timeout" for m in msgs)


# ----------------------------------------------------------------- the session reaches the scanner
def test_session_cookie_reaches_dast_and_probes():
    state = {"auth_session_cookies": {"sid": "full", "bad\r\n": "x"}}
    assert graph._session_cookie(state) == "sid=full"
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Cookie"))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        netloc = f"127.0.0.1:{httpd.server_address[1]}"
        engine.ScopedClient([netloc], delay=0, cookie="sid=full").get(f"http://{netloc}/")
        engine.ScopedClient([netloc], delay=0, cookie="sid=a\r\nX: y").get(f"http://{netloc}/")
    finally:
        httpd.shutdown()
        httpd.server_close()
    assert seen == ["sid=full", None]


def test_audit_records_sign_in_without_secrets():
    rec = audit_log.record_from_state({
        "session_id": "s", "target": {"url": "http://app.test/", "interactive_auth": True},
        "auth_performed": True, "auth_session_cookies": {"sid": "TOPSECRET"},
        "auth_pending": {"cookies": {"pre": "TOPSECRET2"}},
        "auth_challenge": {"kind": "sso", "status": "signed_in", "idp_host": "acme.okta.com"}})
    assert rec["auth"] == {"authenticated": True, "challenge": "sso", "challenge_result": "signed_in",
                           "idp_host": "acme.okta.com"}
    assert rec["target"]["interactive_auth"] is True and "TOPSECRET" not in json.dumps(rec)


def test_no_stale_coverage_warning_after_a_successful_sign_in(target):
    target.mfa = False
    assert not any("skipped/incomplete" in f for f in _login(interactive=False)["red_flags"])
    up = auth_flow.authenticate.invoke({"login_form_detected": True, "signup_form_detected": False})
    assert any("skipped/incomplete" in f for f in up.update["red_flags"])  # nothing to sign in with
