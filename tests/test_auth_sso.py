"""SSO / MFA sign-in: detection, pausing (all entry points), TOTP, session profiles, sign-in
results, and secrets kept out of the state / checkpoint / LLM (secret_vault). No network, no LLM."""
from __future__ import annotations

import asyncio
import contextlib
import json
from types import SimpleNamespace

import pytest
from langgraph.types import Command

from pentest_agent import (
    checkpointer,
    credential_store,
    graph,
    scan_service,
    secret_vault,
    totp,
)
from pentest_agent.config import settings
from pentest_agent.mcp_server import server as mcp_mod
from pentest_agent.schemas import (
    AuthCredentials,
    HumanAuthResponse,
    SessionCredentials,
    TargetInput,
)
from pentest_agent.tools import auth_flow
from pentest_agent.tools.auth_detect import sso_signal
from pentest_agent.tools.recon import login_methods

ALLOWED = {"app.example.com"}


def _resp(status=200, location=None, text=""):
    return SimpleNamespace(status_code=status, headers={"location": location} if location else {}, text=text)


# ----------------------------------------------------------------------------- TOTP (RFC 6238)
def test_totp_matches_the_rfc_test_vector():
    seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # base32 of "12345678901234567890"
    assert totp.code(seed, at=59, digits=8) == "94287082"
    assert totp.code(seed, at=1111111109, digits=8) == "07081804"
    assert totp.code(seed, at=59) == "287082"
    assert totp.normalize_secret("gezd gnbv-gy3t qojq") == "GEZDGNBVGY3TQOJQ"
    for bad in ("short", "otpauth://totp/x?secret=ABC", "!!!!!!!!!!!!!!!!"):
        with pytest.raises(ValueError):
            totp.normalize_secret(bad)
    assert AuthCredentials(totp_secret="gezdgnbvgy3tqojq").totp_secret == "GEZDGNBVGY3TQOJQ"


# ----------------------------------------------------------------------------- detection
def test_sso_is_found_on_any_page_without_false_positives():
    idp = sso_signal("https://app.example.com/dashboard", 302,
                     "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=x", "", ALLOWED)
    assert idp["kind"] == "sso" and idp["idp_host"] == "login.microsoftonline.com"
    assert idp["login_url"] == "https://app.example.com/dashboard"
    footer = '<a href="https://github.com/acme">GitHub</a><p>Welcome</p>'
    assert sso_signal("https://app.example.com/about", 200, None, footer, ALLOWED) is None
    button = '<a href="https://acme.okta.com/app/x">Sign in with Okta</a>'
    assert sso_signal("https://app.example.com/login", 200, None, button, ALLOWED)["idp_host"] == "acme.okta.com"
    saml = '<form action="https://idp.corp.test/sso"><input name="SAMLRequest" value="x"></form>'
    assert sso_signal("https://app.example.com/", 200, None, saml, ALLOWED)["kind"] == "sso"


def test_login_methods_classify_password_sso_or_both():
    assert login_methods(True, None)["kind"] == "password"
    assert login_methods(False, {"idp_host": "okta.com"}) == {"kind": "sso", "password": False, "sso": True,
                                                              "idp_host": "okta.com"}
    assert login_methods(True, {"idp_host": "x"})["kind"] == "password_and_sso"
    assert login_methods(False, None)["kind"] == "none"


def _authenticate(**kw):
    args = {"login_form_detected": False, "signup_form_detected": False, "allowed_domains": sorted(ALLOWED),
            "target_url": "https://app.example.com/"} | kw
    return auth_flow.authenticate.invoke(args).update


def test_sso_only_site_pauses_by_default_and_never_when_off():
    hint = {"kind": "sso", "idp_host": "login.microsoftonline.com", "evidence": "redirects to an IdP",
            "login_url": "https://app.example.com/"}
    paused = _authenticate(sso_hint=hint)
    assert paused["auth_challenge"]["kind"] == "sso" and paused["auth_challenge"]["status"] == "pending"
    assert paused["auth_challenge"]["methods"] == ["SSO"]
    off = _authenticate(sso_hint=hint, interactive=False)
    assert not off["auth_challenge"] and any("signs in with SSO" in f for f in off["red_flags"])


def test_no_sso_and_no_login_form_does_nothing():
    update = _authenticate()
    assert not update["auth_challenge"] and not update["red_flags"] and not update["auth_performed"]


def test_plain_login_form_pauses_only_when_asked():
    assert not _authenticate(login_form_detected=True)["auth_challenge"]  # auto: SSO / MFA only
    assert _authenticate(login_form_detected=True, interactive=True)["auth_challenge"]["kind"] == "session"


# ----------------------------------------------------------------------------- session check
def test_a_session_is_proven_on_a_page_that_needs_sign_in(monkeypatch):
    pages = {"https://app.example.com/account": _resp(200, text="<a href='/logout'>Log out</a>"),
             "https://app.example.com/": _resp(200, text="<p>public</p>")}

    class Client:
        def __init__(self, *a, **k): ...
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def get(self, url): return pages[url]

    monkeypatch.setattr(auth_flow, "rate_limited_client", Client)
    ok = auth_flow.verify_session("https://app.example.com/", {"sid": "x"}, {}, ALLOWED,
                                  protected_url="https://app.example.com/account")
    assert ok == {"ok": True, "verified": True, "detail": "a page that needs sign-in now opens (HTTP 200)"}
    unproven = auth_flow.verify_session("https://app.example.com/", {"sid": "x"}, {}, ALLOWED)
    assert unproven["ok"] and not unproven["verified"]
    pages["https://app.example.com/account"] = _resp(302, "https://login.microsoftonline.com/authorize?client_id=1")
    failed = auth_flow.verify_session("https://app.example.com/", {"sid": "x"}, {}, ALLOWED,
                                      protected_url="https://app.example.com/account")
    assert not failed["ok"] and "sign-in page" in failed["detail"]


def test_failed_sso_is_marked_failed_sso_login(monkeypatch):
    monkeypatch.setattr(auth_flow, "verify_session",
                        lambda *a, **k: {"ok": False, "verified": False, "detail": "the target answered HTTP 401"})
    challenge = {"kind": "sso", "status": "pending", "idp_host": "okta.com"}
    update = auth_flow.resolve_challenge(challenge, {}, {"action": "session", "cookie": "sid=abc12345"},
                                         "https://app.example.com/", sorted(ALLOWED))
    assert update["auth_challenge"]["status"] == "failed"
    assert update["red_flags"][0].startswith("SSO login failed:")
    result = graph.sign_in_result(update, {"sso_detected": {"idp_host": "okta.com"}}, first_step=False)
    assert result["status"] == "failed" and result["outcome"].startswith("SSO login failed")
    assert result["idp_host"] == "okta.com"


# ----------------------------------------------------------------------------- secret vault
def test_secrets_never_enter_the_state_and_are_encrypted_in_memory():
    target = TargetInput.model_validate({
        "url": "https://app.example.com/", "authorization_confirmed": True, "session_id": "vault-1",
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig",
        "auth": {"login_url": "https://app.example.com/login", "username": "alice-qa",
                 "password": "Hunter2-secret", "totp_secret": "GEZDGNBVGY3TQOJQ"}}).model_dump(mode="json")
    public, held = secret_vault.prepare_target(target, "vault-1")
    text = json.dumps(public)
    for secret in ("alice-qa", "Hunter2-secret", "GEZDGNBVGY3TQOJQ", "eyJhbGciOiJIUzI1NiJ9"):
        assert secret not in text
        assert secret.encode() not in secret_vault._store["vault-1"]["ct"]  # only ciphertext in memory
    assert held == {"jwt": True, "session": False, "login": True, "totp": True}
    full = secret_vault.full_target(public, "vault-1")
    assert full["auth"]["password"] == "Hunter2-secret" and full["jwt"].startswith("eyJ")
    assert secret_vault.redact("user alice-qa / Hunter2-secret", "vault-1") == "user [REDACTED] / [REDACTED]"
    secret_vault.clear("vault-1")
    assert secret_vault.get("vault-1") == {}


def test_a_tampered_vault_entry_reads_as_empty():
    secret_vault.put("vault-2", target_jwt="token-value-1")
    blob = secret_vault._store["vault-2"]
    blob["ct"] = bytes([blob["ct"][0] ^ 1]) + blob["ct"][1:]
    assert secret_vault.get("vault-2") == {}
    secret_vault.clear("vault-2")


def test_sign_in_answers_resume_through_the_vault():
    req = {"type": "sign_in"}
    resumed = secret_vault.resume_value("vault-3", req, {"action": "mfa_code", "code": "123456"})
    assert resumed == {"action": "mfa_code", "vault": True}
    assert secret_vault.pop("vault-3", "sign_in_answer") == {"action": "mfa_code", "code": "123456"}
    assert secret_vault.resume_value("vault-3", req, {"action": "skip"}) == {"action": "skip"}


def test_the_checkpoint_serializer_blanks_secret_keys():
    serde = checkpointer.make_serde()
    kind, data = serde.dumps_typed({"target": {"auth": {"password": "Hunter2-secret", "username_field": "u"},
                                               "jwt": "tok"}, "auth_session_cookies": {"sid": "abc"}})
    loaded = serde.loads_typed((kind, data))
    assert b"Hunter2-secret" not in data and b"abc" not in data
    assert loaded["target"]["auth"]["password"] == "[REDACTED]" and loaded["target"]["auth"]["username_field"] == "u"


def test_llm_messages_are_redacted():
    from langchain_core.messages import HumanMessage

    secret_vault.put("vault-4", target_login={"password": "Hunter2-secret"})
    out = secret_vault.redact_messages([HumanMessage(content="page says Hunter2-secret"), "plain"])
    assert out[0].content == "page says [REDACTED]" and out[1] == "plain"
    secret_vault.clear("vault-4")


# ----------------------------------------------------------------------------- credential profiles
def test_session_and_totp_profiles(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "scan_credentials_file", str(tmp_path / "creds.json"))
    credential_store.save(credential_store.CredentialProfile(
        name="sso-app", targets=("app.example.com",), session=SessionCredentials(cookie="sid=abc12345")))
    login = AuthCredentials(login_url="https://app.example.com/login", username="qa", password="pw-12345",
                            totp_secret="GEZDGNBVGY3TQOJQ")
    credential_store.save(credential_store.CredentialProfile(name="mfa", targets=("app.example.com",), login=login))
    listed = {p["name"]: p for p in credential_store.list_profiles()}
    assert listed["sso-app"]["kind"] == "session" and listed["sso-app"]["session"] == {"cookie": True, "bearer": False}
    assert listed["mfa"]["totp"] is True and "pw-12345" not in json.dumps(listed)
    assert credential_store.get("sso-app").target_fields() == {"session": {"cookie": "sid=abc12345", "bearer": None}}


# ----------------------------------------------------------------------------- the pause via MCP / service
class PausingGraph:
    """Pauses once for sign-in, then finishes; records the resume value."""

    def __init__(self):
        self.resumed = None
        self.timeout = 30

    async def astream(self, payload, config=None, stream_mode=None):
        if isinstance(payload, Command):
            self.resumed = payload.resume
            for node in ("auth_challenge", "report", "audit"):
                yield {node: {"phase": f"{node}_done"}}
            return
        yield {"recon": {"phase": "recon_complete", "login_methods": {"kind": "sso", "idp_host": "okta.com"}}}
        yield {"__interrupt__": (SimpleNamespace(value={
            "type": "sign_in", "kind": "sso", "login_url": "https://app.example.com/login",
            "idp_host": "okta.com", "evidence": "the site redirects to an SSO endpoint", "methods": ["SSO"],
            "timeout_seconds": self.timeout}),)}

    async def aget_state(self, config):
        return SimpleNamespace(values={"phase": "report_complete", "report_md_path": None,
                                       "sign_in_result": {"status": "skipped", "outcome": "SSO login skipped"}})


@pytest.fixture
def pausing(monkeypatch):
    g = PausingGraph()

    @contextlib.asynccontextmanager
    async def fake_checkpointer(_path=None):
        yield None

    monkeypatch.setattr(scan_service.graph_module, "build_graph", lambda checkpointer=None: g)
    monkeypatch.setattr(scan_service, "async_main_checkpointer", fake_checkpointer)
    monkeypatch.setattr(settings, "mcp_allowed_targets", "app.example.com")
    monkeypatch.setattr(settings, "mcp_role", "admin")
    mcp_mod.reset_service()
    yield g
    mcp_mod.reset_service()


async def _call(name, args):
    res = await mcp_mod.mcp.call_tool(name, args)
    return json.loads(res.content[0].text)


async def test_mcp_scan_pauses_for_sso_and_skip_sign_in_continues(pausing):
    started = await _call("start_scan", {"target_url": "https://app.example.com/", "authorization_confirmed": True,
                                         "profile": "quick"})
    waiting = await _call("get_scan", {"scan_id": started["scan_id"], "wait_seconds": 5})
    assert waiting["status"] == "input_required"
    assert waiting["sign_in"]["kind"] == "sso" and waiting["sign_in"]["idp_host"] == "okta.com"
    assert waiting["sign_in"]["methods"] == ["SSO"] and "skip_sign_in" in waiting["next_step"]
    assert waiting["login_methods"]["kind"] == "sso"
    await _call("skip_sign_in", {"scan_id": started["scan_id"]})
    done = await _call("get_scan", {"scan_id": started["scan_id"], "wait_seconds": 5})
    assert done["status"] == "completed" and pausing.resumed == {"action": "skip"}
    assert done["sign_in_result"]["outcome"] == "SSO login skipped"


async def test_mfa_code_goes_through_the_vault_not_the_checkpoint(pausing):
    svc = mcp_mod.service()
    run = await svc.start_scan("https://app.example.com/", authorization_confirmed=True, profile="quick")
    await svc.wait(run.scan_id, 5)
    assert run.status == "input_required"
    with pytest.raises(scan_service.PolicyError, match="Invalid sign-in answer"):
        await svc.submit_sign_in(run.scan_id, "mfa_code", code="x")
    await svc.submit_sign_in(run.scan_id, "mfa_code", code="123456")
    await svc.wait(run.scan_id, 5)
    assert pausing.resumed == {"action": "mfa_code", "vault": True}  # no code in the resume write
    with pytest.raises(scan_service.PolicyError, match="not waiting"):
        await svc.submit_sign_in(run.scan_id, "skip")


async def test_inline_session_values_need_the_operator_switch(pausing):
    svc = mcp_mod.service()
    run = await svc.start_scan("https://app.example.com/", authorization_confirmed=True, profile="quick")
    await svc.wait(run.scan_id, 5)
    with pytest.raises(scan_service.PolicyError, match="Inline session values are disabled"):
        await svc.submit_sign_in(run.scan_id, "session", cookie="sid=abc12345")
    await svc.skip_sign_in(run.scan_id)
    await svc.wait(run.scan_id, 5)


async def test_no_answer_in_time_means_skip(pausing, monkeypatch):
    pausing.timeout = 0.2
    svc = mcp_mod.service()
    run = await svc.start_scan("https://app.example.com/", authorization_confirmed=True, profile="quick")
    await asyncio.wait({run.task}, timeout=5)
    assert pausing.resumed == {"action": "skip"} and run.status == "completed"


def test_answers_are_validated_like_the_websocket():
    with pytest.raises(ValueError):
        HumanAuthResponse.model_validate({"action": "session"})
    assert HumanAuthResponse.model_validate({"action": "skip"}).action == "skip"
