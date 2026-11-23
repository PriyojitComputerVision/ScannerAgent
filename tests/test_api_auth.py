"""API authentication (RS256 JWT, auto refresh) and RBAC, at the API and in the agents."""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from pentest_agent import api_auth, graph, rbac, websocket_server
from pentest_agent.config import settings

SECRET = "test-client-secret-value"


@pytest.fixture
def auth_on(tmp_path, monkeypatch):
    keys = tmp_path / "keys"
    for name, value in {
        "auth_enabled": True,
        "jwt_private_key_path": str(keys / "jwt_private.pem"),
        "jwt_public_key_path": str(keys / "jwt_public.pem"),
        "auth_clients_file": str(keys / "clients.json"),
        "auth_client_id": "main-client",
        "auth_client_secret": SECRET,
        "auth_client_roles": "admin",
        "reports_dir": str(tmp_path / "reports"),
        "jwt_access_ttl_minutes": 60,
        "jwt_refresh_ttl_minutes": 24 * 60,
        "jwt_auto_refresh_before_minutes": 10,
    }.items():
        monkeypatch.setattr(settings, name, value)
    api_auth.generate_keypair()
    api_auth.revoked_refresh_tokens.clear()
    report = tmp_path / "reports" / "r1"
    report.mkdir(parents=True)
    (report / "report.html").write_text("<p>report</p>", encoding="utf-8")
    yield tmp_path
    api_auth.revoked_refresh_tokens.clear()


def token(roles=("scanner",), sub="alice") -> str:
    return api_auth.issue_tokens(sub, list(roles)).access_token


def bearer(t: str) -> dict:
    return {"Authorization": f"Bearer {t}"}


# --------------------------------------------------------------------- tokens
def test_issue_and_verify_roundtrip(auth_on):
    pair = api_auth.issue_tokens("alice", ["scanner"])
    claims = api_auth.verify_token(pair.access_token)
    assert claims["sub"] == "alice" and claims["roles"] == ["scanner"] and claims["typ"] == "access"
    assert 3590 <= claims["exp"] - claims["iat"] <= 3600          # 60 minutes
    assert pair.expires_in == 3600 and pair.roles == ["scanner"]
    with pytest.raises(api_auth.AuthError, match="expected a access token"):
        api_auth.verify_token(pair.refresh_token)                # refresh token is not an access token


@pytest.mark.parametrize("mutate, message", [
    (lambda c: c.update(exp=int(time.time()) - 120), "expired"),
    (lambda c: c.update(aud="someone-else"), "audience"),
    (lambda c: c.update(iss="evil"), "issuer"),
    (lambda c: c.pop("roles"), "roles"),
    (lambda c: c.update(roles=["superuser"]), "invalid roles"),
])
def test_bad_claims_are_rejected(auth_on, mutate, message):
    now = int(time.time())
    claims = {"iss": settings.jwt_issuer, "aud": settings.jwt_audience, "sub": "a", "typ": "access",
              "jti": "x", "iat": now, "nbf": now, "exp": now + 600, "auth_time": now, "roles": ["admin"]}
    mutate(claims)
    t = pyjwt.encode(claims, api_auth.private_key(), algorithm="RS256", headers={"kid": api_auth.key_id()})
    with pytest.raises(api_auth.AuthError, match=message):
        api_auth.verify_token(t)


def test_algorithm_confusion_and_tampering_rejected(auth_on):
    from cryptography.hazmat.primitives import serialization

    pub_pem = api_auth.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())
    claims = {"iss": settings.jwt_issuer, "aud": settings.jwt_audience, "sub": "a", "typ": "access",
              "jti": "x", "iat": now, "nbf": now, "exp": now + 600, "auth_time": now, "roles": ["admin"]}
    import base64
    import hashlib
    import hmac as _hmac

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": api_auth.key_id()}).encode())
    body = b64(json.dumps(claims).encode())
    sig = b64(_hmac.new(pub_pem, f"{head}.{body}".encode(), hashlib.sha256).digest())
    with pytest.raises(api_auth.AuthError, match="algorithm"):
        api_auth.verify_token(f"{head}.{body}.{sig}")            # HS256 signed with the public key
    good = token(["viewer"])
    h, b, s = good.split(".")
    forged = b64(json.dumps({**json.loads(base64.urlsafe_b64decode(b + "==")), "roles": ["admin"]}).encode())
    with pytest.raises(api_auth.AuthError):
        api_auth.verify_token(f"{h}.{forged}.{s}")               # role escalation by editing the payload


def test_refresh_rotates_and_rejects_reuse(auth_on):
    pair = api_auth.issue_tokens("alice", ["viewer"])
    new = api_auth.refresh_tokens(pair.refresh_token)
    assert api_auth.verify_token(new.access_token)["roles"] == ["viewer"]
    with pytest.raises(api_auth.AuthError, match="already used"):
        api_auth.refresh_tokens(pair.refresh_token)


def test_session_cap_stops_renewal(auth_on, monkeypatch):
    old_login = int(time.time()) - 24 * 3600 - 5
    with pytest.raises(api_auth.AuthError, match="session expired"):
        api_auth.issue_access_token("alice", old_login, ["scanner"])
    # access tokens never outlive the session
    monkeypatch.setattr(settings, "jwt_refresh_ttl_minutes", 30)
    pair = api_auth.issue_tokens("alice", ["scanner"])
    assert pair.expires_in <= 30 * 60


def test_auto_refresh_only_near_expiry(auth_on, monkeypatch):
    fresh = api_auth.verify_token(token())
    assert api_auth.auto_refresh(fresh) is None
    monkeypatch.setattr(settings, "jwt_access_ttl_minutes", 5)   # < 10 min left -> renew
    near = api_auth.verify_token(token())
    monkeypatch.setattr(settings, "jwt_access_ttl_minutes", 60)
    new_token, exp = api_auth.auto_refresh(near)
    claims = api_auth.verify_token(new_token)
    assert exp > near["exp"] and claims["roles"] == near["roles"] and claims["auth_time"] == near["auth_time"]


def test_client_registry_and_cli(auth_on, capsys):
    assert api_auth.client_roles("main-client", SECRET) == ["admin"]
    assert api_auth.client_roles("main-client", "wrong") is None
    secret = api_auth.add_client("ci-bot", ["viewer"])
    stored = json.loads((auth_on / "keys" / "clients.json").read_text())
    assert secret not in json.dumps(stored)                     # only the hash is stored
    assert api_auth.client_roles("ci-bot", secret) == ["viewer"]
    assert api_auth.remove_client("ci-bot") and api_auth.client_roles("ci-bot", secret) is None
    assert api_auth.main(["token", "--sub", "me", "--roles", "viewer"]) == 0
    assert json.loads(capsys.readouterr().out)["roles"] == ["viewer"]
    assert api_auth.main(["keys"]) == 1                          # refuses to overwrite


# ----------------------------------------------------------------- HTTP API
def test_http_requires_valid_token_and_role(auth_on):
    with TestClient(websocket_server.app) as c:
        assert c.get("/healthz").status_code == 200              # public
        r = c.get("/reports/r1/")
        assert r.status_code == 401 and r.headers["WWW-Authenticate"].startswith("Bearer")
        assert c.get("/reports/r1/", headers={"Authorization": "Bearer nope"}).status_code == 401
        assert c.get("/reports/r1/", headers=bearer(token(["viewer"]))).status_code == 200


def test_token_endpoint_and_refresh_endpoint(auth_on):
    with TestClient(websocket_server.app) as c:
        assert c.post("/auth/token", json={"client_id": "main-client", "client_secret": "x"}).status_code == 401
        pair = c.post("/auth/token", json={"client_id": "main-client", "client_secret": SECRET}).json()
        assert pair["roles"] == ["admin"] and pair["expires_in"] == 3600
        new = c.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert new.status_code == 200
        again = c.post("/auth/refresh", json={"refresh_token": pair["refresh_token"]})
        assert again.status_code == 401 and "already used" in again.json()["detail"]


def test_http_auto_refresh_header_and_report_cookie(auth_on, monkeypatch):
    monkeypatch.setattr(settings, "jwt_access_ttl_minutes", 5)
    near = token(["viewer"])
    monkeypatch.setattr(settings, "jwt_access_ttl_minutes", 60)
    with TestClient(websocket_server.app) as c:
        r = c.get("/reports/r1/", headers=bearer(near))
        assert r.status_code == 200 and api_auth.verify_token(r.headers["X-New-Access-Token"])
        # browser flow: ?access_token= once, then the HttpOnly cookie carries it
        r = c.get(f"/reports/r1/?access_token={token(['viewer'])}")
        assert r.status_code == 200 and "pa_access_token" in r.headers["set-cookie"]
        assert "httponly" in r.headers["set-cookie"].lower()
        assert c.get("/reports/r1/report.html").status_code == 200   # cookie only


# ---------------------------------------------------------------- WebSocket
class _FakeGraph:
    def __init__(self):
        self.inputs = []

    async def astream(self, inputs, config, stream_mode):
        self.inputs.append(inputs)
        yield {"report": {"phase": "done"}}

    async def aget_state(self, config):
        return SimpleNamespace(values={"principal": {"sub": "alice"}})


def _ws_messages(c, url, headers=None, payload=None):
    msgs = []
    with c.websocket_connect(url, headers=headers or {}) as ws:
        if payload is not None:
            ws.send_json(payload)
        try:
            while True:
                m = ws.receive_json()
                msgs.append(m)
                if m["type"] in ("complete", "error"):
                    break
        except WebSocketDisconnect:
            pass
    return msgs


SCAN = {"url": "https://example.com", "profile": "quick", "authorization_confirmed": True}


@pytest.fixture
def fake_graph(monkeypatch):
    g = _FakeGraph()
    monkeypatch.setattr(websocket_server, "get_graph", lambda: g)
    return g


def test_ws_rejects_missing_or_bad_token(auth_on, fake_graph):
    with TestClient(websocket_server.app) as c:
        m = _ws_messages(c, "/ws?session_id=s1", payload=SCAN)            # no token anywhere
        assert m[-1]["code"] == 401 and "Unauthorized" in m[-1]["message"]
        m = _ws_messages(c, "/ws?session_id=s1&access_token=garbage")
        assert m[-1]["code"] == 401
        m = _ws_messages(c, "/ws?session_id=s1", payload={**SCAN, "access_token": "garbage"})
        assert m[-1]["code"] == 401
    assert not fake_graph.inputs


def test_ws_token_in_first_json_message(auth_on, fake_graph):
    """Clients that cannot set handshake headers send the token with the JSON."""
    t = token(["scanner"])
    with TestClient(websocket_server.app) as c:
        m = _ws_messages(c, "/ws?session_id=j1", payload={**SCAN, "access_token": t})
        assert m[-1]["type"] == "complete"
        m = _ws_messages(c, "/ws?session_id=j2", payload={**SCAN, "authorization": f"Bearer {t}"})
        assert m[-1]["type"] == "complete"
        # RBAC still applies to a token sent this way
        m = _ws_messages(c, "/ws?session_id=j3",
                         payload={**SCAN, "profile": "aggressive", "access_token": t})
        assert m[-1]["code"] == 403
    sent = json.dumps(fake_graph.inputs)
    assert t not in sent and "access_token" not in sent                  # never reaches the agents
    assert [i["principal"]["sub"] for i in fake_graph.inputs] == ["alice", "alice"]


def test_ws_first_message_must_be_json(auth_on, fake_graph):
    with TestClient(websocket_server.app) as c, c.websocket_connect("/ws?session_id=j4") as ws:
        ws.send_text("not json")
        m = ws.receive_json()
    assert m["code"] == 401 and "JSON object" in m["message"]


def test_ws_resume_with_token_in_message(auth_on, fake_graph):
    with TestClient(websocket_server.app) as c:
        m = _ws_messages(c, "/ws?session_id=j5",
                         payload={"resume": True, "access_token": token(["scanner"], sub="alice")})
    assert m[-1]["type"] == "complete"


def test_header_token_and_stray_token_field_are_both_fine(auth_on, fake_graph):
    """With the header used, an access_token field in the JSON is still stripped."""
    t = token(["scanner"])
    with TestClient(websocket_server.app) as c:
        m = _ws_messages(c, "/ws?session_id=j6", bearer(t), {**SCAN, "access_token": t})
    assert m[-1]["type"] == "complete" and t not in json.dumps(fake_graph.inputs)


@pytest.mark.parametrize("roles, payload, allowed", [
    (["viewer"], SCAN, False),                                          # no scan:run
    (["scanner"], SCAN, True),
    (["scanner"], {**SCAN, "profile": "aggressive"}, False),            # needs scan:aggressive
    (["scanner"], {**SCAN, "jwt": "eyJhbGciOiJIUzI1NiJ9.e30.x"}, False),  # needs scan:authenticated
    (["admin"], {**SCAN, "profile": "aggressive"}, True),
])
def test_ws_rbac(auth_on, fake_graph, roles, payload, allowed):
    with TestClient(websocket_server.app) as c:
        m = _ws_messages(c, "/ws?session_id=s2", bearer(token(roles)), payload)
    if allowed:
        assert m[-1]["type"] == "complete"
        assert fake_graph.inputs[-1]["principal"]["roles"] == roles      # agents get the caller
    else:
        assert m[-1]["code"] == 403 and not fake_graph.inputs


def test_ws_resume_only_by_owner_or_admin(auth_on, fake_graph):
    with TestClient(websocket_server.app) as c:
        m = _ws_messages(c, "/ws?session_id=s3", bearer(token(["scanner"], sub="bob")), {"resume": True})
        assert m[-1]["code"] == 403 and "another user" in m[-1]["message"]
        m = _ws_messages(c, "/ws?session_id=s3", bearer(token(["scanner"], sub="alice")), {"resume": True})
        assert m[-1]["type"] == "complete"
        m = _ws_messages(c, "/ws?session_id=s3", bearer(token(["admin"], sub="carol")), {"resume": True})
        assert m[-1]["type"] == "complete"


def test_ws_pushes_token_refreshed_before_expiry(auth_on, monkeypatch):
    class SlowGraph(_FakeGraph):
        async def astream(self, inputs, config, stream_mode):
            import asyncio
            await asyncio.sleep(0.5)
            yield {"report": {"phase": "done"}}

    monkeypatch.setattr(websocket_server, "get_graph", lambda: SlowGraph())
    monkeypatch.setattr(settings, "jwt_access_ttl_minutes", 5)   # inside the 10 min window
    t = token(["scanner"])
    monkeypatch.setattr(settings, "jwt_access_ttl_minutes", 60)
    with TestClient(websocket_server.app) as c:
        m = _ws_messages(c, "/ws?session_id=s4", bearer(t), SCAN)
    refreshed = [x for x in m if x["type"] == "token_refreshed"]
    assert refreshed and api_auth.verify_token(refreshed[0]["access_token"])["sub"] == "alice"
    assert m[-1]["type"] == "complete"


# ------------------------------------------------------------ agents (RBAC)
def _state(roles, **target):
    p = rbac.Principal(sub="alice", roles=roles).state_dict()
    return {"session_id": "s", "principal": p, "allowed_domains": ["example.com"], "profile": "quick",
            "target": {"url": "https://example.com", "authorization_confirmed": True, "profile": "quick",
                       "session_id": "s", **target}}


def test_agent_validate_node_enforces_rbac():
    cmd = graph.validate_input_node(_state(["scanner"], profile="aggressive"))
    assert cmd.update["phase"] == "forbidden" and "scan:aggressive" in cmd.update["error"]
    assert graph.validate_input_node(_state(["scanner"])).update["phase"] == "validated"


def test_agent_codegen_node_skips_without_probe_permission():
    cmd = graph.plan_probes_node(_state(["viewer"]))
    assert cmd.update["phase"] == "codegen_probes_skipped" and cmd.goto == "aggregate"
    assert "scan:probes" in cmd.update["red_flags"][0]


def test_agent_auth_node_drops_target_credentials_without_permission(monkeypatch):
    seen = {}

    class Tool:
        def invoke(self, args):
            seen.update(args)
            return SimpleNamespace(update={"phase": "auth_complete"})

    monkeypatch.setattr(graph, "authenticate", Tool())
    graph.auth_node(_state(["scanner"], jwt="eyJhbGciOiJIUzI1NiJ9.e30.x"))
    assert seen["jwt"] is None and seen["auth_creds"] is None
    graph.auth_node(_state(["admin"], jwt="eyJhbGciOiJIUzI1NiJ9.e30.x"))
    assert seen["jwt"] == "eyJhbGciOiJIUzI1NiJ9.e30.x"
