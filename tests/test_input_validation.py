"""Strict input handling: unknown keys and wrong values are rejected with a
clear error, and the session id can never leave the reports folder."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from pentest_agent import websocket_server
from pentest_agent.schemas import TargetInput, validate_session_id


# ---------------------------------------------------------------- schema
@pytest.mark.parametrize("bad", ["../x", "..", ".hidden", "a/b", "a\\b", "", " ", "a b",
                                 "x" * 129, "a..b", "ok;rm", "é"])
def test_unsafe_session_ids_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_session_id(bad)


@pytest.mark.parametrize("good", ["ws-1795422976", "sim_1", "a", "A.b-c_9", "x" * 128])
def test_safe_session_ids_pass(good):
    assert validate_session_id(good) == good


def test_target_input_rejects_unknown_keys_and_loose_values(valid_target_dict):
    with pytest.raises(ValidationError, match="extra_forbidden|Extra inputs"):
        TargetInput.model_validate({**valid_target_dict, "urll": "https://x.example"})
    for loose in ("true", "yes", 1):
        with pytest.raises(ValidationError):
            TargetInput.model_validate({**valid_target_dict, "authorization_confirmed": loose})
    with pytest.raises(ValidationError):
        TargetInput.model_validate({**valid_target_dict, "profile": "turbo"})
    with pytest.raises(ValidationError):
        TargetInput.model_validate({**valid_target_dict, "notes": "n" * 2001})
    with pytest.raises(ValidationError):
        TargetInput.model_validate({**valid_target_dict, "session_id": "../../etc"})


@pytest.mark.parametrize("bad", ["https://cdn.example.com", "*.example.com", "cdn.example.com/x",
                                 "exa mple.com", "-bad.example.com", ""])
def test_additional_domains_must_be_host_names(valid_target_dict, bad):
    with pytest.raises(ValidationError):
        TargetInput.model_validate({**valid_target_dict, "additional_allowed_domains": [bad]})


def test_additional_domains_are_normalised_and_capped(valid_target_dict):
    t = TargetInput.model_validate({**valid_target_dict,
                                    "additional_allowed_domains": [" CDN.Example.com ", "api.example.com:8443"]})
    assert t.additional_allowed_domains == ["cdn.example.com", "api.example.com:8443"]
    with pytest.raises(ValidationError):
        TargetInput.model_validate({**valid_target_dict,
                                    "additional_allowed_domains": [f"h{i}.example.com" for i in range(21)]})


def test_auth_credentials_reject_unknown_keys_and_too_many_fields(valid_target_dict):
    with pytest.raises(ValidationError):
        TargetInput.model_validate({**valid_target_dict, "auth": {"username": "u", "pass": "p"}})
    with pytest.raises(ValidationError):
        TargetInput.model_validate({**valid_target_dict,
                                    "auth": {"extra_form_fields": {f"f{i}": "v" for i in range(21)}}})


# ---------------------------------------------------------------- WebSocket
def _first_error(url: str, payload: dict | None = None) -> tuple[dict, int | None]:
    # `with` runs the app lifespan, so the graph exists when the message is checked.
    with TestClient(websocket_server.app) as c, c.websocket_connect(url) as ws:
        if payload is not None:
            ws.send_json(payload)
        msg = ws.receive_json()
        code = None
        try:
            ws.receive_json()
        except Exception as exc:  # noqa: BLE001 - the server closed the socket
            code = getattr(exc, "code", None)
    return msg, code


@pytest.mark.parametrize("sid", ["..%2F..%2Fetc", "a%20b", "%2Ehidden"])
def test_ws_rejects_unsafe_session_id_before_anything_runs(sid):
    msg, code = _first_error(f"/ws?session_id={sid}")
    assert msg["type"] == "error" and msg["code"] == 400 and "session_id" in msg["message"]
    assert code == 4400


def test_ws_unknown_key_gets_422_without_echoing_values(valid_target_dict):
    payload = {k: v for k, v in valid_target_dict.items() if k != "session_id"}
    msg, code = _first_error("/ws?session_id=v1", {**payload, "password": "s3cret-value"})
    assert msg["code"] == 422 and msg["message"] == "Invalid input" and code == 4422
    assert msg["detail"][0]["loc"] == ["password"]
    assert "s3cret-value" not in str(msg)


@pytest.mark.parametrize("payload", [
    {"resume": "yes"},
    {"resume": True, "url": "https://x.example"},
    {"resume": False},
])
def test_ws_resume_message_must_be_exact(payload):
    msg, code = _first_error("/ws?session_id=v2", payload)
    assert msg["code"] == 422 and code == 4422


def test_ws_force_refresh_must_be_bool(valid_target_dict):
    payload = {k: v for k, v in valid_target_dict.items() if k != "session_id"}
    msg, code = _first_error("/ws?session_id=v3", {**payload, "force_refresh": "yes"})
    assert msg["code"] == 422 and msg["detail"][0]["loc"] == ["force_refresh"] and code == 4422


# ---------------------------------------------------------------- HTTP
def test_auth_endpoints_reject_unknown_keys():
    c = TestClient(websocket_server.app)
    r = c.post("/auth/token", json={"client_id": "a", "client_secret": "b", "role": "admin"})
    assert r.status_code == 422
    r = c.post("/auth/refresh", json={"refresh_token": "x", "extra": 1})
    assert r.status_code == 422
