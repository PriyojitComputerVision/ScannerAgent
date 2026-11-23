
from __future__ import annotations

import base64
import datetime as dt
import json

import jwt as pyjwt

from pentest_agent.auth import inspect_jwt, jwt_red_flags

TEST_SECRET = "throwaway-test-secret-with-at-least-32-bytes"


def _make_token(
    claims: dict,
    headers: dict | None = None,
) -> str:
    """
    Generate a test JWT signed using HS256.

    inspect_jwt only inspects the JWT structure and claims.
    It does not verify the signature against the target's secret.
    """
    return pyjwt.encode(
        claims,
        TEST_SECRET,
        algorithm="HS256",
        headers=headers,
    )


def _encode_segment(data: dict) -> str:
    """Encode a JWT header or payload as Base64URL without padding."""
    raw = json.dumps(
        data,
        separators=(",", ":"),
    ).encode("utf-8")

    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _make_unsigned_token(
    claims: dict,
    algorithm: str = "none",
) -> str:
    """
    Construct an unsigned JWT manually.

    PyJWT does not permit a non-empty signing key with alg=none.
    """
    header = _encode_segment(
        {
            "alg": algorithm,
            "typ": "JWT",
        }
    )

    payload = _encode_segment(claims)

    return f"{header}.{payload}."


def test_inspect_jwt_absent_token():
    info = inspect_jwt(None)

    assert info.present is False
    assert info.valid_structure is False


def test_inspect_jwt_valid_unexpired_token():
    future = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)

    token = _make_token(
        {
            "sub": "user1",
            "exp": int(future.timestamp()),
        }
    )

    info = inspect_jwt(token)

    assert info.present is True
    assert info.valid_structure is True
    assert info.expired is False
    assert info.claims["sub"] == "user1"


def test_inspect_jwt_expired_token():
    past = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)

    token = _make_token(
        {
            "sub": "user1",
            "exp": int(past.timestamp()),
        }
    )

    info = inspect_jwt(token)

    assert info.present is True
    assert info.valid_structure is True
    assert info.expired is True


def test_inspect_jwt_garbage_token():
    info = inspect_jwt("this.is.not-a-real-jwt")

    assert info.present is True
    assert info.valid_structure is False
    assert info.error is not None


def test_jwt_red_flags_missing_but_required():
    info = inspect_jwt(None)

    flags = jwt_red_flags(
        info,
        jwt_required_detected=True,
    )

    assert any(
        "none was supplied" in flag.lower()
        for flag in flags
    )


def test_jwt_red_flags_expired():
    past = dt.datetime.now(dt.UTC) - dt.timedelta(hours=1)

    token = _make_token(
        {
            "exp": int(past.timestamp()),
        }
    )

    info = inspect_jwt(token)

    flags = jwt_red_flags(
        info,
        jwt_required_detected=True,
    )

    assert any(
        "already expired" in flag.lower()
        for flag in flags
    )


def test_jwt_red_flags_alg_none_marker():
    # Construct alg=none token without using PyJWT's signing function.
    token = _make_unsigned_token(
        {
            "sub": "x",
        }
    )

    info = inspect_jwt(token)

    assert info.present is True
    assert info.valid_structure is True

    flags = jwt_red_flags(
        info,
        jwt_required_detected=False,
    )

    assert any(
        "alg=none" in flag.lower()
        for flag in flags
    )


def test_jwt_red_flags_clean_token_no_flags():
    future = dt.datetime.now(dt.UTC) + dt.timedelta(hours=1)

    token = _make_token(
        {
            "sub": "user1",
            "exp": int(future.timestamp()),
        }
    )

    info = inspect_jwt(token)

    flags = jwt_red_flags(
        info,
        jwt_required_detected=True,
    )

    assert flags == []
