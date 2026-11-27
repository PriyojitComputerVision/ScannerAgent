"""Get a ready-to-use API access token. No arguments needed:

    uv run python scripts/get_token.py

What it does, in order:
1. Creates the RSA key pair in keys/ if it does not exist yet.
2. Reuses the token saved in keys/token.json while it has more than
   JWT_AUTO_REFRESH_BEFORE_MINUTES (default 10) left; otherwise mints a fresh
   access token (valid JWT_ACCESS_TTL_MINUTES, default 60) + refresh token.
3. Saves the pair to keys/token.json (gitignored) and prints its expiry, roles and
   how to use it (Postman header, a shell line that reads the file). The token
   itself is not printed, so it stays out of terminal scrollback and CI logs.

Tokens are signed locally with the private key, so the server does not need to
be running. Subject and roles come from .env: AUTH_CLIENT_ID and
AUTH_CLIENT_ROLES. The running server must use the same keys/ folder.
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pentest_agent import api_auth, rbac
from pentest_agent.config import settings

TOKEN_FILE = Path(settings.jwt_private_key_path).parent / "token.json"


def _saved_token() -> dict | None:
    """The saved pair, if its access token is still valid with time to spare."""
    try:
        saved = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
        claims = api_auth.verify_token(saved["access_token"])
    except (OSError, ValueError, KeyError, api_auth.AuthError):
        return None
    if api_auth.seconds_left(claims) <= settings.jwt_auto_refresh_before_minutes * 60:
        return None
    return saved


def main() -> int:
    if not api_auth.keys_present():
        priv, pub = api_auth.generate_keypair()
        print(f"Created key pair: {priv} and {pub}")

    pair = _saved_token()
    if pair is None:
        roles = rbac.parse_roles(settings.auth_client_roles)
        pair = json.loads(api_auth.issue_tokens(settings.auth_client_id, roles).model_dump_json())
        TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(json.dumps(pair, indent=2), encoding="utf-8")
        status = "New token created"
    else:
        status = "Reusing saved token (still valid)"

    claims = api_auth.verify_token(pair["access_token"])
    expires = dt.datetime.fromtimestamp(claims["exp"]).astimezone()
    minutes_left = int(api_auth.seconds_left(claims) // 60)
    port = settings.ws_port

    print(f"\n{status} for '{claims['sub']}' with roles: {', '.join(claims['roles'])}")
    print(f"Expires: {expires:%Y-%m-%d %H:%M:%S %Z} ({minutes_left} min left; "
          f"the server renews it automatically while you use it)\n")
    print(f"Token pair saved to {TOKEN_FILE} (gitignored). It is not printed, so it stays out of")
    print("terminal scrollback and CI logs; copy access_token from that file.")
    print("\nPostman / HTTP header:")
    print("  Authorization: Bearer <access_token>")
    print("\nShell (bash):")
    print('  T=$(uv run python -c "import json; print(json.load(open(\'keys/token.json\'))[\'access_token\'])")')
    print("\nWebSocket URL (send the header above, or put access_token in the first JSON message):")
    print(f"  ws://127.0.0.1:{port}/ws?session_id=postman-demo-1")
    print("\nReports in a browser: open them from the console (no token in the URL).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
