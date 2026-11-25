# Setup and troubleshooting

## Connect the MCP server

Run every command from the repo root of scopeguard-agent; the server resolves `.env`, `data/`
and `keys/` from there.

| Client | Config |
| --- | --- |
| Claude Code | `.mcp.json` in the repo (approve "scopeguard" once), or `claude mcp add scopeguard -- uv --directory REPO run --no-sync python -m pentest_agent.mcp_server.server` |
| Cursor | `.cursor/mcp.json`: `{"mcpServers": {"scopeguard": {"command": "uv", "args": ["--directory", "REPO", "run", "--no-sync", "python", "-m", "pentest_agent.mcp_server.server"]}}}` |
| VS Code | `.vscode/mcp.json`: `{"servers": {"scopeguard": {"type": "stdio", "command": "uv", "args": ["--directory", "REPO", "run", "--no-sync", "python", "-m", "pentest_agent.mcp_server.server"]}}}` |
| HTTP clients | `http://127.0.0.1:8765/mcp` with `Authorization: Bearer <JWT>` (the server starts with `uv run pentest-agent`) |

Launch through `python -m` with `--no-sync`, not the `scopeguard-mcp` script: on Windows a running `scopeguard-mcp.exe` is locked, and every later `uv run`/`uv sync` would fail with os error 32 while the client is open. Run `uv sync` once before the first launch.

Check the effective policy without a client: `uv run scopeguard-mcp --check`.

## Operator settings (`.env`, restart after a change)

| Setting | Meaning |
| --- | --- |
| `MCP_ALLOWED_TARGETS` / `A2A_ALLOWED_TARGETS` | The hosts agents may scan, comma separated. A bare host allows any port; `host:port` allows only that port. Empty means the demo app only. |
| `MCP_ROLE` | Role for stdio MCP. `scanner` allows quick and standard scans and reading reports. `admin` adds aggressive profiles, credentials, upload tests and the audit log. Over HTTP the token's roles apply instead. |
| `MCP_ALLOW_INLINE_CREDENTIALS` / `A2A_ALLOW_INLINE_CREDENTIALS` | Accept raw JWT or password values in calls. Off by default, because those values land in the transcript. |
| `MCP_DISABLED_TOOLS` | MCP tools to switch off, comma separated (e.g. `cancel_scan,verify_audit_log`). A switched-off tool is not listed and cannot be called, over HTTP and stdio. Empty means all tools are on. `scopeguard-mcp --check` shows the result. |

## Credential profiles

The operator types the secret into a hidden prompt; it is never typed into the chat:

```
uv run scopeguard-mcp credentials add NAME --target HOST --login-url URL --username USER \
    --username-field FIELD --password-field FIELD     # form login
uv run scopeguard-mcp credentials add NAME --target HOST   # JWT profile (token prompted)
uv run scopeguard-mcp credentials list
```

The field names must match the login form's `name="..."` attributes; check them in the
browser's dev tools.

A profile only works for its own hosts. If the run shows `signed_in: false`, the red flags say
why, for example "the login form came back": wrong credentials or wrong field names.

## Watch a scan, event by event

```
uv run python scripts/mcp_client.py                      # stdio MCP, demo app
uv run python scripts/mcp_client.py --sign-in --profile standard --delay 2
uv run python scripts/mcp_client.py --target URL --i-am-authorized [--credentials NAME]
uv run python scripts/a2a_client.py --target URL --i-am-authorized --profile standard
```

The scripts allowlist `--target` for a server they start themselves. If a shared agent doesn't
list the host, they start a private agent for the run.

## Common refusals

| Message | What to tell the user |
| --- | --- |
| "No targets are allowlisted" / "Not on the operator allowlist" | Add the host to `*_ALLOWED_TARGETS` in `.env` and restart the server. |
| "authorization_confirmed must be true" | Ask the user to confirm ownership or permission, then retry once with `true`. |
| "lack permission 'scan:aggressive'" or "'scan:authenticated'" | Use quick or standard, or have the operator set `MCP_ROLE=admin`. Over HTTP, use a token with the admin role. |
| "no credential profile 'X'" | Have the operator run `credentials add` (above). |
| "belongs to H, never sent to another host" | The credential profile is bound to another host. Use the right profile. |
| "Cannot resolve" / "Refusing to scan ... metadata" | DNS failed, or the target is a blocked address. Check the URL. |
| "still running (one scan at a time)" | Wait with `get_scan`, or `cancel_scan` the other scan. |
| "Unknown scan profile ..." | Use one of `quick`, `standard`, `aggressive`, `auth_deep`. |
| A tool is missing / "Unknown tool" | The operator switched it off with `MCP_DISABLED_TOOLS`. Tell the user; don't work around it. |
