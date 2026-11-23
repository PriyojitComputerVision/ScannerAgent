# ScopeGuard over A2A

Use A2A when you are an agent on the network rather than a coding assistant with MCP tools. The
A2A endpoint starts with `uv run pentest-agent`. It has the same rules as MCP; only the transport
differs.

## Endpoints and auth

| What | Where |
| --- | --- |
| Agent card (public) | `GET http://127.0.0.1:8765/.well-known/agent-card.json` |
| JSON-RPC (A2A 1.0) | `POST http://127.0.0.1:8765/a2a` |

Every JSON-RPC call needs two headers:

- `A2A-Version: 1.0`. Without it the server assumes 0.3 and rejects the call.
- `Authorization: Bearer <API JWT>`. The operator mints the token with
  `uv run pentest-auth token --sub my-agent --roles scanner`.

Scans run as the token's subject and roles. Tasks belong to that subject, so another token can't
read or cancel them.

## Requests

Send one user message containing a JSON object, as a data part (preferred) or as JSON text.

| Action | Body |
| --- | --- |
| policy | `{"action": "policy"}` |
| demo scan | `{"action": "demo_scan", "profile": "quick", "sign_in": false}` |
| scan | `{"action": "scan", "target_url": "https://app.example.com/", "authorization_confirmed": true, "profile": "standard", "credentials": "staging", "max_findings": 25}` |
| reports | `{"action": "list_reports"}` or `{"action": "get_report", "session_id": "...", "format": "md"}` |

`authorization_confirmed` must be the JSON literal `true`. The string `"true"` is rejected on
purpose.

## Task lifecycle

`policy` and the report actions answer with a single message. Scans become tasks:

1. The task is created in state `TASK_STATE_SUBMITTED`, then moves to `TASK_STATE_WORKING`.
2. One `working` status update arrives per finished agent step. Its metadata holds `node`,
   `phase`, `at_seconds` and `scan_id`. Relay these as progress.
3. A `scan-result` data artifact follows. Its content matches MCP `get_scan`: `status`,
   `severity_counts`, `findings` (evidence wrapped as untrusted), `red_flags`, `report_files`,
   `audit`, `signed_in`.
4. The task ends in a terminal state:

| State | Meaning |
| --- | --- |
| `COMPLETED` | The scan finished. |
| `REJECTED` | The allowlist, the authorization flag or RBAC refused it. Read the status message and don't retry with variants. |
| `FAILED` | The scan crashed. |
| `CANCELED` | Stopped through `CancelTask`. |

Use `SendStreamingMessage` (SSE) to get the updates live. With `SendMessage`, the call blocks
until the task is finished.

## Watch it run

`uv run python scripts/a2a_client.py` does all of this and prints each event one at a time. It
mints a JWT and starts a private agent when needed. Add `--target URL --i-am-authorized` for the
user's own site.
