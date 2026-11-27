# pentest-agent (ScopeGuard)

Autonomous, guard-railed **web security scanner agent**. Orchestrated by LangGraph, optional Groq LLM,
exposed over a WebSocket. **No OWASP ZAP, no Java**: all scanning is pure Python and runs in a
Docker-free sandbox; code checks and uploaded code run in Kubernetes Jobs (a Dockerfile is provided only
to package test -> drift check -> server).

> Authorization is mandatory. Only scan systems you own or are explicitly authorized to test.

## Architecture

New to ScopeGuard? Start with **[How a scan works, told as a story](docs/scan-story.png)**: every
agent as a character with one job, from your request to your report, in plain language.

![Architecture: the browser console or a WebSocket client signs in and sends a scan request to the FastAPI server; the request waits in a server-wide queue, then runs the 16-step LangGraph pipeline; the choose_scope, auth_challenge and code_source steps can pause for the operator (what to test: website + code, website only or code only; SSO / MFA sign-in; source code at the SAST step), several steps send in-scope requests to the target, two call the Groq LLM, the report step writes files and the audit step appends a tamper-evident record.](docs/architecture.png)

A client signs in at `/auth/token` and sends the scan request over `/ws`. The request waits in the
server-wide queue (1 scan runs at a time, up to 50 wait; see [API management](#api-management-queues)),
then the server runs the LangGraph pipeline `validate → choose_scope → recon → auth → [auth_challenge] → code_source → [code_sast] → sast → sandbox_check → dast → plan_probes → run_probes → aggregate → summarize → report → audit`
and streams progress back. `choose_scope` asks you first, before any request, what the scan tests:
the **website + its source code**, the **website only**, or the **code only** (then the run skips the
recon layer, `choose_scope → auth → code_source → code_sast → sandbox_check → dast → plan_probes → run_probes → aggregate`, and the website steps pass straight on, so nothing is sent to any site; see
[What to test](#what-to-test-website--code-website-only-code-only-human-in-the-loop)). `auth_challenge` runs only when the target needs a human for SSO or MFA
(see [Sign-in with SSO / MFA](#sign-in-with-sso--mfa-human-in-the-loop)); `code_source` is the SAST step's
human in the loop: it pauses and asks you for code files, a .zip or a public repository's `.git` link (or skip), and
`code_sast` analyses that code in the sandbox (see [Source code at the SAST step](#source-code-at-the-sast-step-human-in-the-loop));
every route, including
refused and safety-stopped runs, ends in `audit` (see [Audit log](#audit-log)). `sast` runs only when the sandbox check is off (`SANDBOX_CHECK_ENABLED=false`):
otherwise `sandbox_check` applies the same JavaScript rules inside its Kubernetes Job
(`scopeguard-job-<session_id>`, deleted after the run). Orange lines mark the only traffic to the target website (in scope only).
Only `plan_probes` and `summarize` call the LLM, and both have offline fallbacks. Reports,
SQLite checkpoints (AES-encrypted with `CHECKPOINT_ENCRYPTION_KEY`) and the audit log are written under `data/`.
Checkpoints are written asynchronously (aiosqlite + LangGraph's `AsyncSqliteSaver`, no synchronous SQLite anywhere);
the server and every MCP / A2A scan share the file through WAL mode with a busy timeout
(`CHECKPOINT_BUSY_TIMEOUT_SECONDS`, 30), so concurrent scans wait for each other instead of failing with "database is locked".
The diagrams are rendered from `docs/src/*.html` with `uv run python scripts/render_docs.py`. The same scan engine (`src/scopeguard/`) also runs
standalone through `python -m scopeguard.cli`.

### Agent graph

<img src="docs/agent-tree.png" alt="LangGraph agent graph: validate, choose_scope (asks what to test: website, code or both), recon, auth, auth_challenge, code_source (asks you for source code at the SAST step), code_sast, the sast subgraph (run_sast), sandbox_check, dast, plan_probes, run_probes, aggregate, summarize, report, audit; dashed edges are Command routes, including each step's safety stop to aggregate." width="360">

Drawn by LangGraph itself (`get_graph(xray=True).draw_mermaid()`). Solid edges are fixed, dashed
edges are `Command(goto=...)` routes declared in each node's return annotation, and the `sast` box
is the SAST sub-agent running as a subgraph. `choose_scope`, `code_source` and `auth_challenge` are the human-in-the-loop
steps (LangGraph `interrupt`); `code_sast` analyses your source code in the sandbox. The LLM steps (`plan_probes`, `summarize`) are their own
nodes, so their results are checkpointed and a resumed run doesn't call the LLM again. Regenerate
after changing the graph with `uv run python scripts/draw_graph.py` (writes
[docs/agent-graph.mmd](docs/agent-graph.mmd) and the PNG; rendered locally, nothing is sent to a
diagram service).

## Quick start (no setup beyond Python 3.12)

Check this machine first: `uv run python scripts/system_check.py` (Python, dependencies, settings, keys,
audit trails, the Python sandbox's memory cap and analyzer, Docker/kubectl and where code scans will run;
`--bootstrap` brings the Kubernetes sandbox up first, `--quick` skips the sandbox tests, `--json` for
scripts; exit 1 on any FAIL). Kubernetes sandbox setup (kind + Calico): [k8s/README.md](k8s/README.md).

```bash
# 1. Self-contained simulation. Needs NOTHING installed (stdlib only):
cd src && python -m scopeguard.cli --simulate
#    starts a vulnerable loopback target, scans it inside the sandbox, writes
#    data/reports/simulated-*/report.{md,json,html,docx}, runs a self-test (exit 0 = pass)

# 2. Scan your own app (sandboxed). The app must be running: an unreachable target exits 4.
python -m scopeguard.cli --url http://localhost:3000 --profile standard --i-have-authorization

# 3. View reports in the browser (loopback only):
python -m scopeguard.cli --simulate --serve      # scan, then serve -> http://127.0.0.1:8000/
python -m scopeguard.cli --serve --port 8000     # browse existing reports
```

On Windows without `python` on PATH, use the uv environment: `uv run python -m scopeguard.cli ...`
or `.venv\Scripts\python.exe -m scopeguard.cli ...`.

### Browser console (one command)

```bash
uv run pentest-agent          # server + console + built-in vulnerable target, opens your browser
uv run scopeguard-demo        # same, but always loopback-only and on a free port if 8765 is taken
```

The console is served by the agent server itself at `http://127.0.0.1:8765/`: a live view of the
16-step pipeline, an event stream, a findings radar, severity mix and risk grade, the cited executive
summary (each `[Sn]` jumps to its finding), attack coverage, a findings explorer and all saved
reports with html/docx/md/json downloads, and the **agent integrations** (MCP and A2A endpoints,
see below). Admins also see the **audit trail** (live chain check) and
can tick **Pause for SSO / MFA sign-in** to complete a target's sign-in themselves when asked, and choose
**What to test** in the New scan card (website + code, website only, code only, where you give files, a .zip or a git link
right there instead of a link, or
decide after launch). The page fits one
screen: the top bar and footer stay put while the left rail and the main stage scroll on their own
(on narrow screens it becomes one scrolling page). The **Agent pipeline** card follows the scope: code
only shows every step but `recon`, the website steps marked "code only" as they pass on; website only
and website + code show every step. The built-in target (`127.0.0.1` only) is offered as a
one-click demo target. Flags: `--no-browser`, `--no-target`, `--host`, `--port`.

There is no login screen, and API authentication stays on:

- The server prints a **one-time sign-in link** (`/#demo=<code>`, single use, valid 10 minutes, only
  its SHA-256 is kept in memory). The page exchanges the code at `POST /ui/demo-login` for a normal
  RS256 token pair with the `AUTH_CLIENT_ROLES` roles, then removes it from the address bar.
- The browser keeps the pair in `sessionStorage` (per tab) and sends the access token in the
  `Authorization` header, or in the first WebSocket message. Tokens are never put in a URL. The
  token is renewed 5 minutes before expiry with the single-use refresh token. The page also adopts
  `X-New-Access-Token` and `token_refreshed` pushes and retries once after refreshing on a 401.
- Report links work through an HttpOnly, SameSite=Strict cookie set by `POST /api/report-cookie`.
- Every UI file is served from a fixed whitelist with a strict CSP: no inline code, no third-party
  loads, no framing. Scanned-site text is rendered as text only, never parsed as HTML.
- `/ws` rejects browser connections from another origin (close `4403`).

Reloading the page keeps the session. After a restart, open the new link the server prints.
Replace `src/pentest_agent/webui/favicon/favicon.png` to change the tab icon and the top-left logo
(served at `/ui/favicon.png` and `/favicon.ico`, read from disk on each request). In Docker the
server runs with `--no-browser --no-target`.

### MCP and A2A: other agents and coding assistants

`uv run pentest-agent` also starts two agent endpoints next to the console. Both are listed in the
startup banner and in the console's **Agent integrations** card:

![MCP tools: the human operator, the MCP chatbot agent and coding assistants call ten MCP tools over Streamable HTTP or stdio, grouped into discover (scan_policy), run (start_scan, start_demo_scan, cancel_scan, each approved by a person), follow (get_scan, list_scans), read (list_reports, get_report, verify_audit_log) and code (upload_code: a .zip or code files for a scan's code SAST step); every call goes through the shared ScanService rules before the scan pipeline sends in-scope requests to the target.](docs/mcp-tools.png)


| Endpoint | Who uses it | Auth |
| --- | --- | --- |
| MCP over Streamable HTTP, `http://127.0.0.1:8765/mcp` | MCP clients that connect by URL | API JWT (`Authorization: Bearer`); tools run as the token's subject and roles |
| MCP over stdio, `uv run scopeguard-mcp` | coding assistants on this machine (Claude Code picks it up from `.mcp.json`) | none: it is the assistant's own child process; runs as `MCP_ROLE` |
| A2A 1.0, `http://127.0.0.1:8765/a2a` (agent card: `/.well-known/agent-card.json`, public) | other agents | API JWT; tasks belong to the token's subject |

Tokens: `uv run pentest-auth token --sub my-agent --roles scanner`.

Every path goes through one shared service, `pentest_agent/scan_service.py`, with the same
guardrails as the console:

- **Operator allowlist.** `MCP_ALLOWED_TARGETS` / `A2A_ALLOWED_TARGETS` list the hosts agents may
  scan. Empty means the built-in demo app only.
- **Authorization.** `authorization_confirmed` must be `true`.
- **RBAC and limits.** Role checks apply, and only one scan runs at a time.
- **Profiles.** Only the four pentest profiles (`quick`, `standard`, `aggressive`, `auth_deep`);
  anything else is refused.
- **Audit log.** Every attempt is recorded, including refused, cancelled and crashed ones.
- **Untrusted output.** Text from the target is returned wrapped as untrusted.
- **Logging.** The server log has one line per MCP tool call (caller, safe arguments,
  outcome, duration) and per WebSocket message, never payloads, arguments in full or tokens.

**Switching MCP tools off.** `MCP_DISABLED_TOOLS` in `.env` lists tools to remove, comma
separated (for example `cancel_scan,verify_audit_log`). A removed tool is not listed and
cannot be called, over HTTP and stdio. `uv run scopeguard-mcp --check` shows which tools
are on, and `scan_policy` reports them as `disabled_tools`. Restart after a change.

Authenticated scans use **credential profiles**. The operator stores the secret once; agents pass
only the profile's name, so passwords never enter an agent's context:

```bash
uv run scopeguard-mcp credentials add staging --target staging.example.com \
    --login-url https://staging.example.com/login --username qa    # password prompted, hidden
```

Profiles are bound to their hosts and need the `scan:authenticated` permission (admin). The demo
app has a public fake account for trying this out (`sign_in: true`).

Watch a scan go through either protocol, one event at a time. Each step, finding, report path and
audit record is printed on its own, with a pause set by `--delay`:

```bash
uv run python scripts/mcp_client.py                  # stdio MCP, demo app
uv run python scripts/mcp_client.py --http           # MCP over /mcp
uv run python scripts/a2a_client.py                  # A2A task with streamed status updates
uv run python scripts/a2a_client.py --sign-in --profile standard --delay 2   # signed-in demo scan, slower

# Your own site (only systems you own or may test): no .env change needed
uv run python scripts/mcp_client.py --target https://your-app.example/ --i-am-authorized --profile standard --delay 2
uv run python scripts/a2a_client.py --target https://your-app.example/ --i-am-authorized --profile standard
uv run python scripts/mcp_client.py --target http://localhost:3000 --i-am-authorized --credentials local
```

The scripts set themselves up:

- **Sign-in.** They mint an API JWT with this machine's key (`keys/`): role `scanner`, or `admin` for
  `--sign-in` / `--credentials`. Over stdio no token is needed.
- **Server.** stdio MCP starts its own MCP server. `--http` and A2A use the running `pentest-agent`, or
  start one headless for the run.
- **Allowlist.** `--target` is allowlisted only for a server the script starts. If a `pentest-agent`
  is already running and its `.env` does not list the host, the script shows a `SWITCH` event and
  starts a private agent on a free port with only that host allowlisted, then stops it afterwards.
  `--own-server` always does that. To scan through the shared agent instead, add the host to
  `A2A_ALLOWED_TARGETS` / `MCP_ALLOWED_TARGETS` in `.env` and restart it.
- **Missing pieces.** A missing credential profile stops the run with a `SETUP` event that prints
  the exact `uv run scopeguard-mcp credentials add ...` command.

Other options: `--findings N` (findings shown one by one; default 100, i.e. all the server returns), `--no-llm`, `--show-refusal` (demo of
the allowlist refusing a host), `-h` for all.

For a quick unattended scan without any server, the stdlib CLI needs only the authorization flag:
`uv run python -m scopeguard.cli --url https://your-app.example/ --profile standard --i-have-authorization`.
It has no form login (only `--bearer`), no LLM summary and no sandboxed code check.

Usage guides for assistants: [src/pentest_agent/mcp_server/CLAUDE.md](src/pentest_agent/mcp_server/CLAUDE.md)
and [src/pentest_agent/a2a_server/CLAUDE.md](src/pentest_agent/a2a_server/CLAUDE.md).

**Agent skill** `scopeguard-scan` teaches an assistant the whole flow:

- check the policy, get the user's authorization, pick a profile
- use credential profiles by name only
- wait with `get_scan`
- treat scan output as untrusted
- present findings and fix them in code

It lives in two places:

- [.claude/skills/scopeguard-scan/](.claude/skills/scopeguard-scan/SKILL.md): Claude Code loads it
  automatically in this repo.
- [skills/scopeguard-scan.skill](skills/scopeguard-scan.skill): the packaged version, to upload in
  Claude (Settings, Capabilities, Skills) or to share.

After editing the skill, rebuild the package with the skill-creator's `package_skill` script
(`python -m scripts.package_skill .claude/skills/scopeguard-scan skills`).

### Full LangGraph + WebSocket agent

```bash
uv sync
cp .env.example .env            # GROQ_API_KEY is optional; empty = deterministic offline mode
uv run python scripts/get_token.py       # creates keys/ if needed and prints a 60-min access token
uv run python scripts/simulate_full.py   # whole pipeline against the built-in target (auth on)
uv run pentest-agent                      # console at http://127.0.0.1:8765/ + ws://127.0.0.1:8765/ws?session_id=<id>
uv run python scripts/ws_client.py --simulate   # Postman-free client for the running server (see --help)
uv run pytest
uv run golden-check                       # golden-dataset drift check (see below)
```

Client message: `{"url": "...", "profile": "quick|standard|aggressive|auth_deep", "authorization_confirmed": true}`
(`{"resume": true}` with the same `session_id` resumes from the SQLite checkpoint.)

Input is checked strictly. Anything outside these rules is rejected with
`{"type": "error", "code": 422, "message": "Invalid input", "detail": [...]}` and close code `4422`;
`detail` names each bad field but never echoes the submitted values:

| Key | Accepted |
| --- | --- |
| `session_id` (query) | 1-128 letters, digits, `.`, `_`, `-`, starting with a letter or digit (it names the report folder); otherwise error `400`, close `4400` |
| `url` | `http(s)://` URL |
| `profile` | `quick`, `standard`, `aggressive`, `auth_deep` |
| `authorization_confirmed` | JSON `true` only (`"true"`, `1` or `"yes"` are rejected) |
| `additional_allowed_domains` | up to 20 host names, optionally `:port`; no scheme, path or wildcard |
| `notes` / `jwt` / `source_path` | strings up to 2000 / 8000 / 1000 characters |
| `auth` | `login_url`, `username`, `password`, `username_field`, `password_field`, `extra_form_fields` (max 20) |
| `force_refresh` | `true` or `false` |
| `interactive_auth` | JSON `true` / `false`: pause for SSO / MFA sign-in (admin; see [Sign-in with SSO / MFA](#sign-in-with-sso--mfa-human-in-the-loop)) |
| `resume` | exactly `{"resume": true}`, nothing else in the message |
| `access_token` / `authorization` | the API token; removed before the request is processed |

Any other key is rejected. `POST /auth/token` and `/auth/refresh` reject unknown keys too (HTTP `422`).
The final `complete` message includes absolute report URLs: `report_url` (HTML view, e.g. `http://127.0.0.1:8765/reports/<session_id>/`) and `report_md_url`, `report_json_url`, `report_docx_url` (downloads). Server file paths are never sent. Warnings and errors are also written to `LOG_FILE` (default `data/logs/pentest-agent.log`).

While a scan runs, the server also sends `status` messages, for example when the LLM is
rate limited (`"event": "llm_rate_limit_wait"`, `"wait_seconds"`). One LLM call waits at most
`LLM_RATE_LIMIT_MAX_WAIT_SECONDS` (default 120) before that step uses its offline fallback.

### WebSocket client (instead of Postman)

`scripts/ws_client.py` runs the same WebSocket flow from the terminal against a running server.
Start the server first (`uv run pentest-agent`), then run the client in a second terminal from the repo root:

```bash
# Self-test against the built-in vulnerable target (prints SIMULATION PASSED/FAILED)
uv run python scripts/ws_client.py --simulate

# Scan your own site (only targets you own or are authorized to test)
uv run python scripts/ws_client.py https://your-app.example --profile standard --i-have-authorization

# Same, with your own access token (e.g. from scripts/get_token.py)
uv run python scripts/ws_client.py https://your-app.example --i-have-authorization --token "eyJhbGciOi..."

# Send a Postman-style JSON body as-is (an access_token inside it is used; nothing else signs in)
uv run python scripts/ws_client.py --payload keys/body.json

# Resume an interrupted run with the session id it printed
uv run python scripts/ws_client.py --session-id ws-1795422976 --resume
```

Example `--payload` body (keep it out of git: it holds a live token; `keys/` is gitignored):

```json
{
  "access_token": "<token>",
  "url": "https://your-app.example/",
  "profile": "standard",
  "authorization_confirmed": true,
  "force_refresh": true
}
```

The client checks `GET /healthz`, gets a token, connects to `/ws?session_id=<id>`, prints every
`status` / `phase_update` / `error` message as it arrives, adopts `token_refreshed` tokens,
and prints the report URLs at the end. With `--interactive-auth` it answers a sign-in pause in the
terminal (hidden input for codes, cookies and tokens; empty = skip).

| Option | Meaning |
| --- | --- |
| `url` | target URL (needs `--i-have-authorization`; not used with `--simulate`, `--resume`, `--payload`) |
| `--profile` | `quick`, `standard` (default), `aggressive`, `auth_deep` |
| `--simulate` | scan the built-in vulnerable target and check the expected findings |
| `--payload FILE` | JSON file sent as the request body (overrides the scan options) |
| `--session-id ID` / `--resume` | choose the session id / resume that session from its checkpoint |
| `--force-refresh` | ignore a cached result for the same request |
| `--allow-domain DOMAIN` | extra in-scope domain (repeatable) |
| `--notes TEXT` | free-text notes stored with the scan |
| `--token TOKEN` | access token to use as-is |
| `--token-in message\|header\|query` | send the token in the first message (default), `Authorization` header or `?access_token=` |
| `--no-auth` | send no token (server with `AUTH_ENABLED=false`) |
| `--host` / `--port` | server address (default `127.0.0.1` / `WS_PORT`) |
| `--raw` | print every message as full JSON |
| `--save-md FILE` | write the markdown report to a file |

Without `--token` or a token in the payload, the client signs in at `POST /auth/token` with
`AUTH_CLIENT_ID` / `AUTH_CLIENT_SECRET` from `.env`, or signs a token locally with `keys/`.
Exit codes: `0` complete, `1` server error or rejected (e.g. `401` expired token),
`2` socket closed early (it prints the resume command), `3` server not reachable or no token.

### Report viewer

| Where | URL |
| --- | --- |
| WebSocket server | `http://127.0.0.1:8765/reports/` (index), `/reports/<session_id>/` (HTML), `/reports/<id>/report.{md,json,docx}` |
| CLI `--serve` | `http://127.0.0.1:<port>/` (index), `/<report-folder>/` (HTML) |

Downloads are named after the session id (CLI: the report folder), e.g. `money-dynocde-001.docx`,
`.md`, `.json`; on disk they stay `report.*`.
Reports are rendered with every target-controlled value HTML-escaped and served with a strict
`Content-Security-Policy` (no scripts), so a hostile page cannot inject markup into the viewer.

## API authentication (JWT) and roles (RBAC)

Every call to the agent server needs an access token, except `GET /healthz`,
`POST /auth/token` and `POST /auth/refresh`. Tokens are RS256 JWTs signed with
the key pair in `keys/` (gitignored, along with `*.pem`; never commit it).

```bash
uv run python scripts/get_token.py        # no arguments: creates keys/ if missing, prints a token
uv run pentest-auth keys                  # (re)create the key pair (--force replaces it)
uv run pentest-auth secret                # random value for AUTH_CLIENT_SECRET
uv run pentest-auth token --roles scanner # mint a token locally
uv run pentest-auth add-client --id ci-bot --roles viewer   # extra client; secret printed once, stored hashed
uv run pentest-auth list-clients | remove-client --id ci-bot | verify <token>
```

**Getting a token over HTTP**

```http
POST /auth/token        {"client_id": "<AUTH_CLIENT_ID>", "client_secret": "<AUTH_CLIENT_SECRET>"}
-> {"access_token", "refresh_token", "token_type": "Bearer", "roles", "expires_in": 3600, "expires_at", "refresh_expires_in"}
POST /auth/refresh      {"refresh_token": "..."}   -> a new pair (each refresh token works once)
```

Send it as `Authorization: Bearer <access_token>` on every HTTP request.

On the WebSocket, most clients cannot set handshake headers, so put the token in
the first JSON message (it is removed before the scan request is processed and
never reaches the agents, cache or logs):

```json
{"access_token": "<token>", "url": "https://your-app.example", "profile": "standard", "authorization_confirmed": true}
```

(`"authorization": "Bearer <token>"` in the message, the `Authorization` header, or
`?access_token=` in the URL also work.) The server waits up to 15 s for that first
message. Browsers can open reports with `?access_token=<token>` (masked in all
logs); the first report request then sets an HttpOnly cookie so the links inside work.

**Lifetime and automatic refresh**

| Setting | Default | Meaning |
| --- | --- | --- |
| `JWT_ACCESS_TTL_MINUTES` | 60 | access token lifetime |
| `JWT_AUTO_REFRESH_BEFORE_MINUTES` | 10 | the server renews a token with less than this left |
| `JWT_REFRESH_TTL_MINUTES` | 1440 | max session length from sign-in; no renewal after that |

The server renews tokens by itself. An HTTP response carries the new token in
`X-New-Access-Token` (and `X-New-Access-Token-Expires-At`). A WebSocket session
gets `{"type": "token_refreshed", "access_token": ..., "expires_at": ...}` before
expiry, so scans longer than an hour keep running. When the session cap is
reached the socket closes with 4401; sign in again and resume with the same
`session_id`. `pentest_agent.auth_client.TokenManager` does all of this for
Python clients (`scripts/scan_client.py` uses it).

**Roles** (`AUTH_CLIENT_ROLES` for the `.env` client, `--roles` for others)

| Role | Permissions |
| --- | --- |
| `viewer` | read reports |
| `scanner` | viewer + run/resume own scans (`quick`, `standard`) + LLM-planned probes |
| `admin` | scanner + `aggressive`/`auth_deep`, authenticated target testing (`jwt`/`auth`/`interactive_auth` in the request), any user's sessions, the audit log (`audit:read`) |

The API checks roles first (HTTP 403, WebSocket close 4403). The agent graph
checks them again per node from the caller stored in its state: the validate
node blocks forbidden profiles/credentials, the auth/DAST/probe nodes drop
target credentials without `scan:authenticated`, and the probe node is skipped
(with a red flag) without `scan:probes`.

| Error | HTTP | WebSocket |
| --- | --- | --- |
| missing/invalid/expired token | 401 + `WWW-Authenticate` | `{"type":"error","code":401}`, close 4401 |
| role lacks permission | 403 | `{"type":"error","code":403}`, close 4403 |

`AUTH_ENABLED=false` turns all of this off (local testing only). In Docker,
mount the keys (`-v "$PWD/keys:/app/keys"`); without them the container creates
a new pair at start, and tokens from other keys will not work.

## Text from scanned sites

Hyperlinks are removed from all text read from scanned websites before it is
stored or shown to an LLM (`scopeguard/textsafe.py`): finding evidence (scanner
engine and the agent's `Finding` model) and page content wrapped for the LLM.
Anchors and markdown links keep only their text; URLs and `href`/`src`/`action`
values become `[link removed]`. A finding's `affected_url` and the validated
source links in reports are scan metadata and stay.

## Sandbox code & content check, discovery, and attack coverage

Between the JS SAST and the live DAST, the agent runs a **sandbox check** of backend
source code and the website content it fetched from the target:

* It runs `scopeguard.codecheck` in a **Kubernetes Job** (no Docker, no custom image; see
  [Source code at the SAST step](#source-code-at-the-sast-step-human-in-the-loop)):
  deny-all NetworkPolicy, read-only root filesystem, dropped capabilities, non-root user;
  the analyzer also installs an audit hook, so any attempt to reach the network, run a
  process, or write/read outside the inputs is **blocked and reported as a red flag**.
  Without a cluster the check fails with the reason (`SANDBOX_REQUIRE_KUBERNETES=true`,
  the default) or runs in the local process sandbox with a red flag (`false`).
* **Website content** is fetched by the agent from the **target only** (scope-checked,
  no redirects followed); links, redirects and `fetch()`/script `src` to other hosts
  are listed and flagged, never downloaded. Page text that tries to steer an AI agent
  (prompt injection / jailbreak) is detected and flagged.
* **Backend source** (optional `source_path` in the request, admin `scan:source` only;
  constrained to `CODECHECK_SOURCE_ROOTS`) is scanned read-only for injection, SSRF,
  hardcoded secrets (masked), unsafe deserialization, weak crypto, disabled TLS
  verification, `none`-alg JWTs, wildcard CORS and more.

**Discovery** (recon): `robots.txt`, `sitemap.xml`/`sitemap_index.xml`, `security.txt`,
`crossdomain.xml`, `clientaccesspolicy.xml`, `openid-configuration` and other
well-known files are fetched on every in-scope origin. In-scope paths they reveal
(including robots.txt Disallow entries and sitemap URLs) seed the crawl; other hosts
they name are flagged and never visited. Sensitive robots paths, wildcard cross-domain
policies and expired/missing security.txt become findings.

**Attack coverage** (DAST): the live scan now also tests CORS bypasses (null / prefix /
suffix origin, preflight), reflected / script-context / `javascript:`-URL XSS,
error- / boolean- / time-based SQL injection, time-based OS command injection,
server-side template injection, CRLF/header injection, host-header injection, open
redirect, path traversal, weak CSP, extra cross-origin headers, **API docs exposure**
(`/docs`, `/redoc`, swagger, openapi, graphql consoles — reported accessible or not),
and **backend/API endpoints** referenced by the frontend (in-scope ones are requested
and tested, others only listed). Every report ends with an **Attack coverage** table:
for each check, how many tests ran, how many findings, and short notes — so a check
that found nothing is still recorded as having run.

**File upload testing** (aggressive/auth_deep profile + admin `scan:upload`, settable
with `ENABLE_UPLOAD_TESTS`): upload forms are always reported (accepted types, declared
max size). When active, the scanner POSTs **benign, inert marker files** under disguised
and dangerous names (`.php`, `.phtml`, `.jsp`, `.svg`, double extensions like
`x.jpg.php`, case/null-byte tricks, a renamed `.exe`, and an oversized file) to detected
same-origin upload endpoints, then checks whether they were accepted, stored or executed.
The payloads contain no shells and no real executables — only a unique marker string an
executing server would echo back — so the control is tested without planting a webshell.
Confirmed execution is reported CRITICAL (CWE-434).

## What to test: website + code, website only, code only (human in the loop)

Right after `validate`, before a single request goes to the target, the `choose_scope` node decides
what the scan tests:

| Scope | Runs | Requests to the site |
| --- | --- | --- |
| `website_and_code` | every website step, then the code at the SAST step (`code_source` → `code_sast`) | yes |
| `website` | every website step; no code step | yes |
| `code` | every step but `recon`: `choose_scope → auth → code_source → code_sast → sandbox_check → dast → plan_probes → run_probes → aggregate → summarize → report → audit`; auth, sandbox_check, dast and the probes pass straight on (phase `<step>_code_only`) | **none**: no website is needed; a URL, if given, only labels the report |

* **Ask me (human in the loop).** With `"ask_scan_scope": true` the run pauses (LangGraph `interrupt`,
  checkpointed) and the server sends `input_required` with `request.type == "scan_scope"`, the offered
  `options` and the `default`. Answer `{"type": "scope_response", "scope": "website_and_code" | "website" | "code"}`.
  Only offered scopes are accepted; no answer within `SCOPE_INPUT_TIMEOUT_SECONDS` (300) keeps the default.
  In the console pick **Decide after launch** in the New scan card; the scan then shows a
  **What should this scan test?** dialog.
* **Named up front.** `"scan_scope": "..."` in the scan request (console: the **What to test** chips in
  the New scan card, Website + code by default for admins; **Code only** turns the card into "Which code
  should ScopeGuard analyse?": the link field is replaced by the code itself (code files or one .zip,
  uploaded when you launch, or a public `.git` link + optional branch/tag), sent with the request, so the
  scan does not pause again; MCP `start_scan(scan_scope=...)`; A2A `"scan_scope"`; the MCP chatbot's approval card has a
  **What to test** choice). Code scopes need the code (`upload_id` / `git_url`, or `ask_for_code` for a
  client that answers the code pause); `website` together with code is refused.
* **No website.** A code-only scan may omit `url` (MCP/A2A: `target_url`): nothing is checked against the
  network policy or the allowlist, and the report is labelled `source code (no website)`. Every other
  scope needs the URL (the error points at `url`); a code-only scan without one takes no extra hosts or
  target credentials.
* **Default.** Without either, the scope follows the request as before: code named or `ask_for_code` →
  website + code, otherwise website only.

Code scopes need `scan:source` (admin): other roles are offered the website only and never pause; a
code scope named by them is refused by RBAC. The choice is in the report (**Scope** row), in MCP
`get_scan.scan_scope` and in the audit record (`scope: {scope, decided_by}`, `decided_by` = operator,
request, default, timeout). A code-only run without code (skipped or refused) finishes with an empty
report and a red flag saying nothing was analysed.

## Source code at the SAST step (human in the loop)

Source code is analysed as a step of the agent graph (the code SAST step), with or without the
website steps (see [What to test](#what-to-test-website--code-website-only-code-only-human-in-the-loop)).
When the scan reaches the SAST step, its `code_source` node pauses (a LangGraph `interrupt`,
checkpointed) and asks you for the app's source code:

* **code files** (select several; packed into a zip on the server) or **one `.zip`**, or
* a **public git repository**: its `.git` clone link (`https://github.com/owner/repo.git`), optional
  branch or tag (empty = the default branch), on `GIT_ALLOWED_HOSTS` (default GitHub, GitLab,
  Bitbucket), or
* **skip** (website only; for a code-only scan nothing is analysed). No answer within `CODE_INPUT_TIMEOUT_SECONDS` (600) also means skip.

`code_sast` then unpacks and reads the code **only inside a Kubernetes Job** (or the process sandbox);
the code is never run. Its findings (`source: code_upload`) go into the scan's own report, which gets a
**Source code (code SAST step)** section (where the code came from, per-rule fixes, guardrail verdicts).
**One document per scan**: the website findings, the JavaScript SAST, the source-code findings, the
code's per-rule fixes and its guardrail verdicts are all in the same report (HTML, Markdown, JSON and
DOCX); there is no separate code report.
**Non-Python files are marked.** The code's files are classified from the zip's file list (nothing is
unpacked on the server): every program file that is not Python is listed in the report as "not Python,
partial coverage", its findings get a `[<language>, not Python: partial coverage]` prefix and `low`
confidence, and code with no (or mostly no) Python raises a red flag. The console's source-code dialog
marks such files before you send them, and MCP `get_scan.code_sast.languages` returns the same verdict.
**Executables and scripts are listed.** `.exe`, `.bat` and `.cmd` files are **warnings** (with a red flag),
`.sh` shell scripts only a **note** (most projects ship harmless build/deploy scripts). Files in the code (zip, files
or git) are listed under **Executable and script files** with their level; ScopeGuard never runs them,
but someone should review them. `.bat`/`.cmd` can be sent as code files; an `.exe`
only inside a `.zip`.
**Guardrails before and after.** The code step's **pre-guardrails** (authorization confirmed, the
`scan:source` permission, uploads enabled, a valid answer, then the upload's owner/archive or the git
checks below) and the sandbox's own pre-checks, and its **post-guardrails** (the sandbox output
re-validated, then the step's own: findings confined to the upload with our source tag, non-Python
findings marked, file names cleaned / secret-masked / withheld if they address AI agents, the git origin
re-validated) are all printed in the report's **Guardrails** table, in MCP and in the code audit trail
(`guardrail.pre` / `guardrail.post`, `stage: code_step`). Code refused by a pre-guardrail still gets a
report section that says which check failed.
**Python only for now**: the code analysis is built and tested for Python projects; other languages are only partly covered, so a clean result for them means little.

| How you answer | Console | WebSocket / API | MCP / A2A |
| --- | --- | --- | --- |
| Pause and ask (human in the loop) | **What to test** → website + code or code only (or **Ask me after launch**), then the **source code** dialog | `"ask_for_code": true` (or `"ask_scan_scope": true`); on `input_required` with `request.type == "code_source"` reply `{"type": "code_response", "action": "upload", "upload_id": ...}`, `{"action": "git", "git_url": "https://.../repo.git", "git_ref": <optional>}` or `{"action": "skip"}` | agents cannot answer a pause: name the code up front |
| Name the code up front | — | `upload_id` or `git_url` (+ `git_ref`) in the scan request, optional `scan_scope` | MCP `upload_code` → `start_scan(upload_id=..., scan_scope=...)`, or `start_scan(git_url=...)`; A2A `"upload_id"` / `"git_url"` / `"scan_scope"` |

Store code first with `POST /api/uploads?filename=src.zip` (raw `.zip`) or `POST /api/uploads/files`
with `{"files": [{"name": "app/main.py", "content": "..."}]}` (relative paths of source/text files the
analyzer reads, plus `.bat`/`.cmd`, at most `CODE_FILES_MAX_COUNT`, 1 MB each).

Git links are checked step by step, each a **pre-guardrail** verdict in the report: only the
repository's **`.git` clone link** is accepted (`https://github.com/owner/repo.git`, validated by the
Pydantic `GitLink` model: https, no credentials, port, query or fragment), the host must be on
`GIT_ALLOWED_HOSTS` and pass the network policy (never private/loopback/metadata), then a hardened
`git ls-remote` proves the repository is **reachable, public and not empty** and that the branch/tag
exists (one retry on a transient network error; nothing is downloaded yet). The console asks you to
fix the link while the scan waits. Only then the clone runs: https only, no credentials, submodules,
LFS, hooks or redirects (`git -c protocol.allow=never -c protocol.https.allow=always ... clone --depth 1
--single-branch [--branch <ref>] -- <url>`), one retry on a transient error, `GIT_CLONE_TIMEOUT_SECONDS`
and `GIT_CLONE_MAX_MB` caps; `.git` is dropped and only the text files are stored, as an upload. The
`git` binary must be installed (the Docker image installs it).

**The upload folder is deleted as soon as the code analysis is done** (archive, checkpoint and metadata; audited as
`upload.deleted`): the findings live in the scan's report, so your code is kept no longer than needed. Only a
failed analysis keeps the folder, until `CODE_UPLOAD_TTL_HOURS`, so a resumed scan can retry it from its checkpoint.
An upload id is therefore good for one scan.
Without Docker or Kubernetes it runs in the Python process sandbox (isolated interpreter, scrubbed
env, memory caps, an audit hook that blocks all egress, subprocesses and writes); that is a normal run,
reported as a note. A cluster that is reachable but unsafe (NetworkPolicy not enforced, RBAC) stays a red flag.

* **Where**: the console's **source code** dialog at the SAST step (admin; the **Source code SAST** card
  shows the sandbox status), `POST /api/uploads` / `POST /api/uploads/files` / a git link, or MCP
  `upload_code` → `start_scan(upload_id=...)`. `GET /api/uploads/policy` shows the accepted types, the git
  hosts and Kubernetes readiness.
* **Type checks**: the name must end in `.zip`, the MIME type must be a zip type
  (`application/zip`, `application/x-zip-compressed`, `application/x-zip`, `application/octet-stream`),
  and the first bytes must be a zip signature (a renamed `.exe`/ELF/tarball is refused with 415).
  Max `CODE_UPLOAD_MAX_MB` (50; MCP `MCP_MAX_UPLOAD_MB`, 10).
* **Archive safety** (flagged, never extracted): Zip Slip paths, symlinks, setuid bits, encrypted or
  duplicate entries, zip bombs (ratio and real decompressed bytes), executables/binaries, nested
  archives, names with control/bidi characters, and committed secrets files (`.env`, private keys,
  keystores, Terraform state, `.git`).
* **Checks**: SAST (SQL/NoSQL/command/LDAP injection, eval, deserialization, XXE, weak crypto, JWT,
  TLS), **XSS** (reflected responses, unescaped templates, `dangerouslySetInnerHTML`, `v-html`,
  Angular bypass, autoescape off), **IDOR / access control** (lookups by request ids, routes without an
  ownership check, admin routes without auth, mass assignment, open redirect, path traversal, CSRF off),
  SSRF, SSTI, insecure cookies, secrets, sensitive logging, obfuscated code / Trojan Source, supply chain
  (`postinstall`, `curl | sh`), Dockerfile / Kubernetes misconfiguration, **DOM-based attacks** (URL /
  referrer / postMessage data into HTML or code sinks, DOM open redirect, `javascript:` URL injection,
  message listeners without an origin check, prototype pollution, string timers) and **DoS weaknesses**
  in the code (ReDoS, regexes from input, unbounded body/upload sizes, HTTP calls without timeouts,
  loop/allocation sizes from input, XML entity expansion, login/reset/OTP routes without rate limiting).
  ScopeGuard only *detects* DoS weaknesses statically; it never sends denial-of-service traffic.
* **Coding standard (PEP 8)** for Python files (`scopeguard/codestyle.py`, stdlib, runs in the same sandbox):
  line length (79), tabs / indentation not a multiple of four, trailing whitespace, missing final newline,
  several imports on one line, wildcard imports, bare `except`, `== None` / `== True`, lambdas assigned to
  names, mutable default arguments (flake8-bugbear B006), CapWords classes and snake_case functions, and
  files that do not parse. Each rule is **one finding per file** (count + first line numbers), `info`, or
  `low` for the ones that hide bugs; at most 150 per scan so they never crowd out security findings. The
  report gets a **Coding standard (PEP 8)** table with a fix per rule and the PEP 8 link; MCP
  `get_scan.code_sast.coding_standard`, the console and the chatbot show the same summary.
* **Remediation**: every rule carries a fix, and the IDOR, XSS, DOM, DoS, injection and SSRF rules carry
  structured guidance (`scopeguard/remediation.py`): a summary, ordered steps, a **before/after code fix in
  the language of the affected file** (JS/TS, Python or PHP) and OWASP Cheat Sheet links. Reports have a
  **Recommendations** table (one row per rule) and a **Remediation** section in the scan report;
  MCP `get_scan` returns a `code_sast` summary.
* **Pre-guardrails** (before anything reaches the sandbox; a failure refuses the scan): `.zip` name, MIME
  type and zip signature, size cap, per-user upload rate (`CODE_UPLOAD_MAX_PER_HOUR`), the
  `authorization_confirmed` flag, archive integrity (SHA-256 unchanged since the upload), a metadata-only
  archive preflight (readable, entry/size limits, not all encrypted, something analysable), and sandbox
  readiness including the Kubernetes isolation probe.
* **Post-guardrails** (on the sandbox output, before it is shown or stored): schema validation, locations
  confined to the upload, secrets re-masked, control/bidi characters removed, prompt-injection text in the
  code flagged, size caps, and sandbox violations / partial scans turned into red flags. Both verdict lists
  are stored with the result, shown in the console, returned by MCP and printed in the report.
* **Separate audit trail** (`CODE_AUDIT_LOG_PATH`, `data/audit/code_audit.jsonl`): a hash-chained record
  for every upload, refusal, pre/post guardrail verdict, sandbox attempt (Job name, memory, multiplier,
  OOMKilled, files done), completion (with report hashes) and deletion; also the agent's code-check
  attempts. It never holds code or secrets. `uv run pentest-audit --trail code verify|list|show`,
  `GET /api/audit?trail=code`, the console's Audit card (Scans / Code & sandbox) and MCP
  `verify_audit_log(trail="code")`.
* **Sandbox**: one batch/v1 **Job** per scan running a stock image (`K8S_IMAGE`, default
  `python:3.12-slim`; pin a digest). The analyzer code is an immutable ConfigMap named after its
  SHA-256 (verified before use) mounted read-only; the zip is streamed into the pod's stdin. Deny-all
  NetworkPolicy (checked before every run), Pod Security `restricted`, no service-account token, DNS to
  127.0.0.1, non-root, read-only root, capabilities dropped, seccomp, `activeDeadlineSeconds`,
  `ttlSecondsAfterFinished`, optional `K8S_RUNTIME_CLASS` (gVisor/Kata). Set up once with
  `kubectl apply -f k8s/sandbox.yaml`. The same Job runs the agent's code check.
  Local cluster with Calico (enforces NetworkPolicy), step by step: [k8s/README.md](k8s/README.md).
* **Started before the console**: with `kubectl` present, `pentest-agent` / `scopeguard-demo` bring the sandbox
  up first (start the stopped kind node `K8S_KIND_CLUSTER`; if the cluster does not exist at all, create it from
  `k8s/kind-calico.yaml` and install the pinned, SHA-256-checked Calico (`K8S_AUTO_CREATE_CLUSTER`, needs the kind
  CLI; only into context `kind-<cluster>`; the first run takes minutes); apply `k8s/sandbox.yaml` if missing, ship the
  analyzer, run the isolation probe; at most `K8S_STARTUP_WAIT_SECONDS`), then serve the console; the start-up
  banner's **Code sandbox** line says where scans run. No `kubectl`, no Docker, or any step failing: scans run
  in the Python process sandbox (`SANDBOX_REQUIRE_KUBERNETES=false`, the default). By hand:
  `uv run python -m scopeguard.k8s --bootstrap`.
* **Retried until ready**: while the cluster is down (Docker or the kind node started later), the server retries
  the bring-up every `K8S_RETRY_SECONDS` (60; 0 = start-up only) and switches new scans to Kubernetes Jobs once
  it is ready, without a restart. The console's Source code SAST card refreshes itself (10 s while not ready, 30 s
  after) and shows the last check and retry.
* **Network isolation is proven, not assumed** (`K8S_VERIFY_NETWORK_ISOLATION=true`): before trusting a
  cluster, a probe Job in the sandbox namespace tries to reach the Kubernetes API and the internet; if
  either connects, scans are refused ("NetworkPolicy ... is NOT enforced"). Some network plugins (kind's
  default, Docker Desktop) ignore NetworkPolicy: use Calico or Cilium. Local kind cluster with Calico: see [k8s/README.md](k8s/README.md).
* **Memory and out-of-memory crashes**: the limit is **5×** the content size
  (`SANDBOX_MEMORY_MULTIPLIER`; floor 256 MB, ceiling 4 GB). If the pod is OOMKilled (or the analyzer
  hits `MemoryError`), it is retried **once with 10×** (`SANDBOX_RETRY_MEMORY_MULTIPLIER`) and
  **resumes from its checkpoint**: the analyzer streams a checkpoint after each batch of finished files,
  so files already analysed are not run again. A failed scan keeps its checkpoint, and starting it again
  later resumes too. The local process sandbox enforces the same limits (POSIX rlimits / Windows Job Object).
* **Afterwards**: the findings are in the web scan's report (`/reports/<session_id>/`), its audit record has a
  `code` block (source kind, upload id, archive hash, git URL and commit; never code), and the upload folder
  is already deleted (a failed analysis keeps it until `CODE_UPLOAD_TTL_HOURS` for a retry).

**Safety stop**: every agent node (and the sub-agents) may run at most
`AGENT_MAX_ITERATIONS` times per scan (default 5); past that the step is skipped with a
red flag and the run moves on, and a LangGraph `recursion_limit` backstops the whole run.

## Pipeline

validate/gate -> recon+crawl -> auth -> [human sign-in: SSO / MFA] -> JS SAST -> native DAST -> custom probes -> aggregate -> summary -> report (md + html + docx) -> audit record

## Sign-in with SSO / MFA (human in the loop)

The agent signs in to a target by itself only with a JWT or a username/password form. It never signs
in to an identity provider (Okta, Entra ID, Google, Auth0, SAML/OIDC, ...) and never stores MFA
secrets: those are designed to need a person. Instead, with `"interactive_auth": true` (admin,
`scan:authenticated`) the run **pauses** in the `auth_challenge` node with LangGraph `interrupt()`,
checkpointed, until the operator answers:

| Detected (tools/auth_detect.py) | What you do | What the agent does |
| --- | --- | --- |
| **SSO**: the login redirects to another host, posts SAML, links to an OIDC/OAuth `authorize` endpoint or a known IdP | Sign in in your own browser, then paste the target's session (Cookie header and/or bearer token) | Checks the session with one in-scope GET, then scans signed in |
| **MFA**: after the password step the target shows a one-time-code form (or redirects to `/mfa`, `/2fa`, `/otp`, ...) | Type the current code | Submits it to the target's own form with the pre-MFA session and CSRF token (no second login) |
| A login form but no credentials | Sign in yourself and paste the session | Same as SSO |

Protocol: the server sends `{"type": "input_required", "request": {"kind", "login_url", "idp_host",
"evidence", "target_url"}, "timeout_seconds": n}` and waits for
`{"type": "auth_response", "action": "skip" | "session" | "mfa_code", "cookie"?, "bearer"?, "code"?}`
on the same socket. Answers are validated strictly (no CR/LF, codes 4-12 characters); an invalid one
gets `{"type": "input_invalid"}` and the wait continues. No answer within `AUTH_INPUT_TIMEOUT_SECONDS`
(default 300) means skip: the scan continues unauthenticated. A client that disconnects while paused
can reconnect with `{"resume": true}` and is asked again.

Without `interactive_auth`, SSO and MFA raise a red flag and the scan runs unauthenticated. A password
login that lands on an MFA page or back on the login form is never counted as signed in. The session
(cookie or bearer) is sent by DAST and the probes to in-scope hosts only; it, the MFA code and the
pre-MFA session are never streamed to clients, logged, traced or written to the audit log, and
checkpoints holding them are AES-encrypted with `CHECKPOINT_ENCRYPTION_KEY`.

## Audit log

Every finished scan gets one record in `data/audit/audit.jsonl` (`AUDIT_LOG_PATH`), written by the
graph's last node `audit` for every run the graph executes (completed, refused by guardrails/RBAC,
safety stop) and by the server for outcomes the graph never sees: requests rejected before the graph
(token, role, cross-origin, queue full, invalid input), cached results, crashes and disconnects.
CLI scans (`scopeguard.cli`) are recorded too.

A record holds who (subject, roles, client IP, transport), what (sanitized target URL, profile, extra
hosts, which credentials were *provided*, never their values), when, the outcome and reason, the
steps run, result counts, how sign-in went (`auth.challenge`, `auth.challenge_result`) and the
SHA-256 of every report file. Records are hash-chained (`seq`, `prev`, `hash`); with `AUDIT_HMAC_KEY`
the chain is an HMAC, so records cannot be forged or rewritten without the key.

```bash
uv run pentest-audit verify --reports-dir data/reports   # exit 0 = intact, 1 = tampered (edits, gaps, reorders, changed reports)
uv run pentest-audit list --limit 20
uv run pentest-audit show <session_id>
```

`GET /api/audit` (permission `audit:read`, admins) returns the newest records plus a fresh
verification; the console shows it as the audit trail.

## LLM prompts (`prompts/`)

The system prompts for every LLM step are plain-text files in a local `prompts/` folder at the repo
root, committed with the repository. Each step loads its prompt with
`pentest_agent/prompts.py` from `PROMPTS_DIR` (default `./prompts`, relative to the working directory):

| File | Used by |
| --- | --- |
| `run_summary.md` | rolling summary of the run once the message history grows long (`graph.maybe_summarize`) |
| `executive_summary.md` | executive summary in the report, citing `[Sn]` sources (`graph.generate_executive_summary`) |
| `probe_plan_system.md` | custom probe plan (`subagents/codegen_subagent.generate_probe_plan`) |
| `golden_judge.md` | LLM-as-judge in the golden-dataset drift check (`evals/golden.judge_messages`) |
| `content_injection_reminder.md` | reminder paired with untrusted page content (`guardrails.content_injection_system_reminder`); `{{start}}` and `{{end}}` are replaced with the untrusted-content markers |

If a file is missing or empty, its step uses the same deterministic fallback as when no `GROQ_API_KEY`
is set. The scanner still runs and still writes reports, but without LLM-written text:

* the executive summary is the deterministic, fully cited summary, and `fallback_reason` names the missing file;
* the probe plan is the built-in default plan;
* the golden check reports `NOT_EVALUATED` when the judge prompt is missing.

Notes:

* The tests don't read your `prompts/`. `tests/conftest.py` writes stand-in prompts to a temp folder
  and points `PROMPTS_DIR` at it. With `GOLDEN_LIVE=1`, tests use the real `./prompts`.
* `docker build` copies `prompts/` into the image, so the image runs with the same prompts as the repo.

## Source citations (anti-hallucination)

Every finding becomes a numbered source `S1..Sn` (most severe first), linked to its in-scope URL and its
MITRE CWE page. The LLM executive summary must cite claims as `[Sn]`; afterwards
`scopeguard/citations.py`:

* removes citations to ids that are not in the source dictionary, and URLs that are not a known source
  or the target (hallucinated links);
* replaces surviving `[Sn]` markers, by regex, with links built from the dictionary;
* falls back to a deterministic, fully cited summary when the LLM answer is empty or has no valid citation.

Reports end with a **Sources** section; finding headings carry their `[Sn]` anchor.

## What the native DAST does (all GET/HEAD/OPTIONS/TRACE, non-destructive)

Spider (same-scope only) • security headers • cookie flags • CORS origin reflection • directory listing •
verbose errors • exposed `.env`/`.git`/phpinfo (soft-404 aware) • reflected input (unencoded `< " '`) •
error-based SQLi signature • open redirect (never followed) • path traversal signature • risky HTTP methods
(TRACE) • password-over-HTTP • POST form without CSRF token • JS static rules (eval, innerHTML, secrets...).

`quick` = passive only. `standard` = + active checks. `aggressive`/`auth_deep` = more targets + payload variants.

## Custom probes (`tools/probe_runner.py`)

The LLM (or, without one, a built-in default plan) picks up to 16 checks from a fixed list. Hand-written
Python runs each check with GET or OPTIONS only, never follows redirects, and never runs generated code.
What the planner sees from the scanned site (the crawled paths, reduced to in-scope relative
paths, and the findings so far) is wrapped as untrusted data and paired with the
content-injection reminder; without that reminder prompt the LLM is not called at all.

| Probe type | What it reports |
| --- | --- |
| `security_headers` | missing HSTS, CSP, X-Content-Type-Options, Referrer-Policy, clickjacking protection |
| `csp_weakness` | a CSP that allows `'unsafe-inline'` (without nonce/hash), `'unsafe-eval'`, wildcard script sources, or unrestricted `object-src` |
| `cors` | a reflected untrusted Origin, or wildcard origin with credentials |
| `cookie_flags` | cookies without Secure, HttpOnly or SameSite |
| `cache_control` | responses that set cookies or answer an authenticated request without `no-store`/`private` |
| `http_methods` | methods advertised by `OPTIONS` (informational) |
| `server_banner` | server or framework versions in `Server`, `X-Powered-By` and similar headers |
| `information_disclosure` | stack traces and verbose framework errors in the body |
| `directory_listing` | auto-generated file indexes (Apache, nginx, IIS, Tomcat, Python) |
| `mixed_content` | `http://` scripts, styles, frames (Medium) or images/media (Low) on an HTTPS page |
| `insecure_transport` | the page answers on plain HTTP without redirecting to HTTPS (Informational for local/private hosts) |
| `open_redirect` | a query parameter that redirects to an outside host, tested with the unresolvable `https://scopeguard.invalid/` |
| `reflected_marker` | a harmless marker echoed back from a query parameter (informational, not proof of XSS) |

`open_redirect` and `reflected_marker` need a parameter name seen during the crawl. The default plan runs
the baseline checks on `/`, then open-redirect checks on redirect-like parameters (`next`, `url`, `return`, ...),
directory-listing checks on up to two crawled directories, then reflection checks.

**Slow or flaky sites.** A probe whose request times out or loses its connection is retried with
tenacity: up to `PROBE_MAX_ATTEMPTS` (5) tries, exponential backoff 2, 4, 8, 16 s (never shorter than
the `Retry-After` the site sent earlier in the run), 25 s to answer on a retry. All retries of one scan
together take at most `PROBE_RETRY_BUDGET_SECONDS` (180), so a site that is down does not stall the
scan. HTTP 429 itself is retried by the transport, which honours `Retry-After`. A check that still
fails becomes a plain red flag, e.g. "csp_weakness at /: the site sent no response within 25 s
(tried 5 times), so this check was not run".

## Caching (saves LLM cost and repeat requests)

Identical work within `CACHE_TTL_SECONDS` (default 300, i.e. 5 minutes; `0` turns caching off) is reused
instead of repeated (`pentest_agent/ttl_cache.py`):

| What | Reused when |
| --- | --- |
| Whole scan (WebSocket) | same request: URL, profile, credentials, extra domains and notes (`session_id` aside). The reply arrives instantly with `"cached": true`, `cached_from_session` and `cache_age_seconds`, and points at the earlier report. Send `"force_refresh": true` to scan again. |
| Probe check | same probe type, URL, parameter and bearer token |
| Probe plan (LLM) | same model, prompt, target, scope, findings and crawled pages |
| Executive summary (LLM) | same model, prompt and findings; only grounded answers are cached |
| Run summary (LLM) | same model and transcript |

Keys are SHA-256 digests, so tokens and passwords that are part of a key are never stored. Random finding
ids are left out of keys so a repeat scan still matches. Errors and fallbacks are never cached. Caches live
in memory in one server process and are shared by all its sessions; a restart empties them. The golden
drift check always calls the model fresh and never uses the cache.

## HTTP 429 handling

* **Scanned link**: every client that talks to the target (engine `ScopedClient`, and the agent's httpx
  clients via `http_retry.RateLimitRetryTransport`) retries `429` (and `503` with `Retry-After`) up to 3
  times, honouring `Retry-After` (seconds or HTTP-date, capped at 30s) or backing off 1/2/4s, and slows
  down after being throttled. Throttling is reported as a **red flag**, so incomplete results are visible.
* **LLM (Groq)**: retries 429/5xx, waiting for Groq's `Retry-After` (capped at 60s) or jittered backoff.
* **Backend**: a per-client-IP limit returns `429 Too Many Requests` + `Retry-After` on HTTP routes
  (`/healthz` exempt). Configure with `HTTP_RATE_LIMIT_PER_MINUTE`. Concurrency is handled by the
  server-wide queues below.

## API management (queues)

The server runs **1 WebSocket scan** and **1 HTTP API call** at a time, across all clients.
Up to **50** more of each wait in a first-come, first-served queue. When a queue is full, the request
gets `429` with the message *"Too many requests … Please try again after some time."* and a
`Retry-After` (WebSocket: error message, then close code `4429`). `/healthz` is never queued.

A queued WebSocket client gets a `queued` message right away, whenever its place changes, and every
`QUEUE_UPDATE_SECONDS` (default 5) while it waits:

```json
{"type": "queued", "position": 3, "queue_length": 5, "active": 1, "max_active": 1, "max_queue": 50,
 "estimated_wait_seconds": 240,
 "message": "Server busy (1/1 scans running). You are #3 in the queue: your scan starts after 3 more scan(s) finish (about 240s)."}
```

`position` is also the number of running scans that must finish before this one starts.
`estimated_wait_seconds` comes from recent scan durations (`null` until one has finished). When the
scan starts, the client gets `{"type": "status", "event": "queue_admitted", "waited_seconds": ...}`
and the normal flow continues. Disconnecting while queued gives up the place.
`scripts/ws_client.py` prints these as `[queue]` lines.

HTTP calls wait silently (at most `HTTP_QUEUE_TIMEOUT_SECONDS`, default 60, then `429`). Every
response carries `X-Queue-Position` (place at arrival, `0` = no wait) and `X-Queue-Wait-Seconds`.
`GET /healthz` shows the current counts:
`"queues": {"websocket": {"active", "max_active", "waiting", "max_queue"}, "http": {...}}`.

| Setting | Default | Meaning |
| --- | --- | --- |
| `WS_MAX_ACTIVE` / `HTTP_MAX_ACTIVE` | 1 | run at once (server-wide); `0` disables the queue |
| `WS_MAX_QUEUE` / `HTTP_MAX_QUEUE` | 50 | waiting places; more get `429` |
| `QUEUE_UPDATE_SECONDS` | 5 | interval of `queued` updates to waiting WebSocket clients |
| `HTTP_QUEUE_TIMEOUT_SECONDS` | 60 | longest an HTTP call waits before `429` |

The queues are in-process (`pentest_agent/admission.py`): run a single uvicorn worker.

## LangSmith tracing

Set `LANGSMITH_TRACING=true` and `LANGSMITH_API_KEY` (legacy `LANGCHAIN_*` names also work). Each scan is one
run tree: graph nodes, tools, Groq calls, the sandboxed DAST scan, probe planning/running, JS SAST and the
citation-grounding step, tagged with session id, target host and profile. A dedicated client redacts JWTs,
passwords, cookies, Authorization headers and API keys from inputs, outputs and metadata before upload.
Step-by-step setup, what each run shows and troubleshooting: [docs/LANGSMITH.md](docs/LANGSMITH.md).

## Golden dataset and drift check

Drift is decided on the **results** the summary reports, not on its citation formatting: required
findings reported (cited **or** named), severities attributed correctly, counts not inflated, plus safety
checks (an answer exists, no invented URLs or forbidden claims, length). Citation checks are listed for
information only. A case whose data could not be collected (crash, killed run) is `NOT_EVALUATED`, never
`DATA_DRIFT`; a model failure on drifted data is labelled *unattributed*. The report models are pydantic
(`CaseResult.status`, a validator that makes verdict / exit code / drift flags consistent,
`verdict_explanation`). `golden-check --reclassify` re-scores every stored run in `golden/results/` with
the current rules (no LLM calls) and writes `golden_report.reclassified.{json,md}` next to each original.

`golden/golden_dataset.json` holds the golden cases (sandboxed scans of the built-in target and fixed
findings fixtures, with recorded baselines and reference summaries). `uv run golden-check` runs the real
pipeline on each case and checks:

* **Auth (JWT + RBAC)**: with `AUTH_ENABLED=true` every run mints a fresh access token for the subject
  `golden-check` (roles from `AUTH_CLIENT_ROLES`; keys are created if missing), verifies it exactly like the
  API does, checks each case's profile against the roles, and renews the token if it nears expiry. The report
  shows subject, roles, key id and expiry (never the token). An auth or permission failure is `NOT_EVALUATED`
  (exit 2), not drift.
* **Data (deterministic)**: required/forbidden finding titles, title-set Jaccard, severity histogram (±tolerance),
  pages crawled, blocked links, and input fingerprints against the baseline.
* **Model (deterministic)**: the LLM answer is used (no fallback), no hallucinated `[Sn]` ids or invented URLs,
  minimum citations, required sources cited, forbidden phrases absent, length, and severity grounding:
  a sentence about one severity level may only cite findings of that level (`severity_consistent_citations`),
  and per-severity counts such as "11 high" may not exceed SOURCES (`severity_numbers_grounded`).
* **Model (LLM-as-judge)**: a pydantic `JudgeVerdict` (faithfulness, coverage, citation accuracy, clarity, overall,
  hallucinations quoted from the answer). The judge sees every source plus the per-severity counts, and is
  told that SOURCES are the ground truth and the reference only an example. It runs
  `thresholds.judge_runs` times (3); the **median** `overall` must be **>= 7** (`thresholds.min_judge_score`).
  Set `GOLDEN_JUDGE_MODEL` to use a different judge model than the generator.
* **Reference freshness**: each reference summary is stamped (`baseline.reference_sha256`) together with the
  baseline it describes. If the baseline changes and nobody has reviewed the reference since, the case is
  `NOT_EVALUATED` instead of being judged against outdated facts.

It prints one strict verdict and exits with its code:

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `NO_DRIFT` | 0 | data and model checks passed |
| `DATA_DRIFT` | 10 | the model's input data changed (scanner output / fixtures differ from baseline) |
| `MODEL_DRIFT` | 20 | data is stable but the LLM output failed a check or scored below threshold |
| `DATA_AND_MODEL_DRIFT` | 30 | both (model failures on drifted cases are not attributed to the model) |
| `NOT_EVALUATED` | 2 | no `GROQ_API_KEY`, judge error, or a case whose data could not be collected (crash/killed run): not drift |

Results are written to `golden/results/golden-<timestamp>/golden_report.{json,md}` and
`golden/results/latest.json` (git-ignored). `--allow-no-llm` runs data checks only; after an intentional
scanner change, re-capture baselines with `uv run golden-check --record-baseline`. It flags each case whose
reference needs review; rewrite those `reference_summary` texts, then run `uv run golden-check --approve-references`.
`GOLDEN_LIVE=1 uv run pytest tests/test_golden_dataset.py` also runs the live judge inside pytest.

## MCP chatbot (`chatbots/`)

A LangChain `create_agent` chatbot (with `AgentState` and an in-memory checkpointer) that
uses the scanner's MCP server as its tools:
- **Approval:** a human approves every scan (`HumanInTheLoopMiddleware`).
- **Streaming:** scan steps stream live.
- **Results:** the scanner's own result block is shown, and the model explains it.
- **Interfaces:** one command (`chatbots/ui/serve_ui.py`) starts the scanner, the
  chatbot and a browser UI where you add any number of allowed targets. A terminal version
  and a single Dockerfile are included.
- **Separate project:** it has its own uv project and venv, because `langchain-mcp-adapters`
  needs the MCP 1.x client.
- **Settings:** it uses the Groq key and model from this repo's `.env`.
- **Guardrails:** messages are checked before they reach the LLM (jailbreaks, prompt
  injection and prompt-leak attempts, approval bypass, SQL / shell / script / template
  payloads, path traversal, pasted secrets), tool arguments before every call, and answers
  on the way out (no prompt leakage, secrets redacted).
- **Tool switches:** `CHATBOT_DISABLED_TOOLS` (or `--disable-tool`) turns chat tools off;
  tools the server disabled (`MCP_DISABLED_TOOLS`) are never offered.

```powershell
uv run --project chatbots\mcp_chatbot python chatbots\ui\serve_ui.py --allow your-site.example --allow other-site.example
```

See [chatbots/README.md](chatbots/README.md).

## Docker

```bash
docker build -t pentest-agent .
docker run --rm -p 8765:8765 --env-file .env \
  -v "$PWD/golden/results:/app/golden/results" pentest-agent
```

The container runs **pytest** (offline; keys masked), then the **golden-dataset drift check** (needs
`GROQ_API_KEY`), then starts the **server** on `0.0.0.0:8765`, stopping at the first failure with that
step's exit code. `-e GOLDEN_ARGS=--allow-no-llm` skips the model part. `.env` is never copied into the image.

## Docker-free sandbox (`src/scopeguard/sandbox.py`, `worker.py`)

Scans run in a child interpreter (`python -I`) with: scrubbed environment (no API keys), throwaway working dir,
a permanent **audit hook** blocking subprocess/exec/fork/listening sockets, writes outside the sandbox dir,
DNS for non-allow-listed names, and any connection except allow-listed IP:port; POSIX rlimits (CPU, memory,
file size, fds); hard wall-clock kill. Inside, `ScopedClient` re-checks scope on every request, never follows
redirects automatically, and enforces a request budget and size caps. `tests/test_scopeguard_sandbox.py`
proves the escapes are blocked. (Windows: rlimits unavailable; all other layers apply.)
This is strong process-level containment, not a VM/kernel boundary. Do not scan hostile targets with it on a
machine holding secrets you cannot afford to expose.

## Network policy: no metadata, no DNS rebinding (`src/scopeguard/netpolicy.py`)

Some addresses are never reached by a scan:

- link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, `100.100.100.200`,
  `192.0.0.192`, `metadata.google.internal`, …);
- `0.0.0.0/8` and `::`, multicast, reserved and broadcast addresses;
- IPv6 forms that hide one of those (IPv4-mapped, NAT64, 6to4, Teredo) are unwrapped and refused too.

`BLOCK_PRIVATE_TARGETS=true` also refuses loopback and private ranges (`127/8`, `10/8`, `172.16/12`,
`192.168/16`, `100.64/10`, `fc00::/7`, `localhost`). It defaults to `false` so local dev apps and the demo
target can be scanned. The policy is enforced in four places:

| Layer | What happens |
| --- | --- |
| Browser console | An obviously blocked URL (e.g. `http://169.254.169.254/`, `http://0xA9FEA9FE/`) disables Launch with the reason. |
| Pre-scan guardrail | The target and every extra allowed host are resolved. If any address is blocked, the scan is refused (`validate → blocked`, shown as REFUSED); an unresolvable target is refused too. |
| Every agent-side connection (`http_retry.PinnedNetworkBackend`) | The host is resolved and every address checked, then the socket opens to exactly the checked IP (TLS still verifies the real host name). A DNS answer that changes mid-scan (DNS rebinding) is refused before any socket is opened. Environment proxies are ignored. |
| Sandbox worker | Blocked addresses never enter the egress allowlist and are never probed; a blocked target ends the scan with an error. |

`scopeguard.cli --url` applies the same check (exit code `5`) and reads `BLOCK_PRIVATE_TARGETS` from the
environment.

## Scans never download files (`src/scopeguard/contentpolicy.py`)

- **No file links are crawled.** Links to executables, installers, archives, disk images, office/PDF
  documents, media, fonts and wasm are never requested by the crawlers. Fixed security probes such as
  `/backup.zip` still send their single request but only use the status and headers.
- **Attachments and binaries are discarded unread.** This covers `Content-Disposition: attachment`, binary
  media types and unsupported compression (`br`, `zstd`): the connection is closed without reading the body.
  The response keeps its status and headers plus `x-scopeguard-body-dropped: <reason>`.
- **Unknown types are sniffed.** At most 64 KB is read; a body with NUL bytes or a file signature
  (MZ/ELF/ZIP/PDF/…) is discarded. Text bodies are capped at 2 MB in memory, and gzip/deflate is decoded
  with a hard output cap, so a compression bomb cannot expand.
- **Nothing from the target is saved as a file.** The one exception is the sandboxed code check, which stages
  the *text* of in-scope HTML pages and JavaScript under fixed names (`pages/0001.html`, `scripts/0001.js`)
  in a private temp folder, packs that text into the sandbox Job's input (no network there) and deletes the
  folder when the check ends. Reports quote short evidence snippets as text.
- **Refused downloads are reported.** The report's attack coverage lists them as "File downloads refused".

## Layout

`src/scopeguard/` stdlib-only engine, sandbox, citations, rate limiting, reports, simulated target, CLI.
`src/pentest_agent/` LangGraph agent, guardrails, schemas, tools, tracing, rate limits, websocket server,
`evals/golden.py`, `prompts.py`, `audit_log.py`, `web_ui.py` + `webui/`, `scan_service.py` (shared rules for agent
callers), `mcp_server/` and `a2a_server/` (each with a `CLAUDE.md` usage guide), `credential_store.py`.
`golden/golden_dataset.json`, `tests/`, `scripts/simulate_full.py`, `scripts/mcp_client.py`, `scripts/a2a_client.py`,
`scripts/render_docs.py` (docs diagrams from `docs/src/`), `Dockerfile`, `.mcp.json`.
`prompts/` holds the LLM prompt texts; see [LLM prompts](#llm-prompts-prompts).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Copyright 2026 Priyojit Chakraborty; see
[NOTICE](NOTICE). Use ScopeGuard only against systems you own or are explicitly authorized to test.
