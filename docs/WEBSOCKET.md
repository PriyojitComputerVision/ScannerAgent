# Running scans over the WebSocket

This guide covers `ws://<host>:<port>/ws`: how to run it, every message the server sends and expects,
how a client should handle each one, and CORS for browser pages on another origin. The terminal client
`scripts/ws_client.py` speaks the whole protocol and prints every frame, so it doubles as a live
reference. Only scan sites and code you own or are authorized to test.

- [1. Quick start](#1-quick-start)
- [2. Connecting](#2-connecting)
- [3. What the client sends](#3-what-the-client-sends)
- [4. What the server sends, and how to handle it](#4-what-the-server-sends-and-how-to-handle-it)
- [5. Pauses (human in the loop)](#5-pauses-human-in-the-loop)
- [6. Source code: how files reach the scan](#6-source-code-how-files-reach-the-scan)
- [6a. Recipes: website only, website + code, code only](#6a-recipes-website-only-website--code-code-only)
- [7. Errors and close codes](#7-errors-and-close-codes)
- [8. Resume, cache, queue, token renewal](#8-resume-cache-queue-token-renewal)
- [9. CORS and browser clients](#9-cors-and-browser-clients)
- [10. Minimal clients (Python, browser JavaScript)](#10-minimal-clients)
- [11. ws_client.py reference](#11-ws_clientpy-reference)

## 1. Quick start

```bash
# terminal 1: the server (console at http://127.0.0.1:8765/, WebSocket at /ws)
uv run pentest-agent

# terminal 2: a scan of the built-in vulnerable target, every frame printed as pretty JSON
uv run python scripts/ws_client.py --simulate --frames

# or let the client ask for everything (numbered menus; the JWT is automatic)
uv run python scripts/ws_client.py
```

Output, shortened (colours in a terminal; secrets masked):

```text
[sim]    built-in vulnerable target at http://127.0.0.1:53121
[auth] token signed locally with keys/ for 'pentest-client', roles: admin
[ws]     connect ws://127.0.0.1:8765/ws?session_id=ws-1795600000 (token in message)
------------------------------------------------------------------------
>>> SENT  14:02:11.120  scan request  (1012 bytes)
    {
      "access_token": "*** (803 chars)",
      "url": "http://127.0.0.1:53121",
      "profile": "standard",
      "authorization_confirmed": true,
      "additional_allowed_domains": []
    }
------------------------------------------------------------------------
------------------------------------------------------------------------
<<< RECV  14:02:11.301  status  (78 bytes)
    {
      "type": "status",
      "message": "Starting scan of http://127.0.0.1:53121/",
      "profile": "standard"
    }
------------------------------------------------------------------------
<<< RECV  14:02:11.402  phase_update  node=validate  (190 bytes)
    ...
<<< RECV  14:03:40.877  complete  (48211 bytes)
    {
      "type": "complete",
      "session_id": "ws-1795600000",
      "report_url": "http://127.0.0.1:8765/reports/ws-1795600000/",
      "report_md": "# Security report ... (+47012 chars)",
      ...
    }
[done]   session ws-1795600000 complete
SIMULATION PASSED
```

Without `--frames` you get the frames you send as pretty JSON and one summary line per server message.

## 2. Connecting

```
ws://127.0.0.1:8765/ws?session_id=<id>
```

| Part | Rule |
| --- | --- |
| `session_id` | Required. 1-128 characters `A-Z a-z 0-9 . _ -`, starting with a letter or digit, no `..`. It names the checkpoint thread and the report folder, so reuse it only to resume. |
| Access token | An RS256 JWT from `POST /auth/token` (`{"client_id", "client_secret"}`) or `scripts/get_token.py`. Send it in **one** of three places: the `Authorization: Bearer <jwt>` handshake header; `?access_token=<jwt>` (avoid: URLs end up in logs); or `"access_token"` inside the first JSON message (the default, and the only option for browsers). The token needs `scan:run`. |
| `Origin` | Scripts send none and are fine. A browser always sends one: it must be the server's own origin or listed in `CORS_ALLOWED_ORIGINS` (section 9), otherwise you get error 403 and close `4403`. |
| First message | Must arrive within 15 s when the token is in it. |

## 3. What the client sends

### 3.1 The scan request (first message)

Strict JSON object: unknown keys are refused (`422`), booleans must be real `true`/`false`.

| Key | Type | Notes |
| --- | --- | --- |
| `url` | string | The site to test. Optional only for `scan_scope: "code"`. |
| `authorization_confirmed` | `true` | **Required.** Anything else: error, close `4403`. |
| `profile` | `quick` \| `standard` \| `aggressive` \| `auth_deep` | Default `standard`. `aggressive`/`auth_deep` need the admin role. |
| `additional_allowed_domains` | string[] | Extra in-scope hosts (max 20). |
| `notes` | string | Stored with the scan (max 2000 characters). |
| `jwt` / `auth` | string / `{login_url, username, password, username_field?, password_field?, extra_form_fields?}` | Credentials **for the target** (needs `scan:authenticated`). |
| `interactive_auth` | bool | Pause for SSO / MFA sign-in (section 5). |
| `scan_scope` | `website_and_code` \| `website` \| `code` | What to test. Default: derived from the request. |
| `ask_scan_scope` | bool | Pause before any request and ask what to test. |
| `upload_id` | 32 hex | Code stored over HTTP (section 6). Not with `git_url`. |
| `git_url` / `git_ref` | string | Public `.git` clone link (+ branch/tag) on `GIT_ALLOWED_HOSTS`. |
| `ask_for_code` | bool | Pause at the SAST step and ask for code. |
| `force_refresh` | bool | Ignore a cached result for the same request. |
| `access_token` | string | Your API token (removed before anything else sees the message). |

```json
{"access_token": "eyJ...", "url": "https://staging.example.com", "profile": "quick",
 "authorization_confirmed": true}
```

### 3.2 Resume

Exactly `{"resume": true}` (plus `access_token` if it travels in the message), on the same `session_id`.

### 3.3 Answers to pauses

Sent on the same socket after an `input_required` message (section 5):

| Pause `request.type` | Answer |
| --- | --- |
| `scan_scope` | `{"type": "scope_response", "scope": "website"}` |
| `code_source` | `{"type": "code_response", "action": "upload", "upload_id": "<32 hex>"}`, `{"type": "code_response", "action": "git", "git_url": "https://github.com/o/r.git", "git_ref": "main"}` or `{"type": "code_response", "action": "skip"}` |
| `sign_in` | `{"type": "auth_response", "action": "mfa_code", "code": "123456"}`, `{"type": "auth_response", "action": "session", "cookie": "sid=...", "bearer": "..."}` or `{"type": "auth_response", "action": "skip"}` |

## 4. What the server sends, and how to handle it

Every server frame is one JSON object with a `type`. Handle them in a loop until `complete` or `error`.

| `type` | When | Key fields | What the client should do |
| --- | --- | --- | --- |
| `queued` | Server busy (`WS_MAX_ACTIVE` scans running) | `position`, `queue_length`, `active`, `max_active`, `estimated_wait_seconds`, `message` | Show the position and keep the socket open. Updates arrive on change and every `QUEUE_UPDATE_SECONDS`. |
| `status` | Progress notes | `message`, optional `event` (`queue_admitted`, `input_received`, `input_timeout`, `git_probe`, LLM rate-limit waits), `profile`, `wait_seconds`, `attempt` | Display it. Nothing to answer. |
| `phase_update` | After each graph step | `node` (e.g. `recon`, `dast`, `run_probes`, `report`), `data` (the step's **new** state: `phase`, `findings`, `red_flags`, `crawled_pages`, report links, ...) | Lists in `data` are **increments**: append them, don't replace. Merge findings per issue + URL if you show live totals (the report does the same). Secrets and server file paths are never in `data`. |
| `input_required` | The scan paused for the operator | `request` (`type` = `scan_scope` \| `code_source` \| `sign_in` + details), `timeout_seconds`, `message` | Answer with the matching `*_response` (section 3.3) before the timeout. No answer = default scope / skip. |
| `input_invalid` | Your answer was refused | `message`, optional `detail` (validation errors) | Ask again and resend. The pause is still open. |
| `token_refreshed` | Your API token is about to expire (`JWT_AUTO_REFRESH_BEFORE_MINUTES`) | `access_token`, `expires_at`, `expires_in` | Store it for the next HTTP call / resume. The socket stays authenticated. |
| `complete` | The run finished (or a cached result was served) | `session_id`, `report_url`, `report_html_url`, `report_md_url`, `report_json_url`, `report_docx_url`, `report_md`, `langsmith_project`; cached: `cached`, `cached_from_session`, `cache_age_seconds` | Show the report. Report URLs need the token (`Authorization` header, or `?access_token=` once; a cookie then covers relative links). The server closes the socket. |
| `error` | Refusal or failure | `message`, usually `code` (HTTP-like), `detail` for `422`, `retry_after` for `429` | Show it and stop. The close code (section 7) tells you whether to retry, resume or fix the request. |

Findings in `phase_update.data.findings` and in the report come from the scanned site: treat them as
untrusted text (escape before rendering, never execute or follow links automatically).

## 5. Pauses (human in the loop)

A run pauses only when the request asks it to (`ask_scan_scope`, `ask_for_code`, `interactive_auth`), so
clients that cannot answer never wait. Pauses happen in this order:

```
validate -> choose_scope [scan_scope pause] -> recon -> auth [sign_in pause] -> code_source [code_source pause] -> ...
```

```json
{"type": "input_required", "timeout_seconds": 300,
 "message": "Nothing has been sent to the target yet. Pick what this scan tests; ...",
 "request": {"type": "scan_scope", "target_url": "https://staging.example.com/",
             "options": [{"value": "website_and_code", "label": "...", "description": "..."},
                         {"value": "website", "label": "...", "description": "..."},
                         {"value": "code", "label": "...", "description": "..."}],
             "default": "website"}}
```

- `scan_scope`: answer with one of `request.options[].value`. Timeout `SCOPE_INPUT_TIMEOUT_SECONDS` (300) keeps `default`.
- `code_source`: `request` lists `accepts`, `max_upload_mb`, `max_files`, `git_enabled`, `git_hosts`. Upload the code over HTTP first, then answer with the `upload_id` (section 6). A git link is checked (host allowlist, reachable, branch exists) before the scan resumes. A failed check returns `input_invalid`, so you can fix the link. Timeout `CODE_INPUT_TIMEOUT_SECONDS` (600) = skip.
- `sign_in`: `request.kind` is `mfa` (send the one-time `code`) or `sso` (sign in in your own browser, then send the target's `cookie` header value and/or a `bearer` token). Timeout `AUTH_INPUT_TIMEOUT_SECONDS` (300) = continue unauthenticated.

After a valid answer you get `status` with `event: "input_received"`, and the run continues.

## 6. Source code: how files reach the scan

**Files never travel over the WebSocket, and they are not base64 on this path.** The socket only carries
a reference (`upload_id`) or a `git_url`. Store the code first over HTTP (admin token, `scan:source`):

```bash
# a .zip as the raw request body (binary, not base64)
curl -X POST "http://127.0.0.1:8765/api/uploads?filename=src.zip" \
     -H "Authorization: Bearer $T" -H "Content-Type: application/zip" --data-binary @src.zip

# or code files as JSON text (plain strings, not base64); the server packs them into a zip
curl -X POST http://127.0.0.1:8765/api/uploads/files \
     -H "Authorization: Bearer $T" -H "Content-Type: application/json" \
     -d '{"files": [{"name": "app/main.py", "content": "print(1)\n"}]}'
```

Both return `201` with an `upload_id`. Put it in the scan request (`"upload_id": "..."`) or in a
`code_response`. An upload serves one scan: it is deleted after a successful analysis. The only base64
path is the MCP tool `upload_code`, because a zip has to fit inside a JSON tool call. A git link is cloned
by the server (`--depth 1`, hardened), so nothing is uploaded at all.

`scripts/ws_client.py --code-path <.zip or folder>` (or the wizard's "local .zip file or project
folder") does the upload for you: a folder is zipped in memory and sent as the raw `POST /api/uploads`
body with the automatic token; the returned `upload_id` goes into the scan request. The zip leaves out
what the folder's `.gitignore` files exclude (so `.env`, `keys/`, `data/` stay on your machine),
vendored / cache folders (`.git`, `node_modules`, `.venv`, `.ruff_cache`, ...), symlinks, documents
(`.md`, `.txt`, `.pdf`, `.docx`, `.mmd`, ...), images and model weights (`.pkl`, `.pt`, `.onnx`, `.h5`, ...).
Code needs the admin role (`scan:source`) and is analysed as Python (other languages: partial coverage,
marked in the report). Not analysed: whatever the project's .gitignore excludes, pytest files (test_*.py, *_test.py, conftest.py), .claude/ and cache / vendored folders, documents (.md, .txt, .pdf, .docx, .mmd, ...), images and model weights (never opened). A bundled zip whose files are all in the upload as source is not reported as a nested archive.

## 6a. Recipes: website only, website + code, code only

`scan_scope` decides what is tested. Leave it out and the server derives it: code named or
`ask_for_code` = `website_and_code`, otherwise `website`. Nothing is sent to a website with `code`.
Every recipe needs `authorization_confirmed: true`, so only use targets and code you own or may test.
`$T` is an access token: `uv run python scripts/get_token.py` saves one to `keys/token.json` (it is not printed),
then `T=$(uv run python -c "import json; print(json.load(open('keys/token.json'))['access_token'])")`. `ws_client.py` gets one itself.

In every recipe you can also run `uv run python scripts/ws_client.py` with no arguments. It asks the
same questions as numbered menus: target, URL, authorization, code (local path / git / upload id),
scope, extra domains, sign-in pause, profile, cache, notes, session id, output. It then shows the
exact frame it will send and waits for "Start?".

### Website only (custom URL)

```json
{"url": "https://staging.example.com", "profile": "standard", "authorization_confirmed": true,
 "scan_scope": "website", "additional_allowed_domains": ["api.staging.example.com"]}
```

```bash
uv run python scripts/ws_client.py https://staging.example.com --scope website \
    --allow-domain api.staging.example.com --i-have-authorization --frames
```

### Website + code from a git repository

```json
{"url": "https://staging.example.com", "profile": "standard", "authorization_confirmed": true,
 "scan_scope": "website_and_code", "git_url": "https://github.com/you/app.git", "git_ref": "main"}
```

```bash
uv run python scripts/ws_client.py https://staging.example.com --scope website_and_code \
    --git-url https://github.com/you/app.git --git-ref main --i-have-authorization
```

The link must be a public `https://....git` clone link on `GIT_ALLOWED_HOSTS`. The server checks that it
is reachable and the branch/tag exists before it clones (`--depth 1`). The website runs first, then the
code SAST step.

### Website + code from a .zip or a folder

```bash
# 1. store the code (raw zip body), keep the upload_id from the reply
curl -X POST "http://127.0.0.1:8765/api/uploads?filename=app.zip" \
     -H "Authorization: Bearer $T" -H "Content-Type: application/zip" --data-binary @app.zip
```

```json
{"url": "https://staging.example.com", "profile": "standard", "authorization_confirmed": true,
 "scan_scope": "website_and_code", "upload_id": "0123456789abcdef0123456789abcdef"}
```

```bash
# or in one step: the client uploads the .zip / zips the folder, then sends the upload_id
uv run python scripts/ws_client.py https://staging.example.com --scope website_and_code \
    --code-path ./app.zip --i-have-authorization
uv run python scripts/ws_client.py https://staging.example.com --code-path ../my-project --i-have-authorization
```

### Website + code, chosen during the scan (pauses)

```json
{"url": "https://staging.example.com", "authorization_confirmed": true,
 "ask_scan_scope": true, "ask_for_code": true}
```

The scan pauses twice: `scan_scope` (before any request) and `code_source` (at the SAST step). Answer with
`scope_response` and a `code_response` holding an `upload_id` or `git_url`, or `skip` (section 5).
`ws_client.py --ask-scope --ask-for-code` prompts for both. At the code prompt you can type a local
.zip/folder path (uploaded for you), an upload id or a `.git` link. Without a prompt, use
`--scope-answer website_and_code --code-answer-git https://github.com/you/app.git` or `--code-answer-upload <id>`.

### Code only: git repository

```json
{"scan_scope": "code", "git_url": "https://github.com/you/app.git", "git_ref": "v1.2.0",
 "authorization_confirmed": true}
```

```bash
uv run python scripts/ws_client.py --scope code --git-url https://github.com/you/app.git --git-ref v1.2.0 \
    --i-have-authorization
```

### Code only: .zip or folder

```json
{"scan_scope": "code", "upload_id": "0123456789abcdef0123456789abcdef", "authorization_confirmed": true}
```

```bash
uv run python scripts/ws_client.py --scope code --code-path ./app.zip --i-have-authorization
uv run python scripts/ws_client.py --scope code --code-path ../my-project --i-have-authorization
```

`url` may be left out for `code`. If you give one, it only labels the report and no request goes to it.
The recon, auth, DAST and probe steps report `<step>_code_only` and pass straight on.

| Scope | `url` | Code (`upload_id` / `git_url` / `--code-path`) | Requests to the website | Role |
| --- | --- | --- | --- | --- |
| `website` | required | not allowed | yes | `scan:run` |
| `website_and_code` | required | required (or `ask_for_code`) | yes, then the code SAST step | admin (`scan:source`) |
| `code` | optional label | required (or `ask_for_code`) | none | admin (`scan:source`) |

## 7. Errors and close codes

| Close code | `error.code` | Meaning | What to do |
| --- | --- | --- | --- |
| `1000` | – | Normal close after `complete` | Done. |
| `4400` | `400` | Bad or missing `session_id`, or the first message is not a JSON object | Fix the request. |
| `4401` | `401` | Missing / invalid / expired token, or the session cap was reached mid-scan | Sign in again (`/auth/token`), reconnect with the same `session_id` and resume. |
| `4403` | `403` | Cross-origin browser page, missing permission, `authorization_confirmed` not true, another user's session, refused code | Don't retry unchanged. |
| `4422` | `422` | Request failed validation (`detail` lists the fields, never your values) | Fix the fields. |
| `4429` | `429` | Per-IP rate limit or queue full (`retry_after`, `queue`) | Wait `retry_after` seconds. |
| `1011` | – | Server error / the run crashed | Reconnect with the same `session_id` and send `{"resume": true}`. |
| `1006` / drop | – | Network drop | The run is checkpointed: resume. |

## 8. Resume, cache, queue, token renewal

- **Resume**: every graph step is checkpointed under `session_id`. After a drop, reconnect with the same
  id and send `{"resume": true}`. Only the session's owner (or a role with `sessions:any`) may resume, or start a new scan on an
  existing `session_id` (anyone else: close 4403, "belongs to another user; use a new session id").
- **Cache**: the same scan request within `CACHE_TTL_SECONDS` returns the earlier result at once
  (`complete` with `cached: true`), for the same user only. Send `"force_refresh": true` to scan again. Scans with code are never cached.
- **Queue**: one scan runs at a time by default (`WS_MAX_ACTIVE`). Later clients get `queued` messages,
  then `status` `queue_admitted`. More than `WS_MAX_QUEUE` waiting = `429`.
- **Token renewal**: long scans keep running past the token's lifetime: the server pushes
  `token_refreshed` before it expires, until the sign-in session cap (`4401` after that).

## 9. CORS and browser clients

The console is served by the same server, so it needs no CORS. A browser app on **another origin** (a
React dev server on `http://localhost:5173`, say) does. List its exact origins in `.env`:

```dotenv
CORS_ALLOWED_ORIGINS=http://localhost:5173,https://dashboard.example.com
```

| Rule | Value |
| --- | --- |
| Default | Empty = off: same-origin only. |
| Format | Exact `scheme://host[:port]`, comma-separated. A trailing `/` and default ports are normalised. `*`, `null`, wildcards, paths and `user:pw@` are refused (logged at start-up). |
| Methods | `GET`, `POST`, `DELETE`, `OPTIONS` |
| Request headers | `Authorization`, `Content-Type`, `A2A-Version`, `Mcp-Session-Id`, `Mcp-Protocol-Version` |
| Readable response headers | `X-New-Access-Token`, `X-New-Access-Token-Expires-At`, `Retry-After`, `X-Queue-Position`, `X-Queue-Wait-Seconds`, `Content-Disposition`, `Mcp-Session-Id` |
| Credentials | Off (`Access-Control-Allow-Credentials` is never sent): use the bearer token, not cookies. |
| Preflight cache | 600 s |
| WebSocket | CORS does not cover WebSockets, so `/ws` applies the same list to the handshake `Origin`. Listed origins may connect (they still need a token); others get close `4403`. |
| `/healthz` | Shows `"cors": true/false` only, not the origins. |

CORS runs as the outermost middleware: preflights are answered before auth and rate limits, and
`401`/`429` replies still carry the CORS headers, so a browser app can read why a call failed.

Check it:

```bash
# preflight from an allowed origin: 200 + access-control-allow-origin
curl -i -X OPTIONS http://127.0.0.1:8765/api/integrations \
     -H "Origin: http://localhost:5173" -H "Access-Control-Request-Method: GET" \
     -H "Access-Control-Request-Headers: authorization"

# the WebSocket with a browser-like Origin header
uv run python scripts/ws_client.py --simulate --origin http://localhost:5173
```

Restart the server after changing `CORS_ALLOWED_ORIGINS`: it is read at start-up.

## 10. Minimal clients

### Python (`websockets`)

```python
import asyncio, json, time, websockets

async def scan(token: str, url: str) -> None:
    uri = f"ws://127.0.0.1:8765/ws?session_id=py-{int(time.time())}"
    async with websockets.connect(uri, max_size=None) as ws:
        await ws.send(json.dumps({"access_token": token, "url": url, "profile": "quick",
                                  "authorization_confirmed": True}))   # only for sites you may test
        async for raw in ws:
            msg = json.loads(raw)
            kind = msg["type"]
            if kind == "token_refreshed":
                token = msg["access_token"]
            elif kind == "input_required":                       # only if you asked for pauses
                answer = {"scan_scope": {"type": "scope_response", "scope": msg["request"]["default"]},
                          "code_source": {"type": "code_response", "action": "skip"},
                          "sign_in": {"type": "auth_response", "action": "skip"}}[msg["request"]["type"]]
                await ws.send(json.dumps(answer))
            elif kind == "phase_update":
                print(msg["node"], len(msg["data"].get("findings", [])), "new findings")
            elif kind in ("status", "queued"):
                print(msg.get("message"))
            elif kind == "complete":
                print("report:", msg["report_url"]); return
            elif kind == "error":
                raise RuntimeError(msg)
```

### Browser JavaScript (another origin: needs `CORS_ALLOWED_ORIGINS`)

```js
// 1. token over HTTP (CORS): keep client secrets on a backend in real apps
const { access_token } = await (await fetch("http://127.0.0.1:8765/auth/token", {
  method: "POST", headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ client_id: "pentest-client", client_secret: "<from your backend>" }),
})).json();

// 2. WebSocket: browsers can't set headers, so the token goes in the first message
const ws = new WebSocket(`ws://127.0.0.1:8765/ws?session_id=web-${Date.now()}`);
ws.onopen = () => ws.send(JSON.stringify({
  access_token, url: "https://staging.example.com", profile: "quick", authorization_confirmed: true }));
ws.onmessage = (e) => {
  const msg = JSON.parse(e.data);
  switch (msg.type) {
    case "phase_update": render(msg.node, msg.data); break;   // escape text: it comes from the target
    case "status": case "queued": log(msg.message); break;
    case "token_refreshed": token = msg.access_token; break;
    case "complete": showReport(msg.report_url); break;
    case "error": showError(msg.code, msg.message); break;
  }
};
ws.onclose = (e) => { if (e.code === 1011 || e.code === 1006) offerResume(); };
```

Render target text with `textContent`, never `innerHTML`: findings and evidence come from the scanned site.

## 11. ws_client.py reference

```bash
uv run python scripts/ws_client.py --help
```

| Flag | Effect |
| --- | --- |
| `URL` / `--simulate` / `--payload FILE` / `--resume --session-id ID` | What to send (`--payload` = a Postman-style JSON body, sent as-is). |
| `--profile`, `--allow-domain`, `--notes`, `--force-refresh` | Scan request fields. |
| `--i-have-authorization` | Required for a real URL or code: you own it or may test it. |
| *(no arguments)* / `-i` | Interactive: numbered menus ask for everything (URL, code, git link, path, scope, profile, ...), show the frame, then ask "Start?". |
| `--scope`, `--upload-id`, `--git-url`, `--git-ref` | Source code named up front (`--scope code --upload-id ...` needs no URL). |
| `--code-path ZIP_OR_DIR` | Upload a local .zip or folder over HTTP first (raw zip body), then send its `upload_id`. A folder leaves out gitignored files, caches, documents, images and model weights. |
| `--ask-scope`, `--ask-for-code`, `--interactive-auth` | Turn the pauses on; the client prompts in the terminal (secrets hidden). |
| `--scope-answer`, `--code-answer-upload`, `--code-answer-git` | Answer pauses without a prompt. Without a TTY: default scope / skip. |
| `--frames` | Print every received frame as pretty JSON (long strings shortened). `--full`: no shortening. |
| `--raw` | Received frames as plain full JSON (for pipes / `jq`). |
| `--no-color` | No ANSI colours (also `NO_COLOR=1`, or when output is not a terminal). |
| `--origin URL` | Send a browser-like `Origin` header (tests `CORS_ALLOWED_ORIGINS`). |
| `--token`, `--token-in message\|header\|query`, `--no-auth` | Token source and where it goes. |
| `--host`, `--port`, `--save-md FILE` | Connection and report output. |

The access token is never asked for. The client uses `--token`, else `POST /auth/token` with
`AUTH_CLIENT_ID`/`AUTH_CLIENT_SECRET` from `.env`, else a token signed locally with `keys/`, and it creates
the key pair when it is missing. Frames you send are always printed. Tokens, passwords, cookies, bearer values and MFA codes are masked
(`*** (n chars)`) in everything the client prints. Exit codes: `0` complete, `1` error / rejected,
`2` socket closed early (resume hint printed), `3` server not reachable or no token, `130` interrupted.
