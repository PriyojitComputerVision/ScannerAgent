# ScopeGuard MCP chatbot

A chatbot that runs ScopeGuard scans for you. Send it a URL you own or are authorized
to test. It asks you to approve the scan, streams the scan's progress step by step,
shows the scanner's verified result and explains it.

- **Agent:** LangChain `create_agent` with `AgentState` and an `InMemorySaver` checkpointer
  (one conversation per thread, kept in memory).
- **Tools:** the scanner's MCP server (`<server>/mcp`, Streamable HTTP), loaded with
  `langchain-mcp-adapters`. A small `watch_scan` tool built on the MCP `get_scan` tool
  streams each finished scan step and returns the result when the scan ends.
- **Human in the loop:** `HumanInTheLoopMiddleware` pauses before every `start_scan`,
  `start_demo_scan` and `cancel_scan`. You approve, edit the arguments, or reject.
  Approving `start_scan` *is* the authorization confirmation: the chatbot sets
  `authorization_confirmed=true` on the approved call itself, never the model.
- **Verified results:** the result block (counts, every finding under its own severity,
  red flags, report files, audit record) comes straight from the scanner. The model only
  writes the analysis around it, so it cannot misfile a severity or invent a file path.
- **Allowed targets:** any number of hosts. Add or remove them in the UI. Each change
  restarts only the scanner, so the conversation keeps going.

```
chatbots/
├── Dockerfile                         everything in one container
├── mcp_chatbot/                       own uv project + venv (MCP 1.x client; the scanner uses MCP 2.x)
│   ├── chatbot.py                     terminal chatbot, or --serve for the UI's JSON API
│   ├── scopeguard_common.py           settings, sign-in, agent, streaming engine, approval
│   ├── system_prompt.md
│   ├── test_chatbot.py                offline tests (no LLM, no server)
│   └── .env.example                   copy to .env (gitignored)
└── ui/                                serve_ui.py (ONE command: scanner + chatbot + UI) + static page
```

## Settings

Copy `mcp_chatbot/.env.example` to `mcp_chatbot/.env` (gitignored).

- **Groq:** the key and the model (`GROQ_API_KEY`, `GROQ_MODEL`, `GROQ_REASONING_EFFORT`)
  always come from the repo's main `.env`. They're the same as the scanner's.
- **Sign-in:** automatic. The chatbot signs an API JWT with the scanner's key in `keys/`,
  so no token is copied anywhere. Create the keys once with `uv run pentest-auth keys` if
  you haven't.
- **`CHATBOT_ALLOW`:** the hosts you may test, comma separated, as many as you like. For
  example: `CHATBOT_ALLOW=syslab-blond.vercel.app,staging.example.com,localhost:3000`.
- **`CHATBOT_NO_SCANNER_LLM=true`:** the scanner skips its own LLM steps (executive
  summary, probe plan), which is faster. The chat agent still uses the LLM.
- **Groq limits:** Groq's on_demand tier allows 8,000 tokens per request and per minute, so
  results reach the model in compact form and old tool outputs are cleared from the
  history. Each turn may wait briefly for the rate limit.

## Run it: one command

From the repo root (PowerShell or bash):

```powershell
uv run --project chatbots/mcp_chatbot python chatbots/ui/serve_ui.py
```

Options go at the end, for example:

```powershell
uv run --project chatbots/mcp_chatbot python chatbots/ui/serve_ui.py --allow syslab-blond.vercel.app --allow staging.example.com
uv run --project chatbots/mcp_chatbot python chatbots/ui/serve_ui.py --no-scanner-llm
```

This one command starts three things, all on `127.0.0.1`:

1. **the scanner** (pentest-agent) on a free port, allowing the hosts you passed (or
   `CHATBOT_ALLOW`), so it never clashes with a console you already run on 8765;
2. **the chatbot backend**, which uses that scanner's MCP server as its tools;
3. **the web page**, opened in your browser through a single-use launch link (valid for
   10 minutes).

Ctrl+C stops all three. The first run installs the chatbot's own venv.

In the page:

- **Allowed targets** (the bar under the title): type a host or URL and press **Add**.
  Add as many as you need, and use ✕ to remove one. Each change restarts only the
  scanner, in about 10 seconds; the chat stays.
- **The chat:** send for example `scan https://syslab-blond.vercel.app/ with the standard
  profile`, or ask for `a quick demo scan`.
- **Approval:** the chatbot stops at a small form instead of running anything.
  - **Website scan:** a **Target** field (prefilled, with your allowed targets as
    suggestions and a warning if the host isn't allowed), a **Profile** dropdown
    (quick / standard / aggressive / auth deep), and the checkbox **I own this site or am
    authorized to test it**. **Run scan** stays disabled until you tick it, and that tick
    is the authorization confirmation.
  - **Demo scan:** a profile and the optional demo sign-in.
  - **Cancel a scan:** **Yes, stop it** or **No**.

  **Cancel** rejects the request. What the assistant asked for is under "details". After
  **Run**, the scan steps stream in, then the verified result, then the explanation.

To use a pentest-agent you already run instead of starting one, pass
`--url http://127.0.0.1:8765`. Its own `.env` (`MCP_ALLOWED_TARGETS`) then decides the
allowlist, and the UI shows it read-only.

The page is protected like the main console:
- it binds to loopback only and checks the Host header;
- it has a strict CSP, with no inline code and no third-party loads;
- it renders text only, never HTML;
- the launch link sets an HttpOnly, SameSite=Strict session cookie;
- POSTs must come from the same origin;
- host names are strictly validated (no user info, no wildcards);
- the browser never sees a token.

### Terminal instead of the browser (optional)

```powershell
uv run --project chatbots/mcp_chatbot python chatbots/mcp_chatbot/chatbot.py --allow syslab-blond.vercel.app --allow staging.example.com
```

At the approval prompt, answer `a` (approve), `e` (edit the arguments as JSON) or `r`
(reject). `/new` starts a new conversation; `/quit` exits. Without `--allow`, it uses the
pentest-agent at `SCOPEGUARD_URL` (default `http://127.0.0.1:8765`).

## Docker: one container

The image holds the scanner, the chatbot and the UI. It runs the same launcher, and the
scanner stays on loopback inside the container.

```bash
docker build -f chatbots/Dockerfile -t scopeguard-chatbot .
docker run --rm -p 127.0.0.1:8800:8800 \
  -v "$PWD/.env:/app/.env:ro" \
  -v "$PWD/chatbots/mcp_chatbot/.env:/app/chatbots/mcp_chatbot/.env:ro" \
  -v "$PWD/keys:/app/keys:ro" \
  -v "$PWD/data/reports:/app/data/reports" \
  scopeguard-chatbot --allow syslab-blond.vercel.app
```

Open the `LAUNCH LINK` from the log. Hosts can be added in the UI here too.

- **Secrets:** the `.env` files and `keys/` are mounted read-only, never baked into the
  image.
- **Reports:** they land in `data/reports/`. Paths shown in the UI are container paths
  (`/app/data/reports/...`).

## Tests

```bash
cd chatbots/mcp_chatbot
uv run pytest          # offline: approval flow, decisions, streaming, token claims
```
