# pentest-agent (ScopeGuard)

Autonomous, guard-railed **web security scanner agent**. Orchestrated by LangGraph, optional Groq LLM,
exposed over a WebSocket. **No OWASP ZAP, no Java**: all scanning is pure Python and runs in a
Docker-free sandbox (a Dockerfile is provided only to package test -> drift check -> server).

> Authorization is mandatory. Only scan systems you own or are explicitly authorized to test.

## Quick start (no setup beyond Python 3.12)

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

### Full LangGraph + WebSocket agent

```bash
uv sync
cp .env.example .env            # GROQ_API_KEY is optional; empty = deterministic offline mode
uv run python scripts/simulate_full.py   # whole pipeline against the built-in target
uv run pentest-agent                      # ws://127.0.0.1:8765/ws?session_id=<id>
uv run pytest
uv run golden-check                       # golden-dataset drift check (see below)
```

Client message: `{"url": "...", "profile": "quick|standard|aggressive|auth_deep", "authorization_confirmed": true}`
(`{"resume": true}` with the same `session_id` resumes from the SQLite checkpoint.)
The final `complete` message includes `report_url`, e.g. `/reports/<session_id>/`.

### Report viewer

| Where | URL |
| --- | --- |
| WebSocket server | `http://127.0.0.1:8765/reports/` (index), `/reports/<session_id>/` (HTML), `/reports/<id>/report.{md,json,docx}` |
| CLI `--serve` | `http://127.0.0.1:<port>/` (index), `/<report-folder>/` (HTML) |

Downloads are named after the session id (CLI: the report folder), e.g. `money-dynocde-001.docx`,
`.md`, `.json`; on disk they stay `report.*`.
Reports are rendered with every target-controlled value HTML-escaped and served with a strict
`Content-Security-Policy` (no scripts), so a hostile page cannot inject markup into the viewer.

## Pipeline

validate/gate -> recon+crawl -> auth -> JS SAST -> native DAST -> custom probes -> aggregate -> report (md + html + docx)

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

## HTTP 429 handling

* **Scanned link**: every client that talks to the target (engine `ScopedClient`, and the agent's httpx
  clients via `http_retry.RateLimitRetryTransport`) retries `429` (and `503` with `Retry-After`) up to 3
  times, honouring `Retry-After` (seconds or HTTP-date, capped at 30s) or backing off 1/2/4s, and slows
  down after being throttled. Throttling is reported as a **red flag**, so incomplete results are visible.
* **LLM (Groq)**: retries 429/5xx, waiting for Groq's `Retry-After` (capped at 60s) or jittered backoff.
* **Backend**: per-client-IP limits return `429 Too Many Requests` + `Retry-After` on HTTP routes
  (`/healthz` exempt) and close WebSocket scans with code `4429` (`{"type":"error","code":429,"retry_after":n}`).
  Configure with `HTTP_RATE_LIMIT_PER_MINUTE`, `WS_SCANS_PER_MINUTE`, `MAX_CONCURRENT_SCANS_PER_CLIENT`
  (in-process, per worker).

## LangSmith tracing

Set `LANGSMITH_TRACING=true` and `LANGSMITH_API_KEY` (legacy `LANGCHAIN_*` names also work). Each scan is one
run tree: graph nodes, tools, Groq calls, the sandboxed DAST scan, probe planning/running, JS SAST and the
citation-grounding step, tagged with session id, target host and profile. A dedicated client redacts JWTs,
passwords, cookies, Authorization headers and API keys from inputs, outputs and metadata before upload.
Step-by-step setup, what each run shows and troubleshooting: [docs/LANGSMITH.md](docs/LANGSMITH.md).

## Golden dataset and drift check

`golden/golden_dataset.json` holds the golden cases (sandboxed scans of the built-in target and fixed
findings fixtures, with recorded baselines and reference summaries). `uv run golden-check` runs the real
pipeline on each case and checks:

* **Data (deterministic)**: required/forbidden finding titles, title-set Jaccard, severity histogram (±tolerance),
  pages crawled, blocked links, and input fingerprints against the baseline.
* **Model (deterministic)**: the LLM answer is used (no fallback), no hallucinated `[Sn]` ids or invented URLs,
  minimum citations, required sources cited, forbidden phrases absent, length.
* **Model (LLM-as-judge)**: a pydantic `JudgeVerdict` (faithfulness, coverage, citation accuracy, clarity, overall,
  hallucinations) whose `overall` score must be **>= 7** (`thresholds.min_judge_score`). Set
  `GOLDEN_JUDGE_MODEL` to use a different judge model than the generator.

It prints one strict verdict and exits with its code:

| Verdict | Exit | Meaning |
| --- | --- | --- |
| `NO_DRIFT` | 0 | data and model checks passed |
| `DATA_DRIFT` | 10 | the model's input data changed (scanner output / fixtures differ from baseline) |
| `MODEL_DRIFT` | 20 | data is stable but the LLM output failed a check or scored below threshold |
| `DATA_AND_MODEL_DRIFT` | 30 | both (model failures on drifted cases are not attributed to the model) |
| `NOT_EVALUATED` | 2 | no `GROQ_API_KEY` / judge error: the model could not be assessed |

Results are written to `golden/results/golden-<timestamp>/golden_report.{json,md}` and
`golden/results/latest.json` (git-ignored). `--allow-no-llm` runs data checks only; after an intentional
scanner change, re-capture baselines with `uv run golden-check --record-baseline`.
`GOLDEN_LIVE=1 uv run pytest tests/test_golden_dataset.py` also runs the live judge inside pytest.

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

## Layout

`src/scopeguard/` stdlib-only engine, sandbox, citations, rate limiting, reports, simulated target, CLI.
`src/pentest_agent/` LangGraph agent, guardrails, schemas, tools, tracing, rate limits, websocket server,
`evals/golden.py`. `golden/golden_dataset.json`, `tests/`, `scripts/simulate_full.py`, `Dockerfile`.
