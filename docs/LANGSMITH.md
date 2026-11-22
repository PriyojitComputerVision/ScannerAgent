# LangSmith tracing guide

Tracing is optional and off by default. When it is on, every scan run by the WebSocket agent, and every
golden-dataset case, is recorded in LangSmith as one run tree. Implementation: `src/pentest_agent/tracing.py`.

## 1. Get an API key

1. Sign in at <https://smith.langchain.com>.
2. Open **Settings → API Keys → Create API Key** (a personal access token `lsv2_pt_...` is fine).
3. Copy the key. It is shown only once.

## 2. Configure `.env`

```dotenv
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=lsv2_pt_your_key_here
LANGSMITH_PROJECT=pentest-agent          # project is created automatically on first run
LANGSMITH_ENDPOINT=https://api.smith.langchain.com
```

* EU workspace: `LANGSMITH_ENDPOINT=https://eu.api.smith.langchain.com`.
* The legacy names `LANGCHAIN_TRACING_V2`, `LANGCHAIN_API_KEY`, `LANGCHAIN_PROJECT` and
  `LANGCHAIN_ENDPOINT` are also accepted. If a file has both, the `LANGSMITH_*` name wins.
  Your `.env` currently uses `LANGCHAIN_TRACING_V2`: set it to `true`, or replace it with
  `LANGSMITH_TRACING=true`.
* Tracing switches on only when the flag is `true` **and** a key is set. Placeholder keys
  (`test-...`, `your_...`, `changeme`) count as unset.

## 3. Verify

```bash
uv run pentest-agent
curl http://127.0.0.1:8765/healthz
# {"status":"ok","graph_initialized":true,"langsmith_tracing":true}
```

The WebSocket `complete` message also includes `"langsmith_project": "<project>"` when tracing is on.

## 4. Generate traces

```bash
uv run python scripts/simulate_full.py        # full agent pipeline against the built-in target
uv run golden-check                           # golden-dataset cases (one trace per case)
```

Or connect a client to `ws://127.0.0.1:8765/ws?session_id=<id>` (see `scripts/scan_client.py`).

## 5. What you will see

Each scan is one root run named `pentest-scan:<target-host>`, tagged `pentest-agent` and `profile:<profile>`,
with metadata `session_id`, `target_host`, `profile` and `app`. Below it:

| Run | What it is |
| --- | --- |
| `validate`, `recon`, `auth`, `sast`, `dast`, `codegen_probes`, `aggregate`, `report` | LangGraph nodes |
| `recon_and_crawl`, `authenticate`, `run_native_dast`, ... | LangChain tools |
| `js_sast_scan` | JavaScript SAST over crawled assets |
| `native_dast_sandbox_scan` | the sandboxed DAST scan (inputs/outputs, duration) |
| `codegen_probe_plan`, `probe_runner` | LLM probe planning and the trusted probe runner |
| `executive_summary` → `ChatGroq` | the summary prompt and Groq call (tokens, latency) |
| `ground_summary_citations` | citation grounding: shows which `[Sn]` ids or URLs were removed as hallucinated |

Golden runs use `session_id = golden:<case-id>`. Filter on that metadata to compare runs over time.

Useful filters in the LangSmith UI:

* `metadata_key = "session_id"` to find one scan.
* `tags = profile:standard` to compare profiles.
* Runs named `ground_summary_citations` whose output has a non-empty third element: the model
  hallucinated citations.

## 6. What is never sent

All inputs, outputs and metadata go through `tracing.redact()` before upload:

* Keys matching password, secret, token, jwt, bearer, authorization, cookie, api key, credential, auth
  session data or private key are replaced with `[REDACTED]`. Boolean flags such as `jwt_provided` are kept.
* Values that look like JWTs, `Bearer ...` tokens, Groq/LangSmith keys, AWS access key ids or PEM private
  keys are redacted wherever they appear.
* Metadata carries only the target **host**, never its path or query string.

Tracing is enabled per run through `tracing_context` with this redacting client, never through
process-wide environment variables, so nothing can be uploaded through an un-redacted default client.
Note that page-derived finding text (titles, descriptions, evidence) *is* uploaded. Only enable tracing for
targets whose scan data may be stored in your LangSmith workspace.

## 7. Docker

```bash
docker run --rm -p 8765:8765 --env-file .env pentest-agent
```

The `pytest` step masks the LangSmith key, so tests never upload. The golden check and the server trace when
`.env` enables tracing.

## 8. Troubleshooting

| Symptom | Fix |
| --- | --- |
| `/healthz` shows `"langsmith_tracing": false` | Check that the flag is `true` and the key is real; restart the server (settings load at start). |
| Runs appear late or are missing at shutdown | Runs are batched and flushed on server shutdown and at the end of `golden-check`. Stop the server with Ctrl+C rather than killing it. |
| `403` / `401` in logs | Wrong key, or a key from another region: match `LANGSMITH_ENDPOINT` to your workspace. |
| `429` from LangSmith | Workspace ingest limits. The client retries; lower scan volume or upgrade the plan. |
| Want it off for one run | `LANGSMITH_TRACING=false uv run pentest-agent` |
