"""ScopeGuard system check: is this machine ready to run the agent, and where will scans run?

    uv run python scripts/system_check.py            # all checks (takes ~10-60 s with a cluster)
    uv run python scripts/system_check.py --quick    # skip the sandbox self-tests and Kubernetes
    uv run python scripts/system_check.py --bootstrap   # also bring the Kubernetes sandbox up first
    uv run python scripts/system_check.py --json     # machine-readable output

Read-only apart from temporary files (and the optional --bootstrap). It never prints secret
values, makes no LLM calls and no requests to any target. Exit code: 0 = no FAIL, 1 = FAIL.
(While `scopeguard-mcp` is running, use `uv run --no-sync python scripts/system_check.py`.)
"""
from __future__ import annotations

import argparse
import importlib
import io
import json
import os
import shutil
import socket
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
os.chdir(REPO)  # .env, data/ and keys/ are resolved from the repo root
sys.path.insert(0, str(REPO / "src"))

PASS, WARN, FAIL, INFO = "PASS", "WARN", "FAIL", "INFO"
RESULTS: list[dict] = []


def record(group: str, name: str, status: str, detail: str = "") -> None:
    RESULTS.append({"group": group, "check": name, "status": status, "detail": detail})


def guarded(group: str, name: str):
    """Decorator: an unexpected exception in a check is a FAIL for that check, not a crash."""
    def wrap(fn):
        def run(*a, **kw):
            started = time.monotonic()
            try:
                fn(*a, **kw)
            except Exception as exc:  # noqa: BLE001 - report every problem, keep checking
                record(group, name, FAIL, f"{type(exc).__name__}: {str(exc)[:200]}")
            finally:
                took = time.monotonic() - started
                if took > 5 and RESULTS and RESULTS[-1]["check"] == name:
                    RESULTS[-1]["detail"] += f" ({took:.0f}s)"
        return run
    return wrap


# ----------------------------------------------------------------------------- environment
@guarded("environment", "python")
def check_python():
    v = sys.version_info
    ok = (v.major, v.minor) == (3, 12)
    record("environment", "python", PASS if ok else FAIL,
           f"{sys.version.split()[0]} on {sys.platform}" + ("" if ok else " (the project needs Python 3.12: uv sync)"))


@guarded("environment", "dependencies")
def check_dependencies():
    mods = {"fastapi": "fastapi", "uvicorn": "uvicorn", "langgraph": "langgraph", "langchain": "langchain",
            "langchain_groq": "langchain-groq", "httpx": "httpx", "bs4": "beautifulsoup4", "docx": "python-docx",
            "Crypto": "pycryptodome", "jwt": "pyjwt", "mcp": "mcp", "a2a": "a2a-sdk", "aiosqlite": "aiosqlite"}
    missing = []
    for mod, pkg in mods.items():
        try:
            importlib.import_module(mod)
        except Exception:  # noqa: BLE001
            missing.append(pkg)
    record("environment", "dependencies", FAIL if missing else PASS,
           f"missing: {', '.join(missing)} (run: uv sync)" if missing else f"{len(mods)} packages import")


@guarded("environment", ".env + settings")
def check_settings():
    env = REPO / ".env"
    if not env.is_file():
        record("environment", ".env + settings", WARN, "no .env: defaults are used (cp .env.example .env)")
    from pentest_agent.config import settings  # validates every value (pydantic)

    record("environment", ".env + settings", PASS, f"settings valid; sandbox backend {settings.sandbox_backend}")


@guarded("environment", "data folders writable")
def check_dirs():
    from pentest_agent.config import settings

    bad = []
    for label, path in (("reports", settings.reports_dir), ("uploads", settings.code_upload_dir),
                        ("checkpoints", Path(settings.checkpoint_db_path).parent),
                        ("audit", Path(settings.audit_log_path).parent)):
        p = Path(path)
        try:
            p.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=p, prefix=".write-test-", delete=True):
                pass
        except OSError as exc:
            bad.append(f"{label} ({exc.__class__.__name__})")
    record("environment", "data folders writable", FAIL if bad else PASS,
           f"not writable: {', '.join(bad)}" if bad else "reports, uploads, checkpoints, audit")


# ----------------------------------------------------------------------------- configuration
@guarded("configuration", "LLM (Groq)")
def check_llm():
    from pentest_agent import llm
    from pentest_agent.config import settings

    if llm.llm_available():
        record("configuration", "LLM (Groq)", PASS, f"key set; model {settings.groq_model} (not called by this check)")
    else:
        record("configuration", "LLM (Groq)", WARN, "no GROQ_API_KEY: summaries and probe plans use the "
                                                    "deterministic offline fallbacks")


@guarded("configuration", "prompt files")
def check_prompts():
    from pentest_agent import prompts

    names = ["executive_summary", "run_summary", "probe_plan_system", "content_injection_reminder", "golden_judge"]
    missing = [n for n in names if not prompts.available(n)]
    record("configuration", "prompt files", WARN if missing else PASS,
           f"missing: {', '.join(missing)} (those steps use fallbacks)" if missing else f"{len(names)} present")


@guarded("configuration", "API auth (JWT)")
def check_auth():
    from pentest_agent import api_auth
    from pentest_agent.config import settings

    if not settings.auth_enabled:
        record("configuration", "API auth (JWT)", WARN, "AUTH_ENABLED=false: the API accepts unauthenticated calls")
    elif api_auth.keys_present():
        record("configuration", "API auth (JWT)", PASS, "enabled, signing keys present")
    else:
        record("configuration", "API auth (JWT)", INFO, "enabled; keys are created on first start (pentest-auth keys)")


@guarded("configuration", "secrets at rest")
def check_secret_keys():
    from pentest_agent.config import settings

    missing = [name for name, value in (("CHECKPOINT_ENCRYPTION_KEY", settings.checkpoint_encryption_key),
                                        ("AUDIT_HMAC_KEY", settings.audit_hmac_key)) if not str(value or "").strip()]
    record("configuration", "secrets at rest", WARN if missing else PASS,
           f"not set: {', '.join(missing)}" if missing else "checkpoints encrypted, audit chain HMAC-signed")


@guarded("configuration", "targets + network policy")
def check_targets():
    from pentest_agent.config import settings

    mcp = settings.mcp_allowed_targets.strip() or "demo target only"
    a2a = settings.a2a_allowed_targets.strip() or "demo target only"
    record("configuration", "targets + network policy", INFO,
           f"MCP allowlist: {mcp}; A2A allowlist: {a2a}; BLOCK_PRIVATE_TARGETS={settings.block_private_targets}")


@guarded("configuration", "golden dataset")
def check_golden():
    from pentest_agent.evals import golden

    ds = golden.load_dataset()
    record("configuration", "golden dataset", PASS, f"version {ds.version}, {len(ds.cases)} case(s) valid")


# ----------------------------------------------------------------------------- integrity
@guarded("integrity", "audit trails")
def check_audit():
    from pentest_agent.config import settings
    from scopeguard import audit

    parts, status = [], PASS
    for label, path in (("scans", settings.audit_log_path), ("code", settings.code_audit_log_path)):
        if not Path(path).is_file():
            parts.append(f"{label}: empty")
            continue
        res = audit.verify(path, settings.audit_hmac_key or None, settings.reports_dir)
        if res["problems"]:
            status = FAIL
            parts.append(f"{label}: TAMPERED ({res['problems'][0][:100]})")
        elif res["unverifiable_hmac_records"]:
            status = WARN if status == PASS else status
            parts.append(f"{label}: {res['unverifiable_hmac_records']} record(s) need AUDIT_HMAC_KEY")
        else:
            parts.append(f"{label}: {res['records']} record(s) intact")
    record("integrity", "audit trails", status, "; ".join(parts))


# ----------------------------------------------------------------------------- sandbox
@guarded("sandbox", "python sandbox memory cap")
def check_memory_cap():
    from scopeguard import limits

    run = limits.run_limited([limits.sandbox_python(), "-I", "-c", "b = bytearray(900 * 1024 * 1024)"],
                             timeout=60, memory_mb=128)
    ok = run.returncode != 0 and run.oom
    record("sandbox", "python sandbox memory cap", PASS if ok else FAIL,
           f"900 MB allocation stopped at a 128 MB cap ({'rlimit' if os.name == 'posix' else 'job object'})"
           if ok else f"allocation was NOT stopped (exit {run.returncode})")


@guarded("sandbox", "python sandbox analyzer")
def check_analyzer():
    from scopeguard import codescan

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app/server.js", "app.get('/o/:id', async (req, res) => {\n"
                                    "  res.send('<p>' + req.query.q + '</p>' + await Order.findById(req.params.id));\n});\n")
        z.writestr("../escape.txt", "x")
    out = codescan.scan_archive(buf.getvalue(), backend="process", timeout=120)
    rules = {f["title"].split(":")[0] for f in out["findings"]}
    want = {"XSS_REFLECTED_RESPONSE", "IDOR_DIRECT_OBJECT_LOOKUP", "ZIP_SLIP"}
    ok = want <= rules and not out.get("violations")
    record("sandbox", "python sandbox analyzer", PASS if ok else FAIL,
           f"sample zip: {len(out['findings'])} finding(s), planted issues found, no escape attempts" if ok
           else f"expected {sorted(want - rules)} in the sample; got {sorted(rules)}")


@guarded("sandbox", "docker / kubectl")
def check_tools():
    docker, kubectl = shutil.which("docker"), shutil.which("kubectl")
    record("sandbox", "docker / kubectl", INFO,
           f"docker: {'found' if docker else 'not found'} (only used to start a stopped kind node); "
           f"kubectl: {'found' if kubectl else 'not found'}")


@guarded("sandbox", "kubernetes sandbox")
def check_kubernetes(bootstrap: bool):
    from pentest_agent import code_upload
    from pentest_agent.config import settings
    from scopeguard import k8s

    if settings.sandbox_backend != "kubernetes":
        record("sandbox", "kubernetes sandbox", INFO, "SANDBOX_BACKEND=process: Kubernetes not used")
        return
    if not shutil.which("kubectl"):
        record("sandbox", "kubernetes sandbox", WARN, "kubectl not found: code scans run in the Python sandbox")
        return
    if bootstrap:
        res = code_upload.bring_up_sandbox()
        ok, why = res["ready"], res["reason"]
        steps = f" [steps: {'; '.join(res['actions'])}]" if res["actions"] else ""
    else:
        ok, why = k8s.cluster_status(code_upload.k8s_config())
        steps = ""
    if ok:
        record("sandbox", "kubernetes sandbox", PASS, f"Jobs in {settings.k8s_namespace}, isolation verified{steps}")
    else:
        record("sandbox", "kubernetes sandbox", WARN, f"{why}{steps} (code scans use the Python process sandbox)")


@guarded("sandbox", "where code scans run")
def check_effective(skip_k8s: bool):
    from pentest_agent.config import settings
    from scopeguard import k8s

    if settings.sandbox_backend == "process":
        where = "Python process sandbox (SANDBOX_BACKEND=process)"
    elif skip_k8s:
        where = "not determined (--quick skips the Kubernetes check)"
    else:
        from pentest_agent import code_upload

        ok, _why = k8s.cluster_status(code_upload.k8s_config())
        where = "Kubernetes Jobs" if ok else "Python process sandbox (Kubernetes not ready)"
    record("sandbox", "where code scans run", FAIL if where.startswith("error") else INFO, where)


# ----------------------------------------------------------------------------- service
@guarded("service", "agent port")
def check_port():
    from pentest_agent.config import settings, unspecified_host

    host = "127.0.0.1" if unspecified_host(settings.ws_host) else settings.ws_host
    port = settings.ws_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        busy = s.connect_ex((host, port)) == 0
    if not busy:
        record("service", "agent port", PASS, f"{host}:{port} free (start: uv run pentest-agent)")
        return
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=3) as r:  # nosec B310 - fixed http:// URL to this machine's agent
            health = json.loads(r.read().decode())
        record("service", "agent port", PASS, f"pentest-agent already running on {host}:{port} "
                                              f"(graph ready: {health.get('graph_initialized')})")
    except Exception:  # noqa: BLE001
        record("service", "agent port", WARN, f"{host}:{port} is used by another program (set WS_PORT)")


# ----------------------------------------------------------------------------- output
def render(results: list[dict]) -> str:
    colors = {PASS: "\033[32m", WARN: "\033[33m", FAIL: "\033[31m", INFO: "\033[36m"}
    use_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    lines, group = ["", "ScopeGuard system check", "=" * 72], None
    for r in results:
        if r["group"] != group:
            group = r["group"]
            lines.append(f"\n[{group}]")
        tag = f"{colors[r['status']]}{r['status']}\033[0m" if use_color else r["status"]
        lines.append(f"  {tag:<4}  {r['check']:<28} {r['detail']}")
    counts = {s: sum(1 for r in results if r["status"] == s) for s in (PASS, WARN, FAIL, INFO)}
    lines += ["", "=" * 72,
              f"{counts[PASS]} pass, {counts[WARN]} warn, {counts[FAIL]} fail, {counts[INFO]} info -> "
              + ("NOT READY (fix the FAIL lines)" if counts[FAIL] else "READY"), ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Check whether this machine is ready to run ScopeGuard.")
    ap.add_argument("--quick", action="store_true", help="skip sandbox self-tests and the Kubernetes check")
    ap.add_argument("--bootstrap", action="store_true", help="bring the Kubernetes sandbox up before checking it")
    ap.add_argument("--json", action="store_true", help="print JSON instead of a table")
    a = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            if isinstance(stream, io.TextIOWrapper):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    check_python()
    check_dependencies()
    check_settings()
    check_dirs()
    check_llm()
    check_prompts()
    check_auth()
    check_secret_keys()
    check_targets()
    check_golden()
    check_audit()
    if not a.quick:
        check_memory_cap()
        check_analyzer()
    check_tools()
    if not a.quick:
        check_kubernetes(a.bootstrap)
    check_effective(a.quick)
    check_port()

    if a.json:
        print(json.dumps({"results": RESULTS, "ok": not any(r["status"] == FAIL for r in RESULTS)}, indent=2))
    else:
        print(render(RESULTS))
    return 1 if any(r["status"] == FAIL for r in RESULTS) else 0


if __name__ == "__main__":
    raise SystemExit(main())
