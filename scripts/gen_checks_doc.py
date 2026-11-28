"""Write docs/SECURITY_CHECKS.md: every check the scanner runs (DAST, custom probes, website JavaScript
SAST, source-code SAST, PEP 8 / ruff lint, the code SAST step's tools) and every automated test file,
with where to look.

The rule tables are read from the code (engine.JS_RULES, engine.SENSITIVE_PATHS, codecheck.BACKEND_RULES,
codestyle.STYLE_RULES, probe_models.ProbeType), the test list from each test file's docstring, so the
document cannot drift from the code: tests/test_new_checks.py checks that every rule id is listed.

    uv run python scripts/gen_checks_doc.py
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pentest_agent import code_tools
from pentest_agent.tools.probe_models import PARAMETER_PROBES, ProbeType
from scopeguard import codecheck, codestyle, engine

OUT = ROOT / "docs" / "SECURITY_CHECKS.md"

# Test files without a module docstring: what they cover.
TEST_NOTES = {
    "test_auth.py": "Target sign-in helpers: JWT inspection, form login, session handling.",
    "test_code_exec_scope_guard.py": "Custom probes stay in scope: URL building and host allowlist checks.",
    "test_codegen_subagent.py": "Probe planner: LLM plan validation, whitelisted probe types, default plan fallback.",
    "test_config.py": "Settings: defaults, validation and environment overrides.",
    "test_dast_native.py": "Native DAST end to end against the built-in vulnerable target, unknown profiles, "
                           "unreachable targets.",
    "test_graph_validate_node.py": "The graph's first node: authorization flag, guardrails, allowed domains.",
    "test_guardrails.py": "Pre-run guardrail: authorization, scope (host + www + extra domains), untrusted-content "
                          "wrapping.",
    "test_recon_helpers.py": "Recon / crawl helpers: link extraction, scope filtering, discovery.",
    "test_report_tool.py": "Report rendering: Markdown, HTML, JSON and DOCX from the same structured data.",
    "test_schemas.py": "Pydantic schemas: TargetInput, Finding, FinalReport, report links.",
}

# DAST checks that are code, not tables: (check, what it finds, profiles, where in engine.py).
DAST_STEPS = [
    ("Crawl and discovery", ("In-scope pages, robots.txt, sitemaps, .well-known; off-scope and file links recorded, "
     "never fetched"), "all", "Scanner.crawl, tools/recon.py, tools/discovery.py"),
    ("Security headers", ("Missing CSP, HSTS, X-Frame-Options / frame-ancestors, X-Content-Type-Options, "
     "Referrer-Policy, COOP, CORP, Permissions-Policy"), "all", "Scanner.passive"),
    ("Weak CSP", "unsafe-inline, unsafe-eval, wildcard script sources", "all", "Scanner.passive"),
    ("Weak HSTS", "max-age under 180 days (or missing)", "all", "Scanner._passive_extras"),
    ("Subresource Integrity", "Third-party scripts without an integrity attribute", "all",
     "Scanner._passive_extras"),
    ("Forms posting to HTTP", "HTTPS pages whose form action is http://; password forms on HTTP", "all",
     "Scanner._passive_extras, Scanner.passive"),
    ("Reverse tabnabbing", "target=\"_blank\" links without rel=\"noopener\"", "all", "Scanner._passive_extras"),
    ("Cookie flags", "Missing HttpOnly, Secure, SameSite", "all", "Scanner._cookie"),
    ("Error disclosure", "Python / Java / .NET / PHP stack traces, phpinfo()", "all", "Scanner.passive (INFO_LEAKS)"),
    ("Directory listing", "Automatic directory indexes", "all", "Scanner.passive"),
    ("Anti-CSRF token", "POST forms without a CSRF-like hidden field (heuristic)", "all", "Scanner.passive"),
    ("Prompt injection in pages", "Text written to hijack an AI agent or scanner", "all", "Scanner.passive"),
    ("Server banner", "Server header with software / version", "all", "Scanner.passive"),
    ("HTTP methods / TRACE", "Risky methods in Allow, TRACE echo", "all", "Scanner.http_checks"),
    ("CORS", "Arbitrary / null / prefix / suffix origin reflection, wildcard with credentials, preflight DELETE",
     "all", "Scanner.http_checks"),
    ("Host header injection", "X-Forwarded-Host reflected in Location or body", "all", "Scanner.http_checks"),
    ("API documentation", "/docs, swagger, openapi, GraphQL consoles exposed", "all",
     "Scanner.http_checks (API_DOC_PATHS)"),
    ("GraphQL introspection", "Full schema returned to anyone (GET ?query={__schema...})", "all",
     "Scanner.http_checks (GRAPHQL_PATHS)"),
    ("Exposed files", "See the table below (soft-404 aware; content never copied into the report)", "all",
     "Scanner.http_checks (SENSITIVE_PATHS)"),
    ("Reflected XSS", ("Unencoded reflection of <, \" and ' (HTML), quote break-out inside <script>, "
     "javascript: URLs in links"), "standard+", "Scanner.active"),
    ("Server-side template injection", "{{7*7}}-style expression evaluated", "standard+", "Scanner.active"),
    ("CRLF / header injection", "Injected response header returned", "standard+", "Scanner.active"),
    ("SQL injection", "Error-based (DB error on a quote), boolean-based; time-based on aggressive", "standard+",
     "Scanner.active, Scanner._sqli_boolean, Scanner._time_based"),
    ("OS command injection", "Time-based (aggressive / auth_deep, capped)", "aggressive", "Scanner._time_based"),
    ("Open redirect", "Redirect parameter accepts an outside host (never followed)", "standard+", "Scanner.active"),
    ("Path traversal", "/etc/passwd signature through file-like parameters", "standard+", "Scanner.active"),
    ("File upload", "Benign disguised payloads; confirmed execution is critical", "aggressive / auth_deep",
     "Scanner.upload_tests"),
    ("Endpoint probing", "Backend endpoints referenced by the frontend", "all", "Scanner.probe_endpoints"),
    ("Rate limiting (429)", "Retry-After honoured; throttled URLs reported as incomplete coverage", "all",
     "ScopedClient, scopeguard/ratelimit.py"),
]

PROBE_NOTES = {
    "security_headers": "missing HSTS, CSP, X-Content-Type-Options, Referrer-Policy, clickjacking protection",
    "csp_weakness": "unsafe-inline (without nonce/hash), unsafe-eval, wildcard script sources, open object-src",
    "cors": "a reflected untrusted Origin, or wildcard origin with credentials",
    "cookie_flags": "cookies without Secure, HttpOnly or SameSite",
    "cache_control": "cookie-setting / authenticated responses without no-store / private",
    "http_methods": "methods advertised by OPTIONS (informational)",
    "server_banner": "server / framework versions in Server, X-Powered-By and similar headers",
    "information_disclosure": "stack traces and verbose framework errors in the body",
    "directory_listing": "auto-generated file indexes",
    "mixed_content": "http:// scripts, styles, frames (medium) or images / media (low) on an HTTPS page",
    "insecure_transport": "the page answers on plain HTTP without redirecting to HTTPS",
    "open_redirect": "a query parameter that redirects to an outside host",
    "reflected_marker": "a harmless marker echoed back from a query parameter (not proof of XSS)",
}


def _cell(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _table(header: list[str], rows: list[list[object]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return out


def _test_files() -> list[list[str]]:
    rows = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8")))
        first = " ".join((doc or TEST_NOTES.get(path.name, "")).split("\n\n")[0].split())
        rows.append([f"`tests/{path.name}`", first or "-"])
    return rows


def build() -> str:
    lines = [
        "# Security checks and tests",
        "",
        ("Generated by `uv run python scripts/gen_checks_doc.py` from the rule tables in the code; regenerate "
        "it after adding or changing a check (`tests/test_new_checks.py` fails when a rule is missing here)."),
        "",
        ("Every check is read-only towards the target: GET, HEAD, OPTIONS and TRACE only (POST only for the "
        "benign upload test on the aggressive profiles), in scope only, never following redirects, never "
        "downloading files, and never sending denial-of-service traffic. Findings are leads, not proof."),
        "",
        "## Where each kind of check runs",
        "",
        *_table(["Layer", "What it tests", "Code", "Runs in"], [
            ["DAST (native engine)", "the running website", "`src/scopeguard/engine.py` (`Scanner`)",
             "isolated child interpreter with audit hooks (`src/scopeguard/sandbox.py`, `worker.py`)"],
            ["Custom probes", "planned extra checks on the website", "`src/pentest_agent/tools/probe_runner.py`",
             "the agent (httpx client with the network policy and 429 handling)"],
            ["Website JavaScript SAST", "the site's own scripts and inline JS", "`engine.JS_RULES`",
             ("the DAST engine (`Scanner.sast`, in its sandbox) and the sandbox check (Kubernetes Job; "
             "in-process fallback)")],
            ["Source-code SAST", "your uploaded / git code", ("`src/scopeguard/codecheck.py` (`BACKEND_RULES`, "
             "`scan_routes`, `scan_file_level`)"), "Kubernetes Job (or the process sandbox); code is never run"],
            ["Coding standard + ruff lint", "Python files of your code", "`src/scopeguard/codestyle.py`",
             "same sandbox, parsed with `ast` / `tokenize`, never executed"],
            ["Archive safety", "the uploaded .zip itself", "`src/scopeguard/archive.py`", "inside the sandbox"],
            ["Code tools (ruff, mypy, bandit, radon, semgrep, pip-audit)",
             "Python files of your code; versions pinned in its requirements-type files",
             "`src/pentest_agent/code_tools.py`, `src/scopeguard/deps.py`",
             ("child processes on the server in the same code SAST step (audit hook: no processes, writes only "
             "in a temp folder, network only for pip-audit's vulnerability database); code is never run")],
        ]),
        "",
        ("Profiles (`engine.PROFILES`): `quick` = crawl + passive checks only; `standard` adds safe active "
        "checks; `aggressive` / `auth_deep` add payload variants, time-based checks and upload tests."),
        "",
        "## DAST checks (`src/scopeguard/engine.py`)",
        "",
        *_table(["Check", "Finds", "Profiles", "Where"], [list(r) for r in DAST_STEPS]),
        "",
        "### Exposed files (`engine.SENSITIVE_PATHS`)",
        "",
        ("Each path is fetched once; a finding needs HTTP 200, a body that differs from the site's 404 page and "
        "a content signature. The file's content is never copied into the report."),
        "",
        *_table(["Path", "Severity", "Finding", "CWE"],
                [[f"`{p}`", sev, title, cwe] for p, _sig, sev, title, cwe in engine.SENSITIVE_PATHS]),
        "",
        "## Custom probes (`src/pentest_agent/tools/probe_runner.py`)",
        "",
        ("The LLM (or the built-in plan without one) picks up to 16 probes from this fixed list; hand-written "
        "code runs them with GET or OPTIONS only. Timeouts are retried with tenacity (up to "
        "`PROBE_MAX_ATTEMPTS`)."),
        "",
        *_table(["Probe", "Reports", "Needs a parameter"],
                [[f"`{p.value}`", PROBE_NOTES.get(p.value, "-"), "yes" if p in PARAMETER_PROBES else "no"]
                 for p in ProbeType]),
        "",
        "## Website JavaScript SAST (`engine.JS_RULES`)",
        "",
        "Applied line by line to the site's inline and same-site scripts. Secret matches never show the value.",
        "",
        *_table(["Rule", "Severity", "CWE", "Finds"],
                [[f"`{rid}`", sev, cwe, desc] for rid, _rx, sev, _cat, desc, cwe in engine.JS_RULES]),
        "",
        "## Source-code SAST (`codecheck.BACKEND_RULES`)",
        "",
        ("Python projects are the supported language (other files are marked \"partial coverage\"). Rules with "
        "no regex are route- or file-level checks (`codecheck.scan_routes`, `scan_file_level`). Every rule "
        "has a recommendation; the IDOR, XSS, DOM and DoS groups have full before/after fixes "
        "(`src/scopeguard/remediation.py`)."),
        "",
        *_table(["Rule", "Severity", "CWE", "Finds", "Files"],
                [[f"`{r[0]}`", r[2], r[5], r[4], "all" if r[7] is None else ", ".join(sorted(r[7]))[:60]]
                 for r in codecheck.BACKEND_RULES]),
        "",
        "## Coding standard: PEP 8 and ruff lint (`src/scopeguard/codestyle.py`)",
        "",
        ("One finding per rule and file (with a count and the first lines), capped at "
        f"{codestyle.MAX_STYLE_FINDINGS} per scan so style never crowds out security findings. The ruff "
        "rules are re-implemented with the standard library's `ast` (ruff itself cannot run in the sandbox: "
        "no network, no extra binaries)."),
        "",
        *_table(["Rule", "Code", "Severity", "Finds"],
                [[f"`{rid}`", codestyle.code_label(r[0]), r[1], r[2]] for rid, r in codestyle.STYLE_RULES.items()]),
        "",
        "## Code tools (`src/pentest_agent/code_tools.py`)",
        "",
        ("Run in the graph's `code_sast` step after the sandbox analysis, on the same upload, before it is "
        "deleted. Static only: nothing from the upload is run, imported or installed, and the project's own "
        "tool settings are ignored. Findings go through the same post-guardrail as the sandbox output "
        "(`code_guardrails.post_tools`) and land in the scan's one report."),
        "",
        *_table(["Tool", "Checks", "Rule ids", "Severity", "Settings used"], [
            ["ruff", "pyflakes, pycodestyle errors, flake8-bugbear", "`RUFF_<code>` (one per rule and file)", "low",
             f"`--isolated --select {code_tools.RUFF_SELECT}`"],
            ["mypy", "type errors", "`MYPY_<error code>` (one per code and file)", "low",
             "our own config file (no project plugins), `--no-site-packages`"],
            ["bandit", "Python security issues", "`BANDIT_<test id>`", "bandit's own (high / medium / low)",
             "defaults, from a neutral working folder"],
            ["radon", "cyclomatic complexity, rank C or worse", "`RADON_COMPLEXITY`", "info (C), low (D-F)",
             "`cc -n C`"],
            ["semgrep", "the local rules in `src/pentest_agent/semgrep/python.yml`", "`SEMGREP_<rule>`",
             "ERROR high, WARNING medium", "`--config <local file> --metrics=off`; optional install"],
            ["pip-audit", "known vulnerabilities (OSV or PyPI) in exactly pinned versions",
             "`VULNERABLE_DEPENDENCY` (one per package version)", "medium (pip-audit gives no CVSS)",
             "`--disable-pip --no-deps`, our own `name==version` file; `PIP_AUDIT_SERVICE`"],
        ]),
        "",
        ("Requirements-type files (`scopeguard.deps.is_requirements_file`): `requirements*.txt` / `*.in` (also "
        "in a `requirements/` folder), `constraints*.txt`, `pyproject.toml` (PEP 621, PEP 735 groups, Poetry), "
        "`setup.cfg`, `Pipfile`, `Pipfile.lock`, `uv.lock`, `poetry.lock`, `pdm.lock`, `pylock*.toml`. Only "
        "entries pinned to one version (`==` / `===`, Poetry's bare version, lock files) are audited; the "
        "rest is listed as not audited. Packages from git, a path or a URL and the project itself are skipped."),
        "",
        "## Automated tests (`tests/`)",
        "",
        ("Run everything with `uv run pytest` (no real network or LLM calls; the golden live judge needs "
        "`GOLDEN_LIVE=1`). Other gates: `uv run ruff check src tests` (lint), "
        "`uv run python -m scopeguard.cli --simulate` (all planted issues found), "
        "`uv run golden-check --allow-no-llm` (data drift) and `uv run pentest-audit verify` (audit chain)."),
        "",
        *_table(["File", "Covers"], _test_files()),
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    OUT.write_text(build(), encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
