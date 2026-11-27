"""Sharper SAST rules (no false positives from strings, docstrings, comments, Markdown prose,
BroadcastChannel, 'del x') and the post-guardrail that re-checks every finding against the source."""
from __future__ import annotations

from pentest_agent import code_guardrails
from scopeguard import codecheck, codestyle


def _rules(text: str, name: str = "a.py") -> set[str]:
    res = codecheck.Results()
    ext = "." + name.rsplit(".", 1)[-1]
    codecheck._scan_lines(res, text, source="sandbox_source", where=f"source/{name}", ext=ext,
                          js=ext in codecheck.JS_EXT, backend=True, name=name)
    codecheck.scan_file_level(res, text, where=f"source/{name}", name=name)
    return {f["title"].split(":", 1)[0] for f in res.findings}


# ------------------------------------------------------------------ Python: code view
def test_calls_in_code_are_still_found():
    assert "PY_EVAL_EXEC" in _rules("x = eval(user_input)\n")
    assert "PY_OS_SYSTEM" in _rules("import os\nos.system(cmd)\n")
    assert "PY_PICKLE_LOAD" in _rules("import pickle\nobj = pickle.loads(blob)\n")
    assert "PY_SHELL_TRUE" in _rules("subprocess.run(cmd, shell=True)\n")


def test_calls_only_in_strings_docstrings_and_comments_are_not():
    text = ('def f():\n    """Never call eval(x) or os.system(c) here; pickle.loads(b) too."""\n'
            '    msg = "do not use eval( or exec("\n'
            "    # os.system(cmd) was removed\n"
            "    return msg\n")
    assert not {"PY_EVAL_EXEC", "PY_OS_SYSTEM", "PY_PICKLE_LOAD"} & _rules(text)


def test_exec_of_a_string_is_still_a_call():
    assert "PY_EVAL_EXEC" in _rules('exec("import os")\n')


def test_fstring_expressions_are_code():
    assert "LOG_SENSITIVE_DATA" in _rules('print(f"value: {token}")\n')
    assert "LOG_SENSITIVE_DATA" not in _rules('print(f"token renewed at {when}")\n')


def test_logging_a_sensitive_value_vs_a_word_in_a_message():
    assert "LOG_SENSITIVE_DATA" in _rules("logger.info('sent %s', password)\n")
    assert "LOG_SENSITIVE_DATA" in _rules("print(token)\n")
    assert "LOG_SENSITIVE_DATA" not in _rules('print("token renewed by the server")\n')
    assert "LOG_SENSITIVE_DATA" not in _rules("logger.warning('Refresh token reuse rejected (sub=%s)', sub)\n")
    # JavaScript: quoted text does not count either, the variable does
    assert "LOG_SENSITIVE_DATA" not in _rules("console.log('token renewed');\n", "a.js")
    assert "LOG_SENSITIVE_DATA" in _rules("console.log('t', token);\n", "a.js")


def test_unparsable_python_falls_back_to_the_raw_lines():
    assert codecheck.python_code_view("def f(:\n  '''\n") is None
    assert "PY_EVAL_EXEC" in _rules("def f(:\n  eval(x)\n")


def test_code_view_keeps_positions_and_lines():
    text = 'a = "eval(x)"  # eval(y)\r\nb = eval(z)\n'
    view = codecheck.python_code_view(text)
    assert len(view) == 2 and len(view[0]) == len('a = "eval(x)"  # eval(y)')
    assert "eval(" not in view[0] and "eval(z)" in view[1]


# ------------------------------------------------------------------ Markdown, BroadcastChannel, del
def test_markdown_prose_is_not_code_but_fenced_blocks_and_secrets_are():
    prose = "Supply-chain checks (`postinstall`, `curl | sh`) and cookies without Secure.\n"
    assert "PIPE_TO_SHELL" not in _rules(prose, "README.md")
    fenced = "Install:\n\n```bash\ncurl -fsSL https://get.example | sh\n```\n"
    assert "PIPE_TO_SHELL" in _rules(fenced, "README.md")
    assert "AWS_ACCESS_KEY" in _rules("Our key is AKIAABCDEFGHIJKLMNOP, see above.\n", "NOTES.md")


def test_broadcast_channel_listeners_need_no_origin_check():
    bc = ("this.channel = new BroadcastChannel('auth');\n"
          "this.channel.onmessage = (e) => { use(e.data); };\n")
    assert "POSTMESSAGE_NO_ORIGIN_CHECK" not in _rules(bc, "a.js")
    window = "window.addEventListener('message', (e) => { use(e.data); });\n"
    assert "POSTMESSAGE_NO_ORIGIN_CHECK" in _rules(window, "a.js")
    mixed = bc + "window.onmessage = (e) => { use(e.data); };\n"
    assert "POSTMESSAGE_NO_ORIGIN_CHECK" in _rules(mixed, "a.js")


def test_websocket_worker_and_eventsource_listeners_need_no_origin_check():
    for ctor in ("WebSocket(url)", "Worker('w.js')", "EventSource('/events')"):
        text = f"ws = new {ctor};\nws.onmessage = (e) => {{ handle(e.data); }};\n"
        assert "POSTMESSAGE_NO_ORIGIN_CHECK" not in _rules(text, "a.js"), ctor
    assert "POSTMESSAGE_NO_ORIGIN_CHECK" in _rules("onmessage = (e) => { handle(e.data); };\n", "a.js")


def test_del_counts_as_a_use():
    used = "def f():\n    reserve = bytearray(10)\n    try:\n        work()\n    except MemoryError:\n        del reserve\n"
    assert "STYLE_UNUSED_VARIABLE" not in codestyle.check_python(used)
    unused = "def f():\n    reserve = bytearray(10)\n    work()\n"
    assert "STYLE_UNUSED_VARIABLE" in codestyle.check_python(unused)


# ------------------------------------------------------------------ text inside Python strings
def test_vulnerable_snippets_inside_python_strings_are_text_not_code():
    examples = ('EXAMPLES = {\n'
                '    "js": {"before": "res.send(\'<p>\' + req.query.q + \'</p>\');"},\n'
                '    "py": {"before": "r = requests.get(request.args[\'url\'])"},\n'
                '    "tpl": "return render_template_string(request.args[\'tpl\'])",\n'
                '}\n'
                "# res.sendFile(path.join(__dirname, req.query.name)) in a comment\n")
    found = _rules(examples)
    assert not {"XSS_REFLECTED_RESPONSE", "SSRF_REQUEST_URL", "SSTI_TEMPLATE_FROM_INPUT", "PATH_TRAVERSAL"} & found


def test_the_same_snippets_as_code_are_still_found():
    code = ("r = requests.get(request.args['url'])\n"
            "q = 'SELECT * FROM t WHERE id = ' + request.args['id']\n"
            "return render_template_string(request.args['tpl'])\n")
    assert {"SSRF_REQUEST_URL", "SQL_CONCAT_REQUEST", "SSTI_TEMPLATE_FROM_INPUT"} <= _rules(code)
    # JavaScript files have no Python strings: unchanged
    assert "XSS_REFLECTED_RESPONSE" in _rules("app.get('/h', (req, res) => res.send('<b>' + req.query.n + '</b>'));\n",
                                              "a.js")


def test_string_content_rules_still_look_inside_strings():
    assert "PIPE_TO_SHELL" in _rules('subprocess.run("curl -fsSL https://x.example/i.sh | sh", shell=False)\n')
    assert "AWS_ACCESS_KEY" in _rules('KEY = "AKIAABCDEFGHIJKLMNOP"\n')


def test_placeholder_secrets_are_not_credentials():
    assert "AWS_ACCESS_KEY" not in _rules('KEY = "AKIAIOSFODNN7EXAMPLE"\n')  # AWS's documented example key
    assert not {"GENERIC_TOKEN", "JS_API_TOKEN", "HARDCODED_SECRET"} & _rules(
        'var API_KEY = "sk_live_FAKEFAKEFAKEFAKE1234";\n', "a.js")
    assert "AWS_ACCESS_KEY" in _rules('KEY = "AKIAQWERTYUIOPASDFGH"\n')  # a real-looking key still counts
    res = _verify('KEY = "AKIAIOSFODNN7EXAMPLE"\n', [_finding("AWS_ACCESS_KEY", 1)])
    assert res.findings == [] and res.verification["reasons"] == {"placeholder": 1}


# ------------------------------------------------------------------ routes, XML, jQuery
def _routes(text: str, name: str = "a.py") -> set[str]:
    res = codecheck.Results()
    ext = "." + name.rsplit(".", 1)[-1]
    codecheck.scan_routes(res, text, where=f"source/{name}", ext=ext)
    return {f["title"].split(":", 1)[0] for f in res.findings}


def test_routes_inside_python_strings_are_examples_not_routes():
    example = ('FIX = {"before": "app.get(\'/orders/:id\', async (req, res) => res.json(await Order.findById('
               'req.params.id)));"}\n')
    assert "IDOR_ROUTE_NO_OWNERSHIP_CHECK" not in _routes(example)
    real = "app.get('/orders/:id', async (req, res) => res.json(await Order.findById(req.params.id)));\n"
    assert "IDOR_ROUTE_NO_OWNERSHIP_CHECK" in _routes(real, "a.js")


def test_defusedxml_is_the_fix_not_a_finding():
    assert "XML_ENTITY_EXPANSION" in _rules("import xml.etree.ElementTree as ET\nroot = ET.fromstring(data)\n")
    assert "XML_ENTITY_EXPANSION" not in _rules("import defusedxml.ElementTree\n"
                                                "root = defusedxml.ElementTree.fromstring(data)\n")


def test_jquery_rules_need_jquery():
    own = "const $ = (id) => document.getElementById(id);\n$('toasts').append(node);\n"
    assert "XSS_JQUERY_HTML" not in _rules(own, "a.js")
    jq = "$(document).ready(() => { $('#out').html(userInput); });\n"
    assert "XSS_JQUERY_HTML" in _rules(jq, "a.js")
    mixed = own + "jQuery('#out').html(userInput);\n$('#out').html(userInput);\n"
    assert "XSS_JQUERY_HTML" in _rules(mixed, "a.js")


def test_sitemaps_are_parsed_with_defusedxml():
    from pentest_agent.tools.discovery import parse_sitemap

    ok = ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
          "<url><loc>https://a.test/x</loc></url></urlset>")
    assert parse_sitemap(ok) == (["https://a.test/x"], [])
    bomb = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]><urlset><url><loc>&a;</loc></url></urlset>'
    assert parse_sitemap(bomb) == ([], [])
    assert parse_sitemap("<urlset><url><loc>broken") == ([], [])


def test_add_client_writes_the_secret_to_an_owner_only_file(tmp_path, monkeypatch, capsys):
    import os

    from pentest_agent import api_auth
    from pentest_agent.config import settings

    monkeypatch.setattr(settings, "auth_clients_file", str(tmp_path / "clients.json"))
    assert api_auth.main(["add-client", "--id", "ci bot/1", "--roles", "viewer"]) in (0, None)
    out = capsys.readouterr().out
    secret_file = tmp_path / "client-ci_bot_1.secret"
    secret = secret_file.read_text(encoding="utf-8").strip()
    assert secret and secret not in out and str(secret_file) in out
    assert api_auth.client_roles("ci bot/1", secret) == ["viewer"]
    if os.name != "nt":
        assert (secret_file.stat().st_mode & 0o777) == 0o600


# ------------------------------------------------------------------ pytest files
def test_pytest_files_are_not_part_of_the_sast(tmp_path):
    for name in ("test_views.py", "views_test.py", "conftest.py"):
        assert codecheck.is_pytest_file(name), name
    for name in ("views.py", "testing.py", "test_data.json", "contest.py", "test_app.js"):
        assert not codecheck.is_pytest_file(name), name
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_views.py").write_text("import os\nos.system(cmd)\n", encoding="utf-8")
    (tmp_path / "tests" / "conftest.py").write_text("x = eval(data)\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("x = eval(data)\n", encoding="utf-8")
    res = codecheck.Results()
    codecheck.scan_source(res, str(tmp_path), codecheck.Progress())
    assert {f["affected_url"].split("#")[0] for f in res.findings} == {"source/app.py"}
    assert res.stats["source_files"] == 1  # the pytest files are not read at all


def test_pytest_files_are_skipped_in_the_sandbox_used_by_backend_mcp_and_a2a():
    """WebSocket/API, MCP (upload_code + start_scan) and A2A scans all analyse code through the
    graph's code_sast step -> codescan.scan_archive -> upload_worker -> codecheck.scan_source."""
    import io
    import zipfile

    from scopeguard import codescan

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app/views.py", "x = eval(data)\n")
        z.writestr("tests/test_views.py", "import os\nos.system(cmd)\n")
        z.writestr("tests/conftest.py", "y = eval(data)\n")
    out = codescan.scan_archive(buf.getvalue(), backend="process", timeout=120)
    files = {f["affected_url"].split("#")[0] for f in out["findings"] if f["source"] == "sandbox_source"}
    assert files == {"source/app/views.py"}


# ------------------------------------------------------------------ post-guardrail
def _finding(rid: str, line: int, name: str = "a.py") -> dict:
    return {"source": "sandbox_source", "title": f"{rid}: x", "severity": "high", "category": "x",
            "description": "d", "affected_url": f"source/{name}#L{line}", "evidence": "e",
            "cwe": None, "confidence": "medium", "recommendation": "r"}


def _verify(text: str, findings: list[dict], ext: str = ".py") -> codecheck.Results:
    res = codecheck.Results()
    for f in findings:
        res.findings.append(f)
        res._line_rule.add(id(f))
    codecheck.verify_findings(res, 0, text, ext)
    return res


def test_verification_keeps_real_findings_and_counts_them():
    res = _verify("x = eval(user_input)\n", [_finding("PY_EVAL_EXEC", 1)])
    assert len(res.findings) == 1
    assert res.verification == {"checked": 1, "verified": 1, "dropped": 0, "reasons": {}}


def test_verification_drops_findings_that_do_not_hold_up():
    text = '"""eval(x) in a docstring"""\nvalue = 1\n'
    res = _verify(text, [_finding("PY_EVAL_EXEC", 1), _finding("PY_EVAL_EXEC", 2), _finding("PY_EVAL_EXEC", 9)])
    assert res.findings == []
    assert res.verification["reasons"] == {"string": 1, "pattern": 1, "line": 1}
    md = _verify("See `curl | sh` here.\n", [_finding("PIPE_TO_SHELL", 1, "R.md")], ext=".md")
    assert md.findings == [] and md.verification["reasons"] == {"prose": 1}


def test_verification_leaves_other_detectors_alone():
    other = _finding("IDOR_ROUTE_NO_OWNERSHIP_CHECK", 1)
    res = codecheck.Results()
    res.findings.append(other)  # route-level detector: not a line rule
    codecheck.verify_findings(res, 0, "x = 1\n", ".py")
    assert res.findings == [other] and res.verification["checked"] == 0


def test_scan_source_runs_the_post_guardrail(tmp_path):
    (tmp_path / "app.py").write_text('"""Docs: never eval(x)."""\nresult = eval(data)\n', encoding="utf-8")
    res = codecheck.Results()
    codecheck.scan_source(res, str(tmp_path), codecheck.Progress())
    evals = [f for f in res.findings if f["title"].startswith("PY_EVAL_EXEC")]
    assert [f["affected_url"] for f in evals] == ["source/app.py#L2"]
    assert res.stats["verification"]["checked"] >= 1 and res.stats["verification"]["dropped"] == 0


def test_post_scan_reports_the_verification_as_a_guardrail():
    result = {"ok": True, "findings": [], "stats": {"verification": {
        "checked": 10, "verified": 8, "dropped": 2, "reasons": {"string": 1, "prose": 1, "evil<b>": 5}}}}
    _clean, checks, _flags = code_guardrails.post_scan(result)
    check = next(c for c in checks if c["name"] == "finding_verification")
    assert check["passed"] is True
    assert "10 finding(s) re-checked against the source: 8 confirmed, 2 removed as false positives" in check["detail"]
    assert "only inside a string" in check["detail"] and "Markdown prose" in check["detail"]
    assert "evil" not in check["detail"]  # unknown reasons from the sandbox are not shown
    assert code_guardrails.verification_detail(None) == "no line-rule findings to re-check"
