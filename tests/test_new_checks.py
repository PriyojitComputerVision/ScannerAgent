"""The extra SAST and DAST checks: code rules (archives, temp files, assert, ciphers, IVs, password
hashing, timing-safe compare, SQLAlchemy text(), Django hosts, debug server), website JavaScript rules
(DOM XSS, string timers, API tokens), and DAST checks (Subresource Integrity, weak HSTS, forms posting
to HTTP, GraphQL introspection, more exposed files). Positive and safe variants; no network."""
from __future__ import annotations

import pytest

from scopeguard import codecheck, engine, remediation


def _scan(name: str, text: str) -> set[str]:
    res = codecheck.Results()
    ext = "." + name.rsplit(".", 1)[-1].lower()
    codecheck._scan_lines(res, text, source="sandbox_source", where=f"source/{name}", ext=ext,
                          js=ext in codecheck.JS_EXT, backend=True, name=name)
    return {f["title"].split(":")[0] for f in res.findings}


# ---------------------------------------------------------------- code SAST
@pytest.mark.parametrize("name, code, rule", [
    ("a.py", "tar.extractall(dest)", "PY_ARCHIVE_EXTRACTALL"),
    ("a.py", "zipfile.ZipFile(p).extractall('out')", "PY_ARCHIVE_EXTRACTALL"),
    ("a.py", "name = tempfile.mktemp()", "PY_TEMPFILE_MKTEMP"),
    ("a.py", "    assert request.user.is_admin", "PY_ASSERT_SECURITY"),
    ("a.py", "cipher = DES.new(key, DES.MODE_ECB)", "WEAK_CIPHER"),
    ("a.py", "Cipher(algorithms.AES(k), modes.ECB())", "WEAK_CIPHER"),
    ("a.js", "crypto.createCipheriv('aes-128-ecb', k, null)", "WEAK_CIPHER"),
    ("a.py", "iv = b'0000000000000000'", "STATIC_IV"),
    ("a.py", "h = hashlib.sha256(password.encode()).hexdigest()", "FAST_HASH_PASSWORD"),
    ("a.js", "crypto.createHash('sha256').update(password)", "FAST_HASH_PASSWORD"),
    ("a.py", "if signature == expected:", "TIMING_UNSAFE_COMPARE"),
    ("a.py", 'db.execute(text(f"SELECT * FROM u WHERE id={uid}"))', "SQLALCHEMY_TEXT_FORMAT"),
    ("a.py", "ALLOWED_HOSTS = ['*']", "DJANGO_ALLOWED_HOSTS_ALL"),
    ("a.py", "app.run(host='0.0.0.0', debug=True)", "BIND_ALL_INTERFACES_DEBUG"),
])
def test_new_code_rules_find_the_weakness(name, code, rule):
    assert rule in _scan(name, code)


@pytest.mark.parametrize("name, code, rule", [
    ("a.py", "tar.extractall(dest, filter='data')", "PY_ARCHIVE_EXTRACTALL"),
    ("a.py", "fd, p = tempfile.mkstemp()", "PY_TEMPFILE_MKTEMP"),
    ("a.py", "assert len(items) == 3", "PY_ASSERT_SECURITY"),
    ("a.py", "Cipher(algorithms.AES(k), modes.GCM(iv))", "WEAK_CIPHER"),
    ("a.py", "iv = os.urandom(16)", "STATIC_IV"),
    ("a.py", "hashlib.sha256(data).hexdigest()", "FAST_HASH_PASSWORD"),
    ("a.py", "if hmac.compare_digest(signature, expected):", "TIMING_UNSAFE_COMPARE"),
    ("a.py", "stmt = text('SELECT * FROM t WHERE id = :id')", "SQLALCHEMY_TEXT_FORMAT"),
    ("a.py", "ALLOWED_HOSTS = ['example.com']", "DJANGO_ALLOWED_HOSTS_ALL"),
    ("a.py", "app.run(host='127.0.0.1', debug=True)", "BIND_ALL_INTERFACES_DEBUG"),
])
def test_new_code_rules_stay_quiet_on_the_safe_variant(name, code, rule):
    assert rule not in _scan(name, code)


def test_new_rules_have_recommendations_and_dom_remediation():
    for rid in ("PY_ARCHIVE_EXTRACTALL", "PY_TEMPFILE_MKTEMP", "PY_ASSERT_SECURITY", "WEAK_CIPHER", "STATIC_IV",
                "FAST_HASH_PASSWORD", "TIMING_UNSAFE_COMPARE", "SQLALCHEMY_TEXT_FORMAT",
                "DJANGO_ALLOWED_HOSTS_ALL", "BIND_ALL_INTERFACES_DEBUG", "JS_DOM_XSS", "JS_STRING_TIMER",
                "JS_API_TOKEN", "GOOGLE_API_KEY"):
        assert codecheck.RECOMMENDATIONS.get(rid), rid
    for rid in ("JS_DOM_XSS", "JS_STRING_TIMER"):
        assert remediation.for_rule(rid, location="site/app.js")["group"] == "DOM"


# ---------------------------------------------------------------- website JavaScript SAST
JS = {r[0]: r[1] for r in engine.JS_RULES}


@pytest.mark.parametrize("rule, hit, safe", [
    ("JS_DOM_XSS", "el.innerHTML = location.hash.slice(1)", "el.textContent = location.hash"),
    ("JS_DOM_XSS", "document.write(document.referrer)", "el.innerHTML = '<b>x</b>'"),
    ("JS_STRING_TIMER", "setTimeout('doIt()', 10)", "setTimeout(() => go(), 10)"),
    ("JS_API_TOKEN", "const t = 'ghp_abcdefghijklmnopqrstuvwxyz0123'", "sk_test_abc"),
    ("GOOGLE_API_KEY", "key: 'AIzaSyA1234567890abcdefghijklmnopqrstuv'", "AIza-short"),
])
def test_new_js_rules(rule, hit, safe):
    assert JS[rule].search(hit) and not JS[rule].search(safe)


def _scanner() -> engine.Scanner:
    return engine.Scanner("https://app.test/", ["app.test"], profile="standard", delay=0)


def test_secret_js_matches_never_show_the_value():
    s = _scanner()
    token = "ghp_abcdefghijklmnopqrstuvwxyz0123"
    s.pages = [engine.Page(url="https://app.test/", resp=engine.Response(url="https://app.test/", status=200,
                                                                         body="<html></html>"),
                           inline_scripts=[f"const t = '{token}';"])]
    s.sast()
    hits = [f for f in s.f.all() if f["title"].startswith("JS_API_TOKEN")]
    assert hits and token not in (hits[0]["evidence"] or "") and "redacted" in hits[0]["evidence"]


# ---------------------------------------------------------------- DAST, on the fetched response
def _page(url: str, body: str, headers: dict | None = None, forms: list | None = None) -> engine.Page:
    resp = engine.Response(url=url, status=200, headers={"content-type": "text/html", **(headers or {})}, body=body)
    return engine.Page(url=url, resp=resp, forms=forms or [])


def _titles(s: engine.Scanner) -> set[str]:
    return {f["title"] for f in s.f.all()}


def test_third_party_script_without_sri():
    s = _scanner()
    page = _page("https://app.test/", '<script src="https://cdn.other.example/lib.js"></script>'
                                      '<script src="/own.js"></script>'
                                      '<script src="https://cdn.ok.example/x.js" integrity="sha384-abc" '
                                      'crossorigin="anonymous"></script>')
    s._passive_extras(page, page.resp)
    sri = [f for f in s.f.all() if "Subresource Integrity" in f["title"]]
    assert len(sri) == 1 and "cdn.other.example/lib.js" in sri[0]["evidence"] and "cdn.ok.example" not in sri[0]["evidence"]


@pytest.mark.parametrize("hsts, weak", [("max-age=3600", True), ("max-age=31536000; includeSubDomains", False),
                                        ("includeSubDomains", True)])
def test_weak_hsts(hsts, weak):
    s = _scanner()
    page = _page("https://app.test/", "<html></html>", {"strict-transport-security": hsts})
    s._passive_extras(page, page.resp)
    assert ("Weak Strict-Transport-Security (short max-age)" in _titles(s)) is weak


def test_https_form_posting_to_http():
    s = _scanner()
    page = _page("https://app.test/login", "<html></html>",
                 forms=[{"action": "http://app.test/do-login", "method": "post", "inputs": []},
                        {"action": "/search", "method": "get", "inputs": []}])
    s._passive_extras(page, page.resp)
    hits = [f for f in s.f.all() if f["title"] == "HTTPS page submits a form over plaintext HTTP"]
    assert len(hits) == 1 and "app.test/do-login" in hits[0]["evidence"]


# ---------------------------------------------------------------- DAST, extra requests (GET only)
def test_graphql_introspection_and_new_exposed_files(monkeypatch):
    s = _scanner()
    sent = []

    def fake_request(method, url, headers=None):
        sent.append((method, url))
        path = url.split("app.test", 1)[1]
        if path.startswith("/graphql?"):
            return engine.Response(url=url, status=200, headers={"content-type": "application/json"},
                                   body='{"data":{"__schema":{"queryType":{"name":"Query"},"types":[]}}}')
        bodies = {"/.git/config": "[core]\n\trepositoryformatversion = 0\n",
                  "/actuator/env": '{"activeProfiles":["prod"],"propertySources":[]}',
                  "/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc"}
        if path in bodies:
            return engine.Response(url=url, status=200, headers={"content-type": "text/plain"}, body=bodies[path])
        return engine.Response(url=url, status=404, headers={}, body="not found")

    monkeypatch.setattr(s.client, "request", fake_request)
    s.http_checks()
    titles = _titles(s)
    assert "GraphQL introspection enabled (/graphql)" in titles
    assert {"Exposed .git/config (repository settings, remote URLs)", "Exposed SSH private key",
            "Spring Boot actuator /env exposed (configuration and secrets)"} <= titles
    assert "Exposed AWS credentials file" not in titles  # 404: nothing reported
    assert {m for m, _ in sent} <= engine.ALLOWED_METHODS  # read-only requests only
    key = next(f for f in s.f.all() if f["title"] == "Exposed SSH private key")
    assert key["severity"] == "critical" and "abc" not in (key["evidence"] or "")


# ---------------------------------------------------------------- second batch
@pytest.mark.parametrize("name, code, rule, safe", [
    ("a.py", "DB = 'postgresql://app:S3cretPw@db:5432/x'", "DB_URL_WITH_PASSWORD", "DB = os.environ['DATABASE_URL']"),
    ("a.py", "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)", "OLD_TLS_VERSION",
     "ctx.minimum_version = ssl.TLSVersion.TLSv1_2"),
    ("a.js", "vm.runInNewContext(code, sandbox)", "NODE_VM_RUN", "const vm2 = require('x')"),
    ("a.py", 'r = requests.get("http://api.example.com/v1")', "PY_HTTP_PLAINTEXT_CALL",
     'r = requests.get("https://api.example.com/v1")'),
])
def test_second_batch_code_rules(name, code, rule, safe):
    assert rule in _scan(name, code) and rule not in _scan(name, safe)
    assert codecheck.RECOMMENDATIONS.get(rule)


def test_db_url_password_is_never_copied():
    res = codecheck.Results()
    codecheck._scan_lines(res, "DB = 'postgresql://app:S3cretPw@db/x'", source="sandbox_source",
                          where="source/a.py", ext=".py", js=False, backend=True, name="a.py")
    assert res.findings and all("S3cretPw" not in (f.get("evidence") or "") for f in res.findings)


def test_reverse_tabnabbing_and_source_maps():
    s = _scanner()
    page = _page("https://app.test/", '<a href="/x" target="_blank">x</a><a href="/y" target="_blank" '
                                      'rel="noopener">y</a>')
    s._passive_extras(page, page.resp)
    tab = [f for f in s.f.all() if "tabnabbing" in f["title"]]
    assert len(tab) == 1 and tab[0]["evidence"] == "1 link(s)"
    s.pages = [engine.Page(url="https://app.test/", resp=page.resp,
                           inline_scripts=["var a=1;\n//# sourceMappingURL=app.js.map"])]
    s.sast()
    assert "JavaScript source map published" in _titles(s)


def test_cross_domain_policy_files(monkeypatch):
    s = _scanner()

    def fake_request(method, url, headers=None):
        if url.endswith("/crossdomain.xml"):
            return engine.Response(url=url, status=200, headers={"content-type": "text/xml"},
                                   body='<cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>')
        return engine.Response(url=url, status=404, headers={}, body="no")

    monkeypatch.setattr(s.client, "request", fake_request)
    s.http_checks()
    assert "Flash cross-domain policy allows any domain" in _titles(s)
    assert "Silverlight client access policy allows any domain" not in _titles(s)


# ---------------------------------------------------------------- ruff lint rules (code SAST, Python)
from scopeguard import codestyle


@pytest.mark.parametrize("code, rule, safe", [
    ("import os\n", "STYLE_UNUSED_IMPORT", "import os\nprint(os.sep)\n"),
    ("from x import y as z\n", "STYLE_UNUSED_IMPORT", "from x import y as y\n"),          # explicit re-export
    ("def f():\n    unused = 5\n", "STYLE_UNUSED_VARIABLE", "def f():\n    _ignored = 5\n"),
    ('x = f"hello"\n', "STYLE_FSTRING_NO_PLACEHOLDER", 'x = f"{v:>10}"\n'),               # a format spec is fine
    ("def a():\n    pass\n\n\ndef a():\n    pass\n", "STYLE_REDEFINED",
     "class P:\n    @property\n    def v(self):\n        return 1\n\n    @v.setter\n    def v(self, x):\n        pass\n"),
    ('if x is "a":\n    pass\n', "STYLE_IS_LITERAL", "if x is None:\n    pass\n"),
    ("l = 3\n", "STYLE_AMBIGUOUS_NAME", "length = 3\n"),
])
def test_ruff_lint_rules(code, rule, safe):
    assert rule in codestyle.check_python(code) and rule not in codestyle.check_python(safe)


def test_ruff_lint_respects_usage_the_ast_cannot_see_directly():
    src = ('from typing import TYPE_CHECKING\nfrom h import helper\n__all__ = ["helper"]\n'
           'if TYPE_CHECKING:\n    from orders import Order\n\n\ndef use(o: "Order") -> None:\n    seen = []\n'
           '    def inner():\n        return seen\n    return inner\n')
    hits = codestyle.check_python(src)
    assert "STYLE_UNUSED_IMPORT" not in hits and "STYLE_UNUSED_VARIABLE" not in hits


def test_ruff_findings_are_labelled_and_capped_like_pep8():
    by = {f["rid"]: f for f in codestyle.findings_for_file("import os\nl = 1\n", "source/a.py")}
    assert "(ruff F401 (Pyflakes))" in by["STYLE_UNUSED_IMPORT"]["title"]
    assert "(ruff E741 (pycodestyle))" in by["STYLE_AMBIGUOUS_NAME"]["title"]
    assert codestyle.code_label("E722") == "PEP 8 E722" and codestyle.code_label("F403") == "PEP 8 F403"
    assert set(codestyle.STYLE_RULES) <= set(codecheck.RECOMMENDATIONS)  # every rule has advice


def test_security_checks_doc_is_up_to_date():
    """docs/SECURITY_CHECKS.md lists every rule and test file; regenerate it with
    uv run python scripts/gen_checks_doc.py after adding a check."""
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location("gen_checks_doc", root / "scripts" / "gen_checks_doc.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    expected = gen.build()
    assert (root / "docs" / "SECURITY_CHECKS.md").read_text(encoding="utf-8") == expected, \
        "docs/SECURITY_CHECKS.md is stale: run uv run python scripts/gen_checks_doc.py"
    for rid in ([r[0] for r in engine.JS_RULES] + [r[0] for r in codecheck.BACKEND_RULES]
                + list(codestyle.STYLE_RULES) + [p for p, *_ in engine.SENSITIVE_PATHS]):
        assert f"`{rid}`" in expected, rid
    for test_file in (root / "tests").glob("test_*.py"):
        assert f"`tests/{test_file.name}`" in expected, test_file.name
