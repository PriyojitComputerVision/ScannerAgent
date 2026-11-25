"""SAST rules for uploaded / backend code: XSS, IDOR, injection, SSRF, supply chain, IaC,
with a recommendation for every rule and no false alarm on the safe variants."""
from __future__ import annotations

import pytest

from scopeguard import codecheck


def _scan(name: str, text: str) -> set[str]:
    res = codecheck.Results()
    ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
    codecheck._scan_lines(res, text, source="sandbox_source", where=f"source/{name}", ext=ext,
                          js=ext in codecheck.JS_EXT, backend=True, name=name)
    codecheck.scan_routes(res, text, where=f"source/{name}", ext=ext)
    codecheck.scan_file_level(res, text, where=f"source/{name}", name=name)
    return {f["title"].split(":")[0] for f in res.findings}


@pytest.mark.parametrize("name, code, rule", [
    # XSS
    ("a.js", "app.get('/h', (req, res) => res.send('<b>' + req.query.name + '</b>'));", "XSS_REFLECTED_RESPONSE"),
    ("a.php", "<?php echo $_GET['q']; ?>", "XSS_REFLECTED_RESPONSE"),
    ("a.py", "    return f\"<p>{request.args.get('n')}</p>\"", "XSS_FSTRING_RESPONSE"),
    ("a.py", "html = mark_safe(user_bio)", "XSS_MARK_SAFE"),
    ("p.html", "<div>{{ comment | safe }}</div>", "XSS_TEMPLATE_UNESCAPED"),
    ("p.ejs", "<div><%- user.bio %></div>", "XSS_TEMPLATE_UNESCAPED"),
    ("C.jsx", "<div dangerouslySetInnerHTML={{__html: html}} />", "XSS_REACT_DANGEROUS_HTML"),
    ("C.vue", '<div v-html="post.body"></div>', "XSS_VUE_SVELTE_RAW_HTML"),
    ("c.ts", "this.s.bypassSecurityTrustHtml(value)", "XSS_ANGULAR_BYPASS"),
    ("a.py", "env = Environment(autoescape=False)", "XSS_AUTOESCAPE_OFF"),
    ("a.py", "return render_template_string(request.args['t'])", "SSTI_TEMPLATE_FROM_INPUT"),
    # Access control
    ("a.js", "const o = await Order.findById(req.params.id);", "IDOR_DIRECT_OBJECT_LOOKUP"),
    ("a.py", "inv = Invoice.objects.get(pk=request.GET['invoice_id'])", "IDOR_DIRECT_OBJECT_LOOKUP"),
    ("a.js", "await User.findByIdAndUpdate(req.user.id, req.body);", "MASS_ASSIGNMENT"),
    ("a.py", "user = User(**request.json)", "MASS_ASSIGNMENT"),
    ("a.js", "res.redirect(req.query.next);", "OPEN_REDIRECT"),
    ("a.js", "res.sendFile(path.join(__dirname, req.query.file));", "PATH_TRAVERSAL"),
    ("a.py", "return send_file(request.args['p'])", "PATH_TRAVERSAL"),
    ("a.py", "@csrf_exempt", "CSRF_PROTECTION_DISABLED"),
    # Injection / SSRF / XXE / deserialization
    ("a.js", "db.users.find(req.body, cb)", "NOSQL_INJECTION"),
    ("a.py", "q = 'SELECT * FROM t WHERE id = ' + request.args['id']", "SQL_CONCAT_REQUEST"),
    ("a.php", "system('ping ' . $_GET['h']);", "COMMAND_INJECTION_INPUT"),
    ("a.py", "r = requests.get(request.args['url'])", "SSRF_REQUEST_URL"),
    ("a.js", "const r = await axios.get(req.query.url);", "SSRF_REQUEST_URL"),
    ("a.py", "p = etree.XMLParser(resolve_entities=True)", "XXE_EXTERNAL_ENTITIES"),
    ("a.php", "$o = unserialize($_COOKIE['s']);", "INSECURE_DESERIALIZATION"),
    # Sessions / crypto / logging
    ("a.py", "SESSION_COOKIE_SECURE = False", "INSECURE_COOKIE"),
    ("a.py", "reset_token = str(random.randint(0, 999999))", "WEAK_RANDOM_SECRET"),
    ("a.js", "console.log('login', user, password)", "LOG_SENSITIVE_DATA"),
    ("a.js", 'const t = jwt.sign(p, "s3cr3t-value")', "HARDCODED_JWT_SECRET"),
    # Malicious code / supply chain / IaC
    ("a.js", "eval(atob('ZG9jdW1lbnQ='))", "OBFUSCATED_CODE"),
    ("a.py", "exec(base64.b64decode(blob))", "OBFUSCATED_CODE"),
    ("a.js", "if (isAdmin \u202e) { }", "TROJAN_SOURCE_BIDI"),
    ("package.json", '{"scripts": {"postinstall": "node x.js"}}', "NPM_INSTALL_SCRIPT"),
    ("install.sh", "curl -fsSL https://get.example.sh | sudo bash", "PIPE_TO_SHELL"),
    ("Dockerfile", "FROM node:20\nRUN npm ci", "CONTAINER_RUNS_AS_ROOT"),
    ("Dockerfile", "FROM x\nADD https://x.example/a.tgz /a\nUSER app", "UNPINNED_REMOTE_ADD"),
    ("deploy.yaml", "    securityContext:\n      privileged: true", "K8S_PRIVILEGED"),
    ("setup.sh", "chmod -R 777 /srv/app", "WORLD_WRITABLE"),
])
def test_rule_fires(name, code, rule):
    assert rule in _scan(name, code)


IDOR_JS = """
app.get('/api/orders/:orderId', async (req, res) => {
  const order = await Order.findById(req.params.orderId);
  res.json(order);
});
"""
SAFE_JS = """
app.get('/api/orders/:orderId', requireAuth, async (req, res) => {
  const order = await Order.findOne({ _id: req.params.orderId, ownerId: req.user.id });
  res.json(order);
});
"""
IDOR_PY = """
@app.route("/invoices/<int:invoice_id>")
def show(invoice_id):
    inv = Invoice.query.get(invoice_id)
    return render_template("i.html", inv=inv)
"""
SAFE_PY = """
@app.route("/invoices/<int:invoice_id>")
@login_required
def show(invoice_id):
    inv = Invoice.query.get(invoice_id)
    if inv.owner_id != current_user.id:
        abort(403)
    return render_template("i.html", inv=inv)
"""
ADMIN_JS = "app.delete('/admin/users/:id', (r, s) => s.send(User.remove(r.params.id)));\n"


def test_route_idor_without_ownership_check():
    assert "IDOR_ROUTE_NO_OWNERSHIP_CHECK" in _scan("orders.js", IDOR_JS)
    assert "IDOR_ROUTE_NO_OWNERSHIP_CHECK" in _scan("views.py", IDOR_PY)


def test_route_with_ownership_check_is_not_flagged():
    assert "IDOR_ROUTE_NO_OWNERSHIP_CHECK" not in _scan("orders.js", SAFE_JS)
    assert "IDOR_ROUTE_NO_OWNERSHIP_CHECK" not in _scan("views.py", SAFE_PY)


def test_admin_route_without_auth():
    assert "ADMIN_ROUTE_NO_AUTH" in _scan("admin.js", ADMIN_JS)
    assert "ADMIN_ROUTE_NO_AUTH" not in _scan("admin.js", "app.delete('/admin/u/:id', requireAdmin, h);\n")


@pytest.mark.parametrize("name, code", [
    ("a.js", "res.send(escapeHtml(name));"),
    ("a.js", "el.textContent = req;"),
    ("a.py", "return render_template('x.html', n=request.args.get('n'))"),
    ("a.py", "r = requests.get('https://api.example.com/v1')"),
    ("a.js", "res.redirect('/home');"),
    ("a.py", "token = secrets.token_urlsafe(32)"),
    ("Dockerfile", "FROM node:20\nUSER node"),
    ("package.json", '{"scripts": {"test": "jest"}}'),
])
def test_safe_variants_are_quiet(name, code):
    assert _scan(name, code) == set()


def test_every_rule_has_a_recommendation():
    for rid, *_rest in codecheck.BACKEND_RULES:
        assert codecheck.RECOMMENDATIONS.get(rid), rid


def test_recommendations_group_by_rule_most_severe_first():
    findings = [{"title": "WEAK_HASH: x", "severity": "low", "recommendation": "a", "affected_url": "f1"},
                {"title": "PY_EVAL_EXEC: x", "severity": "high", "recommendation": "b", "affected_url": "f2"},
                {"title": "PY_EVAL_EXEC: x", "severity": "high", "recommendation": "b", "affected_url": "f3"}]
    recs = codecheck.build_recommendations(findings)
    assert [(r["rule"], r["count"]) for r in recs] == [("PY_EVAL_EXEC", 2), ("WEAK_HASH", 1)]


def test_hardcoded_signing_secret_is_masked():
    res = codecheck.Results()
    codecheck._scan_lines(res, 'SECRET_KEY = "dev-secret-123456"', source="sandbox_source",
                          where="source/s.py", ext=".py", js=False, backend=True, name="s.py")
    f = next(x for x in res.findings if x["title"].startswith("HARDCODED_JWT_SECRET"))
    assert "dev-secret-123456" not in f["evidence"] and "dev-" in f["evidence"]
