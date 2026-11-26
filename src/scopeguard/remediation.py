"""Structured remediation guidance per rule. Stdlib only.

Each entry: ``summary``, ordered ``steps``, before/after ``examples`` per language
(``js`` = JavaScript/TypeScript, ``py`` = Python, ``php``) and OWASP ``references``.
:func:`enrich` adds a ``remediation`` block to every per-rule recommendation
(``codecheck.build_recommendations``), choosing the example from the language of the
rule's example location. Rules without a dedicated entry get their one-line fix plus
the OWASP reference for their category.

These texts are ours (never derived from scanned or uploaded content).
"""
from __future__ import annotations

CS = "https://cheatsheetseries.owasp.org/cheatsheets/"
REF = {
    "idor": CS + "Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
    "authz": CS + "Authorization_Cheat_Sheet.html",
    "mass": CS + "Mass_Assignment_Cheat_Sheet.html",
    "xss": CS + "Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "domxss": CS + "DOM_based_XSS_Prevention_Cheat_Sheet.html",
    "csp": CS + "Content_Security_Policy_Cheat_Sheet.html",
    "sqli": CS + "SQL_Injection_Prevention_Cheat_Sheet.html",
    "params": CS + "Query_Parameterization_Cheat_Sheet.html",
    "cmd": CS + "OS_Command_Injection_Defense_Cheat_Sheet.html",
    "ssrf": CS + "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    "redirect": CS + "Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
    "csrf": CS + "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
    "input": CS + "Input_Validation_Cheat_Sheet.html",
    "secrets": CS + "Secrets_Management_Cheat_Sheet.html",
    "deser": CS + "Deserialization_Cheat_Sheet.html",
    "xxe": CS + "XML_External_Entity_Prevention_Cheat_Sheet.html",
    "node": CS + "Nodejs_Security_Cheat_Sheet.html",
    "docker": CS + "Docker_Security_Cheat_Sheet.html",
    "k8s": CS + "Kubernetes_Security_Cheat_Sheet.html",
    "session": CS + "Session_Management_Cheat_Sheet.html",
    "logging": CS + "Logging_Cheat_Sheet.html",
    "crypto": CS + "Cryptographic_Storage_Cheat_Sheet.html",
    "ssti": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection",
    "supply": CS + "Software_Supply_Chain_Security_Cheat_Sheet.html",
    "proto": CS + "Prototype_Pollution_Prevention_Cheat_Sheet.html",
    "html5": CS + "HTML5_Security_Cheat_Sheet.html",
    "dos": CS + "Denial_of_Service_Cheat_Sheet.html",
    "redos": "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
    "auth": CS + "Authentication_Cheat_Sheet.html",
}
CATEGORY_REF = {
    "A01:2021-Broken Access Control": REF["authz"], "A02:2021-Cryptographic Failures": REF["crypto"],
    "A03:2021-Injection": REF["input"], "A05:2021-Security Misconfiguration": REF["docker"],
    "A07:2021-Identification and Authentication Failures": REF["session"],
    "A08:2021-Software and Data Integrity Failures": REF["supply"],
    "A09:2021-Security Logging and Monitoring Failures": REF["logging"],
    "A10:2021-Server-Side Request Forgery": REF["ssrf"], "Cross-Site Scripting": REF["xss"],
    "A04:2021-Insecure Design": REF["dos"],
}
LANG_BY_EXT = {".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".vue": "js",
               ".svelte": "js", ".html": "js", ".htm": "js", ".ejs": "js", ".hbs": "js", ".py": "py",
               ".pyw": "py", ".jinja": "py", ".jinja2": "py", ".j2": "py", ".php": "php", ".phtml": "php",
               ".twig": "php"}

_IDOR_STEPS = [
    "Identify the owner of every object the route returns or changes (user, tenant, account).",
    ("Scope the database query to the caller instead of checking afterwards when you can: "
    "WHERE id = ? AND owner_id = <current user>."),
    "Otherwise load the object, then enforce an object-level permission check before using it.",
    "Return 404 (not 403) for objects the caller may not see, so ids cannot be enumerated.",
    "Prefer random, unguessable ids (UUIDv4) as defence in depth, never as the only control.",
    "Add a test that requests another user's object id and expects 404.",
]
_XSS_STEPS = [
    ("Keep untrusted data as data: render it through the framework's auto-escaping "
    "(template {{ }}, JSX children, textContent)."),
    "Encode for the exact context (HTML body, attribute, URL, JavaScript) when you must build output by hand.",
    ("If HTML from users is required, sanitize it with an allow-list sanitizer (DOMPurify, nh3/bleach) "
    "right before rendering."),
    ("Send a strict Content-Security-Policy (no 'unsafe-inline') and the right Content-Type as a second line "
    "of defence."),
    "Add a test that submits <script>alert(1)</script> and asserts it is rendered as text.",
]

REMEDIATIONS: dict[str, dict] = {
    # ------------------------------------------------------------------ IDOR / access control
    "IDOR_DIRECT_OBJECT_LOOKUP": {
        "summary": "An object is fetched with an id taken straight from the request and returned without "
                   "checking that it belongs to the caller (Insecure Direct Object Reference).",
        "steps": _IDOR_STEPS,
        "examples": {
            "js": {"before": "app.get('/api/orders/:id', auth, async (req, res) => {\n"
                             "  res.json(await Order.findById(req.params.id));\n});",
                   "after": "app.get('/api/orders/:id', auth, async (req, res) => {\n"
                            "  const order = await Order.findOne({ _id: req.params.id, ownerId: req.user.id });\n"
                            "  if (!order) return res.sendStatus(404);   // not yours = not found\n"
                            "  res.json(order);\n});"},
            "py": {"before": "@app.get('/invoices/<int:invoice_id>')\n@login_required\n"
                             "def invoice(invoice_id):\n    return jsonify(Invoice.query.get(invoice_id))",
                   "after": "@app.get('/invoices/<int:invoice_id>')\n@login_required\n"
                            "def invoice(invoice_id):\n"
                            "    inv = Invoice.query.filter_by(id=invoice_id, owner_id=current_user.id).first()\n"
                            "    if inv is None:\n        abort(404)  # not yours = not found\n"
                            "    return jsonify(inv)"},
            "php": {"before": "$stmt = $pdo->prepare('SELECT * FROM orders WHERE id = ?');\n"
                              "$stmt->execute([$_GET['id']]);",
                    "after": "$stmt = $pdo->prepare('SELECT * FROM orders WHERE id = ? AND owner_id = ?');\n"
                             "$stmt->execute([$_GET['id'], $_SESSION['user_id']]);\n"
                             "if (!$order = $stmt->fetch()) { http_response_code(404); exit; }"},
        },
        "references": [REF["idor"], REF["authz"]],
    },
    "IDOR_ROUTE_NO_OWNERSHIP_CHECK": {
        "summary": "A route takes an object id from its path and loads the object, but no ownership or "
                   "permission check is visible in the handler.",
        "steps": [("Confirm in code review whether a middleware or policy already enforces ownership; if so, "
                  "mark this finding as a false positive."), *_IDOR_STEPS],
        "examples": {
            "js": {"before": "router.put('/projects/:projectId', async (req, res) => {\n"
                             "  const p = await Project.findByPk(req.params.projectId);\n"
                             "  await p.update({ name: req.body.name });\n});",
                   "after": "router.put('/projects/:projectId', requireAuth, async (req, res) => {\n"
                            "  const p = await Project.findOne({ where: { id: req.params.projectId,\n"
                            "                                             tenantId: req.user.tenantId } });\n"
                            "  if (!p || !can(req.user, 'project:update', p)) return res.sendStatus(404);\n"
                            "  await p.update({ name: req.body.name });\n  res.sendStatus(204);\n});"},
            "py": {"before": "class DocumentView(APIView):\n    def get(self, request, pk):\n"
                             "        return Response(DocumentSerializer(Document.objects.get(pk=pk)).data)",
                   "after": "class DocumentView(APIView):\n    permission_classes = [IsAuthenticated]\n"
                            "    def get(self, request, pk):\n"
                            "        doc = get_object_or_404(Document, pk=pk, owner=request.user)\n"
                            "        return Response(DocumentSerializer(doc).data)"},
        },
        "references": [REF["idor"], REF["authz"]],
    },
    "ADMIN_ROUTE_NO_AUTH": {
        "summary": "An admin route has no visible authentication or role check.",
        "steps": ["Require authentication on every admin route (router-level middleware, not per handler).",
                  "Check a server-side role/permission (e.g. role === 'admin'); never trust a client flag.",
                  "Deny by default: mount admin routes under a router that applies the check to all of them.",
                  "Audit-log admin actions and add a test that a normal user gets 403/404."],
        "examples": {
            "js": {"before": "app.delete('/admin/users/:id', (req, res) => User.destroy(req.params.id));",
                   "after": "const admin = express.Router();\n"
                            "admin.use(requireAuth, requireRole('admin'));        // every /admin route\n"
                            "admin.delete('/users/:id', async (req, res) => {\n"
                            "  await User.destroy({ where: { id: req.params.id } });\n  res.sendStatus(204);\n});\n"
                            "app.use('/admin', admin);"},
            "py": {"before": "@app.route('/admin/users/<int:uid>', methods=['DELETE'])\n"
                             "def delete_user(uid): ...",
                   "after": "@app.route('/admin/users/<int:uid>', methods=['DELETE'])\n@login_required\n"
                            "@roles_required('admin')\ndef delete_user(uid): ..."},
        },
        "references": [REF["authz"]],
    },
    "MASS_ASSIGNMENT": {
        "summary": "The whole request body is bound to a model, so a user can set fields such as role, "
                   "owner or price.",
        "steps": [("Copy an explicit allow-list of fields (or validate with a DTO/schema) instead of the whole "
                  "body."), "Never accept server-owned fields (id, role, ownerId, balance) from the client.",
                  ("Use the framework feature: $fillable in Laravel, Pydantic/serializer fields in Python, "
                  "a validation schema (zod/joi) in Node.")],
        "examples": {
            "js": {"before": "await User.findByIdAndUpdate(req.user.id, req.body);",
                   "after": "const { name, email } = profileSchema.parse(req.body);   // zod: only these keys\n"
                            "await User.findByIdAndUpdate(req.user.id, { name, email });"},
            "py": {"before": "user = User(**request.json)",
                   "after": "class SignUp(BaseModel):\n    name: str\n    email: EmailStr\n\n"
                            "data = SignUp.model_validate(request.json)   # role/owner are not accepted\n"
                            "user = User(name=data.name, email=data.email)"},
        },
        "references": [REF["mass"]],
    },
    "OPEN_REDIRECT": {
        "summary": "A redirect target comes from the request, so the app can send users to a phishing site.",
        "steps": ["Redirect only to relative paths, or to an allow-list of known destinations.",
                  "Reject absolute and protocol-relative URLs (//evil.example) and backslash tricks.",
                  "Prefer an id that maps to a server-side URL over a raw URL parameter."],
        "examples": {
            "js": {"before": "res.redirect(req.query.next);",
                   "after": "const next = String(req.query.next || '/');\n"
                            "const safe = next.startsWith('/') && !next.startsWith('//') && !next.includes('\\\\');\n"
                            "res.redirect(safe ? next : '/');"},
            "py": {"before": "return redirect(request.args.get('next'))",
                   "after": "nxt = request.args.get('next', '/')\n"
                            "if not url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.host}):\n"
                            "    nxt = '/'\nreturn redirect(nxt)"},
        },
        "references": [REF["redirect"]],
    },
    "PATH_TRAVERSAL": {
        "summary": "A file path is built from request input, so ../ sequences can read or write any file.",
        "steps": ["Map user input to an allow-listed id or file name instead of a path.",
                  "Otherwise resolve the final path and verify it stays inside the base folder.",
                  "Reject absolute paths, NUL bytes and encoded separators before resolving."],
        "examples": {
            "js": {"before": "res.sendFile(path.join(__dirname, 'files', req.query.name));",
                   "after": "const base = path.resolve(__dirname, 'files');\n"
                            "const target = path.resolve(base, String(req.query.name));\n"
                            "if (!target.startsWith(base + path.sep)) return res.sendStatus(404);\n"
                            "res.sendFile(target);"},
            "py": {"before": "return send_file(os.path.join(BASE, request.args['name']))",
                   "after": "return send_from_directory(BASE, request.args['name'])  # rejects ../ escapes"},
        },
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal", REF["input"]],
    },
    "CSRF_PROTECTION_DISABLED": {
        "summary": "CSRF protection is switched off for a route or the whole app.",
        "steps": ["Keep CSRF tokens on for every state-changing route that uses cookie authentication.",
                  ("Remove csrf_exempt / csrf: false unless the route uses a non-cookie token (Authorization "
                  "header)."), "Set SameSite=Lax or Strict on session cookies as defence in depth."],
        "examples": {
            "py": {"before": "@csrf_exempt\ndef transfer(request): ...",
                   "after": "def transfer(request): ...   # CsrfViewMiddleware checks the token\n"
                            "# template: <form method=\"post\">{% csrf_token %} ...</form>"},
            "js": {"before": "app.use(csurf({ ignoreMethods: ['GET', 'POST'] }));",
                   "after": "app.use(doubleCsrfProtection);   // csrf-csrf; send the token in a header"},
        },
        "references": [REF["csrf"]],
    },
    # ------------------------------------------------------------------ XSS
    "XSS_REFLECTED_RESPONSE": {
        "summary": "Request input is written straight into the HTTP response (reflected XSS).",
        "steps": _XSS_STEPS,
        "examples": {
            "js": {"before": "app.get('/search', (req, res) => res.send('<h1>' + req.query.q + '</h1>'));",
                   "after": "app.get('/search', (req, res) => res.render('search', { q: req.query.q }));\n"
                            "// search.ejs: <h1><%= q %></h1>   (<%= escapes, <%- does not)"},
            "py": {"before": "return '<h1>' + request.args['q'] + '</h1>'",
                   "after": "return render_template('search.html', q=request.args.get('q', ''))\n"
                            "# search.html: <h1>{{ q }}</h1>   (Jinja2 autoescape)"},
            "php": {"before": "echo '<h1>' . $_GET['q'] . '</h1>';",
                    "after": "echo '<h1>' . htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES | ENT_HTML5, 'UTF-8') . "
                             "'</h1>';"},
        },
        "references": [REF["xss"], REF["csp"]],
    },
    "XSS_FSTRING_RESPONSE": {
        "summary": "HTML is built with an f-string from request data (reflected XSS).",
        "steps": _XSS_STEPS,
        "examples": {"py": {"before": "return f\"<p>Hello {request.args.get('n')}</p>\"",
                            "after": "from markupsafe import escape\n"
                                     "return f\"<p>Hello {escape(request.args.get('n', ''))}</p>\""}},
        "references": [REF["xss"]],
    },
    "XSS_MARK_SAFE": {
        "summary": "mark_safe()/Markup() turns off escaping for a dynamic value.",
        "steps": ["Only mark constant, developer-written HTML as safe.",
                  "For user HTML, sanitize with an allow-list (nh3/bleach) before marking it safe.",
                  "Prefer format_html() (Django) / Markup.format() which escape the arguments."],
        "examples": {"py": {"before": "return mark_safe(f'<b>{user.bio}</b>')",
                            "after": "return format_html('<b>{}</b>', user.bio)     # escapes user.bio\n"
                                     "# rich text: mark_safe(nh3.clean(user.bio_html))"}},
        "references": [REF["xss"]],
    },
    "XSS_TEMPLATE_UNESCAPED": {
        "summary": "A template prints a value without HTML escaping.",
        "steps": ["Use the escaped form: {{ }} (Jinja/Twig/Handlebars/Blade), <%= %> (EJS).",
                  "Keep |safe, {{{ }}}, {!! !!} and <%- for HTML your code produced, never for user data.",
                  "Sanitize rich text with DOMPurify / nh3 before it reaches the template."],
        "examples": {
            "py": {"before": "<div>{{ comment | safe }}</div>", "after": "<div>{{ comment }}</div>"},
            "js": {"before": "<div><%- user.bio %></div>   <!-- EJS --> / <div>{{{ bio }}}</div>",
                   "after": "<div><%= user.bio %></div>   <!-- EJS --> / <div>{{ bio }}</div>"},
            "php": {"before": "<div>{!! $comment !!}</div>", "after": "<div>{{ $comment }}</div>"},
        },
        "references": [REF["xss"]],
    },
    "XSS_AUTOESCAPE_OFF": {
        "summary": "The template engine is configured without auto-escaping.",
        "steps": ["Turn auto-escaping on globally; opt out only for trusted constants."],
        "examples": {"py": {"before": "env = Environment(loader=loader, autoescape=False)",
                            "after": "env = Environment(loader=loader, autoescape=select_autoescape(['html', 'xml']))"},
                     "js": {"before": "Handlebars.compile(src, { noEscape: true })",
                            "after": "Handlebars.compile(src)   // escaping on by default"}},
        "references": [REF["xss"]],
    },
    "XSS_REACT_DANGEROUS_HTML": {
        "summary": "dangerouslySetInnerHTML renders raw HTML (DOM XSS if the value is user controlled).",
        "steps": ["Render text as JSX children; React escapes it.",
                  "If HTML is required, sanitize with DOMPurify right before rendering.",
                  "Keep a strict CSP and consider Trusted Types."],
        "examples": {"js": {"before": "<div dangerouslySetInnerHTML={{ __html: post.body }} />",
                            "after": "<div>{post.body}</div>\n// HTML needed:\n"
                                     "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.body) }} />"}},
        "references": [REF["domxss"], REF["xss"]],
    },
    "XSS_VUE_SVELTE_RAW_HTML": {
        "summary": "v-html / {@html} renders raw HTML.",
        "steps": ["Bind text with {{ }} (Vue) or {value} (Svelte).",
                  "If HTML is required, sanitize with DOMPurify first."],
        "examples": {"js": {"before": "<div v-html=\"comment.body\"></div>",
                            "after": "<div>{{ comment.body }}</div>\n"
                                     "<!-- HTML needed: <div v-html=\"DOMPurify.sanitize(comment.body)\"></div> -->"}},
        "references": [REF["domxss"]],
    },
    "XSS_ANGULAR_BYPASS": {
        "summary": "Angular's sanitizer is bypassed with bypassSecurityTrust*.",
        "steps": ["Remove bypassSecurityTrust* and let Angular sanitize [innerHTML] bindings.",
                  "If you must trust a value, sanitize it first (DOMPurify) and keep the bypass to constants."],
        "examples": {"js": {"before": "this.html = this.sanitizer.bypassSecurityTrustHtml(userHtml);",
                            "after": "this.html = userHtml;   // [innerHTML]=\"html\" is sanitized by Angular"}},
        "references": [REF["domxss"]],
    },
    "XSS_JQUERY_HTML": {
        "summary": "jQuery inserts a dynamic value as HTML.",
        "steps": ["Use .text() for text, or build elements and set their text.",
                  "Sanitize with DOMPurify if HTML is required."],
        "examples": {"js": {"before": "$('#msg').html(data.message);",
                            "after": "$('#msg').text(data.message);"}},
        "references": [REF["domxss"]],
    },
    "JS_INNERHTML": {
        "summary": "innerHTML/outerHTML assignment parses its value as HTML (DOM XSS).",
        "steps": ["Use textContent for text; createElement + textContent for structure.",
                  "Sanitize with DOMPurify if HTML is required; enable Trusted Types with a strict CSP."],
        "examples": {"js": {"before": "el.innerHTML = location.hash.slice(1);",
                            "after": "el.textContent = decodeURIComponent(location.hash.slice(1));"}},
        "references": [REF["domxss"]],
    },
    "JS_DOCUMENT_WRITE": {
        "summary": "document.write() injects HTML into the page.",
        "steps": ["Replace document.write with DOM APIs (createElement, textContent, append)."],
        "examples": {"js": {"before": "document.write('<p>' + name + '</p>');",
                            "after": "const p = document.createElement('p');\np.textContent = name;\n"
                                     "document.body.append(p);"}},
        "references": [REF["domxss"]],
    },
    "JS_INSERT_ADJACENT_HTML": {
        "summary": "insertAdjacentHTML() parses its input as HTML.",
        "steps": ["Use insertAdjacentText or build nodes with createElement + textContent.",
                  "Sanitize with DOMPurify if HTML is required."],
        "examples": {"js": {"before": "list.insertAdjacentHTML('beforeend', `<li>${item}</li>`);",
                            "after": "const li = document.createElement('li');\nli.textContent = item;\n"
                                     "list.append(li);"}},
        "references": [REF["domxss"]],
    },
    "SSTI_TEMPLATE_FROM_INPUT": {
        "summary": "A template is compiled from request data (server-side template injection, often RCE).",
        "steps": ["Keep templates as static files; pass user data only as variables.",
                  ("If users must customise text, use a logic-less format (str.format with fixed keys) "
                  "or a sandboxed engine.")],
        "examples": {"py": {"before": "return render_template_string(request.args['tpl'])",
                            "after": "return render_template('greeting.html', name=request.args.get('name', ''))"},
                     "js": {"before": "res.send(ejs.render(req.body.template, data));",
                            "after": "res.render('greeting', { name: req.body.name });"}},
        "references": [REF["ssti"]],
    },
    # ------------------------------------------------------------------ injection / SSRF
    "SQL_STRING_BUILD": {
        "summary": "SQL is built from strings, so input can change the query (SQL injection).",
        "steps": ["Use parameterised queries / prepared statements for every value.",
                  "Allow-list identifiers (column names, sort order) that cannot be parameters.",
                  "Run the app with a least-privilege database user."],
        "examples": {"py": {"before": "cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
                            "after": "cur.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"},
                     "js": {"before": "db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
                            "after": "db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);"},
                     "php": {"before": "$pdo->query(\"SELECT * FROM users WHERE id = \" . $_GET['id']);",
                             "after": "$s = $pdo->prepare('SELECT * FROM users WHERE id = ?');\n"
                                      "$s->execute([$_GET['id']]);"}},
        "references": [REF["sqli"], REF["params"]],
    },
    "NOSQL_INJECTION": {
        "summary": "A query object comes from the request, so operators like $ne/$where can be injected.",
        "steps": ["Build filters from validated scalar fields only.",
                  "Reject keys starting with '$' or containing '.' (express-mongo-sanitize).",
                  "Cast types explicitly (String(), Number())."],
        "examples": {"js": {"before": "User.findOne(req.body);   // {\"password\": {\"$ne\": null}}",
                            "after": "User.findOne({ email: String(req.body.email) });"}},
        "references": [REF["input"], REF["node"]],
    },
    "COMMAND_INJECTION_INPUT": {
        "summary": "A shell command is built from request input (command injection).",
        "steps": ["Avoid the shell: call the program with a fixed argument list.",
                  "Validate input against an allow-list; never concatenate it into a command string."],
        "examples": {"py": {"before": "os.system('ping -c 1 ' + request.args['host'])",
                            "after": "subprocess.run(['ping', '-c', '1', host], check=True)   # host validated"},
                     "js": {"before": "exec('ping -c 1 ' + req.query.host);",
                            "after": "execFile('ping', ['-c', '1', host]);   // host validated"}},
        "references": [REF["cmd"]],
    },
    "SSRF_REQUEST_URL": {
        "summary": "The server requests a URL taken from the request (SSRF: internal services, cloud metadata).",
        "steps": ["Allow-list destination hosts and schemes.",
                  ("Resolve the host and refuse private, loopback, link-local and metadata addresses; "
                  "connect to the checked IP (no DNS rebinding)."),
                  "Disable redirects, set short timeouts, and run fetchers in an egress-restricted network."],
        "examples": {"py": {"before": "r = requests.get(request.args['url'])",
                            "after": "url = request.args['url']\n"
                                     "if urlparse(url).hostname not in ALLOWED_HOSTS:\n    abort(400)\n"
                                     "r = requests.get(url, allow_redirects=False, timeout=5)"},
                     "js": {"before": "const r = await axios.get(req.query.url);",
                            "after": "const u = new URL(String(req.query.url));\n"
                                     "if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname)) "
                                     "return res.sendStatus(400);\n"
                                     "const r = await axios.get(u.href, { maxRedirects: 0, timeout: 5000 });"}},
        "references": [REF["ssrf"]],
    },
}
REMEDIATIONS["SQL_CONCAT_REQUEST"] = REMEDIATIONS["SQL_STRING_BUILD"]
REMEDIATIONS["NODE_SQL_TEMPLATE"] = REMEDIATIONS["SQL_STRING_BUILD"]
REMEDIATIONS["PY_SHELL_TRUE"] = REMEDIATIONS["COMMAND_INJECTION_INPUT"]
REMEDIATIONS["PY_OS_SYSTEM"] = REMEDIATIONS["COMMAND_INJECTION_INPUT"]
REMEDIATIONS["NODE_CHILD_PROCESS"] = REMEDIATIONS["COMMAND_INJECTION_INPUT"]


# ---------------------------------------------------------------------- DOM-based attacks
REMEDIATIONS.update({
    "DOM_XSS_SOURCE_TO_SINK": {
        "summary": "A value the attacker controls in the browser (URL fragment/query, referrer, window.name, "
                   "postMessage data) flows into an HTML or code sink: DOM-based XSS that never touches the server.",
        "steps": [("Find every source to sink path: location.hash/search, document.referrer, event.data into "
                  "innerHTML, document.write, insertAdjacentHTML, eval, jQuery .html()."),
                  "Write text with textContent / innerText, or build nodes with createElement.",
                  "If HTML is required, sanitize with DOMPurify right before the sink.",
                  ("Enable Trusted Types (require-trusted-types-for 'script') with a strict CSP so unsafe sinks "
                  "throw.")],
        "examples": {"js": {"before": "const name = decodeURIComponent(location.hash.slice(1));\n"
                                      "greeting.innerHTML = 'Hello ' + name;",
                            "after": "const name = decodeURIComponent(location.hash.slice(1));\n"
                                     "greeting.textContent = 'Hello ' + name;"}},
        "references": [REF["domxss"], REF["csp"]],
    },
    "DOM_OPEN_REDIRECT": {
        "summary": "The page navigates to a URL taken from the location, referrer or a message (DOM open redirect, "
                   "and javascript: execution in older browsers).",
        "steps": ["Parse the value with new URL(value, location.origin).",
                  "Allow only same-origin (or allow-listed) http(s) targets; otherwise fall back to a default page."],
        "examples": {"js": {"before": "location.href = new URLSearchParams(location.search).get('next');",
                            "after": "const next = new URL(new URLSearchParams(location.search).get('next') || '/',\n"
                                     "                     location.origin);\n"
                                     "location.href = next.origin === location.origin ? next.pathname + next.search : '/';"}},
        "references": [REF["redirect"], REF["domxss"]],
    },
    "DOM_JS_URL_INJECTION": {
        "summary": "A link/src/action attribute is set from a DOM source, so a javascript: URL can run code.",
        "steps": ["Parse with new URL() and allow only the https: (and http:) protocol.",
                  "Set the attribute only after the check; prefer fixed URLs with encoded parameters."],
        "examples": {"js": {"before": "link.href = location.hash.slice(1);",
                            "after": "const u = new URL(location.hash.slice(1), location.origin);\n"
                                     "if (u.protocol === 'https:' || u.protocol === 'http:') link.href = u.href;"}},
        "references": [REF["domxss"]],
    },
    "POSTMESSAGE_NO_ORIGIN_CHECK": {
        "summary": "A message listener uses event.data without checking event.origin, so any page that can "
                   "frame or open yours can drive it.",
        "steps": ["Compare event.origin with an exact allow-list (no substring or endsWith checks).",
                  "Validate the shape of event.data before using it; never pass it to HTML or code sinks.",
                  "When sending, always pass the exact target origin (never '*')."],
        "examples": {"js": {"before": "window.addEventListener('message', (e) => {\n  run(e.data.cmd);\n});",
                            "after": "const TRUSTED = new Set(['https://app.example.com']);\n"
                                     "window.addEventListener('message', (e) => {\n"
                                     "  if (!TRUSTED.has(e.origin)) return;\n"
                                     "  if (typeof e.data?.cmd !== 'string') return;\n  run(e.data.cmd);\n});"}},
        "references": [REF["html5"]],
    },
    "PROTOTYPE_POLLUTION": {
        "summary": "Untrusted objects are deep-merged or assigned, so a __proto__ key can change every object's "
                   "prototype (auth bypass, DoS, sometimes RCE).",
        "steps": ["Validate the input against a schema (zod/joi/ajv with additionalProperties: false) first.",
                  "Reject __proto__, constructor and prototype keys in custom merge/set helpers.",
                  "Merge into Object.create(null) or use a Map for dictionaries; keep lodash >= 4.17.21.",
                  "Consider Object.freeze(Object.prototype) at startup (node --disable-proto=delete)."],
        "examples": {"js": {"before": "_.merge(config, JSON.parse(body));",
                            "after": "const input = settingsSchema.parse(JSON.parse(body));   // known keys only\n"
                                     "Object.assign(config, input);"}},
        "references": [REF["proto"]],
    },
    "STRING_TIMER_EVAL": {
        "summary": "setTimeout/setInterval with a string compiles that string as code (like eval).",
        "steps": ["Pass a function instead of a string.", "Keep a CSP without 'unsafe-eval' so string timers fail."],
        "examples": {"js": {"before": "setTimeout('render(' + id + ')', 10);",
                            "after": "setTimeout(() => render(id), 10);"}},
        "references": [REF["domxss"]],
    },

    # ---------------------------------------------------------------------- DoS / resource exhaustion
    "REDOS_NESTED_QUANTIFIER": {
        "summary": "A regular expression with nested quantifiers can take exponential time on crafted input "
                   "(ReDoS): one request can pin a CPU core.",
        "steps": ["Remove the nested quantifier: (a+)+ becomes a+, (\\w+\\s?)* becomes [\\w\\s]*.",
                  "Cap the input length before matching.",
                  "For user-facing patterns use a linear-time engine (Python: re2 / google-re2, Node: re2).",
                  "Test the pattern with a ReDoS checker (e.g. recheck, safe-regex) in CI."],
        "examples": {"py": {"before": "EMAIL = re.compile(r'^([a-zA-Z0-9]+)*@example\\.com$')",
                            "after": "EMAIL = re.compile(r'^[a-zA-Z0-9]+@example\\.com$')\n"
                                     "if len(value) > 254 or not EMAIL.fullmatch(value): reject()"},
                     "js": {"before": "const re = /^(\\w+\\s?)*$/;",
                            "after": "const re = /^[\\w\\s]*$/;   // + cap length: if (s.length > 200) reject()"}},
        "references": [REF["redos"], REF["dos"]],
    },
    "REGEX_FROM_INPUT": {
        "summary": "A regular expression is compiled from user input: attackers can submit a catastrophic "
                   "pattern (ReDoS) or change what matches.",
        "steps": ["Escape user text before putting it in a pattern (re.escape / lodash escapeRegExp).",
                  "For search, use plain substring matching or a full-text index instead of user regexes.",
                  "If users really need regexes, use RE2 with a length cap and a timeout."],
        "examples": {"js": {"before": "const r = new RegExp(req.query.q, 'i');",
                            "after": "const r = new RegExp(_.escapeRegExp(String(req.query.q).slice(0, 100)), 'i');"},
                     "py": {"before": "pattern = re.compile(request.args['q'])",
                            "after": "pattern = re.compile(re.escape(request.args['q'][:100]), re.I)"}},
        "references": [REF["redos"]],
    },
    "LARGE_BODY_LIMIT": {
        "summary": "Request bodies or uploads may be very large or unlimited, so a few requests can exhaust "
                   "memory or disk.",
        "steps": ["Set a small default body limit (e.g. 100 kB for JSON) and raise it only on routes that need it.",
                  "Stream file uploads to disk/object storage with a per-file size cap instead of buffering.",
                  "Enforce the same limit at the reverse proxy (nginx client_max_body_size, ingress annotations)."],
        "examples": {"js": {"before": "app.use(express.json({ limit: '500mb' }));",
                            "after": "app.use(express.json({ limit: '100kb' }));\n"
                                     "app.post('/upload', multer({ limits: { fileSize: 10 * 1024 * 1024 } })"
                                     ".single('file'), handler);"},
                     "py": {"before": "DATA_UPLOAD_MAX_MEMORY_SIZE = None",
                            "after": "DATA_UPLOAD_MAX_MEMORY_SIZE = 2_621_440   # 2.5 MB (Django default)\n"
                                     "# Flask: app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024"}},
        "references": [REF["dos"]],
    },
    "HTTP_CALL_NO_TIMEOUT": {
        "summary": "An outbound HTTP call has no timeout: a slow or hanging upstream keeps workers busy until "
                   "the service stops answering.",
        "steps": ["Pass an explicit (connect, read) timeout on every call, or use a Session with defaults.",
                  "Add retries with backoff and a circuit breaker for critical dependencies."],
        "examples": {"py": {"before": "r = requests.get(url)",
                            "after": "r = requests.get(url, timeout=(3, 10))"}},
        "references": [REF["dos"]],
    },
    "LOOP_SIZE_FROM_INPUT": {
        "summary": "A loop count or allocation size comes from the request, so one request can burn CPU or "
                   "allocate gigabytes.",
        "steps": ["Parse the number, reject non-integers, and clamp it to a hard maximum.",
                  "Paginate: return at most N items per request and a cursor for the rest."],
        "examples": {"py": {"before": "for i in range(int(request.args['n'])):",
                            "after": "n = min(max(int(request.args.get('n', 10)), 0), 100)\nfor i in range(n):"},
                     "js": {"before": "const buf = new Array(Number(req.query.size));",
                            "after": "const size = Math.min(Math.max(parseInt(req.query.size, 10) || 0, 0), 1000);\n"
                                     "const buf = new Array(size);"}},
        "references": [REF["dos"], REF["input"]],
    },
    "XML_ENTITY_EXPANSION": {
        "summary": "The stdlib XML parsers expand entities, so a tiny 'billion laughs' document can use "
                   "gigabytes of memory.",
        "steps": ["Parse untrusted XML with defusedxml.", "Cap the request size before parsing."],
        "examples": {"py": {"before": "import xml.etree.ElementTree as ET\nroot = ET.fromstring(request.data)",
                            "after": "import defusedxml.ElementTree as ET\nroot = ET.fromstring(request.data)"}},
        "references": [REF["xxe"], REF["dos"]],
    },
    "LOGIN_ROUTE_NO_RATE_LIMIT": {
        "summary": "A login, password-reset or OTP route has no visible rate limit: credential stuffing, OTP "
                   "brute force and request floods are not slowed down.",
        "steps": ["Limit per IP and per account (e.g. 5 attempts / minute), with exponential backoff or lockout.",
                  "Return the same response and timing for unknown users and wrong passwords.",
                  "Add CAPTCHA or step-up checks after repeated failures; alert on spikes."],
        "examples": {"js": {"before": "app.post('/api/login', loginHandler);",
                            "after": "const loginLimiter = rateLimit({ windowMs: 60_000, limit: 5,\n"
                                     "  standardHeaders: true, keyGenerator: (req) => req.ip + ':' + req.body.email });\n"
                                     "app.post('/api/login', loginLimiter, loginHandler);"},
                     "py": {"before": "@app.post('/login')\ndef login(): ...",
                            "after": "limiter = Limiter(get_remote_address, app=app)\n\n"
                                     "@app.post('/login')\n@limiter.limit('5 per minute')\ndef login(): ..."}},
        "references": [REF["auth"], REF["dos"]],
    },
})
DOM_RULES = frozenset({"DOM_XSS_SOURCE_TO_SINK", "DOM_OPEN_REDIRECT", "DOM_JS_URL_INJECTION",
                       "POSTMESSAGE_NO_ORIGIN_CHECK", "PROTOTYPE_POLLUTION", "STRING_TIMER_EVAL",
                       "JS_INNERHTML", "JS_DOCUMENT_WRITE", "JS_INSERT_ADJACENT_HTML", "JS_POSTMESSAGE_WILDCARD"})
DOS_RULES = frozenset({"REDOS_NESTED_QUANTIFIER", "REGEX_FROM_INPUT", "LARGE_BODY_LIMIT", "HTTP_CALL_NO_TIMEOUT",
                       "LOOP_SIZE_FROM_INPUT", "XML_ENTITY_EXPANSION", "LOGIN_ROUTE_NO_RATE_LIMIT", "ZIP_BOMB"})
IDOR_RULES = frozenset({"IDOR_DIRECT_OBJECT_LOOKUP", "IDOR_ROUTE_NO_OWNERSHIP_CHECK", "ADMIN_ROUTE_NO_AUTH",
                        "MASS_ASSIGNMENT", "OPEN_REDIRECT", "PATH_TRAVERSAL", "CSRF_PROTECTION_DISABLED"})
XSS_RULES = frozenset(r for r in REMEDIATIONS if r.startswith(("XSS_", "JS_INNERHTML", "JS_DOCUMENT_WRITE",
                                                                "JS_INSERT_ADJACENT")))


def language_of(location: str | None) -> str | None:
    path = str(location or "").split("#", 1)[0].lower()
    dot = path.rfind(".")
    return LANG_BY_EXT.get(path[dot:]) if dot >= 0 else None


def for_rule(rule: str, *, location: str | None = None, recommendation: str = "",
             category: str | None = None) -> dict:
    """The remediation block for one rule; the example matches the file's language when one exists."""
    if rule.startswith("STYLE_"):
        return _style_remediation(rule, recommendation)
    entry = REMEDIATIONS.get(rule)
    if entry is None:
        ref = CATEGORY_REF.get(category or "")
        return {"summary": recommendation, "steps": [recommendation] if recommendation else [],
                "example": None, "references": [ref] if ref else [], "group": None}
    examples = entry.get("examples") or {}
    lang = language_of(location)
    chosen = lang if lang in examples else next(iter(examples), None)
    example = {"language": chosen, **examples[chosen]} if chosen else None
    group = ("IDOR / access control" if rule in IDOR_RULES else "DOM" if rule in DOM_RULES
             else "XSS" if rule in XSS_RULES else "DoS / resource exhaustion" if rule in DOS_RULES else None)
    return {"summary": entry["summary"], "steps": list(entry["steps"]), "example": example,
            "references": list(entry["references"]), "group": group}


def _style_remediation(rule: str, recommendation: str) -> dict:
    """Coding standard (PEP 8): the rule's advice, a Python before/after where one helps, PEP 8 link."""
    from scopeguard import codestyle

    advice = codestyle.RECOMMENDATIONS.get(rule) or recommendation
    before_after = codestyle.EXAMPLES.get(rule)
    example = {"language": "py", "before": before_after[0], "after": before_after[1]} if before_after else None
    steps = [advice, ("Run a formatter / linter (e.g. ruff check --select E,W,N,F or black) in CI so the "
                     "standard is kept automatically.")]
    return {"summary": advice, "steps": steps, "example": example, "references": [codestyle.PEP8_URL],
            "group": "Coding standard (PEP 8)"}


def enrich(recommendations: list[dict]) -> list[dict]:
    """Add a ``remediation`` block to every per-rule recommendation."""
    out = []
    for rec in recommendations or []:
        out.append({**rec, "remediation": for_rule(str(rec.get("rule") or ""), location=rec.get("example"),
                                                   recommendation=str(rec.get("recommendation") or ""),
                                                   category=rec.get("category"))})
    return out
