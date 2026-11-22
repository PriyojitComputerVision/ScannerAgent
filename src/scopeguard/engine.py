"""Pure-Python DAST + passive analysis + JS SAST engine (stdlib only).

Safety properties
-----------------
* Every request goes through ScopedClient: host allowlist, GET/HEAD/OPTIONS/TRACE
  only, no automatic redirects (each hop is re-checked), request budget,
  response size cap, per-request timeout.
* Active checks are non-destructive: GET requests with harmless markers.
* Anything found in page content that is out of scope is recorded, never fetched.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse as up
import urllib.request
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser

from scopeguard import ratelimit

# --------------------------------------------------------------------------
# Constants (category strings match pentest_agent.schemas.OwaspCategory values)
# --------------------------------------------------------------------------
A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A05 = "A05:2021-Security Misconfiguration"
A07 = "A07:2021-Identification and Authentication Failures"
XSS = "Cross-Site Scripting"
OTHER = "Other"

ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
USER_AGENT = "ScopeGuard-Agent/1.0 (authorized security assessment)"
STATIC_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".mp3", ".webp")
TEST_ORIGIN = "https://scopeguard.invalid"

SQL_ERRORS = [
    "you have an error in your sql syntax", "sqlstate[", "unclosed quotation mark",
    "pg_query()", "sqlite3.operationalerror", "sqlite error", "syntax error at or near",
    "mysql_fetch", "ora-00933", "ora-01756", "odbc sql server driver",
    "quoted string not properly terminated",
]
INFO_LEAKS = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python stack trace"),
    (re.compile(r"at [\w.$]+\([\w]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"System\.Web\.HttpException|Microsoft\.NET Framework Version"), ".NET error page"),
    (re.compile(r"Fatal error: .* in /.* on line \d+"), "PHP fatal error"),
    (re.compile(r"phpinfo\(\)"), "phpinfo() output"),
]
REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_url", "return", "returnurl",
                   "return_to", "continue", "dest", "destination", "goto", "target"}
FILE_PARAMS = {"file", "path", "page", "template", "doc", "document", "include",
               "name", "filename", "folder", "dir", "download"}

SENSITIVE_PATHS = [
    # path, signature regex (applied to body), severity, title, cwe
    ("/.git/HEAD", r"^ref:\s*refs/", "high", "Exposed .git repository metadata", "CWE-538"),
    ("/.env", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "high", "Exposed environment file (.env)", "CWE-538"),
    ("/server-status", r"Apache Server Status", "medium", "Apache server-status exposed", "CWE-200"),
    ("/phpinfo.php", r"phpinfo\(\)|PHP Version", "medium", "phpinfo() page exposed", "CWE-200"),
    ("/config.json", r'"(?:password|secret|api_?key)"', "high", "Exposed configuration file", "CWE-538"),
    ("/backup.sql", r"(?i)CREATE TABLE|INSERT INTO", "high", "Exposed database backup", "CWE-530"),
    ("/.DS_Store", r"Bud1", "low", "Exposed .DS_Store file", "CWE-538"),
]

JS_RULES = [
    ("JS_EVAL", re.compile(r"\beval\s*\("), "high", A03, "eval() executes dynamic code.", "CWE-95"),
    ("JS_FUNCTION_CONSTRUCTOR", re.compile(r"\bnew\s+Function\s*\("), "high", A03,
     "Function constructor creates executable code at runtime.", "CWE-95"),
    ("JS_INNERHTML", re.compile(r"\.(?:inner|outer)HTML\s*="), "medium", XSS,
     "innerHTML/outerHTML assignment can cause DOM XSS with untrusted data.", "CWE-79"),
    ("JS_DOCUMENT_WRITE", re.compile(r"\bdocument\.write(?:ln)?\s*\("), "medium", XSS,
     "document.write() can create HTML injection.", "CWE-79"),
    ("JS_POSTMESSAGE_WILDCARD", re.compile(r"""\.postMessage\s*\([^;\n]*,\s*['"]\*['"]"""),
     "medium", A01, "postMessage with wildcard target origin.", "CWE-346"),
    ("JS_WEAK_RANDOM", re.compile(r"\bMath\.random\s*\("), "low", A02,
     "Math.random() is not cryptographically secure.", "CWE-338"),
    ("JS_STORAGE_TOKEN", re.compile(
        r"""(?i)(?:localStorage|sessionStorage)\s*\.\s*setItem\s*\(\s*['"][^'"]*(?:token|jwt|auth)[^'"]*['"]"""),
     "medium", A07, "Auth token kept in JS-accessible browser storage.", "CWE-922"),
    ("JS_HTTP_URL", re.compile(r"""['"]http://(?!(?:www\.)?w3\.org/|xmlns\.com/|purl\.org/|schemas\.(?:xmlsoap|openxmlformats|microsoft)\.(?:org|com)/)[^'"\s]+['"]"""), "low", A05,
     "Hardcoded plaintext HTTP URL.", "CWE-319"),
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high", A02,
     "Possible AWS access key id in client-side code.", "CWE-798"),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "critical", A02,
     "Private key material in client-side code.", "CWE-321"),
    ("HARDCODED_SECRET", re.compile(
        r"""(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|secret[_-]?key)\b\s*[:=]\s*['"][A-Za-z0-9_./+=-]{12,}['"]"""),
     "high", A02, "Possible hardcoded secret/token.", "CWE-798"),
]

# Rule-specific remediation (falls back to a generic review note).
JS_RECOMMENDATIONS = {
    "JS_EVAL": "Remove eval(); parse data with JSON.parse and call functions directly.",
    "JS_FUNCTION_CONSTRUCTOR": "Avoid new Function(); use static functions or a lookup table.",
    "JS_INNERHTML": "Use textContent/innerText for text, or sanitize HTML (e.g. DOMPurify) before "
                    "assigning innerHTML; keep a strict Content-Security-Policy.",
    "JS_DOCUMENT_WRITE": "Replace document.write with DOM APIs (createElement/textContent).",
    "JS_POSTMESSAGE_WILDCARD": "Pass the exact target origin to postMessage instead of '*', and verify "
                               "event.origin in message listeners.",
    "JS_WEAK_RANDOM": "Use crypto.getRandomValues()/crypto.randomUUID() for anything security-relevant.",
    "JS_STORAGE_TOKEN": "Keep session tokens in HttpOnly, Secure, SameSite cookies rather than "
                        "localStorage/sessionStorage.",
    "JS_HTTP_URL": "Load resources and call APIs over HTTPS only.",
    "AWS_ACCESS_KEY": "Revoke and rotate the key now, remove it from client code, and sign requests server-side.",
    "PRIVATE_KEY": "Revoke the key pair, remove it from client code and history, and keep keys server-side.",
    "HARDCODED_SECRET": "Rotate the secret, remove it from client code, and proxy the call through your backend.",
}

PROFILES = {
    "quick":      dict(max_pages=15, active=False, max_targets=0,   variants=False, max_requests=150),
    "standard":   dict(max_pages=40, active=True,  max_targets=40,  variants=False, max_requests=500),
    "aggressive": dict(max_pages=80, active=True,  max_targets=120, variants=True,  max_requests=1500),
    "auth_deep":  dict(max_pages=80, active=True,  max_targets=120, variants=True,  max_requests=1500),
}


# --------------------------------------------------------------------------
# Scoped HTTP client
# --------------------------------------------------------------------------
class ScopeViolation(Exception):
    pass


class BudgetExceeded(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never auto-follow
        return None


@dataclass
class Response:
    url: str
    status: int = 0
    headers: dict = field(default_factory=dict)
    set_cookies: list = field(default_factory=list)
    body: str = ""
    error: str | None = None

    @property
    def ctype(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.ctype


class ScopedClient:
    def __init__(self, allowed_domains, *, max_requests=500, timeout=8.0,
                 max_bytes=1_000_000, delay=0.05, bearer=None,
                 max_retries=ratelimit.DEFAULT_MAX_RETRIES, max_wait=ratelimit.DEFAULT_MAX_WAIT,
                 sleep=time.sleep):
        self.allowed = {d.strip().lower() for d in allowed_domains if d and d.strip()}
        self.max_requests = max_requests
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.delay = delay
        self.bearer = bearer
        self.count = 0
        self.max_retries = max_retries
        self.max_wait = max_wait
        self._sleep = sleep
        self.rate_limit = ratelimit.RateLimitStats()
        self.log: list[tuple[str, str, int]] = []
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)

    def in_scope(self, url: str) -> bool:
        try:
            p = up.urlparse(url)
            host = (p.hostname or "").lower().rstrip(".")
        except ValueError:
            return False
        if p.scheme not in ("http", "https") or not host or p.username or p.password:
            return False
        return p.netloc.lower() in self.allowed or host in self.allowed

    def request(self, method: str, url: str, headers: dict | None = None) -> Response:
        """Scoped request that backs off on HTTP 429 (and 503 + Retry-After).

        Honours Retry-After (capped at ``max_wait``), otherwise waits 1/2/4s; each
        retry counts against the request budget, and after a throttle the
        per-request delay is raised so the rest of the scan is gentler.
        """
        attempt = 0
        while True:
            resp = self._request_once(method, url, headers)
            retry_after = resp.headers.get("retry-after")
            if not ratelimit.should_retry(resp.status, retry_after):
                return resp
            self.delay = min(max(self.delay * 2, 0.5), 5.0)  # adaptive slow-down
            last = attempt >= self.max_retries or self.count >= self.max_requests
            if last:
                self.rate_limit.record(url, retried=False, gave_up=True)
                return resp
            wait = ratelimit.wait_for(resp.status, retry_after, attempt, cap=self.max_wait)
            self.rate_limit.record(url, retried=True, waited=wait)
            self._sleep(wait)
            attempt += 1

    def _request_once(self, method: str, url: str, headers: dict | None = None) -> Response:
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ScopeViolation(f"method {method} not permitted")
        if not self.in_scope(url):
            raise ScopeViolation(f"out of scope: {url}")
        if self.count >= self.max_requests:
            raise BudgetExceeded(f"request budget {self.max_requests} exhausted")
        self.count += 1
        if self.delay:
            time.sleep(self.delay)

        hdrs = {"User-Agent": USER_AGENT, "Accept": "text/html,application/json,*/*"}
        if self.bearer and "\n" not in self.bearer and "\r" not in self.bearer:
            hdrs["Authorization"] = f"Bearer {self.bearer}"
        hdrs.update(headers or {})
        req = urllib.request.Request(url, method=method, headers=hdrs)
        resp_obj = None
        try:
            resp_obj = self._opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:  # 3xx/4xx/5xx are valid responses for us
            resp_obj = e
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.log.append((method, url, 0))
            return Response(url=url, error=f"{type(e).__name__}: {e}"[:200])

        try:
            raw = resp_obj.read(self.max_bytes + 1)[: self.max_bytes] if method != "HEAD" else b""
            h = resp_obj.headers
            headers_lc = {k.lower(): v for k, v in h.items()}
            cookies = h.get_all("Set-Cookie") or []
            status = getattr(resp_obj, "status", None) or resp_obj.getcode()
            charset = h.get_content_charset() or "utf-8"
            try:
                body = raw.decode(charset, errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")
        finally:
            resp_obj.close()
        self.log.append((method, url, status))
        return Response(url=url, status=status, headers=headers_lc, set_cookies=cookies, body=body)

    def get(self, url, headers=None):
        return self.request("GET", url, headers)


# --------------------------------------------------------------------------
# HTML parsing / spider
# --------------------------------------------------------------------------
class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.script_src: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[dict] = []
        self._form = None
        self._in_script = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script":
            if a.get("src"):
                self.script_src.append(a["src"])
            else:
                self._in_script, self._buf = True, []
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(),
                          "inputs": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", ""),
                                         "type": a.get("type", "text").lower(),
                                         "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._buf))
            self._in_script = False
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data):
        if self._in_script:
            self._buf.append(data)


@dataclass
class Page:
    url: str
    resp: Response
    links: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    inline_scripts: list = field(default_factory=list)


def _norm(url: str) -> str:
    return up.urldefrag(url)[0]


# --------------------------------------------------------------------------
# Finding helper
# --------------------------------------------------------------------------
class Findings:
    def __init__(self):
        self._items: dict[tuple, dict] = {}

    def add(self, *, source, category, severity, title, description, url=None,
            evidence="", cwe=None, confidence="medium", recommendation=""):
        path = (up.urlparse(url).path or "/") if url else ""
        key = (source, title, path, evidence[:80])
        if key in self._items:
            return
        self._items[key] = {
            "id": uuid.uuid4().hex[:8], "source": source, "category": category,
            "severity": severity, "title": title, "description": description[:2000],
            "affected_url": url, "evidence": (evidence or "")[:500] or None, "cwe": cwe,
            "confidence": confidence, "recommendation": recommendation[:1000] or None,
        }

    def all(self) -> list[dict]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return sorted(self._items.values(), key=lambda f: order.get(f["severity"], 9))


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------
class Scanner:
    def __init__(self, target_url, allowed_domains, profile="standard", bearer=None,
                 delay=0.05, max_pages=None, max_requests=None):
        self.cfg = dict(PROFILES.get(profile, PROFILES["standard"]))
        if max_pages:
            self.cfg["max_pages"] = max_pages
        if max_requests:
            self.cfg["max_requests"] = max_requests
        self.target = target_url
        self.profile = profile
        self.client = ScopedClient(allowed_domains, max_requests=self.cfg["max_requests"],
                                   delay=delay, bearer=bearer)
        self.f = Findings()
        self.pages: list[Page] = []
        self.blocked: set[str] = set()
        self.red_flags: list[str] = []
        self.origin = "{0.scheme}://{0.netloc}".format(up.urlparse(target_url))

    # ---- crawl -----------------------------------------------------------
    def _record_external(self, url: str):
        if url.startswith(("http://", "https://")) and not self.client.in_scope(url):
            self.blocked.add(url)

    def crawl(self):
        queue, seen = [_norm(self.target)], set()
        while queue and len(self.pages) < self.cfg["max_pages"]:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            if not self.client.in_scope(url):
                self._record_external(url)
                continue
            if up.urlparse(url).path.lower().endswith(STATIC_EXT):
                continue
            try:
                resp = self.client.get(url)
            except BudgetExceeded as e:
                self.red_flags.append(str(e))
                break
            if resp.error:
                self.f.add(source="recon", category=OTHER, severity="low", title="Page fetch failed",
                           description=f"Could not fetch {url}: {resp.error}", url=url)
                continue
            page = Page(url=url, resp=resp)
            if 300 <= resp.status < 400 and resp.headers.get("location"):
                nxt = _norm(up.urljoin(url, resp.headers["location"]))
                if self.client.in_scope(nxt):
                    queue.append(nxt)
                else:
                    self.blocked.add(nxt)
            if resp.is_html:
                p = _PageParser()
                try:
                    p.feed(resp.body)
                except Exception:  # malformed html must never crash a scan
                    pass
                page.scripts = [_norm(up.urljoin(url, s)) for s in p.script_src]
                page.inline_scripts = p.inline_scripts
                for href in p.links:
                    if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                        continue
                    absu = _norm(up.urljoin(url, href))
                    if self.client.in_scope(absu):
                        queue.append(absu)
                    else:
                        self._record_external(absu)
                page.links = p.links
                for form in p.forms:
                    form["action_abs"] = _norm(up.urljoin(url, form["action"] or url))
                    if not self.client.in_scope(form["action_abs"]):
                        self._record_external(form["action_abs"])
                page.forms = p.forms
            self.pages.append(page)

    # ---- passive ---------------------------------------------------------
    def passive(self):
        missing: dict[str, list[str]] = {}
        required = {
            "content-security-policy": ("Missing Content-Security-Policy header", "medium",
                                        "Define a restrictive Content-Security-Policy."),
            "x-frame-options": ("Missing clickjacking protection (X-Frame-Options/frame-ancestors)", "low",
                                "Set X-Frame-Options or CSP frame-ancestors."),
            "x-content-type-options": ("Missing X-Content-Type-Options header", "low",
                                       "Set X-Content-Type-Options: nosniff."),
            "referrer-policy": ("Missing Referrer-Policy header", "info", "Set a Referrer-Policy."),
        }
        if self.origin.startswith("https"):
            required["strict-transport-security"] = (
                "Missing Strict-Transport-Security (HSTS) header", "medium", "Enable HSTS.")
        server_seen = False
        for pg in self.pages:
            r = pg.resp
            if not r.is_html:
                continue
            for h in required:
                if h not in r.headers:
                    if h == "x-frame-options" and "frame-ancestors" in r.headers.get(
                            "content-security-policy", ""):
                        continue
                    missing.setdefault(h, []).append(pg.url)
            if not server_seen and r.headers.get("server"):
                server_seen = True
                self.f.add(source="recon", category=A05, severity="info",
                           title="Server header discloses software/version",
                           description=f"`Server: {r.headers['server']}` aids fingerprinting.",
                           url=pg.url, evidence=r.headers["server"], cwe="CWE-200",
                           recommendation="Suppress or genericize the Server header.")
            for ck in r.set_cookies:
                self._cookie(ck, pg.url)
            for rx, label in INFO_LEAKS:
                m = rx.search(r.body)
                if m:
                    self.f.add(source="dast_native", category=A05, severity="medium",
                               title=f"Verbose error disclosure: {label}",
                               description="Response contains internal error details.", url=pg.url,
                               evidence=m.group(0)[:200], cwe="CWE-209", confidence="medium",
                               recommendation="Return generic errors; keep diagnostics in server logs.")
                    break
            if re.search(r"<title>\s*Index of /", r.body, re.I) or "Parent Directory" in r.body:
                self.f.add(source="dast_native", category=A05, severity="medium",
                           title="Directory listing enabled",
                           description="The server returns an automatic directory index.", url=pg.url,
                           cwe="CWE-548", confidence="high",
                           recommendation="Disable directory indexing.")
            for form in pg.forms:
                names = [i["type"] for i in form["inputs"]]
                has_pw = "password" in names
                if has_pw and pg.url.startswith("http://"):
                    self.f.add(source="dast_native", category=A02, severity="medium",
                               title="Password form served over plaintext HTTP",
                               description="Credentials would be sent without TLS.", url=pg.url,
                               cwe="CWE-319", confidence="high", recommendation="Serve over HTTPS only.")
                if form["method"] == "post":
                    tokens = [i["name"].lower() for i in form["inputs"] if i["type"] == "hidden"]
                    if not any(k in n for n in tokens for k in ("csrf", "token", "nonce", "authenticity")):
                        self.f.add(source="dast_native", category=A01, severity="low",
                                   title="POST form without apparent anti-CSRF token",
                                   description="No hidden CSRF-like field found (heuristic; verify manually).",
                                   url=pg.url, evidence=f"action={form['action'] or '(self)'}",
                                   cwe="CWE-352", confidence="low",
                                   recommendation="Add per-session anti-CSRF tokens / SameSite cookies.")
        for h, urls in missing.items():
            title, sev, rec = required[h]
            self.f.add(source="dast_native", category=A05, severity=sev, title=title,
                       description=f"`{h}` absent on {len(urls)} page(s).", url=urls[0],
                       evidence="; ".join(urls[:3]), cwe="CWE-693", confidence="high", recommendation=rec)

    def _cookie(self, raw: str, url: str):
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        for flag, sev, tip in (("httponly", "medium", "HttpOnly"), ("samesite", "low", "SameSite"),
                               ("secure", "medium" if url.startswith("https") else "low", "Secure")):
            if flag not in low and not (flag == "secure" and url.startswith("http://")):
                self.f.add(source="dast_native", category=A05, severity=sev,
                           title=f"Cookie '{name}' missing {tip} attribute",
                           description=f"Set-Cookie for '{name}' lacks {tip}.", url=url,
                           evidence=raw[:200], cwe="CWE-1004" if flag == "httponly" else "CWE-614",
                           confidence="high", recommendation=f"Set the {tip} attribute on this cookie.")

    # ---- HTTP-level checks ----------------------------------------------
    def _safe(self, fn, *a):
        try:
            return fn(*a)
        except BudgetExceeded as e:
            if str(e) not in self.red_flags:
                self.red_flags.append(str(e))
        except ScopeViolation:
            pass
        return None

    def http_checks(self):
        root = self.origin + "/"
        r = self._safe(self.client.request, "OPTIONS", root)
        if r and r.headers.get("allow"):
            risky = [m for m in ("PUT", "DELETE", "TRACE", "PATCH") if m in r.headers["allow"].upper()]
            if risky:
                self.f.add(source="dast_native", category=A05, severity="low",
                           title="Risky HTTP methods advertised",
                           description=f"Allow header lists {', '.join(risky)}.", url=root,
                           evidence=f"Allow: {r.headers['allow']}", cwe="CWE-650", confidence="medium",
                           recommendation="Disable unneeded HTTP methods.")
        t = self._safe(self.client.request, "TRACE", root)
        if t and t.status == 200 and "TRACE" in t.body[:200]:
            self.f.add(source="dast_native", category=A05, severity="medium",
                       title="HTTP TRACE method enabled", description="Server echoes TRACE requests.",
                       url=root, cwe="CWE-693", confidence="high",
                       recommendation="Disable TRACE.")
        # CORS on root + api-looking pages
        cands = [root] + [p.url for p in self.pages if "/api" in p.url][:4]
        for u in dict.fromkeys(cands):
            c = self._safe(self.client.get, u, {"Origin": TEST_ORIGIN})
            if not c:
                continue
            ao = c.headers.get("access-control-allow-origin", "")
            cred = c.headers.get("access-control-allow-credentials", "").lower() == "true"
            if ao == TEST_ORIGIN:
                self.f.add(source="dast_native", category=A05, severity="high" if cred else "medium",
                           title="CORS reflects arbitrary Origin" + (" with credentials" if cred else ""),
                           description="Server reflected an untrusted Origin in Access-Control-Allow-Origin.",
                           url=u, evidence=f"ACAO: {ao}; ACAC: {cred}", cwe="CWE-942", confidence="high",
                           recommendation="Validate Origin against a strict allowlist.")
            elif ao == "*" and cred:
                self.f.add(source="dast_native", category=A05, severity="medium",
                           title="CORS wildcard combined with credentials",
                           description="Invalid/misconfigured CORS policy.", url=u,
                           evidence="ACAO: *; ACAC: true", cwe="CWE-942", confidence="medium",
                           recommendation="Use an explicit origin allowlist.")
        # sensitive paths, with soft-404 protection
        junk = self._safe(self.client.get, f"{self.origin}/sg-{uuid.uuid4().hex[:10]}")
        junk_body = junk.body if junk else None
        junk_ok = bool(junk and junk.status == 200)
        for path, sig, sev, title, cwe in SENSITIVE_PATHS:
            r = self._safe(self.client.get, self.origin + path)
            if not r or r.status != 200:
                continue
            if junk_ok and r.body == junk_body:
                continue
            if re.search(sig, r.body[:5000]):
                self.f.add(source="dast_native", category=A05, severity=sev, title=title,
                           description=f"{path} is publicly retrievable and matches a sensitive-content signature.",
                           url=self.origin + path, evidence=re.sub(r"=.*", "=<redacted>", r.body[:80]),
                           cwe=cwe, confidence="high", recommendation="Remove from web root / deny access.")

    # ---- active (non-destructive) ---------------------------------------
    def _targets(self):
        out, seen = [], set()

        def add(base, params, name):
            key = (up.urlparse(base).path, name)
            if key not in seen:
                seen.add(key)
                out.append((base, dict(params), name))

        for pg in self.pages:
            p = up.urlparse(pg.url)
            q = dict(up.parse_qsl(p.query, keep_blank_values=True))
            base = up.urlunparse(p._replace(query="", fragment=""))
            for name in q:
                add(base, q, name)
            for form in pg.forms:
                if form["method"] != "get" or not self.client.in_scope(form["action_abs"]):
                    continue
                params = {i["name"]: (i["value"] or "test") for i in form["inputs"]
                          if i["name"] and i["type"] not in ("submit", "button", "file", "password", "image")}
                fp = up.urlparse(form["action_abs"])
                fbase = up.urlunparse(fp._replace(query="", fragment=""))
                for name in params:
                    add(fbase, params, name)
        return out[: self.cfg["max_targets"]]

    @staticmethod
    def _inject(base, params, name, value):
        q = dict(params)
        q[name] = value
        return base + "?" + up.urlencode(q)

    def active(self):
        targets = self._targets()
        xss_payload = f"sg{uuid.uuid4().hex[:6]}\"'<zq>"
        for base, params, name in targets:
            lname = name.lower()
            # reflected XSS (unencoded reflection of dangerous chars)
            r = self._safe(self.client.get, self._inject(base, params, name, xss_payload))
            if r and r.is_html and xss_payload in r.body:
                self.f.add(source="dast_native", category=XSS, severity="medium",
                           title="Reflected input without output encoding (possible XSS)",
                           description=f"Parameter '{name}' is reflected with <, \" and ' unencoded. "
                                       "No script was executed; confirm manually.",
                           url=self._inject(base, params, name, "<marker>"),
                           evidence=f"param={name}", cwe="CWE-79", confidence="medium",
                           recommendation="Context-aware output encoding and a strict CSP.")
            # error-based SQLi
            base_r = self._safe(self.client.get, self._inject(base, params, name, params.get(name) or "1"))
            r = self._safe(self.client.get, self._inject(base, params, name,
                                                         (params.get(name) or "1") + "'"))
            if r and base_r:
                hit = next((s for s in SQL_ERRORS if s in r.body.lower() and s not in base_r.body.lower()), None)
                if hit:
                    self.f.add(source="dast_native", category=A03, severity="high",
                               title="Possible SQL injection (database error on quote)",
                               description=f"A single quote in '{name}' produced a database error message.",
                               url=base, evidence=f"param={name}; signature='{hit}'", cwe="CWE-89",
                               confidence="medium",
                               recommendation="Use parameterized queries; suppress DB errors.")
            # open redirect
            if lname in REDIRECT_PARAMS:
                r = self._safe(self.client.get, self._inject(base, params, name, TEST_ORIGIN + "/x"))
                if r and 300 <= r.status < 400 and up.urlparse(
                        r.headers.get("location", "")).hostname == "scopeguard.invalid":
                    self.f.add(source="dast_native", category=A01, severity="medium",
                               title="Open redirect", description=f"'{name}' controls the redirect target "
                               "without validation (redirect was not followed).",
                               url=base, evidence=f"param={name}; Location={r.headers['location']}",
                               cwe="CWE-601", confidence="high",
                               recommendation="Allowlist redirect destinations.")
            # path traversal
            if lname in FILE_PARAMS:
                payloads = ["../../../../../../etc/passwd"]
                if self.cfg["variants"]:
                    payloads += ["..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "....//....//....//....//etc/passwd"]
                for pl in payloads:
                    r = self._safe(self.client.get, base + "?" + up.urlencode({**params, name: pl}, safe="%/."))
                    if r and re.search(r"root:[x*]:0:0:", r.body):
                        self.f.add(source="dast_native", category=A01, severity="high",
                                   title="Path traversal (local file disclosure)",
                                   description=f"'{name}' allowed reading a file outside the intended directory.",
                                   url=base, evidence=f"param={name}; /etc/passwd signature matched",
                                   cwe="CWE-22", confidence="high",
                                   recommendation="Canonicalize and allowlist file names.")
                        break

    # ---- JS SAST ---------------------------------------------------------
    def sast(self):
        assets, seen = 0, set()
        for pg in self.pages:
            blobs = [(pg.url + " (inline)", s) for s in pg.inline_scripts]
            for src in pg.scripts:
                if src in seen or assets >= 40:
                    continue
                seen.add(src)
                if not self.client.in_scope(src):
                    self.blocked.add(src)
                    continue
                r = self._safe(self.client.get, src)
                if r and r.status == 200:
                    assets += 1
                    blobs.append((src, r.body))
            for url, code in blobs:
                for n, line in enumerate(code.splitlines(), 1):
                    for rid, rx, sev, cat, desc, cwe in JS_RULES:
                        if rx.search(line):
                            ev = f"Line {n}: {line.strip()[:200]}"
                            if rid in ("AWS_ACCESS_KEY", "HARDCODED_SECRET", "PRIVATE_KEY"):
                                ev = f"Line {n}: <secret pattern {rid} matched; value redacted>"
                            self.f.add(source="python_sast", category=cat, severity=sev,
                                       title=f"{rid}: potentially unsafe JavaScript pattern",
                                       description=desc, url=url.split(" ")[0], evidence=ev, cwe=cwe,
                                       confidence="medium",
                                       recommendation=JS_RECOMMENDATIONS.get(
                                           rid, "Review this pattern and remediate if it handles untrusted data."))

    # ---- orchestration ---------------------------------------------------
    def run(self) -> dict:
        t0 = time.time()
        self.crawl()
        if not self.pages:
            self.red_flags.append("Crawl reached no pages; target unreachable or fully out of scope.")
        self.passive()
        self.sast()
        self.http_checks()
        if self.cfg["active"]:
            self.active()
        flag = self.client.rate_limit.red_flag()
        if flag:
            self.red_flags.append(flag)
        return {
            "findings": self.f.all(),
            "crawled_pages": [p.url for p in self.pages],
            "external_links_blocked": sorted(self.blocked),
            "red_flags": self.red_flags,
            "requests_made": self.client.count,
            "rate_limit": self.client.rate_limit.as_dict(),
            "login_form_detected": any(
                any(i["type"] == "password" for i in f["inputs"]) for p in self.pages for f in p.forms),
            "duration_seconds": round(time.time() - t0, 2),
            "profile": self.profile,
        }


def run_scan(target_url, allowed_domains, profile="standard", bearer=None, delay=0.05,
             max_pages=None, max_requests=None) -> dict:
    return Scanner(target_url, allowed_domains, profile, bearer, delay, max_pages, max_requests).run()


if __name__ == "__main__":  # pragma: no cover
    import sys
    print(json.dumps(run_scan(sys.argv[1], [up.urlparse(sys.argv[1]).netloc]), indent=2))
