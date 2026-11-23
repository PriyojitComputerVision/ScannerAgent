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

import http.client
import json
import re
import time
import urllib.error
import urllib.parse as up
import urllib.request
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser

from scopeguard import contentpolicy, ratelimit
from scopeguard.textsafe import strip_hyperlinks

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
# POST is permitted only through ScopedClient.post_multipart (upload testing),
# never through request(); the upload probe is gated by profile + settings + RBAC.
UPLOAD_METHODS = ALLOWED_METHODS | {"POST"}
USER_AGENT = "ScopeGuard-Agent/1.0 (authorized security assessment)"
STATIC_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
              ".woff2", ".ttf", ".pdf", ".zip", ".mp4", ".mp3", ".webp")
TEST_ORIGIN = "https://scopeguard.invalid"
TEST_HOST = "scopeguard.invalid"
# API documentation / consoles that should not be public in production.
API_DOC_PATHS = ["/docs", "/redoc", "/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger-ui/index.html",
                 "/api-docs", "/api/docs", "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
                 "/graphql", "/graphiql", "/api/graphql"]
API_DOC_SIGNATURE = re.compile(
    r"(?i)swagger|openapi|redoc|graphiql|graphql playground|\"paths\"\s*:|\"__schema\"|api documentation")
# Backend endpoints referenced in HTML/JS (paths or absolute URLs).
ENDPOINT_RX = re.compile(
    r"""["'`]((?:https?://[^"'`\s<>]+?)?/(?:api|v\d+|graphql|rest|ajax|auth|oauth|internal|admin|backend|"""
    r"""services?|rpc|json|ws)(?:[/?][^"'`\s<>]*)?)["'`]""", re.IGNORECASE)
SSTI_PAYLOAD = "sg{{7*7}}sg${7*7}sg<%= 7*7 %>sg#{7*7}sg"
SSTI_HIT = re.compile(r"sg49sg")
CRLF_HEADER = "x-sg-injected"
SQL_SLEEP = 4  # seconds, time-based checks (aggressive/auth_deep only)
SQL_TIME_PAYLOADS = ["' AND SLEEP({n})-- -", "' AND 1=(SELECT 1 FROM PG_SLEEP({n}))--",
                     "'; WAITFOR DELAY '0:0:{n}'--", " AND SLEEP({n})"]
CMD_TIME_PAYLOADS = [";sleep {n}", "|sleep {n}", "$(sleep {n})"]
URL_PARAMS = {"url", "link", "href", "src", "redirect", "next", "return", "returnurl", "goto", "target",
              "dest", "destination", "continue", "callback"}

# File-upload testing. Every payload is a small, INERT marker file. The "scripts"
# only echo a unique marker string if a misconfigured server were to execute them;
# they contain no shell, no real executable, and do nothing on their own. Used to
# check whether an upload control rejects dangerous/disguised files, never to plant
# a working webshell. {m} is replaced with a per-run random marker.
UPLOAD_PROBES = [
    # name, content, content-type sent, server-executable extension?
    ("scopeguard-{m}.txt", "scopeguard upload test {m}", "text/plain", False),
    ("scopeguard-{m}.php", "<?php echo 'scopeguard-exec-{m}'; ?>", "image/jpeg", True),
    ("scopeguard-{m}.phtml", "<?php echo 'scopeguard-exec-{m}'; ?>", "image/png", True),
    ("scopeguard-{m}.jsp", "<% out.print(\"scopeguard-exec-{m}\"); %>", "image/jpeg", True),
    ("scopeguard-{m}.asp", "<% Response.Write(\"scopeguard-exec-{m}\") %>", "image/jpeg", True),
    ("scopeguard-{m}.svg", "<svg xmlns='http://www.w3.org/2000/svg'><!-- scopeguard-{m} --></svg>", "image/svg+xml", True),
    ("scopeguard-{m}.html", "<!-- scopeguard-{m} -->", "image/jpeg", True),
    ("scopeguard-{m}.jpg.php", "<?php echo 'scopeguard-exec-{m}'; ?>", "image/jpeg", True),   # double extension
    ("scopeguard-{m}.pHp", "<?php echo 'scopeguard-exec-{m}'; ?>", "image/jpeg", True),       # case bypass
    ("scopeguard-{m}.php%00.jpg", "<?php echo 'scopeguard-exec-{m}'; ?>", "image/jpeg", True),  # null-byte trick
    ("scopeguard-{m}.exe", "MZ scopeguard inert marker {m} (not a real executable)", "application/octet-stream", False),
]
# A benign, highly compressible oversized file to probe the size limit.
UPLOAD_OVERSIZE_MB = 6
EXEC_MARKER = "scopeguard-exec-"


# Prompt-injection and LLM jailbreak phrases embedded in page content.
PROMPT_INJECTION_RX = re.compile(
    r"(?is)(?:ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier|system)\s+"
    r"(?:instructions?|prompts?|messages?|rules?)"
    r"|disregard\s+(?:all\s+)?(?:previous|prior|your)\s+(?:instructions?|guidelines?|rules?)"
    r"|forget\s+(?:all\s+|everything\s+)?(?:you(?:'re| are| were)|your\s+(?:instructions?|rules?))"
    r"|you\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?(?:dan|do\s+anything\s+now|developer\s+mode|"
    r"jailbr|unrestricted|unfiltered|evil|god\s*mode)"
    r"|(?:enable|enter|activate)\s+(?:dan|developer|god|jailbreak|debug|admin)\s*mode"
    r"|(?:reveal|print|repeat|show|leak|output)\s+(?:me\s+)?(?:your\s+)?(?:system\s+prompt|initial\s+"
    r"instructions?|api\s*key|secret|credentials?)"
    r"|pretend\s+(?:to\s+be|you\s+are)\s+(?:an?\s+)?(?:unrestricted|different|evil|dan)"
    r"|(?:as|now)\s+an?\s+ai\b[^.]{0,40}\b(?:without|no)\s+(?:restrictions?|limits?|filters?|guidelines?)"
    r"|do\s+not\s+(?:follow|obey|apply)\s+(?:your\s+)?(?:safety\s+)?(?:rules?|guidelines?|policy))")

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
    ("JS_INSERT_ADJACENT_HTML", re.compile(r"\.insertAdjacentHTML\s*\("), "medium", XSS,
     "insertAdjacentHTML() parses its input as HTML.", "CWE-79"),
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
    "JS_INSERT_ADJACENT_HTML": "Sanitize untrusted HTML first, or build nodes with createElement and "
                               "textContent instead of insertAdjacentHTML.",
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
    "quick":      {"max_pages": 15, "active": False, "max_targets": 0,   "variants": False, "max_requests": 150, "uploads": False},
    "standard":   {"max_pages": 40, "active": True,  "max_targets": 40,  "variants": False, "max_requests": 500, "uploads": False},
    "aggressive": {"max_pages": 80, "active": True,  "max_targets": 120, "variants": True,  "max_requests": 1500, "uploads": True},
    "auth_deep":  {"max_pages": 80, "active": True,  "max_targets": 120, "variants": True,  "max_requests": 1500, "uploads": True},
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
    dropped: str = ""  # why the body was discarded unread (file/attachment/binary), if it was

    @property
    def ctype(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_html(self) -> bool:
        return "html" in self.ctype


class ScopedClient:
    def __init__(self, allowed_domains, *, max_requests=500, timeout=8.0,
                 max_bytes=1_000_000, delay=0.05, bearer=None, cookie=None,
                 max_retries=ratelimit.DEFAULT_MAX_RETRIES, max_wait=ratelimit.DEFAULT_MAX_WAIT,
                 sleep=time.sleep):
        self.allowed = {d.strip().lower() for d in allowed_domains if d and d.strip()}
        self.max_requests = max_requests
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.delay = delay
        self.bearer = bearer
        # Session cookie header for authenticated scans (e.g. after SSO/MFA sign-in).
        self.cookie = cookie if cookie and not any(c in cookie for c in "\r\n\x00") else None
        self.count = 0
        self.max_retries = max_retries
        self.max_wait = max_wait
        self._sleep = sleep
        self.rate_limit = ratelimit.RateLimitStats()
        self.log: list[tuple[str, str, int]] = []
        # Responses whose body was discarded unread (contentpolicy): (url, reason).
        self.dropped: list[tuple[str, str]] = []
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
        if self.cookie:
            hdrs["Cookie"] = self.cookie
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

        dropped = ""
        try:
            h = resp_obj.headers
            raw = b""
            if method != "HEAD":
                # Never download files: attachments and binary types are not read at
                # all; unknown types are sniffed (small prefix) and dropped if binary.
                mode, why = contentpolicy.body_policy(h.get("Content-Type"), h.get("Content-Disposition"),
                                                      h.get("Content-Encoding"))
                if mode == "drop":
                    dropped = why
                else:
                    limit = min(self.max_bytes, contentpolicy.SNIFF_BYTES) if mode == "sniff" else self.max_bytes
                    raw = resp_obj.read(limit + 1)[:limit]
                    if contentpolicy.looks_binary(raw):
                        raw, dropped = b"", f"binary body ({why or 'file signature'})"
            headers_lc = {k.lower(): v for k, v in h.items()}
            cookies = h.get_all("Set-Cookie") or []
            status = getattr(resp_obj, "status", None) or resp_obj.getcode()
            charset = h.get_content_charset() or "utf-8"
            try:
                body = raw.decode(charset, errors="replace")
            except LookupError:
                body = raw.decode("utf-8", errors="replace")
        except (OSError, http.client.HTTPException, ValueError) as e:
            # Headers arrived but the body stalled/broke (read timeout, reset,
            # IncompleteRead): one slow page must not abort the whole scan.
            self.log.append((method, url, 0))
            return Response(url=url, error=f"{type(e).__name__}: {e}"[:200])
        finally:
            resp_obj.close()
        self.log.append((method, url, status))
        if dropped:
            self.dropped.append((url, dropped))
        return Response(url=url, status=status, headers=headers_lc, set_cookies=cookies, body=body,
                        dropped=dropped)

    def get(self, url, headers=None):
        return self.request("GET", url, headers)

    def post_multipart(self, url: str, fields: dict, file_field: str, filename: str,
                       content: bytes, content_type: str) -> Response:
        """Scoped multipart/form-data POST, used ONLY by the upload probe.

        Enforces scope and the request budget exactly like GET; POST is allowed
        here but nowhere else (request() keeps the GET/HEAD/OPTIONS/TRACE allowlist)."""
        if not self.in_scope(url):
            raise ScopeViolation(f"out of scope: {url}")
        if self.count >= self.max_requests:
            raise BudgetExceeded(f"request budget {self.max_requests} exhausted")
        self.count += 1
        if self.delay:
            time.sleep(self.delay)
        boundary = "----scopeguard" + uuid.uuid4().hex
        parts = []
        for k, v in (fields or {}).items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
        safe_name = filename.replace('"', "").replace("\r", "").replace("\n", "")
        parts.append((f'--{boundary}\r\nContent-Disposition: form-data; name="{file_field}"; '
                      f'filename="{safe_name}"\r\nContent-Type: {content_type}\r\n\r\n').encode())
        body = b"".join(parts) + content + f"\r\n--{boundary}--\r\n".encode()
        hdrs = {"User-Agent": USER_AGENT, "Content-Type": f"multipart/form-data; boundary={boundary}"}
        if self.bearer and "\n" not in self.bearer and "\r" not in self.bearer:
            hdrs["Authorization"] = f"Bearer {self.bearer}"
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        req = urllib.request.Request(url, data=body, method="POST", headers=hdrs)
        resp_obj = None
        try:
            resp_obj = self._opener.open(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            resp_obj = e
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.log.append(("POST", url, 0))
            return Response(url=url, error=f"{type(e).__name__}: {e}"[:200])
        try:
            raw = resp_obj.read(self.max_bytes + 1)[: self.max_bytes]
            h = resp_obj.headers
            status = getattr(resp_obj, "status", None) or resp_obj.getcode()
            body_text = raw.decode(h.get_content_charset() or "utf-8", errors="replace")
        except (OSError, http.client.HTTPException, ValueError) as e:
            self.log.append(("POST", url, 0))
            return Response(url=url, error=f"{type(e).__name__}: {e}"[:200])
        finally:
            resp_obj.close()
        self.log.append(("POST", url, status))
        return Response(url=url, status=status, headers={k.lower(): v for k, v in h.items()},
                        set_cookies=h.get_all("Set-Cookie") or [], body=body_text)


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
        evidence = strip_hyperlinks(evidence or "")  # site-derived text: no hyperlinks
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
                 delay=0.05, max_pages=None, max_requests=None, upload_active=False, cookie=None):
        self.cfg = dict(PROFILES.get(profile, PROFILES["standard"]))
        if max_pages:
            self.cfg["max_pages"] = max_pages
        if max_requests:
            self.cfg["max_requests"] = max_requests
        self.target = target_url
        self.profile = profile
        self.client = ScopedClient(allowed_domains, max_requests=self.cfg["max_requests"],
                                   delay=delay, bearer=bearer, cookie=cookie)
        self.f = Findings()
        self.pages: list[Page] = []
        self.blocked: set[str] = set()
        self.red_flags: list[str] = []
        self.origin = "{0.scheme}://{0.netloc}".format(up.urlparse(target_url))
        self.upload_active = bool(upload_active)
        self.coverage: dict[str, dict] = {}   # attack/check -> tested, findings, notes
        self.endpoints: dict[str, str] = {}   # backend endpoints found in HTML/JS -> where

    def _cov(self, check: str, tested: int = 0, found: int = 0, note: str | None = None) -> None:
        c = self.coverage.setdefault(check, {"tested": 0, "findings": 0, "notes": []})
        c["tested"] += tested
        c["findings"] += found
        if note and len(c["notes"]) < 25:
            c["notes"].append(note)

    def _timed_get(self, url):
        t = time.monotonic()
        r = self._safe(self.client.get, url)
        return r, time.monotonic() - t

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
            if up.urlparse(url).path.lower().endswith(STATIC_EXT) or contentpolicy.is_file_link(url):
                continue  # never request links to files (downloads, media, archives, ...)
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
                except Exception:  # noqa: BLE001, S110 - malformed html must never crash a scan
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
            "cross-origin-opener-policy": ("Missing Cross-Origin-Opener-Policy header", "info",
                                           "Set Cross-Origin-Opener-Policy: same-origin."),
            "cross-origin-resource-policy": ("Missing Cross-Origin-Resource-Policy header", "info",
                                             "Set Cross-Origin-Resource-Policy: same-origin (or same-site)."),
            "permissions-policy": ("Missing Permissions-Policy header", "info",
                                   "Set a Permissions-Policy that disables unused browser features."),
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
            csp = r.headers.get("content-security-policy", "")
            weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'") if w in csp]
            if csp and (weak or re.search(r"(?:script-src|default-src)[^;]*\s\*(?:\s|;|$)", csp)):
                self.f.add(source="dast_native", category=A05, severity="low",
                           title="Weak Content-Security-Policy",
                           description="The CSP allows " + (", ".join(weak) or "any script source (*)") + ".",
                           url=pg.url, evidence=csp[:300], cwe="CWE-693", confidence="high",
                           recommendation="Remove unsafe-inline/unsafe-eval and wildcards; use nonces or hashes.")
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
            mi = PROMPT_INJECTION_RX.search(r.body)
            if mi:
                self.f.add(source="dast_native", category=OTHER, severity="medium",
                           title="Page content attempts prompt injection / jailbreak",
                           description="The page contains text written to hijack an AI agent or scanner "
                                       "(prompt injection / jailbreak). It was treated as data and not followed.",
                           url=pg.url, evidence=re.sub(r"\s+", " ", mi.group(0))[:200], cwe="CWE-1427",
                           confidence="medium",
                           recommendation="Investigate the source of this text (user content or a compromised page).")
            if re.search(r"<title>\s*Index of /", r.body, re.IGNORECASE) or "Parent Directory" in r.body:
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
        self._cov("Security & cross-origin policy headers", tested=len(required) * max(1, len(self.pages)),
                  found=len(missing), note="missing: " + (", ".join(sorted(missing)) or "none"))
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
        self._cov("HTTP methods / TRACE", tested=2)
        # CORS on root + api-looking pages: arbitrary, null and prefix/suffix-bypass origins, preflight
        host = up.urlparse(self.origin).hostname or ""
        bypass = {"null": ("CORS trusts the 'null' origin", "Sandboxed iframes and local files send Origin: null."),
                  f"https://{host}.{TEST_HOST}": ("CORS origin check bypass (prefix match)",
                                                  ("The Origin check accepts any domain that starts with the "
                                                  "target host.")),
                  f"https://{TEST_HOST.split('.')[0]}{host}": ("CORS origin check bypass (suffix match)",
                                                               ("The Origin check accepts any domain that ends "
                                                               "with the target host."))}
        cands = [root] + [p.url for p in self.pages if "/api" in p.url or p.url in self.endpoints][:6]
        for u in dict.fromkeys(cands):
            for origin, (title, why) in bypass.items():
                c = self._safe(self.client.get, u, {"Origin": origin})
                self._cov("CORS (null / prefix / suffix origins)", tested=1)
                if c and c.headers.get("access-control-allow-origin", "") == origin:
                    cred = c.headers.get("access-control-allow-credentials", "").lower() == "true"
                    self._cov("CORS (null / prefix / suffix origins)", found=1, note=f"{title} at {u}")
                    self.f.add(source="dast_native", category=A05, severity="high" if cred else "medium",
                               title=title + (" with credentials" if cred else ""), description=why, url=u,
                               evidence=f"Origin: {origin} -> ACAO: {origin}; ACAC: {cred}", cwe="CWE-942",
                               confidence="high", recommendation="Compare the full Origin against an exact allowlist.")
            pre = self._safe(self.client.request, "OPTIONS", u, {
                "Origin": TEST_ORIGIN, "Access-Control-Request-Method": "DELETE",
                "Access-Control-Request-Headers": "authorization"})
            self._cov("CORS preflight", tested=1)
            if pre and pre.headers.get("access-control-allow-origin", "") in (TEST_ORIGIN, "*") and \
                    "DELETE" in pre.headers.get("access-control-allow-methods", "").upper():
                self._cov("CORS preflight", found=1, note=f"DELETE allowed for any origin at {u}")
                self.f.add(source="dast_native", category=A05, severity="medium",
                           title="CORS preflight allows untrusted origins to send DELETE",
                           description="A preflight from an untrusted origin was approved for DELETE.",
                           url=u, evidence=f"ACAM: {pre.headers.get('access-control-allow-methods', '')}",
                           cwe="CWE-942", confidence="medium",
                           recommendation="Only approve preflights from trusted origins and needed methods.")
            c = self._safe(self.client.get, u, {"Origin": TEST_ORIGIN})
            self._cov("CORS (arbitrary origin)", tested=1)
            if not c:
                continue
            ao = c.headers.get("access-control-allow-origin", "")
            cred = c.headers.get("access-control-allow-credentials", "").lower() == "true"
            if ao in (TEST_ORIGIN, "*"):
                self._cov("CORS (arbitrary origin)", found=1 if ao == TEST_ORIGIN or cred else 0,
                          note=f"ACAO {ao} at {u}")
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
        # Host header injection via X-Forwarded-Host (request still goes to the target)
        hh = self._safe(self.client.get, root, {"X-Forwarded-Host": TEST_HOST})
        self._cov("Host header injection", tested=1)
        if hh and (TEST_HOST in hh.headers.get("location", "") or TEST_HOST in hh.body[:20000]):
            self._cov("Host header injection", found=1, note="X-Forwarded-Host reflected")
            self.f.add(source="dast_native", category=A05, severity="medium",
                       title="Host header injection (X-Forwarded-Host reflected)",
                       description="The response builds URLs from X-Forwarded-Host; this enables password-reset "
                                   "poisoning and cache poisoning.", url=root,
                       evidence=f"X-Forwarded-Host: {TEST_HOST} reflected", cwe="CWE-644", confidence="medium",
                       recommendation="Build absolute URLs from a configured host, not request headers.")
        # sensitive paths, with soft-404 protection
        junk = self._safe(self.client.get, f"{self.origin}/sg-{uuid.uuid4().hex[:10]}")
        junk_body = junk.body if junk else None
        junk_ok = bool(junk and junk.status == 200)
        # API documentation (/docs, swagger, openapi, graphql consoles): accessible or not
        for path in API_DOC_PATHS:
            r = self._safe(self.client.get, self.origin + path)
            self._cov("API docs exposure (/docs, swagger, openapi, graphql)", tested=1)
            status = r.status if r else "no response"
            exposed = bool(r and r.status == 200 and not (junk_ok and r.body == junk_body)
                           and API_DOC_SIGNATURE.search(r.body[:20000]))
            self._cov("API docs exposure (/docs, swagger, openapi, graphql)", found=int(exposed),
                      note=f"{path}: {status}{' (EXPOSED)' if exposed else ' (not accessible)' if status != 200 else ' (no API docs content)'}")
            if exposed:
                self.f.add(source="dast_native", category=A05, severity="medium",
                           title=f"API documentation exposed ({path})",
                           description=f"{path} is publicly accessible and serves API documentation or a "
                                       "query console, which maps every endpoint for an attacker.",
                           url=self.origin + path, evidence=f"GET {path} -> {r.status}", cwe="CWE-200",
                           confidence="high", recommendation="Disable API docs in production or put them "
                                                             "behind authentication.")
        for path, sig, sev, title, cwe in SENSITIVE_PATHS:
            r = self._safe(self.client.get, self.origin + path)
            self._cov("Sensitive files (.env, .git, backups)", tested=1)
            if not r or r.status != 200:
                continue
            if junk_ok and r.body == junk_body:
                continue
            if re.search(sig, r.body[:5000]):
                self._cov("Sensitive files (.env, .git, backups)", found=1, note=path)
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

    @staticmethod
    def _in_script(body: str, marker: str) -> bool:
        i = body.find(marker)
        return i >= 0 and body.rfind("<script", 0, i) > body.rfind("</script", 0, i)

    def _sqli_boolean(self, base, params, name, base_r) -> bool:
        v = params.get(name) or "1"
        pairs = [(v + "' AND '1'='1", v + "' AND '1'='2")]
        if v.isdigit():
            pairs.append((v + " AND 1=1", v + " AND 1=2"))
        for true_v, false_v in pairs:
            t = self._safe(self.client.get, self._inject(base, params, name, true_v))
            f = self._safe(self.client.get, self._inject(base, params, name, false_v))
            self._cov("SQL injection (boolean-based)", tested=1)
            if not (t and f and base_r) or t.status != base_r.status:
                continue
            lb, lt, lf = len(base_r.body), len(t.body), len(f.body)
            same_as_base = abs(lt - lb) <= max(50, 0.03 * lb) + len(true_v)
            differs = f.status != t.status or abs(lt - lf) > max(50, 0.10 * max(lt, 1))
            if same_as_base and differs:
                t2 = self._safe(self.client.get, self._inject(base, params, name, true_v))
                if t2 and abs(len(t2.body) - lt) <= 10:
                    self._cov("SQL injection (boolean-based)", found=1, note=f"param {name} at {base}")
                    self.f.add(source="dast_native", category=A03, severity="high",
                               title="Possible SQL injection (boolean-based)",
                               description=f"'{name}': a true condition returns the normal page and a false "
                                           "one changes it, so the value reaches a SQL query.",
                               url=base, evidence=f"param={name}; true={lt}B false={lf}B ({f.status})",
                               cwe="CWE-89", confidence="medium",
                               recommendation="Use parameterized queries.")
                    return True
        return False

    def _time_based(self, base, params, name, payloads, check, title, cwe, rec) -> bool:
        v = params.get(name) or "1"
        _, t0 = self._timed_get(self._inject(base, params, name, v))
        for tpl in payloads:
            slow, t1 = self._timed_get(self._inject(base, params, name, v + tpl.format(n=SQL_SLEEP)))
            self._cov(check, tested=1)
            if not slow or t1 < t0 + SQL_SLEEP - 0.5:
                continue
            _, t_zero = self._timed_get(self._inject(base, params, name, v + tpl.format(n=0)))
            _, t_again = self._timed_get(self._inject(base, params, name, v + tpl.format(n=SQL_SLEEP)))
            if t_zero < t0 + 1.5 and t_again >= t0 + SQL_SLEEP - 0.5:
                self._cov(check, found=1, note=f"param {name} at {base}: +{t1 - t0:.1f}s")
                self.f.add(source="dast_native", category=A03, severity="high", title=title,
                           description=f"'{name}': a {SQL_SLEEP}s delay payload delayed the response twice, "
                                       "and the 0s version did not.", url=base,
                           evidence=f"param={name}; baseline {t0:.1f}s, delayed {t1:.1f}s/{t_again:.1f}s",
                           cwe=cwe, confidence="medium", recommendation=rec)
                return True
        return False

    def active(self):
        targets = self._targets()
        xss_payload = f"sg{uuid.uuid4().hex[:6]}\"'<zq>"
        timed_left = 15 if self.cfg["variants"] else 0  # time-based checks are slow: cap them
        for base, params, name in targets:
            lname = name.lower()
            # reflected XSS (unencoded reflection of dangerous chars)
            r = self._safe(self.client.get, self._inject(base, params, name, xss_payload))
            self._cov("Cross-site scripting (reflected)", tested=1)
            if r and r.is_html and xss_payload in r.body:
                self._cov("Cross-site scripting (reflected)", found=1, note=f"param {name} at {base}")
                self.f.add(source="dast_native", category=XSS, severity="medium",
                           title="Reflected input without output encoding (possible XSS)",
                           description=f"Parameter '{name}' is reflected with <, \" and ' unencoded. "
                                       "No script was executed; confirm manually.",
                           url=self._inject(base, params, name, "<marker>"),
                           evidence=f"param={name}", cwe="CWE-79", confidence="medium",
                           recommendation="Context-aware output encoding and a strict CSP.")
            # XSS inside a <script> block (quote breaks out of a JS string)
            js_marker = f"sg{uuid.uuid4().hex[:6]}';sgq//"
            r = self._safe(self.client.get, self._inject(base, params, name, js_marker))
            self._cov("Cross-site scripting (script context)", tested=1)
            if r and r.is_html and self._in_script(r.body, js_marker):
                self._cov("Cross-site scripting (script context)", found=1, note=f"param {name} at {base}")
                self.f.add(source="dast_native", category=XSS, severity="high",
                           title="Reflected input inside a <script> block (possible XSS)",
                           description=f"'{name}' is written into JavaScript with the quote unescaped.",
                           url=base, evidence=f"param={name}", cwe="CWE-79", confidence="medium",
                           recommendation="Encode for the JavaScript context or pass data via JSON.")
            # javascript: URL injected into a link/src attribute
            if lname in URL_PARAMS:
                js_url = f"javascript:sg{uuid.uuid4().hex[:6]}()"
                r = self._safe(self.client.get, self._inject(base, params, name, js_url))
                self._cov("Cross-site scripting (javascript: URL)", tested=1)
                if r and r.is_html and re.search(r"(?:href|src|action)\s*=\s*[\"']?" + re.escape(js_url), r.body):
                    self._cov("Cross-site scripting (javascript: URL)", found=1, note=f"param {name} at {base}")
                    self.f.add(source="dast_native", category=XSS, severity="medium",
                               title="javascript: URL accepted in a link (possible XSS)",
                               description=f"'{name}' is placed in an href/src without a scheme check.",
                               url=base, evidence=f"param={name}", cwe="CWE-79", confidence="medium",
                               recommendation="Allow only http(s) URLs in links.")
            # server-side template injection
            r = self._safe(self.client.get, self._inject(base, params, name, SSTI_PAYLOAD))
            self._cov("Server-side template injection", tested=1)
            if r and SSTI_HIT.search(r.body) and SSTI_PAYLOAD not in r.body:
                self._cov("Server-side template injection", found=1, note=f"param {name} at {base}")
                self.f.add(source="dast_native", category=A03, severity="high",
                           title="Server-side template injection",
                           description=f"'{name}': the expression 7*7 was evaluated to 49 by a template engine.",
                           url=base, evidence=f"param={name}; 7*7 -> 49", cwe="CWE-1336", confidence="high",
                           recommendation="Never build templates from user input; pass it as data.")
            # CRLF / response header injection
            r = self._safe(self.client.get, self._inject(base, params, name, f"sg\r\n{CRLF_HEADER}: sg1"))
            self._cov("CRLF / header injection", tested=1)
            if r and CRLF_HEADER in r.headers:
                self._cov("CRLF / header injection", found=1, note=f"param {name} at {base}")
                self.f.add(source="dast_native", category=A03, severity="high",
                           title="CRLF injection (response header injection)",
                           description=f"'{name}' can add response headers (cookies, redirects, cache poisoning).",
                           url=base, evidence=f"param={name}; injected header {CRLF_HEADER} returned",
                           cwe="CWE-113", confidence="high",
                           recommendation="Strip CR/LF from values written to headers.")
            # error-based SQLi
            base_r = self._safe(self.client.get, self._inject(base, params, name, params.get(name) or "1"))
            r = self._safe(self.client.get, self._inject(base, params, name,
                                                         (params.get(name) or "1") + "'"))
            self._cov("SQL injection (error-based)", tested=1)
            sqli_found = False
            if r and base_r:
                hit = next((s for s in SQL_ERRORS if s in r.body.lower() and s not in base_r.body.lower()), None)
                if hit:
                    sqli_found = True
                    self._cov("SQL injection (error-based)", found=1, note=f"param {name} at {base}")
                    self.f.add(source="dast_native", category=A03, severity="high",
                               title="Possible SQL injection (database error on quote)",
                               description=f"A single quote in '{name}' produced a database error message.",
                               url=base, evidence=f"param={name}; signature='{hit}'", cwe="CWE-89",
                               confidence="medium",
                               recommendation="Use parameterized queries; suppress DB errors.")
            if not sqli_found:
                sqli_found = self._sqli_boolean(base, params, name, base_r)
            if timed_left > 0:
                timed_left -= 1
                if not sqli_found:
                    self._time_based(base, params, name, SQL_TIME_PAYLOADS, "SQL injection (time-based)",
                                     "Possible SQL injection (time-based)", "CWE-89",
                                     "Use parameterized queries.")
                self._time_based(base, params, name, CMD_TIME_PAYLOADS, "OS command injection (time-based)",
                                 "Possible OS command injection (time-based)", "CWE-78",
                                 "Never pass input to a shell; use argument lists.")
            # open redirect
            if lname in REDIRECT_PARAMS:
                r = self._safe(self.client.get, self._inject(base, params, name, TEST_ORIGIN + "/x"))
                self._cov("Open redirect", tested=1)
                if r and 300 <= r.status < 400 and up.urlparse(
                        r.headers.get("location", "")).hostname == "scopeguard.invalid":
                    self._cov("Open redirect", found=1, note=f"param {name} at {base}")
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
                    self._cov("Path traversal", tested=1)
                    if r and re.search(r"root:[x*]:0:0:", r.body):
                        self._cov("Path traversal", found=1, note=f"param {name} at {base}")
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
            for url, code in blobs + [(pg.url, pg.resp.body)]:
                for m in ENDPOINT_RX.finditer(code):
                    absu = _norm(up.urljoin(pg.url, m.group(1)))
                    if absu.startswith(("http://", "https://")):
                        self.endpoints.setdefault(absu, url.split(" ")[0])
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

    def _upload_forms(self):
        """Forms with a file input: (action_url, file_field, other_fields, accept, max_declared)."""
        out = []
        for pg in self.pages:
            for form in pg.forms:
                file_inputs = [i for i in form["inputs"] if i.get("type") == "file"]
                if not file_inputs:
                    continue
                action = form.get("action_abs") or pg.url
                if not self.client.in_scope(action):
                    self._record_external(action)
                    continue
                fields = {i["name"]: (i["value"] or "1") for i in form["inputs"]
                          if i.get("name") and i["type"] not in ("file", "submit", "button", "image")}
                accept = next((i.get("accept", "") for i in file_inputs if i.get("accept")), "")
                max_declared = None
                for i in form["inputs"]:
                    if i.get("name", "").upper() == "MAX_FILE_SIZE" and (i.get("value") or "").isdigit():
                        max_declared = int(i["value"])
                out.append((action, file_inputs[0].get("name") or "file", fields, accept, max_declared))
        return out

    def upload_tests(self, enable_active: bool):
        """Report upload controls (accepted types, declared max size) and, when
        active uploads are enabled, try benign disguised files and note the result."""
        forms = self._upload_forms()
        if not forms:
            return
        marker_root = uuid.uuid4().hex[:8]
        for action, file_field, fields, accept, max_declared in forms:
            self._cov("File upload controls", tested=1)
            self.f.add(source="dast_native", category=A05, severity="info",
                       title="File upload detected",
                       description="A file-upload input was found. Accepted types: "
                                   + (accept or "not restricted client-side") + "; declared max size: "
                                   + (f"{max_declared} bytes" if max_declared else "not declared client-side") + ".",
                       url=action, evidence=f"field={file_field}; accept={accept or '*'}", cwe="CWE-434",
                       confidence="high", recommendation="Validate type and size on the server; store uploads "
                                                         "outside the web root and never execute them.")
            if not enable_active:
                continue
            accepted, executed, size_note = [], [], ""
            for name_tpl, content_tpl, ctype, executable in UPLOAD_PROBES:
                m = f"{marker_root}{uuid.uuid4().hex[:4]}"
                name, content = name_tpl.format(m=m), content_tpl.format(m=m).encode()
                self._cov("File upload bypass", tested=1)
                r = self._safe(self.client.post_multipart, action, fields, file_field, name, content, ctype)
                if not r or r.error or r.status >= 400:
                    continue
                accepted.append(name.split(".", 1)[-1])
                # If the response (or the stored file) echoes the exec marker, it ran.
                if EXEC_MARKER + m in r.body:
                    executed.append(name)
                    continue
                # Where might the file be served from? A path in the response (or
                # Location) that names the file, plus a few common upload folders.
                cands = [c for c in re.findall(r"[/\w.\-]*" + re.escape(name), r.body)]
                loc = r.headers.get("location", "")
                if loc:
                    cands.append(loc)
                cands += [d + name for d in ("", "uploads/", "upload/", "files/", "file/", "media/",
                                             "images/", "img/", "static/", "tmp/", "data/")]
                tried = set()
                for cand in cands:
                    g_url = up.urljoin(action, cand)
                    if g_url in tried or not self.client.in_scope(g_url):
                        continue
                    tried.add(g_url)
                    g = self._safe(self.client.get, g_url)
                    if g and EXEC_MARKER + m in g.body:
                        executed.append(name)
                        break
            # size limit probe (benign, compressible)
            big = self._safe(self.client.post_multipart, action, fields, file_field,
                             f"scopeguard-{marker_root}-big.txt", b"A" * (UPLOAD_OVERSIZE_MB * 1024 * 1024),
                             "text/plain")
            if big and not big.error:
                size_note = (f"a {UPLOAD_OVERSIZE_MB} MB file was " +
                             ("rejected" if big.status >= 400 else f"accepted (HTTP {big.status})") +
                             (f"; client declares max {max_declared} bytes" if max_declared else ""))
                self._cov("File upload size limit", tested=1, note=size_note)
            dangerous = [e for e in accepted if e.lower() not in ("txt",)]
            if executed:
                self._cov("File upload bypass", found=1, note=f"executed: {', '.join(executed)}")
                self.f.add(source="dast_native", category=A03, severity="critical",
                           title="Unrestricted file upload leads to code execution",
                           description="An uploaded file with a server-executable extension was executed; the "
                                       "benign marker it printed was returned. A real attacker could upload a web shell.",
                           url=action, evidence="executed: " + ", ".join(executed[:5]), cwe="CWE-434",
                           confidence="high", recommendation="Reject executable extensions, validate content, store "
                                                            "uploads outside the web root, and serve them non-executable.")
            elif dangerous:
                self._cov("File upload bypass", found=1, note=f"accepted: {', '.join(dangerous)}")
                self.f.add(source="dast_native", category=A05, severity="high",
                           title="File upload accepts dangerous/disguised file types",
                           description="The server accepted uploads with dangerous or disguised extensions "
                                       "(" + ", ".join(sorted(set(dangerous))[:8]) + "). Execution was not confirmed, "
                                       "but client-side type checks are being bypassed.",
                           url=action, evidence="accepted extensions: " + ", ".join(sorted(set(dangerous))[:8]),
                           cwe="CWE-434", confidence="medium",
                           recommendation="Enforce a server-side allowlist of extensions and content types.")
            if big and not big.error and big.status < 400 and (not max_declared or UPLOAD_OVERSIZE_MB * 1024 * 1024 > (max_declared or 0)):
                self.f.add(source="dast_native", category=A05, severity="low",
                           title="File upload has no effective size limit",
                           description=f"A {UPLOAD_OVERSIZE_MB} MB upload was accepted (HTTP {big.status}); large "
                                       "uploads enable denial of service.", url=action, evidence=size_note,
                           cwe="CWE-400", confidence="medium",
                           recommendation="Enforce a server-side maximum upload size.")

    def probe_endpoints(self, limit: int = 40):
        """GET in-scope backend endpoints found in HTML/JS (others recorded, never fetched).
        Endpoints with query parameters join the active attack targets."""
        crawled = {p.url for p in self.pages}
        notes = []
        for url in list(self.endpoints)[:200]:
            if not self.client.in_scope(url):
                self._record_external(url)
                notes.append(f"{url} (other host, not fetched)")
                continue
            if url in crawled or limit <= 0:
                continue
            limit -= 1
            r = self._safe(self.client.get, url)
            self._cov("Backend endpoint discovery", tested=1)
            if not r:
                continue
            notes.append(f"{up.urlparse(url).path or '/'}{'?' + up.urlparse(url).query if up.urlparse(url).query else ''}: {r.status}")
            if r.status < 400:
                self.pages.append(Page(url=url, resp=r))
                crawled.add(url)
        if self.endpoints:
            self._cov("Backend endpoint discovery", found=0, note=f"{len(self.endpoints)} endpoint(s) referenced")
            self.f.add(source="recon", category=OTHER, severity="info",
                       title="Backend/API endpoints referenced by the frontend",
                       description=f"{len(self.endpoints)} backend endpoint(s) are referenced in HTML/JS. In-scope "
                                   "ones were requested and tested; others were not fetched.",
                       url=self.origin + "/", evidence="; ".join(notes[:20]), cwe="CWE-200", confidence="high",
                       recommendation="Make sure every listed endpoint enforces authentication and authorization.")

    # ---- orchestration ---------------------------------------------------
    def run(self) -> dict:
        t0 = time.time()
        self.crawl()
        if not self.pages:
            self.red_flags.append("Crawl reached no pages; target unreachable or fully out of scope.")
        self.passive()
        self.sast()
        self.probe_endpoints()
        self.http_checks()
        if self.cfg["active"]:
            self.active()
        if self.cfg.get("uploads") and self.upload_active:
            self.upload_tests(enable_active=True)
        else:
            self.upload_tests(enable_active=False)
        flag = self.client.rate_limit.red_flag()
        if flag:
            self.red_flags.append(flag)
        if self.client.dropped:
            self._cov("File downloads refused (body discarded unread)", tested=len(self.client.dropped))
            for url, why in self.client.dropped[:10]:
                self._cov("File downloads refused (body discarded unread)", note=f"{url}: {why}")
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
            "attack_summary": self.coverage,
            "endpoints": sorted(self.endpoints),
            "profile": self.profile,
        }


def run_scan(target_url, allowed_domains, profile="standard", bearer=None, delay=0.05,
             max_pages=None, max_requests=None, upload_active=False, cookie=None) -> dict:
    return Scanner(target_url, allowed_domains, profile, bearer, delay, max_pages, max_requests,
                   upload_active=upload_active, cookie=cookie).run()


if __name__ == "__main__":  # pragma: no cover
    import sys
    print(json.dumps(run_scan(sys.argv[1], [up.urlparse(sys.argv[1]).netloc]), indent=2))
