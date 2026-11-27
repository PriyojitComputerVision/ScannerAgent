"""Guardrails for the MCP chatbot (standard library only).

Three layers, all deterministic (no LLM call, so they cost no tokens and cannot be
talked out of their decision):

1. ``check_input``: runs on every user message *before* it reaches the model.
   Blocks jailbreaks, prompt-injection and prompt-leak attempts, attempts to skip the
   human approval, injection payloads (SQL, shell, script/XSS, template, path
   traversal), pasted secrets and over-long input. Text is normalized first (Unicode
   NFKC, zero-width and bidi control characters removed) so look-alike or hidden
   characters cannot smuggle a pattern past the checks. A blocked message is never
   sent to the model and never stored in the conversation.
2. ``check_tool_args``: runs before every tool call (the model's own calls and calls a
   reviewer edited). Only well-formed values pass: http(s) target URLs without
   credentials or markup, the four scan profiles, safe ids and names. Inline secrets
   are refused.
3. ``check_output``: runs on the model's final answer. A reply that reproduces the
   system prompt is withdrawn; anything that looks like a secret is redacted.

These are filters for a chat assistant, not the scanner's security boundary: the
scanner enforces its own allowlist, authorization, RBAC and sandboxing regardless.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

MAX_INPUT_CHARS = 4000
SCAN_PROFILES = ("quick", "standard", "aggressive", "auth_deep")
SCAN_SCOPES = ("website_and_code", "website", "code")

# Zero-width, bidi override/isolate and other invisible format characters.
_INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e"
                        "\u2060-\u2064\u2066-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def normalize(text: str) -> str:
    """NFKC (full-width / look-alike forms folded), invisible and control characters
    removed, whitespace collapsed. Used for matching only."""
    text = unicodedata.normalize("NFKC", text or "")
    text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def _rx(*patterns: str) -> list[re.Pattern]:
    return [re.compile(p, re.IGNORECASE) for p in patterns]


# --------------------------------------------------------------------------- input rules
_JAILBREAK = _rx(
    r"\b(ignore|disregard|forget|override|bypass)\b.{0,40}\b(previous|prior|above|earlier|all|any|your|the|these)\b"
    r".{0,30}\b(instructions?|rules|prompts?|guidelines|guardrails|polic(y|ies)|restrictions|directives)\b",
    r"\byou are (now )?(dan|jailbroken|unrestricted|unfiltered|in developer mode|free of (all )?rules)\b",
    r"\b(do anything now|developer mode|jailbreak|god mode|sudo mode)\b",
    r"\b(pretend|act|behave|roleplay)\b.{0,40}\b(no|without|free of)\b.{0,20}\b(rules|restrictions|limits|filters|"
    r"guardrails|safety)\b",
    r"\bfrom now on\b.{0,40}\b(you (will|must|should)|ignore|answer without)\b",
    r"\b(new|updated|real|actual) system (prompt|message|instructions)\b",
    r"(<\|?(im_start|im_end|system|endoftext)\|?>|\[/?(system|inst)\]|^\s*#{2,}\s*system\b|\bsystem\s*:\s*you are)",
)
_PROMPT_LEAK = _rx(
    r"\b(show|print|reveal|repeat|output|display|dump|leak|list|tell me|give me|share|copy|paste|translate|summari[sz]e)"
    r"\b.{0,40}\b(system prompt|initial prompt|hidden prompt|developer (prompt|message)|your (prompt|instructions|"
    r"rules|guidelines|configuration)|the instructions (you were given|above))\b",
    r"\bwhat (is|are|were) (your|the) (system prompt|instructions|initial prompt|hidden rules)\b",
    r"\b(repeat|print|output) (everything|all|the text|the words) (above|before|so far)\b",
    r"\bverbatim\b.{0,40}\b(prompt|instructions)\b",
)
_APPROVAL_BYPASS = _rx(
    r"\bauthori[sz]ation_confirmed\b\s*[:=]?\s*(true|1|yes)\b",
    r"\b(skip|bypass|disable|without|no need for)\b.{0,20}\b(the )?(approval|confirmation|human review|authori[sz]ation)\b",
    r"\bauto[- ]?approve\b",
    r"\b(don'?t|do not|never) ask (me )?(for )?(approval|confirmation|permission)\b",
)
_SQL = _rx(
    r"['\"`]\s*\)?\s*(or|and)\s+['\"`]?\w+['\"`]?\s*(=|like|<|>)\s*['\"`]?\w+",
    r"\bunion\b(\s+all)?\s+select\b",
    r";\s*(drop|delete|truncate|alter|insert|update|create|exec(ute)?|grant)\s+\w+",
    r"['\"`]\s*;?\s*(--|#|/\*)",
    r"\b(sleep|pg_sleep|benchmark)\s*\(\s*\d+",
    r"\bwaitfor\s+delay\b",
    r"\b(xp_cmdshell|information_schema|sysobjects|load_file|into\s+(out|dump)file)\b",
    r"\bselect\b.{0,60}\bfrom\b.{0,60}\bwhere\b.{0,40}(=|like)",
)
_COMMAND = _rx(
    r"(;|&&|\|\||\|)\s*(rm|curl|wget|nc|ncat|netcat|bash|sh|zsh|powershell|pwsh|cmd|python\d?|perl|chmod|"
    r"chown|cat|whoami|certutil|bitsadmin)\b",
    r"\$\([^)]{1,200}\)",
    r"\brm\s+-[rf]{1,2}\b",
    r"\b(eval|exec|system|popen|subprocess|os\.system|__import__)\s*\(",
)
_SCRIPT = _rx(
    r"<\s*/?\s*(script|iframe|object|embed|svg|img|body|style|link|meta|base|form)\b",
    r"\bjavascript\s*:",
    r"\bvbscript\s*:",
    r"\bdata\s*:\s*text/html",
    r"\bon(error|load|click|mouseover|focus|blur|submit|input|change)\s*=",
)
_TEMPLATE = _rx(r"\{\{.{0,200}\}\}", r"\{%.{0,200}%\}", r"\$\{.{0,200}\}", r"<%.{0,200}%>")
_TRAVERSAL = _rx(r"(\.\.[\\/]){2,}", r"%2e%2e(%2f|%5c)", r"\b(etc/passwd|etc/shadow|win\.ini|boot\.ini)\b")
_SECRET = _rx(
    r"\bgsk_[A-Za-z0-9]{20,}",
    r"\bsk-(proj-|ant-)?[A-Za-z0-9_-]{20,}",
    r"\blsv2_[a-z]{2}_[A-Za-z0-9]{16,}",
    r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    r"\bgh[pousr]_[A-Za-z0-9]{30,}",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"\b(password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*\S{4,}",
)

# (category, patterns, message shown to the user). Order: most specific first.
_INPUT_RULES = [
    ("secret", _SECRET,
     ("Your message looks like it contains a secret (API key, token, private key or password). Don't paste "
     "secrets into the chat: they would be sent to the language model. For signed-in scans, the operator stores "
     "a credential profile (scopeguard-mcp credentials add) and you only name it.")),
    ("jailbreak", _JAILBREAK,
     ("This looks like an attempt to change or override the assistant's rules. The rules can't be changed from "
     "the chat. Ask about a scan, a finding or a report instead.")),
    ("prompt_leak", _PROMPT_LEAK,
     "The assistant's instructions are not shared. Ask what it can do instead, e.g. \"what can you scan?\"."),
    ("approval_bypass", _APPROVAL_BYPASS,
     ("Scans can't skip the human approval: every scan waits for you to confirm, in the approval form, that you own "
     "or may test the site. Just ask for the scan and approve it there.")),
    ("sql_injection", _SQL,
     ("Your message contains what looks like a SQL injection payload. The assistant doesn't send or craft attack "
     "payloads; the scanner runs its own safe, built-in checks. Ask it to scan the site instead.")),
    ("command_injection", _COMMAND,
     ("Your message contains what looks like a shell or code-execution payload. The assistant never runs commands; "
     "ask it to scan a site or explain a finding instead.")),
    ("script_injection", _SCRIPT,
     ("Your message contains HTML or script markup (possible XSS payload). The assistant doesn't relay markup; "
     "describe what you want to check in plain words.")),
    ("template_injection", _TEMPLATE,
     ("Your message contains template expressions ({{ }}, ${ }). The assistant doesn't relay them; describe what "
     "you want to check in plain words.")),
    ("path_traversal", _TRAVERSAL,
     ("Your message contains a path-traversal pattern. The assistant doesn't relay it; the scanner runs its own "
     "safe traversal checks during a scan.")),
]


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    category: str = ""
    message: str = ""
    text: str = ""  # the cleaned text to send (invisible/control characters removed)


def check_input(text: str) -> Verdict:
    """Pre-guardrail for a user message. ``allowed=False`` means: do not send it to the model."""
    raw = text or ""
    if len(raw) > MAX_INPUT_CHARS:
        return Verdict(False, "too_long", f"Your message is longer than {MAX_INPUT_CHARS} characters. "
                                          "Please shorten it.")
    norm = normalize(raw)
    if not norm:
        return Verdict(False, "empty", "Your message is empty.")
    for category, patterns, message in _INPUT_RULES:
        if any(p.search(norm) for p in patterns):
            return Verdict(False, category, message)
    clean = _CONTROL.sub(" ", _INVISIBLE.sub("", unicodedata.normalize("NFC", raw))).strip()
    return Verdict(True, text=clean)


# --------------------------------------------------------------------------- tool arguments
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*(:\d{1,5})?$")
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_URL_BAD_CHARS = re.compile(r"[\s'\"<>`\\{}|^]")


def _check_url(url) -> str | None:
    if not isinstance(url, str) or not url or len(url) > 2048:
        return "target_url must be an http(s) URL (at most 2048 characters)"
    if _URL_BAD_CHARS.search(url) or _INVISIBLE.search(url) or _CONTROL.search(url):
        return "target_url contains characters a URL must not have (spaces, quotes, markup)"
    try:
        parts = urlsplit(url)
    except ValueError:
        return "target_url is not a valid URL"
    if parts.scheme.lower() not in ("http", "https"):
        return "target_url must start with http:// or https://"
    if "@" in parts.netloc:
        return "target_url must not contain credentials (user:password@)"
    if not _HOST_RE.match(parts.netloc.lower()):
        return "target_url has an invalid host name"
    full = normalize(url)
    for _cat, patterns, _msg in _INPUT_RULES[4:]:  # injection payloads hidden in the URL
        if any(p.search(full) for p in patterns):
            return "target_url contains an injection payload; give the plain address of the site"
    return None


_UPLOAD_RE = re.compile(r"^[a-f0-9]{32}$")
# A public https repository (no credentials, port, query); the scanner checks its host allowlist.
# Only .git clone links (the scanner validates the same with its GitLink model).
_GIT_URL_RE = re.compile(r"^https://[a-z0-9.-]{1,253}(?:/[A-Za-z0-9_.-]{1,100}){1,5}/[A-Za-z0-9_.-]{1,100}\.git$",
                         re.IGNORECASE)
_GIT_REF_RE = re.compile(r"^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,200}$")


def _check_id(value, field: str) -> str | None:
    if not isinstance(value, str) or not _ID_RE.match(value):
        return f"{field} must be a scan id like mcp-1a2b3c4d5e6f"
    return None


def check_tool_args(name: str, args: dict | None) -> str | None:
    """Pre-guardrail for a tool call. Returns a reason to refuse it, or None."""
    args = args or {}
    if name == "start_scan":
        # A source-code-only scan needs no website: target_url may be left out.
        code_only_no_url = args.get("scan_scope") == "code" and not args.get("target_url")
        problem = None if code_only_no_url else _check_url(args.get("target_url"))
        if problem:
            return problem
        if args.get("jwt") or args.get("login"):
            return "inline credentials are not accepted from the chat; use a credential profile name"
        cred = args.get("credentials")
        if cred is not None and (not isinstance(cred, str) or not _NAME_RE.match(cred)):
            return "credentials must be a credential profile name (letters, digits, - and _)"
        for host in args.get("additional_allowed_domains") or []:
            if not isinstance(host, str) or not _HOST_RE.match(host.lower()):
                return f"invalid additional domain: {str(host)[:60]!r}"
    if name in ("start_scan", "start_demo_scan") and args.get("profile", "standard") not in SCAN_PROFILES:
        return f"profile must be one of: {', '.join(SCAN_PROFILES)}"
    if name == "start_demo_scan" and not isinstance(args.get("sign_in", False), bool):
        return "sign_in must be true or false"
    needs_upload = name == "start_scan" and args.get("upload_id") is not None
    if needs_upload and not (isinstance(args.get("upload_id"), str) and _UPLOAD_RE.match(args["upload_id"])):
        return "upload_id must be the 32-character id of an uploaded archive"
    if name == "start_scan" and args.get("git_url") is not None:
        if args.get("upload_id") is not None:
            return "pass either upload_id or git_url, not both"
        if not (isinstance(args["git_url"], str) and _GIT_URL_RE.match(args["git_url"])):
            return "git_url must be a public repository's .git clone link, e.g. https://github.com/owner/repo.git"
    if name == "start_scan" and args.get("scan_scope") is not None:
        if args["scan_scope"] not in SCAN_SCOPES:
            return f"scan_scope must be one of: {', '.join(SCAN_SCOPES)}"
        has_code = args.get("upload_id") is not None or args.get("git_url") is not None
        if args["scan_scope"] != "website" and not has_code:
            return "scan_scope website_and_code / code needs source code (an attached .zip or a git_url)"
        if args["scan_scope"] == "website" and has_code:
            return "scan_scope website tests no source code: drop upload_id / git_url"
    if name == "start_scan" and args.get("git_ref") is not None and not (
            isinstance(args["git_ref"], str) and _GIT_REF_RE.match(args["git_ref"])):
        return "git_ref must be a branch or tag name"
    if name in ("get_scan", "cancel_scan", "watch_scan"):
        return _check_id(args.get("scan_id"), "scan_id")
    if name == "get_report":
        return _check_id(args.get("session_id"), "session_id") or (
            None if args.get("format", "md") in ("md", "json") else "format must be md or json")
    if name == "list_reports" and not (isinstance(args.get("limit", 20), int) and 1 <= args.get("limit", 20) <= 100):
        return "limit must be a number from 1 to 100"
    return None


# --------------------------------------------------------------------------- output
_LEAK_NOTICE = ("I can't share my instructions. I can scan sites you're authorized to test, follow a scan, "
                "and explain its findings and reports.")


def _prompt_lines(prompts: list[str]) -> list[str]:
    lines = []
    for prompt in prompts:
        for line in (prompt or "").splitlines():
            norm = normalize(line).lower().lstrip("-*0123456789. ")
            if len(norm) >= 50:
                lines.append(norm[:120])
    return lines


def check_output(text: str, prompts: list[str]) -> tuple[str, str | None]:
    """Post-guardrail for a final answer. Returns (safe_text, reason or None)."""
    norm = normalize(text).lower()
    if any(line in norm for line in _prompt_lines(prompts)):
        return _LEAK_NOTICE, "prompt_leak"
    redacted, hits = text, 0
    for pattern in _SECRET:
        redacted, n = pattern.subn("[redacted]", redacted)
        hits += n
    return redacted, ("secret_redacted" if hits else None)
