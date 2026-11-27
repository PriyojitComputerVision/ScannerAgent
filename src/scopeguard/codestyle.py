"""Coding-standard check (PEP 8) for Python source in the code SAST step. Stdlib only.

Runs inside the sandbox analyzer (``codecheck.scan_source``) next to the security rules, so it is
shipped in the analyzer ConfigMap (``k8s.ANALYZER_MODULES``) and must not import anything outside
the standard library. The code is parsed (``ast``, ``tokenize``), never executed.

Each rule is reported **once per file** with a count and the first line numbers, so a long file
with hundreds of long lines yields one finding, not hundreds. Style findings are ``info`` (``low``
for the ones that hide bugs: bare ``except``, mutable defaults, wildcard imports, a file that does
not parse) and are capped per scan (:data:`MAX_STYLE_FINDINGS`) so they never crowd out security
findings.
"""
from __future__ import annotations

import ast
import io
import re
import tokenize

PEP8_URL = "https://peps.python.org/pep-0008/"
MAX_LINE_LENGTH = 79          # PEP 8: "Limit all lines to a maximum of 79 characters."
MAX_STYLE_FINDINGS = 150      # per scan, across all files
MAX_LINES_LISTED = 8
CATEGORY = "Other"
STYLE_CWE = "CWE-1078"        # Inappropriate Source Code Style or Formatting

# rule id -> (PEP 8 / pycodestyle code, severity, title, recommendation, CWE)
STYLE_RULES: dict[str, tuple[str, str, str, str, str]] = {
    "STYLE_LINE_TOO_LONG": ("E501", "info", f"line longer than {MAX_LINE_LENGTH} characters",
                            (f"Wrap lines at {MAX_LINE_LENGTH} characters (PEP 8 'Maximum Line Length'), using implied "
                            "line continuation inside parentheses rather than backslashes."), STYLE_CWE),
    "STYLE_TAB_INDENT": ("W191", "info", "indentation uses tabs",
                         "Indent with 4 spaces per level (PEP 8 'Tabs or Spaces?'); never mix tabs and spaces.",
                         STYLE_CWE),
    "STYLE_INDENT_NOT_4": ("E111", "info", "indentation is not a multiple of four",
                           "Use 4 spaces per indentation level (PEP 8 'Indentation').", STYLE_CWE),
    "STYLE_TRAILING_WHITESPACE": ("W291", "info", "trailing whitespace",
                                  ("Remove trailing whitespace (PEP 8 'Other Recommendations'); configure the editor "
                                  "to strip it on save."), STYLE_CWE),
    "STYLE_NO_FINAL_NEWLINE": ("W292", "info", "no newline at end of file",
                               "End every file with a single newline.", STYLE_CWE),
    "STYLE_MULTIPLE_IMPORTS": ("E401", "info", "multiple imports on one line",
                               "Put each import on its own line (PEP 8 'Imports'): 'import os' and 'import sys'.",
                               STYLE_CWE),
    "STYLE_WILDCARD_IMPORT": ("F403", "low", "wildcard import",
                              ("Avoid 'from module import *' (PEP 8 'Imports'): import the names you use, so "
                              "readers and tools know where each name comes from."), STYLE_CWE),
    "STYLE_BARE_EXCEPT": ("E722", "low", "bare except",
                          ("Catch specific exceptions (PEP 8 'Programming Recommendations'); a bare 'except:' also "
                          "catches SystemExit and KeyboardInterrupt and hides bugs."), "CWE-396"),
    "STYLE_COMPARE_TO_NONE": ("E711", "info", "comparison to None with == / !=",
                              "Compare to None with 'is' / 'is not' (PEP 8 'Programming Recommendations').",
                              STYLE_CWE),
    "STYLE_COMPARE_TO_BOOL": ("E712", "info", "comparison to True / False with == / !=",
                              "Don't compare booleans to True or False with '=='; use 'if x:' / 'if not x:'.",
                              STYLE_CWE),
    "STYLE_LAMBDA_ASSIGNMENT": ("E731", "info", "lambda assigned to a name",
                                ("Use a 'def' statement instead of assigning a lambda to a name (PEP 8 "
                                "'Programming Recommendations')."), STYLE_CWE),
    "STYLE_MUTABLE_DEFAULT": ("B006", "low", "mutable default argument",
                              ("Don't use a mutable default ([] / {} / set()): it is shared between calls. Default to "
                              "None and create the object inside the function."), "CWE-1188"),
    "STYLE_CLASS_NAME": ("N801", "info", "class name is not CapWords",
                         "Name classes in CapWords (PEP 8 'Naming Conventions'), e.g. OrderService.", STYLE_CWE),
    "STYLE_FUNCTION_NAME": ("N802", "info", "function name is not lower_case_with_underscores",
                            "Name functions and methods in lower_case_with_underscores (PEP 8 'Naming Conventions').",
                            STYLE_CWE),
    "STYLE_SYNTAX_ERROR": ("E999", "low", "the file does not parse as Python 3",
                           ("Fix the syntax error so the file can be analysed (and run); only the line-based style "
                           "checks were applied to it."), STYLE_CWE),
    # ---- ruff lint rules (Pyflakes F, pycodestyle E741)
    "STYLE_UNUSED_IMPORT": ("F401", "low", "imported but unused",
                            ("Remove unused imports (ruff F401); if the import is a re-export, list it in __all__ "
                            "or import it 'as' itself."), "CWE-1164"),
    "STYLE_UNUSED_VARIABLE": ("F841", "info", "local variable assigned but never used",
                              ("Remove the assignment (ruff F841), or name it '_' when the value is deliberately "
                              "ignored; unused variables often mean a forgotten check."), "CWE-563"),
    "STYLE_FSTRING_NO_PLACEHOLDER": ("F541", "info", "f-string without any placeholders",
                                     "Drop the f prefix (ruff F541), or add the {value} that was meant to be there.",
                                     STYLE_CWE),
    "STYLE_REDEFINED": ("F811", "low", "function or class redefined in the same scope",
                        ("Rename or remove one definition (ruff F811): the later one silently replaces the first, "
                        "so the first is dead code."), "CWE-561"),
    "STYLE_IS_LITERAL": ("F632", "low", "'is' / 'is not' compared with a str, bytes or number literal",
                         ("Use == / != for values (ruff F632); 'is' checks identity, which for literals depends on "
                         "interpreter caching and is a real bug."), "CWE-597"),
    "STYLE_AMBIGUOUS_NAME": ("E741", "info", "ambiguous variable name (l, O or I)",
                             "Don't name variables l, O or I (ruff E741, PEP 8): they look like 1 and 0.", STYLE_CWE),
}
RECOMMENDATIONS = {rid: rule[3] for rid, rule in STYLE_RULES.items()}

# Before/after examples for the report's "How to fix" section (scopeguard.remediation).
EXAMPLES = {
    "STYLE_BARE_EXCEPT": ("try:\n    load()\nexcept:\n    pass",
                          "try:\n    load()\nexcept (OSError, ValueError) as exc:\n    log.warning(\"load failed: %s\", exc)"),
    "STYLE_MUTABLE_DEFAULT": ("def add(item, items=[]):\n    items.append(item)\n    return items",
                              ("def add(item, items=None):\n    items = [] if items is None else items\n"
                              "    items.append(item)\n    return items")),
    "STYLE_WILDCARD_IMPORT": ("from utils import *", "from utils import load_config, parse_args"),
    "STYLE_COMPARE_TO_NONE": ("if user == None:\n    ...", "if user is None:\n    ..."),
    "STYLE_LAMBDA_ASSIGNMENT": ("square = lambda x: x * x", "def square(x):\n    return x * x"),
    "STYLE_MULTIPLE_IMPORTS": ("import os, sys", "import os\nimport sys"),
}

_CAPWORDS = re.compile(r"^_*[A-Z][A-Za-z0-9]*$")
_SNAKE = re.compile(r"^_*[a-z][a-z0-9_]*$|^__[a-z][a-z0-9_]*__$")


def _add(hits: dict[str, list[int]], rid: str, line: int) -> None:
    hits.setdefault(rid, []).append(line)


def _line_checks(text: str, hits: dict[str, list[int]]) -> None:
    lines = text.splitlines()
    for no, line in enumerate(lines, 1):
        if len(line) > MAX_LINE_LENGTH:
            _add(hits, "STYLE_LINE_TOO_LONG", no)
        if line != line.rstrip():
            _add(hits, "STYLE_TRAILING_WHITESPACE", no)
        indent = line[: len(line) - len(line.lstrip(" \t"))]
        if "\t" in indent:
            _add(hits, "STYLE_TAB_INDENT", no)
    if text and not text.endswith("\n"):
        _add(hits, "STYLE_NO_FINAL_NEWLINE", len(lines))


def _indent_checks(text: str, hits: dict[str, list[int]]) -> None:
    """Indentation from INDENT tokens only (continuation lines are free to align)."""
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.INDENT and "\t" not in tok.string and len(tok.string) % 4:
                _add(hits, "STYLE_INDENT_NOT_4", tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        pass


class _Visitor(ast.NodeVisitor):
    def __init__(self, hits: dict[str, list[int]]) -> None:
        self.hits = hits

    def visit_Import(self, node: ast.Import) -> None:
        if len(node.names) > 1:
            _add(self.hits, "STYLE_MULTIPLE_IMPORTS", node.lineno)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if any(alias.name == "*" for alias in node.names):
            _add(self.hits, "STYLE_WILDCARD_IMPORT", node.lineno)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is None:
            _add(self.hits, "STYLE_BARE_EXCEPT", node.lineno)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        operands = [node.left, *node.comparators]
        for i, op in enumerate(node.ops):
            if not isinstance(op, ast.Eq | ast.NotEq):
                continue
            # either side: "x == None" and "None == x" are both flagged
            for side in (operands[i], operands[i + 1]):
                if isinstance(side, ast.Constant) and side.value is None:
                    _add(self.hits, "STYLE_COMPARE_TO_NONE", node.lineno)
                elif isinstance(side, ast.Constant) and isinstance(side.value, bool):
                    _add(self.hits, "STYLE_COMPARE_TO_BOOL", node.lineno)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Lambda) and all(isinstance(t, ast.Name) for t in node.targets):
            _add(self.hits, "STYLE_LAMBDA_ASSIGNMENT", node.lineno)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if not _CAPWORDS.match(node.name):
            _add(self.hits, "STYLE_CLASS_NAME", node.lineno)
        self.generic_visit(node)

    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # visit_* / do_* / setUp-style overrides of framework APIs are not the author's choice
        if not _SNAKE.match(node.name) and not node.name.startswith(("visit_", "do_", "setUp", "tearDown")):
            _add(self.hits, "STYLE_FUNCTION_NAME", node.lineno)
        defaults = [*node.args.defaults, *(d for d in node.args.kw_defaults if d is not None)]
        if any(isinstance(d, ast.List | ast.Dict | ast.Set)
               or (isinstance(d, ast.Call) and isinstance(d.func, ast.Name) and d.func.id in ("list", "dict", "set"))
               for d in defaults):
            _add(self.hits, "STYLE_MUTABLE_DEFAULT", node.lineno)
        self.generic_visit(node)

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function


# ---------------------------------------------------------------- ruff lint rules (ast, never executed)
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_NOT_REDEFINITION = re.compile(r"overload|setter|getter|deleter|register|dispatch")


def _shallow(node: ast.AST):
    """Every node inside ``node`` except the insides of nested functions, classes and lambdas."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        yield child
        if not isinstance(child, _SCOPES):
            stack.extend(ast.iter_child_nodes(child))


def _annotation_names(tree: ast.AST) -> set[str]:
    """Names used inside string annotations ("Order", "list[Item]"): they count as used imports."""
    out: set[str] = set()
    for node in ast.walk(tree):
        anns = []
        if isinstance(node, _FUNCS):
            anns = [a.annotation for a in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)]
            anns.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            anns = [node.annotation]
        for ann in anns:
            for sub in ast.walk(ann) if ann is not None else ():
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    out.update(re.findall(r"[A-Za-z_]\w*", sub.value))
    return out


def _unused_imports(tree: ast.Module, hits: dict[str, list[int]]) -> None:
    """F401: module-level imports no code refers to (re-exports via __all__ or 'import x as x' are kept)."""
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | _annotation_names(tree)
    for node in ast.walk(tree):  # __all__ = ["name", ...]
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            used |= {e.value for e in ast.walk(node.value) if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    body = [n for n in tree.body]
    for node in tree.body:  # imports inside top-level try/if blocks count too
        if isinstance(node, ast.Try | ast.If):
            body += [n for n in ast.walk(node) if isinstance(n, ast.Import | ast.ImportFrom)]
    for node in body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            continue
        if isinstance(node, ast.Import | ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*" or (alias.asname and alias.asname == alias.name.split(".")[-1]):
                    continue
                bound = alias.asname or (alias.name.split(".")[0] if isinstance(node, ast.Import) else alias.name)
                if bound not in used:
                    _add(hits, "STYLE_UNUSED_IMPORT", node.lineno)


def _unused_variables(fn: ast.FunctionDef | ast.AsyncFunctionDef, hits: dict[str, list[int]]) -> None:
    """F841: a local assigned with a plain 'name = ...' and never read (closures count as reads)."""
    nodes = list(_shallow(fn))
    if any(isinstance(n, ast.Global | ast.Nonlocal) for n in nodes) or any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("locals", "vars")
            for n in nodes):
        return
    loads = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    for n in nodes:
        targets = n.targets if isinstance(n, ast.Assign) else [n.target] if (
            isinstance(n, ast.AnnAssign) and n.value is not None) else []
        for t in targets:
            if isinstance(t, ast.Name) and not t.id.startswith("_") and t.id not in loads:
                _add(hits, "STYLE_UNUSED_VARIABLE", n.lineno)


def _redefinitions(body: list[ast.stmt], hits: dict[str, list[int]]) -> None:
    """F811: the same function / class name defined twice in one block (overloads, property setters and
    singledispatch registrations are not redefinitions)."""
    seen: dict[str, ast.AST] = {}
    for node in body:
        if not isinstance(node, (*_FUNCS, ast.ClassDef)):
            continue
        decorators = " ".join(ast.dump(d) for d in getattr(node, "decorator_list", []))
        if node.name in seen and not _NOT_REDEFINITION.search(decorators):
            _add(hits, "STYLE_REDEFINED", node.lineno)
        seen[node.name] = node


def _lint_checks(tree: ast.Module, hits: dict[str, list[int]]) -> None:
    _unused_imports(tree, hits)
    format_specs = {id(n.format_spec) for n in ast.walk(tree)
                    if isinstance(n, ast.FormattedValue) and n.format_spec is not None}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, *_FUNCS)):
            _redefinitions(node.body, hits)
        if isinstance(node, ast.JoinedStr) and id(node) not in format_specs \
                and not any(isinstance(v, ast.FormattedValue) for v in node.values):
            _add(hits, "STYLE_FSTRING_NO_PLACEHOLDER", node.lineno)
        elif isinstance(node, ast.Compare):
            operands = [node.left, *node.comparators]
            for i, op in enumerate(node.ops):
                if isinstance(op, ast.Is | ast.IsNot) and any(
                        isinstance(s, ast.Constant) and isinstance(s.value, str | bytes | int | float)
                        and not isinstance(s.value, bool) for s in (operands[i], operands[i + 1])):
                    _add(hits, "STYLE_IS_LITERAL", node.lineno)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id in ("l", "O", "I") or isinstance(node, ast.arg) and node.arg in ("l", "O", "I"):
            _add(hits, "STYLE_AMBIGUOUS_NAME", node.lineno)
        elif isinstance(node, _FUNCS):
            _unused_variables(node, hits)


def check_python(text: str) -> dict[str, list[int]]:
    """Rule id -> line numbers (1-based) of PEP 8 and ruff lint issues in one Python file."""
    hits: dict[str, list[int]] = {}
    _line_checks(text, hits)
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError) as exc:
        _add(hits, "STYLE_SYNTAX_ERROR", int(getattr(exc, "lineno", 0) or 1))
        return hits
    _indent_checks(text, hits)
    _Visitor(hits).visit(tree)
    _lint_checks(tree, hits)
    return hits


def findings_for_file(text: str, where: str) -> list[dict]:
    """One finding per rule for this file (count + first line numbers), most serious first."""
    out = []
    lines = text.splitlines()
    for rid, line_nos in sorted(check_python(text).items(),
                                key=lambda kv: (STYLE_RULES[kv[0]][1] != "low", kv[0])):
        code, severity, title, recommendation, cwe = STYLE_RULES[rid]
        standard = code_label(code)
        line_nos = sorted(set(line_nos))
        shown = ", ".join(str(n) for n in line_nos[:MAX_LINES_LISTED])
        more = f" (+{len(line_nos) - MAX_LINES_LISTED} more)" if len(line_nos) > MAX_LINES_LISTED else ""
        first = line_nos[0]
        evidence = lines[first - 1][:200].rstrip() if 0 < first <= len(lines) else ""
        out.append({
            "rid": rid, "severity": severity, "category": CATEGORY, "cwe": cwe,
            "title": f"{rid}: {title} ({standard})",
            "description": (f"Coding standard ({standard}): {title}, {len(line_nos)} time(s) in this file; "
                            f"line(s) {shown}{more}. Style issues make code harder to review, and some hide bugs."),
            "line": first, "evidence": evidence, "recommendation": recommendation})
    return out


_RUFF_FAMILIES = {"F": "Pyflakes", "E741": "pycodestyle"}


def code_label(code: str) -> str:
    """'PEP 8 E501'; B-codes are flake8-bugbear checks that go beyond PEP 8; the ruff lint rules are named
    after their family ('ruff F401 (Pyflakes)'). F403 stays 'PEP 8' (PEP 8 itself says no wildcard imports)."""
    if code.startswith("B"):
        return f"flake8-bugbear {code}"
    if code != "F403":
        for prefix, family in _RUFF_FAMILIES.items():
            if code.startswith(prefix):
                return f"ruff {code} ({family})"
    return f"PEP 8 {code}"


def summary(findings: list[dict]) -> dict:
    """Coding-standard overview for the report: files with issues, and per rule the files it was found in."""
    style = [f for f in findings if str(f.get("title", "")).startswith("STYLE_")]
    files_by_rule: dict[str, int] = {}
    files = set()
    for f in style:
        rid = str(f["title"]).split(":", 1)[0]
        files_by_rule[rid] = files_by_rule.get(rid, 0) + 1
        files.add(str(f.get("affected_url") or "").split("#", 1)[0])
    return {"standard": "PEP 8", "reference": PEP8_URL, "max_line_length": MAX_LINE_LENGTH,
            "files_with_issues": len(files), "files_by_rule": dict(sorted(files_by_rule.items())),
            "codes": {rid: STYLE_RULES[rid][0] for rid in files_by_rule if rid in STYLE_RULES}}
