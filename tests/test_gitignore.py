"""The project's .gitignore decides what the code SAST leaves out (scopeguard/gitignore.py)."""
from __future__ import annotations

import io
import tempfile
import zipfile

import pytest

from scopeguard import archive, codecheck
from scopeguard.gitignore import GitIgnore

RULES = """
# secrets / env
.env
*.env
!.env.example
CLAUDE.md
!src/pkg/CLAUDE.md
__pycache__/
*.py[cod]
build/
/data/
keys/
*.log
docs/**/draft-*.txt
"""


@pytest.fixture
def ignore() -> GitIgnore:
    g = GitIgnore()
    g.add(RULES)
    return g


@pytest.mark.parametrize("path, ignored", [
    (".env", True), ("app/prod.env", True), (".env.example", False),
    ("CLAUDE.md", True), ("src/pkg/CLAUDE.md", False), ("other/CLAUDE.md", True),
    ("app/__pycache__/x.cpython-312.pyc", True), ("app/x.pyc", True), ("app/x.py", False),
    ("build/out.js", True), ("src/build/out.js", True),      # unanchored folder: any depth
    ("data/report.json", True), ("src/data/x.py", False),    # anchored: only at the root
    ("keys/private.pem", True), ("server.log", True),
    ("docs/a/b/draft-1.txt", True), ("docs/final.txt", False),
])
def test_gitignore_rules(ignore, path, ignored):
    assert ignore.ignored(path) is ignored


def test_files_in_an_ignored_folder_cannot_be_re_included():
    g = GitIgnore()
    g.add("vendor/\n!vendor/keep.py\n")
    assert g.ignored("vendor/keep.py")


def test_nested_gitignore_applies_to_its_folder_only():
    g = GitIgnore()
    g.add("*.gen.py\n", "pkg")
    assert g.ignored("pkg/a.gen.py") and g.ignored("pkg/sub/b.gen.py") and not g.ignored("other/a.gen.py")


def test_dir_only_rule_does_not_match_a_file():
    g = GitIgnore()
    g.add("logs/\n")
    assert g.ignored("logs/a.py") and not g.ignored("logs")


def test_scan_source_honours_the_projects_gitignore(tmp_path):
    (tmp_path / ".gitignore").write_text("generated/\nlocal_*.py\n", encoding="utf-8")
    (tmp_path / "generated").mkdir()
    (tmp_path / "generated" / "x.py").write_text("x = eval(data)\n", encoding="utf-8")
    (tmp_path / "local_settings.py").write_text("y = eval(data)\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("z = eval(data)\n", encoding="utf-8")
    res = codecheck.Results()
    codecheck.scan_source(res, str(tmp_path), codecheck.Progress())
    assert {f["affected_url"].split("#")[0] for f in res.findings} == {"source/app.py"}


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_uploads_are_extracted_without_gitignored_files():
    data = _zip({"proj/.gitignore": b"secrets/\n*.local.py\n", "proj/app.py": b"x = 1\n",
                 "proj/secrets/api.py": b"KEY = 'x'\n", "proj/settings.local.py": b"y = 2\n"})
    with tempfile.TemporaryDirectory() as d:
        rep = archive.inspect_and_extract(data, d)
    assert rep.extracted == ["proj/app.py"] and rep.stats["gitignored"] == 2


def test_documents_diagrams_and_images_are_not_analysed():
    for name in ("notes.txt", "spec.pdf", "design.docx", "old.doc", "flow.mmd", "logo.png", "photo.JPEG",
                 "icon.svg", "README.md"):
        assert codecheck.is_not_analysed(name), name
    for name in ("model.pkl", "weights.pt", "best.pth", "m.safetensors", "m.h5", "m.onnx", "m.tflite", "e.npy",
                 "m.keras", "m.ckpt", "model.ckpt.index", "model.ckpt.meta", "model.ckpt-1000.data-00000-of-00001",
                 "variables/variables.index", "variables/variables.data-00000-of-00001", "saved_model.pb"):
        assert codecheck.is_not_analysed(name) and codecheck.is_model_weight(name), name
    assert not codecheck.is_model_weight("app/index.js") and not codecheck.is_model_weight("checkpoints.py")
    for name in ("app.py", "index.js", "config.yml", "Dockerfile", "page.html", "main.tf"):
        assert not codecheck.is_not_analysed(name), name


def test_weight_files_are_never_opened(monkeypatch):
    """Skipped by name: not sniffed, not hashed, not even inside a bundle comparison."""
    weights = b"\x80\x04" + b"w" * 64
    bundle = _zip({"m/model.pt": weights, "m/README.md": b"r\n"})
    data = _zip({"proj/model.pt": weights, "proj/m/model.pt": weights, "proj/m/README.md": b"r\n",
                 "proj/model.pkl": weights, "proj/model.onnx": weights, "proj/app.py": b"x = 1\n",
                 "proj/m.zip": bundle})
    opened = []  # spy only on reads, after the test archives are built (writestr uses open() too)
    real_open = zipfile.ZipFile.open

    def spy(self, name, mode="r", *a, **k):
        if mode == "r":
            opened.append(getattr(name, "filename", name))
        return real_open(self, name, mode, *a, **k)

    monkeypatch.setattr(zipfile.ZipFile, "open", spy)
    with tempfile.TemporaryDirectory() as d:
        rep = archive.inspect_and_extract(data, d)
    assert "proj/app.py" in opened  # the spy works
    assert not [n for n in opened if str(n).lower().endswith((".pt", ".pkl", ".onnx"))]
    nested = [f for f in rep.findings if f["title"].startswith("NESTED_ARCHIVE")]
    assert nested and "model weight files" in nested[0]["evidence"]


def test_client_zip_leaves_out_gitignored_files_and_documents(tmp_path):
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location("ws_client", Path(__file__).resolve().parent.parent
                                                  / "scripts" / "ws_client.py")
    ws_client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ws_client)
    (tmp_path / ".gitignore").write_text(".env\nkeys/\ndata/\n", encoding="utf-8")
    for rel, body in {".env": "SECRET=1", "keys/private.pem": "x", "data/r.json": "{}", "app/main.py": "x = 1\n",
                      "docs/spec.pdf": "%PDF", "img/logo.png": "png", "notes.txt": "n", ".ruff_cache/x": "c",
                      "models/best.pt": "w", "models/clf.pkl": "w", "models/net.onnx": "w"}.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    data, _ = ws_client.zip_code(tmp_path)
    assert sorted(zipfile.ZipFile(io.BytesIO(data)).namelist()) == [".gitignore", "app/main.py"]
