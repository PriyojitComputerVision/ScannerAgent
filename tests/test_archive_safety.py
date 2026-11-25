"""Uploaded archives: hostile entries are flagged and never extracted; only text files the
analyzer reads are written, inside the extraction folder."""
from __future__ import annotations

import io
import os
import stat
import zipfile

import pytest

from scopeguard import archive


def _zip(entries, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in entries:
            if isinstance(name, zipfile.ZipInfo):
                z.writestr(name, data)
            else:
                z.writestr(name, data)
    return buf.getvalue()


def _rids(rep):
    return {f["title"].split(":")[0] for f in rep.findings}


def _files(root):
    out = set()
    for d, _, names in os.walk(root):
        for n in names:
            out.add(os.path.relpath(os.path.join(d, n), root).replace(os.sep, "/"))
    return out


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/cron.d/x", "C:/Windows/x.py",
                                  "..\\..\\evil.py"])
def test_zip_slip_entries_are_refused(tmp_path, name):
    rep = archive.inspect_and_extract(_zip([(name, "x = 1"), ("ok.py", "y = 2")]), str(tmp_path / "x"))
    assert "ZIP_SLIP" in _rids(rep)
    assert _files(tmp_path / "x") == {"ok.py"}
    assert not (tmp_path / "evil.py").exists()


def test_symlinks_and_setuid_are_flagged_not_extracted(tmp_path):
    link = zipfile.ZipInfo("app/link.py")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    suid = zipfile.ZipInfo("app/run.sh")
    suid.external_attr = (stat.S_IFREG | stat.S_ISUID | 0o755) << 16
    rep = archive.inspect_and_extract(_zip([(link, "/etc/passwd"), (suid, "echo hi")]), str(tmp_path / "x"))
    assert {"ARCHIVE_SYMLINK", "ARCHIVE_SETUID"} <= _rids(rep)
    assert _files(tmp_path / "x") == {"app/run.sh"}


def test_duplicate_names_keep_only_the_first(tmp_path):
    rep = archive.inspect_and_extract(_zip([("App.py", "a = 1"), ("app.py", "b = 2")]), str(tmp_path / "x"))
    assert "ARCHIVE_DUPLICATE_ENTRY" in _rids(rep)
    assert (tmp_path / "x" / "App.py").read_text() == "a = 1"


def test_compression_bomb_entry_is_not_extracted(tmp_path):
    rep = archive.inspect_and_extract(_zip([("bomb.txt", "0" * 5_000_000)]), str(tmp_path / "x"))
    assert "ZIP_BOMB" in _rids(rep) and _files(tmp_path / "x") == set()


def test_declared_size_lie_is_caught_while_streaming(tmp_path):
    data = bytearray(_zip([("a.py", "print('hello world, this is longer than declared')")],
                          compression=zipfile.ZIP_STORED))
    # shrink the declared size in the central directory (offset 24 = uncompressed size)
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 24:cd + 28] = (5).to_bytes(4, "little")
    rep = archive.inspect_and_extract(bytes(data), str(tmp_path / "x"))
    assert "a.py" not in _files(tmp_path / "x")
    assert "ZIP_BOMB" in _rids(rep) or rep.notices  # refused either way


def test_sensitive_files_binaries_and_nested_archives_are_flagged(tmp_path):
    nested = _zip([("inner.py", "x")])
    rep = archive.inspect_and_extract(_zip([
        (".env", "SECRET=1"), (".env.example", "SECRET=changeme"), ("deploy/id_rsa", "k"),
        ("terraform.tfstate", "{}"), ("tools/helper", b"\x7fELF" + b"\0" * 64), ("libs/dep.zip", nested),
        (".git/config", "[core]"), ("src/app.py", "x = 1")]), str(tmp_path / "x"))
    rids = _rids(rep)
    assert {"SENSITIVE_ENV_FILE", "SENSITIVE_PRIVATE_KEY", "SENSITIVE_TF_STATE", "ARCHIVE_BINARY_EXECUTABLE",
            "NESTED_ARCHIVE", "GIT_METADATA"} <= rids
    env_flags = [f for f in rep.findings if f["title"].startswith("SENSITIVE_ENV_FILE")]
    assert [f["affected_url"] for f in env_flags] == ["upload/.env"]   # .env.example is fine
    assert "tools/helper" not in _files(tmp_path / "x") and "libs/dep.zip" not in _files(tmp_path / "x")
    assert "src/app.py" in _files(tmp_path / "x")


def test_deceptive_names_are_flagged(tmp_path):
    rep = archive.inspect_and_extract(_zip([("invoice\u202egpj.py", "x = 1")]), str(tmp_path / "x"))
    flag = next(f for f in rep.findings if f["title"].startswith("ARCHIVE_DECEPTIVE_NAME"))
    assert "<U+202E>" in flag["evidence"]


def test_only_text_files_are_written_and_resumed_ones_skipped(tmp_path):
    rep = archive.inspect_and_extract(_zip([("a.py", "1"), ("b.py", "2"), ("logo.png", b"\x89PNG....")]),
                                      str(tmp_path / "x"), skip={"a.py"})
    assert _files(tmp_path / "x") == {"b.py"}
    assert rep.stats["skipped_resumed"] == 1


def test_hard_limits(tmp_path, monkeypatch):
    with pytest.raises(archive.ArchiveError, match="not a readable zip"):
        archive.inspect_and_extract(b"not a zip at all", str(tmp_path / "x"))
    monkeypatch.setattr(archive, "MAX_ENTRIES", 2)
    with pytest.raises(archive.ArchiveError, match="entries"):
        archive.inspect_and_extract(_zip([("a.py", "1"), ("b.py", "2"), ("c.py", "3")]), str(tmp_path / "y"))


def test_content_size_estimate_counts_text_only():
    data = _zip([("a.py", "x" * 1000), ("img.png", b"\0" * 5000)])
    assert len(data) + 1000 == archive.archive_content_bytes(data)
