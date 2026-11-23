"""What a scan may read from a target response (stdlib only).

Rule: scans never download files. Concretely:

* **Links to files are not requested by the crawlers** (``is_file_link``:
  executables, installers, archives, disk images, office/PDF documents, media,
  fonts, wasm, ...). Fixed security probes (e.g. ``/backup.zip``) still send
  their one request but only use the status and headers.
* **Attachments and binary responses are discarded unread**
  (``body_policy`` -> ``drop``): ``Content-Disposition: attachment``, binary
  media types, and compressed encodings that cannot be decoded safely. The
  connection is closed without reading the body.
* **Unknown types are sniffed**: at most ``SNIFF_BYTES`` are read; if they
  look binary (NUL bytes or a known file signature such as MZ/ELF/ZIP/PDF)
  the body is discarded.
* **Text is read into memory only, size-capped**, and is never written to
  disk or executed (reports quote short evidence snippets as text).
"""
from __future__ import annotations

import posixpath
import urllib.parse as up

SNIFF_BYTES = 64 * 1024
TEXT_LIMIT_BYTES = 2_000_000
DROPPED_HEADER = "x-scopeguard-body-dropped"  # set on responses whose body was discarded

TEXT_TYPES = frozenset({
    "text/html", "application/xhtml+xml", "text/plain", "text/css", "text/csv", "text/markdown",
    "text/javascript", "application/javascript", "application/x-javascript", "application/ecmascript",
    "text/ecmascript", "application/json", "application/ld+json", "application/manifest+json",
    "application/problem+json", "application/xml", "text/xml", "application/rss+xml",
    "application/atom+xml", "application/graphql", "application/x-www-form-urlencoded",
})
BINARY_PREFIXES = ("image/", "audio/", "video/", "font/", "model/", "multipart/")
BINARY_TYPES = frozenset({
    "application/zip", "application/x-zip-compressed", "application/pdf", "application/x-msdownload",
    "application/x-msdos-program", "application/vnd.microsoft.portable-executable",
    "application/x-executable", "application/x-elf", "application/x-mach-binary",
    "application/x-sharedlib", "application/java-archive", "application/x-java-archive",
    "application/x-7z-compressed", "application/x-rar-compressed", "application/vnd.rar",
    "application/gzip", "application/x-gzip", "application/x-tar", "application/x-bzip2",
    "application/x-xz", "application/zstd", "application/x-apple-diskimage",
    "application/vnd.android.package-archive", "application/x-iso9660-image", "application/x-msi",
    "application/x-ms-installer", "application/vnd.ms-cab-compressed", "application/wasm",
    "application/x-shockwave-flash", "application/msword", "application/vnd.ms-excel",
    "application/vnd.ms-powerpoint", "application/rtf", "application/x-sqlite3",
    "application/vnd.sqlite3", "application/x-debian-package", "application/x-rpm",
    "application/x-redhat-package-manager", "application/x-sh", "application/x-csh",
    "application/x-bat", "application/x-msdos-batch", "application/hta", "application/x-ms-shortcut",
    "application/vnd.ms-office", "application/x-ole-storage",
})
BINARY_TYPE_PREFIXES = ("application/vnd.openxmlformats-officedocument.", "application/vnd.oasis.opendocument.",
                        "application/vnd.ms-")
# Leading bytes of common binary/executable/archive formats.
FILE_SIGNATURES = (
    b"MZ", b"\x7fELF", b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"%PDF", b"\x1f\x8b", b"BZh",
    b"\xfd7zXZ\x00", b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe",
    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    b"\x00asm", b"SQLite format 3\x00", b"\x89PNG", b"GIF8", b"\xff\xd8\xff", b"ID3", b"OggS",
    b"\x28\xb5\x2f\xfd", b"!<arch>", b"wOFF", b"wOF2",
)
FILE_EXTENSIONS = frozenset({
    ".exe", ".msi", ".msix", ".appx", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".hta", ".lnk", ".jar", ".war", ".apk", ".aab", ".ipa", ".dmg", ".pkg", ".app", ".deb", ".rpm",
    ".bin", ".run", ".so", ".dylib", ".elf", ".iso", ".img", ".vhd", ".vmdk", ".ova",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".cab", ".lz", ".lzma",
    ".pdf", ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".odt",
    ".ods", ".odp", ".rtf", ".epub",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".avif", ".heic", ".psd",
    ".mp3", ".mp4", ".m4a", ".m4v", ".wav", ".flac", ".ogg", ".oga", ".ogv", ".webm", ".avi", ".mov",
    ".mkv", ".wmv", ".flv", ".swf",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".wasm", ".sqlite", ".db", ".mdb", ".torrent",
})


def media_type(content_type: str | None) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def is_attachment(content_disposition: str | None) -> bool:
    return (content_disposition or "").split(";", 1)[0].strip().lower() == "attachment"


def body_policy(content_type: str | None, content_disposition: str | None = None,
                content_encoding: str | None = None) -> tuple[str, str]:
    """('read' | 'sniff' | 'drop', reason) for a response with these headers."""
    if is_attachment(content_disposition):
        return "drop", "file attachment (Content-Disposition: attachment)"
    encoding = (content_encoding or "").strip().lower()
    if encoding not in ("", "identity", "gzip", "x-gzip", "deflate"):
        return "drop", f"unsupported Content-Encoding {encoding!r}"
    mt = media_type(content_type)
    if mt in TEXT_TYPES or mt.startswith("text/") or (
            mt.endswith(("+json", "+xml")) and not mt.startswith(BINARY_PREFIXES)):
        return "read", ""
    if mt.startswith(BINARY_PREFIXES) or mt in BINARY_TYPES or mt.startswith(BINARY_TYPE_PREFIXES):
        return "drop", f"binary content ({mt})"
    return "sniff", mt or "no Content-Type"


def looks_binary(head: bytes) -> bool:
    """NUL bytes or a known file signature in the first bytes of a body."""
    sample = head[:4096]
    return b"\x00" in sample or sample.lstrip(b"\xef\xbb\xbf").startswith(FILE_SIGNATURES)


def is_file_link(url: str) -> bool:
    """True when a URL's path names a downloadable file the crawlers must not request."""
    try:
        path = up.urlsplit(url).path
    except ValueError:
        return False
    return posixpath.splitext(up.unquote(path).lower().rstrip("/"))[1] in FILE_EXTENSIONS
