"""Upload hardening: size limits, bounded decompression (ZIP / gzip) and a parse-time budget.

Evidence files are untrusted input. Everything in this module exists so that a hostile or merely
oversized file is rejected with a clear message instead of exhausting memory or CPU.
"""
from __future__ import annotations

import gzip
import io
import time
import zipfile
from pathlib import PurePosixPath

MAX_UPLOAD_BYTES = 50 * 1024 * 1024            # per file, measured before and after decompression
MAX_ARCHIVE_MEMBERS = 25                       # files accepted from one ZIP
MAX_ARCHIVE_TOTAL_BYTES = 200 * 1024 * 1024    # sum of decompressed members from one ZIP
MAX_COMPRESSION_RATIO = 250                    # only enforced once the output is larger than RATIO_FLOOR_BYTES
RATIO_FLOOR_BYTES = 10 * 1024 * 1024
MAX_ROWS_PER_FILE = 200_000
MAX_COLUMNS = 300
MAX_JSON_LEVEL = 6                             # nested objects deeper than this are kept as text, not flattened
PARSE_TIMEOUT_SECONDS = 60.0
MAX_REQUEST_BYTES = 220 * 1024 * 1024          # whole HTTP request body (several files at once)

GZIP_MAGIC = b"\x1f\x8b"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06")


class UploadRejected(ValueError):
    """A file was refused for a reason the analyst can understand and fix."""


class ParseTimeout(UploadRejected):
    """Parsing one file took longer than the time budget."""


class Deadline:
    """Cooperative time budget: parsers call check() inside loops and between stages."""

    def __init__(self, seconds: float = PARSE_TIMEOUT_SECONDS):
        self.seconds = seconds
        self._end = time.monotonic() + seconds

    def check(self) -> None:
        if time.monotonic() > self._end:
            raise ParseTimeout(f"parsing took longer than {int(self.seconds)} seconds and was stopped. Split the file or remove unneeded columns.")


def _mb(n: int) -> str:
    return f"{n / 2**20:.0f} MB"


def _read_capped(stream, limit: int, label: str) -> bytes:
    """Read a decompression stream but never hold more than `limit` bytes (decompression-bomb guard)."""
    buf = io.BytesIO()
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            return buf.getvalue()
        buf.write(chunk)
        if buf.tell() > limit:
            raise UploadRejected(f"{label} expands to more than {_mb(limit)}; it was refused (decompression-bomb protection).")


def sniff_container(raw: bytes) -> str | None:
    """Return 'gzip', 'zip', 'tar' or None by magic bytes (file names are never trusted)."""
    if raw[:2] == GZIP_MAGIC:
        return "gzip"
    if raw[:4] in ZIP_MAGICS:
        return "zip"
    if raw[257:262] == b"ustar":
        return "tar"
    return None


def expand_upload(name: str, raw: bytes) -> tuple[list[tuple[str, bytes]], dict | None]:
    """Turn one uploaded file into the log files inside it.

    Plain files come back unchanged. A .gz becomes one file; a .zip becomes up to MAX_ARCHIVE_MEMBERS files.
    Member names are reduced to their base name and are only ever used as labels (nothing is written to disk
    under an archive-controlled path). Nested archives and tar files are refused.
    Returns (files, info) where info describes the expansion (None for plain files).
    """
    kind = sniff_container(raw)
    if kind is None:
        return [(name, raw)], None
    if kind == "tar":
        raise UploadRejected("tar archives are not supported. Extract the logs and upload them directly (or as a .zip / .gz).")
    if kind == "gzip":
        try:
            data = _read_capped(gzip.GzipFile(fileobj=io.BytesIO(raw)), MAX_UPLOAD_BYTES, name)
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            raise UploadRejected(f"is not a valid gzip file ({type(exc).__name__}).") from exc
        if sniff_container(data):
            raise UploadRejected("contains another archive. Nested archives are not supported.")
        inner = name[:-3] if name.lower().endswith(".gz") and len(name) > 3 else name + ".decompressed"
        return [(inner, data)], {"archive": name, "kind": "gzip", "members": [inner]}

    # ZIP
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
        infos = [i for i in zf.infolist() if not i.is_dir()]
    except (zipfile.BadZipFile, OSError, NotImplementedError) as exc:
        raise UploadRejected(f"is not a readable ZIP file ({type(exc).__name__}).") from exc
    infos = [i for i in infos if not i.filename.startswith("__MACOSX/") and not PurePosixPath(i.filename.replace("\\", "/")).name.startswith("._")]
    if not infos:
        raise UploadRejected("the ZIP file contains no files.")
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise UploadRejected(f"the ZIP file contains {len(infos)} files; the limit is {MAX_ARCHIVE_MEMBERS}.")
    out, total = [], 0
    for info in infos:
        base = PurePosixPath(info.filename.replace("\\", "/")).name
        if not base:
            continue
        label = f"{name}/{base}"
        if info.flag_bits & 0x1:
            raise UploadRejected(f"{label} is password-protected; encrypted archives cannot be read.")
        if info.file_size > MAX_UPLOAD_BYTES:
            raise UploadRejected(f"{label} is larger than {_mb(MAX_UPLOAD_BYTES)} once extracted.")
        try:
            with zf.open(info) as fh:
                data = _read_capped(fh, MAX_UPLOAD_BYTES, label)
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError) as exc:
            raise UploadRejected(f"{label} could not be extracted ({type(exc).__name__}).") from exc
        total += len(data)
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise UploadRejected(f"the ZIP file expands to more than {_mb(MAX_ARCHIVE_TOTAL_BYTES)} in total.")
        if info.compress_size and len(data) > RATIO_FLOOR_BYTES and len(data) / info.compress_size > MAX_COMPRESSION_RATIO:
            raise UploadRejected(f"{label} has a suspicious compression ratio (over {MAX_COMPRESSION_RATIO}:1) and was refused.")
        if sniff_container(data):
            raise UploadRejected(f"{label} is itself an archive. Nested archives are not supported.")
        if data.strip():
            out.append((label, data))
    if not out:
        raise UploadRejected("the ZIP file contains only empty files.")
    return out, {"archive": name, "kind": "zip", "members": [n for n, _ in out]}
