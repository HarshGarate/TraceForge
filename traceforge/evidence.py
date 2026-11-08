"""Evidence vault: read-only copies of every imported file, re-verified against their SHA-256.

Files are stored as ``<sha256>.bin`` (the name *is* the expected hash, so nothing the analyst or an archive controls
ever becomes a path). Each file is written atomically and set read-only; ``check`` re-hashes it on demand.
"""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


class IntegrityError(Exception):
    """A stored evidence file no longer matches the hash recorded when it was imported."""


def _hash_file(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


class EvidenceVault:
    def __init__(self, root: Path | None):
        self.root = Path(root) if root else None
        if self.root:
            self.root.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.root, 0o700)
            except OSError:
                pass

    @property
    def enabled(self) -> bool:
        return self.root is not None

    def path(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            raise ValueError("not a SHA-256 digest")
        assert self.root is not None
        return self.root / f"{sha256}.bin"

    def put(self, sha256: str, raw: bytes) -> None:
        if not self.enabled:
            return
        target = self.path(sha256)
        if target.exists():
            if self.check(sha256, len(raw)) is None:
                return
            self.delete(sha256)                              # a damaged copy is replaced by the verified upload
        tmp = target.with_suffix(".part")
        with open(tmp, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        os.chmod(target, stat.S_IRUSR)                      # read-only for the owner

    def read(self, sha256: str) -> bytes:
        target = self.path(sha256)
        if not target.exists():
            raise IntegrityError("the stored copy is missing")
        raw = target.read_bytes()
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise IntegrityError("the stored copy no longer matches its SHA-256")
        return raw

    def check(self, sha256: str, size: int | None = None) -> str | None:
        """None when the stored file is intact, otherwise a short description of the problem."""
        if not self.enabled:
            return None
        target = self.path(sha256)
        if not target.exists():
            return "the stored copy is missing"
        digest, n = _hash_file(target)
        if digest != sha256:
            return "the stored copy no longer matches its SHA-256 (it was modified)"
        if size is not None and n != size:
            return "the stored copy has a different size than recorded"
        return None

    def delete(self, sha256: str) -> None:
        if not self.enabled:
            return
        target = self.path(sha256)
        try:
            os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
            target.unlink()
        except FileNotFoundError:
            pass

    def stored_hashes(self) -> set[str]:
        if not self.enabled:
            return set()
        return {p.stem for p in self.root.glob("*.bin")}
