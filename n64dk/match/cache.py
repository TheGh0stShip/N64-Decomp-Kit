"""Local content-addressed storage for reproducible build artifacts.

The cache belongs outside Git.  It never infers trust from a filename: callers
must verify an artifact through the exact oracle before crediting it.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable


class CacheError(RuntimeError):
    pass


class ContentCache:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.objects = self.root / "objects"
        self.refs = self.root / "refs"
        self.locks = self.root / "locks"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.refs.mkdir(parents=True, exist_ok=True)
        self.locks.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def path(self, digest: str) -> Path:
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("expected a lowercase SHA-256 digest")
        return self.objects / digest[:2] / digest[2:]

    def put(self, data: bytes) -> str:
        digest = self.digest(data)
        target = self.path(digest)
        if target.is_file():
            if self.digest(target.read_bytes()) != digest:
                raise CacheError(f"corrupt cached object {digest}")
            return digest
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".incoming-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, target)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass
        return digest

    def get(self, digest: str) -> bytes:
        data = self.path(digest).read_bytes()
        if self.digest(data) != digest:
            raise CacheError(f"corrupt cached object {digest}")
        return data

    def contains(self, digest: str) -> bool:
        return self.path(digest).is_file()

    @staticmethod
    def _safe_key(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def get_ref(self, key: str) -> str | None:
        path = self.refs / self._safe_key(key)
        if not path.is_file():
            return None
        payload = json.loads(path.read_text())
        digest = payload.get("digest", "")
        return digest if self.contains(digest) else None

    def put_ref(self, key: str, digest: str) -> None:
        if not self.contains(digest):
            raise CacheError(f"cannot reference missing object {digest}")
        target = self.refs / self._safe_key(key)
        payload = json.dumps({"key": key, "digest": digest}, sort_keys=True).encode()
        fd, name = tempfile.mkstemp(prefix=".incoming-ref-", dir=self.refs)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, target)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    @contextmanager
    def lock(self, key: str, timeout: float = 300.0):
        path = self.locks / self._safe_key(key)
        deadline = time.monotonic() + timeout
        while True:
            try:
                path.mkdir()
                break
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise CacheError(f"timed out waiting for cache key {key}")
                time.sleep(0.05)
        try:
            yield
        finally:
            try:
                path.rmdir()
            except FileNotFoundError:
                pass

    def resolve(self, key: str, producer: Callable[[], bytes]) -> tuple[str, bool]:
        """Return the object's digest and whether ``producer`` actually ran."""
        hit = self.get_ref(key)
        if hit is not None:
            return hit, False
        with self.lock(key):
            hit = self.get_ref(key)
            if hit is not None:
                return hit, False
            digest = self.put(producer())
            self.put_ref(key, digest)
            return digest, True
