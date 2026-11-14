"""Incremental content-addressed index of standalone candidate sources."""
from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from pathlib import Path


_NAME = re.compile(r"(?:func_)?([0-9A-Fa-f]{8})(?:_[^/]*)?\.c$")
_FUNCTION = re.compile(r"\b(func_[0-9A-Fa-f]{8})\s*\(")
_IGNORED = {"build", "extract", "extracted", "bundle", "bundles", "campaigns",
            ".git", ".n64dk", "__pycache__"}


class SourceIndex:
    def __init__(self, project: str | Path):
        self.project = Path(project).resolve()
        root = self.project / ".n64dk"
        root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(root / "source-index.sqlite")
        self.db.execute("""CREATE TABLE IF NOT EXISTS sources (
            path TEXT PRIMARY KEY, mtime_ns INTEGER NOT NULL, size INTEGER NOT NULL,
            digest TEXT NOT NULL, function_name TEXT, vram INTEGER, indexed_ns INTEGER NOT NULL)""")
        self.db.execute("CREATE INDEX IF NOT EXISTS sources_function_name ON sources(function_name)")
        self.db.execute("CREATE INDEX IF NOT EXISTS sources_vram ON sources(vram)")
        self.db.execute("CREATE INDEX IF NOT EXISTS sources_digest ON sources(digest)")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def empty(self) -> bool:
        return self.db.execute("SELECT 1 FROM sources LIMIT 1").fetchone() is None

    def refresh(self) -> dict:
        started = time.monotonic()
        root = self.project / ".tmp"
        seen = set()
        scanned = hashed = 0
        existing = {row[0]: row[1:] for row in self.db.execute(
            "SELECT path,mtime_ns,size,digest FROM sources")}
        if root.is_dir():
            for path in root.rglob("*.c"):
                relative = path.relative_to(self.project)
                if any(part.lower() in _IGNORED for part in relative.parts):
                    continue
                scanned += 1
                key = str(relative)
                seen.add(key)
                stat = path.stat()
                old = existing.get(key)
                if old and old[0] == stat.st_mtime_ns and old[1] == stat.st_size:
                    continue
                raw = path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                hashed += 1
                match = _NAME.search(path.name)
                vram = int(match.group(1), 16) if match else None
                content_match = _FUNCTION.search(raw.decode("utf-8", "replace"))
                function_name = content_match.group(1) if content_match else (
                    f"func_{match.group(1).upper()}" if match else None)
                self.db.execute("""INSERT INTO sources VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(path) DO UPDATE SET mtime_ns=excluded.mtime_ns, size=excluded.size,
                    digest=excluded.digest, function_name=excluded.function_name,
                    vram=excluded.vram, indexed_ns=excluded.indexed_ns""",
                    (key, stat.st_mtime_ns, stat.st_size, digest, function_name, vram, time.time_ns()))
        stale = set(existing) - seen
        if stale:
            self.db.executemany("DELETE FROM sources WHERE path=?", ((value,) for value in stale))
        self.db.commit()
        return {"scanned": scanned, "hashed": hashed, "elapsed_seconds": round(time.monotonic() - started, 6)}

    def find(self, name: str, vram: int) -> list[dict]:
        rows = self.db.execute("""SELECT path, digest, mtime_ns, size FROM sources
                                  WHERE function_name = ? OR vram = ? ORDER BY path""",
                               (name, vram)).fetchall()
        return [{"path": row[0], "digest": row[1], "mtime_ns": row[2], "size": row[3]}
                for row in rows]
