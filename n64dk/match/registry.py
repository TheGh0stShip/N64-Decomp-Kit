"""Project-wide matching-session registry and historical frontier lookup."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path


def project_root(project: str | Path | None = None) -> Path:
    return Path(project or ".").expanduser().resolve()


def standard_store(project: str | Path | None = None) -> Path:
    return project_root(project) / ".n64dk" / "match-sessions"


def target_signature(context: dict) -> str:
    identity = {key: context.get(key) for key in
                ("rom_sha256", "vram_delta", "addr", "size")}
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


class SessionRegistry:
    def __init__(self, project: str | Path | None = None):
        self.project = project_root(project)
        root = self.project / ".n64dk"
        root.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(root / "session-registry.sqlite")
        self.db.execute("""CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY, store_root TEXT NOT NULL, target_signature TEXT NOT NULL,
            image_digest TEXT, image TEXT, vram INTEGER, size INTEGER, source_digest TEXT,
            producer TEXT NOT NULL, created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL)""")
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def register(self, session_id: str, store_root: str | Path, context: dict,
                 source_digest: str | None = None, producer: str = "session") -> None:
        now = time.time_ns()
        self.db.execute("""INSERT INTO sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET store_root=excluded.store_root,
              target_signature=excluded.target_signature, source_digest=excluded.source_digest,
              updated_ns=excluded.updated_ns""",
            (session_id, str(Path(store_root).resolve()), target_signature(context),
             context.get("rom_sha256"), context.get("inventory_image"), context.get("addr"),
             context.get("size"), source_digest, producer, now, now))
        self.db.commit()

    def resolve(self, session_id: str) -> Path | None:
        row = self.db.execute("SELECT store_root FROM sessions WHERE session_id = ?",
                              (session_id,)).fetchone()
        if row and Path(row[0], "sessions.sqlite").is_file():
            return Path(row[0])
        # Import sessions made before the registry existed. Search only known state roots.
        roots = [standard_store(self.project), self.project / ".n64dk" / "quickwin-sweeps" / "sessions"]
        roots += [path.parent for path in (self.project / ".n64dk").glob("*/sessions/sessions.sqlite")]
        package_state = Path(__file__).resolve().parents[2] / ".n64dk"
        roots += [path.parent for path in package_state.glob("*/sessions.sqlite")]
        from .session import SessionStore
        for root in dict.fromkeys(roots):
            if not Path(root, "sessions.sqlite").is_file():
                continue
            store = SessionStore(root)
            try:
                try:
                    context = store.context(session_id)
                except KeyError:
                    continue
                best = store.best(session_id)
                self.register(session_id, root, context, best.source_digest, "imported")
                return Path(root)
            finally:
                store.close()
        return None

    def refresh(self) -> int:
        """Incrementally import sessions from the bounded set of project-owned stores."""
        roots = [standard_store(self.project), self.project / ".n64dk" / "quickwin-sweeps" / "sessions"]
        package_checkout = Path(__file__).resolve().parents[2]
        roots.append(package_checkout / ".n64dk" / "match-sessions")
        roots += [path.parent for path in (package_checkout / ".n64dk").glob("*/sessions.sqlite")]
        roots += [path.parent for path in (self.project / ".n64dk").glob("*/sessions/sessions.sqlite")]
        imported = 0
        from .session import SessionStore
        for root in dict.fromkeys(roots):
            if not Path(root, "sessions.sqlite").is_file():
                continue
            store = SessionStore(root)
            try:
                session_ids = [row[0] for row in store.db.execute("SELECT session_id FROM sessions")]
                for session_id in session_ids:
                    try:
                        context = store.context(session_id)
                        best = store.best(session_id)
                    except (KeyError, ValueError):
                        continue
                    context_project = context.get("project")
                    if context_project and Path(context_project).resolve() != self.project:
                        continue
                    self.register(session_id, root, context, best.source_digest, "imported")
                    imported += 1
            finally:
                store.close()
        return imported

    def same_target(self, context: dict) -> list[dict]:
        self.refresh()
        signature = target_signature(context)
        rows = self.db.execute("""SELECT session_id, store_root, source_digest, producer
                                  FROM sessions WHERE target_signature = ?""", (signature,)).fetchall()
        from .session import SessionStore
        result = []
        for session_id, root, source_digest, producer in rows:
            if not Path(root, "sessions.sqlite").is_file():
                continue
            store = SessionStore(root)
            try:
                best = store.best(session_id)
                result.append({"session_id": session_id, "store_root": root,
                               "candidate_id": best.candidate_id, "exact": best.exact,
                               "score": best.score, "counts": best.counts,
                               "source_digest": source_digest or best.source_digest,
                               "producer": producer})
            except (KeyError, ValueError):
                pass
            finally:
                store.close()
        result.sort(key=lambda row: (not row["exact"], row["score"] if row["score"] is not None else 2**63))
        return result


def resolve_store(session_id: str, project: str | Path | None = None,
                  preferred: str | Path | None = None) -> Path:
    if preferred and Path(preferred, "sessions.sqlite").is_file():
        from .session import SessionStore
        store = SessionStore(preferred)
        try:
            try:
                store.context(session_id)
                return Path(preferred).resolve()
            except KeyError:
                pass
        finally:
            store.close()
    registry = SessionRegistry(project)
    try:
        root = registry.resolve(session_id)
    finally:
        registry.close()
    if root is None:
        raise KeyError(f"unknown matching session {session_id} in project {project_root(project)}")
    return root
