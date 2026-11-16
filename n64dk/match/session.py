"""Transactional matching sessions for standalone source files.

A session removes the edit-file/build boundary from iterative matching.  Candidate source is
stored by digest, edits are applied in memory, and a batch of source/pipeline/flag variants is
evaluated through the normal matching engine.  Results retain causal lineage and residual
deltas; no candidate is written into the project tree unless explicitly exported.
"""
from __future__ import annotations

import hashlib
import json
import shlex
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .cache import ContentCache
from .engine import Outcome
from .hypotheses import suggest


def _canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _identity(value) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


@dataclass(frozen=True)
class SessionCandidate:
    candidate_id: str
    parent_id: str | None
    source_digest: str
    label: str
    hypothesis: str
    pipeline: str
    flags: tuple[str, ...]
    status: str
    exact: bool
    score: int | None
    counts: dict[str, int]
    outcome: dict
    error: str | None
    created_ns: int

    def as_dict(self) -> dict:
        value = asdict(self)
        value["flags"] = list(self.flags)
        return value

    def summary(self, details: bool = False) -> dict:
        value = self.as_dict()
        if not details:
            value.pop("outcome", None)
        return value


class SessionStore:
    def __init__(self, root: str | Path):
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.cache = ContentCache(self.root / "cache")
        self.db = sqlite3.connect(self.root / "sessions.sqlite", check_same_thread=False)
        self._lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                context TEXT NOT NULL,
                created_ns INTEGER NOT NULL,
                updated_ns INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS session_candidates (
                session_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                parent_id TEXT,
                source_digest TEXT NOT NULL,
                label TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                pipeline TEXT NOT NULL,
                flags TEXT NOT NULL,
                status TEXT NOT NULL,
                exact INTEGER NOT NULL,
                score INTEGER,
                counts TEXT NOT NULL,
                outcome TEXT NOT NULL,
                error TEXT,
                created_ns INTEGER NOT NULL,
                PRIMARY KEY (session_id, candidate_id),
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );
            CREATE INDEX IF NOT EXISTS session_candidates_rank
                ON session_candidates(session_id, exact DESC, score, created_ns);
            CREATE TABLE IF NOT EXISTS flag_capabilities (
                pipeline_family TEXT NOT NULL,
                flag TEXT NOT NULL,
                supported INTEGER NOT NULL,
                evidence TEXT NOT NULL,
                updated_ns INTEGER NOT NULL,
                PRIMARY KEY (pipeline_family, flag)
            );
            CREATE TABLE IF NOT EXISTS option_capabilities (
                toolchain_digest TEXT NOT NULL, pipeline_family TEXT NOT NULL,
                stage TEXT NOT NULL, option TEXT NOT NULL, option_argument TEXT NOT NULL,
                supported INTEGER NOT NULL, evidence TEXT NOT NULL, updated_ns INTEGER NOT NULL,
                PRIMARY KEY(toolchain_digest,pipeline_family,stage,option,option_argument)
            );
            CREATE TABLE IF NOT EXISTS session_experiments (
                session_id TEXT NOT NULL, signature TEXT NOT NULL, round INTEGER NOT NULL,
                family TEXT NOT NULL, parent_id TEXT NOT NULL, variants INTEGER NOT NULL,
                unique_objects INTEGER NOT NULL, best_delta INTEGER, conclusion TEXT NOT NULL,
                payload TEXT NOT NULL, created_ns INTEGER NOT NULL,
                PRIMARY KEY (session_id, signature)
            );
            CREATE TABLE IF NOT EXISTS candidate_attempts (
                session_id TEXT NOT NULL, candidate_id TEXT NOT NULL, attempt_ns INTEGER NOT NULL,
                status TEXT NOT NULL, exact INTEGER NOT NULL, score INTEGER, error TEXT,
                outcome TEXT NOT NULL,
                PRIMARY KEY (session_id, candidate_id, attempt_ns)
            );
        """)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def create(self, context: dict) -> str:
        now = time.time_ns()
        session_id = _identity({"context": context, "created_ns": now})[:20]
        self.db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                        (session_id, "active", _canonical(context), now, now))
        self.db.commit()
        return session_id

    def context(self, session_id: str) -> dict:
        with self._lock:
            row = self.db.execute("SELECT context FROM sessions WHERE session_id = ?",
                                  (session_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown matching session {session_id}")
        return json.loads(row[0])

    def append(self, session_id: str, candidate: SessionCandidate) -> bool:
        before = self.db.total_changes
        self.db.execute("""
            INSERT OR IGNORE INTO candidate_attempts
            (session_id, candidate_id, attempt_ns, status, exact, score, error, outcome)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (session_id, candidate.candidate_id, candidate.created_ns, candidate.status,
              int(candidate.exact), candidate.score, candidate.error, _canonical(candidate.outcome)))
        self.db.execute("""
            INSERT INTO session_candidates
            (session_id, candidate_id, parent_id, source_digest, label, hypothesis,
             pipeline, flags, status, exact, score, counts, outcome, error, created_ns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, candidate_id) DO UPDATE SET
              parent_id=excluded.parent_id, label=excluded.label, hypothesis=excluded.hypothesis,
              status=excluded.status, exact=excluded.exact, score=excluded.score,
              counts=excluded.counts, outcome=excluded.outcome, error=excluded.error,
              created_ns=excluded.created_ns
            WHERE session_candidates.status='failed'
        """, (session_id, candidate.candidate_id, candidate.parent_id,
              candidate.source_digest, candidate.label, candidate.hypothesis,
              candidate.pipeline, _canonical(candidate.flags), candidate.status,
              int(candidate.exact), candidate.score, _canonical(candidate.counts),
              _canonical(candidate.outcome), candidate.error, candidate.created_ns))
        inserted = self.db.total_changes > before
        if inserted:
            self.db.execute("UPDATE sessions SET updated_ns = ? WHERE session_id = ?",
                            (time.time_ns(), session_id))
        self.db.commit()
        return inserted

    @staticmethod
    def _candidate(row) -> SessionCandidate:
        return SessionCandidate(
            row[0], row[1], row[2], row[3], row[4], row[5],
            tuple(json.loads(row[6])), row[7], bool(row[8]), row[9],
            json.loads(row[10]), json.loads(row[11]), row[12], row[13],
        )

    def candidates(self, session_id: str) -> list[SessionCandidate]:
        self.context(session_id)
        rows = self.db.execute("""
            SELECT candidate_id, parent_id, source_digest, label, hypothesis, pipeline,
                   flags, status, exact, score, counts, outcome, error, created_ns
            FROM session_candidates WHERE session_id = ? ORDER BY created_ns, rowid
        """, (session_id,))
        return [self._candidate(row) for row in rows]

    def get(self, session_id: str, candidate_id: str) -> SessionCandidate | None:
        with self._lock:
            row = self.db.execute("""
                SELECT candidate_id, parent_id, source_digest, label, hypothesis, pipeline,
                       flags, status, exact, score, counts, outcome, error, created_ns
                FROM session_candidates WHERE session_id = ? AND candidate_id = ?
            """, (session_id, candidate_id)).fetchone()
        return self._candidate(row) if row else None

    def best(self, session_id: str) -> SessionCandidate:
        rows = [row for row in self.candidates(session_id) if row.status == "evaluated"]
        if not rows:
            raise ValueError("session has no evaluated candidate")
        return min(rows, key=lambda row: (not row.exact,
                                          row.score if row.score is not None else 2**63,
                                          row.created_ns))

    @staticmethod
    def _family(pipeline: str) -> str:
        return pipeline.split("+", 1)[0]

    def flag_supported(self, pipeline: str, flag: str, toolchain_digest: str = "unknown",
                       stage: str = "compiler") -> bool | None:
        option, _, argument = flag.partition("=")
        with self._lock:
            row = self.db.execute(
                "SELECT supported FROM option_capabilities WHERE toolchain_digest=? AND "
                "pipeline_family=? AND stage=? AND option=? AND option_argument=?",
                (toolchain_digest, self._family(pipeline), stage, option, argument)).fetchone()
        return bool(row[0]) if row else None

    def record_flag(self, pipeline: str, flag: str, supported: bool, evidence: str,
                    toolchain_digest: str = "unknown", stage: str = "compiler") -> None:
        option, _, argument = flag.partition("=")
        with self._lock:
            self.db.execute("""
                INSERT INTO option_capabilities VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(toolchain_digest,pipeline_family,stage,option,option_argument) DO UPDATE SET
                    supported=excluded.supported, evidence=excluded.evidence,
                    updated_ns=excluded.updated_ns
            """, (toolchain_digest, self._family(pipeline), stage, option, argument,
                  int(supported), evidence[-2000:], time.time_ns()))
            self.db.commit()

    def capabilities(self) -> list[dict]:
        columns = ("toolchain_digest", "pipeline_family", "stage", "option",
                   "option_argument", "supported", "evidence", "updated_ns")
        return [dict(zip(columns, row)) for row in self.db.execute(
            "SELECT * FROM option_capabilities ORDER BY pipeline_family,stage,option")]

    def invalidate_capabilities(self, pipeline=None, option=None, stage=None) -> int:
        clauses, values = [], []
        for column, value in (("pipeline_family", pipeline), ("option", option), ("stage", stage)):
            if value:
                clauses.append(column + "=?"); values.append(value)
        sql = "DELETE FROM option_capabilities" + (" WHERE " + " AND ".join(clauses) if clauses else "")
        before = self.db.total_changes
        self.db.execute(sql, values); self.db.commit()
        return self.db.total_changes - before

    def experiment_seen(self, session_id: str, signature: str) -> bool:
        return self.db.execute("""SELECT 1 FROM session_experiments
                                  WHERE session_id = ? AND signature = ?""",
                               (session_id, signature)).fetchone() is not None

    def experiment_seen_global(self, signature: str) -> bool:
        return self.db.execute("SELECT 1 FROM session_experiments WHERE signature=? LIMIT 1",
                               (signature,)).fetchone() is not None

    def record_experiment(self, session_id: str, signature: str, round_number: int,
                          family: str, parent_id: str, variants: int, unique_objects: int,
                          best_delta: int | None, conclusion: str, payload: dict) -> None:
        self.db.execute("""INSERT OR IGNORE INTO session_experiments
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (session_id, signature, round_number, family, parent_id, variants, unique_objects,
             best_delta, conclusion, _canonical(payload), time.time_ns()))
        self.db.commit()

    def experiments(self, session_id: str) -> list[dict]:
        rows = self.db.execute("""SELECT signature, round, family, parent_id, variants,
                   unique_objects, best_delta, conclusion, payload, created_ns
                   FROM session_experiments WHERE session_id = ? ORDER BY created_ns""",
                               (session_id,)).fetchall()
        keys = ("signature", "round", "family", "parent_id", "variants", "unique_objects",
                "best_delta", "conclusion", "payload", "created_ns")
        result = []
        for row in rows:
            item = dict(zip(keys, row))
            item["payload"] = json.loads(item["payload"])
            result.append(item)
        return result


def _flags(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return tuple(shlex.split(value))
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise ValueError("flags must be a shell string or list of strings")


def apply_edits(source: str, edits: list[dict]) -> str:
    """Apply ordered, digest-independent edits to an in-memory candidate."""
    result = source
    for index, edit in enumerate(edits):
        if not isinstance(edit, dict):
            raise ValueError(f"edit {index} must be an object")
        if "start" in edit or "end" in edit:
            start, end = int(edit.get("start", -1)), int(edit.get("end", -1))
            if start < 0 or end < start or end > len(result):
                raise ValueError(f"edit {index} has an invalid character range")
            replacement = edit.get("replacement", edit.get("with", ""))
            if not isinstance(replacement, str):
                raise ValueError(f"edit {index} replacement must be text")
            result = result[:start] + replacement + result[end:]
            continue
        old = edit.get("old", edit.get("replace"))
        new = edit.get("new", edit.get("with"))
        if not isinstance(old, str) or not isinstance(new, str) or not old:
            raise ValueError(f"edit {index} requires non-empty old/replace and textual new/with")
        occurrences = [position for position in range(len(result)) if result.startswith(old, position)]
        if not occurrences:
            raise ValueError(f"edit {index} text was not found")
        if edit.get("all"):
            result = result.replace(old, new)
            continue
        occurrence = int(edit.get("occurrence", 1))
        if occurrence < 1 or occurrence > len(occurrences):
            raise ValueError(f"edit {index} occurrence {occurrence} is unavailable")
        position = occurrences[occurrence - 1]
        result = result[:position] + new + result[position + len(old):]
    return result


def _domination_vector(candidate: SessionCandidate) -> tuple[int, ...]:
    keys = ("instruction", "size", "immediate", "branch", "register",
            "scheduling", "hazard-nop", "operand-order")
    return tuple(candidate.counts.get(key, 0) for key in keys) + (
        candidate.score if candidate.score is not None else 2**31,
    )


def frontier(candidates: list[SessionCandidate]) -> list[SessionCandidate]:
    """Return candidates not strictly dominated across residual classes and score."""
    viable = [row for row in candidates if row.status == "evaluated"]
    result = []
    for candidate in viable:
        vector = _domination_vector(candidate)
        dominated = False
        for other in viable:
            if other.candidate_id == candidate.candidate_id:
                continue
            other_vector = _domination_vector(other)
            if all(left <= right for left, right in zip(other_vector, vector)) \
                    and any(left < right for left, right in zip(other_vector, vector)):
                dominated = True
                break
        if not dominated:
            result.append(candidate)
    return sorted(result, key=lambda row: (not row.exact,
                                           row.score if row.score is not None else 2**63,
                                           row.created_ns))


def residual_delta(parent: SessionCandidate | None, child: SessionCandidate) -> dict:
    if parent is None or parent.status != "evaluated" or child.status != "evaluated":
        return {"comparable": False, "score": None, "counts": {}}
    keys = sorted(set(parent.counts) | set(child.counts))
    return {
        "comparable": True,
        "score": (None if parent.score is None or child.score is None
                  else child.score - parent.score),
        "counts": {key: child.counts.get(key, 0) - parent.counts.get(key, 0)
                   for key in keys if child.counts.get(key, 0) != parent.counts.get(key, 0)},
    }


class MatchSession:
    """Persistent session using a caller-supplied authentic match evaluator."""

    def __init__(self, store: SessionStore,
                 evaluator: Callable[[bytes, str, tuple[str, ...], str], Outcome],
                 environment: Callable[[bytes, str, tuple[str, ...]], str] | None = None):
        self.store = store
        self.evaluator = evaluator
        self.environment = environment or getattr(evaluator, "environment", None)

    def create(self, context: dict, source: bytes, pipeline: str,
               flags: tuple[str, ...]) -> tuple[str, SessionCandidate]:
        digest = self.store.cache.put(source)
        enriched = dict(context)
        enriched.update({"baseline_source_digest": digest,
                         "default_pipeline": pipeline,
                         "default_flags": list(flags)})
        session_id = self.store.create(enriched)
        candidate = self._evaluate(session_id, None, source, "baseline",
                                   "establish the standalone baseline", pipeline, flags)
        self.store.append(session_id, candidate)
        return session_id, candidate

    def _evaluate(self, session_id: str, parent_id: str | None, source: bytes,
                  label: str, hypothesis: str, pipeline: str,
                  flags: tuple[str, ...]) -> SessionCandidate:
        source_digest = self.store.cache.put(source)
        context = self.store.context(session_id)
        identity = {"session": session_id, "source": source_digest,
                    "pipeline": pipeline, "flags": flags,
                    "toolchain": context.get("toolchain_digest"),
                    "includes": context.get("include_closure_digest"),
                    "target": context.get("target_text_sha256")}
        if self.environment is not None:
            try:
                identity["environment"] = self.environment(source, pipeline, tuple(flags))
            except Exception as error:
                # Unknown external state must never reuse a stale candidate.
                identity["environment"] = f"unavailable:{time.time_ns()}:{error}"
        candidate_id = _identity(identity)[:24]
        existing = self.store.get(session_id, candidate_id)
        # Successful observations are immutable.  Failures may be transient (lock, OOM,
        # compiler crash) and are deliberately retried while every attempt remains in the
        # append-only candidate_attempts ledger.
        if existing is not None and existing.status != "failed":
            return existing
        try:
            outcome = self.evaluator(source, pipeline, flags, label)
            payload = outcome.as_dict()
            report = outcome.result.diff if outcome.result and outcome.result.diff else None
            score = 0 if outcome.exact else (report.score if report else None)
            counts = {} if outcome.exact or report is None else dict(report.counts)
            status, error = "evaluated", outcome.error
            if outcome.error and outcome.result is None:
                status = "failed"
                lowered = outcome.error.lower()
                if "invalid option" in lowered or "unrecognized option" in lowered \
                        or "unknown option" in lowered:
                    # Attribute rejection only to an option named by the compiler error.
                    # Never poison the inherited base recipe because one added flag failed.
                    toolchain_digest = self.store.context(session_id).get("toolchain_digest", "unknown")
                    for flag in flags:
                        option = flag.partition("=")[0]
                        if option.startswith("-") and option in outcome.error:
                            stage = "assembler" if flag.startswith("-Wa,") else "preprocessor" if flag.startswith("-Wp,") else "compiler"
                            self.store.record_flag(pipeline, flag, False, outcome.error,
                                                   toolchain_digest, stage)
            return SessionCandidate(candidate_id, parent_id, source_digest, label,
                                    hypothesis, pipeline, flags, status, outcome.exact,
                                    score, counts, payload, error, time.time_ns())
        except Exception as error:  # retain unexpected build/oracle failures as evidence
            return SessionCandidate(candidate_id, parent_id, source_digest, label,
                                    hypothesis, pipeline, flags, "failed", False,
                                    None, {}, {}, str(error)[-16000:], time.time_ns())

    def _parent(self, session_id: str, selector: str | None) -> SessionCandidate:
        if selector in (None, "best"):
            return self.store.best(session_id)
        candidate = self.store.get(session_id, selector)
        if candidate is None:
            raise ValueError(f"unknown parent candidate {selector}")
        return candidate

    def try_proposal(self, session_id: str, proposal: dict,
                     jobs: int = 4, details: bool = False) -> dict:
        if not isinstance(proposal, dict):
            raise ValueError("proposal must be a JSON object")
        context = self.store.context(session_id)
        parent = self._parent(session_id, proposal.get("parent"))
        parent_source = self.store.cache.get(parent.source_digest).decode()
        hypothesis = proposal.get("hypothesis", "evaluate a bounded source-form experiment")
        if not isinstance(hypothesis, str) or not hypothesis.strip():
            raise ValueError("proposal hypothesis must be non-empty text")
        base_source = proposal.get("source")
        if base_source is None:
            base_source = apply_edits(parent_source, proposal.get("edits", []))
        if not isinstance(base_source, str):
            raise ValueError("proposal source must be text")
        variants = proposal.get("variants") or [{}]
        if not isinstance(variants, list) or not variants:
            raise ValueError("proposal variants must be a non-empty list")
        flag_variants = proposal.get("flag_variants")
        if flag_variants is None:
            flag_variants = [None]
        if not isinstance(flag_variants, list) or not flag_variants:
            raise ValueError("flag_variants must be a non-empty list")

        work = []
        default_pipeline = parent.pipeline
        default_flags = parent.flags
        for variant_index, variant in enumerate(variants):
            if not isinstance(variant, dict):
                raise ValueError("each variant must be an object")
            source = variant.get("source")
            if source is None:
                source = apply_edits(base_source, variant.get("edits", []))
            if not isinstance(source, str):
                raise ValueError("variant source must be text")
            pipeline = variant.get("pipeline", proposal.get("pipeline", default_pipeline))
            flag_value = variant.get("flags", proposal.get("flags"))
            base_flags = default_flags if flag_value is None else _flags(flag_value)
            remove = set(_flags(variant.get("remove_flags", proposal.get("remove_flags"))))
            base_flags = tuple(flag for flag in base_flags if flag not in remove)
            base_flags += _flags(proposal.get("add_flags")) + _flags(variant.get("add_flags"))
            base_label = variant.get("label", f"variant-{variant_index + 1}")
            for flag_index, extra in enumerate(flag_variants):
                extra_flags = _flags(extra)
                label = base_label
                if len(flag_variants) > 1:
                    label += f"/flags-{flag_index + 1}"
                work.append((source.encode(), label, pipeline, base_flags + extra_flags))

        from .typed_explore import source_shape
        precompile_shapes = {}
        for source_bytes, label, pipeline, flags in work:
            precompile_shapes.setdefault(source_shape(source_bytes.decode("utf-8", "replace")), []).append(label)
        unique_work = {}
        for item in work:
            source, _label, pipeline, flags = item
            unique_work.setdefault((hashlib.sha256(source).hexdigest(), pipeline, flags), item)
        work = list(unique_work.values())

        # Reject previously disproved compiler flags before allocating a worker.  Two options
        # frequently proposed for KMC GCC are known absent and seed the cache immediately.
        known_absent = {"kmc": {"-fno-cse", "-fno-cse2"}}
        toolchain_digest = context.get("toolchain_digest", "unknown")
        rejected = []
        supported_work = []
        for item in work:
            source, label, pipeline, flags = item
            bad = [flag for flag in flags if (flag in known_absent.get(pipeline.split("+", 1)[0], set())
                   or self.store.flag_supported(pipeline, flag, toolchain_digest,
                       "assembler" if flag.startswith("-Wa,") else "preprocessor" if flag.startswith("-Wp,") else "compiler") is False)]
            if bad:
                rejected.append({"label": label, "pipeline": pipeline, "flags": list(flags),
                                 "status": "unsupported", "unsupported_flags": bad,
                                 "reason": "compiler capability preflight"})
                for flag in bad:
                    stage = "assembler" if flag.startswith("-Wa,") else "preprocessor" if flag.startswith("-Wp,") else "compiler"
                    self.store.record_flag(pipeline, flag, False, "compiler capability preflight",
                                           toolchain_digest, stage)
            else:
                supported_work.append(item)
        work = supported_work

        def evaluate(item):
            source, label, pipeline, flags = item
            return self._evaluate(session_id, parent.candidate_id, source, label,
                                  hypothesis, pipeline, flags)

        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            evaluated = list(pool.map(evaluate, work))
        inserted = []
        for candidate in evaluated:
            if self.store.append(session_id, candidate):
                inserted.append(candidate.candidate_id)
        rows = self.store.candidates(session_id)
        by_id = {row.candidate_id: row for row in rows}
        results = []
        seen = set()
        for candidate in evaluated:
            if candidate.candidate_id in seen:
                continue
            seen.add(candidate.candidate_id)
            retained = by_id.get(candidate.candidate_id, candidate)
            results.append({**retained.summary(details),
                            "delta": residual_delta(parent, retained),
                            "suggestions": suggest(retained.counts),
                            "cache_hit": retained.candidate_id not in inserted})
        current_frontier = frontier(rows)
        transaction_viable = [row for row in evaluated if row.status == "evaluated"]
        transaction_best = (min(transaction_viable, key=lambda row: (not row.exact,
                            row.score if row.score is not None else 2**63)).summary(details)
                            if transaction_viable else None)
        object_classes = {}
        ir_classes = {}
        for candidate in evaluated:
            digest = candidate.outcome.get("sha256_text") if candidate.outcome else None
            object_classes.setdefault(digest or "no-object", []).append(candidate.candidate_id)
            opcode = lambda value: (str(value or "").split(None, 1) or ["missing"])[0]
            ir_value = {"counts": candidate.counts,
                        "transitions": [(item.get("kind"), opcode(item.get("compiled")),
                                         opcode(item.get("retail")))
                                        for item in candidate.outcome.get("diff", {}).get("entries", [])]}
            ir_digest = hashlib.sha256(_canonical(ir_value).encode()).hexdigest()
            ir_classes.setdefault(ir_digest, []).append(candidate.candidate_id)
        session_best = self.store.best(session_id)
        return {
            "session_id": session_id,
            "parent": parent.summary(details),
            "results": results,
            "rejected": rejected,
            "best": session_best.summary(details),
            "transaction_results": results,
            "transaction_best": transaction_best,
            "session_best": session_best.summary(details),
            "object_classes": [{"object_digest": digest, "candidate_ids": ids,
                                "equivalent_sources": len(ids)}
                               for digest, ids in object_classes.items()],
            "source_shape_classes": [{"shape_digest": digest, "labels": labels,
                                      "equivalent_forms": len(labels)}
                                     for digest, labels in precompile_shapes.items()],
            "compiler_ir_classes": [{"ir_fingerprint": digest, "candidate_ids": ids,
                                     "equivalent_candidates": len(ids)}
                                    for digest, ids in ir_classes.items()],
            "why_not_better": ("transaction did not improve the retained session frontier"
                               if transaction_best and transaction_best.get("score") is not None
                               and session_best.score is not None
                               and transaction_best["score"] >= session_best.score else None),
            "frontier": [row.summary(details) for row in current_frontier],
            "attempts": len(rows),
            "suggestions": suggest(self.store.best(session_id).counts),
        }

    def status(self, session_id: str, include_candidates: bool = False,
               details: bool = False) -> dict:
        rows = self.store.candidates(session_id)
        result = {
            "session_id": session_id,
            "context": self.store.context(session_id),
            "attempts": len(rows),
            "exact": sum(row.exact for row in rows),
            "failed": sum(row.status == "failed" for row in rows),
            "best": self.store.best(session_id).summary(details),
            "frontier": [row.summary(details) for row in frontier(rows)],
            "suggestions": suggest(self.store.best(session_id).counts),
            "experiments": self.store.experiments(session_id),
        }
        if include_candidates:
            result["candidates"] = [row.summary(details) for row in rows]
        return result
