"""Append-only experiment ledger for causal, reproducible matching work."""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .fingerprint import canonical_digest


@dataclass(frozen=True)
class Experiment:
    experiment_id: str
    unit_id: str
    parent_id: str | None
    build_closure: str
    candidate_digest: str
    transform_id: str
    hypothesis: str
    result_digest: str
    exact: bool
    score: int | None
    residual: dict
    elapsed_ms: int
    created_ns: int

    @classmethod
    def create(cls, unit_id: str, build_closure: str, candidate_digest: str,
               transform_id: str, hypothesis: str, result_digest: str,
               exact: bool, score: int | None, residual: dict,
               elapsed_ms: int, parent_id: str | None = None) -> "Experiment":
        created = time.time_ns()
        identity = canonical_digest({"unit_id": unit_id, "closure": build_closure,
                                     "candidate": candidate_digest, "transform": transform_id,
                                     "parent": parent_id})
        return cls(identity, unit_id, parent_id, build_closure, candidate_digest,
                   transform_id, hypothesis, result_digest, exact, score, residual,
                   elapsed_ms, created)


class ExperimentLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS experiments (
                experiment_id TEXT PRIMARY KEY,
                unit_id TEXT NOT NULL,
                parent_id TEXT,
                build_closure TEXT NOT NULL,
                candidate_digest TEXT NOT NULL,
                transform_id TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS experiments_unit ON experiments(unit_id)")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS verifications (
                verification_id TEXT PRIMARY KEY,
                experiment_id TEXT NOT NULL,
                payload TEXT NOT NULL
            )
        """)
        self.db.execute("CREATE INDEX IF NOT EXISTS verifications_experiment "
                        "ON verifications(experiment_id)")
        self.db.commit()

    def append(self, experiment: Experiment) -> bool:
        payload = json.dumps(asdict(experiment), sort_keys=True, separators=(",", ":"))
        before = self.db.total_changes
        self.db.execute("""
            INSERT OR IGNORE INTO experiments
            (experiment_id, unit_id, parent_id, build_closure, candidate_digest,
             transform_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (experiment.experiment_id, experiment.unit_id, experiment.parent_id,
              experiment.build_closure, experiment.candidate_digest,
              experiment.transform_id, payload))
        self.db.commit()
        return self.db.total_changes > before

    def get(self, experiment_id: str) -> Experiment | None:
        row = self.db.execute("SELECT payload FROM experiments WHERE experiment_id = ?",
                              (experiment_id,)).fetchone()
        return Experiment(**json.loads(row[0])) if row else None

    def for_unit(self, unit_id: str) -> list[Experiment]:
        rows = self.db.execute("SELECT payload FROM experiments WHERE unit_id = ? "
                               "ORDER BY rowid", (unit_id,))
        return [Experiment(**json.loads(row[0])) for row in rows]

    def record_verification(self, experiment_id: str, payload: dict) -> str:
        identity = canonical_digest({"experiment_id": experiment_id, "payload": payload})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.db.execute("INSERT OR IGNORE INTO verifications "
                        "(verification_id, experiment_id, payload) VALUES (?, ?, ?)",
                        (identity, experiment_id, encoded))
        self.db.commit()
        return identity

    def verifications(self, experiment_id: str) -> list[dict]:
        rows = self.db.execute("SELECT payload FROM verifications WHERE experiment_id = ? "
                               "ORDER BY rowid", (experiment_id,))
        return [json.loads(row[0]) for row in rows]

    def close(self) -> None:
        self.db.close()
