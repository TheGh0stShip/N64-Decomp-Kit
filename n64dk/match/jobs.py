"""Persistent, resumable, evidence-driven source matching jobs.

Jobs are intentionally conservative: they search bounded source spellings through the
authentic adapter build and exact owned-span oracle.  A low diagnostic score is never
promoted as proof; only the runner's exact result plus an independent rebuild can produce
an accepted exploratory candidate.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .fingerprint import sha256_file
from .runner import RunnerError, UnitRunner


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class JobConfig:
    unit_id: str
    budget: int = 200
    beam_width: int = 12
    max_candidates_per_parent: int = 32

    def __post_init__(self) -> None:
        if self.budget < 1 or self.beam_width < 1 or self.max_candidates_per_parent < 1:
            raise ValueError("job budgets and widths must be positive")


@dataclass(frozen=True)
class SourceCandidate:
    candidate_id: str
    parent_id: str | None
    source_digest: str
    transform_id: str
    hypothesis: str
    status: str
    score: int | None
    exact: bool
    experiment_id: str | None
    residual: dict
    error: str | None
    created_ns: int


@dataclass(frozen=True)
class GeneratedCandidate:
    source: bytes
    transform_id: str
    hypothesis: str


class JobStore:
    """SQLite checkpoint and event log; source bodies live in the content cache."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                config TEXT NOT NULL,
                context_digest TEXT NOT NULL,
                created_ns INTEGER NOT NULL,
                updated_ns INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS candidates (
                job_id TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                parent_id TEXT,
                source_digest TEXT NOT NULL,
                transform_id TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                status TEXT NOT NULL,
                score INTEGER,
                exact INTEGER NOT NULL,
                experiment_id TEXT,
                residual TEXT NOT NULL,
                error TEXT,
                created_ns INTEGER NOT NULL,
                PRIMARY KEY (job_id, candidate_id),
                FOREIGN KEY (job_id) REFERENCES jobs(job_id)
            );
            CREATE INDEX IF NOT EXISTS candidates_job_score
                ON candidates(job_id, exact DESC, score, created_ns);
            CREATE TABLE IF NOT EXISTS job_events (
                job_id TEXT NOT NULL,
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_ns INTEGER NOT NULL
            );
        """)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def create(self, config: JobConfig, context_digest: str) -> str:
        created = time.time_ns()
        identity = _digest(_json({"config": asdict(config), "context": context_digest,
                                  "created_ns": created}).encode())[:20]
        self.db.execute("INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?)",
                        (identity, "ready", _json(asdict(config)), context_digest,
                         created, created))
        self.event(identity, "created", {"config": asdict(config),
                                          "context_digest": context_digest})
        self.db.commit()
        return identity

    def config(self, job_id: str) -> JobConfig:
        row = self.db.execute("SELECT config FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown job {job_id}")
        return JobConfig(**json.loads(row[0]))

    def context_digest(self, job_id: str) -> str:
        row = self.db.execute("SELECT context_digest FROM jobs WHERE job_id = ?",
                              (job_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown job {job_id}")
        return row[0]

    def set_status(self, job_id: str, status: str) -> None:
        self.db.execute("UPDATE jobs SET status = ?, updated_ns = ? WHERE job_id = ?",
                        (status, time.time_ns(), job_id))
        self.event(job_id, "status", {"status": status})
        self.db.commit()

    def event(self, job_id: str, kind: str, payload: dict) -> None:
        self.db.execute("INSERT INTO job_events(job_id, kind, payload, created_ns) VALUES (?, ?, ?, ?)",
                        (job_id, kind, _json(payload), time.time_ns()))

    def append_candidate(self, job_id: str, candidate: SourceCandidate) -> bool:
        before = self.db.total_changes
        self.db.execute("""
            INSERT OR IGNORE INTO candidates
            (job_id, candidate_id, parent_id, source_digest, transform_id, hypothesis,
             status, score, exact, experiment_id, residual, error, created_ns)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (job_id, candidate.candidate_id, candidate.parent_id, candidate.source_digest,
              candidate.transform_id, candidate.hypothesis, candidate.status,
              candidate.score, int(candidate.exact), candidate.experiment_id,
              _json(candidate.residual), candidate.error, candidate.created_ns))
        inserted = self.db.total_changes > before
        if inserted:
            self.event(job_id, "candidate", asdict(candidate))
        self.db.commit()
        return inserted

    def candidates(self, job_id: str) -> list[SourceCandidate]:
        rows = self.db.execute("""
            SELECT candidate_id, parent_id, source_digest, transform_id, hypothesis,
                   status, score, exact, experiment_id, residual, error, created_ns
            FROM candidates WHERE job_id = ? ORDER BY created_ns, rowid
        """, (job_id,))
        return [SourceCandidate(row[0], row[1], row[2], row[3], row[4], row[5],
                                row[6], bool(row[7]), row[8], json.loads(row[9]),
                                row[10], row[11]) for row in rows]

    def summary(self, job_id: str) -> dict:
        row = self.db.execute("SELECT status, config, context_digest, created_ns, updated_ns "
                              "FROM jobs WHERE job_id = ?",
                              (job_id,)).fetchone()
        if not row:
            raise KeyError(f"unknown job {job_id}")
        candidates = self.candidates(job_id)
        ranked = sorted((item for item in candidates if item.status == "evaluated"),
                        key=lambda item: (not item.exact,
                                          item.score if item.score is not None else 2**63,
                                          item.created_ns))
        return {
            "job_id": job_id, "status": row[0], "config": json.loads(row[1]),
            "context_digest": row[2], "created_ns": row[3], "updated_ns": row[4],
            "attempts": len(candidates),
            "evaluated": sum(item.status == "evaluated" for item in candidates),
            "failed": sum(item.status == "failed" for item in candidates),
            "exact": sum(item.exact for item in candidates),
            "best": asdict(ranked[0]) if ranked else None,
        }


_DECL_INIT = re.compile(
    r"(?m)^(?P<indent>[ \t]+)(?P<type>(?:(?:unsigned|signed|const|volatile)\s+)*"
    r"(?:char|short|int|long|float|double|[A-Za-z_]\w*(?:\s*\*)?))\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<expr>[^;\n]+);\s*$"
)
_DECL_THEN_ASSIGN = re.compile(
    r"(?m)^(?P<indent>[ \t]+)(?P<type>(?:(?:unsigned|signed|const|volatile)\s+)*"
    r"(?:char|short|int|long|float|double|[A-Za-z_]\w*(?:\s*\*)?))\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*;\s*\n"
    r"(?P=indent)(?P=name)\s*=\s*(?P<expr>[^;\n]+);\s*$"
)
_COMPOUND = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<name>[A-Za-z_]\w*)\s*(?P<op>[+\-*&|^])="
    r"\s*(?P<expr>[^;\n]+);\s*$"
)
_EXPANDED = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<name>[A-Za-z_]\w*)\s*=\s*(?P=name)\s*"
    r"(?P<op>[+\-*&|^])\s*(?P<expr>[^;\n]+);\s*$"
)
_SIMPLE_COMPARISON = re.compile(
    r"(?m)^(?P<prefix>[ \t]*(?:if|while)\s*\(\s*)"
    r"(?P<left>(?:[A-Za-z_]\w*|-?(?:0[xX][0-9A-Fa-f]+|\d+)))\s*"
    r"(?P<op><=|>=|==|!=|<|>)\s*"
    r"(?P<right>(?:[A-Za-z_]\w*|-?(?:0[xX][0-9A-Fa-f]+|\d+)))"
    r"(?P<suffix>\s*\).*)$"
)


def _preferred_transforms(residual: dict) -> tuple[str, ...]:
    mechanisms = {
        diagnosis.get("mechanism")
        for span in residual.get("spans", ())
        for diagnosis in span.get("diagnoses", ())
    }
    preferred: list[str] = []
    if mechanisms & {"register-allocation", "reload-spill-frame"}:
        preferred += ["split-fuse-expression", "declaration-lifetime",
                      "call-argument-local"]
    if "scheduling-delay-slot" in mechanisms:
        preferred += ["compound-assignment", "statement-order",
                      "split-fuse-expression"]
    if "semantics-or-cfg" in mechanisms:
        preferred += ["loop-induction-shape", "switch-cfg-shape",
                      "split-fuse-expression"]
    return tuple(dict.fromkeys(preferred))


def generate_candidates(source: bytes, limit: int = 32,
                        preferred: tuple[str, ...] = ()) -> list[GeneratedCandidate]:
    """Generate deterministic, local, equivalence-oriented spelling candidates."""
    text = source.decode(errors="strict")
    generated: list[GeneratedCandidate] = []

    def add(start: int, end: int, replacement: str, transform: str, hypothesis: str) -> None:
        candidate = (text[:start] + replacement + text[end:]).encode()
        if candidate != source:
            generated.append(GeneratedCandidate(candidate, transform, hypothesis))

    for match in _DECL_INIT.finditer(text):
        replacement = (f"{match['indent']}{match['type']} {match['name']};\n"
                       f"{match['indent']}{match['name']} = {match['expr']};")
        add(match.start(), match.end(), replacement, "split-fuse-expression",
            f"split initialization of {match['name']} to alter pseudo lifetime")
    for match in _DECL_THEN_ASSIGN.finditer(text):
        replacement = (f"{match['indent']}{match['type']} {match['name']} = "
                       f"{match['expr']};")
        add(match.start(), match.end(), replacement, "split-fuse-expression",
            f"fuse declaration and initialization of {match['name']}")
    for match in _COMPOUND.finditer(text):
        replacement = (f"{match['indent']}{match['name']} = {match['name']} "
                       f"{match['op']} {match['expr']};")
        add(match.start(), match.end(), replacement, "compound-assignment",
            f"expand compound assignment of {match['name']}")
    for match in _EXPANDED.finditer(text):
        replacement = f"{match['indent']}{match['name']} {match['op']}= {match['expr']};"
        add(match.start(), match.end(), replacement, "compound-assignment",
            f"contract assignment of {match['name']} into compound form")
    flipped = {"<": ">", ">": "<", "<=": ">=", ">=": "<=",
               "==": "==", "!=": "!="}
    for match in _SIMPLE_COMPARISON.finditer(text):
        replacement = (f"{match['prefix']}{match['right']} {flipped[match['op']]} "
                       f"{match['left']}{match['suffix']}")
        add(match.start(), match.end(), replacement, "split-fuse-expression",
            "commute a simple comparison to test operand and branch spelling")

    unique: dict[str, GeneratedCandidate] = {}
    for candidate in generated:
        unique.setdefault(_digest(candidate.source), candidate)
    priority = {name: index for index, name in enumerate(preferred)}
    rows = list(unique.values())
    rows.sort(key=lambda item: priority.get(item.transform_id, len(priority)))
    return rows[:limit]


class MatchJob:
    def __init__(self, runner: UnitRunner, store: JobStore):
        self.runner = runner
        self.store = store

    def _context_digest(self, unit_id: str) -> str:
        unit = self.runner._unit(unit_id)
        adapter = self.runner.adapter
        inputs = {label: sha256_file(path)
                  for label, path in adapter.input_files(unit).items()}
        tools = {label: sha256_file(path)
                 for label, path in adapter.toolchain_files(unit).items()}
        targets = [{"span": asdict(span),
                    "sha256": _digest(adapter.target_span_bytes(unit, span))}
                   for span in unit.spans]
        payload = {
            "adapter": [adapter.adapter_id, adapter.adapter_version],
            "unit": unit.unit_id,
            "source": str(unit.source.resolve()),
            "profile": unit.toolchain_profile,
            "flags": unit.flags,
            "inputs": inputs,
            "tools": tools,
            "targets": targets,
            "command": adapter.build_command(unit, Path(".")),
            "environment": adapter.build_environment(unit),
            "allowed_environment": adapter.allowed_environment(unit),
            "oracle_policy": adapter.oracle_policy(unit),
        }
        return _digest(_json(payload).encode())

    def create(self, config: JobConfig) -> str:
        return self.store.create(config, self._context_digest(config.unit_id))

    def _evaluate(self, job_id: str, source: bytes, transform_id: str, hypothesis: str,
                  parent_candidate_id: str | None,
                  parent_experiment_id: str | None) -> SourceCandidate:
        source_digest = self.runner.cache.put(source)
        candidate_id = source_digest
        try:
            summary = self.runner.evaluate(
                self.store.config(job_id).unit_id, transform_id, hypothesis,
                parent_experiment_id, False, source)
            experiment = summary.result.experiment
            return SourceCandidate(candidate_id, parent_candidate_id, source_digest, transform_id,
                                   hypothesis, "evaluated", experiment.score,
                                   experiment.exact, experiment.experiment_id,
                                   experiment.residual, None, time.time_ns())
        except (RunnerError, OSError, UnicodeError) as error:
            return SourceCandidate(candidate_id, parent_candidate_id, source_digest, transform_id,
                                   hypothesis, "failed", None, False, None, {},
                                   str(error)[-16000:], time.time_ns())

    def run(self, job_id: str) -> dict:
        config = self.store.config(job_id)
        current_context = self._context_digest(config.unit_id)
        if current_context != self.store.context_digest(job_id):
            raise RunnerError(
                "job build/target context changed; create a new job instead of mixing evidence"
            )
        self.store.set_status(job_id, "running")
        existing = self.store.candidates(job_id)
        known = {item.candidate_id for item in existing}
        if not existing:
            unit = self.runner._unit(config.unit_id)
            baseline = self._evaluate(job_id, unit.source.read_bytes(), "baseline",
                                      "establish exact owned-section baseline", None, None)
            self.store.append_candidate(job_id, baseline)
            existing = [baseline]
            known.add(baseline.candidate_id)
        try:
            while len(existing) < config.budget and not any(item.exact for item in existing):
                viable = [item for item in existing if item.status == "evaluated"]
                viable.sort(key=lambda item: (item.score is None,
                                               item.score if item.score is not None else 2**63,
                                               item.created_ns))
                # Preserve at least one lineage per transformation before filling by score.
                parents, represented = [], set()
                for item in viable:
                    if item.transform_id not in represented:
                        parents.append(item)
                        represented.add(item.transform_id)
                    if len(parents) == config.beam_width:
                        break
                for item in viable:
                    if len(parents) == config.beam_width:
                        break
                    if item not in parents:
                        parents.append(item)
                proposals: list[tuple[SourceCandidate, GeneratedCandidate]] = []
                for parent in parents:
                    source = self.runner.cache.get(parent.source_digest)
                    preferred = _preferred_transforms(parent.residual)
                    for generated in generate_candidates(
                            source, config.max_candidates_per_parent, preferred):
                        identity = _digest(generated.source)
                        if identity not in known:
                            known.add(identity)
                            proposals.append((parent, generated))
                if not proposals:
                    self.store.set_status(job_id, "exhausted")
                    return self.store.summary(job_id)
                for parent, generated in proposals:
                    if len(existing) >= config.budget:
                        break
                    candidate = self._evaluate(job_id, generated.source,
                                               generated.transform_id,
                                               generated.hypothesis,
                                               parent.candidate_id,
                                               parent.experiment_id)
                    self.store.append_candidate(job_id, candidate)
                    existing.append(candidate)
                    if candidate.exact:
                        self.store.set_status(job_id, "exact")
                        return self.store.summary(job_id)
            self.store.set_status(job_id, "exact" if any(item.exact for item in existing)
                                  else "budget-exhausted")
            return self.store.summary(job_id)
        except BaseException:
            self.store.set_status(job_id, "interrupted")
            raise

    def verify_best(self, job_id: str) -> dict:
        config = self.store.config(job_id)
        exact = [item for item in self.store.candidates(job_id) if item.exact]
        if not exact:
            raise RunnerError("job has no exact candidate to verify")
        candidate = min(exact, key=lambda item: item.created_ns)
        source = self.runner.cache.get(candidate.source_digest)
        summary = self.runner.evaluate(config.unit_id, "independent-verification",
                                       "independently rebuild exact job candidate",
                                       candidate.experiment_id, True, source)
        return summary.as_dict()
