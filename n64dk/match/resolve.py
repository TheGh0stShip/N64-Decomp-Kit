"""Resolution cases: a durable record per unmatched function and the ladder that fills it.

The matching loop keeps answering one question per function -- *what kind of work does this
one need?* -- and without a record the answer is rediscovered every session.  A resolution
case stores it: the verified target identity, the ranked causes (``causes.TAXONOMY``), every
stage that ran, the best candidate, the families that were tried and did nothing, and the
next recommended experiment.

``resolve`` climbs a bounded ladder and stops at the first rung that settles the case:

1. **target**    control flow, liveness and frame analysis of the retail bytes.  A range that
                 is not a whole function (fragment, false split, embedded data), one that uses a
                 non-standard register convention, or probable hand-written code is recorded as
                 such and costs no compile.
2. **source**    the supplied candidate, the case's previous best, or a fresh draft.
3. **baseline**  build and compare; exact ends the case.
4. **diagnose**  typed causes from the residual.
5. **iterate**   variant families justified by the causes first, then the remaining ones,
                 skipping families already closed for this exact source.
6. **classify**  re-diagnose the best candidate; the top cause names the remaining blocker.

A case is keyed by ``IMAGE:VRAM:SIZE`` and carries the digest of its target bytes: when the
boundary, the image or the bytes change, the old case is archived as stale and never reused.
Every case marked ``exact`` has already passed ``verify.strict_compare``.  Integration still
performs an independent clean rebuild and the configured project gates before it becomes credit.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..analysis import flow as flowmod
from . import causes as causemod
from . import iterate as itermod

BLOCKING = ("boundary.fragment", "boundary.false_split", "boundary.embedded_data")
STATUSES = ("exact", "assumed", "near", "open", "blocked-boundary", "needs-tu", "probable-handwritten", "needs-source",
            "does-not-build", "stale")
# rough tractability of the top cause, used only to order the queue (higher = sooner)
TRACTABILITY = {"compiler.family": 0.95, "type.signedness": 0.9, "type.width": 0.9, "type.volatile": 0.85, "register.lifetime": 0.8,
                "global.declaration": 0.7, "control.branch_form": 0.6, "control.branch_likely": 0.6,
                "frame.size": 0.6, "register.permutation": 0.5, "schedule.delay_slot": 0.5,
                "register.pressure": 0.4, "source.missing": 0.4, "assembler.variant": 0.3,
                "relocation.target": 0.7, "schedule.load_hazard": 0.3, "control.switch": 0.4,
                "semantic.unknown": 0.2, "tu.context": 0.15, "abi.nonstandard": 0.1,
                "boundary.fragment": 0.0, "boundary.false_split": 0.0, "boundary.shared_tail": 0.05,
                "boundary.embedded_data": 0.0, "assembly.handwritten": 0.0}


def case_id(image: str, vram: int, size: int) -> str:
    return f"{image}:{vram:08X}:{size:X}"


@dataclass
class Case:
    case_id: str
    image: str
    name: str
    vram: int
    size: int
    target_digest: str
    status: str = "open"
    top_cause: str = ""
    causes: list[dict] = field(default_factory=list)
    best_score: int | None = None
    best_digest: str | None = None
    stages: list[dict] = field(default_factory=list)
    closed_families: dict[str, list[str]] = field(default_factory=dict)   # source digest -> families
    next: str = ""
    builds: int = 0
    updated_ns: int = 0
    proof: dict | None = None

    def as_dict(self) -> dict:
        return {"case": self.case_id, "name": self.name, "vram": f"0x{self.vram:08X}", "size": self.size,
                "status": self.status, "top_cause": self.top_cause, "causes": self.causes,
                "best_score": self.best_score, "best_source": self.best_digest, "builds": self.builds,
                "stages": self.stages, "next": self.next, "proof": self.proof}


class CaseStore:
    """SQLite store (WAL) for cases plus content-addressed candidate sources."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        (self.root / "sources").mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()            # one connection shared by worker threads
        self.db = sqlite3.connect(self.root / "cases.sqlite", timeout=60, isolation_level=None,
                                  check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS cases (case_id TEXT PRIMARY KEY, target_digest TEXT NOT NULL, "
                        "status TEXT NOT NULL, top_cause TEXT NOT NULL, size INTEGER NOT NULL, payload TEXT NOT NULL, "
                        "updated_ns INTEGER NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS stale (case_id TEXT NOT NULL, target_digest TEXT NOT NULL, "
                        "payload TEXT NOT NULL, archived_ns INTEGER NOT NULL)")

    def close(self) -> None:
        self.db.close()

    def get(self, key: str) -> Case | None:
        with self.lock:
            row = self.db.execute("SELECT payload FROM cases WHERE case_id = ?", (key,)).fetchone()
        return Case(**json.loads(row[0])) if row else None

    def put(self, case: Case) -> None:
        case.updated_ns = time.time_ns()
        payload = json.dumps(case.__dict__, sort_keys=True)
        for attempt in range(8):                              # short retry: other processes may hold the lock
            try:
              with self.lock:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(case_id) DO UPDATE SET "
                                "target_digest = excluded.target_digest, status = excluded.status, "
                                "top_cause = excluded.top_cause, size = excluded.size, payload = excluded.payload, "
                                "updated_ns = excluded.updated_ns",
                                (case.case_id, case.target_digest, case.status, case.top_cause, case.size, payload,
                                 case.updated_ns))
                self.db.execute("COMMIT")
                return
            except sqlite3.OperationalError:
                with self.lock:
                    try:
                        self.db.execute("ROLLBACK")
                    except sqlite3.OperationalError:
                        pass
                if attempt == 7:
                    raise
                time.sleep(0.05 * (attempt + 1))

    def archive(self, case: Case) -> None:
        with self.lock:
            self._archive(case)

    def _archive(self, case: Case) -> None:
        self.db.execute("INSERT INTO stale VALUES (?, ?, ?, ?)",
                        (case.case_id, case.target_digest, json.dumps(case.__dict__, sort_keys=True), time.time_ns()))

    def all(self) -> list[Case]:
        with self.lock:
            rows = self.db.execute("SELECT payload FROM cases ORDER BY case_id").fetchall()
        return [Case(**json.loads(row[0])) for row in rows]

    def save_source(self, text: str) -> str:
        digest = hashlib.sha256(text.encode()).hexdigest()
        path = self.root / "sources" / f"{digest}.c"
        if not path.exists():
            temporary = path.with_suffix(f".{time.time_ns()}.tmp")
            temporary.write_text(text)
            temporary.replace(path)
        return digest

    def source(self, digest: str | None) -> str | None:
        path = self.root / "sources" / f"{digest}.c" if digest else None
        return path.read_text() if path is not None and path.is_file() else None


def resolve(store: CaseStore, image: str, name: str, vram: int, target: bytes, evaluate, *,
            source: str | None = None, draft=None, flow: flowmod.Flow | None = None,
            neighbours: set[int] | None = None, budget: int = 300, jobs: int = 8, force: bool = False,
            near: int = 10, emit=None, pipeline: str | None = None, recipes=None) -> Case:
    """Run the ladder for one function and store the case.

    ``evaluate(text) -> (iterate.Evaluation, relocated candidate bytes or None)``;
    ``draft(family) -> (source text or None, error or None)`` produces a first candidate when
    none is supplied (``family`` is the detected compiler family or None);
    ``recipes(family) -> [(label, pipeline, evaluate)]`` lists alternative build recipes, tried on
    the baseline source when the bytes carry another compiler family's fingerprint or the
    baseline is far off; ``emit(event_dict)`` receives progress events."""
    size, digest = len(target), hashlib.sha256(target).hexdigest()
    key = case_id(image, vram, size)

    def event(kind: str, **extra) -> None:
        if emit is not None:
            emit({"event": kind, "case": key, "name": name, **extra})

    previous = store.get(key)
    if previous is not None and previous.target_digest != digest:
        previous.status = "stale"
        store.archive(previous)
        event("stale-case-archived", old_target=previous.target_digest[:12])
        previous = None
    if previous is not None and previous.status == "exact" and not force:
        return previous
    case = Case(key, image, name, vram, size, digest)
    if previous is not None:
        case.closed_families, case.best_digest, case.best_score = (previous.closed_families, previous.best_digest,
                                                                   previous.best_score)

    def finish(status: str, ranked, next_step: str = "") -> Case:
        case.status = status
        case.causes = [c.as_dict() for c in ranked]
        case.top_cause = ranked[0].id if ranked else ""
        case.next = next_step or (ranked[0].next if ranked else "")
        store.put(case)
        event("case-" + status, top_cause=case.top_cause, score=case.best_score, builds=case.builds)
        return case

    # 1. target
    flow = flow or flowmod.analyse(target, vram)
    found = causemod.target_causes(flow, neighbours)
    fingerprint = causemod.compiler_family(flow)
    family = fingerprint["family"] if fingerprint["confidence"] >= 0.6 else None
    case.stages.append({"stage": "target", "shape": flowmod.shapes(flow)[0]["shape"],
                        "entry": flowmod.entry_evidence(flow)["problems"][:3],
                        "compiler_family": fingerprint["family"], "family_confidence": fingerprint["confidence"]})
    by_id = {c.id: c for c in found}
    if not force:
        blocking = [c for c in found if c.id in BLOCKING and c.confidence >= 0.7]
        if blocking:
            return finish("blocked-boundary", found)
        if by_id.get("abi.nonstandard") and by_id["abi.nonstandard"].confidence >= 0.7:
            return finish("needs-tu", found)
        if by_id.get("assembly.handwritten") and by_id["assembly.handwritten"].confidence >= 0.8:
            return finish("probable-handwritten", found)

    # 2. source
    text, origin = source, "supplied"
    if text is None and case.best_digest:
        text, origin = store.source(case.best_digest), "previous-best"
    if text is None and draft is not None:
        text, error = draft(family)
        origin = "draft"
        if text is None:
            case.stages.append({"stage": "source", "origin": "draft", "error": (error or "")[-300:]})
            return finish("needs-source", causemod.diagnose(target, None, vram, flow, neighbours),
                          "the automatic draft failed: " + (error or "no output")[-200:])
    if text is None:
        return finish("needs-source", causemod.diagnose(target, None, vram, flow, neighbours))
    case.stages.append({"stage": "source", "origin": origin})

    # 3. baseline
    built: dict[str, bytes | None] = {}

    def run(candidate: str) -> itermod.Evaluation:
        evaluation, code = evaluate(candidate)
        built[hashlib.sha256(candidate.encode()).hexdigest()] = code
        return evaluation

    base = run(text)
    case.builds += 1
    wrong_family = family is not None and pipeline is not None and causemod.pipeline_family(pipeline) != family
    if recipes is not None and not base.exact and (wrong_family or base.score is None or base.score > 4 * near):
        tried, chosen = 0, None
        for label, recipe_pipeline, recipe_evaluate in recipes(family):
            evaluation, code = recipe_evaluate(text)
            tried += 1
            case.builds += 1
            if evaluation.score is not None and (base.score is None or evaluation.score < base.score):
                base, chosen, evaluate, pipeline = evaluation, label, recipe_evaluate, recipe_pipeline
                built[hashlib.sha256(text.encode()).hexdigest()] = code
                if evaluation.exact:
                    break
        case.stages.append({"stage": "recipe", "tried": tried, "chosen": chosen, "score": base.score})
        if chosen:
            event("recipe-selected", recipe=chosen, score=base.score)
    if base.score is None:
        case.stages.append({"stage": "baseline", "error": (base.error or "")[-300:]})
        return finish("does-not-build", causemod.diagnose(target, None, vram, flow, neighbours),
                      "fix the compile error: " + (base.error or "")[-200:])
    case.best_score, case.best_digest = base.score, store.save_source(text)
    case.stages.append({"stage": "baseline", "score": base.score, "exact": base.exact})
    if base.outcome and base.outcome.get("proof"):
        case.proof = base.outcome["proof"]
        case.stages.append({"stage": "strict-verify", "verdict": case.proof.get("verdict"),
                            "assumptions": len(case.proof.get("assumptions", []))})
    event("baseline", score=base.score, exact=base.exact)
    if base.exact:
        return finish("exact", [], "strictly verified; prepare independent integration")
    if base.score == 0 and case.proof and case.proof.get("verdict") == "assumed":
        return finish("assumed", found, "declare or independently prove every strict-verifier assumption")

    # 4. diagnose
    candidate_code = built.get(hashlib.sha256(text.encode()).hexdigest())
    ranked = causemod.diagnose(target, candidate_code, vram, flow, neighbours, pipeline) if candidate_code is not None \
        else found
    case.stages.append({"stage": "diagnose", "causes": [c.id for c in ranked][:6]})

    # 5. iterate: justified families first, then the rest; never repeat a closed family on the same source
    best_text, best = text, base
    order = causemod.family_order(ranked, itermod.FAMILIES)
    justified = [f for c in ranked for f in c.families if f in itermod.FAMILIES]
    justified = list(dict.fromkeys(justified))
    remaining = max(0, budget - case.builds)
    for label, families, share in (("justified", justified, 0.6), ("all", order, 1.0)):
        source_digest = hashlib.sha256(best_text.encode()).hexdigest()
        families = [f for f in families if f not in case.closed_families.get(source_digest, [])]
        allowance = int(remaining * share) if label == "justified" else max(0, budget - case.builds)
        if not families or allowance < 4 or best.exact:
            continue
        result = itermod.descend(best_text, name, run, tuple(families), jobs=jobs, budget=allowance)
        spent = result.get("evaluated", 0)
        case.builds += spent
        improved = result.get("final_score") is not None and result["final_score"] < best.score
        helpful = {row["family"] for row in result.get("sensitivity", []) if row.get("delta", 0) < 0}
        tried = set(families)
        if not improved:
            case.closed_families.setdefault(source_digest, [])
            case.closed_families[source_digest] = sorted(set(case.closed_families[source_digest]) | (tried - helpful))
        case.stages.append({"stage": "iterate:" + label, "families": families, "builds": spent,
                            "start": result.get("start_score"), "final": result.get("final_score"),
                            "applied": [s.get("applied") for s in result.get("steps", []) if s.get("applied")],
                            "helpful_families": sorted(helpful)})
        event("iterate", pass_=label, start=result.get("start_score"), final=result.get("final_score"), builds=spent)
        if improved and result.get("source"):
            best_text = result["source"]
            best = itermod.Evaluation(result["final_score"], bool(result.get("exact")))
            case.best_score, case.best_digest = best.score, store.save_source(best_text)
            if best.exact:
                verified, _code = evaluate(best_text)
                case.proof = (verified.outcome or {}).get("proof")
                case.stages.append({"stage": "strict-verify", "verdict":
                                    (case.proof or {}).get("verdict", "missing")})
                if not verified.exact:
                    return finish("assumed", ranked,
                                  "candidate is exploration-exact but lacks strict relocation/data proof")
                event("exact-found", builds=case.builds)
                return finish("exact", [], "strictly verified; prepare independent integration")

    # 6. classify what is left
    final_code = built.get(hashlib.sha256(best_text.encode()).hexdigest())
    if final_code is None:
        _evaluation, final_code = evaluate(best_text)
    ranked = causemod.diagnose(target, final_code, vram, flow, neighbours, pipeline) if final_code is not None else ranked
    return finish("near" if (case.best_score or 0) <= near else "open", ranked)


def hard_queue(cases: list[Case]) -> dict:
    """Unresolved cases grouped by top cause and ordered by expected progress."""
    groups: dict[str, dict] = {}
    for case in cases:
        if case.status in ("exact", "stale"):
            continue
        key = case.top_cause or case.status
        group = groups.setdefault(key, {"cause": key, "meaning": causemod.TAXONOMY.get(key, case.status),
                                        "functions": 0, "bytes": 0, "cases": []})
        group["functions"] += 1
        group["bytes"] += case.size
        group["cases"].append((case.best_score if case.best_score is not None else 1 << 30, case.size, case.name,
                               case.case_id, case.status))
    rows = []
    for key, group in groups.items():
        group["cases"].sort()
        group["expected_progress"] = round(group["bytes"] * TRACTABILITY.get(key, 0.2))
        group["best"] = [{"name": n, "case": c, "score": None if s == 1 << 30 else s, "size": size, "status": st}
                         for s, size, n, c, st in group.pop("cases")[:8]]
        rows.append(group)
    rows.sort(key=lambda g: -g["expected_progress"])
    statuses: dict[str, int] = {}
    for case in cases:
        statuses[case.status] = statuses.get(case.status, 0) + 1
    return {"cases": len(cases), "statuses": statuses, "queue": rows}
