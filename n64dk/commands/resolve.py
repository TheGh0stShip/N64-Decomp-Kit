"""``resolve-case``, ``resolve-hard`` and ``hard-queue``: the hard-function resolution engine."""
from __future__ import annotations

import hashlib
import json
import shlex
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..analysis import flow as flowmod
from ..analysis.functions import load_catalogue
from ..cli import command
from ..match import autodraft, m2c_bridge
from ..match import iterate as itermod
from ..match import resolve as resolvemod
from ..match.engine import match_source
from ..match.pipeline import split_flags
from .match import _common, _setup


def _int(text: str) -> int:
    return int(text, 0)


def _state(args, cfg) -> Path:
    return Path(args.state).resolve() if args.state else Path(cfg.project) / ".n64dk" / "resolve"


def _image_label(args) -> str:
    return args.image_name or Path(args.rom).stem


class _Runner:
    """Build/compare and draft services bound to one image and recipe."""

    def __init__(self, args, cfg, target, syms, work: Path):
        self.args, self.cfg, self.target, self.syms, self.work = args, cfg, target, syms, work
        self.spec = split_flags(shlex.split(args.flags), args.pipeline)

    def evaluator(self, vram: int, size: int, filename: str = "candidate.c", spec=None):
        spec = spec or self.spec

        def evaluate(text: str):
            folder = self.work / hashlib.sha256(
                f"{vram}:{spec.pipeline}:{spec.flags}:{text}".encode()).hexdigest()[:20]
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / filename
            path.write_text(text)
            try:
                outcome = match_source(path, spec, self.cfg, self.target, vram, size, self.syms, folder, None,
                                       strict_verification=True)
            except Exception as error:                       # a failed build is data for the case
                return itermod.Evaluation(None, error=str(error)[-400:]), None
            if outcome.error or outcome.result is None:
                return itermod.Evaluation(None, error=(outcome.error or "no comparison")[-400:]), None
            report = outcome.result.diff
            code = getattr(outcome.result, "compiled_text", b"") or None
            if report is None:
                return itermod.Evaluation(0 if outcome.exploratory_exact else 1, outcome.exact, None,
                                          outcome=outcome.as_dict()), code
            return itermod.Evaluation(report.score, outcome.exact, report.as_dict(limit=4096),
                                      outcome=outcome.as_dict()), code
        return evaluate

    def recipes(self, vram: int, size: int, filename: str, limit: int = 12):
        """Alternative build recipes of the detected compiler family, usual retail settings first."""
        from ..match.engine import default_pipelines, sweep_specs

        def alternatives(family):
            pipelines = [p for p in default_pipelines(self.cfg)
                         if (p.startswith("ido")) == (family == "ido") and p != self.spec.pipeline]
            if family is None:
                pipelines = [p for p in default_pipelines(self.cfg) if p != self.spec.pipeline]
            out = []
            for pipeline in pipelines:
                for spec in sweep_specs([pipeline])[:max(1, limit // max(1, len(pipelines)))]:
                    spec.section_bases.update(self.spec.section_bases)
                    spec.symbols.update(self.spec.symbols)
                    out.append((f"{spec.pipeline} {' '.join(spec.flags)}", spec.pipeline,
                                self.evaluator(vram, size, filename, spec)))
            return out
        return alternatives

    def drafter(self, name: str, vram: int, size: int, evaluate, names: dict[int, str]):
        def draft(family=None):
            offset = vram - self.target.delta
            code = self.target.rom[offset:offset + size]
            tables = m2c_bridge.find_jump_tables(self.target.rom, self.target.delta, vram, size)
            compiler = "ido" if family == "ido" else ("kmc" if family == "gcc" else self.args.pipeline)
            result = m2c_bridge.draft(name, code, vram, compiler,
                                      Path(self.args.context) if self.args.context else None, names, tables)
            if result.get("source") is None:
                return None, f"{result.get('status')}: {result.get('error')}"
            text = autodraft.prepare(result["source"])
            for _attempt in range(12):                       # mechanical compile repairs only
                evaluation, _code = evaluate(text)
                if evaluation.score is not None:
                    return text, None
                fixed = autodraft.repair(text, evaluation.error or "")
                if fixed is None or fixed == text:
                    return text, None                        # baseline stage reports the build error
                text = fixed
            return text, None
        return draft

    def flow(self, vram: int, size: int):
        return flowmod.analyse_in_image(self.target.rom, self.target.delta, vram, size)


def _events(path: str | None):
    if not path:
        return None, None
    handle, lock = open(path, "a", encoding="utf-8"), threading.Lock()

    def emit(event: dict) -> None:
        with lock:
            handle.write(json.dumps({"time": round(time.time(), 3), **event}) + "\n")
            handle.flush()
    return emit, handle


@command("resolve-case", "Diagnose one unmatched function and climb the resolution ladder (draft, iterate, classify)")
def resolve_case(args):
    cfg, target, syms, _files = _setup(args)
    catalogue_vram = args.addr
    linked_vram = getattr(args, "_comparison_addr", catalogue_vram)
    names = {address: name for name, address in syms.items()}
    name = args.name or names.get(linked_vram) or f"func_{catalogue_vram:08X}"
    store = resolvemod.CaseStore(_state(args, cfg))
    emit, handle = _events(args.events)
    try:
        with tempfile.TemporaryDirectory(prefix="n64dk-resolve-") as work:
            runner = _Runner(args, cfg, target, syms, Path(work))
            offset = linked_vram - target.delta
            code = target.rom[offset:offset + args.size]
            source = Path(args.source).read_text() if args.source else None
            evaluate = runner.evaluator(linked_vram, args.size, Path(args.source).name if args.source else f"{name}.c")
            coordinate_shift = catalogue_vram - linked_vram
            starts = ({v - coordinate_shift for _n, v, _s in load_catalogue(Path(args.catalogue))}
                      if args.catalogue else None)
            case = resolvemod.resolve(store, _image_label(args), name, linked_vram, code, evaluate, source=source,
                                      draft=None if args.no_draft else runner.drafter(name, linked_vram, args.size,
                                                                                      evaluate, names),
                                      flow=runner.flow(linked_vram, args.size), neighbours=starts,
                                      budget=args.budget, jobs=args.jobs or 8, force=args.force, emit=emit,
                                      pipeline=args.pipeline,
                                      recipes=None if args.no_recipes else runner.recipes(
                                          linked_vram, args.size, Path(args.source).name if args.source else f"{name}.c"))
        result = case.as_dict()
        result["coordinates"] = {"image": _image_label(args),
                                 "catalogue_vram": f"0x{catalogue_vram:08X}",
                                 "linked_vram": f"0x{linked_vram:08X}",
                                 "size": args.size}
        if args.out and case.best_digest:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(store.source(case.best_digest) or "")
            result["written"] = args.out
        return result
    finally:
        store.close()
        if handle:
            handle.close()


def _case_args(p):
    _common(p, rom_required=True)
    p.add_argument("source", nargs="?", help="existing candidate C file (omit to start from an m2c draft)")
    p.add_argument("--addr", type=_int, required=True)
    p.add_argument("--size", type=_int, required=True)
    p.add_argument("--name")
    _shared(p)
    p.add_argument("--out", help="write the best candidate here")


def _shared(p):
    p.add_argument("--pipeline", default="kmc+builtin")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--context", help="m2c context file (types and prototypes)")
    p.add_argument("--catalogue", help="function catalogue: neighbouring starts for boundary evidence")
    p.add_argument("--budget", type=int, default=300, help="maximum builds per function")
    p.add_argument("--state", help="case store directory (default: <project>/.n64dk/resolve)")
    p.add_argument("--events", help="append JSON-lines progress events to this file")
    p.add_argument("--no-draft", action="store_true", help="never generate an m2c draft")
    p.add_argument("--no-recipes", action="store_true", help="never try alternative compiler recipes")
    p.add_argument("--force", action="store_true", help="continue past boundary/ABI findings and redo exact cases")


resolve_case.arguments = _case_args


@command("resolve-hard", "Run the resolution ladder over every function without matching source and report the queue")
def resolve_hard(args):
    catalogue_functions = load_catalogue(Path(args.catalogue))
    # Give the canonical image resolver one real interval so a composite image obtains its
    # physical offset and catalogue-to-link transformation before the batch is constructed.
    probe_addr = probe_size = None
    if catalogue_functions:
        probe_addr, probe_size = catalogue_functions[0][1], catalogue_functions[0][2]
        args.addr, args.size = probe_addr, probe_size
    cfg, target, syms, _files = _setup(args)
    if probe_addr is not None:
        linked_probe = getattr(args, "_comparison_addr", probe_addr - args.catalogue_shift)
        coordinate_shift = probe_addr - linked_probe
    else:
        coordinate_shift = args.catalogue_shift
    names = {address: name for name, address in syms.items()}
    functions = [(n, v - coordinate_shift, s) for n, v, s in catalogue_functions]
    starts = {v for _n, v, _s in functions}
    covered = []
    for path in args.manifest:
        for line in Path(path).read_text().splitlines():
            parts = line.split("\t")
            if not line.startswith("#") and len(parts) >= 3:
                try:
                    covered.append((int(parts[0], 0), int(parts[1], 0)))
                except ValueError:
                    pass
    todo = [f for f in functions if f[2] >= args.min_size and 0 <= f[1] - target.delta <= len(target.rom) - f[2]
            and not any(a <= f[1] - target.delta < a + n for a, n in covered)]
    todo.sort(key=lambda f: f[2])
    if args.max_size:
        todo = [f for f in todo if f[2] <= args.max_size]
    if args.every > 1:
        todo = todo[::args.every]
    if args.limit:
        todo = todo[:args.limit]
    store = resolvemod.CaseStore(_state(args, cfg))
    emit, handle = _events(args.events)
    image, started = _image_label(args), time.time()
    inner = 4 if (args.jobs or 8) >= 8 else 2
    try:
        with tempfile.TemporaryDirectory(prefix="n64dk-resolve-") as work:
            runner = _Runner(args, cfg, target, syms, Path(work))

            def one(function):
                name, vram, size = function
                offset = vram - target.delta
                evaluate = runner.evaluator(vram, size, f"{name}.c")
                try:
                    return resolvemod.resolve(store, image, name, vram, target.rom[offset:offset + size], evaluate,
                                              draft=None if args.no_draft else runner.drafter(name, vram, size,
                                                                                              evaluate, names),
                                              flow=runner.flow(vram, size), neighbours=starts, budget=args.budget,
                                              jobs=inner, force=args.force, emit=emit, pipeline=args.pipeline,
                                              recipes=None if args.no_recipes else runner.recipes(vram, size,
                                                                                                  f"{name}.c"))
                except Exception as error:                   # one bad function must not stop the sweep
                    if emit:
                        emit({"event": "case-error", "name": name, "error": str(error)[-300:]})
                    return None

            with ThreadPoolExecutor(max(1, (args.jobs or 8) // inner)) as pool:
                cases = [c for c in pool.map(one, todo) if c is not None]
        elapsed = time.time() - started
        queue = resolvemod.hard_queue(cases)
        exact = [c for c in cases if c.status == "exact"]
        return {"image": image, "functions": len(todo), "resolved_cases": len(cases), "statuses": queue["statuses"],
                "exact": [{"name": c.name, "size": c.size, "source": c.best_digest} for c in exact],
                "exact_bytes": sum(c.size for c in exact), "builds": sum(c.builds for c in cases),
                "seconds": round(elapsed, 1),
                "exact_per_hour": round(len(exact) * 3600 / elapsed, 1) if elapsed else None,
                "queue": [{k: g[k] for k in ("cause", "meaning", "functions", "bytes", "expected_progress")}
                          | {"best": g["best"][:args.show]} for g in queue["queue"]],
                "state": str(store.root)}
    finally:
        store.close()
        if handle:
            handle.close()


def _hard_args(p):
    _common(p, rom_required=True)
    p.add_argument("--catalogue", required=True)
    p.add_argument("--catalogue-shift", type=_int, default=0)
    p.add_argument("--manifest", action="append", default=[], help="manifest of already matched code (repeatable)")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--max-size", type=_int, default=0)
    p.add_argument("--min-size", type=_int, default=4)
    p.add_argument("--every", type=int, default=1, help="take every Nth function (sampling for benchmarks)")
    p.add_argument("--show", type=int, default=3)
    p.add_argument("--pipeline", default="kmc+builtin")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--context")
    p.add_argument("--budget", type=int, default=200)
    p.add_argument("--state")
    p.add_argument("--events")
    p.add_argument("--no-draft", action="store_true")
    p.add_argument("--no-recipes", action="store_true")
    p.add_argument("--force", action="store_true")


resolve_hard.arguments = _hard_args


@command("hard-queue", "Group stored resolution cases by cause and rank them by expected progress")
def hard_queue(args):
    store = resolvemod.CaseStore(Path(args.state))
    try:
        cases = store.all()
        if args.image_name:
            cases = [c for c in cases if c.image == args.image_name]
        report = resolvemod.hard_queue(cases)
        for group in report["queue"]:
            group["best"] = group["best"][:args.show]
        return report
    finally:
        store.close()


def _queue_args(p):
    p.add_argument("--state", required=True, help="case store directory")
    p.add_argument("--image-name")
    p.add_argument("--show", type=int, default=5)


hard_queue.arguments = _queue_args
