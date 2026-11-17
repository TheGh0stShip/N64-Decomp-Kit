"""``decompile-run``: one command that drives every image of a project through the pipeline.

For each image named in the project's ``[images.<name>]`` configuration::

    discovery  ->  boundaries  ->  donors  ->  resolve  ->  strict queue  ->  ledger

* **discovery**   the catalogue checked against call, pointer and prologue evidence
                  (``n64dk.analysis.coverage``); an incomplete one is repaired into ``<out>/discovery``;

* **boundaries**  boundary operations the catalogue needs (reported; never applied to the project);
* **donors**      functions that are machine-code-identical to code already matched in another
                  local project are rebuilt from that proven source and verified;
* **resolve**     everything else climbs the resolution ladder (draft portfolio with recovered
                  declarations, compiler-family and per-unit recipe selection, cause diagnosis,
                  variant search), each function ending as a durable case;
* **queue**       exact cases re-verified with the strict oracle are exported as sources plus
                  manifest rows plus the declarations they still assume;
* **ledger**      byte ownership and its violations for the image.

Everything is written under ``--out`` (never into the project's sources).  The run is
resumable: cases, the donor index and each stage's result are kept, so a second invocation
continues where the first stopped.  Progress is appended to ``<out>/events.jsonl``.

Per-image build settings come from ``n64dk.toml``::

    [run]                         # defaults for every image
    pipeline = "ido5.3"
    flags = "-O2 -mips2 -non_shared -G 0"
    symbols = ["symbol_addrs.txt"]
    [run.images.main]             # overrides and, per manifest, the pipeline its rows used
    recipes = { "config/matching_ido_units.tsv" = "ido5.3", "config/matching_kmc_units.tsv" = "kmc+as" }
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import tomllib
from pathlib import Path

from ..cli import command
from ..resources import plan_jobs
from ..match import images as imagemod
from ..match import resolve as resolvemod
from ..match import solver


def _settings(project: Path, image: str) -> dict:
    path = project / "n64dk.toml"
    data = tomllib.loads(path.read_text()) if path.is_file() else {}
    run = dict(data.get("run") or {})
    per_image = (run.pop("images", {}) or {}).get(image, {})
    return {**run, **per_image}


def _stage(folder: Path, name: str, compute, redo: bool, identity: str = ""):
    """Checkpointed stage result, invalidated when its immutable inputs change."""
    path = folder / f"stage_{name}.json"
    meta = folder / f"stage_{name}.meta.json"
    if path.is_file() and not redo and (not identity or (meta.is_file() and
            json.loads(meta.read_text()).get("identity") == identity)):
        return json.loads(path.read_text()), True
    result = compute()
    folder.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(result, indent=1, default=str)
    with tempfile.NamedTemporaryFile("w", dir=folder, prefix=f".{name}-", delete=False) as handle:
        handle.write(payload)
        temporary = Path(handle.name)
    temporary.replace(path)
    if identity:
        temporary_meta = meta.with_suffix(".tmp")
        temporary_meta.write_text(json.dumps({"identity": identity}))
        temporary_meta.replace(meta)
    return result, False


def _profiled(profiler, name: str, image: str, compute):
    """``compute`` measured as one stage of the run's profile (``n64dk.profiling``), with what it
    produced recorded as the stage's gain."""
    def run():
        with profiler.stage(name, image) as record:
            result = compute()
            if isinstance(result, dict):
                record["gain"] = {key: result[key] for key in (
                    "functions_recovered", "functions_awaiting_symbols", "statuses", "promoted", "declared",
                    "chosen", "rodata_settlement") if key in result and not isinstance(result[key], list)}
                if isinstance(record["gain"].get("chosen"), dict):
                    record["gain"]["chosen"] = record["gain"]["chosen"].get("label")
            return result
    return run


def _identity(**values) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()


CALIBRATION_SIZES = (0x18, 0x80)      # small enough to match from a draft, large enough to depend on the recipe


RECIPE_DOUBT = 0.4         # share of an image whose marks contradict its configured recipe that triggers calibration
DOUBT_SAMPLE = 96


def calibrate_recipe(resolve_hard, resolve_options, state: Path, image: str, rows, skip, sample: int,
                     delta: int | None = None, region: tuple[int, int] | None = None) -> dict:
    """Resolve a spread sample of small functions with every available recipe tried on each, and
    return the recipe most of the byte-identical ones were built with.

    A title's compiler and optimisation level are not known in advance, and the configured recipe
    is a guess (for a project made by ``decompile-init``, a fingerprint).  The sample is taken
    across the whole address range, skipping what donors already recovered, so library code built
    with another compiler does not decide the answer.  The cases it produces stay in the store."""
    low, high = CALIBRATION_SIZES
    eligible = [row for row in rows if low <= row[2] <= high and row[1] not in skip]
    if not eligible:
        return {"sample": 0, "identical": 0, "recipes": {}, "chosen": None, "reason": "no functions in the size window"}
    every = max(1, len(eligible) // sample)
    extra = {}
    if region is not None:                               # only this region's functions
        extra["only_names"] = [",".join(sorted({row[0] for row in eligible}))]
    result = resolve_hard(resolve_options(min_size=low, max_size=high, every=every, limit=sample,
                                          cross_recipes=64, refine=None, budget=40, provisional=True,
                                          write_scope=False if region is not None else True, **extra))
    store = resolvemod.CaseStore(state)
    try:
        cases = [case for case in store.all() if case.image == image and case.status in ("exact", "assumed")
                 and low <= case.size <= high and (region is None or region[0] <= case.vram <= region[1])]
    finally:
        store.close()
    tally: dict[str, int] = {}
    for case in cases:
        if case.recipe:
            tally[case.recipe] = tally.get(case.recipe, 0) + 1
    ranked = sorted(tally.items(), key=lambda item: (-item[1], item[0]))
    chosen = None
    if ranked and ranked[0][1] >= 3:
        pipeline, _, flags = ranked[0][0].partition(" ")
        chosen = {"label": ranked[0][0], "pipeline": pipeline, "flags": flags, "matched": ranked[0][1]}
    return {"sample": result.get("functions"), "identical": len(cases), "recipes": dict(ranked[:8]),
            "chosen": chosen, "seconds": result.get("seconds"),
            "reason": None if chosen else "fewer than three sample functions were byte-identical under any recipe"}


REGION_MIN_FUNCTIONS = 40      # a region calibrated on its own needs this many functions
REGION_MIN_SAMPLE = 24


def calibrate_regions(resolve_hard, resolve_options, state: Path, image: str, rows, skip, sample: int,
                      delta: int, data: bytes, emit=None) -> dict:
    """Regional calibration: the image's toolchain regions (``n64dk.match.toolchain_regions``)
    each calibrated on a sample of their own small functions, so a region built by another recipe
    than the rest is not decided by the majority.  Returns ``{"regions": [...], "map": [...]}``
    where ``map`` holds the regions that chose a recipe (start, end, pipeline, flags) for
    ``resolve-hard``'s ``region_map``.  Regions without enough functions or a choice keep the
    image's recipe."""
    from ..match import toolchain_regions as tcmod
    found = tcmod.reconstruct(data, delta, rows)
    regions = [r for r in found.get("regions") or [] if r["functions"] >= REGION_MIN_FUNCTIONS
               and r["verdict"] != "assembly"]
    if len(regions) < 2:
        return {"regions": [], "map": [], "reason": "fewer than two regions large enough to calibrate apart"}
    total = sum(r["functions"] for r in regions)
    out, mapping = [], []
    for region in regions:
        lo, hi = int(region["start"], 16), int(region["end"], 16)
        inside = [row for row in rows if lo <= row[1] <= hi]
        share = max(REGION_MIN_SAMPLE, round(sample * region["functions"] / total))
        found_here = calibrate_recipe(resolve_hard, resolve_options, state, image, inside, skip, share, delta,
                                      region=(lo, hi))
        chosen = found_here.get("chosen")
        out.append({"start": region["start"], "end": region["end"], "functions": region["functions"],
                    "verdict": region["verdict"], "sample": found_here.get("sample"),
                    "identical": found_here.get("identical"), "recipes": found_here.get("recipes"),
                    "chosen": (chosen or {}).get("label")})
        if chosen:
            mapping.append({"start": lo, "end": hi, "pipeline": chosen["pipeline"], "flags": chosen["flags"],
                            "label": chosen["label"]})
        if emit:
            emit("stage", image=image, stage="calibrate-region", start=region["start"], chosen=(chosen or {}).get("label"))
    return {"regions": out, "map": mapping}


def refine_settings(settings: dict, args):
    """``[run.refine]`` (or a per-image override) merged with the command line; None when no
    refiner command is configured."""
    from ..match import refine as refinemod
    built = refinemod.Settings.from_table(settings.get("refine"), getattr(args, "refine_command", None))
    if built is None:
        return None
    for key in ("rounds", "max_cases", "jobs", "max_score"):
        value = getattr(args, f"refine_{key}", None)
        if value is not None:
            setattr(built, key, value)
    if getattr(args, "refine_known_source", None):
        built.known_source = [*built.known_source, *args.refine_known_source]
    return built


def declare_assumed(resolve_hard, resolve_options, state: Path, image: str, folder: Path, overrides: dict) -> dict:
    """Declare the addresses that byte-identical (``assumed``) cases lean on and verify those cases
    again.

    Only a symbol whose name states its own address (``D_80123456`` at 0x80123456) is declared: the
    declaration says nothing the name did not, and the address was read from the target's own
    instructions.  Any other assumption (a named symbol, a section) is left for a person.  The
    verdict still comes from the strict verifier; a case it does not call exact stays ``assumed``."""
    store = resolvemod.CaseStore(state)
    try:
        names: dict[str, int] = {}
        waiting = 0
        for case in store.all():
            if case.image != image or case.status != "assumed":
                continue
            waiting += 1
            for item in (case.strict or {}).get("assumptions", []):
                try:
                    address = int(str(item.get("address")), 16)
                except ValueError:
                    continue
                if item.get("kind") == "symbol" and item.get("name") == f"D_{address:08X}":
                    names[item["name"]] = address
    finally:
        store.close()
    if not names:
        return {"declared": 0, "promoted": 0, "waiting": waiting}
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "declared_symbols.txt"
    path.write_text("".join(f"{name} = 0x{address:08X};\n" for name, address in sorted(names.items(), key=lambda r: r[1])))
    options = resolve_options(**overrides, refine=None, only_statuses=("assumed",))
    options.symbols = list(options.symbols) + [str(path)]
    report = resolve_hard(options)
    statuses = report.get("statuses") or {}
    return {"declared": len(names), "file": str(path), "waiting": waiting, "promoted": statuses.get("exact", 0),
            "still_assumed": statuses.get("assumed", 0)}


def resolve_options_for(args, settings: dict, *, mode, project: Path, spec, jobs: int, events: Path, out: Path,
                        manifests: list[str], recipes: dict, recovered: set[int]):
    """The ``resolve-hard`` options of one image, as a function of per-call overrides.  ``mode`` is
    the effort policy; the options themselves come from ``args`` after ``solver.apply_policy``
    (``normal`` fills exactly the defaults decompile-run had before effort modes)."""
    def resolve_options(**overrides):
        options = argparse.Namespace(
            project=str(project), config=None, toolchain_dir=args.toolchain_dir, normalizer=None, include=[],
            rom=str(spec.path), vram_delta=spec.vram_delta if spec.delta_source == "declared" else None,
            jobs=jobs, workers=args.workers,
            worker_memory_mb=args.worker_memory_mb, memory_reserve_mb=args.memory_reserve_mb,
            refine=refine_settings(settings, args) if mode.refine else None, refine_command=None, keep_padding=False,
            search_ceiling=(args.search_ceiling if args.search_ceiling is not None
                            else settings.get("search_ceiling", resolvemod.SEARCH_CEILING)),
            symbols=[str(project / s) for s in settings.get("symbols", [])],
            catalogue=str(spec.catalogue), catalogue_shift=spec.catalogue_shift,
            manifest=[m + ("=" + recipes[str(Path(m).resolve())] if str(Path(m).resolve()) in recipes else "")
                      for m in manifests],
            limit=args.limit, max_size=args.max_size, min_size=4, every=1, holdout=0, show=5,
            image_name=spec.name, pipeline=settings.get("pipeline", args.pipeline),
            flags=settings.get("flags", args.flags), context="auto",
            context_parts="structs,globals,prototypes", proto_confidence=0.9, budget=args.budget,
            context_headers=[str(project / h) for h in settings.get("context_headers", [])],
            state=str(out / "state"), events=str(events), no_draft=False, no_recipes=False,
            draft_portfolio=True, draft_options=settings.get("draft_options", ""), force=False,
            skip_vrams=recovered, addr=None, size=None, cross_recipes=getattr(args, "cross_recipes", None),
            only_names=getattr(args, "only_names", None), order=getattr(args, "order", None),
            region_recipes=bool(getattr(args, "region_recipes", False) or
                                settings.get("region_recipes", False)),
            unit_recipes=bool(getattr(args, "unit_recipes", False) or
                              settings.get("unit_recipes", False)),
            skip_unknown_search=bool(getattr(args, "skip_unknown_search", False) or
                                     settings.get("skip_unknown_search", False)),
            search_economics=bool(getattr(args, "search_economics", False) or
                                  settings.get("search_economics", False)),
            recipe_gate=bool(settings.get("recipe_gate", True) if getattr(args, "recipe_gate", None) is None
                             else args.recipe_gate))
        for key, value in overrides.items():
            setattr(options, key, value)
        return options

    return resolve_options


@command("decompile-run", "Drive every configured image through boundaries, donors, resolution, strict queue and ledger")
def decompile_run(args):
    """One heavy job at a time, with a preflight and a lease (see ``n64dk.safety``)."""
    from .. import safety
    prepare_invocation(args)
    try:
        with safety.heavy_job("decompile-run", Path(args.out), wait_for_lock=getattr(args, "wait_for_lock", False),
                              force=getattr(args, "force_resources", False), argv=sys.argv[1:]) as check:
            result = _decompile_run(args)
    except safety.Busy as error:
        raise SystemExit(str(error)) from None
    if isinstance(result, dict) and not check.get("nested"):
        result["preflight"] = check
        result["paused"] = safety.pauses()
    return result


# options a resumed invocation takes from its own command line; every other one comes from the
# invocation that started the run (solver/invocation.json)
RESUME_FROM_COMMAND_LINE = ("budget_time", "budget_builds", "budget_model_calls", "wait_for_lock", "force_resources",
                            "jobs", "workers", "worker_memory_mb", "memory_reserve_mb")
_NOT_SAVED = {"_fn", "format", "resume", "command", "redo"} | set(RESUME_FROM_COMMAND_LINE)


def prepare_invocation(args) -> solver.Policy:
    """Merge ``--resume RUN_DIR`` with the invocation that started the run, check the effort mode
    and fill every option the command line left unset from it."""
    if getattr(args, "resume", None):
        run_dir = Path(args.resume).resolve()
        path = run_dir / "solver" / "invocation.json"
        if not path.is_file():
            raise SystemExit(f"--resume {run_dir}: no solver/invocation.json; only a run made by this version "
                             "of decompile-run can be resumed")
        saved = json.loads(path.read_text())
        rounds, effort, schedule = (getattr(args, "rounds", None), getattr(args, "effort", None),
                                    getattr(args, "schedule", None))
        for key, value in saved.items():
            if key not in _NOT_SAVED:
                setattr(args, key, value)
        if effort is not None and effort != saved.get("effort"):
            # another mode for the rounds still to come (e.g. a finished normal run continued as deep):
            # its rounds, scheduling, techniques and cascade apply; the options the run was started
            # with (budget per function, sizes, recipes) stay as they were, so round 1 is comparable
            args.effort, args.rounds, args.schedule = effort, None, None
        if rounds is not None:
            args.rounds = rounds
        if schedule is not None:
            args.schedule = schedule
        args.out, args.redo = str(run_dir), False
    if not getattr(args, "project", None) or not getattr(args, "out", None):
        raise SystemExit("decompile-run needs --project and --out (or --resume RUN_DIR)")
    mode = solver.policy(getattr(args, "effort", None))
    solver.check_policy(mode)
    args.effort = mode.name
    solver.apply_policy(args, mode)
    return mode


def save_invocation(args, out: Path) -> None:
    keep = {}
    for key, value in vars(args).items():
        if key in _NOT_SAVED or callable(value):
            continue
        try:
            json.dumps(value)
        except TypeError:
            continue
        keep[key] = value
    for key in ("project", "donors", "donor_index", "library", "toolchain_dir"):    # resumable from anywhere
        if isinstance(keep.get(key), str) and keep[key]:
            keep[key] = str(Path(keep[key]).expanduser().resolve())
    solver.write_json(out / "solver" / "invocation.json", keep)


def _decompile_run(args):
    if getattr(args, "donors", None) and not Path(args.donors).is_file():
        raise SystemExit(f"--donors {args.donors}: no such file")
    project = Path(args.project).resolve()
    out = Path(args.out).resolve()
    if (out == project or project in out.parents) and not (project / ".n64dk" == out or
            project / ".n64dk" in out.parents) and not getattr(args, "allow_project_output", False):
        raise SystemExit("refusing to write generated run state inside the project source tree; "
                         "use <project>/.n64dk/... or --allow-project-output")
    out.mkdir(parents=True, exist_ok=True)
    from ..profiling import Profiler
    profiler = Profiler(out)
    registry = imagemod.load_registry(project)
    if not registry:
        raise SystemExit("no [images.<name>] tables in the project's n64dk.toml: declare each image (path, "
                         "vram_delta for linear images, catalogue, manifests)")
    names = sorted(registry) if args.all_images or not args.image else args.image
    events = out / "events.jsonl"
    # --- effort mode, rounds log, observations and budgets (n64dk.match.solver)
    mode = solver.policy(getattr(args, "effort", None))
    resume = bool(getattr(args, "resume", None))
    solver_dir = out / "solver"
    log = solver.RoundsLog(out / "rounds.jsonl")
    session = (log.latest_session() if resume else None) or f"{time.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
    if not resume:
        save_invocation(args, out)
    observations = solver.Observations(solver_dir / "observations.json")
    if not resume:
        observations.cells, observations.facts, observations.evidence, observations.plateaus = {}, {}, {}, {}
    budget = solver.Budget(solver.parse_duration(getattr(args, "budget_time", None)),
                           getattr(args, "budget_builds", None), getattr(args, "budget_model_calls", None))
    resource_plan = plan_jobs(args.jobs, reserve_mb=args.memory_reserve_mb or None,
                              memory_per_job_mb=args.worker_memory_mb or None)
    jobs = resource_plan.jobs
    started = time.time()

    def emit(kind: str, **fields) -> None:
        with events.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"time": round(time.time(), 3), "event": kind, **fields}) + "\n")

    report = {"project": str(project), "images": {}, "resources": resource_plan.as_dict()}
    emit("resource-plan", **resource_plan.as_dict())
    # --- 0. discovery: is each catalogue complete enough to decompile against?  An incomplete one
    # is repaired from call, pointer and prologue evidence into the run directory (never the
    # project), and the report says so: a percentage over a catalogue that misses code is not one.
    repaired: dict[str, Path] = {}
    placed: dict = {}                    # segments the discovery stage placed from the ROM
    names = list(names)
    discovery_mode = getattr(args, "discovery", None) or "repair"
    if discovery_mode != "off" and "discovery" not in args.skip_stage:
        from .discovery import run_audit
        try:
            with profiler.stage("discovery", "*"):
                found = run_audit(project, names, out / "discovery", repair=discovery_mode == "repair")
            report["discovery"] = discovery_summary(found)
            repaired = {name: Path(img["repair"]["catalogue"]) for name, img in found["images"].items()
                        if (img.get("repair") or {}).get("catalogue")}
            for name, info in (found.get("extra_images") or {}).items():
                placed[name] = imagemod.ImageSpec(name, Path(info["bin"]), int(info["vram"], 16),
                                                  Path(info["catalogue"]))
                if args.all_images or not args.image:
                    names.append(name)
        except Exception as error:                           # noqa: BLE001 - reported; the run goes on
            report["discovery"] = {"error": f"{type(error).__name__}: {error}"[-300:]}
        emit("stage", image="*", stage="discovery", result=report["discovery"])

    def resolve_spec(name: str):
        if name in placed:
            return placed[name]
        spec = imagemod.resolve(project, name)
        if name in repaired:
            import dataclasses
            spec = dataclasses.replace(spec, catalogue=repaired[name], _rows=None)
        return spec
    # a library of earlier runs: every other title in it is a donor, and this run joins it at the end
    from ..match import library as libmod
    library = Path(args.library).expanduser().resolve() if getattr(args, "library", None) else None
    first = imagemod.resolve(project, "main" if "main" in registry else sorted(registry)[0])
    title_key = libmod.rom_key(Path(first.path).read_bytes())
    specs_seen = []
    # every function start of the title, whichever image it is in: a unit may call across images
    title_starts: set[int] = set()
    for name in sorted(set(registry) | set(placed)):
        try:
            title_starts.update(vram for _n, vram, _s in resolve_spec(name).rows())
        except Exception:                                    # noqa: BLE001 - an image without a catalogue
            pass
    for name in names:
        spec = resolve_spec(name)
        settings = _settings(project, spec.name)
        folder = out / spec.name
        rows = spec.rows()
        data, delta = spec.load(), spec.delta
        emit("image-start", image=spec.name, functions=len(rows))
        image_report: dict = {"functions": len(rows)}
        manifests = [str(m) for m in spec.manifests]
        stage_identity = _identity(image=spec.name, image_digest=hashlib.sha256(data).hexdigest(),
                                   delta=delta, rows=rows, manifests=manifests, settings=settings,
                                   min_confidence=args.min_confidence)
        recipes = {str((project / k).resolve()): v for k, v in (settings.get("recipes") or {}).items()}

        # --- 1. boundaries (report only)
        def boundaries():
            from ..analysis import boundaries as boundmod
            from ..match import byteledger as ownmod
            # Manifest rows are ownership claims, not rebuild receipts.  The unattended boundary
            # audit is report-only and must not label those ranges as independently verified.
            verified = boundmod.Verified([])
            operations = boundmod.solve(boundmod.Image(data, delta), rows, verified=verified)
            new_rows, applied, skipped = boundmod.apply(rows, operations, args.min_confidence)
            folder.mkdir(parents=True, exist_ok=True)
            boundmod.dump_operations(folder / "boundary_operations.json", operations, image=spec.name)
            kinds: dict[str, int] = {}
            for op in operations:
                kinds[op.get("kind", "?")] = kinds.get(op.get("kind", "?"), 0) + 1
            return {"operations": kinds, "would_apply": len(applied), "functions_after": len(new_rows),
                    "file": str(folder / "boundary_operations.json")}
        if "boundaries" not in args.skip_stage:
            try:
                image_report["boundaries"], _cached = _stage(folder, "boundaries", _profiled(profiler, "boundaries", spec.name, boundaries), args.redo,
                                                               stage_identity)
            except Exception as error:                       # a stage failure is reported, not fatal
                image_report["boundaries"] = {"error": str(error)[-300:]}
            emit("stage", image=spec.name, stage="boundaries", result=image_report["boundaries"])

        # --- 2. donors
        recovered: set[int] = set()
        library_identity = libmod.identity(library, title_key)
        if (args.donors or library_identity) and "donors" not in args.skip_stage:
            def donors():
                from ..match import transplant
                from ..match.engine import Target
                specs = (transplant.load_donors(args.donors, args.donor or None, args.exclude_donor or None)
                         if args.donors else []) + libmod.donors(library, title_key)
                index, _stats = transplant.build_index(specs, args.donor_index or out / "donor_index.json")
                target = Target(data, delta, (0, len(data)))
                skip = [(v, v + s) for v, s in ((r.vram, r.size) for m in manifests
                                                for r in _rows_of(m, delta))]
                from ..match.toolchain import load_config
                toolchain = args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN") or \
                    load_config(project, None, None).toolchain_root
                result = transplant.run(None, target, rows, index, skip=skip, out_dir=folder / "donors",
                                        jobs=min(jobs, 4), toolchain_root=Path(toolchain) if toolchain else None,
                                        other_starts=title_starts - {v for _n, v, _s in rows})
                keep = {k: v for k, v in result.items()
                        if not k.startswith("_") and (not isinstance(v, (list, dict)) or k in ("verdicts", "timing_s", "rodata_settlement"))}
                by_name = {n: v for n, v, _s in rows}
                keep["verified"] = [{"functions": r.get("functions", []), "vram": r.get("target_vram"),
                                     "size": r.get("size"), "donor": r.get("donor"), "unit": r.get("donor_unit"),
                                     "source_kind": ("assembly" if Path(str(r.get("donor_unit", ""))).suffix.lower()
                                                     in (".s", ".asm") else "c"),
                                     "function_vrams": [by_name[n] for n in r.get("functions", []) if n in by_name]}
                                    for r in result.get("rows", [])
                                    if r.get("verdict") == transplant.EXACT_VERDICT]
                keep["assumed"] = [{"functions": r.get("functions", []), "vram": r.get("target_vram"),
                                    "size": r.get("size"), "donor": r.get("donor"), "unit": r.get("donor_unit"),
                                    "source_kind": ("assembly" if Path(str(r.get("donor_unit", ""))).suffix.lower()
                                                    in (".s", ".asm") else "c"),
                                    "awaiting": r.get("awaiting") or {},
                                    "function_vrams": [v for _n, v, _s in rows
                                                       if int(str(r.get("target_vram")), 16) <= v
                                                       < int(str(r.get("target_vram")), 16) + (r.get("size") or 0)]}
                                   for r in result.get("rows", [])
                                   if r.get("verdict") == transplant.ASSUMED_VERDICT]
                return keep
            try:
                image_report["donors"], _cached = _stage(folder, "donors", _profiled(profiler, "donors", spec.name, donors), args.redo,
                                                          _identity(base=stage_identity, donors=args.donors,
                                                                    selected=args.donor,
                                                                    excluded=args.exclude_donor,
                                                                    library=library_identity))
                for row in image_report["donors"].get("verified", []) + image_report["donors"].get("assumed", []):
                    recovered.update(int(v) for v in row.get("function_vrams", []))
            except Exception as error:
                image_report["donors"] = {"error": str(error)[-300:]}
            emit("stage", image=spec.name, stage="donors",
                 verified=len(image_report["donors"].get("verified", [])) if isinstance(image_report["donors"], dict) else 0)

        # --- 3. resolve
        resolve_options = resolve_options_for(args, settings, mode=mode, project=project, spec=spec, jobs=jobs,
                                              events=events, out=out, manifests=manifests, recipes=recipes,
                                              recovered=recovered)

        plan = solver.stage_plan(mode, args, settings)
        held = {"overrides": {}}
        if "resolve" in plan:
            from .resolve import resolve_hard
            round1 = solver_dir / f"round1_{spec.name}.json"
            last, stopped = log.progress(session, spec.name) if resume else (0, None)

            def sweep():
                """Round 1: today's decompile-run resolve stage, unchanged (calibrate, sweep, declare)."""
                chosen_recipe = None
                # --- 3a. calibrate: measure the title's recipe on a sample of its own functions
                sample = args.calibrate if args.calibrate is not None else int(settings.get("calibrate", 0) or 0)
                if sample == 0 and "calibrate" not in args.skip_stage and settings.get("pipeline"):
                    # No calibration asked for: the configured recipe is taken on trust.  When the code's
                    # own marks say most of the image was built another way, measure instead.
                    try:
                        from ..match import idioms
                        table = idioms.Table.load()
                        marked = [(vram, idioms.features(data[vram - delta:vram - delta + size], vram))
                                  for _name, vram, size in rows if size >= 8]
                        found = idioms.doubt(marked, table, f"{settings['pipeline']} {settings.get('flags', '')}")
                        if found["share"] >= RECIPE_DOUBT:
                            image_report["recipe_doubt"] = found
                            sample = DOUBT_SAMPLE
                            emit("stage", image=spec.name, stage="recipe-doubt", share=found["share"])
                    except Exception:                            # noqa: BLE001 - a hint, never a reason to stop
                        pass
                regional = bool(getattr(args, "regional_calibration", False) or settings.get("regional_calibration"))
                if sample > 0 and "calibrate" not in args.skip_stage and regional:
                    def calibrate_by_region():
                        return calibrate_regions(resolve_hard, resolve_options, out / "state", spec.name, rows,
                                                 recovered, sample, delta, data, emit)
                    try:
                        image_report["calibrate_regions"], _cached = _stage(
                            folder, "calibrate_regions", _profiled(profiler, "calibrate-regions", spec.name,
                                                                   calibrate_by_region), args.redo,
                            _identity(base=stage_identity, sample=sample, donors=sorted(recovered)))
                        held["region_map"] = image_report["calibrate_regions"].get("map") or []
                    except Exception as error:
                        image_report["calibrate_regions"] = {"error": str(error)[-300:]}
                if sample > 0 and "calibrate" not in args.skip_stage:
                    def calibrate():
                        return calibrate_recipe(resolve_hard, resolve_options, out / "state", spec.name, rows, recovered,
                                                sample, delta)
                    try:
                        image_report["calibrate"], _cached = _stage(
                            folder, "calibrate", _profiled(profiler, "calibrate", spec.name, calibrate), args.redo,
                            _identity(base=stage_identity, sample=sample, donors=sorted(recovered)))
                        chosen_recipe = image_report["calibrate"].get("chosen")
                    except Exception as error:
                        image_report["calibrate"] = {"error": str(error)[-300:]}
                    emit("stage", image=spec.name, stage="calibrate",
                         chosen=(chosen_recipe or {}).get("label"))
                overrides = held["overrides"] = {}
                if chosen_recipe:
                    overrides = held["overrides"] = {"pipeline": chosen_recipe["pipeline"], "flags": chosen_recipe["flags"]}
                if held.get("region_map"):
                    overrides = held["overrides"] = {**overrides, "region_map": held["region_map"]}
                try:
                    call = dict(overrides)
                    if resume:
                        # Round 1 was cut short: a case the interrupted sweep finished is not swept
                        # again (that would continue it from its stored source, a second and different
                        # pass, and repeat builds).  Calibration samples still marked provisional, and
                        # functions without a case, are swept as an uninterrupted run would sweep them.
                        finished = finished_cases(out / "state", spec.name)
                        if finished:
                            # applied after the selection (size window, --limit), so the resumed
                            # sweep covers exactly the functions the original one selected
                            call["resume_finished"] = finished
                            image_report["resume_skipped_finished"] = len(finished)
                    image_report["resolve"] = _profiled(profiler, "resolve", spec.name,
                                                        lambda: resolve_hard(resolve_options(**call)))()
                except Exception as error:
                    image_report["resolve"] = {"error": str(error)[-300:]}
                # --- 3b. declare: settle byte-identical cases that only wait for an address to be declared
                if (args.declare_assumed or settings.get("declare_assumed")) and "error" not in image_report["resolve"]:
                    try:
                        image_report["declare"] = _profiled(profiler, "declare", spec.name, lambda: declare_assumed(
                            resolve_hard, resolve_options, out / "state", spec.name, folder, overrides))()
                        moved = image_report["declare"].get("promoted", 0)
                        statuses = image_report["resolve"].get("statuses")
                        if moved and isinstance(statuses, dict):
                            statuses["exact"] = statuses.get("exact", 0) + moved
                            statuses["assumed"] = max(0, statuses.get("assumed", 0) - moved)
                    except Exception as error:
                        image_report["declare"] = {"error": str(error)[-300:]}
                    emit("stage", image=spec.name, stage="declare", promoted=image_report["declare"].get("promoted"))

                solver.write_json(round1, {**{key: image_report.get(key) for key in
                                              ("recipe_doubt", "calibrate", "resolve", "declare") if key in image_report},
                                           "overrides": held["overrides"]})
                return {"model_calls": int(((image_report.get("resolve") or {}).get("refine") or {}).get("calls") or 0),
                        "declared": isinstance(image_report.get("declare"), dict)
                        and "error" not in image_report["declare"]}

            if last >= 1 and round1.is_file():               # a resume: round 1 is not redone
                saved = json.loads(round1.read_text())
                held["overrides"] = saved.pop("overrides", None) or {}
                image_report.update(saved)

            def technique(name, decisions, calls_left):
                """One later-round technique on a named set of stored cases (n64dk.match.solver)."""
                options = resolve_options(**held["overrides"], **solver.technique_options(name, mode),
                                          only_names=[",".join(sorted({d.name for d in decisions}))])
                if name == "refine":
                    if options.refine is None:
                        return {"error": "no refiner configured"}
                    if calls_left is not None:
                        cap = max(1, calls_left // max(1, options.refine.rounds))
                        options.refine.max_cases = min(options.refine.max_cases or cap, cap)
                else:
                    options.refine = None                    # a build technique never asks the refiner
                result = _profiled(profiler, f"round:{name}", spec.name, lambda: resolve_hard(options))()
                return {"model_calls": int(((result.get("refine") or {}).get("calls")) or 0),
                        "error": result.get("error")}

            def declare():
                result = declare_assumed(resolve_hard, resolve_options, out / "state", spec.name, folder,
                                         held["overrides"])
                listing = folder / "declared_symbols.txt"
                names = [line.split(" = ")[0] for line in listing.read_text().splitlines()
                         if " = " in line] if listing.is_file() else []
                image_report.setdefault("declare_rounds", []).append(result)
                return {**result, "names": names}

            graph: dict[int, set[int]] = {}

            def neighbours(vram: int) -> set[int]:
                if not graph:                                  # rows and cases are both in link space
                    graph.update(solver.call_graph(data, delta, rows) or {0: set()})
                return graph.get(vram, set())

            ceiling = (args.search_ceiling if args.search_ceiling is not None
                       else settings.get("search_ceiling", resolvemod.SEARCH_CEILING))
            model = bool(mode.refine and refine_settings(settings, args) is not None)
            finished = stopped is not None and str(stopped.get("reason", "")).startswith(
                ("fixed point", "nothing applicable"))
            if finished:
                image_report["solver_stop"] = stopped
            else:
                image_report["solver_stop"] = solver.solve_image(
                    image=spec.name, store_root=out / "state", mode=mode, budget=budget, log=log,
                    observations=observations, hooks=solver.Hooks(sweep, technique, declare, neighbours),
                    session=session, rounds=args.rounds, start_round=last + 1,
                    unknown=lambda: solver.Stretches((image_report.get("resolve") or {}).get("unknown_toolchain")),
                    ceiling=ceiling, model=model, emit=emit)

        # --- 3c. solver outputs (read the store, build nothing): coverage, primary causes, dossiers
        if "resolve" in plan:
            try:
                image_report["solver"] = solver_outputs(
                    out, spec.name, mode, observations, rows=rows, data=data, delta=delta, recovered=recovered,
                    manifest_rows=[(r.vram, r.size) for m in manifests for r in _rows_of(m, delta)],
                    stretches=solver.Stretches((image_report.get("resolve") or {}).get("unknown_toolchain")),
                    ceiling=ceiling, model=model, stop=image_report.get("solver_stop") or {},
                    boundary_file=folder / "boundary_operations.json")
            except Exception as error:                       # an observation failure never costs the run
                image_report["solver"] = {"observation_error": f"{type(error).__name__}: {error}"[-300:]}

        # --- 3d. toolchain regions (builds nothing): ranked recipes per region, component mismatches,
        #     abstention and dossiers, with the run's exact cases as proof
        if "resolve" in plan:
            try:
                from ..match import toolchain_regions as tcmod
                store = resolvemod.CaseStore(out / "state", readonly=True)
                try:
                    image_cases = [case for case in store.all() if case.image == spec.name]
                finally:
                    store.close()
                from ..match import transform_classes as transforms
                tally: dict[str, int] = {}
                for case in image_cases:
                    if case.status == "exact":
                        found = transforms.provenance(case.stages)
                        key = found["class"] or "as drafted"
                        tally[key] = tally.get(key, 0) + 1
                        tally["with frame scaffolding"] = tally.get("with frame scaffolding", 0) + found["scaffolding"]
                image_report["exact_provenance"] = tally
                regions = tcmod.reconstruct(data, delta, rows, cases=image_cases)
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "toolchain_regions.json").write_text(json.dumps(regions, indent=1) + "\n")
                image_report["toolchain_regions"] = {**(regions.get("summary") or {}),
                                                     "file": str(folder / "toolchain_regions.json")}
            except Exception as error:                       # noqa: BLE001 - an analysis, never the run's failure
                image_report["toolchain_regions"] = {"observation_error": f"{type(error).__name__}: {error}"[-300:]}

        # --- 4. strict queue
        store = resolvemod.CaseStore(out / "state")
        try:
            image_report["queue"] = resolvemod.export_queue(store, out / "queue", spec.name, not args.strict_only)
            image_report["hard_queue"] = [
                {k: g[k] for k in ("cause", "functions", "bytes")}
                for g in resolvemod.hard_queue([c for c in store.all() if c.image == spec.name])["queue"]]
        finally:
            store.close()

        # --- 5. ledger
        if "ledger" not in args.skip_stage:
            def ledger():
                from ..match import byteledger as ownmod
                manifest_rows = []
                for manifest in manifests:
                    cls = "asm" if "asm" in Path(manifest).name.lower() else "c"
                    manifest_rows += ownmod.read_manifest(manifest, delta, cls)
                built = ownmod.build(ownmod.ImageInfo.of(spec.name, data, delta), rows, manifest_rows, data=data)
                violations = built.check()
                folder.mkdir(parents=True, exist_ok=True)
                built.to_tsv(folder / "ownership.tsv")
                kinds: dict[str, int] = {}
                for violation in violations:
                    kinds[violation.kind] = kinds.get(violation.kind, 0) + 1
                return {"totals": built.totals(), "violations": kinds, "file": str(folder / "ownership.tsv")}
            try:
                image_report["ledger"], _cached = _stage(folder, "ledger", _profiled(profiler, "ledger", spec.name, ledger), args.redo, stage_identity)
            except Exception as error:
                image_report["ledger"] = {"error": str(error)[-300:]}
        report["images"][spec.name] = image_report
        specs_seen.append(spec)
        emit("image-done", image=spec.name)
    # The tables under queue/ are rewritten by each image's export: one more export, of every
    # image, leaves them complete (and the library below describes every image, not the last).
    if len(specs_seen) > 1:
        store = resolvemod.CaseStore(out / "state")
        try:
            report["queue"] = {k: v for k, v in resolvemod.export_queue(
                store, out / "queue", None, not args.strict_only).items() if k != "skipped"}
        except Exception as error:
            report["queue"] = {"error": str(error)[-300:]}
        finally:
            store.close()
    # this run as a donor for other titles (strictly exact functions only)
    try:
        symbol_files = [project / s for s in (_settings(project, names[0]).get("symbols") or [])]
        report["donor"] = libmod.write_donor(out, project, specs_seen, title_key, symbol_files)
        if library is not None:
            report["donor"]["registered"] = libmod.register(library, out, title_key)
    except Exception as error:
        report["donor"] = {"error": str(error)[-300:]}
    report["seconds"] = round(time.time() - started, 1)
    report["profile"] = profiler.summary()
    if os.environ.get("N64DK_MEASURE_RSS") == "1":
        from .. import safety as safetymod
        report["tool_profile"] = str(safetymod.save_tool_profile())
    report["failed_stages"] = {name: _headline(item)["errors"] for name, item in report["images"].items()
                               if _headline(item)["errors"]}
    report["status"] = "incomplete" if report["failed_stages"] else "complete"
    (out / "report.json").write_text(json.dumps(report, indent=1, default=str))
    (out / "report.md").write_text(_markdown(report))
    return {"status": report["status"], "failed_stages": report["failed_stages"],
            "discovery": {k: v for k, v in (report.get("discovery") or {}).items() if k != "images"},
            "report": str(out / "report.md"), "events": str(events),
            "images": {name: _headline(item) for name, item in report["images"].items()},
            "seconds": report["seconds"]}


def solver_outputs(out: Path, image: str, mode, observations, *, rows, data: bytes, delta: int, recovered,
                   manifest_rows, stretches, ceiling, model: bool, stop: dict, boundary_file: Path) -> dict:
    """Coverage of every catalogued function and a dossier for every unresolved one, from the
    case store (read-only).  Every address is in link space (``ImageSpec.rows``), as cases are."""
    store = resolvemod.CaseStore(out / "state", readonly=True)
    try:
        cases = [case for case in store.all() if case.image == image]
    finally:
        store.close()
    left_out = {}
    scope = out / "state" / f"scope_{image}.json"
    if scope.is_file():
        try:
            left_out = {int(row["vram"], 16): row["reason"] for row in json.loads(scope.read_text()).get("left_out", [])}
        except (ValueError, KeyError, TypeError):
            left_out = {}

    def covered(vram: int) -> bool:
        return any(start <= vram < start + size for start, size in manifest_rows)
    found = solver.coverage(rows, cases, recovered=recovered, left_out=left_out, covered=covered,
                            image_size=len(data), delta=delta)
    solver.write_json(out / "solver" / f"coverage_{image}.json", found)
    graph = solver.call_graph(data, delta, rows)
    order = sorted(vram for _n, vram, _s in rows)
    position = {vram: i for i, vram in enumerate(order)}
    exact = {case.vram: case.name for case in cases if case.status == "exact"}
    boundary = solver.boundary_operations(boundary_file)
    recipes = solver.recipe_confidence(cases)
    try:
        from ..match import toolchain_regions as tcmod
        reconstruction = tcmod.reconstruct(data, delta, rows, cases=cases)
    except Exception:                                        # noqa: BLE001 - dossier context, never the run's failure
        reconstruction = {}
    records, by_cause = [], {}
    for case in sorted(cases, key=lambda c: c.vram):
        if case.status not in solver.UNRESOLVED:
            continue
        decision = solver.decide(case, mode, observations, unknown=stretches, ceiling=ceiling, model=model)
        index = position.get(case.vram, -1)
        adjacent = {order[i] for i in (index - 1, index + 1) if 0 <= i < len(order)} if index >= 0 else set()
        related = sorted({(exact[v], "calls or is called by") for v in graph.get(case.vram, set()) if v in exact}
                         | {(exact[v], "adjacent in the catalogue") for v in adjacent if v in exact})
        records.append(solver.dossier(case, decision, observations,
                                      related=[{"name": n, "relation": r} for n, r in related],
                                      boundary=boundary.get(case.vram, []), stop=stop.get("reason") or "",
                                      image_recipes=recipes,
                                      region=tcmod.region_of(reconstruction, case.vram) if reconstruction else None))
        group = by_cause.setdefault(decision.cause, {"functions": 0, "bytes": 0, "next": {}})
        group["functions"] += 1
        group["bytes"] += case.size
        key = decision.technique or "stop"
        group["next"][key] = group["next"].get(key, 0) + 1
    solver.write_json(out / "solver" / f"hard_queue_{image}.json", records)
    ledger_path = out / "solver" / f"attempts_{image}.jsonl"
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = ledger_path.with_suffix(".tmp")
    with temporary.open("w") as handle:
        for entry in solver.attempts(cases, observations):
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
    temporary.replace(ledger_path)
    sieve_table = solver.sieve(cases, recovered=len(recovered))
    warning = None
    if mode.require_reasons and found["unexplained"]:
        warning = (f"effort {mode.name} requires a recorded reason for every function not attempted: "
                   f"{found['unexplained']} have none (see coverage_{image}.json)")
    return {"mode": mode.name, "stop": stop.get("reason"), "after_round": stop.get("after_round"),
            "coverage_warning": warning,
            "coverage": {k: found[k] for k in ("functions", "attempted", "not_attempted", "unexplained", "reasons")},
            "remaining_by_cause": dict(sorted(by_cause.items(), key=lambda kv: -kv[1]["bytes"])),
            "sieve": sieve_table,
            "files": {"rounds": str(out / "rounds.jsonl"), "coverage": str(out / "solver" / f"coverage_{image}.json"),
                      "hard_queue": str(out / "solver" / f"hard_queue_{image}.json"),
                      "attempts": str(ledger_path)}}


def finished_cases(state: Path, image: str) -> set[int]:
    """Link-space addresses of the cases of ``image`` whose ladder finished (a case is stored only
    when its ladder ends), less calibration samples still marked provisional."""
    if not Path(state).is_dir():
        return set()
    store = resolvemod.CaseStore(state, readonly=True)
    try:
        return {case.vram for case in store.all() if case.image == image
                and not any(stage.get("stage") == "provisional" for stage in case.stages)}
    finally:
        store.close()


def discovery_summary(found: dict) -> dict:
    """Per image: the audit's verdict before and after repair, and what the repair added."""
    images = {}
    for name, img in found["images"].items():
        repair = img.get("repair") or {}
        images[name] = {"verdict": img.get("verdict"), "coverage": img.get("coverage"),
                        "functions": img.get("functions"), "reasons": img.get("reasons"),
                        "missing_call_targets": (img.get("direct_calls") or {}).get("missing"),
                        "unmapped_call_targets": (img.get("direct_calls") or {}).get("unmapped"),
                        "framed_functions_outside": (img.get("prologues_outside") or {}).get("walk_as_functions"),
                        "repaired_functions": repair.get("added", 0), "repaired_bytes": repair.get("bytes", 0),
                        "verdict_after": repair.get("verdict_after", img.get("verdict")),
                        "coverage_after": repair.get("coverage_after", img.get("coverage")),
                        "functions_after": repair.get("functions_after", img.get("functions")),
                        # what remains after repair (round 11: the summary used to carry only the
                        # pre-repair reasons, which overstated what was still missing)
                        "reasons_after": repair.get("reasons_after", img.get("reasons"))}
    verdict = found.get("verdict")
    return {"verdict_before": found.get("verdict_before", verdict), "verdict": verdict,
            "rom_reasons": found.get("rom_reasons"),
            "placed": [{k: p[k] for k in ("name", "rom", "rom_end", "vram", "landed", "functions")}
                       for p in found.get("placed") or []],
            "warning": (None if verdict != "incomplete" else
                        "the function catalogue is incomplete even after repair: every count and percentage in "
                        "this report is over the catalogue, not over the title's code"),
            "images": images}


def _rows_of(manifest: str, delta: int):
    from ..match import byteledger as ownmod
    try:
        return ownmod.read_manifest(manifest, delta, "c")
    except Exception:
        return []


def _headline(item: dict) -> dict:
    resolve = item.get("resolve") or {}
    donors = item.get("donors") or {}
    queue = item.get("queue") or {}
    return {"functions": item.get("functions"),
            "donor_verified": sum(len(r.get("functions", [])) for r in donors.get("verified", [])),
            "donor_assumed": sum(len(r.get("function_vrams", [])) for r in donors.get("assumed", [])),
            "resolved": resolve.get("statuses"), "exact_bytes": resolve.get("exact_bytes"),
            "queued": queue.get("strict_exact"), "queued_strict_exact": queue.get("strict_exact"),
            "awaiting_symbols": queue.get("assumed"), "refine": resolve.get("refine"),
            "calibrate": item.get("calibrate"), "declare": item.get("declare"),
            "errors": [k for k, v in item.items() if isinstance(v, dict) and "error" in v]}


def _markdown(report: dict) -> str:
    lines = [f"# decompile-run report", "", f"Project: `{report['project']}`  ", f"Wall time: {report.get('seconds')} s", ""]
    found = report.get("discovery") or {}
    if found.get("verdict"):
        lines.append(f"Discovery: catalogue {found['verdict']}"
                     + (f" (before repair: {found['verdict_before']})" if found.get("verdict_before") != found["verdict"] else ""))
        for name, img in (found.get("images") or {}).items():
            lines.append(f"- {name}: {img['verdict_after']}, coverage {img['coverage_after']}"
                         + (f", +{img['repaired_functions']} functions from call/pointer/prologue evidence"
                            if img.get("repaired_functions") else ""))
            if img.get("verdict_after") != "complete":
                lines += [f"  - {reason}" for reason in (img.get("reasons_after") or [])[:4]]
        if found.get("warning"):
            lines.append(f"- WARNING: {found['warning']}")
        lines.append("")
    for name, item in report["images"].items():
        head = _headline(item)
        lines += [f"## {name}", "", f"- catalogued functions: {head['functions']}",
                  f"- recovered from donors (verified): {head['donor_verified']}",
                  f"- identical to a donor unit, awaiting symbols: {head.get('donor_assumed') or 0} "
                  "(`donors/awaiting_symbols.txt`)",
                  f"- resolution outcomes this run: {head['resolved']}",
                  f"- exact bytes from resolution: {head['exact_bytes']}",
                  f"- queued for integration (strictly exact): {head['queued_strict_exact']}",
                  f"- byte-identical, awaiting symbol declarations: {head.get('awaiting_symbols') or 0} "
                  "(`queue/assumed.tsv`; review `queue/symbols.assumed.txt`, add it to the symbol file, rerun)"]
        if head.get("calibrate"):
            info = head["calibrate"]
            picked = (info.get("chosen") or {}).get("label")
            lines.append(f"- recipe calibration: {info.get('identical')} of {info.get('sample')} sample functions "
                         f"byte-identical; " + (f"sweep recipe `{picked}`" if picked
                                               else f"configured recipe kept ({info.get('reason')})"))
        if head.get("refine"):
            info = head["refine"]
            lines.append(f"- refiner: asked about {info.get('attempted')} cases in {info.get('calls')} calls; "
                         f"{info.get('improved')} improved, {info.get('exact')} became exact, "
                         f"{info.get('assumed')} byte-identical awaiting symbols, {info.get('errors')} call errors")
        if item.get("exact_provenance"):
            lines.append(f"- exact functions by what their source went through (n64dk.match.transform_classes): "
                         f"{item['exact_provenance']}")
        if (item.get("toolchain_regions") or {}).get("functions_by_verdict"):
            lines.append(f"- toolchain regions: {item['toolchain_regions']['functions_by_verdict']} "
                         f"(`{item['toolchain_regions'].get('file')}`)")
        if item.get("boundaries"):
            lines.append(f"- boundary operations proposed: {item['boundaries'].get('operations')}")
        if item.get("ledger") and "totals" in item["ledger"]:
            lines.append(f"- ledger violations: {item['ledger'].get('violations')}")
        solved = item.get("solver") or {}
        if solved.get("mode"):
            lines.append(f"- effort `{solved['mode']}`: stopped after round {solved.get('after_round')} "
                         f"({solved.get('stop')}); rounds in `rounds.jsonl`, dossiers in "
                         f"`solver/hard_queue_{name}.json`")
            cover = solved.get("coverage") or {}
            if solved.get("coverage_warning"):
                lines.append(f"- WARNING: {solved['coverage_warning']}")
            lines.append(f"- coverage: {cover.get('attempted')} of {cover.get('functions')} catalogued functions "
                         f"attempted, {cover.get('not_attempted')} not attempted (each with a recorded reason), "
                         f"{cover.get('unexplained')} unexplained")
            if solved.get("sieve"):
                lines += ["", "| sieve stage | settled | builds |", "|---|---:|---:|"]
                lines += [f"| {name} | {row['settled']} | {row['builds']} |"
                          for name, row in solved["sieve"]["stages"].items() if row["settled"] or row["builds"]]
                lines.append(f"| unresolved | {solved['sieve']['unresolved']} | |")
            if solved.get("remaining_by_cause"):
                lines += ["", "| primary cause | functions | bytes | next action |", "|---|---:|---:|---|"]
                lines += [f"| {cause} | {g['functions']} | {g['bytes']} | "
                          + ", ".join(f"{k} {v}" for k, v in sorted(g["next"].items(), key=lambda kv: -kv[1]))
                          + " |" for cause, g in solved["remaining_by_cause"].items()]
        if item.get("hard_queue"):
            lines += ["", "| remaining cause | functions | bytes |", "|---|---:|---:|"]
            lines += [f"| {g['cause']} | {g['functions']} | {g['bytes']} |" for g in item["hard_queue"]]
        if head["errors"]:
            lines.append(f"- stages with errors: {head['errors']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _args(p):
    p.add_argument("--project", help="project directory (required unless --resume)")
    p.add_argument("--image", action="append", default=[], help="logical image name (repeatable)")
    p.add_argument("--all-images", action="store_true")
    p.add_argument("--out", help="output directory for state, queue, reports (not a source tree; required unless "
                                 "--resume)")
    p.add_argument("--effort", choices=sorted(solver.MODES), default=None,
                   help="effort mode (default normal: exactly the single pass decompile-run always made); deep and "
                        "exhaustive add later rounds until a fixed point; see docs/solver.md")
    p.add_argument("--rounds", type=int, help="most rounds (default: the effort mode's)")
    p.add_argument("--schedule", choices=("observe", "order"),
                   help="observe: record the ranking's predictions only; order: let it order later rounds' work "
                        "(default: the effort mode's; never changes what is credited)")
    p.add_argument("--budget-time", help="stop starting work after this long: seconds, or 30m, 2h")
    p.add_argument("--budget-builds", type=int, help="stop starting work after this many builds (all images)")
    p.add_argument("--budget-model-calls", type=int, help="stop asking the refiner after this many calls")
    p.add_argument("--resume", metavar="RUN_DIR",
                   help="continue a run from its case store and rounds.jsonl (finished rounds are not redone)")
    p.add_argument("--declare-assumed", action="store_true",
                   help="declare self-describing data addresses (D_<address>) that byte-identical cases lean on "
                        "and verify those cases again (default: [run] declare_assumed)")
    p.add_argument("--allow-project-output", action="store_true",
                   help="allow --out in the project outside .n64dk (unsafe for generated state)")
    p.add_argument("--donors", help="donors TOML for transplant (see docs/donors.example.toml)")
    p.add_argument("--donor-index", help="donor index file (default: <out>/donor_index.json)")
    p.add_argument("--library", help="directory of finished runs: every other title registered there is used "
                                     "as a donor, and this run registers its own strictly exact functions when it ends")
    p.add_argument("--donor", action="append", default=[], help="use only these donors")
    p.add_argument("--exclude-donor", action="append", default=[],
                   help="leave these donors out (always exclude the target project itself)")
    p.add_argument("--toolchain-dir")
    p.add_argument("--pipeline", default="kmc+builtin", help="default pipeline when [run] does not set one")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--jobs", type=int, default=0,
                   help="parallel builds in total (default: adaptive, capped at 4; set "
                        "N64DK_ALLOW_OVERSUBSCRIBE=1 for an explicit unsafe override)")
    p.add_argument("--calibrate", type=int,
                   help="functions sampled to measure the title's recipe before the sweep "
                        "(default: [run] calibrate, else none)")
    p.add_argument("--refine-command",
                   help="external author for unresolved cases: reads a prompt on stdin, prints C "
                        "(default: [run.refine] command; none configured means the stage is skipped)")
    p.add_argument("--refine-rounds", type=int)
    p.add_argument("--refine-max-cases", type=int)
    p.add_argument("--refine-max-score", type=int)
    p.add_argument("--refine-jobs", type=int, help="refiner calls at once (default 1)")
    p.add_argument("--refine-known-source", action="append", default=[], metavar="DIR",
                   help="folder of known source (an imported tree's split/): prompts holding its lines are not "
                        "sent, and answers reproducing it are flagged as recollection; repeatable")
    p.add_argument("--workers", type=int, default=0,
                   help="worker processes for the resolve stage (default 0: automatic, from hardware "
                        "threads and free memory)")
    p.add_argument("--worker-memory-mb", type=int, default=0,
                   help="memory estimate used by automatic worker selection (0: adaptive)")
    p.add_argument("--memory-reserve-mb", type=int, default=0,
                   help="memory excluded from automatic workers (0: adaptive)")
    p.add_argument("--budget", type=int, default=None, help="maximum builds per function (default: the effort "
                                                                 "mode's; normal 200)")
    p.add_argument("--search-ceiling", type=int, default=None,
                   help="skip the variant search when the best draft scores above this "
                        "(default: [run] search_ceiling, else the resolver's measured default; 0: always search)")
    p.add_argument("--limit", type=int, default=0, help="at most this many functions per image (smallest first)")
    p.add_argument("--order", default=None,
                   help="attempt order within a pass: size (default), reverse, shuffle:SEED; for determinism checks")
    p.add_argument("--regional-calibration", action="store_true", default=None,
                   help="calibrate each toolchain region (n64dk.match.toolchain_regions) on its own functions and "
                        "start every function from its region's recipe (experimental; off by default until measured)")
    p.add_argument("--region-recipes", action="store_true", default=None,
                   help="enable the experimental region-recipe retry (measured 3/126; off by default)")
    p.add_argument("--unit-recipes", action="store_true", default=None,
                   help="enable the experimental nearest-unit recipe retry (measured 0/165; off by default)")
    p.add_argument("--skip-unknown-search", action="store_true",
                   help="experimental: skip variant search in unknown-toolchain regions; advisory only by default")
    p.add_argument("--recipe-gate", dest="recipe_gate", action="store_true", default=None,
                   help="run the wide recipe retry only for functions with unoptimised-code evidence (in the "
                        "function or its neighbourhood) or another compiler family (default; [run] recipe_gate). "
                        "Measured offline: 0 exact lost on 3 held-out blind titles, 67K builds saved")
    p.add_argument("--no-recipe-gate", dest="recipe_gate", action="store_false",
                   help="run the wide recipe retry on every far function (round-10 behaviour)")
    p.add_argument("--search-economics", action="store_true", default=None,
                   help="stop the variant search in a stratum (recipe x first-draft distance) whose searches have "
                        "returned nothing after a fixed spend, probing it now and then (n64dk.match.economics)")
    p.add_argument("--only-names", action="append",
                   help="attempt only these functions: comma-separated names or @FILE (one per line); repeatable")
    p.add_argument("--max-size", type=lambda s: int(s, 0), default=None,
                   help="attempt only functions up to this size (default: the effort mode's; 0: no limit)")
    p.add_argument("--min-confidence", type=float, default=0.8)
    p.add_argument("--strict-only", action="store_true", help="queue only strictly exact cases")
    p.add_argument("--skip-stage", action="append", default=[],
                   choices=["discovery", "boundaries", "donors", "resolve", "ledger"])
    p.add_argument("--discovery", choices=("repair", "audit", "off"), default=None,
                   help="discovery gate before every stage (default repair): audit each catalogue against call, "
                        "pointer and prologue evidence; repair adds evidence-backed functions to an incomplete "
                        "catalogue in the run directory (never the project); audit only reports")
    p.add_argument("--redo", action="store_true", help="recompute checkpointed stages")


def _all_args(p):
    _args(p)
    _guard_arguments(p)


def _guard_arguments(p):
    p.add_argument("--wait-for-lock", action="store_true",
                   help="wait for another heavy n64dk job to finish instead of refusing to start")
    p.add_argument("--force-resources", action="store_true",
                   help="start even when memory, memory pressure or disk space are below the thresholds")


decompile_run.arguments = _all_args
