"""``decompile-run``: one command that drives every image of a project through the pipeline.

For each image named in the project's ``[images.<name>]`` configuration::

    boundaries  ->  donors  ->  resolve  ->  strict queue  ->  ledger

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
import tempfile
import time
import tomllib
from pathlib import Path

from ..cli import command
from ..match import images as imagemod
from ..match import resolve as resolvemod


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


def _identity(**values) -> str:
    return hashlib.sha256(json.dumps(values, sort_keys=True, default=str).encode()).hexdigest()


@command("decompile-run", "Drive every configured image through boundaries, donors, resolution, strict queue and ledger")
def decompile_run(args):
    project = Path(args.project).resolve()
    out = Path(args.out).resolve()
    if (out == project or project in out.parents) and not (project / ".n64dk" == out or
            project / ".n64dk" in out.parents) and not getattr(args, "allow_project_output", False):
        raise SystemExit("refusing to write generated run state inside the project source tree; "
                         "use <project>/.n64dk/... or --allow-project-output")
    out.mkdir(parents=True, exist_ok=True)
    registry = imagemod.load_registry(project)
    if not registry:
        raise SystemExit("no [images.<name>] tables in the project's n64dk.toml: declare each image (path, "
                         "vram_delta for linear images, catalogue, manifests)")
    names = sorted(registry) if args.all_images or not args.image else args.image
    events = out / "events.jsonl"
    jobs = args.jobs or os.cpu_count() or 8
    started = time.time()

    def emit(kind: str, **fields) -> None:
        with events.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"time": round(time.time(), 3), "event": kind, **fields}) + "\n")

    report = {"project": str(project), "images": {}}
    for name in names:
        spec = imagemod.resolve(project, name)
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
                image_report["boundaries"], _cached = _stage(folder, "boundaries", boundaries, args.redo,
                                                               stage_identity)
            except Exception as error:                       # a stage failure is reported, not fatal
                image_report["boundaries"] = {"error": str(error)[-300:]}
            emit("stage", image=spec.name, stage="boundaries", result=image_report["boundaries"])

        # --- 2. donors
        recovered: set[int] = set()
        if args.donors and "donors" not in args.skip_stage:
            def donors():
                from ..match import transplant
                from ..match.engine import Target
                index, _stats = transplant.build_index(
                    transplant.load_donors(args.donors, args.donor or None, args.exclude_donor or None),
                    args.donor_index or out / "donor_index.json")
                target = Target(data, delta, (0, len(data)))
                skip = [(v, v + s) for v, s in ((r.vram, r.size) for m in manifests
                                                for r in _rows_of(m, delta))]
                from ..match.toolchain import load_config
                toolchain = args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN") or \
                    load_config(project, None, None).toolchain_root
                result = transplant.run(None, target, rows, index, skip=skip, out_dir=folder / "donors",
                                        jobs=min(jobs, 4), toolchain_root=Path(toolchain) if toolchain else None)
                keep = {k: v for k, v in result.items()
                        if not k.startswith("_") and (not isinstance(v, (list, dict)) or k in ("verdicts", "timing_s"))}
                by_name = {n: v for n, v, _s in rows}
                keep["verified"] = [{"functions": r.get("functions", []), "vram": r.get("target_vram"),
                                     "size": r.get("size"), "donor": r.get("donor"), "unit": r.get("donor_unit"),
                                     "function_vrams": [by_name[n] for n in r.get("functions", []) if n in by_name]}
                                    for r in result.get("rows", [])
                                    if r.get("verdict") == transplant.EXACT_VERDICT]
                return keep
            try:
                image_report["donors"], _cached = _stage(folder, "donors", donors, args.redo,
                                                          _identity(base=stage_identity, donors=args.donors,
                                                                    selected=args.donor,
                                                                    excluded=args.exclude_donor))
                for row in image_report["donors"].get("verified", []):
                    recovered.update(int(v) for v in row.get("function_vrams", []))
            except Exception as error:
                image_report["donors"] = {"error": str(error)[-300:]}
            emit("stage", image=spec.name, stage="donors",
                 verified=len(image_report["donors"].get("verified", [])) if isinstance(image_report["donors"], dict) else 0)

        # --- 3. resolve
        if "resolve" not in args.skip_stage:
            from .resolve import resolve_hard
            options = argparse.Namespace(
                project=str(project), config=None, toolchain_dir=args.toolchain_dir, normalizer=None, include=[],
                rom=str(spec.path), vram_delta=spec.vram_delta if spec.delta_source == "declared" else None,
                jobs=jobs, workers=args.workers,
                worker_memory_mb=args.worker_memory_mb, memory_reserve_mb=args.memory_reserve_mb,
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
                state=str(out / "state"), events=str(events), no_draft=False, no_recipes=False,
                draft_portfolio=True, draft_options=settings.get("draft_options", ""), force=False,
                skip_vrams=recovered, addr=None, size=None)
            try:
                image_report["resolve"] = resolve_hard(options)
            except Exception as error:
                image_report["resolve"] = {"error": str(error)[-300:]}

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
                image_report["ledger"], _cached = _stage(folder, "ledger", ledger, args.redo, stage_identity)
            except Exception as error:
                image_report["ledger"] = {"error": str(error)[-300:]}
        report["images"][spec.name] = image_report
        emit("image-done", image=spec.name)
    report["seconds"] = round(time.time() - started, 1)
    report["failed_stages"] = {name: _headline(item)["errors"] for name, item in report["images"].items()
                               if _headline(item)["errors"]}
    report["status"] = "incomplete" if report["failed_stages"] else "complete"
    (out / "report.json").write_text(json.dumps(report, indent=1, default=str))
    (out / "report.md").write_text(_markdown(report))
    return {"status": report["status"], "failed_stages": report["failed_stages"],
            "report": str(out / "report.md"), "events": str(events),
            "images": {name: _headline(item) for name, item in report["images"].items()},
            "seconds": report["seconds"]}


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
            "resolved": resolve.get("statuses"), "exact_bytes": resolve.get("exact_bytes"),
            "queued": queue.get("strict_exact"), "queued_strict_exact": queue.get("strict_exact"),
            "awaiting_symbols": queue.get("assumed"),
            "errors": [k for k, v in item.items() if isinstance(v, dict) and "error" in v]}


def _markdown(report: dict) -> str:
    lines = [f"# decompile-run report", "", f"Project: `{report['project']}`  ", f"Wall time: {report.get('seconds')} s", ""]
    for name, item in report["images"].items():
        head = _headline(item)
        lines += [f"## {name}", "", f"- catalogued functions: {head['functions']}",
                  f"- recovered from donors (verified): {head['donor_verified']}",
                  f"- resolution outcomes this run: {head['resolved']}",
                  f"- exact bytes from resolution: {head['exact_bytes']}",
                  f"- queued for integration (strictly exact): {head['queued_strict_exact']}",
                  f"- byte-identical, awaiting symbol declarations: {head.get('awaiting_symbols') or 0} "
                  "(`queue/assumed.tsv`; review `queue/symbols.assumed.txt`, add it to the symbol file, rerun)"]
        if item.get("boundaries"):
            lines.append(f"- boundary operations proposed: {item['boundaries'].get('operations')}")
        if item.get("ledger") and "totals" in item["ledger"]:
            lines.append(f"- ledger violations: {item['ledger'].get('violations')}")
        if item.get("hard_queue"):
            lines += ["", "| remaining cause | functions | bytes |", "|---|---:|---:|"]
            lines += [f"| {g['cause']} | {g['functions']} | {g['bytes']} |" for g in item["hard_queue"]]
        if head["errors"]:
            lines.append(f"- stages with errors: {head['errors']}")
        lines.append("")
    return "\n".join(lines) + "\n"


def _args(p):
    p.add_argument("--project", required=True)
    p.add_argument("--image", action="append", default=[], help="logical image name (repeatable)")
    p.add_argument("--all-images", action="store_true")
    p.add_argument("--out", required=True, help="output directory for state, queue, reports (not a source tree)")
    p.add_argument("--allow-project-output", action="store_true",
                   help="allow --out in the project outside .n64dk (unsafe for generated state)")
    p.add_argument("--donors", help="donors TOML for transplant (see docs/donors.example.toml)")
    p.add_argument("--donor-index", help="donor index file (default: <out>/donor_index.json)")
    p.add_argument("--donor", action="append", default=[], help="use only these donors")
    p.add_argument("--exclude-donor", action="append", default=[],
                   help="leave these donors out (always exclude the target project itself)")
    p.add_argument("--toolchain-dir")
    p.add_argument("--pipeline", default="kmc+builtin", help="default pipeline when [run] does not set one")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--jobs", type=int, default=0,
                   help="parallel builds in total (default: the number of hardware threads)")
    p.add_argument("--workers", type=int, default=0,
                   help="worker processes for the resolve stage (default 0: automatic, from hardware "
                        "threads and free memory)")
    p.add_argument("--worker-memory-mb", type=int, default=0,
                   help="memory estimate used by automatic worker selection (0: adaptive)")
    p.add_argument("--memory-reserve-mb", type=int, default=0,
                   help="memory excluded from automatic workers (0: adaptive)")
    p.add_argument("--budget", type=int, default=200, help="maximum builds per function")
    p.add_argument("--search-ceiling", type=int, default=None,
                   help="skip the variant search when the best draft scores above this "
                        "(default: [run] search_ceiling, else the resolver's measured default; 0: always search)")
    p.add_argument("--limit", type=int, default=0, help="at most this many functions per image (smallest first)")
    p.add_argument("--max-size", type=lambda s: int(s, 0), default=0)
    p.add_argument("--min-confidence", type=float, default=0.8)
    p.add_argument("--strict-only", action="store_true", help="queue only strictly exact cases")
    p.add_argument("--skip-stage", action="append", default=[],
                   choices=["boundaries", "donors", "resolve", "ledger"])
    p.add_argument("--redo", action="store_true", help="recompute checkpointed stages")


decompile_run.arguments = _args
