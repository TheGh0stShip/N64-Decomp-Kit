"""Matching commands: one-shot relocated compare / configuration sweep, manifest batches and
the permuter driver."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
from pathlib import Path

from ..cli import command
from ..match import manifest as manmod
from ..match import symbols as symmod
from ..match.engine import Target, batch, default_pipelines, manifest_row, match_source, sweep
from ..match.pipeline import PIPELINES, BuildSpec, split_flags, scratch_dir
from ..match.session import MatchSession, SessionStore
from ..match.registry import SessionRegistry, resolve_store, standard_store
from ..match.layout import Layout, from_inventory, preflight, resolve_image_map
from ..match.toolchain import Config, PROFILES, load_config
from ..match import inventory as inventorymod
from ..rom import Rom


def _exact_project_evidence(cfg, args, outcome, source, spec, target):
    if not outcome.exact or outcome.vram is None:
        return {}
    try:
        inventory = inventorymod.build(cfg.project)
        rows = [row for row in inventory["functions"] if int(row["vram"], 0) == outcome.vram
                and int(row["size"]) == outcome.size]
    except Exception:
        rows = []
    selected = None
    for row in rows:
        try:
            check = preflight(args.rom, from_inventory(row), row.get("catalogue_status", ""))
        except Exception:
            continue
        if int(check["selected_image_offset"], 0) == outcome.vram - target.delta:
            selected = (row, check); break
    if selected is None and len(rows) == 1:
        row = rows[0]; selected = (row, None)
    if selected is None:
        return {"exact_evidence": {"target_text": outcome.result.text.match if outcome.result else True,
                                   "source_sha256": hashlib.sha256(Path(source).read_bytes()).hexdigest(),
                                   "generated_text_sha256": outcome.as_dict().get("sha256_text")}}
    row, check = selected; layout = from_inventory(row)
    target_digest = outcome.as_dict().get("sha256_text")
    relative = str(Path(source).resolve().relative_to(cfg.project)) if Path(source).resolve().is_relative_to(cfg.project) else str(source)
    project_row = "\t".join((f"0x{layout.rom:X}", f"0x{outcome.size:X}", relative,
                             spec.manifest_flags(), target_digest or ""))
    profile_key = {"ido5.3": "ido53", "ido7.1": "ido71", "sn": "sn"}.get(spec.pipeline, "kmc")
    compiler_root = cfg.toolchain(profile_key); compiler_hasher = hashlib.sha256()
    if compiler_root:
        for relative_name in PROFILES[profile_key].required:
            compiler_hasher.update(relative_name.encode()); compiler_hasher.update(hashlib.sha256((compiler_root / relative_name).read_bytes()).digest())
    compiler_digest = compiler_hasher.hexdigest() if compiler_root else None
    return {"image_mapping": {"raw_rom": f"0x{layout.rom:X}",
                              "composite_rom": check.get("selected_image_offset") if check else None,
                              "vram": f"0x{outcome.vram:08X}", "image": row["image"]},
            "project_manifest_row": project_row,
            "exact_evidence": {"target_text_sha256": target_digest,
                               "complete_owned_sections": all(section.match for section in outcome.result.sections) if outcome.result else True,
                               "expected_manifest_hash": target_digest,
                               "compiler_binary_digest": compiler_digest,
                               "source_sha256": hashlib.sha256(Path(source).read_bytes()).hexdigest(),
                               "relocations_checked": bool(outcome.result and outcome.result.sections),
                               "mapping_preflight": check}}


def _replay_record(cfg, args, outcome, source: Path, spec: BuildSpec, target: Target) -> dict:
    profile_key = {"ido5.3": "ido53", "ido7.1": "ido71", "sn": "sn"}.get(spec.pipeline, "kmc")
    root = cfg.toolchain(profile_key); binaries = {}
    if root:
        for name in PROFILES[profile_key].required:
            path = root / name
            if path.is_file(): binaries[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    allowed_environment = {key: os.environ[key] for key in ("LANG", "LC_ALL", "TZ", "TMPDIR", "WIBO")
                           if key in os.environ}
    return {"version": "n64dk-replay-v1", "source": str(source),
            "source_digest": hashlib.sha256(source.read_bytes()).hexdigest(),
            "toolchain_binaries": binaries, "pipeline": spec.pipeline, "flags": list(spec.flags),
            "include_paths": [str(path) for path in cfg.include],
            "symbol_files": [str(path) for path in (args.symbols or cfg.symbols)],
            "image": str(Path(args.rom).resolve()), "image_digest": hashlib.sha256(target.rom).hexdigest(),
            "address": outcome.vram, "size": outcome.size, "vram_delta": target.delta,
            "target_digest": hashlib.sha256(target.rom[outcome.vram - target.delta:
                outcome.vram - target.delta + outcome.size]).hexdigest(),
            "environment": allowed_environment}


def _common(p, rom_required: bool):
    p.add_argument("--rom", required=rom_required, help="retail ROM image"
                   + ("" if rom_required else " (default: n64dk.toml [match] rom or baserom*.z64 in the project)"))
    p.add_argument("--project", help="project directory: working directory for builds, "
                   "default include/, .toolchain/ and symbol files (default: current directory)")
    p.add_argument("--config", help="n64dk.toml (default: <project>/n64dk.toml)")
    p.add_argument("--toolchain-dir", help="directory holding kmc-gcc-2.7.2/, ido5.3/, ... ")
    p.add_argument("--symbols", action="append", default=[],
                   help="symbol file: splat symbol_addrs.txt or catalogue TOML (repeatable)")
    p.add_argument("-I", "--include", action="append", default=[], help="include directory (repeatable)")
    p.add_argument("--normalizer", help="assembly normalizer hook, e.g. 'python3 tools/norm.py {input} {output}'")
    p.add_argument("--vram-delta", type=lambda s: int(s, 0), help="VRAM - ROM offset of the code segment")
    p.add_argument("--jobs", type=int, default=None, help="parallel builds (default: CPU count)")


def _setup(args):
    cfg = load_config(args.project, args.config, args.toolchain_dir)
    if args.normalizer:
        cfg.normalizer = args.normalizer
    if args.include:
        cfg.include = list(dict.fromkeys([Path(cfg.project, i).resolve() for i in args.include] + cfg.include))
    rom_path = args.rom or cfg.find_rom()
    if rom_path is None:
        raise SystemExit("no ROM: pass --rom or set [match] rom in n64dk.toml")
    image = Rom.load(rom_path)
    if image.checksum_ok() is False:
        raise SystemExit(f"{rom_path}: header checksum mismatch; not a clean base image")
    selected_delta = args.vram_delta if args.vram_delta is not None else cfg.vram_delta
    if getattr(args, "addr", None) is not None and getattr(args, "size", None) is not None:
        try:
            inventory = inventorymod.build(cfg.project)
            rows = [row for row in inventory["functions"] if int(row["vram"], 0) == args.addr
                    and int(row["size"]) == args.size]
            image_number = re.search(r"overlay[_-]?(\d+)", Path(rom_path).name, re.I)
            if image_number:
                rows = [row for row in rows if row["image"].replace("_", "") == "overlay" + image_number.group(1)]
            if len(rows) == 1:
                resolved = resolve_image_map(rom_path, from_inventory(rows[0]))
                canonical_delta = args.addr - resolved["selected"]["offset"]
                if args.vram_delta is not None and args.vram_delta != canonical_delta:
                    raise ValueError(f"explicit vram_delta 0x{args.vram_delta:X} conflicts with canonical "
                                     f"image mapping 0x{canonical_delta:X}")
                selected_delta = canonical_delta
                args._resolved_mapping = resolved
                args._resolved_inventory_row = rows[0]
        except ValueError:
            raise
        except Exception:
            pass
    target = Target.from_rom(image, selected_delta)
    sym_files = [Path(s) for s in args.symbols] or cfg.symbols or symmod.discover(cfg.project)
    syms = symmod.load(sym_files)
    return cfg, target, syms, sym_files


def _spec(args, cfg) -> BuildSpec:
    pipe = args.pipeline
    if pipe is None:
        avail = default_pipelines(cfg)
        pipe = avail[0] if avail else "kmc+builtin"
    flags = shlex.split(args.flags) if args.flags is not None else None
    if flags is None:
        key = {"ido5.3": "ido53", "ido7.1": "ido71", "sn": "sn"}.get(pipe, "kmc")
        flags = list(PROFILES[key].default_flags)
    return split_flags(flags, pipe)


def _match_args(p):
    p.add_argument("source", help="C (or assembly) source file")
    _common(p, rom_required=True)
    p.add_argument("--addr", type=lambda s: int(s, 16),
                   help="VRAM of the unit's .text (hex; default: search the ROM for the compiled code)")
    p.add_argument("--size", type=lambda s: int(s, 16), help="text size in bytes (hex; default: compiled size)")
    p.add_argument("--pipeline", choices=PIPELINES, help="build pipeline (default: first available)")
    p.add_argument("--flags", help="compiler flags (default: the toolchain profile's standard flags)")
    p.add_argument("--sweep", action="store_true",
                   help="search pipelines x flags x rodata placement for the first exact configuration")
    p.add_argument("--pipelines", help="comma-separated pipelines for --sweep (default: all available)")
    p.add_argument("--all", action="store_true", help="with --sweep: do not stop at the first exact result")
    p.add_argument("--no-infer", action="store_true",
                   help="do not recover unresolved external symbols from the retail code")
    p.add_argument("--lines", type=int, default=24, help="diff lines shown in text output")


@command("match", "Build a source with an original toolchain and compare it relocated against the ROM")
def match(args):
    cfg, target, syms, _files = _setup(args)
    source = Path(args.source).resolve()
    if args.sweep:
        pipes = args.pipelines.split(",") if args.pipelines else None
        base = split_flags(shlex.split(args.flags), "kmc+builtin") if args.flags else None
        res = sweep(source, cfg, target, args.addr, args.size, syms, pipes, args.jobs,
                    stop_at_first=not args.all, base_spec=base)
        out = {"source": str(source), "vram": f"0x{(res.exact.vram if res.exact else args.addr or 0):08X}",
               "tried": len(res.tried),
               "pipelines": pipes or default_pipelines(cfg), "exact": res.exact is not None}
        if res.exact is not None:
            o = res.exact
            out.update({"pipeline": o.spec.pipeline, "flags": " ".join(o.spec.flags),
                        "bases": {k: f"0x{v:08X}" for k, v in o.result.bases.items()},
                        "manifest_row": manifest_row(o, cfg.project, source, target, syms)})
            if args.all:
                out["all_exact"] = [f"{x.spec.pipeline} {' '.join(x.spec.flags)}" for x in res.tried if x.exact]
        else:
            best = res.best()
            if best is not None:
                out.update({"best_pipeline": best.spec.pipeline, "best_flags": " ".join(best.spec.flags),
                            "best_diff": best.result.diff.summary() if best.result.diff else best.error})
        if args.format == "json":
            out["results"] = [{"pipeline": o.spec.pipeline, "flags": " ".join(o.spec.flags), "exact": o.exact,
                               "score": (o.result.diff.score if o.result and o.result.diff else
                                         (0 if o.exact else None)), "error": o.error} for o in res.tried]
        return out
    spec = _spec(args, cfg)
    with scratch_dir() as tmp:
        o = match_source(source, spec, cfg, target, args.addr, args.size, syms, Path(tmp),
                         infer_externals=not args.no_infer)
    payload = o.as_dict(); payload["replay"] = _replay_record(cfg, args, o, source, spec, target)
    if o.exact:
        payload["manifest_row"] = manifest_row(o, cfg.project, source, target, syms)
        payload.update(_exact_project_evidence(cfg, args, o, source, spec, target))
    # Direct observations enter the same durable history as sessions immediately.
    try:
        from ..match.results import ResultIndex
        address, size = o.vram, o.size
        target_offset = address - target.delta
        target_digest = (hashlib.sha256(target.rom[target_offset:target_offset + size]).hexdigest()
                         if 0 <= target_offset <= len(target.rom) - size else None)
        history = ResultIndex(cfg.project / ".n64dk" / "results.sqlite")
        try:
            history.record_direct(payload, {"rom_sha256": hashlib.sha256(target.rom).hexdigest(),
                "target_text_sha256": target_digest, "vram_delta": target.delta,
                "addr": address, "size": size}, source,
                source.stem if re.fullmatch(r"func_[0-9A-Fa-f]{8}", source.stem) else None,
                "valid_current_target" if target_digest else "unknown_provenance")
        finally: history.close()
    except Exception:
        pass  # matching remains available when the optional history store is unavailable
    if args.format == "json":
        return payload
    lines = [f"{'MATCH' if o.exact else 'DIFF'} {source.name} @ 0x{o.vram:08X} "
             f"[{spec.pipeline} {' '.join(spec.flags)}]"]
    if o.error:
        lines.append(f"error: {o.error}")
    if o.result:
        r = o.result
        lines.append(f".text 0x{r.text.size:X} bytes (compiled 0x{r.compiled_size:X})"
                     + (f", first difference at +0x{r.text.first_diff:X}" if r.text.first_diff is not None else ""))
        for s in r.sections:
            lines.append(f"{s.name} @ 0x{s.vram:08X} 0x{s.size:X} bytes: {'match' if s.match else 'DIFF'}")
        if r.inferred_symbols:
            lines.append("symbols recovered from the ROM: " +
                         ", ".join(f"{k}=0x{v:08X}" for k, v in sorted(r.inferred_symbols.items())))
        if r.error:
            lines.append(r.error)
        if r.diff:
            lines.append("diff: " + r.diff.summary())
            lines += r.diff.lines(args.lines)
        if o.exact:
            lines.append("manifest row: " + manifest_row(o, cfg.project, source, target, syms))
    return "\n".join(lines)


match.arguments = _match_args


def _session_context(args, cfg, target, sym_files, source: Path, spec: BuildSpec,
                     source_bytes: bytes) -> dict:
    rom_path = Path(args.rom).expanduser().resolve()
    toolchain_hasher = hashlib.sha256()
    for key, root in sorted(cfg.toolchains.items()):
        toolchain_hasher.update(key.encode())
        if root.is_dir():
            for item in sorted(path for path in root.iterdir() if path.is_file()):
                toolchain_hasher.update(item.name.encode()); toolchain_hasher.update(hashlib.sha256(item.read_bytes()).digest())
    if cfg.toolchain_root:
        toolchain_hasher.update(str(cfg.toolchain_root.resolve()).encode())
    profile_key = {"ido5.3": "ido53", "ido7.1": "ido71", "sn": "sn"}.get(spec.pipeline, "kmc")
    profile_root = cfg.toolchain(profile_key)
    if profile_root:
        for relative in PROFILES[profile_key].required:
            binary = profile_root / relative
            toolchain_hasher.update(relative.encode()); toolchain_hasher.update(hashlib.sha256(binary.read_bytes()).digest())
    context = {
        "source_name": source.name,
        "source_suffix": source.suffix or ".c",
        "rom": str(rom_path),
        "rom_sha256": hashlib.sha256(target.rom).hexdigest(),
        "project": str(cfg.project),
        "toolchain_root": str(cfg.toolchain_root) if cfg.toolchain_root else None,
        "toolchains": {key: str(value) for key, value in cfg.toolchains.items()},
        "include": [str(value) for value in cfg.include],
        "symbols": [str(Path(value).resolve()) for value in sym_files],
        "normalizer": cfg.normalizer,
        "vram_delta": target.delta,
        "addr": args.addr,
        "size": args.size,
        "infer_externals": not args.no_infer,
        "default_pipeline": spec.pipeline,
        "default_flags": list(spec.flags),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "compiler_recipe": {"pipeline": spec.pipeline, "flags": list(spec.flags)},
        "toolchain_digest": toolchain_hasher.hexdigest(),
    }
    if args.addr is not None and args.size is not None:
        layout = (from_inventory(args._resolved_inventory_row)
                  if getattr(args, "_resolved_inventory_row", None) else
                  Layout("standalone", 0, target.delta, len(target.rom), args.addr, args.size,
                         "standalone-explicit-range"))
        context["layout_preflight"] = preflight(rom_path, layout, strict_entry=args.strict_entry)
        rom_offset = args.addr - target.delta
        target_bytes = target.rom[rom_offset:rom_offset + args.size]
        context["target_text_sha256"] = hashlib.sha256(target_bytes).hexdigest()
        context["image_identity"] = rom_path.name
        context["catalogue_boundary_revision"] = None
    return context


def _session_runtime(context: dict):
    rom_path = Path(context["rom"])
    image = Rom.load(rom_path)
    if hashlib.sha256(image.data).hexdigest() != context["rom_sha256"]:
        raise RuntimeError("session ROM changed; start a new matching session")
    cfg = Config(
        project=Path(context["project"]),
        toolchain_root=(Path(context["toolchain_root"])
                        if context.get("toolchain_root") else None),
        toolchains={key: Path(value) for key, value in context.get("toolchains", {}).items()},
        include=[Path(value) for value in context.get("include", [])],
        symbols=[Path(value) for value in context.get("symbols", [])],
        normalizer=context.get("normalizer"),
        vram_delta=context["vram_delta"],
        rom=rom_path,
    )
    target = Target.from_rom(image, context["vram_delta"])
    syms = symmod.load([Path(value) for value in context.get("symbols", [])])
    return cfg, target, syms


def _session_evaluator(context: dict):
    cfg, target, syms = _session_runtime(context)

    def evaluate(source: bytes, pipeline: str, flags: tuple[str, ...], label: str):
        spec = split_flags(list(flags), pipeline)
        with tempfile.TemporaryDirectory(prefix="n64dk-session-") as name:
            root = Path(name)
            source_path = root / ("candidate" + context.get("source_suffix", ".c"))
            source_path.write_bytes(source)
            workdir = root / "build"
            workdir.mkdir()
            outcome = match_source(
                source_path, spec, cfg, target, context.get("addr"), context.get("size"),
                syms, workdir, infer_externals=context.get("infer_externals", True),
                name=label,
            )
            artifact_dir = context.get("artifact_dir")
            if artifact_dir:
                destination = Path(artifact_dir) / re.sub(r"[^A-Za-z0-9_.-]", "_", label)
                destination.mkdir(parents=True, exist_ok=True)
                for artifact in workdir.rglob("*"):
                    if artifact.is_file() and artifact.suffix not in {".o"}:
                        shutil.copy2(artifact, destination / artifact.name)
            return outcome
    return evaluate


def _session_start_args(p):
    p.add_argument("source", help="baseline C/assembly source file, or - for stdin")
    p.add_argument("--source-name", default="stdin.c",
                   help="logical filename when source is stdin (default: stdin.c)")
    _common(p, rom_required=True)
    p.add_argument("--addr", type=lambda value: int(value, 16),
                   help="VRAM of the unit's .text (hex)")
    p.add_argument("--size", type=lambda value: int(value, 16), help="text size in bytes (hex)")
    p.add_argument("--pipeline", choices=PIPELINES)
    p.add_argument("--flags")
    p.add_argument("--no-infer", action="store_true")
    p.add_argument("--state-root", help="session store (default: <project>/.n64dk/match-sessions)")
    p.add_argument("--details", action="store_true", help="include the full instruction diff")
    p.add_argument("--strict-entry", action="store_true",
                   help="reject likely internal fragments using entry and delay-slot evidence")
    _session_output_args(p)


def _session_output_args(p):
    group = p.add_mutually_exclusive_group()
    group.add_argument("--summary-only", action="store_true", help="omit candidate collections")
    group.add_argument("--best-only", action="store_true", help="return only the best candidate")
    group.add_argument("--best-details", action="store_true", help="return only the best candidate with its outcome")
    group.add_argument("--candidate", help="return one candidate ID with full details")
    group.add_argument("--exact-only", action="store_true", help="return exact candidates only")


def _project_session_output(value: dict, args, store: SessionStore | None = None) -> dict:
    if getattr(args, "best_only", False) or getattr(args, "best_details", False):
        return {"session_id": value["session_id"], "best": value.get("best") or value.get("baseline")}
    candidate_id = getattr(args, "candidate", None)
    if candidate_id:
        if store is None:
            raise ValueError("candidate selection is unavailable")
        candidate = store.get(value["session_id"], candidate_id)
        if candidate is None:
            raise ValueError(f"unknown candidate {candidate_id}")
        return {"session_id": value["session_id"], "candidate": candidate.summary(True)}
    if getattr(args, "summary_only", False):
        return {key: item for key, item in value.items()
                if key not in {"frontier", "results", "candidates", "context", "experiments"}}
    if getattr(args, "exact_only", False):
        result = dict(value)
        for key in ("frontier", "results", "candidates"):
            if key in result:
                result[key] = [row for row in result[key] if row.get("exact")]
        return result
    return value


@command("match-session-start", "Start a persistent standalone matching session")
def match_session_start(args):
    cfg, target, syms, sym_files = _setup(args)
    source = Path(args.source).resolve() if args.source != "-" else Path(args.source_name)
    source_bytes = source.read_bytes() if args.source != "-" else sys.stdin.buffer.read()
    spec = _spec(args, cfg)
    context = _session_context(args, cfg, target, sym_files, source, spec, source_bytes)
    store_root = Path(args.state_root).resolve() if args.state_root else standard_store(cfg.project)
    store = SessionStore(store_root)
    try:
        session = MatchSession(store, _session_evaluator(context))
        session_id, baseline = session.create(context, source_bytes,
                                              spec.pipeline, tuple(spec.flags))
        registry = SessionRegistry(cfg.project)
        try:
            registry.register(session_id, store_root, context, baseline.source_digest, "standalone")
        finally:
            registry.close()
        result = {
            "session_id": session_id,
            "state_root": str(store_root),
            "baseline": baseline.summary(args.details or args.best_details),
            "frontier": [baseline.summary(args.details or args.best_details)] if baseline.status == "evaluated" else [],
        }
        return _project_session_output(result, args, store)
    finally:
        store.close()


match_session_start.arguments = _session_start_args


def _read_proposal(value: str) -> dict:
    if value == "-":
        return json.load(sys.stdin)
    if value.lstrip().startswith("{"):
        return json.loads(value)
    return json.loads(Path(value).read_text())


def _session_try_args(p):
    p.add_argument("session_id")
    p.add_argument("--state-root")
    p.add_argument("--project", default=".")
    p.add_argument("--proposal", default="-",
                   help="JSON object, JSON file, or - for stdin (default)")
    p.add_argument("--jobs", type=int, default=4)
    p.add_argument("--details", action="store_true", help="include full outcome and diff entries")
    p.add_argument("--transaction-results", action="store_true")
    p.add_argument("--transaction-best", action="store_true")
    p.add_argument("--session-best", action="store_true")
    p.add_argument("--changed-only", action="store_true")
    p.add_argument("--object-classes", action="store_true")
    p.add_argument("--why-not-better", action="store_true")
    _session_output_args(p)


@command("match-session-try", "Apply in-memory edits and evaluate source/flag variants as one transaction")
def match_session_try(args):
    store = SessionStore(resolve_store(args.session_id, args.project, args.state_root))
    try:
        context = store.context(args.session_id)
        session = MatchSession(store, _session_evaluator(context))
        value = session.try_proposal(args.session_id, _read_proposal(args.proposal),
                                     args.jobs, args.details or args.best_details)
        selected = [name for name in ("transaction_results", "transaction_best", "session_best",
                    "object_classes", "why_not_better") if getattr(args, name, False)]
        if args.changed_only:
            value["transaction_results"] = [row for row in value["transaction_results"]
                                             if not row.get("cache_hit") and
                                             (row.get("delta", {}).get("score") or
                                              row.get("delta", {}).get("counts"))]
        if selected:
            value = {"session_id": args.session_id, **{key: value.get(key) for key in selected}}
        return _project_session_output(value, args, store)
    finally:
        store.close()


match_session_try.arguments = _session_try_args


def _session_status_args(p):
    p.add_argument("session_id")
    p.add_argument("--state-root")
    p.add_argument("--project", default=".")
    p.add_argument("--candidates", action="store_true")
    p.add_argument("--details", action="store_true", help="include full outcome and diff entries")
    _session_output_args(p)


@command("match-session-status", "Inspect a standalone matching session and its residual frontier")
def match_session_status(args):
    store = SessionStore(resolve_store(args.session_id, args.project, args.state_root))
    try:
        session = MatchSession(store, lambda *_args: None)
        value = session.status(args.session_id, args.candidates or args.exact_only,
                               args.details or args.best_details)
        registry = SessionRegistry(args.project)
        try:
            historical = registry.same_target(store.context(args.session_id))
        finally:
            registry.close()
        value["project_best"] = historical[0] if historical else None
        value["historical_sessions"] = len(historical)
        return _project_session_output(value, args, store)
    finally:
        store.close()


match_session_status.arguments = _session_status_args


def _session_export_args(p):
    p.add_argument("session_id")
    p.add_argument("output")
    p.add_argument("--state-root")
    p.add_argument("--project", default=".")
    p.add_argument("--candidate-id", help="default: current best candidate")


@command("match-session-export", "Export a retained session candidate without editing project source")
def match_session_export(args):
    store = SessionStore(resolve_store(args.session_id, args.project, args.state_root))
    try:
        candidate = (store.get(args.session_id, args.candidate_id)
                     if args.candidate_id else store.best(args.session_id))
        if candidate is None:
            raise ValueError("candidate does not exist in this session")
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(store.cache.get(candidate.source_digest))
        evidence = output.with_suffix(output.suffix + ".evidence.json")
        evidence.write_text(json.dumps(candidate.as_dict(), indent=2, sort_keys=True) + "\n")
        return {"output": str(output), "evidence": str(evidence),
                "candidate": candidate.as_dict()}
    finally:
        store.close()


match_session_export.arguments = _session_export_args


def _winner_prepare_args(p):
    p.add_argument("session_id")
    p.add_argument("output_dir")
    p.add_argument("--state-root")
    p.add_argument("--project", default=".")
    p.add_argument("--candidate-id", help="default: exact best candidate")


@command("match-session-prepare-winner", "Independently recompile an exact candidate and prepare an integration transaction")
def match_session_prepare_winner(args):
    store = SessionStore(resolve_store(args.session_id, args.project, args.state_root))
    try:
        candidate = (store.get(args.session_id, args.candidate_id)
                     if args.candidate_id else store.best(args.session_id))
        if candidate is None or not candidate.exact:
            raise ValueError("integration preparation requires an exact retained candidate")
        context = store.context(args.session_id)
        source = store.cache.get(candidate.source_digest)
        verified = _session_evaluator(context)(source, candidate.pipeline, candidate.flags,
                                               "independent-winner-verification")
        if not verified.exact:
            raise RuntimeError("independent recompilation did not reproduce the exact match")
        root = Path(args.output_dir).resolve()
        root.mkdir(parents=True, exist_ok=True)
        canonical_name = (f"{context.get('inventory_name')}.c" if context.get("inventory_name") else
                          f"func_{int(context['addr']):08X}.c" if context.get("addr") is not None else "winner.c")
        source_path = root / canonical_name
        source_path.write_bytes(source)
        receipt = {
            "proof": "independent exact recompilation",
            "session_id": args.session_id,
            "candidate_id": candidate.candidate_id,
            "source_sha256": candidate.source_digest,
            "pipeline": candidate.pipeline,
            "flags": list(candidate.flags),
            "target": {key: context.get(key) for key in
                       ("rom_sha256", "vram_delta", "addr", "size", "inventory_id", "inventory_image")},
            "outcome": verified.as_dict(),
            "project_edits_applied": False,
            "historical_source_name": context.get("source_name"),
            "canonical_source_name": canonical_name,
        }
        evidence = root / "winner.evidence.json"
        evidence.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        queue = root / "exact-winner.jsonl"
        queue.write_text(json.dumps({key: receipt[key] for key in
                                    ("session_id", "candidate_id", "source_sha256", "pipeline", "flags")},
                                    sort_keys=True) + "\n")
        return {"source": str(source_path), "evidence": str(evidence), "export_queue": str(queue),
                "exact": True, "project_edits_applied": False}
    finally:
        store.close()


match_session_prepare_winner.arguments = _winner_prepare_args


def _session_explore_args(p):
    p.add_argument("session_id")
    p.add_argument("--project", default=".")
    p.add_argument("--state-root")
    p.add_argument("--strategy", choices=("residual-guided",), default="residual-guided")
    p.add_argument("--jobs", type=int, default=4)
    p.add_argument("--rounds", type=int, default=4)
    p.add_argument("--variants-per-round", type=int, default=12)
    p.add_argument("--stop-on-exact", action="store_true")
    p.add_argument("--best-details", action="store_true")
    p.add_argument("--target-window", help="target residual byte window START:END")
    p.add_argument("--freeze-prefix", type=lambda value: int(value, 0),
                   help="freeze residual behavior before this target offset")
    p.add_argument("--freeze-suffix", type=lambda value: int(value, 0),
                   help="freeze residual behavior at and after this target offset")
    p.add_argument("--dimensions", default="spelling,prototype,lifetime,narrowing,control-flow,flags")


@command("match-session-explore", "Run bounded multi-round residual-guided source experiments")
def match_session_explore(args):
    from ..match.explore import explore
    store = SessionStore(resolve_store(args.session_id, args.project, args.state_root))
    try:
        session = MatchSession(store, _session_evaluator(store.context(args.session_id)))
        window = None
        if args.target_window:
            try: left, right = args.target_window.split(":", 1); window = (int(left, 0), int(right, 0))
            except (ValueError, TypeError): raise ValueError("--target-window must be START:END")
        elif args.freeze_prefix is not None and args.freeze_suffix is not None:
            window = (args.freeze_prefix, args.freeze_suffix)
        if window and not 0 <= window[0] < window[1]: raise ValueError("residual window must be increasing")
        result = explore(store, session, args.session_id, args.jobs, args.rounds,
                         args.variants_per_round, args.stop_on_exact, window,
                         {value.strip() for value in args.dimensions.split(",") if value.strip()})
        if args.best_details:
            result["best"] = store.best(args.session_id).summary(True)
        return result
    finally:
        store.close()


match_session_explore.arguments = _session_explore_args


def _session_explain_args(p):
    p.add_argument("session_id")
    p.add_argument("--project", default=".")
    p.add_argument("--state-root")
    p.add_argument("--from", dest="from_id", required=True)
    p.add_argument("--to", dest="to_id", required=True)


@command("match-session-explain", "Explain source and residual changes between two candidates")
def match_session_explain(args):
    from ..match.explore import explain
    store = SessionStore(resolve_store(args.session_id, args.project, args.state_root))
    try:
        return explain(store, args.session_id, args.from_id, args.to_id)
    finally:
        store.close()


match_session_explain.arguments = _session_explain_args


def _batch_args(p):
    p.add_argument("manifests", nargs="+", metavar="MANIFEST[=PIPELINE]",
                   help="manifest TSV; optional =PIPELINE overrides the pipeline taken from its header")
    _common(p, rom_required=False)
    p.add_argument("--kmc-lane", choices=("hook", "builtin", "as", "asn64"), default=None,
                   help="assembler lane for KMC rows without --assembler= (default: hook when a "
                        "normalizer is configured, else builtin)")
    p.add_argument("--source-template", help="unit-row source path, e.g. 'src/code/{unit}.c'")
    p.add_argument("--flags", help="compiler flags for unit rows (default: toolchain profile)")
    p.add_argument("--status-flags", action="append", default=[], metavar="STATUS=FLAGS",
                   help="extra compiler flags for unit rows with this status (repeatable)")
    p.add_argument("--rodata-map", help="TSV UNIT VRAM SIZE fixing .rodata placement of unit rows")
    p.add_argument("--infer-externals", action="store_true",
                   help="recover symbols no symbol file or batch unit defines from the retail code")
    p.add_argument("--only", action="append", default=[], help="verify only units whose name contains this")


@command("match-batch", "Rebuild and verify every unit of one or more matching manifests in parallel")
def match_batch(args):
    cfg, target, syms, sym_files = _setup(args)
    lane = args.kmc_lane or ("hook" if cfg.normalizer else "builtin")
    status_flags = {}
    for item in args.status_flags:
        k, _, v = item.partition("=")
        status_flags[k] = shlex.split(v)
    rodata = manmod.load_section_map(Path(cfg.project, args.rodata_map)) if args.rodata_map else None
    units = []
    for spec in args.manifests:
        path, _, pipe = spec.partition("=")
        if pipe and pipe not in PIPELINES and pipe != "kmc":
            raise SystemExit(f"unknown pipeline {pipe!r}")
        units += manmod.parse(Path(cfg.project, path), cfg.project, target.rom_to_vram, pipe or None,
                              f"kmc+{lane}", args.source_template,
                              shlex.split(args.flags) if args.flags else None, status_flags, rodata)
    if args.only:
        units = [u for u in units if any(o in u.name for o in args.only)]
    done = [0]

    def progress(_o):
        done[0] += 1
        if args.format != "json" and sys.stderr.isatty():
            print(f"\r{done[0]}/{len(units)}", end="", file=sys.stderr, flush=True)

    outs = batch(units, cfg, target, syms, args.jobs, args.infer_externals, progress)
    exact = [o for o in outs if o.exact]
    by_pipe: dict[str, list[int]] = {}
    for o in outs:
        by_pipe.setdefault(o.spec.pipeline, [0, 0])
        by_pipe[o.spec.pipeline][0] += 1
        by_pipe[o.spec.pipeline][1] += o.exact
    summary = {"units": len(outs), "exact": len(exact), "failed": len(outs) - len(exact),
               "text_bytes": sum(o.size for o in exact),
               "data_bytes": sum(s.size for o in exact for s in (o.result.sections if o.result else [])),
               "by_pipeline": {k: f"{v[1]}/{v[0]}" for k, v in sorted(by_pipe.items())},
               "symbol_files": [str(f) for f in sym_files]}
    if args.format == "json":
        summary["results"] = [o.as_dict() for o in outs]
        return summary
    if sys.stderr.isatty():
        print(file=sys.stderr)
    lines = [f"{'MATCH' if o.exact else 'FAIL '} [{o.spec.pipeline}] {o.name}: 0x{o.vram:08X} (0x{o.size:X} bytes)"
             + ("" if o.exact else " -- " + (o.error or (o.result.error if o.result and o.result.error else "")
                                             or (o.result.diff.summary() if o.result and o.result.diff else
                                                 "digest mismatch" if o.digest_ok is False else "section mismatch")))
             for o in outs]
    lines.append(f"Verified {summary['exact']}/{summary['units']} units, {summary['text_bytes']} code bytes, "
                 f"{summary['data_bytes']} data bytes ({', '.join(f'{k} {v}' for k, v in summary['by_pipeline'].items())})")
    print("\n".join(lines))
    return 0 if not summary["failed"] else 1


match_batch.arguments = _batch_args


def _permute_args(p):
    p.add_argument("source", help="C source containing the function")
    _common(p, rom_required=True)
    p.add_argument("--addr", required=True, type=lambda s: int(s, 16), help="VRAM of the unit's .text (hex)")
    p.add_argument("--size", type=lambda s: int(s, 16), help="text size (hex)")
    p.add_argument("--function", help="C name of the function to permute (default: the one at --addr)")
    p.add_argument("--pipeline", choices=PIPELINES)
    p.add_argument("--flags")
    p.add_argument("--iterations", type=int, default=200)
    p.add_argument("--seed", type=int)
    p.add_argument("--max-mutations", type=int, default=3)
    p.add_argument("--temperature", type=float, default=0.1)
    p.add_argument("--out", help="directory for best.c")
    p.add_argument("--replay-log", help="append every generated candidate and oracle score as JSONL")
    p.add_argument("--proposal-log", help="generate uncompiled candidates here and exit")
    p.add_argument("--parent-score", type=int, help="base score recorded in --proposal-log rows")


@command("match-permute", "Random AST permutation search scored by the relocated instruction diff")
def match_permute(args):
    from ..match import permuter
    if not permuter.available():
        raise SystemExit("pycparser is not importable; install it or add it to PYTHONPATH")
    cfg, target, syms, _files = _setup(args)
    spec = _spec(args, cfg)
    if args.proposal_log:
        if args.parent_score is None:
            raise SystemExit("--proposal-log requires --parent-score")
        generated = permuter.generate_pool(
            Path(args.source).resolve(), syms, cfg.include, args.function, args.addr,
            args.iterations, args.seed, args.max_mutations, args.parent_score,
            Path(args.proposal_log))
        return {"generated": generated, "proposal_log": args.proposal_log,
                "compiled": 0}
    res = permuter.permute(Path(args.source).resolve(), spec, cfg, target, args.addr, args.size, syms,
                           cfg.include, args.function, args.iterations, args.jobs or 4, args.seed,
                           args.max_mutations, args.temperature, Path(args.out) if args.out else None,
                           Path(args.replay_log) if args.replay_log else None)
    return {"base_score": res.base_score, "best_score": res.best_score, "exact": res.exact,
            "iterations": res.iterations, "improvements": res.history,
            **({"best_source": res.best_source} if args.format == "json" else {})}


match_permute.arguments = _permute_args
