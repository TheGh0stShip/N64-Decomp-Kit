"""Throughput commands: comparable scores, fragment audit, similarity queue, m2c drafts, hints.

All commands read a linear image file (a ROM, an unpacked program or an overlay composite)
with ``--vram-delta`` = VRAM minus file offset, so they work for any image a project can
produce and never write into the project.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..analysis import fragments
from ..analysis.functions import load_catalogue
from ..cli import command, emit
from ..match import hints as hintmod
from ..match import m2c_bridge, similar
from ..match import score as scoremod


def _int(text: str) -> int:
    return int(text, 0)


def _catalogue(path: str, shift: int = 0) -> list[tuple[str, int, int]]:
    return [(name, vram - shift, size) for name, vram, size in load_catalogue(Path(path))]


def _manifest_intervals(paths: list[str]) -> list[tuple[int, int, str]]:
    out = []
    for path in paths:
        for line in Path(path).read_text().splitlines():
            parts = line.split("\t")
            if line.startswith("#") or len(parts) < 3:
                continue
            try:
                out.append((int(parts[0], 0), int(parts[1], 0), parts[2]))
            except ValueError:
                continue
    return sorted(out)


@command("asm-score", "Score candidate code against target code with asm-differ/permuter penalties")
def asm_score(args):
    target, candidate = Path(args.target).read_bytes(), Path(args.candidate).read_bytes()
    return scoremod.score(target, candidate, args.vram, not args.ignore_stack).as_dict()


def _score_args(p):
    p.add_argument("target", help="retail code bytes (raw, big-endian)")
    p.add_argument("candidate", help="relocated candidate code bytes")
    p.add_argument("--vram", type=_int, default=0x80000000)
    p.add_argument("--ignore-stack", action="store_true", help="do not penalise stack offsets")


asm_score.arguments = _score_args


@command("fragment-audit", "Find catalogue starts that are interior fragments and propose merges")
def fragment_audit(args):
    data = Path(args.image).read_bytes()
    others = []
    for item in args.also:
        path, delta = item.rsplit(":", 1)
        others.append((Path(path).read_bytes(), _int(delta)))
    report = fragments.audit(data, args.vram_delta, _catalogue(args.catalogue, args.catalogue_shift), others)
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=1))
    if args.all:
        return report
    return {"summary": report["summary"], "merges": report["merges"][:args.limit],
            "fragments": [s for s in report["starts"] if s["fragment"]][:args.limit]}


def _fragment_args(p):
    p.add_argument("image")
    p.add_argument("--vram-delta", type=_int, required=True, help="VRAM minus file offset of the image")
    p.add_argument("--catalogue", required=True, help="function catalogue TOML or symbol_addrs.txt")
    p.add_argument("--catalogue-shift", type=_int, default=0,
                   help="subtract from catalogue addresses (catalogue VRAM minus link VRAM)")
    p.add_argument("--also", action="append", default=[], metavar="IMAGE:DELTA",
                   help="other image whose calls may target this one (repeatable)")
    p.add_argument("--limit", type=int, default=40)
    p.add_argument("--all", action="store_true")
    p.add_argument("--out", help="write the full JSON report here")


fragment_audit.arguments = _fragment_args


@command("similar-queue", "Rank unmatched functions by similarity to already matched ones")
def similar_queue(args):
    signatures = []
    for spec in args.set:
        name, image, delta, catalogue, *manifests = spec.split(",")
        data, delta = Path(image).read_bytes(), _int(delta)
        intervals = _manifest_intervals(manifests)
        for fn, vram, size in _catalogue(catalogue):
            off = vram - delta
            if off < 0 or off + size > len(data):
                continue
            owner = next((src for start, length, src in intervals if start <= off < start + length), None)
            signatures.append(similar.signature(fn, data[off:off + size], vram, matched=owner is not None,
                                                source=owner, image=name))
    rows = similar.queue(signatures, args.threshold)
    with_reference = [r for r in rows if r["best_similarity"] >= args.threshold]
    return {"functions": len(signatures), "unmatched": len(rows), "with_matched_sibling": len(with_reference),
            "sibling_bytes": 4 * sum(r["instructions"] for r in with_reference), "queue": rows[:args.limit]}


def _similar_args(p):
    p.add_argument("--set", action="append", required=True,
                   metavar="NAME,IMAGE,VRAM_DELTA,CATALOGUE[,MANIFEST...]",
                   help="one image: catalogue plus the ROM_START/SIZE/SOURCE manifests that mark matched code")
    p.add_argument("--threshold", type=float, default=0.8)
    p.add_argument("--limit", type=int, default=50)


similar_queue.arguments = _similar_args


def _jump_tables_tsv(path: str, data: bytes, delta: int, start: int, end: int) -> list[tuple[int, list[int]]]:
    """Tables from ``functions --out``'s jump_tables.tsv whose owner or ``jr`` site is this
    function; entries are re-read from the image (the TSV keeps only the first target)."""
    tables = []
    for line in Path(path).read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or line.startswith(("#", "address")):
            continue
        try:
            address, count, owner, site = int(parts[0], 0), int(parts[1], 0), int(parts[3], 0), int(parts[4], 0)
        except ValueError:
            continue
        off = address - delta
        if not (owner == start or start <= site < end) or count <= 0 or off < 0 or off + 4 * count > len(data):
            continue
        tables.append((address, [int.from_bytes(data[off + 4 * i:off + 4 * i + 4], "big") for i in range(count)]))
    return tables


def _draft_inputs(args):
    data = Path(args.image).read_bytes()
    names, sizes = {}, {}
    for path in args.symbols:
        for name, vram, size in load_catalogue(Path(path)):
            names[vram] = name
            if size:
                sizes[vram] = size
    size = args.size if args.size is not None else sizes.get(args.addr)
    if not size:
        raise SystemExit(f"--size not given and no catalogue entry with a size at 0x{args.addr:08X}")
    off = args.addr - args.vram_delta
    if size <= 0 or off < 0 or off + size > len(data):
        raise SystemExit(f"0x{args.addr:08X}+0x{size:X} is outside {args.image} "
                         f"(file offset 0x{off:X}, image 0x{len(data):X} bytes)")
    name = args.name or names.get(args.addr) or f"func_{args.addr:08X}"
    if not m2c_bridge.SYMBOL.match(name):
        raise SystemExit(f"{name!r} is not usable as an assembler symbol / file name; pass --name")
    if args.context and not Path(args.context).is_file():
        raise SystemExit(f"--context {args.context}: file not found")
    tables: dict[int, list[int]] = {}
    for path in args.jump_tables:
        tables.update(_jump_tables_tsv(path, data, args.vram_delta, args.addr, args.addr + size))
    if not args.no_auto_jump_tables:
        for address, targets in m2c_bridge.find_jump_tables(data, args.vram_delta, args.addr, size):
            tables.setdefault(address, targets)
    return data[off:off + size], names, name, sorted(tables.items())


def _draft_mapping(args) -> dict | None:
    """Fail closed when an explicit offset disagrees with authoritative project mapping."""
    try:
        from ..match import inventory as invmod
        from ..match.layout import from_inventory, resolve_image_map

        inventory = invmod.build(args.project)
        rows = [row for row in inventory.get("functions", [])
                if int(row["vram"], 0) == args.addr
                and (args.size is None or int(row["size"]) == args.size)]
        image_number = re.search(r"overlay[_-]?(\d+)", Path(args.image).name, re.I)
        if image_number:
            rows = [row for row in rows if row["image"].replace("_", "") == "overlay" + image_number.group(1)]
        if len(rows) != 1:
            return None
        resolved = resolve_image_map(args.image, from_inventory(rows[0]))
        canonical_delta = args.addr - resolved["selected"]["offset"]
        if canonical_delta != args.vram_delta:
            raise ValueError(f"explicit vram_delta 0x{args.vram_delta:X} selects file offset "
                             f"0x{args.addr - args.vram_delta:X}, but project mapping selects "
                             f"0x{resolved['selected']['offset']:X} (delta 0x{canonical_delta:X})")
        return {"authority": resolved["selected"].get("authority"),
                "selected_offset": f"0x{resolved['selected']['offset']:X}",
                "vram_delta": f"0x{canonical_delta:X}", "inventory_id": rows[0].get("id")}
    except ValueError:
        raise
    except Exception:
        return None


@command("m2c-draft", "Emit symbolized assembly for a function and, when m2c is installed, a first C draft")
def m2c_draft(args):
    mapping = _draft_mapping(args)
    code, names, name, tables = _draft_inputs(args)
    if args.asm_only:
        result = {"name": name, "status": "asm-only", "error": None, "source": None,
                  "asm": m2c_bridge.emit_asm(name, code, args.addr, names, tables),
                  "jump_tables": [f"0x{a:08X}" for a, _t in tables]}
    else:
        result = m2c_bridge.draft(name, code, args.addr, args.compiler,
                                  Path(args.context) if args.context else None, names, tables,
                                  extra=args.m2c_arg, timeout=args.timeout, m2c=args.m2c)
    result["image_mapping"] = mapping
    if mapping is None:
        result.setdefault("warnings", []).append("target mapping was not verified against project inventory")
    failed = result["status"] not in ("ok", "asm-only")
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{name}.s").write_text(result["asm"])
        written = {"asm": str(out / f"{name}.s")}
        if result.get("m2c_input") and result["m2c_input"] != result["asm"]:
            (out / f"{name}.m2c.s").write_text(result["m2c_input"])
            written["m2c_input"] = str(out / f"{name}.m2c.s")
        if result["source"]:
            (out / f"{name}.c").write_text(result["source"])
            written["source"] = str(out / f"{name}.c")
        summary = {k: v for k, v in result.items() if k not in ("asm", "m2c_input", "source")}
        result = {**summary, **written, "source": written.get("source")}
    elif not failed:
        return result["source"] or result["asm"]
    if failed:
        emit({k: v for k, v in result.items() if k != "m2c_input"}, args.format)
        return 1
    return result


def _m2c_args(p):
    p.add_argument("image")
    p.add_argument("--project", default=".", help="project used to validate raw/composite image mapping")
    p.add_argument("--vram-delta", type=_int, required=True, help="VRAM minus file offset of the image")
    p.add_argument("--addr", type=_int, required=True)
    p.add_argument("--size", type=_int, help="bytes (default: the --symbols catalogue entry at --addr)")
    p.add_argument("--name")
    p.add_argument("--compiler", default="kmc",
                   help="kmc, sn, gcc or ido (selects the m2c target), or a full m2c triple such as mips-ido-c")
    p.add_argument("--context", help="preprocessed C context file for m2c")
    p.add_argument("--symbols", action="append", default=[], help="catalogue/symbol file for names (repeatable)")
    p.add_argument("--jump-tables", action="append", default=[], metavar="TSV",
                   help="jump_tables.tsv from `functions --out` (repeatable)")
    p.add_argument("--no-auto-jump-tables", action="store_true",
                   help="do not recover jump tables from the function's jr dispatches")
    p.add_argument("--m2c", help=f"m2c executable, m2c.py, source checkout or command (default: ${m2c_bridge.ENV_VAR}, "
                                 "PATH, the interpreter's scripts dir, then an importable m2c)")
    p.add_argument("--m2c-arg", action="append", default=[], metavar="ARG",
                   help="extra m2c argument, e.g. --m2c-arg=--stack-structs (repeatable)")
    p.add_argument("--timeout", type=float, default=60, help="m2c timeout in seconds")
    p.add_argument("--asm-only", action="store_true")
    p.add_argument("--out", help="directory for NAME.s, NAME.m2c.s (m2c input) and NAME.c")


m2c_draft.arguments = _m2c_args


@command("match-hints", "Turn a match diff (JSON with entries/counts) into specific source hints")
def match_hints(args):
    data = json.loads(Path(args.report).read_text())
    for key in ("diff", "outcome", "result"):           # accept nested match/session outputs
        while isinstance(data, dict) and "entries" not in data and key in data:
            data = data[key]
    return {"hints": hintmod.hints(data, args.family)}


def _hint_args(p):
    p.add_argument("report", help="JSON from `n64dk --format json match ...` or a diff as_dict()")
    p.add_argument("--family", choices=("any", "gcc", "ido"), default="any")


match_hints.arguments = _hint_args


@command("draft-sweep", "Draft unmatched functions with m2c, build them, compare them and rank the results")
def draft_sweep(args):
    import shlex
    import tempfile

    from ..match import autodraft
    from ..match.engine import Target, match_source
    from ..match.pipeline import split_flags
    from ..match import symbols as symmod
    from ..match.toolchain import load_config
    from ..rom import RomError
    from .match import _setup

    try:
        cfg, target, syms, _files = _setup(args)
    except RomError:
        if args.vram_delta is None:
            raise ValueError("a raw loaded image requires an explicit --vram-delta")
        cfg = load_config(args.project, args.config, args.toolchain_dir)
        if args.normalizer: cfg.normalizer = args.normalizer
        if args.include:
            cfg.include = list(dict.fromkeys([Path(cfg.project, value).resolve()
                                              for value in args.include] + cfg.include))
        target = Target(Path(args.rom).read_bytes(), args.vram_delta, (0, Path(args.rom).stat().st_size))
        symbol_files = [Path(value) for value in args.symbols] or cfg.symbols or symmod.discover(cfg.project)
        syms = symmod.load(symbol_files); _files = symbol_files
    spec = split_flags(shlex.split(args.flags), args.pipeline)
    covered = [(start, size) for start, size, _src in _manifest_intervals(args.manifest)]
    functions = [(name, vram - args.catalogue_shift, size)
                 for name, vram, size in load_catalogue(Path(args.catalogue))]
    todo = [function for function in functions
            if not any(start <= target.vram_to_rom(function[1]) < start + size
                       for start, size in covered)]
    rejected = []
    if args.preflight:
        from ..match import inventory as invmod
        from ..match.layout import from_inventory, preflight, resolve_image_map

        inventory = invmod.build(args.project)
        by_key = {(row["name"], int(row["vram"], 0)): row for row in inventory["functions"]}
        verified = []
        canonical_deltas = set()
        for function in todo:
            row = by_key.get((function[0], function[1]))
            if row is None:
                rejected.append({"name": function[0], "reason": "not present in project inventory"})
                continue
            try:
                # Resolve coordinates before decoding.  If the caller supplied the wrong
                # delta, preflight would otherwise inspect unrelated bytes and merely reject
                # every row as a bad boundary instead of exposing the mapping error.
                resolved = resolve_image_map(args.rom, from_inventory(row))
                canonical_delta = function[1] - int(resolved["selected"]["offset"])
                canonical_deltas.add(canonical_delta)
                if canonical_delta != target.delta:
                    raise ValueError(f"selected vram_delta 0x{target.delta:X} conflicts with "
                                     f"canonical project image mapping 0x{canonical_delta:X}")
                check = preflight(args.rom, from_inventory(row), row.get("catalogue_status", ""), strict_entry=True)
            except (OSError, ValueError) as error:
                rejected.append({"name": function[0], "reason": str(error)})
            else:
                verified.append(function)
        todo = verified
        if len(canonical_deltas) > 1:
            raise ValueError("catalogue resolves to multiple image mappings; split the sweep by image region")
        if canonical_deltas and target.delta not in canonical_deltas:
            canonical = next(iter(canonical_deltas))
            raise ValueError(f"selected vram_delta 0x{target.delta:X} conflicts with canonical "
                             f"project image mapping 0x{canonical:X}")
    todo.sort(key=lambda function: function[2])
    if args.limit:
        todo = todo[:args.limit]
    out = Path(args.out)
    names = {vram: name for name, vram, _size in functions}
    with tempfile.TemporaryDirectory(prefix="n64dk-draft-sweep-") as work:
        def evaluate(path, vram, size):
            return match_source(path, spec, cfg, target, vram, size, syms, Path(work), None)

        report = autodraft.sweep(todo, target.rom, target.delta, evaluate, out,
                                 jobs=args.jobs or 8, compiler=args.pipeline, names=names,
                                 max_size=args.max_size,
                                 family="ido" if args.pipeline.startswith("ido") else "gcc",
                                 context=Path(args.context) if args.context else None)
    report["summary"]["preflight_rejected"] = len(rejected)
    report["preflight_rejected"] = rejected
    (out / "report.json").write_text(json.dumps(report, indent=1))
    return {"summary": report["summary"], "report": str(out / "report.json"),
            "best": report["rows"][:args.show]}


def _draft_sweep_args(p):
    from .match import _common
    _common(p, rom_required=True)
    p.add_argument("--catalogue", required=True, help="function catalogue TOML or symbol_addrs.txt")
    p.add_argument("--catalogue-shift", type=_int, default=0,
                   help="subtract catalogue VRAM minus linked VRAM")
    p.add_argument("--manifest", action="append", default=[],
                   help="ROM_START/SIZE/SOURCE manifest of already matched code (repeatable)")
    p.add_argument("--pipeline", default="kmc+builtin")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--context", help="preprocessed C context for m2c (types and prototypes)")
    p.add_argument("--no-preflight", action="store_false", dest="preflight", default=True,
                   help="allow catalogue entries that fail project inventory/boundary validation")
    p.add_argument("--out", required=True, help="output directory for drafts and report.json")
    p.add_argument("--limit", type=int, default=0)
    p.add_argument("--max-size", type=_int, default=0x1000)
    p.add_argument("--show", type=int, default=20)


draft_sweep.arguments = _draft_sweep_args
