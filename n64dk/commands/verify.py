"""``manifest-verify``: rebuild manifest units and verify them without retail-derived addresses."""
from __future__ import annotations

import shlex
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..analysis.functions import load_catalogue
from ..cli import command
from ..elf import Elf
from ..match import manifest as manmod
from ..match import verify as verifymod
from ..match.pipeline import PIPELINES, BuildError, build
from .match import _common, _setup


@command("manifest-verify", "Rebuild manifest units and classify each as exact, assumed (retail-derived "
         "addresses) or mismatch")
def manifest_verify(args):
    cfg, target, syms, sym_files = _setup(args)
    units = []
    for spec in args.manifests:
        path, _, pipe = spec.partition("=")
        if pipe and pipe not in PIPELINES and pipe != "kmc":
            raise SystemExit(f"unknown pipeline {pipe!r}")
        units += manmod.parse(Path(cfg.project, path), cfg.project, target.rom_to_vram, pipe or None,
                              f"kmc+{args.kmc_lane}", None, shlex.split(args.flags) if args.flags else None)
    if args.only:
        units = [u for u in units if any(o in u.name for o in args.only)]
    starts = None
    if args.catalogue:
        starts = set()
        for path in args.catalogue:
            starts |= {vram for _name, vram, _size in load_catalogue(Path(cfg.project, path))}
    rows: list[dict] = [{"unit": u.name, "vram": u.vram, "size": u.size, "pipeline": u.spec.pipeline} for u in units]
    with tempfile.TemporaryDirectory(prefix="n64dk-verify-") as tmp:
        def compile_unit(item):
            index, unit = item
            if not unit.source.is_file():
                return None, "source-missing"
            folder = Path(tmp) / f"u{index}"
            folder.mkdir(exist_ok=True)
            try:
                return Elf.load(build(unit.source, unit.spec, cfg, folder)), None
            except (BuildError, RuntimeError, OSError, ValueError) as error:
                return None, f"build-failed: {str(error)[-300:]}"

        with ThreadPoolExecutor(max_workers=args.jobs or 8) as pool:
            built = list(pool.map(compile_unit, enumerate(units)))
        # symbols that verified-layout units define for each other (text symbols and declared bases only)
        declared = syms.copy()
        for unit, (elf, _error) in zip(units, built):
            if elf is not None:
                for name, address in verifymod.unit_defines(elf, unit.vram, unit.spec.section_bases).items():
                    declared.setdefault(name, address)
        if starts is not None:
            starts |= {unit.vram for unit in units}
        for row, unit, (elf, error) in zip(rows, units, built):
            if elf is None:
                row["verdict"] = error.split(":")[0]
                row["error"] = error
                continue
            # Candidate-authored LDSYM markers and aliases are useful to exploration, but
            # are not independent proof authority.  Strict verification accepts only the
            # loaded project map, definitions from this verified build set, and manifest
            # recipe symbols.
            local = declared.copy()
            local.update(unit.spec.symbols)
            verdict = verifymod.strict_compare(elf, target.rom, target.vram_to_rom, unit.vram, unit.size, local,
                                               unit.spec.section_bases, unit.section_sizes or None, starts)
            row["verdict"], row["detail"], row["_verdict"] = verdict.verdict, verdict.as_dict(), verdict
    counts, byte_counts = Counter(r["verdict"] for r in rows), Counter()
    for row in rows:
        byte_counts[row["verdict"]] += row["size"]
    ledger = verifymod.reconcile_assumptions([{"unit": r["unit"], "verdict": r["_verdict"]}
                                              for r in rows if "_verdict" in r])
    unverified_data = sum(1 for r in rows if "_verdict" in r
                          and any(s.get("status") == "unverified" for s in r["_verdict"].sections))
    section_assumed = sum(1 for r in rows if "_verdict" in r
                          and any(a.kind == "section" for a in r["_verdict"].assumptions))
    for row in rows:
        row.pop("_verdict", None)
        row["vram"] = f"0x{row['vram']:08X}"
    if args.write_symbols:
        Path(args.write_symbols).write_text("\n".join(ledger["proposed_symbols"]) + "\n")
    interesting = [r for r in rows if r["verdict"] not in ("exact",)]
    order = {"mismatch": 0, "build-failed": 1, "source-missing": 2, "assumed": 3}
    interesting.sort(key=lambda r: (order.get(r["verdict"], 9), -r["size"]))
    return {"units": len(rows), "verdicts": dict(counts), "bytes": dict(byte_counts),
            "units_with_assumed_section_base": section_assumed, "units_with_unverified_data": unverified_data,
            "symbols_assumed": ledger["symbols_assumed"], "contradictions": ledger["contradictions"],
            "proposed_symbols": ledger["proposed_symbols"][:args.show] if not args.write_symbols
            else f"{len(ledger['proposed_symbols'])} written to {args.write_symbols}",
            "symbol_files": [str(f) for f in sym_files],
            "rows": rows if args.all else interesting[:args.show]}


def _args(p):
    _common(p, rom_required=False)
    p.add_argument("manifests", nargs="+", metavar="MANIFEST[=PIPELINE]")
    p.add_argument("--kmc-lane", default="builtin", help="hook, builtin, as or asn64 for KMC rows")
    p.add_argument("--flags", help="flags for unit-style rows")
    p.add_argument("--catalogue", action="append", default=[],
                   help="function catalogue: calls through assumed symbols must land on a start (repeatable)")
    p.add_argument("--only", action="append", default=[], help="only units whose name contains this")
    p.add_argument("--write-symbols", help="write the proposed (consistent, retail-derived) symbols here for review")
    p.add_argument("--show", type=int, default=25)
    p.add_argument("--all", action="store_true", help="include every row")


manifest_verify.arguments = _args
