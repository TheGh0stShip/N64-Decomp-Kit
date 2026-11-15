"""``transplant-scan``: recover target functions from C matched in other local projects."""
from __future__ import annotations

import os
import time
from pathlib import Path

from ..cli import command
from ..match import symbols as symmod
from ..match import transplant as tp


@command("transplant-scan", "Find target functions identical (relocations masked) to C matched in donor "
         "projects, transfer donor symbols, transplant and strictly verify the donor sources")
def transplant_scan(args):
    from ..match.engine import Target
    from ..rom import Rom
    donors = tp.load_donors(args.donors, args.donor or None, args.exclude_donor or None)
    if not donors:
        raise SystemExit("no donors selected")
    t0 = time.time()
    index_path = Path(args.index) if args.index else None
    index, info = tp.build_index(donors, index_path)
    t_index = time.time() - t0
    target = Target.from_rom(Rom.load(args.rom), args.vram_delta)
    functions = tp.load_functions([Path(p) for p in args.catalogue], target.delta)
    if not functions:
        raise SystemExit("the target catalogue yielded no functions")
    skip = tp.manifest_intervals([Path(p) for p in args.manifest], target.delta)
    syms = symmod.load([Path(p) for p in args.symbols]) if args.symbols else symmod.SymbolMap()
    toolchain = args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN")
    out = Path(args.out) if args.out else None
    truth = tp.manifest_declared_addresses([Path(p) for p in args.truth_manifest + args.manifest])
    report = tp.run(None, target, functions, index, skip, out, args.jobs,
                    Path(toolchain) if toolchain else None, not args.no_verify, args.near, syms, truth)
    report.pop("_symbol_file", None)
    report["index"] = {"functions_by_donor": index.stats(), "build": info, "seconds": round(t_index, 2)}
    if not args.full:
        for key in ("rows", "near_hits", "needs_review", "partial_units", "contradictions", "suspicious"):
            if isinstance(report.get(key), list) and len(report[key]) > 20:
                report[key] = report[key][:20] + [f"... {len(report[key]) - 20} more (see report.json)"]
    return report


def _arguments(p):
    p.add_argument("--rom", required=True, help="target image (ROM, or a linear image with --vram-delta)")
    p.add_argument("--vram-delta", type=lambda s: int(s, 0), help="VRAM - file offset of the target code")
    p.add_argument("--catalogue", action="append", default=[], required=True,
                   help="target function catalogue (recomp TOML, splat symbol_addrs with sizes, or ROM/SIZE/VRAM/NAME TSV)")
    p.add_argument("--manifest", action="append", default=[],
                   help="already-matched rows of the target (ROM_START SIZE ...); overlapping functions are skipped")
    p.add_argument("--symbols", action="append", default=[], help="target symbol file (precision report only)")
    p.add_argument("--truth-manifest", action="append", default=[],
                   help="target manifests whose --symbol/--section-base addresses score transfer precision (not skipped)")
    p.add_argument("--donors", required=True, help="donors TOML (see donors.example.toml)")
    p.add_argument("--donor", action="append", default=[], help="use only these donor names")
    p.add_argument("--exclude-donor", action="append", default=[], help="leave these donors out")
    p.add_argument("--index", help="donor index JSON (outside any game project; reused incrementally)")
    p.add_argument("--out", help="output directory for candidate sources, proposed rows and symbols")
    p.add_argument("--toolchain-dir", help="toolchain root (default: $N64DK_TOOLCHAIN)")
    p.add_argument("--jobs", type=int, default=4)
    p.add_argument("--near", type=int, default=2, help="report near hits with up to N differing words")
    p.add_argument("--no-verify", action="store_true", help="scan and transfer only")
    p.add_argument("--full", action="store_true", help="do not truncate lists in the printed report")


transplant_scan.arguments = _arguments
