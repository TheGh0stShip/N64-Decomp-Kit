"""``compiler-components``: the toolchain component graph, what a toolchain root holds of it, and
every lane as a recipe of stages with a stable identity."""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..cli import command


@command("compiler-components", "List toolchain components (role, provenance, disposition, installed files and "
                                 "digests) and every lane as a recipe of stages with its identity")
def compiler_components(args):
    from ..match import components
    root = Path(args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN", "")) if (args.toolchain_dir or
                                                                                 os.environ.get("N64DK_TOOLCHAIN")) else None
    if args.compare:
        first, second = args.compare
        return components.shared_stages(first, second)
    data = components.catalogue_json(root, digests=not args.no_digests)
    if args.recipe:
        return data["recipes"].get(args.recipe) or {"error": f"no recipe {args.recipe!r}",
                                                     "recipes": sorted(data["recipes"])}
    if args.out:
        Path(args.out).write_text(json.dumps(data, indent=1) + "\n")
    summary = {"root": str(root) if root else None, "components": len(data["components"]),
               "installed": sum(1 for row in data["components"] if row["installed"]),
               "by_disposition": {}, "by_provenance": {},
               "recipes": {lane: {"identity": recipe["identity"][:16], "runnable": recipe["runnable"],
                                  "stages": [f"{stage['stage']}:{stage['component']}" for stage in recipe["stages"]]}
                           for lane, recipe in data["recipes"].items()}}
    for row in data["components"]:
        summary["by_disposition"][row["disposition"]] = summary["by_disposition"].get(row["disposition"], 0) + 1
        summary["by_provenance"][row["provenance"]] = summary["by_provenance"].get(row["provenance"], 0) + 1
    if args.verbose:
        summary["components_detail"] = [{key: row[key] for key in ("ident", "role", "provenance", "disposition",
                                                                   "installed", "platform", "emulator")}
                                        for row in data["components"]]
    return summary


def _args(p):
    p.add_argument("--toolchain-dir", help="toolchain root (default: $N64DK_TOOLCHAIN)")
    p.add_argument("--out", help="write the full machine-readable catalogue (components, recipes, digests) here")
    p.add_argument("--recipe", help="show one lane's recipe stage by stage")
    p.add_argument("--compare", nargs=2, metavar="LANE", help="which stages two lanes share and which differ")
    p.add_argument("--no-digests", action="store_true", help="skip file digests (faster)")
    p.add_argument("--verbose", action="store_true")


compiler_components.arguments = _args


@command("compiler-probes", "Build the synthetic probe suite under every runnable recipe and flag set: determinism, "
                            "equivalence classes, stage attribution, line-layout sensitivity")
def compiler_probes(args):
    import sys
    from .. import safety
    from ..match import probes
    root = Path(args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN", ""))
    out = Path(args.out).resolve()

    def emit(kind, **fields):
        print(json.dumps({"event": kind, **fields}), file=sys.stderr, flush=True)
    try:
        with safety.heavy_job("compiler-probes", out.parent, wait_for_lock=args.wait_for_lock,
                              force=args.force_resources, argv=sys.argv[1:]):
            if args.tool_profile:
                os.environ["N64DK_MEASURE_RSS"] = "1"          # each tool's own peak, through /usr/bin/time
            with __import__("tempfile").TemporaryDirectory(prefix="n64dk-probes-") as work:
                result = probes.run(root, Path(work), args.probe or None, args.lane or None, args.repeat, emit)
            result["tool_usage"] = safety.TOOL_USAGE
            if args.tool_profile:
                result["tool_profile"] = str(safety.save_tool_profile())
    except safety.Busy as error:
        raise SystemExit(str(error)) from None
    out.write_text(json.dumps(result, indent=1) + "\n")
    return {key: result[key] for key in ("distinct_recipes", "usable_recipes", "nondeterministic", "seconds")} | {
        "tool_profile": result.get("tool_profile"),
        "failed": {key: len(value) for key, value in result["errors"].items()}, "out": str(out)}


def _probe_args(p):
    from .run import _guard_arguments
    p.add_argument("--toolchain-dir", help="toolchain root (default: $N64DK_TOOLCHAIN)")
    p.add_argument("--out", required=True, help="write the probe table and analysis here (JSON)")
    p.add_argument("--lane", action="append", help="only these lanes (repeatable)")
    p.add_argument("--probe", action="append", help="only these probes (repeatable)")
    p.add_argument("--repeat", type=int, default=2, help="builds of each probe, for the determinism check")
    p.add_argument("--tool-profile", action="store_true",
                   help="measure every tool's own peak RSS and merge it into the machine's tool profile, which "
                        "weights tool admission (n64dk.safety.tool_weight)")
    _guard_arguments(p)


compiler_probes.arguments = _probe_args
