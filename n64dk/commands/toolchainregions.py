"""``toolchain-regions``: which tool chain built which stretch of each image, component by
component, with abstention and a dossier for what no known tool chain explains (read-only)."""
from __future__ import annotations

import json
from pathlib import Path

from ..cli import command


def render(result: dict) -> str:
    lines = [f"toolchain regions of {result['project']}"]
    for name, rec in result["images"].items():
        summary = rec.get("summary") or {}
        lines.append(f"  {name}: {rec.get('functions')} functions, {summary.get('regions', 0)} regions, "
                     f"functions by verdict {summary.get('functions_by_verdict')}")
        for region in rec.get("regions") or []:
            best = ", ".join(f"{r['recipe']} {r['share']:.0%}" for r in region["ranked"][:2])
            extra = ""
            if region["component_mismatches"]:
                extra = "; differs in " + ", ".join(sorted({m["component"] for m in region["component_mismatches"]}))
            if region["unknown_marks"]:
                extra += "; no class explains " + ", ".join(region["unknown_marks"])
            if region.get("unreproduced_components"):
                extra += "; no installed tool chain produces " + ", ".join(
                    sorted({u["component"] for u in region["unreproduced_components"]}))
            proven = f"; exact under {region['proven']}" if region["proven"] else ""
            lines.append(f"    {region['start']}..{region['end']} {region['functions']:5d} fn  {region['verdict']:9s} "
                         f"{best}{extra}{proven}")
    return "\n".join(lines)


def run(project: Path, images=None, run_dir: Path | None = None, out: Path | None = None,
        probes: Path | None = None) -> dict:
    from ..analysis import coverage
    from ..match import images as imagemod
    from ..match import resolve as resolvemod
    from ..match import toolchain_regions as tcmod
    registry = imagemod.load_registry(project)
    cases = []
    if run_dir is not None and (run_dir / "state").is_dir():
        store = resolvemod.CaseStore(run_dir / "state", readonly=True)
        try:
            cases = store.all()
        finally:
            store.close()
    result = {"project": project.name, "images": {}}
    for name in images or sorted(registry):
        try:
            spec = imagemod.resolve(project, name)
            data, rows = spec.load(), coverage.rows_of(spec)
        except Exception as error:                           # noqa: BLE001 - reported per image
            result["images"][name] = {"error": str(error)[-200:]}
            continue
        result["images"][name] = tcmod.reconstruct(data, spec.delta, rows,
                                                   cases=[c for c in cases if c.image == name],
                                                   lane_marks=tcmod.load_lane_marks(probes))
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "toolchain_regions.json").write_text(json.dumps(result, indent=1) + "\n")
    return result


@command("toolchain-regions", "Regional tool-chain reconstruction: ranked recipes per region, component "
                              "mismatches, abstention and unknown-toolchain dossiers (read-only)")
def toolchain_regions(args):
    result = run(Path(args.project).resolve(), args.image or None,
                 Path(args.run).resolve() if args.run else None, Path(args.out).resolve() if args.out else None,
                 Path(args.probes).resolve() if args.probes else None)
    if getattr(args, "format", "text") == "text":
        print(render(result))
        return 0
    return result


def _args(p):
    p.add_argument("--project", required=True, help="project directory (read only)")
    p.add_argument("--image", action="append", help="only this image (repeatable)")
    p.add_argument("--run", help="a decompile-run --out directory: its exact cases are the regions' proof")
    p.add_argument("--out", help="write toolchain_regions.json here")
    p.add_argument("--probes", help="a compiler-probes result (its lane_marks: which component forms each installed "
                                    "recipe produces); default: the shipped table")


toolchain_regions.arguments = _args
