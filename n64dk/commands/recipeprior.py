"""``recipe-prior``: what an image's machine code says about how it was built, without compiling."""
from __future__ import annotations

import json
from pathlib import Path

from ..cli import command


def proven(state: Path, project: Path):
    """``(recipe label, code, vram)`` of every strictly matched C function of a finished run."""
    from ..match import handasm, images as imagemod
    from ..match import resolve as resolvemod
    store = resolvemod.CaseStore(state)
    try:
        cases = [case for case in store.all() if case.status in ("exact", "assumed") and case.recipe
                 and case.rom_offset is not None and case.recipe != handasm.RECIPE]
    finally:
        store.close()
    loaded: dict[str, bytes] = {}
    for case in cases:
        if case.image not in loaded:
            try:
                loaded[case.image] = imagemod.resolve(project, case.image).load()
            except Exception:                                # noqa: BLE001 - an image that is gone teaches nothing
                loaded[case.image] = b""
        code = loaded[case.image][case.rom_offset:case.rom_offset + case.size]
        if len(code) == case.size:
            yield case.recipe, code, case.vram


def built(folder: Path):
    """``(recipe label, code, vram)`` of every C function of one ``sdk-donor`` build."""
    image = (folder / "image.bin").read_bytes()
    units = []
    for manifest in sorted(folder.glob("manifest.*.tsv")):
        pipeline = manifest.name[len("manifest."):-len(".tsv")]
        pipeline = {"kmc_as": "kmc+as", "kmc_asn64": "kmc+asn64", "kmc_builtin": "kmc+builtin"}.get(pipeline, pipeline)
        for line in manifest.read_text().splitlines():
            cells = line.split("\t")
            if len(cells) >= 3 and cells[0].startswith("0x") and cells[2].endswith(".c"):
                units.append((int(cells[0], 16), int(cells[1], 16), f"{pipeline} {cells[3] if len(cells) > 3 else ''}"))
    for line in (folder / "functions.tsv").read_text().splitlines():
        cells = line.split("\t")
        if len(cells) == 4 and cells[0].startswith("0x"):
            offset, size = int(cells[0], 16), int(cells[1], 16)
            label = next((label for start, length, label in units if start <= offset < start + length), None)
            if label and size:
                yield label, image[offset:offset + size], int(cells[2], 16)


@command("recipe-prior", "Rank compilers and optimisation levels for each stretch of an image from the marks they "
                         "leave in machine code (no compiling); --learn adds finished runs to the table")
def recipe_prior(args):
    from ..match import idioms, images as imagemod
    table = idioms.Table.load(args.table)
    learned = []
    for item in args.learn or []:
        state, _, project = item.partition("=")
        if not project:
            raise SystemExit("--learn takes STATE_DIR=PROJECT_DIR (the run's state and the project it ran on)")
        learned.append({"state": state, "functions": idioms.learn(table, proven(Path(state), Path(project)))})
    for folder in args.learn_build or []:
        learned.append({"build": folder, "functions": idioms.learn(table, built(Path(folder)))})
    if learned:
        if not args.table:
            raise SystemExit("--learn needs --table FILE to write to (the shipped table is not modified)")
        table.save(args.table)
    report: dict = {"classes": {name: entry["functions"] for name, entry in sorted(table.classes.items())}}
    if learned:
        report["learned"] = learned
    if args.project:
        project = Path(args.project)
        registry = imagemod.load_registry(project)
        names = [args.image] if args.image else sorted(registry)
        report["images"] = {}
        for name in names:
            spec = imagemod.resolve(project, name)
            data, delta = spec.load(), spec.delta
            functions = []
            for _name, vram, size in spec.rows():
                code = data[vram - delta:vram - delta + size]
                if len(code) == size and size:
                    functions.append((vram, idioms.features(code, vram)))
            found = idioms.stretches(functions, table, args.window)
            for row in found:
                row["start"], row["end"] = f"0x{row['start']:08X}", f"0x{row['end']:08X}"
            marks = [(vram, frozenset(m for m in found_marks if not m.startswith("seq:")))
                     for vram, found_marks in functions]
            unknown = idioms.unknown_stretches(marks, table)
            for row in unknown:
                row["start"], row["end"] = f"0x{row['start']:08X}", f"0x{row['end']:08X}"
            report["images"][name] = {"functions": len(functions), "stretches": found,
                                      "no_known_compiler": unknown}
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=1) + "\n")
    return report


def _args(p):
    p.add_argument("--project", help="project whose images are mapped (its catalogue gives the functions)")
    p.add_argument("--image", help="one image (default: every image of the project)")
    p.add_argument("--window", type=int, default=12, help="functions ranked together around each one (default: 12)")
    p.add_argument("--table", help="table of marks per recipe class (default: the one shipped with the kit)")
    p.add_argument("--learn", action="append", metavar="STATE=PROJECT",
                   help="add the strictly matched functions of a finished run to --table (repeatable)")
    p.add_argument("--learn-build", action="append", metavar="DIR",
                   help="add every C function of an `sdk-donor` build directory to --table (repeatable)")
    p.add_argument("--out", help="also write the report to this file")


recipe_prior.arguments = _args
