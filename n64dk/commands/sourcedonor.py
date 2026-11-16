"""``source-donor``: any C source tree as a donor, with its build found by measurement."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from ..cli import command

RECIPE_MATCHES = 3         # a recipe of the run is a candidate when this many of its matches used it
MAX_RECIPES = 6
LEVELS = ("-O0", "-O1", "-O2", "-O3", "-g")


def recipes_of_run(run: Path, limit: int = MAX_RECIPES) -> list[str]:
    """The recipes a finished run matched functions under, most used first: what the title's own
    code says about how it was built."""
    store = Path(run) / "state" / "cases.sqlite"
    if not store.is_file():
        return []
    tally: dict[str, int] = {}
    with closing(sqlite3.connect(f"file:{store}?mode=ro", uri=True)) as db:
        for (payload,) in db.execute("select payload from cases where status in ('exact', 'assumed')"):
            recipe = json.loads(payload).get("recipe")
            if recipe:
                tally[recipe] = tally.get(recipe, 0) + 1
    ranked = sorted(tally.items(), key=lambda item: (-item[1], item[0]))
    return with_levels([recipe for recipe, count in ranked if count >= RECIPE_MATCHES], limit)


def with_levels(recipes: list[str], limit: int = MAX_RECIPES) -> list[str]:
    """``recipes``, then the first one at the other usual levels: a title's library and its game
    code are often the same compiler at two levels, and a run that matched few library functions
    by itself says nothing about the second."""
    out = list(recipes[:limit])
    if out:
        parts = out[0].split()
        level = next((index for index, part in enumerate(parts) if part in LEVELS), None)
        if level is not None:
            plain = "-g" if parts[0].startswith(("ido", "custom:ido", "custom:mipspro")) else "-O0"
            for other in ("-O2", plain, "-O1"):
                variant = " ".join([*parts[:level], other, *parts[level + 1:]])
                if variant not in out and len(out) < limit:
                    out.append(variant)
    return out


MIN_SHARED = 8             # target functions a tree must give before it is taken as a donor of the title


def import_tree(source: Path, project: Path, out: Path, recipes: list[str], toolchain: str | None = None,
                name: str | None = None, jobs: int = 4, defines: list[str] | None = None,
                max_macros: int = 48, keep_work: bool = False, emit=None, by_function: bool = True) -> dict:
    """Describe ``source`` as a donor of the title surveyed in ``project``.  Writes
    ``out/donors.toml`` when the tree gives the title anything and returns the measurements."""
    import shutil
    from ..match import sourcedonor
    from ..match.toolchain import load_config
    source, out, project = Path(source).resolve(), Path(out).resolve(), Path(project).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cfg = load_config(out, None, toolchain or os.environ.get("N64DK_TOOLCHAIN"))
    tree = sourcedonor.Tree(source)
    name = name or "tree_" + "".join(ch if ch.isalnum() else "_" for ch in source.name)
    report = {"source": str(source), "name": name, "candidate_recipes": recipes, "units_in_tree": len(tree.units)}
    if not tree.units:
        return {**report, "donors": None, "reason": "no C file with a function body"}
    signatures = sourcedonor.target_signatures(project)
    if not signatures:
        return {**report, "donors": None, "reason": "the project has no surveyed functions to compare with"}
    work = out / name / "work"
    plan = sourcedonor.calibrate(tree, signatures, recipes, cfg, work, jobs=jobs, macros=defines or [],
                                 max_macros=max_macros, emit=emit)
    report.update(target_functions_compared=sum(len(places) for places in signatures.values()),
                  found_by_recipe=plan["found_by_recipe"], macros=plan["macros"],
                  include_directories=[str(path) for path in plan["includes"]],
                  macro_trials=[row for row in plan["macro_trials"] if row["with"] != row["without"]],
                  macros_not_measured=plan["macros_not_measured"][:40])
    donors = out / "donors.toml"
    donors.unlink(missing_ok=True)
    if max(plan["found_by_recipe"].values(), default=0) < MIN_SHARED:
        shutil.rmtree(out / name, ignore_errors=True)
        return {**report, "donors": None,
                "reason": f"fewer than {MIN_SHARED} functions of the title are found in this tree under any candidate recipe"}
    result = sourcedonor.build(tree, plan, out, name, cfg, signatures, by_function=by_function)
    if not keep_work:
        shutil.rmtree(work, ignore_errors=True)
    if result.get("toml"):
        donors.write_text("# Written by `n64dk source-donor`.  Every transplant is rebuilt and verified by the run "
                          "that receives it.\n\n" + result["toml"])
    result.pop("toml", None)
    return {**report, **result, "donors": str(donors) if donors.is_file() else None}


@command("source-donor", "Describe any C source tree as a donor for decompile-run --donors: its units, include "
                         "directories, each unit's recipe and its configuration macros are found by building and "
                         "comparing with the target, not read from its build files")
def source_donor(args):
    source = Path(args.source).resolve()
    if not source.is_dir():
        raise SystemExit(f"{source} is not a directory")
    recipes = list(dict.fromkeys([*(args.recipe or []), *(recipes_of_run(Path(args.run)) if args.run else [])]))
    if not recipes:
        raise SystemExit("no candidate recipe: name a finished run of the target (--run) or give --recipe")

    def emit(kind: str, **fields) -> None:
        print(json.dumps({"event": kind, **fields}, default=str), file=sys.stderr, flush=True)

    return import_tree(source, Path(args.project), Path(args.out), recipes, toolchain=args.toolchain_dir,
                       name=args.name, jobs=args.jobs, defines=args.define, max_macros=args.max_macros,
                       keep_work=args.keep_work, emit=emit, by_function=not args.whole_units)


def _args(p):
    p.add_argument("--source", required=True, help="the source tree (any layout)")
    p.add_argument("--project", required=True, help="surveyed project of the target title (its functions are what "
                                                    "the tree is compared with)")
    p.add_argument("--out", required=True, help="directory for the image, manifests and donors.toml")
    p.add_argument("--run", help="a finished decompile-run of the target: the recipes it matched under are the candidates")
    p.add_argument("--recipe", action="append", metavar="'PIPELINE FLAGS'",
                   help="a candidate recipe (repeatable), e.g. 'ido5.3 -O2 -mips2'")
    p.add_argument("--define", action="append", metavar="NAME",
                   help="a configuration macro to set without measuring it (repeatable)")
    p.add_argument("--max-macros", type=int, default=48, help="configuration macros measured, most used first")
    p.add_argument("--name", help="donor name (default: from the directory)")
    p.add_argument("--whole-units", action="store_true",
                   help="keep the tree's own units as the donor's units (a unit is then taken only when all of it "
                        "stands in the title, and its data comes with it); the default is one unit per function")
    p.add_argument("--keep-work", action="store_true", help="keep the objects of the calibration")
    p.add_argument("--toolchain-dir", help="toolchain root (default: N64DK_TOOLCHAIN)")
    p.add_argument("--jobs", type=int, default=4, help="compilers run at once")


source_donor.arguments = _args
