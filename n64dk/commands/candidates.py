"""``candidate-reconcile``: what an untracked source would add, before anyone counts it.

An exact standalone source is not progress when its bytes already belong to an exact aggregate
unit.  This command answers, for each candidate source, the questions that otherwise take a
temporary manifest, a batch per image and an interval calculation by hand:

* which catalogued function it defines;
* who owns that interval today (the inventory, which places manifest rows with the declared
  image placement, as the matcher does);
* optionally (``--recompile``) whether it builds to the target under the project's recipe;
* what it would add: a new function, a duplicate of an aggregate member, a duplicate of a
  standalone unit, or a C replacement for assembly.

Counts of exact compilations and of new coverage are reported separately, always.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..cli import command

_DEFINITION = re.compile(r"(?m)^[A-Za-z_][\w \t\*]*?\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{")
OWNED_C = {"manifest_exact_unit", "manifest_exact_member", "manifest_nonexact"}
OWNED_ASM = {"assembly_unit", "assembly_member"}


def defined_functions(text: str) -> list[str]:
    """Names of the functions a C source defines (definitions with a body, not prototypes)."""
    return [name for name in _DEFINITION.findall(text) if name not in ("if", "while", "for", "switch")]


def classify(source: str, names: list[str], rows_by_name: dict[str, list[dict]], owners: dict[str, tuple[int, int]],
             image: str | None = None) -> dict:
    """Ownership classification of one candidate source (no compilation)."""
    hits = [row for name in names for row in rows_by_name.get(name, []) if image in (None, row["image"])]
    if not hits:
        return {"source": source, "classification": "source_missing" if not names else "not_in_catalogue",
                "functions": names}
    if len({(row["image"], row["vram"]) for row in hits}) > 1 and len(names) == 1:
        return {"source": source, "classification": "mapping_conflict", "function": names[0],
                "candidates": [f"{row['image']}:{row['vram']}" for row in hits]}
    row = hits[0]
    start, size = int(row["vram"], 0), int(row["size"])
    out = {"source": source, "function": row["name"], "image": row["image"], "vram": row["vram"], "size": size,
           "interval": f"0x{start:08X}-0x{start + size:08X}", "owner": row.get("owner"),
           "ownership_state": row.get("ownership_state"), "new_function_credit": 0, "new_c_byte_credit": 0}
    state = row.get("ownership_state")
    owner = row.get("owner")
    if state == "fragment":
        out["classification"] = "fragment"
    elif state in OWNED_C and owner and Path(owner).as_posix() != Path(source).as_posix():
        low, high = owners.get((row["image"], owner), (start, start + size))
        out["owner_interval"] = f"0x{low:08X}-0x{high:08X}"
        aggregate = (low, high) != (start, start + size)
        out["classification"] = "existing_aggregate_member" if aggregate else "existing_standalone_duplicate"
        out["recommended"] = ("retain the aggregate owner; the candidate is a duplicate split" if aggregate
                              else "the interval already has a C owner")
    elif state in OWNED_C:
        out["classification"] = "already_owned_by_this_source"
    elif state in OWNED_ASM:
        out["classification"] = "assembly_to_c_conversion"
        out["new_function_credit"], out["new_c_byte_credit"] = 1, size
    elif state in ("duplicate_owner", "boundary_conflict"):
        out["classification"] = "mapping_conflict"
    else:
        out["classification"] = "new_function"
        out["new_function_credit"], out["new_c_byte_credit"] = 1, size
    return out


def reconcile(project: Path, sources: list[str], image: str | None = None) -> list[dict]:
    from ..match import inventory
    built = inventory.build(project)
    rows_by_name: dict[str, list[dict]] = {}
    owners: dict[tuple[str, str], tuple[int, int]] = {}
    for row in built["functions"]:
        rows_by_name.setdefault(row["name"], []).append(row)
        if row.get("owner"):
            start = int(row["vram"], 0)
            low, high = owners.get((row["image"], row["owner"]), (start, start + int(row["size"])))
            owners[(row["image"], row["owner"])] = (min(low, start), max(high, start + int(row["size"])))
    out = []
    for source in sources:
        path = project / source
        if not path.is_file():
            out.append({"source": source, "classification": "source_missing", "functions": []})
            continue
        names = defined_functions(path.read_text(errors="replace"))
        stem = re.sub(r"_[0-9a-fA-F]{8}$", "", path.stem)
        names = names or [path.stem, stem]
        out.append(classify(source, names, rows_by_name, owners, image))
    return out


def _untracked(project: Path) -> list[str]:
    done = subprocess.run(["git", "-C", str(project), "ls-files", "--others", "--exclude-standard", "--", "*.c"],
                          capture_output=True, text=True, timeout=60)
    if done.returncode != 0:
        raise SystemExit("candidate-reconcile: --sources-untracked needs a git work tree: " + done.stderr.strip()[-200:])
    return [line for line in done.stdout.splitlines() if line and not line.startswith((".tmp/", ".n64dk/", "build/"))]


def _recompile(project: Path, row: dict, pipeline: str, flags: str, timeout: float) -> dict:
    argv = [sys.executable, "-m", "n64dk", "--format", "json", "match", row["source"], "--project", str(project),
            "--image-name", row["image"], "--addr", row["vram"], "--size", hex(row["size"]), "--pipeline", pipeline,
            f"--flags={flags}"]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd=project,
                              env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[2])})
        data = json.loads(done.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as error:
        return {"outcome": "compile_failed", "error": str(error)[-200:]}
    verdict = (data.get("proof") or {}).get("verdict")
    if data.get("error"):
        return {"outcome": "compile_failed", "error": str(data["error"])[-200:]}
    if data.get("exact"):
        return {"outcome": "exact", "verdict": verdict}
    if data.get("exploratory_exact"):
        return {"outcome": "assumed", "verdict": verdict}
    return {"outcome": "mismatch", "score": (data.get("diff") or {}).get("score")}


@command("candidate-reconcile", "Classify candidate sources against current ownership: new coverage, aggregate "
         "duplicate, standalone duplicate, assembly conversion, fragment or conflict")
def candidate_reconcile(args):
    project = Path(args.project).resolve()
    sources = list(args.source) + (_untracked(project) if args.sources_untracked else [])
    if not sources:
        raise SystemExit("candidate-reconcile: name sources or pass --sources-untracked")
    rows = reconcile(project, sources, args.image_name)
    if args.recompile:
        config = tomllib.loads((project / "n64dk.toml").read_text()).get("run", {}) if (project / "n64dk.toml").is_file() else {}
        pipeline, flags = args.pipeline or config.get("pipeline"), args.flags or config.get("flags", "")
        if not pipeline:
            raise SystemExit("candidate-reconcile: --recompile needs --pipeline or [run] pipeline")
        todo = [row for row in rows if "vram" in row and row["classification"] not in ("fragment", "mapping_conflict")]
        with ThreadPoolExecutor(max(1, args.jobs)) as pool:
            for row, built in zip(todo, pool.map(lambda r: _recompile(project, r, pipeline, flags, args.timeout), todo)):
                row["compile"] = built
    exact = [row for row in rows if (row.get("compile") or {}).get("outcome") == "exact"]
    creditable = [row for row in (exact if args.recompile else rows) if row.get("new_function_credit")]
    summary = {
        "candidates": len(rows), "classifications": dict(Counter(row["classification"] for row in rows)),
        "compiled_exact": len(exact) if args.recompile else None,
        "null_reason": None if args.recompile else "not compiled: pass --recompile to establish exactness",
        "new_exact_functions": len(creditable) if args.recompile else None,
        "new_exact_bytes": sum(row["new_c_byte_credit"] for row in creditable) if args.recompile else None,
        "would_be_new_if_exact": sum(1 for row in rows if row.get("new_function_credit")),
        "aggregate_duplicates": sum(1 for row in rows if row["classification"] == "existing_aggregate_member"),
    }
    return {"schema_version": 1, "summary": summary, "candidates": rows}


def _args(p):
    p.add_argument("source", nargs="*", help="candidate C sources, relative to the project")
    p.add_argument("--project", default=".")
    p.add_argument("--sources-untracked", action="store_true", help="every untracked .c file git reports")
    p.add_argument("--image-name", help="restrict to one logical image")
    p.add_argument("--recompile", action="store_true", help="build each candidate and verify it strictly")
    p.add_argument("--pipeline", help="recipe for --recompile (default: [run] pipeline)")
    p.add_argument("--flags", help="flags for --recompile (default: [run] flags)")
    p.add_argument("--jobs", type=int, default=8)
    p.add_argument("--timeout", type=float, default=300.0)


candidate_reconcile.arguments = _args
