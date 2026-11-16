"""``decompile-export``: a finished run as a tree that can be committed as a decompilation repository."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from ..cli import command

MATCHED = ("donor", "donor-awaiting-symbols", "donor-assembly",
           "donor-assembly-awaiting-symbols", "exact", "awaiting-symbols", "assembly")
_TEXT = (".c", ".h", ".s", ".tsv", ".txt", ".toml", ".md", ".json", ".inc")


_HOME = re.compile(r"(?:/home/|/Users/|/mnt/[a-z]/Users/|[A-Za-z]:\\\\Users\\\\)[^/\\\\\"'\s]+")


def _scrub(text: str, replacements: list[tuple[str, str]]) -> str:
    """Paths of the machine the run was made on say nothing about the title and name its user."""
    for old, new in replacements:
        text = text.replace(old, new)
    return _HOME.sub("<home>", text)


def _copy(source: Path, target: Path, replacements) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.suffix.lower() in _TEXT:
        target.write_text(_scrub(source.read_text(errors="replace"), replacements))
    else:
        shutil.copyfile(source, target)


def _origin(case) -> str:
    """How a case was matched, from its own record."""
    kinds = [stage.get("stage") for stage in case.stages]
    if "refine" in kinds:
        return "external author, strictly verified"
    if "twin" in kinds:
        return "source of an identical function"
    if any(stage.get("stage") in ("region-recipe", "unit-recipe") and stage.get("kept") for stage in case.stages):
        return "draft, recipe of its region"
    iterate = [stage for stage in case.stages if stage.get("stage") == "iterate"]
    if iterate and iterate[-1].get("final") == 0 and iterate[-1].get("start", 0) > 0:
        return "draft after variant search"
    return "draft"


def _donor_roots(run: Path) -> dict[str, str]:
    """Donor name -> its source root, from the index the run built."""
    try:
        return {name: str(entry.get("root") or "") for name, entry in
                (json.loads((run / "donor_index.json").read_text()).get("donors") or {}).items()}
    except (OSError, ValueError):
        return {}


def rom_coverage(ledger: Path, rom_size: int | None) -> dict | None:
    """What the survey's ledger says about every byte of the ROM: bytes per class, whether its
    rows cover the ROM from the first byte to the last without gap or overlap, and the ranges
    it could not classify (largest first)."""
    import csv
    if not ledger.is_file():
        return None
    rows = []
    with ledger.open() as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            try:
                rows.append((int(row["start"], 16), int(row["end"], 16), row.get("class") or "?", row.get("kind") or "",
                             row.get("name") or "", row.get("evidence") or ""))
            except (KeyError, ValueError):
                continue
    rows.sort()
    classes: dict[str, int] = {}
    gaps = overlaps = position = 0
    for start, end, kind, *_rest in rows:
        gaps += max(0, start - position)
        overlaps += max(0, min(end, position) - start)
        classes[kind] = classes.get(kind, 0) + (end - start)
        position = max(position, end)
    size = rom_size if rom_size is not None else position
    gaps += max(0, size - position)
    unknown = sorted(((end - start, start, end, evidence) for start, end, kind, _k, _n, evidence in rows if kind == "unknown"),
                     reverse=True)
    return {"rom_bytes": size, "rows": len(rows), "gap_bytes": gaps, "overlap_bytes": overlaps,
            "bytes_by_class": dict(sorted(classes.items(), key=lambda item: -item[1])),
            "unclassified_ranges": len(unknown),
            "largest_unclassified": [{"start": f"0x{start:X}", "end": f"0x{end:X}", "bytes": length, "evidence": evidence[:160]}
                                     for length, start, end, evidence in unknown[:12]]}


def _disassemble(pending: list, out: Path, project: Path, toolchain, jobs: int = 4) -> dict[tuple[str, int], str]:
    """Assembly source for functions no C reproduces, each proved by assembling it again.

    ``pending`` is ``[(image, function, vram, code, image bytes, delta)]``.  Returns the path of
    the file written for every function whose assembly gives back its bytes."""
    from concurrent.futures import ThreadPoolExecutor
    from ..match import handasm, m2c_bridge
    from ..match import symbols as symmod
    from ..match.toolchain import load_config
    cfg = load_config(project, None, toolchain)
    files = sorted((project / "survey").glob("symbol_addrs*.txt")) + [project / "survey" / "sdk_symbols.txt"]
    try:
        import tomllib
        settings = tomllib.loads((project / "n64dk.toml").read_text()).get("run") or {}
        files += [project / name for name in settings.get("symbols", [])]
    except (OSError, ValueError):
        pass
    try:
        names = {address: name for name, address in symmod.load([f for f in files if f.is_file()]).items()}
    except Exception:                                        # noqa: BLE001 - names are a convenience here
        names = {}

    def one(item):
        image, function, vram, code, data, delta = item
        try:
            tables = m2c_bridge.find_jump_tables(data, delta, vram, len(code))
        except Exception:                                    # noqa: BLE001
            tables = []
        kept = handasm.attempt(function, code, vram, cfg, names, tables)
        if kept is None:
            return (image, vram), None
        path = f"asm_not_decompiled/{image}/{function}.s"
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(kept[0])
        return (image, vram), path

    with ThreadPoolExecutor(max(1, jobs)) as pool:
        return {key: path for key, path in pool.map(one, pending) if path}


def export(project: Path, run: Path, out: Path, title: str | None = None, cover: bool = True,
           toolchain=None) -> dict:
    """Write the export tree and return its counts.  Nothing of the ROM is copied: sources,
    symbol files, recipes and the function table only.

    With ``cover`` every function no C reproduces also gets assembly source that assembles to its
    bytes (``asm_not_decompiled/``), so that each function of the title has a source, and the
    table says which kind: decompiled, hand-written, or only disassembled."""
    from ..match import images as imagemod
    from ..match import resolve as resolvemod
    project, run, out = Path(project).resolve(), Path(run).resolve(), Path(out).resolve()
    replacements = sorted({(str(run), "<run>"), (str(project), "<project>"), (str(Path.home()), "<home>")},
                          key=lambda pair: -len(pair[0]))
    registry = imagemod.load_registry(project)
    store = resolvemod.CaseStore(run / "state")
    try:
        cases = {(case.image, case.vram): case for case in store.all()}
        sources = {key: store.source(case.best_digest) for key, case in cases.items()
                   if case.status in ("exact", "assumed", "assembly") and case.best_digest}
    finally:
        store.close()
    out.mkdir(parents=True, exist_ok=True)
    rows, counts, pending = [], {}, []
    rom_sha1, rom_name, rom_size = None, None, None
    for name in sorted(registry):
        spec = imagemod.resolve(project, name)
        data, delta = spec.load(), spec.delta
        if name == "main" or rom_sha1 is None:
            rom = Path(spec.path)
            if rom.is_file() and rom.suffix.lower() in (".z64", ".n64", ".v64", ".rom"):
                blob = rom.read_bytes()
                rom_sha1, rom_size = hashlib.sha1(blob).hexdigest(), len(blob)
                rom_name = blob[0x20:0x34].decode("ascii", "replace").strip()
        donated: dict[int, tuple[str, str, str, str]] = {}
        stage = run / name / "stage_donors.json"
        if stage.is_file():
            held = json.loads(stage.read_text())
            for kind, key in (("donor", "verified"), ("donor-awaiting-symbols", "assumed")):
                for row in held.get(key, []):
                    for vram in row.get("function_vrams") or []:
                        unit = str(row.get("unit"))
                        if unit.startswith("/"):              # generated text kept outside the donor's root:
                            unit = "/".join(Path(unit).parts[-2:])   # filed by its last two components
                        source_kind = row.get("source_kind") or (
                            "assembly" if Path(unit).suffix.lower() in (".s", ".asm") else "c")
                        outcome = ("donor-assembly" if kind == "donor" else
                                   "donor-assembly-awaiting-symbols") if source_kind == "assembly" else kind
                        donated.setdefault(int(vram), (outcome, str(row.get("donor")), unit, source_kind))
        for function, vram, size in spec.rows():
            case = cases.get((name, vram))
            outcome, how, path, score, code_size = "not attempted", "", "", "", size
            if vram in donated:
                outcome, donor, unit, _source_kind = donated[vram]
                how = f"donor unit {donor}: {unit}"
                path = f"donors/{name}/src/{donor}/{unit}" if not unit.startswith(("<", "/")) else f"donors/{name}/"
            elif case is not None:
                outcome = {"assumed": "awaiting-symbols"}.get(case.status, case.status)
                how, code_size = case.recipe, case.size       # the catalogue's span may end in alignment padding
                score = "" if case.best_score is None else str(case.best_score)
                text = sources.get((name, vram))
                if text is not None:
                    folder = {"exact": "src", "awaiting-symbols": "src_awaiting_symbols", "assembly": "asm"}[outcome]
                    path = f"{folder}/{name}/{function}.{'s' if outcome == 'assembly' else 'c'}"
                    target = out / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(text)
                    how = f"{case.recipe} ({_origin(case)})" if outcome != "assembly" else case.recipe
                elif outcome in ("exact", "awaiting-symbols", "assembly"):
                    outcome = "matched-source-missing"
            counts[outcome] = counts.get(outcome, 0) + 1
            if outcome not in MATCHED and cover:
                span = data[vram - delta:vram - delta + size]
                if len(span) == size and size:
                    pending.append((name, function, vram, span, data, delta))
            rows.append([name, function, f"0x{vram:08X}", f"0x{vram - delta:X}", f"0x{size:X}", f"0x{code_size:X}",
                         outcome, how, path, score])
        # donor units as the donor stage wrote them (sources, the manifests it proposes, symbols)
        donors = run / name / "donors"
        if donors.is_dir():
            for item in sorted(donors.rglob("*")):
                if item.is_file() and item.name != "report.json":
                    _copy(item, out / "donors" / name / item.relative_to(donors), replacements)
        # a run made before sources of awaiting units were kept: fetch them from the donor itself
        missing = {(donor, unit) for kind, donor, unit, _source_kind in donated.values()
                   if not unit.startswith(("<", "/")) and not (out / "donors" / name / "src" / donor / unit).is_file()}
        if missing:
            roots = _donor_roots(run)
            for donor, unit in sorted(missing):
                source = Path(roots.get(donor, "")) / unit
                if roots.get(donor) and source.is_file():
                    _copy(source, out / "donors" / name / "src" / donor / unit, replacements)
        declared = run / name / "declared_symbols.txt"
        if declared.is_file():
            _copy(declared, out / "symbols" / f"declared_{name}.txt", replacements)
    disassembled = _disassemble(pending, out, project, toolchain) if pending else {}
    reproduced = {"C": 0, "assembly (donor source)": 0, "assembly (hand-written)": 0,
                  "assembly (not decompiled)": 0, "nothing": 0}
    for row in rows:
        if row[6].startswith("donor-assembly"):
            kind = "assembly (donor source)"
        elif row[6] == "assembly":
            kind = "assembly (hand-written)"
        elif row[6] in MATCHED:
            kind = "C"
        else:
            found = disassembled.get((row[0], int(row[2], 16)))
            kind = "assembly (not decompiled)" if found else "nothing"
            if found:
                row[8] = found
        reproduced[kind] += 1
        row.append(kind)
    header = "image\tfunction\tvram\trom_offset\tsize\tcode_size\toutcome\thow\tsource\tdistance\treproduced_by\n"
    (out / "FUNCTIONS.tsv").write_text(header + "".join("\t".join(row) + "\n" for row in rows))
    (out / "MATCHED.tsv").write_text(header + "".join("\t".join(row) + "\n" for row in rows if row[6] in MATCHED))
    for item in sorted((run / "queue").glob("*")) if (run / "queue").is_dir() else []:
        if item.is_file():
            _copy(item, out / "manifests" / item.name, replacements)
    survey = project / "survey"
    for item in sorted(survey.glob("*")) if survey.is_dir() else []:
        if item.is_file() and item.suffix in (".txt", ".toml", ".json", ".tsv", ".md"):
            folder = "symbols" if item.name.startswith(("symbol_addrs", "sdk_symbols")) else "config"
            _copy(item, out / folder / item.name, replacements)
    if (project / "n64dk.toml").is_file():
        _copy(project / "n64dk.toml", out / "config" / "n64dk.toml", replacements)
    for item in ("report.md", "report.json"):
        if (run / item).is_file():
            _copy(run / item, out / "report" / item, replacements)
    total = len(rows)
    matched = sum(counts.get(key, 0) for key in MATCHED)
    from_c = matched - counts.get("assembly", 0) - counts.get("donor-assembly", 0) - \
        counts.get("donor-assembly-awaiting-symbols", 0)
    name = title or rom_name or project.name
    order = [*MATCHED, *sorted(key for key in counts if key not in MATCHED)]
    readme = [f"# {name}", "",
              "Functions of this title that an unattended `n64dk decompile-run` reproduced byte for byte, from the ROM",
              "alone.  Nothing of the ROM is in this tree: sources, symbol files, build recipes and the function table.", "",
              f"- ROM header name: `{rom_name}`", f"- ROM SHA-1: `{rom_sha1}`", f"- ROM size: {rom_size} bytes",
              f"- Functions found: {total:,}",
              f"- Matched from C: {from_c:,} ({from_c / total:.1%})" if total else "- Matched from C: 0",
              f"- Hand-written code kept as assembly: {counts.get('assembly', 0):,}",
              f"- Verified donor assembly (not counted as C): "
              f"{counts.get('donor-assembly', 0) + counts.get('donor-assembly-awaiting-symbols', 0):,}",
              f"- Not decompiled, covered by assembly that assembles to the same bytes: "
              f"{reproduced['assembly (not decompiled)']:,}",
              f"- Functions with no source that reproduces them: {reproduced['nothing']:,}", "",
              "| outcome | functions | meaning |", "|---|---:|---|"]
    meaning = {"donor": "a unit of an already decompiled library or title, rebuilt for this image and compared (strict)",
               "donor-awaiting-symbols": "such a unit, byte-identical, leaning on an address nothing independent confirms",
               "donor-assembly": "assembly from a donor, rebuilt and strictly compared; not counted as C",
               "donor-assembly-awaiting-symbols": "donor assembly with identical bytes but an unconfirmed address",
               "exact": "C source accepted by the strict verifier: bytes and every relocation",
               "awaiting-symbols": "C source that is byte-identical and leans on an undeclared address",
               "assembly": "hand-written code: assembly source that assembles to the same bytes",
               "near": "best draft within ten differences", "open": "best draft further away",
               "does-not-build": "no draft compiles", "blocked-boundary": "the catalogued range is not one whole function",
               "not attempted": "outside the size limit of the run, or the run was cut short"}
    for key in order:
        if counts.get(key):
            readme.append(f"| {key} | {counts[key]:,} | {meaning.get(key, '')} |")
    readme += ["", "## Layout", "",
               "- `FUNCTIONS.tsv`: every function with its address, size, outcome, recipe and source file.  `size` is",
               "  the catalogue's span (it may end in alignment padding); `code_size` is what the source reproduces.",
               "- `MATCHED.tsv`: the matched ones only.",
               "- `src/<image>/<function>.c`: strictly exact functions, one per file, as they were verified.",
               "- `src_awaiting_symbols/`: byte-identical functions that wait for a symbol to be declared",
               "  (`manifests/symbols.assumed.txt` lists the declarations).",
               "- `asm/<image>/<function>.s`: hand-written routines.",
               "- `asm_not_decompiled/<image>/<function>.s`: every function no C reproduces yet, as assembly that",
               "  assembles to its bytes.  It is a disassembly, not a decompilation, and is counted apart.",
               "- `config/ledger.tsv`: every byte of the ROM, from the first to the last, with what it is.",
               "- `donors/<image>/`: library and shared units the donor stage verified: their sources, the manifest rows",
               "  it proposes (`proposed_*.tsv`), the symbols it transferred, and what still awaits symbols.",
               "- `manifests/`: recipe of every exported function (`queue.tsv` exact, `assumed.tsv`, `assembly.tsv`).",
               "- `symbols/`, `config/`: symbol files, the function catalogue, the project configuration, the ROM layout.",
               "- `report/`: the run's own report.", "",
               "Each source is a single function with the declarations the decompiler needed; names are addresses",
               "(`func_80012345`, `D_80123456`) unless a library signature named them.  Sources under `donors/` come",
               "from other projects (the SDK library source, other decompiled titles) and keep those projects' terms.", "",
               "## Checking a function", "",
               "```sh", "n64dk decompile-init ROM.z64 --out project",
               "n64dk match --project project --addr VRAM --size SIZE --pipeline PIPELINE --flags=\"FLAGS\" src/main/FUNCTION.c",
               "```", "", "with `VRAM`, `SIZE` (the row's `code_size`), pipeline and flags taken from the function's row in `FUNCTIONS.tsv`.", ""]
    coverage = rom_coverage(project / "survey" / "ledger.tsv", rom_size)
    lines = [f"# Coverage: {name}", "", "## Functions", "",
             "| reproduced by | functions |", "|---|---:|",
             *[f"| {kind} | {count:,} |" for kind, count in reproduced.items()],
             f"| **all** | **{total:,}** |", "",
             "Every function has a source that gives back its bytes when the last row is 0.  Only the first row is",
             "decompilation; the third is disassembly kept so that nothing is left out.", ""]
    if coverage:
        size = coverage["rom_bytes"] or 1
        lines += ["## Every byte of the ROM", "",
                  f"The survey's ledger (`config/ledger.tsv`) has {coverage['rows']:,} rows.  Bytes no row covers: "
                  f"{coverage['gap_bytes']:,}.  Bytes two rows claim: {coverage['overlap_bytes']:,}.", "",
                  "| class | bytes | share |", "|---|---:|---:|",
                  *[f"| {kind} | {count:,} | {count / size:.1%} |" for kind, count in coverage["bytes_by_class"].items()], ""]
        if coverage["largest_unclassified"]:
            lines += [f"`unknown` is content the survey has a row for and could not identify ({coverage['unclassified_ranges']:,} "
                      "ranges).  The largest, with what was measured about each:", "",
                      "| ROM range | bytes | measured |", "|---|---:|---|",
                      *[f"| {row['start']}..{row['end']} | {row['bytes']:,} | {row['evidence']} |"
                        for row in coverage["largest_unclassified"]], ""]
    (out / "COVERAGE.md").write_text("\n".join(lines))
    (out / "README.md").write_text("\n".join(readme))
    return {"title": name, "rom_sha1": rom_sha1, "functions": total, "matched": matched, "from_c": from_c,
            "reproduced_by": reproduced, "rom": coverage and {k: coverage[k] for k in (
                "rom_bytes", "rows", "gap_bytes", "overlap_bytes", "bytes_by_class", "unclassified_ranges")},
            "counts": {key: counts[key] for key in order if counts.get(key)}, "out": str(out)}


@command("decompile-export", "Write a finished decompile-run as a tree ready to commit: one source per matched "
                             "function, the function table, recipes and symbols (nothing of the ROM)")
def decompile_export(args):
    import os
    return export(Path(args.project), Path(args.run), Path(args.out), args.title, cover=not args.no_cover,
                  toolchain=args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN"))


def _args(p):
    p.add_argument("--project", required=True, help="the project the run was made on")
    p.add_argument("--run", required=True, help="the run's output directory (holds state/, queue/, report.json)")
    p.add_argument("--out", required=True, help="directory to write (created; existing files are overwritten)")
    p.add_argument("--title", help="title for the README (default: the ROM's header name)")
    p.add_argument("--no-cover", action="store_true",
                   help="do not write assembly for the functions that are not decompiled")
    p.add_argument("--toolchain-dir", help="toolchain root, for the assembler (default: N64DK_TOOLCHAIN)")


decompile_export.arguments = _args
