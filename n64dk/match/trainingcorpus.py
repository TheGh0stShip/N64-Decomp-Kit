"""Verified draft-to-source pairs from a title whose source tree was imported.

When a source tree gives a title strictly verified functions, each of them is a pair nobody had
before: what the kit drafts from the ROM alone, and C that the original compiler turns into the
same bytes.  The difference between the two is exactly what the drafting lacks.  This module
collects those pairs, keeps them reproducible, and runs controlled experiments on them.

A record (one JSON line in ``pairs.jsonl``) holds:

* identity: title (ROM SHA-1), image, address, size, SHA-256 of the target bytes, the tree's
  unit and function, the tree's provenance (commit, licence), the recipe (pipeline, flags) and
  the compiler's digest;
* the matching C (``sources/<sha256>.c``) and a normalised digest of it;
* what the ROM-only run did with the function (status, best score, recipe, its best source);
* drafts made now, from the ROM, under conditions (``plain``: the decompiler alone; ``context``:
  the decompiler with the tree's declarations and the names the donor stage proved) and whether
  each compiles and how many words differ from the target;
* features of the target (blocks, loops, calls, tables, floating point, loads and stores by
  width) and of the matching source and the drafts (field macros, array indexing, casts, loop
  forms, temporaries), so that the corrections can be counted by kind.

No target bytes and no disassembly are stored: only digests and counts.  The record is still
derived from a ROM; ``export`` writes a copy without the sources for sharing where the tree's
licence allows, and the local corpus is marked as such.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from collections import Counter
from pathlib import Path

FEATURE_PATTERNS = {
    "field_macros": re.compile(r"\bM2C_FIELD\s*\("),
    "array_index": re.compile(r"\w\s*\[[^\]]+\]"),
    "arrow": re.compile(r"->"),
    "casts": re.compile(r"\(\s*(?:unsigned\s+|signed\s+|const\s+|volatile\s+|struct\s+)*[A-Za-z_]\w*\s*\**\s*\)\s*[\w(*&]"),
    "for_loops": re.compile(r"\bfor\s*\("),
    "while_loops": re.compile(r"\bwhile\s*\("),
    "do_loops": re.compile(r"\bdo\s*\{"),
    "switches": re.compile(r"\bswitch\s*\("),
    "gotos": re.compile(r"\bgoto\b"),
    "temps": re.compile(r"\b(?:temp|var|sp|phi)_?\w*\b"),
    "struct_refs": re.compile(r"\bstruct\s+\w+"),
    "pointer_arith": re.compile(r"\(\s*\w+\s*\*\s*\)\s*\(\s*\(\s*[su]8\s*\*\s*\)"),
    "unsigned_types": re.compile(r"\bu(?:8|16|32|64)\b|\bunsigned\b"),
    "floats": re.compile(r"\bf(?:32|64)\b|\bfloat\b|\bdouble\b"),
}


def source_features(text: str) -> dict[str, int]:
    return {name: len(pattern.findall(text or "")) for name, pattern in FEATURE_PATTERNS.items()}


def normalised(text: str) -> str:
    """The C with comments and layout removed: two spellings that differ only in those are one."""
    text = re.sub(r"/\*.*?\*/|//[^\n]*", " ", text or "", flags=re.S)
    return re.sub(r"\s+", " ", text).strip()


def function_body(source: str, name: str) -> str:
    """The definition of ``name`` in ``source`` (from its name to its closing brace)."""
    found = re.search(rf"\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", source)
    if not found:
        return ""
    depth, start = 0, found.start()
    for index in range(found.end() - 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                line = source.rfind("\n", 0, start) + 1
                return source[line:index + 1]
    return source[start:]


def context_of(source: str, name: str) -> str:
    """The split file without the function's own body: every declaration the function needs."""
    body = function_body(source, name)
    return source.replace(body, "") if body else source


def target_features(code: bytes, vram: int) -> dict[str, int]:
    """Counts that describe the target's shape without holding any of its bytes."""
    import struct
    words = struct.unpack(f">{len(code) // 4}I", code[:len(code) // 4 * 4])
    ops = Counter(word >> 26 for word in words)
    branches = sum(1 for word in words if word >> 26 in (1, 4, 5, 6, 7, 20, 21, 22, 23) or (word >> 26 == 17 and (word >> 21) & 31 == 8))
    backward = 0
    for index, word in enumerate(words):
        if word >> 26 in (1, 4, 5, 6, 7, 20, 21, 22, 23):
            offset = word & 0xFFFF
            if offset & 0x8000:
                backward += 1
    return {"words": len(words), "calls": ops[3], "branches": branches, "backward_branches": backward,
            "jump_register": sum(1 for word in words if word >> 26 == 0 and word & 63 == 8 and word >> 21 & 31 != 31),
            "loads_byte": ops[32] + ops[36], "loads_half": ops[33] + ops[37], "loads_word": ops[35],
            "stores_byte": ops[40], "stores_half": ops[41], "stores_word": ops[43],
            "float_ops": ops[17] + ops[49] + ops[53] + ops[57] + ops[61], "lui": ops[15]}


# Bits a relocation fills in at link time, by relocation type (R_MIPS_32, _26, _HI16, _LO16,
# _GPREL16, _PC16, _GOT16, _CALL16)
_RELOCATED_BITS = {2: 0xFFFFFFFF, 4: 0x03FFFFFF, 5: 0xFFFF, 6: 0xFFFF, 7: 0xFFFF, 9: 0xFFFF, 10: 0xFFFF, 11: 0xFFFF}


def defined_functions(object_path: Path) -> list[str]:
    """Names of the sized functions an object defines in ``.text``."""
    from ..elf import Elf
    elf = Elf.load(object_path)
    return [sym.name for sym in elf.symbols if sym.name and sym.size and sym.type != 3 and 0 < sym.section < len(elf.sections)
            and elf.sections[sym.section].name == ".text"]


def masked_difference(object_path: Path, name: str, target: bytes, vram: int) -> tuple[int | None, int | None]:
    """(words that differ, words compared) between function ``name`` of an unlinked object and
    the linked target; (None, None) when the function is missing.  The object's own relocation
    entries say which bits the linker fills in: those bits are ignored, every other bit must be
    equal.  (A pattern-based mask missed %lo fields used through an indexed base register, so
    pairs that linked exactly were reported as not reproducing.)"""
    from ..elf import Elf
    from .transplant import strip_padding
    elf = Elf.load(object_path)
    text = next((section for section in elf.sections if section.name == ".text"), None)
    symbol = next((sym for sym in elf.symbols if sym.name == name and 0 < sym.section < len(elf.sections)
                   and elf.sections[sym.section].name == ".text"), None)
    if text is None or symbol is None:
        return None, None
    size = symbol.size or (len(text.data) - symbol.value)
    ours = strip_padding(text.data[symbol.value:symbol.value + size])
    theirs = strip_padding(target)
    ignore: dict[int, int] = {}
    for offset, kind, _symbol, _addend in elf.relocations(text):
        if symbol.value <= offset < symbol.value + size:
            index = (offset - symbol.value) // 4
            ignore[index] = ignore.get(index, 0) | _RELOCATED_BITS.get(kind, 0xFFFFFFFF)
    a = [int.from_bytes(ours[k:k + 4], "big") for k in range(0, len(ours) - len(ours) % 4, 4)]
    b = [int.from_bytes(theirs[k:k + 4], "big") for k in range(0, len(theirs) - len(theirs) % 4, 4)]
    differ = sum(1 for index, (x, y) in enumerate(zip(a, b)) if (x ^ y) & ~ignore.get(index, 0) & 0xFFFFFFFF)
    return differ + abs(len(a) - len(b)), max(len(a), len(b))


# a top-level function definition in a split file (cpp output: definitions start in column 0)
_DEFINITION = re.compile(r"(?m)^(?!typedef\b|struct\b|union\b|enum\b|extern\b)[A-Za-z_][\w \t\*]*?\b(\w+)\s*\([^;{}]*\)\s*\{")


def reproducing_functions(text: str, pipeline: str, flags: list[str], cfg, target: bytes, vram: int,
                          work: Path) -> list[str] | None:
    """The functions of ``text`` whose code is the target's (None when it does not build)."""
    from .pipeline import BuildError, build, split_flags
    work.mkdir(parents=True, exist_ok=True)
    source = work / "unit.c"
    source.write_text(text)
    try:
        built = build(source, split_flags(list(flags), pipeline), cfg, work / "object", includes=[])
    except (BuildError, OSError, RuntimeError, ValueError):
        return None
    return [name for name in defined_functions(built) if masked_difference(built, name, target, vram)[0] == 0]


def compile_and_compare(text: str, name: str, pipeline: str, flags: list[str], cfg, target: bytes, vram: int,
                        work: Path) -> dict:
    """Build ``text`` and compare function ``name`` with the target."""
    from .pipeline import BuildError, build, split_flags
    work.mkdir(parents=True, exist_ok=True)
    source = work / "unit.c"
    source.write_text(text)
    try:
        with tempfile.TemporaryDirectory(prefix="n64dk-pair-", dir=work) as scratch:
            built = build(source, split_flags(list(flags), pipeline), cfg, Path(scratch), includes=[])
            differ, total = masked_difference(built, name, target, vram)
    except (BuildError, OSError, RuntimeError, ValueError) as error:
        return {"compiles": False, "error": str(error)[-200:]}
    if differ is None:
        return {"compiles": True, "found": False}
    return {"compiles": True, "found": True, "differing_words": differ, "words": total, "text_equal": differ == 0}


def draft(name: str, code: bytes, vram: int, family: str, context: str | None, names: dict[int, str],
          work: Path, prepend: str | None = None) -> tuple[str | None, str | None]:
    """A decompiler draft of the target, as the resolve stage makes it (prepared to compile),
    optionally with ``context`` (declarations) given to the decompiler and put in front
    (``prepend`` instead, when what goes in front differs from the decompiler's context)."""
    from . import autodraft, m2c_bridge
    context_path = None
    if context:
        work.mkdir(parents=True, exist_ok=True)
        context_path = work / "context.h"
        context_path.write_text(context)
    result = m2c_bridge.draft(name, code, vram, "ido" if family == "ido" else "kmc", context_path, names)
    if result.get("source") is None:
        return None, f"{result.get('status')}: {result.get('error')}"
    text = autodraft.prepare(result["source"])
    if context:
        context = prepend if prepend is not None else context
        # the draft's own guesses for what the context declares make way for the real declarations
        kept = autodraft.drop_redeclared(text[len(autodraft.PRELUDE):], context).split("\n")
        # the basic typedefs the context defines itself leave the prelude (C89 rejects a typedef
        # given twice, even an identical one)
        prelude = autodraft.PRELUDE
        for typedef in set(re.findall(r"\btypedef\b[^;{}]*?\b(\w+)\s*;", context)):
            prelude = re.sub(rf"typedef [^;]*\b{re.escape(typedef)};", "", prelude)
        if prelude != autodraft.PRELUDE:
            # the context defines basic types the prelude's own declarations use: it goes first
            text = context + "\n" + prelude + "\n" + "\n".join(kept)
        else:
            text = prelude + "\n" + context + "\n" + "\n".join(kept)
    return text, None


def _case_index(run: Path) -> dict[tuple[str, int], dict]:
    """``{(image, address): case payload}`` of a finished ROM-only run (read without side files)."""
    from .resolve import CaseStore
    store = CaseStore(Path(run) / "state", readonly=True)
    try:
        out = {}
        for case in store.all():
            out[(case.image, case.vram)] = case.__dict__
        return out
    finally:
        store.close()


def build(project: Path, rom_only_run: Path | None, import_run: Path, donor_folder: Path, out: Path, cfg,
          conditions: tuple[str, ...] = ("plain", "context"), draft_sample: int | None = None,
          jobs: int = 2, emit=None) -> dict:
    """Collect every strict pair of one title.  Drafts are made, under ``conditions``
    (``plain``: the decompiler alone; ``context``: with the tree's declarations and the proved
    names), for every pair or, with ``draft_sample``, for an evenly spread sample of that many
    (deterministic: the same corpus is rebuilt the same way).  The output file is rewritten."""
    from concurrent.futures import ThreadPoolExecutor
    from . import images as imagemod, treeaccount
    from .pipeline import toolchain_digest
    emit = emit or (lambda *_a, **_k: None)
    project, out, donor_folder = Path(project), Path(out), Path(donor_folder)
    (out / "sources").mkdir(parents=True, exist_ok=True)
    account = treeaccount.account(project, import_run, donor_folder, donor_folder.name)
    recipes: dict[str, tuple[str, list[str]]] = {}
    for manifest in sorted(donor_folder.glob("manifest.*.tsv")):
        lines = manifest.read_text().splitlines()
        lane = lines[0].split("pipeline ", 1)[1].split(";")[0].strip()
        for line in lines[1:]:
            columns = line.split("\t")
            if len(columns) >= 4:
                recipes[columns[2]] = (lane, columns[3].split())
    provenance = {}
    if (donor_folder / "provenance.json").is_file():
        provenance = json.loads((donor_folder / "provenance.json").read_text()).get("tree", {})
    registry = imagemod.load_registry(project)
    names: dict[int, str] = {}
    for image in sorted(registry):
        report = Path(import_run) / image / "donors" / "report.json"
        if report.is_file():
            for row in json.loads(report.read_text()).get("rows", []):
                if row.get("verdict") == "exact-with-transferred-symbols":
                    for name, address in (row.get("transferred") or {}).items():
                        names.setdefault(int(address, 16), name)
    cases = _case_index(rom_only_run) if rom_only_run and (Path(rom_only_run) / "state" / "cases.sqlite").is_file() else {}
    specs = {name: imagemod.resolve(project, name) for name in registry}
    loaded = {name: (spec.load(), spec.delta) for name, spec in specs.items()}
    rom_sha1 = hashlib.sha1(Path(specs["main"].path).read_bytes()).hexdigest() if "main" in specs else None
    rows = [row for row in account["rows"] if row["cause"] == "strict" and row.get("unit")]
    recovered: dict[str, tuple[str, str]] = {}
    if "recovered" in conditions:
        # the kit's own whole-program recovery (structures, globals, prototypes) from the ROM,
        # exactly as the resolve stage builds it for each image
        import types as _types
        from ..commands.resolve import synthesize_context
        for image, spec in specs.items():
            data, delta = loaded[image]
            with tempfile.TemporaryDirectory(prefix="n64dk-context-") as scratch:
                _path, declarations, _info, rendered, _facts = synthesize_context(
                    _types.SimpleNamespace(rom=data, delta=delta), spec.rows(), names, Path(scratch), image)
            recovered[image] = (rendered.full(typedefs=True), declarations)
    drafted = set(range(len(rows)))
    if draft_sample and draft_sample < len(rows):
        step = len(rows) / draft_sample
        drafted = {int(k * step) for k in range(draft_sample)}
    tally = Counter()
    started = time.time()

    def one(number_row):
        number, row = number_row
        unit = row["unit"]
        split_source = donor_folder / "split" / unit
        if not split_source.is_file() or unit not in recipes:
            return None, ["source missing"]
        pipeline, flags = recipes[unit]
        label = Path(unit).stem
        data, delta = loaded[row["image"]]
        vram, size = int(row["vram"], 16), row["size"]
        code = data[vram - delta:vram - delta + size]
        matching = split_source.read_text()
        # A split file can hold several functions (a helper kept with its caller): the file name
        # then does not say which one the target is.  Build it and keep the one that reproduces.
        defined = set(_DEFINITION.findall(matching))
        if defined != {label}:
            with tempfile.TemporaryDirectory(prefix="n64dk-label-") as scratch:
                choice = reproducing_functions(matching, pipeline, flags, cfg, code, vram, Path(scratch))
            if choice is None:
                return None, ["label: the matching source does not build"]
            if len(choice) != 1:
                return None, [f"label: {len(choice)} functions of the matching source reproduce the target"]
            label = choice[0]
        digest = hashlib.sha256(matching.encode()).hexdigest()
        (out / "sources" / f"{digest}.c").write_text(matching)
        family = "ido" if pipeline.startswith(("ido", "custom:ido", "custom:mipspro")) else "gcc"
        record = {
            "title_sha1": rom_sha1, "image": row["image"], "vram": f"0x{vram:08X}", "size": size,
            "target_sha256": hashlib.sha256(code).hexdigest(), "tree_unit": str(Path(unit).parent) + ".c",
            "tree_function": label, "tree": {k: provenance.get(k) for k in ("remote", "commit", "source_digest")},
            "licence": [item.get("first_line") for item in provenance.get("licence_files", [])],
            "pipeline": pipeline, "flags": flags, "compiler_family": family,
            "toolchain_digest": toolchain_digest(cfg, pipeline),
            "source_sha256": digest, "source_normalised_sha256": hashlib.sha256(normalised(matching).encode()).hexdigest(),
            "target_features": target_features(code, vram),
            "source_features": source_features(function_body(matching, label)),
            "verdict": "strict", "local_only": True,
        }
        case = cases.get((row["image"], vram))
        if case:
            record["rom_only"] = {"status": case.get("status"), "best_score": case.get("best_score"),
                                  "recipe": case.get("recipe"), "builds": case.get("builds"),
                                  "causes": [c.get("cause") if isinstance(c, dict) else c
                                             for c in case.get("causes") or []][:6]}
        notes = []
        if number in drafted:
            record["drafts"] = {}
            work = out / "work" / f"{row['image']}_{vram:08X}"
            for condition in conditions:
                context, prepend = None, None
                if condition == "context":
                    context = context_of(matching, label)
                elif condition == "recovered":
                    context, prepend = recovered[row["image"]]
                text, error = draft(label, code, vram, family, context,
                                    names if condition in ("context", "recovered") else {}, work / condition, prepend)
                if text is None:
                    record["drafts"][condition] = {"drafted": False, "error": error}
                    notes.append(f"{condition}: no draft")
                    continue
                outcome = compile_and_compare(text, label, pipeline, flags, cfg, code, vram, work / condition)
                outcome["features"] = source_features(function_body(text, label))
                draft_digest = hashlib.sha256(text.encode()).hexdigest()
                (out / "sources" / f"{draft_digest}.c").write_text(text)
                outcome["source_sha256"] = draft_digest
                record["drafts"][condition] = {"drafted": True, **outcome}
                notes.append(f"{condition}: " + ("exact text" if outcome.get("text_equal") else
                                                 "compiles" if outcome.get("compiles") else "does not compile"))
            shutil.rmtree(work, ignore_errors=True)
        return record, notes

    written = 0
    with (out / "pairs.jsonl").open("w") as sink, ThreadPoolExecutor(max(1, jobs)) as pool:
        for number, (record, notes) in enumerate(pool.map(one, enumerate(rows))):
            tally.update(notes)
            if record is not None:
                sink.write(json.dumps(record, sort_keys=True) + "\n")
                written += 1
            if number % 100 == 0:
                emit("pairs", done=number, of=len(rows), seconds=round(time.time() - started))
    shutil.rmtree(out / "work", ignore_errors=True)
    return {"pairs": written, "candidates": len(rows), "drafted": len(drafted), "tally": dict(tally),
            "seconds": round(time.time() - started, 1), "account": account["causes"]}


def quarantined(corpus: Path) -> dict[tuple[str, str], dict]:
    """Pairs the audit could not reproduce, with their cause (``quarantine.jsonl``)."""
    path = Path(corpus) / "quarantine.jsonl"
    entries = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.is_file() else []
    return {(entry["image"], entry["vram"]): entry for entry in entries}


def load(corpus: Path, include_quarantined: bool = False) -> list[dict]:
    """The corpus's pairs; pairs the audit quarantined are left out unless asked for, so they
    never reach training or evaluation."""
    path = Path(corpus) / "pairs.jsonl"
    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.is_file() else []
    if include_quarantined:
        return records
    held = quarantined(corpus)
    if not held:
        return records
    return [record for record in records if (record.get("image"), record.get("vram")) not in held]


def audit(corpus: Path, project: Path, cfg, sample: int | None = None, repair: bool = False) -> dict:
    """Reproduce pairs: the target bytes must still have their digest, the compiler its digest,
    and the matching C, rebuilt now, the target's text.  Every failure gets a cause.  With
    ``repair``, a pair whose source reproduces the target under another of its functions is
    relabelled, and every other failure is quarantined (``quarantine.jsonl``) so it never reaches
    training or evaluation."""
    from . import images as imagemod
    from .pipeline import toolchain_digest
    records = load(corpus, include_quarantined=True)
    checked_records = records[::max(1, len(records) // sample)][:sample] if sample else records
    loaded = {}
    problems, checked = Counter(), 0
    failures, relabelled, quarantine = [], {}, []
    for record in checked_records:
        image = record["image"]
        if image not in loaded:
            spec = imagemod.resolve(Path(project), image)
            loaded[image] = (spec.load(), spec.delta)
        data, delta = loaded[image]
        vram = int(record["vram"], 16)
        code = data[vram - delta:vram - delta + record["size"]]
        why = None
        if hashlib.sha256(code).hexdigest() != record["target_sha256"]:
            why = "target bytes changed"
        elif toolchain_digest(cfg, record["pipeline"]) != record["toolchain_digest"]:
            why = "compiler changed"
        elif record.get("verdict") != "strict":
            why = "not a strict match"
        else:
            source = Path(corpus) / "sources" / f"{record['source_sha256']}.c"
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != record["source_sha256"]:
                why = "matching source missing or changed"
            else:
                with tempfile.TemporaryDirectory(prefix="n64dk-audit-") as work:
                    reproducing = reproducing_functions(source.read_text(), record["pipeline"], record["flags"],
                                                        cfg, code, vram, Path(work))
                if reproducing is None:
                    why = "the matching source no longer builds"
                elif record["tree_function"] in reproducing:
                    why = None
                elif len(reproducing) == 1:
                    why = "labelled with the wrong function of its source"
                    relabelled[(image, record["vram"])] = reproducing[0]
                elif reproducing:
                    why = "several functions of its source reproduce the target"
                else:
                    why = "no function of the matching source gives the target's text"
        checked += 1
        if why:
            problems[why] += 1
            failure = {"image": image, "vram": record["vram"], "function": record["tree_function"], "reason": why}
            if (image, record["vram"]) in relabelled:
                failure["reproduced_by"] = relabelled[(image, record["vram"])]
            failures.append(failure)
            if why != "labelled with the wrong function of its source":
                quarantine.append(failure)
    result = {"checked": checked, "reproduced": checked - sum(problems.values()), "problems": dict(problems),
              "failures": failures[:200]}
    if repair:
        if relabelled:
            out = []
            for record in records:
                key = (record["image"], record["vram"])
                if key in relabelled:
                    record = {**record, "tree_function": relabelled[key], "relabelled_from": record["tree_function"]}
                    record.pop("drafts", None)          # drafts were made under the wrong name
                out.append(record)
            temporary = Path(corpus) / "pairs.jsonl.tmp"
            temporary.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in out))
            os.replace(temporary, Path(corpus) / "pairs.jsonl")
        held = quarantined(corpus)
        for entry in quarantine:
            held[(entry["image"], entry["vram"])] = entry
        temporary = Path(corpus) / "quarantine.jsonl.tmp"
        temporary.write_text("".join(json.dumps(entry, sort_keys=True) + "\n" for entry in held.values()))
        os.replace(temporary, Path(corpus) / "quarantine.jsonl")
        result["relabelled"] = len(relabelled)
        result["quarantined"] = len(held)
    return result


def size_bucket(size: int) -> str:
    return "<=0x80" if size <= 0x80 else "<=0x200" if size <= 0x200 else "<=0x400" if size <= 0x400 else ">0x400"


def stats(records: list[dict]) -> dict:
    """Counts by title, compiler family, optimisation, size and draft outcome."""
    def level(record):
        flags = " ".join(record.get("flags", []))
        return "debug" if re.search(r"(^| )(-g\d?|-O0)( |$)", flags) else "optimised"
    out: dict = {"pairs": len(records)}
    for key, fn in (("by_title", lambda r: (r.get("title_sha1") or "?")[:12]), ("by_family", lambda r: r["compiler_family"]),
                    ("by_level", level), ("by_size", lambda r: size_bucket(r["size"])),
                    ("rom_only_status", lambda r: (r.get("rom_only") or {}).get("status", "absent"))):
        out[key] = dict(Counter(fn(record) for record in records).most_common())
    for condition in ("plain", "context", "recovered"):
        outcomes = Counter()
        for record in records:
            found = record.get("drafts", {}).get(condition)
            if found is None:
                continue
            outcomes["exact text" if found.get("text_equal") else "compiles" if found.get("compiles")
                     else "no draft" if not found.get("drafted") else "does not compile"] += 1
        out[f"draft_{condition}"] = dict(outcomes)
    return out


def export(corpus: Path, destination: Path) -> dict:
    """A copy for sharing: records without sources (they are the tree's, under its licence) and
    without anything flagged local; the target is named by digest only."""
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    kept = 0
    with (destination / "pairs.jsonl").open("w") as sink:
        for record in load(corpus):
            shared = {k: v for k, v in record.items() if k not in ("local_only",)}
            shared["sources_withheld"] = True
            sink.write(json.dumps(shared, sort_keys=True) + "\n")
            kept += 1
    return {"pairs": kept, "destination": str(destination)}


def compare_conditions(records: list[dict], first: str = "plain", second: str = "context") -> dict:
    """Paired comparison of two drafting conditions on the same pairs, by compiler family: how
    often each compiles, gives the exact text, and which is closer to the target."""
    def outcome(found):
        if not found or not found.get("drafted"):
            return "no draft", None
        if not found.get("compiles"):
            return "does not compile", None
        if not found.get("found"):
            return "function missing", None
        return ("exact text" if found.get("text_equal") else "compiles"), found.get("differing_words")

    out = {}
    for family in sorted({record["compiler_family"] for record in records}) + ["all"]:
        rows = [record for record in records if (family == "all" or record["compiler_family"] == family)
                and first in record.get("drafts", {}) and second in record.get("drafts", {})]
        table = {first: Counter(), second: Counter()}
        better = worse = same = 0
        words = {first: [], second: []}
        for record in rows:
            a, da = outcome(record["drafts"][first])
            b, db = outcome(record["drafts"][second])
            table[first][a] += 1
            table[second][b] += 1
            if da is not None and db is not None:
                words[first].append(da)
                words[second].append(db)
                better += db < da
                worse += db > da
                same += db == da
        median = lambda values: sorted(values)[len(values) // 2] if values else None     # noqa: E731
        out[family] = {"pairs": len(rows), first: dict(table[first]), second: dict(table[second]),
                       "both_compile": len(words[first]), f"{second}_closer": better, f"{second}_further": worse,
                       "equal": same, f"median_words_{first}": median(words[first]),
                       f"median_words_{second}": median(words[second])}
    return out
