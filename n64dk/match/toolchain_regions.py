"""Regional toolchain reconstruction: which tool chain built which stretch of an image, component
by component, with the uncertainty kept and abstention when nothing known explains a stretch.

A title is several build regimes laid out one after another by the linker: game code at one
level, libraries at another, a second compiler, an assembler that expands macros its own way,
hand-written routines.  One recipe per title (global calibration) is the wrong model; one recipe
per function from one function's evidence is too little evidence (round 10: one function
identifies a recipe in 7-9 of 80 held-out cases).  This module judges stretches of neighbouring
functions together:

* **regions**: ``idioms.stretches`` (the marks table's ranking over a window of neighbours),
  merged until every region has enough functions to stand on;
* **ranked recipe classes** per region with their posterior shares (never a single answer when
  the evidence does not give one);
* **components**: the region's rates of the marks that belong to one component of a tool chain
  (assembler macro expansion, ``$at`` policy, scheduler, register allocator, ISA, small-data
  threshold, optimisation level, division checks), against the best class's usual rates; a mark
  the region shows often and the class all but never does names the component that differs;
* **proof**: the recipes strictly exact functions of the region were built with, when a run's
  case store is given;
* **verdict**: ``known`` (one class holds most of the posterior and the region's marks fit it),
  ``uncertain`` (several classes share it), ``mismatch`` (the best class differs in a named
  component), ``unknown`` (no class of the table fits: ``idioms.unknown_stretches``), or
  ``assembly`` (mostly hand-written);
* a **dossier** for every region that is not ``known``: the component rates, the marks that rule
  the classes out, the instruction-kind histogram, the commonest instruction pairs and the
  smallest functions' disassembly, for compiler archaeology later.

Nothing here builds anything.  The ranking orders and gates work; the compiler and the strict
verifier still decide every match."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from . import idioms

MIN_REGION = 16          # functions a region needs; shorter stretches join a neighbour
KNOWN_SHARE = 0.8        # posterior share of the best class for a region to count as known
MISMATCH_RATE = 0.2      # a region showing a mark this often ...
CLASS_NEVER = 0.02       # ... that its best class shows this seldom: a component mismatch
DOSSIER_EXAMPLES = 3

COMPONENTS = {
    "at=direct-load": "assembler: global loads expanded through $at",
    "at=load": "assembler: loads through $at",
    "at=address": "assembler: %hi through $at (stores, addresses)",
    "at=compare": "assembler: branch macros (blt/bge...) through $at",
    "li=addiu": "assembler: li expansion", "li=ori": "assembler: li expansion",
    "li=ori-small": "assembler: li expansion",
    "move=addu": "compiler/assembler: move encoding", "move=or": "compiler/assembler: move encoding",
    "move=daddu": "compiler/assembler: move encoding",
    "slots=empty": "scheduler / assembler reorder", "slots=filled": "scheduler / assembler reorder",
    "slots=some": "scheduler / assembler reorder", "return=slot-empty": "scheduler / assembler reorder",
    "return=slot-filled": "scheduler / assembler reorder",
    "scratch=t": "register allocator", "scratch=v": "register allocator", "scratch=mixed": "register allocator",
    "branch=likely": "optimiser / ISA: branch-likely",
    "isa=64bit": "ISA / ABI: 64-bit instructions", "ra=64bit": "ISA / ABI: 64-bit registers saved",
    "gp=used": "small-data threshold (-G)",
    "args=homed": "optimisation level (arguments homed)", "args=homed-fp": "optimisation level (frame pointer)",
    "frame=pointer": "optimisation level (frame pointer)", "nops=many": "optimisation level (unscheduled)",
    "nops=few": "optimisation level (scheduled)",
    "frame=first": "frame layout", "frame=later": "frame layout", "frame=none": "frame layout",
    "ra-slot=top": "frame layout", "ra-slot=inner": "frame layout",
    "trap": "division checks", "tail=jump": "tail calls / boundary",
}


def _marks(data: bytes, delta: int, rows) -> list[tuple[int, int, frozenset[str], frozenset[str]]]:
    """(vram, size, marks without sequences, marks with sequences) of every function of 8+ bytes."""
    out = []
    for _name, vram, size in rows:
        code = data[vram - delta:vram - delta + size]
        if size >= 8 and len(code) == size:
            plain = idioms.features(code, vram, sequences=False)
            out.append((vram, size, plain, plain | idioms.sequence_marks(code)))
    return sorted(out)


def _merge(stretches: list[dict], least: int = MIN_REGION) -> list[dict]:
    """Stretches shorter than ``least`` functions join the neighbour of the same lane, else the
    larger neighbour; the posterior shares are weighted by function count."""
    rows = [dict(row, _likely={x["recipe"]: x["share"] * row["functions"] for x in row["likely"]})
            for row in stretches]
    changed = True
    while changed and len(rows) > 1:
        changed = False
        for index, row in enumerate(rows):
            if row["functions"] >= least:
                continue
            left = rows[index - 1] if index > 0 else None
            right = rows[index + 1] if index + 1 < len(rows) else None
            choices = [n for n in (left, right) if n is not None]
            same = [n for n in choices if n["lane"] == row["lane"]]
            into = max(same or choices, key=lambda n: n["functions"])
            into["start"], into["end"] = min(into["start"], row["start"]), max(into["end"], row["end"])
            into["functions"] += row["functions"]
            for name, weight in row["_likely"].items():
                into["_likely"][name] = into["_likely"].get(name, 0.0) + weight
            rows.pop(index)
            changed = True
            break
    for row in rows:
        total = sum(row["_likely"].values()) or 1.0
        row["likely"] = [{"recipe": name, "share": round(weight / total, 3)} for name, weight in
                         sorted(row.pop("_likely").items(), key=lambda kv: -kv[1])[:4]]
    return rows


def _trim(unknown: list[dict], marked) -> list[dict]:
    """Unknown stretches narrowed to their first and last function that shows one of the marks
    no class explains (``unknown_stretches`` flags whole windows, which reach into the code
    around)."""
    out = []
    for u in unknown:
        carriers = [v for v, _s, plain, _f in marked if u["start"] <= v <= u["end"] and set(u["marks"]) & plain]
        if carriers:
            out.append(dict(u, start=carriers[0], end=carriers[-1],
                            functions=sum(1 for v, *_rest in marked if carriers[0] <= v <= carriers[-1])))
    return out


def _cut(regions: list[dict], unknown: list[dict], starts: list[int], least: int) -> list[dict]:
    """Regions cut where a stretch no class explains begins and ends, so the unexplained code is a
    region of its own and does not condemn the known code around it.  A piece with fewer than
    ``least`` functions stays with the piece before it."""
    out = []
    for region in regions:
        cuts = sorted({u["start"] for u in unknown if region["start"] < u["start"] <= region["end"]}
                      | {min((v for v in starts if v > u["end"]), default=region["end"] + 4)
                         for u in unknown if region["start"] <= u["end"] < region["end"]})
        bounds = [region["start"]] + cuts + [region["end"] + 4]
        pieces = []
        for lo, hi in zip(bounds, bounds[1:]):
            members = [v for v in starts if lo <= v < hi]
            if not members:
                continue
            piece = dict(region, start=members[0], end=members[-1], functions=len(members))
            if pieces and len(members) < least:
                pieces[-1].update(end=members[-1], functions=pieces[-1]["functions"] + len(members))
            else:
                pieces.append(piece)
        out += pieces
    return out


def _rates(marks: list[frozenset[str]]) -> dict[str, float]:
    seen: Counter = Counter()
    for found in marks:
        seen.update(m for m in found if not m.startswith("seq:"))
    return {mark: round(count / len(marks), 3) for mark, count in sorted(seen.items())} if marks else {}


def _class_rates(table: idioms.Table, name: str) -> dict[str, float]:
    entry = table.classes.get(name) or {}
    total = entry.get("functions") or 0
    return {m: c / total for m, c in (entry.get("marks") or {}).items() if not m.startswith("seq:")} if total else {}


def _mismatches(rates: dict[str, float], class_rates: dict[str, float]) -> list[dict]:
    out = []
    for mark, rate in rates.items():
        usual = class_rates.get(mark, 0.0)
        if mark in COMPONENTS and rate >= MISMATCH_RATE and usual <= CLASS_NEVER:
            out.append({"mark": mark, "component": COMPONENTS[mark], "region_rate": rate, "class_rate": round(usual, 4),
                        "direction": "region shows it, the class does not"})
        elif mark in COMPONENTS and usual >= 1 - CLASS_NEVER and rate <= 1 - MISMATCH_RATE * 2:
            out.append({"mark": mark, "component": COMPONENTS[mark], "region_rate": rate, "class_rate": round(usual, 4),
                        "direction": "the class always shows it, the region often does not"})
    return sorted(out, key=lambda m: -abs(m["region_rate"] - m["class_rate"]))


def _dossier(data: bytes, delta: int, members, rates, table: idioms.Table, ruled: dict, ranked) -> dict:
    from .. import mips
    kinds: Counter = Counter()
    pairs: Counter = Counter()
    for vram, size, _plain, full in members:
        for word in idioms._words(data[vram - delta:vram - delta + size]):
            kinds[idioms._kind(word)] += 1
        pairs.update(m for m in full if m.startswith("seq:"))
    total = sum(kinds.values()) or 1
    nearest = []
    for entry in ranked[:3]:
        usual = _class_rates(table, entry["recipe"])
        differ = sorted(((m, rates.get(m, 0.0), round(usual.get(m, 0.0), 3)) for m in set(rates) | set(usual)
                         if m in COMPONENTS and abs(rates.get(m, 0.0) - usual.get(m, 0.0)) >= 0.25),
                        key=lambda row: -abs(row[1] - row[2]))
        nearest.append({"recipe": entry["recipe"], "share": entry["share"],
                        "differs": [{"mark": m, "component": COMPONENTS[m], "region": a, "class": b} for m, a, b in differ[:8]]})
    smallest = sorted(members, key=lambda m: (m[1], m[0]))[:DOSSIER_EXAMPLES]
    examples = []
    for vram, size, _plain, _full in smallest:
        try:
            listing = mips.disassemble(data[vram - delta:vram - delta + size], vram)
        except Exception:                                    # noqa: BLE001 - an example, not evidence
            listing = []
        examples.append({"vram": f"0x{vram:08X}", "size": size, "disassembly": listing[:40]})
    return {"instruction_kinds": {k: round(v / total, 4) for k, v in kinds.most_common(16)},
            "common_pairs": [{"pair": m[4:], "functions": c} for m, c in pairs.most_common(12)],
            "nearest_classes": nearest,
            "ruled_out_by": {name: [{"mark": r[0], "seen": r[1], "of": r[2], "class_rate": r[3]} for r in reasons[:4]]
                             for name, reasons in sorted(ruled.items())[:12]},
            "smallest_functions": examples}


LANE_MARKS = Path(__file__).resolve().parent / "data" / "lane_marks.json"


def load_lane_marks(path=None) -> dict[str, set[str]]:
    """recipe -> component marks its probes produce (``compiler-probes``' ``lane_marks``); the
    shipped table when no path is given, empty when there is none."""
    import json
    path = Path(path) if path else LANE_MARKS
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    return {k: set(v) for k, v in (data.get("lane_marks") or data).items()}


def unreproduced(rates: dict[str, float], lane_marks: dict[str, set[str]]) -> list[dict]:
    """Component marks the region shows often (``MISMATCH_RATE``) that no probed recipe produced on
    any probe: no installed tool chain makes that form, whatever the source."""
    if not lane_marks:
        return []
    out = []
    for mark, rate in sorted(rates.items(), key=lambda kv: -kv[1]):
        if mark in COMPONENTS and rate >= MISMATCH_RATE:
            makers = sorted(k for k, found in lane_marks.items() if mark in found)
            if not makers:
                out.append({"mark": mark, "component": COMPONENTS[mark], "region_rate": rate,
                            "probed_recipes": len(lane_marks)})
    return out


def reconstruct(data: bytes, delta: int, rows, table: idioms.Table | None = None, cases=None,
                least: int = MIN_REGION, lane_marks: dict | None = None) -> dict:
    """The regional reconstruction of one image (see the module docstring).  ``rows`` are
    (name, vram, size) in link space; ``cases`` are the image's stored cases (optional);
    ``lane_marks`` (recipe -> component marks its probes produce) says which component forms no
    installed tool chain makes (default: the shipped probe table)."""
    table = table or idioms.Table.load()
    lane_marks = load_lane_marks() if lane_marks is None else lane_marks
    marked = _marks(data, delta, rows)
    if not marked or not table.classes:
        return {"regions": [], "functions": len(marked), "reason": "no functions or no marks table"}
    stretches = idioms.stretches([(v, full) for v, _s, _p, full in marked], table, keep=4)
    regions = _merge(stretches, least) if stretches else []
    unknown = idioms.unknown_stretches([(v, plain) for v, _s, plain, _f in marked], table)
    unknown = _trim(unknown, marked)
    regions = _cut(regions, unknown, [m[0] for m in marked], least)
    proven: dict[int, str] = {}
    for case in cases or []:
        if case.status == "exact" and case.recipe:
            proven[case.vram] = case.recipe
    out = []
    for row in regions:
        members = [m for m in marked if row["start"] <= m[0] <= row["end"]]
        if not members:
            continue
        plain = [m[2] for m in members]
        rates = _rates(plain)
        ranked = row["likely"]
        best = ranked[0] if ranked else None
        mismatches = _mismatches(rates, _class_rates(table, best["recipe"])) if best else []
        overlap = [u for u in unknown if u["start"] <= row["end"] and row["start"] <= u["end"]]
        unknown_functions = sum(1 for m in members if any(u["start"] <= m[0] <= u["end"] for u in overlap))
        recipes = Counter(proven[m[0]] for m in members if m[0] in proven)
        asm_share = sum(1 for m in plain if "trap" in m) / len(plain)
        if unknown_functions * 2 >= len(members):
            verdict = "unknown"
        elif best is None or best["share"] < KNOWN_SHARE:
            verdict = "uncertain"
        elif mismatches:
            verdict = "mismatch"
        else:
            verdict = "known"
        region = {"start": f"0x{row['start']:08X}", "end": f"0x{row['end']:08X}", "functions": len(members),
                  "bytes": sum(m[1] for m in members), "lane": row["lane"], "ranked": ranked,
                  "verdict": verdict, "component_mismatches": mismatches[:6],
                  "unknown_functions": unknown_functions,
                  "unknown_marks": sorted({mark for u in overlap for mark in u["marks"]}),
                  "proven": dict(recipes.most_common(4)), "exact_functions": sum(recipes.values()),
                  "unreproduced_components": unreproduced(rates, lane_marks),
                  "component_rates": {m: r for m, r in rates.items() if m in COMPONENTS}}
        if asm_share >= 0.5:
            region["verdict"] = "assembly"
        if region["verdict"] != "known":
            region["dossier"] = _dossier(data, delta, members, rates, table, table.misfit(plain), ranked)
        out.append(region)
    verdicts = Counter(r["verdict"] for r in out)
    return {"functions": len(marked), "regions": out,
            "summary": {"regions": len(out), "verdicts": dict(verdicts),
                        "functions_by_verdict": {v: sum(r["functions"] for r in out if r["verdict"] == v)
                                                 for v in verdicts}}}


def region_of(reconstruction: dict, vram: int) -> dict | None:
    for region in reconstruction.get("regions") or []:
        if int(region["start"], 16) <= vram <= int(region["end"], 16):
            return region
    return None


def unavailable(reconstruction: dict) -> list[tuple[int, int]]:
    """Address ranges of regions no known tool chain explains (verdict ``unknown``): where a
    variant search under the known recipes is not expected to pay."""
    return [(int(r["start"], 16), int(r["end"], 16)) for r in reconstruction.get("regions") or []
            if r["verdict"] == "unknown"]
