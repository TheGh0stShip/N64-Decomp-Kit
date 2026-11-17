"""Discovery completeness: how much of an image's executable code its function catalogue covers.

Round 10 found a title (Armorines) whose catalogue covered 7% of its code while every gate
passed.  This module audits a catalogue against evidence that does not come from the catalogue
itself, and says whether a decompilation percentage computed over it means anything:

* **direct call targets** (``jal``) from catalogued code that start no catalogued function, inside
  this image, inside another image of the title, or in no image at all (an address the project's
  translation does not map);
* **branch and tail targets** leaving catalogued code into bytes no function owns;
* **stack-frame prologues** (``addiu sp, sp, -N``) outside every function that walk strictly as
  complete functions;
* **pointer words** in the bytes no function owns that point at function-shaped code no function
  owns, plus pointers that reach a catalogued start only after KSEG0/KSEG1 aliasing;
* **executable islands**: function-shaped code (a strict walk to a return) in the gaps, each with
  its evidence and a confidence;
* the datamap's ``.text`` sections where the survey found them.

The verdict is ``complete``, ``doubtful`` or ``incomplete``, with the reasons.  An incomplete
catalogue can be repaired from the same evidence (:func:`repair`): islands with independent
evidence become functions, and the audit runs again until nothing new appears.  Nothing here
changes an existing boundary; interior call targets are reported for the boundary stage.
"""
from __future__ import annotations

import bisect
import json
from dataclasses import dataclass, field
from pathlib import Path

from .. import mips
from . import functions as fnmod

# Gate thresholds.  Measured on catalogues whose starts are byte-verified (Super Mario 64 and
# Dr. Mario 64 against their public trees) and on the catalogue that hid most of Armorines:
# see ``tests/test_coverage.py`` for the synthetic cases and DISCOVERY_AUDIT.md for the census.
INCOMPLETE_COVERAGE = 0.80       # executable bytes in functions below this share: incomplete
DOUBTFUL_COVERAGE = 0.95
MISSING_CALLS_SHARE = 0.01       # distinct direct-call targets outside every function, per function
MISSING_CALLS_FLOOR = 3
PROLOGUES_SHARE = 0.02           # walkable prologues outside every function, per function
PROLOGUES_FLOOR = 20
UNMAPPED_SHARE = 0.01            # distinct direct-call targets in no image of the title, per function
UNMAPPED_FLOOR = 3
PLACE_MIN_VOTES = 4              # call targets that must land on one range's prologues to place it
PLACE_AGREEMENT = 0.6            # share of the targets inside a placed range that must start functions
EXAMPLES = 12                    # addresses listed per finding class


def _prologue(word: int) -> bool:
    """``addiu sp, sp, -N`` with a plausible frame (a multiple of 8, under 64 KiB)."""
    return word >> 16 == 0x27BD and word & 0x8000 and not (-(word & 0xFFFF) & 0xFFFF) % 8


def _saves_ra(img: fnmod.Image, at: int, end: int) -> bool:
    """A ``sw``/``sd ra, N(sp)`` within the eight words after ``at``."""
    for q in range(at + 4, min(at + 36, end), 4):
        word = img.word(q)
        if word >> 16 in (0xAFBF, 0xFFBF):
            return True
    return False


@dataclass
class Island:
    start: int
    end: int
    evidence: list = field(default_factory=list)

    @property
    def confidence(self) -> str:
        """high: referenced and framed, two independent references, or a framed function saving
        ``ra`` inside the datamap's text; medium: one reference, or a framed function; low: only
        padding before it, or a frame outside the datamap's text."""
        ev = set(self.evidence)
        strong = len(ev & {"call target", "pointer target", "branch target"})
        framed = "prologue" in ev
        if (strong and framed) or strong >= 2 or (framed and "saves ra" in ev and "in .text" in ev):
            return "high"
        if strong or (framed and "outside .text" not in ev):
            return "medium"
        return "low"

    def as_dict(self) -> dict:
        return {"start": f"0x{self.start:08X}", "end": f"0x{self.end:08X}", "bytes": self.end - self.start,
                "evidence": self.evidence, "confidence": self.confidence}


class _Layout:
    """Sorted function intervals of one image, with gap lookup."""

    def __init__(self, rows, lo: int, hi: int):
        spans = sorted((v, v + s) for _n, v, s in rows if lo <= v < hi and s > 0)
        self.starts = [a for a, _ in spans]
        self.spans = spans
        self.start_set = set(self.starts)
        self.lo, self.hi = lo, hi

    def owner(self, v: int):
        i = bisect.bisect_right(self.starts, v) - 1
        if i >= 0 and v < self.spans[i][1]:
            return self.spans[i]
        return None

    def gaps(self) -> list[tuple[int, int]]:
        out, pc = [], self.lo
        for a, b in self.spans:
            if a > pc:
                out.append((pc, a))
            pc = max(pc, b)
        if pc < self.hi:
            out.append((pc, self.hi))
        return out

    def function_bytes(self) -> int:
        total, pc = 0, self.lo
        for a, b in self.spans:
            a, b = max(a, pc), min(b, self.hi)
            if b > a:
                total += b - a
                pc = b
        return total


def _in(ranges, v: int) -> bool:
    return any(a <= v < b for a, b in ranges)


def audit_image(name: str, data: bytes, vram: int, rows, *, others: dict | None = None,
                text_ranges=(), extent: tuple[int, int] | None = None, examples: int = EXAMPLES) -> dict:
    """Audit one image.  ``rows`` are (name, vram, size) in link space; ``others`` maps the other
    images of the title to ``(lo, hi, starts)``; ``text_ranges`` are datamap ``.text`` sections;
    ``extent`` limits the audit to the part of the image that is program (a whole ROM mapped
    linearly holds assets past its program)."""
    img = fnmod.Image(bytes(data), vram)
    lo, hi = vram, img.end
    if extent:
        lo, hi = max(lo, extent[0]), min(hi, extent[1])
    layout = _Layout(rows, lo, hi)
    an = fnmod.Analyser(img, layout.starts[0] if layout.starts else lo, text_lo=lo, scan_evidence=False)
    text_ranges = [(max(a, lo), min(b, hi)) for a, b in text_ranges if b > lo and a < hi]
    gaps = layout.gaps()

    # --- evidence from catalogued code: calls, branches and pointers leaving it
    calls: dict[int, list[int]] = {}
    branches: dict[int, list[int]] = {}
    for a, b in layout.spans:
        for pc in range(a, min(b, hi), 4):
            word = img.word(pc)
            op = word >> 26
            if op == 3:                                           # jal
                calls.setdefault((pc & 0xF0000000) | ((word & 0x3FFFFFF) << 2), []).append(pc)
            elif op == 2:                                         # j (tail call or long jump)
                t = (pc & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
                if not a <= t < b:
                    branches.setdefault(t, []).append(pc)
            elif op in (4, 5, 6, 7, 20, 21, 22, 23) or (op == 1 and (word >> 16) & 0x1F in (0, 1, 2, 3)):
                t = pc + 4 + (((word & 0xFFFF) ^ 0x8000) - 0x8000) * 4
                if not a <= t < b and lo <= t < hi:
                    branches.setdefault(t, []).append(pc)
    missing_calls, interior_calls, other_missing, unmapped, cross_ok = {}, {}, {}, {}, 0
    for t, sites in calls.items():
        if lo <= t < hi:
            if t in layout.start_set:
                continue
            (interior_calls if layout.owner(t) else missing_calls)[t] = sites
            continue
        holders = [(other, ostarts) for other, (olo, ohi, ostarts) in (others or {}).items() if olo <= t < ohi]
        if not holders:
            unmapped[t] = sites
        elif any(t in ostarts for _other, ostarts in holders):     # overlays share addresses: any one
            cross_ok += 1
        else:
            other_missing[t] = (holders[0][0], sites)
    branch_out = {t: s for t, s in branches.items() if lo <= t < hi and layout.owner(t) is None}

    # --- pointer words in the bytes no function owns
    pointers: dict[int, list[int]] = {}
    translated_hits, translated_gap = {}, {}
    for g0, g1 in gaps:
        for off, w in mips.iter_words(img.data[g0 - img.vram:g1 - img.vram]):
            if w & 3 or not w:
                continue
            site = g0 + off
            if lo <= w < hi:
                if w not in layout.start_set and layout.owner(w) is None:
                    pointers.setdefault(w, []).append(site)
                continue
            alias = w ^ 0x20000000 if 0x80000000 <= w < 0xC0000000 else None
            if alias is not None and lo <= alias < hi:
                (translated_hits if alias in layout.start_set else translated_gap).setdefault(alias, []).append(site)

    # --- function-shaped islands in the gaps, each with its evidence
    jal_or_ptr = set(missing_calls) | set(pointers) | set(branch_out)
    islands: list[Island] = []
    prologues_outside = walkable_prologues = 0
    for g0, g1 in gaps:
        pc = g0
        while pc < g1:
            word = img.word(pc)
            if not word:
                pc += 4
                continue
            evidence = []
            if _prologue(word):
                prologues_outside += 1
                evidence.append("prologue")
            if pc in missing_calls:
                evidence.append("call target")
            if pc in pointers:
                evidence.append("pointer target")
            if pc in branch_out:
                evidence.append("branch target")
            if not evidence and not (pc - 4 >= lo and img.word(pc - 4) == 0 and fnmod._after_function_end(img, pc)):
                pc += 4
                continue
            body = an.walk(pc, g1, strict=True)
            if not body.ok or body.fell_through or body.end - pc < 8:
                pc += 4
                continue
            strong = [t for t in jal_or_ptr if pc < t < body.end]
            if strong and not ({"call target", "pointer target", "branch target"} & set(evidence)):
                pc = min(strong)                             # a referenced start inside: it is the entry
                continue
            if "prologue" in evidence:
                walkable_prologues += 1
                if _saves_ra(img, pc, body.end):
                    evidence.append("saves ra")
            if not evidence:
                evidence.append("after padding")
            if text_ranges:
                evidence.append("in .text" if _in(text_ranges, pc) else "outside .text")
            islands.append(Island(pc, body.end, evidence))
            pc = body.end
    # A call target in a gap that runs straight (no return) into the next function, which nothing
    # calls itself: that function starts at the call target (loads scheduled before its prologue).
    leadins: dict[int, int] = {}
    for t in sorted(missing_calls):
        k = bisect.bisect_right(layout.starts, t)
        following = layout.starts[k] if k < len(layout.starts) else None
        if following is None or following in calls or any(i.start <= t < i.end for i in islands):
            continue
        body = an.walk(t, following, strict=True)
        if body.ok and body.fell_through and body.end == following:
            leadins[t] = following
    island_bytes = {level: sum(i.end - i.start for i in islands if i.confidence == level)
                    for level in ("high", "medium", "low")}
    function_bytes = layout.function_bytes()
    executable = function_bytes + island_bytes["high"] + island_bytes["medium"]
    coverage = function_bytes / executable if executable else 1.0
    text_bytes = sum(b - a for a, b in text_ranges)
    in_text = 0
    for a, b in layout.spans:
        for x, y in text_ranges:
            in_text += max(0, min(b, y) - max(a, x))

    n = max(1, len(layout.spans))
    reasons, doubts = [], []
    if coverage < INCOMPLETE_COVERAGE:
        reasons.append(f"functions cover {coverage:.0%} of the executable bytes found")
    elif coverage < DOUBTFUL_COVERAGE:
        doubts.append(f"functions cover {coverage:.1%} of the executable bytes found")
    if len(missing_calls) > max(MISSING_CALLS_FLOOR, MISSING_CALLS_SHARE * n):
        reasons.append(f"{len(missing_calls)} direct call targets start no function"
                       + (f" ({len(leadins)} of them lead straight into the next function)" if leadins else ""))
    elif missing_calls:
        doubts.append(f"{len(missing_calls)} direct call targets start no function")
    if walkable_prologues > max(PROLOGUES_FLOOR, PROLOGUES_SHARE * n):
        reasons.append(f"{walkable_prologues} complete functions with a stack frame lie outside the catalogue")
    elif walkable_prologues:
        doubts.append(f"{walkable_prologues} complete functions with a stack frame lie outside the catalogue")
    if text_bytes and in_text / text_bytes < INCOMPLETE_COVERAGE:
        reasons.append(f"functions cover {in_text / text_bytes:.0%} of the datamap's .text")
    if len(unmapped) > max(UNMAPPED_FLOOR, UNMAPPED_SHARE * n):
        reasons.append(f"{len(unmapped)} direct call targets lie in no image of the title (code the project "
                       "does not map: an unplaced segment or overlay, or a wrong address translation)")
    elif unmapped:
        doubts.append(f"{len(unmapped)} direct call targets lie in no image of the title")
    if other_missing:
        doubts.append(f"{len(other_missing)} call targets fall in another image but start no function there")
    verdict = "incomplete" if reasons else "doubtful" if doubts else "complete"

    def listing(found: dict) -> list[str]:
        return [f"0x{t:08X}" for t in sorted(found)[:examples]]

    return {
        "image": name, "vram": f"0x{lo:08X}", "end": f"0x{hi:08X}", "bytes": hi - lo,
        "functions": len(layout.spans), "function_bytes": function_bytes,
        "executable_bytes": executable, "coverage": round(coverage, 4),
        "text_sections": [[f"0x{a:08X}", f"0x{b:08X}"] for a, b in text_ranges],
        "text_bytes": text_bytes, "function_bytes_in_text": in_text,
        "islands": {"count": len(islands), "bytes": island_bytes,
                    "by_confidence": {lvl: sum(1 for i in islands if i.confidence == lvl)
                                      for lvl in ("high", "medium", "low")},
                    "examples": [i.as_dict() for i in sorted(islands, key=lambda i: -(i.end - i.start))[:examples]]},
        "direct_calls": {"targets": len(calls), "missing": len(missing_calls),
                         "missing_sites": sum(len(s) for s in missing_calls.values()),
                         "interior": len(interior_calls), "cross_image": cross_ok,
                         "missing_in_other_image": len(other_missing), "unmapped": len(unmapped),
                         "lead_ins": len(leadins),
                         "examples_missing": listing(missing_calls), "examples_interior": listing(interior_calls),
                         "examples_unmapped": listing(unmapped)},
        "branches_outside": {"targets": len(branch_out), "examples": listing(branch_out)},
        "prologues_outside": {"count": prologues_outside, "walk_as_functions": walkable_prologues},
        "pointers": {"to_uncatalogued_code": sum(1 for i in islands if "pointer target" in i.evidence),
                     "to_gap_words": len(pointers),
                     "translated_to_starts": len(translated_hits), "translated_to_gaps": len(translated_gap)},
        "verdict": verdict, "reasons": reasons, "doubts": doubts,
        "_islands": islands, "_interior": interior_calls, "_unmapped": unmapped, "_leadins": leadins,
    }


def public(report: dict) -> dict:
    """The JSON-safe part of an image audit."""
    return {k: v for k, v in report.items() if not k.startswith("_")}


def repair(name: str, data: bytes, vram: int, rows, *, others=None, text_ranges=(), extent=None, rounds: int = 12,
           levels=("high", "medium")) -> tuple[list, list[dict], list[dict]]:
    """Add every island of the given confidence levels as a function, audit again, and repeat
    until no new island appears.  Returns (rows, added, audits).  An added function ends at its
    body end plus the zero words after it.  One boundary is corrected: a function nothing calls,
    into which a call target runs straight, starts at that call target (``moved_from``).  No
    other existing row changes."""
    rows = sorted(rows, key=lambda r: r[1])
    added, audits = [], []
    img = fnmod.Image(bytes(data), vram)
    for _ in range(rounds):
        report = audit_image(name, data, vram, rows, others=others, text_ranges=text_ranges, extent=extent)
        audits.append(public(report))
        new = [i for i in report["_islands"] if i.confidence in levels]
        leadins = report["_leadins"]
        if leadins:                                          # move those starts back to the call target
            moved = []
            for row in rows:
                start = next((t for t, f in leadins.items() if f == row[1]), None)
                if start is None:
                    moved.append(row)
                    continue
                moved.append((f"func_{start:08X}", start, row[2] + row[1] - start))
                added.append({"start": f"0x{start:08X}", "end": f"0x{row[1] + row[2]:08X}", "bytes": row[1] - start,
                              "size": row[1] - start, "evidence": ["call target", "leads into the next function"],
                              "confidence": "high", "moved_from": f"0x{row[1]:08X}"})
            rows = sorted(moved, key=lambda r: r[1])
        if not new and not leadins:
            break
        if not new:
            continue
        starts = sorted([v for _n, v, _s in rows] + [i.start for i in new])
        for island in new:
            end = island.end
            k = bisect.bisect_right(starts, island.start)
            limit = starts[k] if k < len(starts) else img.end
            while end < limit and end + 4 <= img.end and img.word(end) == 0:
                end += 4
            rows.append((f"func_{island.start:08X}", island.start, end - island.start))
            added.append({**island.as_dict(), "size": end - island.start})
        rows.sort(key=lambda r: r[1])
    else:
        audits.append(public(audit_image(name, data, vram, rows, others=others, text_ranges=text_ranges,
                                         extent=extent)))
    return rows, added, audits


# --- code the title calls but no image holds ------------------------------------------------------
def _start_offsets(data: bytes) -> set[int]:
    """Offsets where a function plausibly starts: a stack-frame prologue, or the first non-zero
    word after a ``jr ra`` and its delay slot."""
    from . import segments as segmod
    words = segmod._words(data)
    out = {4 * i for i, w in enumerate(words) if segmod._is_prologue(w)}
    for i, w in enumerate(words):
        if w == 0x03E00008:
            k = i + 2
            while k < len(words) and words[k] == 0 and k < i + 8:
                k += 1
            if k < len(words):
                out.add(4 * k)
    return out


def _internal_agreement(data: bytes, base: int, starts: set[int]) -> tuple[int, int]:
    """(internal call targets inside the placed range, those landing on a function start)."""
    from . import segments as segmod
    inside = landed = 0
    for word in segmod._words(data):
        if word >> 26 == 3:
            t = (base & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
            if base <= t < base + len(data):
                inside += 1
                landed += (t - base) in starts
    return inside, landed


def place_unmapped(rom_data: bytes, targets, taken, min_votes: int = PLACE_MIN_VOTES,
                   agreement: float = PLACE_AGREEMENT, candidates=()) -> list[dict]:
    """Load addresses for code-dense ROM ranges outside ``taken`` (ROM ranges already placed), from
    call targets no image holds.  ``candidates`` are further ROM ranges (the survey's code it could
    not place).  For each range, the address where the most targets land on its stack-frame
    prologues is its load address when either

    * **one owner**: at least ``min_votes`` targets land there and ``agreement`` of all the targets
      inside the placed range start functions (the range is the whole of that code), or
    * **an overlay**: at least three targets land there, they are at least half of the range's own
      prologues, and its own calls agree (most of them land on its function starts).  Overlays
      loaded at one address each answer part of the calls into it, so their targets stay in the
      vote for the next range.

    Each placed range of the first kind takes its targets out of the vote for the next."""
    from collections import Counter
    from . import segments as segmod
    left = sorted({t for t in targets if not t % 4})
    placed: list[dict] = []
    if len(left) < 3:
        return placed
    ranges, seen = [], set()
    for lo, hi in list(candidates) + segmod.code_regions(rom_data, skip=list(taken)):
        if (lo, hi) not in seen and hi - lo >= 0x100 and not any(lo < b and a < hi for a, b in taken):
            seen.add((lo, hi))
            ranges.append((lo, hi))
    for lo, hi in ranges:
        if len(left) < 3:
            break
        data = rom_data[lo:hi]
        prologues = segmod.profile(data)["prologues"]
        votes: Counter = Counter()
        for t in left:
            for p in prologues:
                votes[t - p] += 1
        if not votes:
            continue
        ranked = votes.most_common(2)
        base, count = ranked[0]
        if len(ranked) > 1 and ranked[1][1] == count:
            continue                                         # two addresses explain it equally: ambiguous
        starts = _start_offsets(data)
        inside = [t for t in left if base <= t < base + len(data)]
        landed = [t for t in inside if t - base in starts]
        own, own_landed = _internal_agreement(data, base, starts)
        owner = count >= min_votes and len(landed) >= agreement * len(inside)
        overlay = (count >= 3 and count * 2 >= len(prologues)
                   and (own < 2 or own_landed >= 0.8 * own))
        if not (owner or overlay):
            continue
        placed.append({"rom": lo, "rom_end": hi, "vram": base, "votes": count, "inside": len(inside),
                       "landed": landed, "kind": "owner" if owner else "overlay",
                       "prologues": len(prologues), "internal_calls": [own, own_landed]})
        if owner:
            left = [t for t in left if t not in set(inside)]
    return placed


def catalogue_for(rom, data: bytes, vram: int, seeds=()):
    """The function catalogue of a code range placed at ``vram`` (as ``decompile-init`` builds one
    for every further segment): the call closure from ``seeds`` and every prologue."""
    from . import segments as segmod
    from ..image import ProgramImage, Segment
    image = ProgramImage(method="emulated", entry=vram, hand_over=vram, stack_top=None,
                         segments=[Segment(vram=vram, size=len(data), kind="packed", data=data,
                                           evidence="placed by call targets from other images")], boot=None)
    found = fnmod.discover(rom, program=image,
                           seeds=list(seeds) + [vram + offset for offset in segmod.profile(data)["prologues"]])
    fnmod.merge_dead_returns(found, data, vram)
    return found


def unplaced_code(project: Path) -> list[tuple[int, int]]:
    """ROM ranges the survey judged code-like but could not place."""
    try:
        blind = json.loads((project / "survey" / "blind.json").read_text())
        return [(int(str(u["rom"]), 16), int(str(u["rom_end"]), 16)) for u in blind.get("code_not_placed") or []
                if u.get("rom") and u.get("rom_end")]
    except (OSError, ValueError, TypeError, KeyError):
        return []


def taken_rom(project: Path) -> list[tuple[int, int]]:
    """ROM ranges the survey already placed: the main program and every further segment."""
    out = []
    try:
        report = json.loads((project / "survey" / "report.json").read_text())
        main = (report.get("program") or {}).get("main") or {}
        if main.get("rom") and main.get("rom_end"):
            out.append((int(main["rom"], 16), int(main["rom_end"], 16)))
    except (OSError, ValueError, TypeError):
        pass
    try:
        blind = json.loads((project / "survey" / "blind.json").read_text())
        for seg in blind.get("segments") or []:
            out.append((int(str(seg["rom"]), 16), int(str(seg["rom_end"]), 16)))
    except (OSError, ValueError, TypeError, KeyError):
        pass
    return out


# --- project level -------------------------------------------------------------------------------
def _text_ranges(project: Path, image: str) -> list[tuple[int, int]]:
    layout = project / "survey" / "layout.json"
    if image != "main" or not layout.is_file():
        return []
    try:
        main = json.loads(layout.read_text()).get("main", {}) or {}
    except (OSError, ValueError):
        return []
    text = [(int(s["vram"], 16), int(s["vram_end"], 16)) for s in main.get("sections") or []
            if s.get("section") == ".text" and s.get("vram") and s.get("vram_end")]
    # RSP microcode linked into .text is not R4300 code
    for r in main.get("rsp") or []:
        lo, hi = int(r["vram"], 16), int(r["vram_end"], 16)
        cut = []
        for a, b in text:
            if hi <= a or b <= lo:
                cut.append((a, b))
                continue
            if a < lo:
                cut.append((a, lo))
            if hi < b:
                cut.append((hi, b))
        text = cut
    return text


def program_extent(project: Path, name: str, spec, data: bytes) -> tuple[int, int]:
    """The part of an image that is program: the declared extent, the survey's main program range
    for a main image mapped from the whole ROM, else the whole image."""
    if spec.extent:
        return tuple(spec.extent)
    lo, hi = spec.delta, spec.delta + len(data)
    layout = project / "survey" / "layout.json"
    if name == "main" and layout.is_file():
        try:
            main = json.loads(layout.read_text()).get("main") or {}
            if main.get("vram") and main.get("end"):
                return max(lo, int(main["vram"], 16)), min(hi, int(main["end"], 16))
        except (OSError, ValueError, TypeError):
            pass
    return lo, hi


def rows_of(spec) -> list:
    """An image's catalogue rows; a catalogue file with no function in it is an empty catalogue
    (``read_catalogue`` refuses it as unrecognised), not an image that cannot be audited."""
    try:
        return spec.rows()
    except ValueError as error:
        if spec.catalogue and spec.catalogue.is_file() and "not a recognised catalogue" in str(error) \
                and "vram =" not in spec.catalogue.read_text():
            spec._rows = []
            return []
        raise


def audit_project(project, images=None, extra: dict | None = None) -> dict:
    """Audit every image of a project (or the named ones) and the ``extra`` images (name ->
    ImageSpec, e.g. segments placed by :func:`place_unmapped`), with the ROM-level picture the
    survey recorded: code found in the ROM but placed in no image, and the ledger's categories.
    ``_unmapped`` (dropped by :func:`public`) holds every call target no image holds."""
    from ..match import images as imagemod
    project = Path(project).resolve()
    registry = imagemod.load_registry(project)
    specs = {}
    for name in sorted(registry):
        try:
            spec = imagemod.resolve(project, name)
            data = spec.load()
            specs[name] = (spec, data, rows_of(spec))
        except Exception as error:                          # noqa: BLE001 - reported, not fatal
            specs[name] = (None, None, str(error)[-200:])
    for name, spec in (extra or {}).items():
        specs[name] = (spec, spec.load(), spec.rows())
    if images is not None:
        images = list(images) + [name for name in (extra or {}) if name not in images]
    bounds = {name: (*program_extent(project, name, s, d), {v for _n, v, _s in rows})
              for name, (s, d, rows) in specs.items() if s is not None}
    out = {"project": project.name, "images": {}, "_unmapped": set()}
    for name in images or sorted(specs):
        spec, data, rows = specs[name]
        if spec is None:
            out["images"][name] = {"verdict": "incomplete", "reasons": [f"image not loadable: {rows}"]}
            continue
        others = {k: v for k, v in bounds.items() if k != name}
        report = audit_image(name, data, spec.delta, rows, others=others,
                             text_ranges=_text_ranges(project, name), extent=bounds[name][:2])
        out["_unmapped"] |= set(report["_unmapped"])
        out["images"][name] = public(report)
    blind = project / "survey" / "blind.json"
    if blind.is_file():
        try:
            summary = json.loads(blind.read_text())
            unplaced = summary.get("code_not_placed") or []
            out["rom"] = {"bytes": summary.get("rom_bytes"),
                          "code_not_placed": len(unplaced),
                          "code_not_placed_bytes": sum(int(u.get("size") or 0) for u in unplaced),
                          "examples_not_placed": [{k: u.get(k) for k in ("rom", "rom_end", "size", "reason")}
                                                  for u in unplaced[:EXAMPLES]]}
        except (OSError, ValueError):
            pass
    layout = project / "survey" / "layout.json"
    if layout.is_file():
        try:
            lay = json.loads(layout.read_text())
            out.setdefault("rom", {}).update({"classified_bytes": sum((lay.get("classified_bytes") or {}).values()),
                                              "unknown_bytes": lay.get("unknown_bytes"),
                                              "microcode": len(lay.get("microcode") or [])})
        except (OSError, ValueError, TypeError):
            pass
    verdicts = [img.get("verdict") for img in out["images"].values()]
    rom_reasons = []
    if (out.get("rom") or {}).get("code_not_placed_bytes"):
        rom_reasons.append(f"{out['rom']['code_not_placed_bytes']} bytes of code-like ROM placed in no image")
    out["rom_reasons"] = rom_reasons
    out["verdict"] = ("incomplete" if "incomplete" in verdicts else
                      "doubtful" if "doubtful" in verdicts or rom_reasons else "complete")
    return out
