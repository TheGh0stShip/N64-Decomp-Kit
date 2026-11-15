"""Translation-unit boundaries and a per-unit recipe map.

Per-file compiler settings are the rule, not the exception: most multi-library ROMs mix
compilers and optimisation levels (game code, SDK objects at ``-O1``/``-O3``, a different
compiler for one library).  Two facts recover that structure without symbols:

* **Object boundaries.**  The assemblers of the N64 toolchains (IDO, KMC, SN, EGCS) pad every
  object's ``.text`` to 16 bytes.  So a new object starts where a function begins on a 16-byte
  boundary *and* the previous function ends in padding (zero words after its last terminator).
  A function that directly follows its predecessor with no padding is in the same object.  An
  aligned start with no padding before it is undecided (the previous object may have ended
  exactly on the boundary): it stays in the same unit unless other evidence splits it.
* **Recipes travel with objects.**  Every function of one object was built by one compiler
  invocation.  Once any unit member is matched, its pipeline and flags are the first thing to
  try for the others; the nearest matched units are the next best guess.

``units`` computes the partition; ``RecipeMap`` answers "which recipes should be tried for this
address, most likely first" from already-matched manifest rows.
"""
from __future__ import annotations

import bisect
from collections import Counter
from dataclasses import dataclass, field

from . import flow as flowmod


@dataclass
class Unit:
    start: int
    end: int
    functions: list[tuple[str, int, int]] = field(default_factory=list)
    padding: int = 0                    # bytes of padding that end the unit
    family: str | None = None           # majority compiler-family fingerprint of its functions
    closed: bool = False                # ends in alignment padding (a confirmed object end)


def units(image: bytes, vram_delta: int, functions: list[tuple[str, int, int]], alignment: int = 16,
          family_of=None) -> list[Unit]:
    """Partition catalogued functions into probable objects.  ``family_of(flow) -> str | None``
    optionally fingerprints each function (e.g. ``causes.compiler_family``); a change of
    confident family between neighbours also starts a new unit."""
    ordered = sorted((f for f in functions if f[2] >= 4), key=lambda f: f[1])
    out: list[Unit] = []
    previous_padding, previous_end, previous_family = 0, None, None
    for name, vram, size in ordered:
        offset = vram - vram_delta
        if offset < 0 or offset + size > len(image):
            continue
        flow = flowmod.analyse_in_image(image, vram_delta, vram, size)
        padding = 4 * sum(1 for _address, role in flowmod.nop_roles(flow) if role == "padding")
        family = family_of(flow) if family_of is not None else None
        gap = 0 if previous_end is None else vram - previous_end
        # zero words between catalogue rows are padding the catalogue did not assign to anyone
        between = gap > 0 and not any(image[previous_end - vram_delta:offset])
        aligned = vram % alignment == 0
        starts_unit = not out or (aligned and (previous_padding > 0 or between)) or \
            (family and previous_family and family != previous_family) or (gap > 0 and not between)
        if starts_unit:
            if out and aligned and (previous_padding > 0 or between):
                out[-1].closed = True
                out[-1].padding = previous_padding + (gap if between else 0)
            out.append(Unit(vram, vram + size))
        unit = out[-1]
        unit.functions.append((name, vram, size))
        unit.end = vram + size
        previous_padding, previous_end = padding, vram + size
        previous_family = family or previous_family
    for unit in out:
        votes = Counter()
        if family_of is not None:
            for _name, vram, size in unit.functions:
                found = family_of(flowmod.analyse_in_image(image, vram_delta, vram, size))
                if found:
                    votes[found] += 1
        unit.family = votes.most_common(1)[0][0] if votes else None
    return out


class RecipeMap:
    """Recipes of already-matched code, queryable by address.

    ``add(vram, size, pipeline, flags)`` records one matched manifest row.  ``candidates(vram)``
    returns distinct (pipeline, flags) pairs: those matched inside the same unit first, then by
    distance in units, then the image-wide most common ones."""

    def __init__(self, unit_list: list[Unit] | None = None):
        self.units = sorted(unit_list or [], key=lambda u: u.start)
        self.starts = [u.start for u in self.units]
        self.rows: list[tuple[int, int, str, tuple[str, ...]]] = []

    def add(self, vram: int, size: int, pipeline: str, flags) -> None:
        self.rows.append((vram, size, pipeline, tuple(flags)))

    def _unit_index(self, vram: int) -> int | None:
        index = bisect.bisect_right(self.starts, vram) - 1
        if index >= 0 and self.units[index].start <= vram < self.units[index].end:
            return index
        return None

    def candidates(self, vram: int, limit: int = 4) -> list[dict]:
        mine = self._unit_index(vram)
        scored = []
        for row_vram, _size, pipeline, flags in self.rows:
            theirs = self._unit_index(row_vram)
            if mine is not None and theirs is not None:
                distance = abs(theirs - mine)
            else:
                distance = 1 + abs(row_vram - vram) // 0x1000
            scored.append((distance, abs(row_vram - vram), pipeline, flags))
        scored.sort()
        out, seen = [], set()
        for distance, _bytes, pipeline, flags in scored:
            if (pipeline, flags) not in seen:
                seen.add((pipeline, flags))
                out.append({"pipeline": pipeline, "flags": list(flags), "unit_distance": distance,
                            "same_unit": distance == 0 and mine is not None})
            if len(out) >= limit:
                break
        common = Counter((p, f) for _v, _s, p, f in self.rows).most_common(limit)
        for (pipeline, flags), _count in common:
            if (pipeline, flags) not in seen and len(out) < limit + 2:
                seen.add((pipeline, flags))
                out.append({"pipeline": pipeline, "flags": list(flags), "unit_distance": None, "same_unit": False})
        return out

    def summary(self) -> dict:
        per_unit: dict[int, set] = {}
        for vram, _size, pipeline, flags in self.rows:
            index = self._unit_index(vram)
            if index is not None:
                per_unit.setdefault(index, set()).add((pipeline, flags))
        return {"units": len(self.units), "closed_units": sum(1 for u in self.units if u.closed),
                "matched_rows": len(self.rows), "units_with_a_matched_member": len(per_unit),
                "units_with_conflicting_recipes": sum(1 for v in per_unit.values() if len(v) > 1),
                "distinct_recipes": len({(p, f) for _v, _s, p, f in self.rows})}
