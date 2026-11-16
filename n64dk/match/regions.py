"""Which recipe built which stretch of an image.

A title is rarely one compiler invocation repeated: game code at one optimisation level, a
library at another, a second library from a different compiler, a debug file.  Each of them is a
contiguous stretch of the image, because a linker lays objects out one after another.

The sweep finds this out one function at a time and by trial: a function is tried under the
image's recipe, then under alternatives, and the first recipe that matches is recorded.  That
record under-reports.  A function matched under the first recipe tried says nothing about whether
the second would have matched it too, so a region whose true recipe is the second looks like a
mixture of both, and its unmatched functions were all searched under the wrong one.

This module turns the matches into regions:

* ``evidence``: for each matched function, the *set* of recipes that reproduce it (its own source
  rebuilt under each candidate; a positive test on a source known to compile).
* ``segment``: the labelling of the matched functions, in address order, that explains the most of
  them with the fewest changes of recipe.  A function no label of its neighbourhood explains is
  an exception inside a region, not a region of its own, unless enough of them stand together.
* ``Regions.recipe_at``: the recipe of the region an address lies in, for the functions the sweep
  did not match.

Nothing here builds anything; the caller supplies the evidence.
"""
from __future__ import annotations

import bisect
from dataclasses import dataclass, field

SWITCH_COST = 2.5        # a change of recipe must be paid for by this many explained functions
MIN_SUPPORT = 3          # a region is offered as evidence from this many functions on


@dataclass
class Region:
    start: int                       # address of the first function the region covers
    end: int                         # address past the last one
    recipe: str
    support: int = 0                 # matched functions the recipe reproduces
    exceptions: int = 0              # matched functions inside the region that it does not
    alternatives: list[str] = field(default_factory=list)   # recipes that explain exactly the same members

    def as_dict(self) -> dict:
        return {"start": f"0x{self.start:08X}", "end": f"0x{self.end:08X}", "recipe": self.recipe,
                "support": self.support, "exceptions": self.exceptions, "alternatives": self.alternatives}


def segment(evidence: list[tuple[int, frozenset[str] | set[str]]], order: list[str] | None = None,
            switch_cost: float = SWITCH_COST) -> list[tuple[int, int, str]]:
    """Label matched functions with recipes: ``[(first index, last index, recipe)]`` runs.

    ``evidence`` is ``[(address, recipes that reproduce the function)]`` in address order.  The
    labelling minimises (functions their label does not reproduce) + ``switch_cost`` x (changes of
    label).  ``order`` breaks ties between recipes, first preferred (the image's own recipe
    first keeps a labelling that nothing contradicts)."""
    if not evidence:
        return []
    recipes = list(order or [])
    for _address, found in evidence:
        for recipe in sorted(found):
            if recipe not in recipes:
                recipes.append(recipe)
    if not recipes:
        return []
    rank = {recipe: position for position, recipe in enumerate(recipes)}
    cost = [0.0 if recipe in evidence[0][1] else 1.0 for recipe in recipes]
    back: list[list[int]] = []
    for _address, found in evidence[1:]:
        best = min(range(len(recipes)), key=lambda k: (cost[k], k))
        step, new = [], []
        for k, recipe in enumerate(recipes):
            stay, move = cost[k], cost[best] + switch_cost
            if move < stay:
                new.append(move)
                step.append(best)
            else:
                new.append(stay)
                step.append(k)
            new[-1] += 0.0 if recipe in found else 1.0
        back.append(step)
        cost = new
    last = min(range(len(recipes)), key=lambda k: (cost[k], rank[recipes[k]]))
    labels = [last]
    for step in reversed(back):
        labels.append(step[labels[-1]])
    labels.reverse()
    runs, begin = [], 0
    for index in range(1, len(labels) + 1):
        if index == len(labels) or labels[index] != labels[begin]:
            runs.append((begin, index - 1, recipes[labels[begin]]))
            begin = index
    return runs


class Regions:
    """Recipe regions of one image."""

    def __init__(self, regions: list[Region] | None = None):
        self.regions = sorted(regions or [], key=lambda region: region.start)
        self._starts = [region.start for region in self.regions]

    @classmethod
    def build(cls, evidence: dict[int, set[str]], starts: list[int] | None = None, end: int | None = None,
              order: list[str] | None = None, switch_cost: float = SWITCH_COST) -> "Regions":
        """Regions from ``{address of a matched function: recipes that reproduce it}``.

        ``starts`` are the addresses of every function of the image (matched or not), so that a
        boundary between two regions falls on a function start halfway between the last matched
        function of one and the first of the next; ``end`` is the address past the image's code."""
        rows = sorted((address, frozenset(found)) for address, found in evidence.items() if found)
        runs = segment(rows, order, switch_cost)
        if not runs:
            return cls([])
        every = sorted(set(starts or []) | {address for address, _found in rows})
        regions = []
        for number, (first, last, recipe) in enumerate(runs):
            members = rows[first:last + 1]
            support = sum(1 for _address, found in members if recipe in found)
            explained = frozenset(address for address, found in members if recipe in found)
            same = sorted({other for _address, found in members for other in found if other != recipe
                           and frozenset(a for a, f in members if other in f) == explained})
            if number == 0:
                start = every[0]
            else:
                # halfway, by count of functions, between the two regions' nearest matched members
                before, here = rows[first - 1][0], members[0][0]
                lo, hi = bisect.bisect_right(every, before), bisect.bisect_left(every, here)
                start = every[(lo + hi) // 2] if lo < hi else here
            regions.append(Region(start, 0, recipe, support, len(members) - support, same))
        for number, region in enumerate(regions):
            region.end = regions[number + 1].start if number + 1 < len(regions) else (
                end if end is not None else every[-1] + 4)
        return cls(regions)

    def region_at(self, address: int) -> Region | None:
        index = bisect.bisect_right(self._starts, address) - 1
        if index >= 0 and self.regions[index].start <= address < self.regions[index].end:
            return self.regions[index]
        return None

    def recipe_at(self, address: int, min_support: int = MIN_SUPPORT) -> str | None:
        """The recipe of the region ``address`` lies in, when enough functions stand behind it."""
        region = self.region_at(address)
        return region.recipe if region is not None and region.support >= min_support else None

    def summary(self) -> dict:
        return {"regions": [region.as_dict() for region in self.regions],
                "recipes": sorted({region.recipe for region in self.regions})}
