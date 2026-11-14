"""Parsers and explainers for GCC 2.7.x allocator dumps.

The module reads diagnostics only.  It never changes the production compiler or
manufactures final output.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass


LOCAL = re.compile(
    r"^Register (?P<pseudo>\d+) used (?P<refs>\d+) times across (?P<span>\d+) "
    r"insns in block (?P<block>\d+);(?P<tail>.*)$", re.MULTILINE)
LOCAL_ASSIGN = re.compile(r"^;; Register (?P<pseudo>\d+) in (?P<hard>\d+)\.$", re.MULTILINE)
GLOBAL_SECTION = re.compile(r"^;; Register dispositions:\s*$", re.MULTILINE)
GLOBAL_ASSIGN = re.compile(r"(?P<pseudo>\d+) in (?P<hard>\d+)")


@dataclass(frozen=True)
class Pseudo:
    number: int
    references: int
    live_span: int
    block: int
    hard_register: int | None
    pointer: bool
    assumed_size_words: int = 1

    @property
    def priority(self) -> int:
        if self.references <= 1 or self.live_span <= 0:
            return 0
        return int(math.floor(math.log2(self.references)) * self.references
                   * self.assumed_size_words / self.live_span * 10000)

    def as_dict(self) -> dict:
        result = asdict(self)
        result["priority"] = self.priority
        return result


def _global_assignments(text: str) -> dict[int, int]:
    match = GLOBAL_SECTION.search(text)
    if not match:
        return {}
    tail = text[match.end():]
    end = tail.find("\n\n\n")
    if end >= 0:
        tail = tail[:end]
    return {int(m.group("pseudo")): int(m.group("hard"))
            for m in GLOBAL_ASSIGN.finditer(tail)}


def parse(local_dump: str, global_dump: str = "") -> list[Pseudo]:
    assignments = {int(m.group("pseudo")): int(m.group("hard"))
                   for m in LOCAL_ASSIGN.finditer(local_dump)}
    assignments.update(_global_assignments(global_dump))
    pseudos = []
    for match in LOCAL.finditer(local_dump):
        number = int(match.group("pseudo"))
        pseudos.append(Pseudo(number, int(match.group("refs")), int(match.group("span")),
                              int(match.group("block")), assignments.get(number),
                              "pointer" in match.group("tail")))
    return pseudos


def explain(local_dump: str, global_dump: str = "") -> dict:
    pseudos = parse(local_dump, global_dump)
    by_priority = sorted(pseudos, key=lambda item: (-item.priority, item.number))
    ties: dict[int, list[int]] = {}
    for item in by_priority:
        ties.setdefault(item.priority, []).append(item.number)
    return {
        "pseudos": [item.as_dict() for item in by_priority],
        "priority_ties": {str(priority): numbers for priority, numbers in ties.items()
                          if len(numbers) > 1},
        "diagnostics": [
            "priority assumes a one-word quantity because the standard dump omits qty_size",
            "pseudo numbering alone does not establish source declaration order or local quantity order",
            "hard-register assignment is diagnostic evidence, not proof of source semantics",
            "global dump dispositions may already include reload effects; inspect the pinned pass driver",
        ],
    }
