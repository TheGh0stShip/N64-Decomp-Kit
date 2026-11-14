"""Conservative residual-to-source hypothesis rules.

Rules name a discriminating experiment and the evidence that triggered it; they never emit
unbounded spelling permutations.
"""
from __future__ import annotations


def suggest(counts: dict[str, int]) -> list[dict]:
    out = []
    if counts.get("immediate"):
        out.append({"kind": "address-formation", "evidence": "immediate residuals",
                    "try": "compare array indexing, pointer cursor, and explicit symbol/base formation"})
    if counts.get("register") and counts.get("scheduling"):
        out.append({"kind": "load-schedule-lifetime", "evidence": "coupled register and scheduling residuals",
                    "try": "change declaration scope or split/rejoin temporaries at the first divergent load"})
    elif counts.get("register"):
        out.append({"kind": "register-lifetime", "evidence": "register-only residuals",
                    "try": "test alias qualifiers, aggregate membership, and declaration order"})
    if counts.get("hazard-nop"):
        out.append({"kind": "dependency-hazard", "evidence": "hazard-nop residuals",
                    "try": "test expression sequencing around the adjacent load or multiply"})
    if counts.get("branch"):
        out.append({"kind": "branch-form", "evidence": "branch target/form residuals",
                    "try": "test inverted condition, early exit, do/while, and branch-likely-capable form"})
    if counts.get("size") and counts.get("instruction"):
        out.append({"kind": "semantic-shape", "evidence": "instruction and size residuals",
                    "try": "recheck signedness, extension width, and loop/index semantics before allocation tuning"})
    return out
