"""Small exhaustive checks for finite scalar rewrite domains.

These checks make no claims about compiler output, pointer aliasing, side effects,
or arbitrary C equivalence. They can falsify proposed scalar identities before
expensive historical compilation.
"""
from __future__ import annotations


def check_unsigned_mask_identity(width: int, mask: int) -> dict:
    """Check x & mask == x for every unsigned value of the declared bit width."""
    if not 1 <= width <= 16:
        raise ValueError("exhaustive checks support widths 1 through 16")
    if mask < 0:
        raise ValueError("mask must be nonnegative")
    failures = []
    for value in range(1 << width):
        actual = value & mask
        if actual != value:
            failures.append({"input": value, "masked": actual, "unmasked": value})
    return {"equivalent": not failures, "width": width, "mask": mask,
            "tested_values": 1 << width, "counterexample_count": len(failures),
            "first_counterexample": failures[0] if failures else None,
            "scope": "pure scalar identity over the stated unsigned domain"}
