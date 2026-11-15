"""Cross-function structure-layout constraints from :mod:`n64dk.analysis.values` facts.

The solver is deliberately evidentiary: it unifies pointer parameters only when a tracked caller
value is passed to a known callee parameter.  A constant displacement is retained, so passing
``object + 0x20`` models an embedded object rather than collapsing both origins.  Loaded pointer
fields form their own layout node.  Conflicting access widths/types are reported and never hidden
behind a guessed C declaration.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
import hashlib
import re

from .values import Facts


Node = tuple[int, tuple]  # (function vram, value key)


class _WeightedUnion:
    """Union-find where ``origin(child) = origin(parent) + weight[child]``."""

    def __init__(self):
        self.parent: dict[Node, Node] = {}
        self.weight: dict[Node, int] = {}
        self.conflicts: list[dict] = []

    def add(self, node: Node) -> None:
        if node not in self.parent:
            self.parent[node] = node
            self.weight[node] = 0

    def find(self, node: Node) -> tuple[Node, int]:
        self.add(node)
        parent = self.parent[node]
        if parent == node:
            return node, 0
        root, up = self.find(parent)
        total = self.weight[node] + up
        self.parent[node], self.weight[node] = root, total
        return root, total

    def union(self, left: Node, right: Node, right_minus_left: int, evidence: str) -> None:
        """Constrain ``origin(right) = origin(left) + right_minus_left``."""
        lroot, loff = self.find(left)
        rroot, roff = self.find(right)
        if lroot == rroot:
            if roff - loff != right_minus_left:
                self.conflicts.append({"kind": "origin-constraint", "evidence": evidence,
                                       "existing": roff - loff, "requested": right_minus_left})
            return
        # origin(rroot)+roff = origin(lroot)+loff+delta
        self.parent[rroot] = lroot
        self.weight[rroot] = loff + right_minus_left - roff


def _node(function: int, key: tuple) -> Node | None:
    if not key:
        return None
    if key[0] == "param":
        return function, key
    if key[0] == "field":
        # A pointer loaded from a field points at another object; retain the full provenance key.
        return function, key
    return None


def _ctype(width: int, signed: bool | None, floating: bool) -> str:
    if floating:
        return "f32" if width == 4 else "f64"
    if signed is None:
        return {1: "u8", 2: "u16", 4: "u32", 8: "u64"}.get(width, "u8")
    prefix = "s" if signed else "u"
    return f"{prefix}{width * 8}"


def infer(facts: dict[int, Facts], names: dict[int, str] | None = None) -> dict:
    names = names or {}
    union = _WeightedUnion()
    for function, fact in facts.items():
        for access in fact.accesses:
            node = _node(function, access.base)
            if node:
                union.add(node)
        for call in fact.calls:
            if call.target not in facts:
                continue
            for register, value in call.args.items():
                if value is None or register not in (4, 5, 6, 7):
                    continue
                caller = _node(function, value[0])
                callee = (call.target, ("param", register - 4))
                if caller:
                    union.union(caller, callee, value[1],
                                f"{names.get(function, hex(function))}@0x{call.site:X} -> "
                                f"{names.get(call.target, hex(call.target))} arg{register - 4}")

    grouped: dict[Node, dict] = {}
    for function, fact in facts.items():
        for access in fact.accesses:
            node = _node(function, access.base)
            if node is None:
                continue
            root, displacement = union.find(node)
            group = grouped.setdefault(root, {"members": set(), "fields": defaultdict(list)})
            group["members"].add(node)
            group["fields"][displacement + access.offset].append((function, access))

    layouts = []
    for index, (root, group) in enumerate(sorted(grouped.items(), key=lambda item: repr(item[0]))):
        fields = []
        for offset, observations in sorted(group["fields"].items()):
            forms = {(a.width, a.signed, a.floating) for _function, a in observations}
            fields.append({"offset": offset,
                           "widths": sorted({form[0] for form in forms}),
                           "types": sorted({_ctype(*form) for form in forms}),
                           "reads": sum(not access.store for _function, access in observations),
                           "writes": sum(access.store for _function, access in observations),
                           "functions": sorted({names.get(function, f"func_{function:08X}")
                                                for function, _access in observations}),
                           "sites": sorted(f"0x{access.site:08X}" for _function, access in observations),
                           "conflict": len(forms) > 1})
        members = []
        for member in sorted(group["members"], key=repr):
            _member_root, displacement = union.find(member)
            members.append({"function": names.get(member[0], f"func_{member[0]:08X}"),
                            "key": repr(member[1]), "origin_offset": displacement})
        digest = hashlib.sha256(repr((root, members, fields)).encode()).hexdigest()[:12]
        layouts.append({"id": f"layout_{digest}", "root": repr(root), "members": members,
                        "fields": fields, "conflicts": [field for field in fields if field["conflict"]],
                        "max_extent": max((field["offset"] + max(field["widths"])
                                           for field in fields if field["offset"] >= 0), default=0)})
    return {"model": "structure-constraints-v1", "layouts": layouts,
            "layout_count": len(layouts), "constraint_conflicts": union.conflicts,
            "conflict_count": len(union.conflicts) + sum(len(row["conflicts"]) for row in layouts)}


def context_header(result: dict, prototypes=(), min_members: int = 1) -> str:
    """Render conservative review-only declarations for m2c; conflicts become byte arrays."""
    lines = ["/* Generated by n64dk structure-context.",
             " * Provisional evidence only: review conflicts and names before integration. */",
             '#include "types.h"', ""]
    for layout in result.get("layouts", []):
        if len(layout["members"]) < min_members or any(field["offset"] < 0 for field in layout["fields"]):
            continue
        lines.append(f"typedef struct {layout['id']} {{")
        cursor = 0
        for field in layout["fields"]:
            offset = field["offset"]
            if offset < cursor:
                lines.append(f"    /* overlapping/conflicting evidence at 0x{offset:X}: "
                             f"{', '.join(field['types'])} */")
                continue
            if offset > cursor:
                lines.append(f"    u8 pad_{cursor:04X}[0x{offset - cursor:X}];")
            width = max(field["widths"])
            ctype = field["types"][0] if len(field["types"]) == 1 else "u8"
            suffix = f"[0x{width:X}]" if len(field["types"]) != 1 else ""
            lines.append(f"    {ctype} field_{offset:04X}{suffix};"
                         + (f" /* conflict: {', '.join(field['types'])} */" if field["conflict"] else ""))
            cursor = offset + width
        lines += [f"}} {layout['id']};", ""]
    for prototype in prototypes:
        declaration = prototype.declaration() if hasattr(prototype, "declaration") else str(prototype)
        lines.append(declaration)
    return "\n".join(lines).rstrip() + "\n"
