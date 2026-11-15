"""Catalogue fragment audit: starts that are not function entries.

A function catalogue built by sweeping (or imported from a splitter) often contains "starts"
that are really interior labels: switch-case bodies, loop heads reached by fall-through, or
code after an early ``jr $ra``.  Every such fragment inflates the function count, produces
"functions" that cannot be compiled on their own (they read registers nobody set), and makes
the enclosing function look like several smaller ones with the wrong size.

``audit`` classifies each catalogue start with independent evidence and proposes merges:

entry evidence (any one keeps the start)
    * target of a ``jal`` anywhere in the supplied images;
    * address stored as a 32-bit word in data (function pointer / table) -- but not when the
      word sits in a jump table (jump-table targets are interior by definition);
    * address formed by a ``lui``/``addiu`` pair (address taken);
    * it is the first start of the range.

interior evidence (any one marks a fragment when there is no entry evidence)
    * a conditional/unconditional branch from the preceding catalogue entry targets it or
      jumps over it (the previous body is not closed at this address);
    * the previous entry does not end in a terminator (``jr``/``j``/``b`` + delay slot), so
      control falls through;
    * it reads a callee-saved/temporary register before writing it while having no stack
      frame of its own (uses the previous function's context).

The result is advisory: boundaries become proof only when a compiled unit matches.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

import rabbitizer

_ARG_OR_ENTRY = {0, 4, 5, 6, 7, 28, 29, 31}          # zero, a0-a3, gp, sp, ra


@dataclass
class Start:
    name: str
    vram: int
    size: int
    entry_evidence: list[str] = field(default_factory=list)
    interior_evidence: list[str] = field(default_factory=list)

    @property
    def fragment(self) -> bool:
        return bool(self.interior_evidence) and not self.entry_evidence


def _word(data: bytes, off: int) -> int:
    return struct.unpack_from(">I", data, off)[0]


def _ins(data: bytes, base: int, vram: int):
    return rabbitizer.Instruction(_word(data, vram - base), vram)


def _reg(r) -> int:
    return int(r.value) if r is not None else -1


def audit(code: bytes, base: int, starts: list[tuple[str, int, int]],
          other_images: list[tuple[bytes, int]] = (), jump_table_words: set[int] = frozenset(),
          data_ranges: list[tuple[int, int]] = ()) -> dict:
    """``code`` is one linear image mapped at ``base``; ``starts`` are (name, vram, size).

    ``other_images`` are additional (bytes, base) images whose calls may target this one
    (resident program for an overlay and vice versa).  ``jump_table_words`` holds the
    addresses of jump-table slots so their contents are not mistaken for function pointers.
    ``data_ranges`` limits the pointer scan to (start, end) vram ranges; default: everything
    outside the catalogue's text span.
    """
    items = [Start(n, v, s) for n, v, s in sorted(starts, key=lambda x: x[1])]
    by_addr = {s.vram: s for s in items}
    if not items:
        return {"starts": [], "merges": [], "summary": {}}
    text_lo, text_hi = items[0].vram, max(s.vram + s.size for s in items)
    items[0].entry_evidence.append("first-start")

    # --- calls and address-taken pairs from every image
    for data, image_base in [(code, base), *other_images]:
        hi: dict[int, int] = {}
        for off in range(0, len(data) - 3, 4):
            word = _word(data, off)
            op = word >> 26
            if op == 3:                                    # jal
                target = ((image_base + off + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
                if target in by_addr:
                    by_addr[target].entry_evidence.append(f"jal@{image_base + off:08X}")
            elif op == 15:                                 # lui
                hi[(word >> 16) & 31] = (word & 0xFFFF) << 16
            elif op == 9 and ((word >> 21) & 31) in hi:    # addiu rt, rs, lo
                lo = word & 0xFFFF
                target = (hi[(word >> 21) & 31] + (lo - 0x10000 if lo & 0x8000 else lo)) & 0xFFFFFFFF
                if target in by_addr:
                    by_addr[target].entry_evidence.append(f"address-taken@{image_base + off:08X}")
            elif op in (2, 0) and (op == 2 or (word & 0x3F) == 8):
                hi.clear()                                 # j / jr: straight-line state ends

    # --- function pointers in data
    ranges = list(data_ranges) or [(base, text_lo), (text_hi, base + len(code))]
    for lo, hi_end in ranges:
        for vram in range((lo + 3) & ~3, min(hi_end, base + len(code)) - 3, 4):
            target = _word(code, vram - base)
            if target in by_addr and vram not in jump_table_words:
                by_addr[target].entry_evidence.append(f"pointer@{vram:08X}")

    # --- interior evidence from the preceding entry
    for previous, current in zip(items, items[1:]):
        end = previous.vram + previous.size
        if end != current.vram or previous.size < 8:
            continue
        furthest = 0
        for vram in range(previous.vram, end, 4):
            ins = _ins(code, base, vram)
            if ins.isBranch():
                target = ins.getBranchVramGeneric()
                furthest = max(furthest, target)
                if target == current.vram:
                    current.interior_evidence.append(f"branch-target@{vram:08X}")
        if furthest > current.vram:
            current.interior_evidence.append("previous-body-branches-past-start")
        closed = False
        for back in range(0, 5):                       # terminator, delay slot, then only zero padding
            at = end - 8 - 4 * back
            if at < previous.vram:
                break
            ins = _ins(code, base, at)
            if (ins.isJump() or ins.isUnconditionalBranch() or ins.getOpcodeName() == "eret") and \
                    not ins.doesLink() and all(_word(code, v - base) == 0 for v in range(at + 8, end, 4)):
                closed = True
                break
        if not closed:
            current.interior_evidence.append("previous-entry-falls-through")

    # --- uses caller context without a frame
    for item in items:
        if item.entry_evidence or item.size < 4:
            continue
        written, frame, reason = set(_ARG_OR_ENTRY), False, None
        for vram in range(item.vram, item.vram + min(item.size, 0x40), 4):
            word = _word(code, vram - base)
            ins = rabbitizer.Instruction(word, vram)
            if word >> 16 == 0x27BD and word & 0x8000:
                frame = True
                break
            if ins.isBranch() or ins.isJump():
                break
            for reads, getter in ((ins.readsRs(), "rs"), (ins.readsRt(), "rt")):
                if not reads:
                    continue
                r = _reg(getattr(ins, getter))
                if r not in written and (8 <= r <= 25 or r in (2, 3, 30)):
                    reason = f"reads-${r}-before-write@{vram:08X}"
                    break
            if reason:
                break
            dest = ins.getDestinationGpr()
            if dest is not None:
                written.add(_reg(dest))
        if reason and not frame:
            item.interior_evidence.append(reason)

    # --- merge proposals: each run of fragments joins the nearest preceding real entry
    merges, owner = [], None
    for item in items:
        if not item.fragment:
            owner = {"into": item.name, "vram": item.vram, "size": item.size, "absorbs": []}
            merges.append(owner)
        elif owner is not None and owner["vram"] + owner["size"] == item.vram:
            owner["absorbs"].append(item.name)
            owner["size"] += item.size
        else:
            owner = None
    merges = [m for m in merges if m["absorbs"]]
    fragments = [s for s in items if s.fragment]
    return {
        "starts": [{"name": s.name, "vram": f"0x{s.vram:08X}", "size": s.size, "fragment": s.fragment,
                    "entry_evidence": s.entry_evidence[:4], "interior_evidence": s.interior_evidence}
                   for s in items],
        "merges": [{**m, "vram": f"0x{m['vram']:08X}"} for m in merges],
        "summary": {"starts": len(items), "fragments": len(fragments),
                    "fragment_bytes": sum(s.size for s in fragments),
                    "no_evidence_either_way": sum(1 for s in items
                                                  if not s.entry_evidence and not s.interior_evidence),
                    "functions_after_merge": len(items) - len(fragments)},
    }
