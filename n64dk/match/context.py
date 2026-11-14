"""Compact evidence bundle for one inventory function."""
from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path

from .. import mips


def bundle(image_path: str | Path, vram: int, size: int, offset: int = 0,
           neighbours: list[dict] | None = None) -> dict:
    data = Path(image_path).read_bytes()
    if offset < 0 or offset + size > len(data):
        raise ValueError("function interval is outside the selected image")
    code = data[offset:offset + size]
    refs = mips.scan_refs(code, vram)
    callers = []
    for ref in mips.scan_refs(data, vram - offset):
        if ref.kind == "call" and ref.address == vram:
            callers.append(ref.site)
    widths = Counter()
    offsets = defaultdict(list)
    for ins in mips.instructions(code, vram):
        if ins.doesLoad() or ins.doesStore():
            op = ins.getOpcodeName()
            widths[{"lb": 1, "lbu": 1, "sb": 1, "lh": 2, "lhu": 2, "sh": 2,
                    "lw": 4, "lwu": 4, "sw": 4, "ld": 8, "sd": 8}.get(op, 0)] += 1
            imm = ins.getImmediate()
            imm = imm - 0x10000 if imm & 0x8000 else imm
            offsets[str(mips.reg(ins.rs))].append(imm)
    return {
        "target": {"vram": f"0x{vram:08X}", "size": size, "image": str(image_path),
                   "image_offset": f"0x{offset:X}"},
        "disassembly": mips.disassemble(code, vram),
        "callers": [f"0x{value:08X}" for value in callers],
        "callees": [f"0x{ref.address:08X}" for ref in refs if ref.kind == "call"],
        "globals": [{"site": f"0x{ref.site:08X}", "address": f"0x{ref.address:08X}",
                     "kind": ref.kind, "opcode": ref.opcode}
                    for ref in refs if ref.kind in {"load", "store", "addr"}],
        "access_widths": {str(key): value for key, value in sorted(widths.items()) if key},
        "base_offset_clusters": {key: sorted(set(value)) for key, value in offsets.items()
                                 if len(value) > 1},
        "neighbours": neighbours or [],
    }
