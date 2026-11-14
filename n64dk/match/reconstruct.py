"""Evidence-backed starter source, shared layouts and project-wide ABI constraints."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .. import mips


def scaffold(name: str, code: bytes, vram: int) -> tuple[str, dict]:
    instructions = list(mips.instructions(code, vram)); arguments = set(); calls = []; offsets = []
    returns_value = False
    for ins in instructions:
        text = ins.disassemble()
        for match in re.finditer(r"\$a([0-3])", text): arguments.add(int(match.group(1)))
        if ins.getOpcodeName() == "jal": calls.append(text.split()[-1])
        if ins.getOpcodeName() in {"lw", "lh", "lhu", "lb", "lbu", "sw", "sh", "sb"}:
            offsets.append({"opcode": ins.getOpcodeName(), "offset": ins.getImmediate()})
        if re.search(r"\$v0", text) and not ins.isJrRa(): returns_value = True
    count = max(arguments, default=-1) + 1
    parameters = ", ".join(f"s32 arg{index}" for index in range(count)) or "void"
    return_type = "s32" if returns_value else "void"
    body = []
    for index in range(count): body.append(f"    (void)arg{index};")
    if return_type != "void": body.append("    return 0;")
    source = '#include "types.h"\n\n' + f"{return_type} {name}({parameters}) {{\n" + "\n".join(body) + "\n}\n"
    evidence = {"function": name, "vram": f"0x{vram:08X}", "arguments": count,
                "return_type": return_type, "calls": calls, "memory_accesses": offsets,
                "confidence": {"arguments": 0.55, "return_type": 0.45},
                "source_digest": hashlib.sha256(source.encode()).hexdigest()}
    return source, evidence


def shared_layout(observations: list[dict]) -> dict:
    fields = {}
    widths = {"lb": (1, "s8"), "lbu": (1, "u8"), "sb": (1, "u8"),
              "lh": (2, "s16"), "lhu": (2, "u16"), "sh": (2, "u16"),
              "lw": (4, "s32"), "sw": (4, "s32")}
    for observation in observations:
        for item in observation.get("memory_accesses", []):
            width, typename = widths.get(item["opcode"], (4, "u32")); offset = int(item["offset"])
            row = fields.setdefault(offset, {"offset": offset, "widths": set(), "types": set(),
                "reads": 0, "writes": 0, "functions": set()})
            row["widths"].add(width); row["types"].add(typename); row["functions"].add(observation["function"])
            row["writes" if item["opcode"].startswith("s") else "reads"] += 1
    output = []
    for offset, row in sorted(fields.items()):
        output.append({**row, "widths": sorted(row["widths"]), "types": sorted(row["types"]),
                       "functions": sorted(row["functions"]), "conflict": len(row["widths"]) > 1})
    return {"fields": output, "conflicts": [row for row in output if row["conflict"]],
            "candidate": "shared object layout; review pointer provenance before emitting a struct"}


def prototype_constraints(project: Path) -> dict:
    declaration = re.compile(r"(?m)^\s*(?:extern\s+|static\s+)?([A-Za-z_]\w*(?:\s*\*)?)\s+"
                             r"(func_[0-9A-Fa-f]{8})\s*\(([^)]*)\)\s*;")
    grouped = {}
    for root in (project / "src", project / "include"):
        if not root.is_dir(): continue
        for path in list(root.rglob("*.c")) + list(root.rglob("*.h")):
            text = path.read_text(errors="replace")
            for found in declaration.finditer(text):
                return_type, symbol, arguments = found.groups()
                grouped.setdefault(symbol, []).append({"return_type": return_type,
                    "arguments": arguments.strip(), "path": str(path.relative_to(project))})
    result = []
    for symbol, evidence in sorted(grouped.items()):
        forms = {(row["return_type"], row["arguments"]) for row in evidence}
        result.append({"symbol": symbol, "constraints": evidence, "conflict": len(forms) > 1,
                       "recommended": max(forms, key=lambda form: sum((row["return_type"], row["arguments"]) == form
                                                                      for row in evidence))})
    return {"symbols": len(result), "conflicts": [row for row in result if row["conflict"]], "results": result}
