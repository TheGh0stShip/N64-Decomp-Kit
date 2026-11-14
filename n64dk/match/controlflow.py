"""Residual branch-target classification and bounded ordinary-C control-flow forms."""
from __future__ import annotations

import re
from pathlib import Path

from .. import mips


_SIMPLE_IF = re.compile(r"(?s)if\s*\((?P<cond>[^{};]+)\)\s*\{(?P<body>[^{}]+)\}")
_SIMPLE_WHILE = re.compile(r"(?s)while\s*\((?P<cond>[^{};]+)\)\s*\{(?P<body>[^{}]+)\}")


def classify_branches(context: dict, outcome: dict) -> list[dict]:
    path = Path(context["rom"]); data = path.read_bytes()
    address, size = int(context["addr"]), int(context["size"])
    offset = address - int(context["vram_delta"])
    code = data[offset:offset + size]
    instructions = list(mips.instructions(code, address))
    by_offset = {ins.vram - address: ins for ins in instructions}
    result = []
    entries = outcome.get("diff", {}).get("entries", [])
    for entry in entries:
        site_offset = entry.get("target_offset", entry.get("offset"))
        ins = by_offset.get(site_offset)
        if ins is None or not ins.isBranch():
            continue
        target = ins.getBranchVramGeneric(); site = address + site_offset
        between = [row for row in instructions if site < row.vram < target]
        if target < site:
            classification = "loop-latch"
        elif target >= address + size:
            classification = "loop-exit"
        elif any(row.isJrRa() for row in instructions if row.vram >= target):
            distance_to_return = min((row.vram - target for row in instructions
                                      if row.vram >= target and row.isJrRa()), default=9999)
            classification = "function-epilogue" if distance_to_return <= 16 else "loop-exit"
        elif any(row.doesLink() for row in between):
            classification = "call-skipping-join"
        elif target - site <= 16:
            classification = "same-basic-block"
        else:
            classification = "shared-cleanup"
        hypotheses = (["goto shared exit", "break", "continue", "early return"]
                      if classification in {"loop-exit", "function-epilogue", "shared-cleanup"}
                      else ["inverted if", "skip-body if"])
        result.append({"site": f"0x{site:08X}", "target": f"0x{target:08X}",
                       "classification": classification, "compiled": entry.get("compiled"),
                       "retail": entry.get("retail"), "hypotheses": hypotheses})
    return result


def variants(source: str, limit: int = 32) -> list[dict]:
    """Generate bounded forms around simple if bodies; every result remains ordinary C."""
    output = []
    labels = re.findall(r"(?m)^\s*([A-Za-z_]\w*)\s*:\s*$", source)
    for index, found in enumerate(_SIMPLE_IF.finditer(source)):
        cond, body = found.group("cond").strip(), found.group("body")
        prefix, suffix = source[:found.start()], source[found.end():]
        forms = {
            "inverted-if": f"if (!({cond})) {{\n    /* join */\n}} else {{{body}}}",
            "skip-body-if": f"if ({cond}) {{{body}}}",
            "break": f"if (!({cond})) {{ break; }}\n{body}",
            "continue": f"if (!({cond})) {{ continue; }}\n{body}",
        }
        if labels:
            forms["goto-shared-exit"] = f"if (!({cond})) {{ goto {labels[-1]}; }}\n{body}"
        # A void early-return form is offered only when the retained source declares void.
        if re.search(r"\bvoid\s+[A-Za-z_]\w*\s*\(", source):
            forms["early-return"] = f"if (!({cond})) {{ return; }}\n{body}"
        for name, replacement in forms.items():
            candidate = prefix + replacement + suffix
            if candidate != source:
                output.append({"label": f"{name}-{index + 1}", "source": candidate,
                               "form": name})
                if len(output) >= limit:
                    return output
    # Directly transfer proven break/continue spellings to an existing shared label.
    if labels:
        for keyword in ("break", "continue"):
            for index, found in enumerate(re.finditer(rf"\b{keyword}\s*;", source)):
                candidate = source[:found.start()] + f"goto {labels[-1]};" + source[found.end():]
                output.append({"label": f"{keyword}-to-goto-{index + 1}", "source": candidate,
                               "form": "goto-shared-exit"})
                if len(output) >= limit: return output
    for index, found in enumerate(_SIMPLE_WHILE.finditer(source)):
        cond, body = found.group("cond").strip(), found.group("body")
        prefix, suffix = source[:found.start()], source[found.end():]
        loop_label, exit_label = f"n64dk_loop_{index}", f"n64dk_exit_{index}"
        forms = {
            "do-while": f"if ({cond}) {{ do {{{body}}} while ({cond}); }}",
            "loop-with-label": (f"{loop_label}:\nif (!({cond})) goto {exit_label};\n"
                                f"{body}\ngoto {loop_label};\n{exit_label}: ;"),
            "for-loop": f"for (; {cond}; ) {{{body}}}",
        }
        for name, replacement in forms.items():
            output.append({"label": f"{name}-{index + 1}", "source": prefix + replacement + suffix,
                           "form": name})
            if len(output) >= limit: return output
    return output
