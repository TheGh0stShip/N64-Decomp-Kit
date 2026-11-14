"""Evidence-bounded ABI, narrowing, value-lifetime and residual-window exploration."""
from __future__ import annotations

import hashlib
import keyword
import re
from pathlib import Path

from .. import mips


DECLARATION = re.compile(
    r"(?m)^(?P<indent>\s*)(?P<prefix>(?:extern\s+|static\s+)?)"
    r"(?P<return>[A-Za-z_]\w*(?:\s*\*)?)\s+(?P<name>[A-Za-z_]\w*)\s*"
    r"\((?P<args>[^)]*)\)\s*;\s*$")


def source_shape(source: str) -> str:
    """Identifier-normalized source fingerprint used only as equivalence evidence."""
    reserved = set(keyword.kwlist) | {"void", "char", "short", "int", "long", "signed", "unsigned",
                                       "s8", "u8", "s16", "u16", "s32", "u32", "float", "double",
                                       "return", "if", "else", "while", "do", "for", "switch", "case"}
    mapping = {}
    def replace(found):
        value = found.group(0)
        if value in reserved or value.startswith("func_") or value.startswith("D_"): return value
        mapping.setdefault(value, f"id{len(mapping)}")
        return mapping[value]
    normalized = re.sub(r"\b[A-Za-z_]\w*\b", replace, re.sub(r"/\*.*?\*/|//[^\n]*", "", source,
                                                               flags=re.S))
    return hashlib.sha256(re.sub(r"\s+", " ", normalized).encode()).hexdigest()


def declaration_context(source: str, symbol: str) -> list[dict]:
    result = []
    for found in DECLARATION.finditer(source):
        if found.group("name") != symbol: continue
        args = found.group("args").strip()
        result.append({"text": found.group(0).strip(), "return": found.group("return").strip(),
                       "arguments": args, "style": "old-style" if not args else "ansi",
                       "line": source[:found.start()].count("\n") + 1})
    return result


def prototype_variants(source: str, symbol: str, return_types: list[str], budget: int = 96) -> list[dict]:
    declarations = [found for found in DECLARATION.finditer(source) if found.group("name") == symbol]
    if not declarations: return []
    target = declarations[0]
    argument_forms = ["void", "s32 arg0", "s16 arg0", "u16 arg0", "void *arg0", ""]
    variants = []
    bases = []
    for return_type in return_types:
        for arguments in argument_forms:
            style = "old-style" if arguments == "" else "ansi"
            replacement = (target.group("indent") + target.group("prefix") + return_type + " " + symbol +
                           "(" + arguments + ");")
            candidate = source[:target.start()] + replacement + source[target.end():]
            item = {"label": f"return={return_type},args={arguments or 'unspecified'}",
                             "source": candidate, "family": "prototype", "axes": {
                                 "return": return_type, "arguments": arguments, "style": style,
                                 "declaration_placement": "original"}}
            variants.append(item); bases.append(item)
            if len(variants) >= budget: return variants
    # Historically plausible implicit declaration: remove only the prototype, never a definition.
    implicit = source[:target.start()] + source[target.end():]
    variants.append({"label": "implicit-declaration", "source": implicit,
                     "family": "prototype", "axes": {"style": "implicit", "return": "implicit-int"}})
    # Declaration placement can influence old compilers; move the declaration immediately before the definition.
    without = source[:target.start()] + source[target.end():]
    function = re.search(r"(?m)^[A-Za-z_]\w*(?:\s*\*)?\s+func_[0-9A-Fa-f]{8}\s*\(", without)
    if function:
        moved = without[:function.start()] + target.group(0).strip() + "\n" + without[function.start():]
        variants.append({"label": "declaration-near-definition", "source": moved,
                         "family": "declaration-context", "axes": {"declaration_placement": "near-definition"}})
    # Cross plausible prototypes with how the caller owns and consumes the result.
    for base in bases:
        bare = re.search(rf"(?m)^(\s*){re.escape(symbol)}\s*(\([^;]*\))\s*;\s*$", base["source"])
        if bare:
            indent, call_args = bare.groups()
            for form, replacement in (
                ("ignored", f"{indent}(void){symbol}{call_args};"),
                ("assigned-wide", f"{indent}s32 prototype_result = {symbol}{call_args};"),
                ("assigned-narrow", f"{indent}s16 prototype_result = (s16){symbol}{call_args};")):
                candidate = base["source"][:bare.start()] + replacement + base["source"][bare.end():]
                variants.append({"label": base["label"] + ",call=" + form, "source": candidate,
                                 "family": "prototype-call-use", "axes": {**base["axes"], "call_use": form}})
                if len(variants) >= budget: return variants
        assigned = re.search(rf"(?m)^(\s*)([A-Za-z_]\w*)\s*=\s*{re.escape(symbol)}\s*(\([^;]*\))\s*;", base["source"])
        if not assigned:
            assigned = re.search(rf"(?m)^(\s*)(?:s32|s16|u16|int)\s+([A-Za-z_]\w*)\s*=\s*"
                                 rf"{re.escape(symbol)}\s*(\([^;]*\))\s*;", base["source"])
        if assigned:
            indent, carrier, call_args = assigned.groups()
            replacement = f"{indent}{carrier} = (s16){symbol}{call_args};"
            variants.append({"label": base["label"] + ",call=narrowed-assignment",
                             "source": base["source"][:assigned.start()] + replacement + base["source"][assigned.end():],
                             "family": "prototype-call-use", "axes": {**base["axes"], "call_use": "narrowed"}})
            if len(variants) >= budget: return variants
    return variants[:budget]


def narrowing_variants(source: str, budget: int = 48) -> list[dict]:
    result = []
    assignments = list(re.finditer(r"(?m)^(\s*)((?:s32|s16|u16|int)\s+)?"
                                   r"([A-Za-z_]\w*)\s*=\s*([^;]+);\s*$", source))
    for index, found in enumerate(assignments):
        indent, declaration, name, expression = found.groups(); prefix = indent + (declaration or "")
        forms = {
            "signed-cast": f"{prefix}{name} = (s16)({expression});",
            "shift-sign-extension": f"{prefix}{name} = ((s32)({expression}) << 16) >> 16;",
            "unsigned-then-signed": f"{prefix}{name} = (s16)(u16)({expression});",
            "narrow-local": ((f"{prefix}{name};\n" if declaration else "") +
                             f"{indent}{{ s16 narrowed = (s16)({expression}); {name} = narrowed; }}"),
            "union-member": ((f"{prefix}{name};\n" if declaration else "") +
                             f"{indent}{{ union {{ s32 word; s16 half[2]; }} narrow; "
                             f"narrow.word = (s32)({expression}) << 16; {name} = narrow.half[0]; }}"),
        }
        for label, replacement in forms.items():
            candidate = source[:found.start()] + replacement + source[found.end():]
            result.append({"label": f"{label}-{index + 1}", "source": candidate,
                           "family": "narrowing", "axes": {"narrowing": label,
                           "barrier_position": "assignment"}})
            if len(result) >= budget: return result
    return result


def lifetime_graph(outcome: dict, context: dict | None = None) -> dict:
    entries = outcome.get("diff", {}).get("entries", [])
    instructions = "\n".join(str(row.get("retail") or row.get("compiled") or "") for row in entries)
    if context and context.get("rom") and context.get("addr") is not None:
        path = Path(context["rom"]); offset = int(context["addr"]) - int(context.get("vram_delta", 0))
        if path.is_file() and 0 <= offset <= path.stat().st_size - int(context.get("size", 0)):
            data = path.read_bytes()[offset:offset + int(context["size"])]
            instructions += "\n" + "\n".join(ins.disassemble() for ins in mips.instructions(data, int(context["addr"])))
    nodes, constraints = [], []
    if "jal" in instructions: nodes.append({"id": "call-result", "producer": "jal/$v0"})
    if re.search(r"(?:move\s+\$s[0-7],\s*\$v0|addu\s+\$s[0-7],\s*\$v0,\s*\$zero)", instructions):
        nodes.append({"id": "preserved-result", "storage": "callee-saved register"})
        constraints.append("call result remains live across a later call")
    if "sll" in instructions and "sra" in instructions:
        nodes.append({"id": "narrowed-result", "mode": "signed-16"})
        constraints.append("narrow after ownership transfer and materialize a distinct value")
    if re.search(r"\bbnez?\b|\bbeqz?\b", instructions): constraints.append("narrowed value controls a branch")
    if re.search(r"\b(?:addu|ori)\s+\$v0,\s*\$zero", instructions): constraints.append("function result is independent")
    return {"nodes": nodes, "constraints": constraints,
            "call_barrier": "jal" in instructions, "signed_narrowing": "sra" in instructions}


def lifetime_variants(source: str, graph: dict, budget: int = 48) -> list[dict]:
    result = []
    initialized = list(re.finditer(r"(?m)^(\s*)(s32|s16|u16|int)\s+([A-Za-z_]\w*)\s*=\s*"
                                       r"(func_[0-9A-Fa-f]{8}\s*\([^;]*\))\s*;", source))
    for index, found in enumerate(initialized):
        indent, typename, name, call = found.groups()
        forms = {
            "separate-call-result": f"{indent}{typename} {name};\n{indent}{name} = {call};",
            "narrow-at-ownership": f"{indent}s16 {name} = (s16){call};",
            "wide-carrier-narrow-use": f"{indent}s32 {name} = {call};",
        }
        for label, replacement in forms.items():
            result.append({"label": f"{label}-{index + 1}",
                           "source": source[:found.start()] + replacement + source[found.end():],
                           "family": "value-lifetime", "axes": {"ownership": label,
                           "call_barrier": graph.get("call_barrier")}, "graph": graph})
            if len(result) >= budget: return result
    declarations = list(re.finditer(r"(?m)^(\s*)(s32|s16|u16|int)\s+([A-Za-z_]\w*)\s*;\s*$", source))
    for index, found in enumerate(declarations):
        indent, typename, name = found.groups()
        for replacement_type in ("s16", "s32", "u16"):
            candidate = source[:found.start(2)] + replacement_type + source[found.end(2):]
            result.append({"label": f"carrier-{name}-{replacement_type}", "source": candidate,
                           "family": "value-lifetime", "axes": {"carrier": replacement_type,
                           "ownership": "named-local", "scope": "function"}, "graph": graph})
        if len(result) >= budget: break
    return result[:budget]


def residual_offsets(outcome: dict) -> set[int]:
    result = set()
    for row in outcome.get("diff", {}).get("entries", []):
        value = row.get("target_offset", row.get("offset"))
        if isinstance(value, int): result.add(value)
    return result
