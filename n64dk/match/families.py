"""Additional source-variant families for ``iterate``: volatile, global declarations,
pointer forms and control flow.

These cover the residual classes that type/lifetime iteration cannot reach:

``volatile``  A volatile access is never reused by CSE, never hoisted out of a loop, never
              deleted, and (GCC 2.7.x ``reorg.c``: ``resource_conflicts_p`` returns true when
              either side is volatile) can never be placed in *any* delay slot.  So when retail
              keeps a store or load in front of a jump with a ``nop`` in the slot, or reloads a
              value it could have reused, the original source accessed that memory through a
              volatile-qualified type.  Variants qualify one pointer parameter, pointer local,
              cast, ``extern`` global or scalar local at a time.
``globals``   The declared type of a global decides load width and signedness, whether an
              access is an array index or a pointer load, and what may alias.  Variants change
              one referenced ``extern`` declaration: integer type, array vs pointer.
``pointer``   ``p[i]`` / ``*(p + i)`` and ``(*p).f`` / ``p->f`` spellings.
``control``   if/else inversion and loop forms (delegated to ``controlflow.variants``).

``volatile`` and ``globals`` change what the program means to the compiler and are always
marked ``semantic_review``: a volatile qualifier is legitimate when the memory really is
observed from outside (hardware registers, data shared with interrupt or DMA code); it is not
a way to force a match.  ``evidence_families`` says which families a residual justifies.
"""
from __future__ import annotations

import re

from .iterate import INT_TYPES, Variant, _function_span

EXTRA_FAMILIES = ("volatile", "globals", "pointer", "control")
_STORES = {"sb", "sh", "sw", "swc1", "sdc1", "sd"}
_LOADS = {"lb", "lbu", "lh", "lhu", "lw", "lwc1", "ldc1", "ld"}
_JUMPS = {"j", "jr", "jal", "jalr", "b", "beq", "bne", "beqz", "bnez", "blez", "bgtz", "bltz", "bgez",
          "beql", "bnel", "beqzl", "bnezl"}
_PARAM_POINTER = re.compile(r"(?<![\w*])((?:const\s+)?(?:(?:struct|union)\s+)?[A-Za-z_]\w*)(\s*\*+\s*)([A-Za-z_]\w*)(?=\s*[,)])")
_LOCAL_POINTER = re.compile(r"^(\s+)((?:const\s+)?(?:(?:struct|union)\s+)?[A-Za-z_]\w*)(\s*\*+\s*)([A-Za-z_]\w*)(\s*(?:=[^;]*)?;.*)$")
_LOCAL_SCALAR = re.compile(r"^(\s+)(s8|u8|s16|u16|s32|u32|f32|int|short|char|long)(\s+)([A-Za-z_]\w*)(\s*(?:=[^;]*)?;.*)$")
_CAST_POINTER = re.compile(r"\((?!volatile\b)((?:(?:struct|union)\s+)?[A-Za-z_]\w*)(\s*\*+)\)")
_EXTERN = re.compile(r"(?m)^(extern\s+)((?:const\s+)?(?:volatile\s+)?)((?:(?:struct|union)\s+)?[A-Za-z_]\w*)"
                     r"(\s*\**\s*)([A-Za-z_]\w*)(\s*(?:\[[^\]]*\])*)\s*;")
_KEYWORDS = {"return", "goto", "sizeof", "if", "while", "for", "switch", "case", "else", "do"}


def evidence_families(report: dict | None) -> list[str]:
    """Families justified by a diff report, most specific first."""
    entries = (report or {}).get("entries", [])
    out: list[str] = []

    def mnemonic(text):
        parts = (text or "").split()
        return parts[0] if parts else ""

    for index, entry in enumerate(entries):
        built, retail = mnemonic(entry.get("compiled")), mnemonic(entry.get("retail"))
        memory = _STORES | _LOADS
        # candidate filled a delay slot with a memory access where retail has a nop (or the reverse
        # position: retail keeps the access in front of the jump)
        if (built in memory and retail == "nop") or (retail in memory and not built):
            near = entries[max(0, index - 2):index + 3]
            if any(mnemonic(e.get("retail")) in _JUMPS or mnemonic(e.get("compiled")) in _JUMPS
                   or mnemonic(e.get("retail")) == "nop" for e in near) or built in memory:
                if "volatile" not in out:
                    out.append("volatile")
        if retail in _LOADS and not built and "globals" not in out:
            out.append("globals")              # retail reloads something the candidate reused
    counts = (report or {}).get("counts", {})
    if counts.get("branch") and "control" not in out:
        out.append("control")
    return out


def _referenced_externs(source: str, body: str, start: int):
    for found in _EXTERN.finditer(source[:start]):
        name = found.group(5)
        if re.search(rf"\b{re.escape(name)}\b", body):
            yield found


def variants(source: str, name: str, families=EXTRA_FAMILIES, limit: int = 24) -> list[Variant]:
    span = _function_span(source, name)
    if span is None:
        return []
    start, body_start, body_end = span
    head, signature, body, tail = source[:start], source[start:body_start], source[body_start:body_end], source[body_end:]
    lines = body.split("\n")
    out: list[Variant] = []

    def emit(label, family, text, review):
        if text != source:
            out.append(Variant(label, family, text, review))

    if "volatile" in families:
        for found in list(_PARAM_POINTER.finditer(signature))[:8]:
            kind, stars, param = found.group(1), found.group(2), found.group(3)
            if kind in _KEYWORDS:
                continue
            if "volatile" in kind or signature[max(0, found.start() - 9):found.start()].rstrip().endswith("volatile"):
                new = signature[:found.start()] + kind.replace("volatile ", "") + stars + param + signature[found.end():]
                new = re.sub(r"volatile\s+(?=" + re.escape(kind) + r"\s*\*)", "", new, count=1)
                emit(f"parameter {param}: drop volatile", "volatile", head + new + body + tail, True)
            else:
                new = signature[:found.start()] + "volatile " + kind + stars + param + signature[found.end():]
                emit(f"parameter {param}: pointer to volatile", "volatile", head + new + body + tail, True)
        count = 0
        for index, line in enumerate(lines):
            found = _LOCAL_POINTER.match(line)
            if found and found.group(2) not in _KEYWORDS and "volatile" not in line and count < limit:
                changed = list(lines)
                changed[index] = f"{found.group(1)}volatile {found.group(2)}{found.group(3)}{found.group(4)}{found.group(5)}"
                emit(f"local {found.group(4)}: pointer to volatile", "volatile", head + signature + "\n".join(changed) + tail, True)
                count += 1
                continue
            found = _LOCAL_SCALAR.match(line)
            if found and "volatile" not in line and count < limit:
                changed = list(lines)
                changed[index] = f"{found.group(1)}volatile {found.group(2)}{found.group(3)}{found.group(4)}{found.group(5)}"
                emit(f"local {found.group(4)}: volatile scalar", "volatile", head + signature + "\n".join(changed) + tail, True)
                count += 1
        for number, found in enumerate(list(_CAST_POINTER.finditer(body))[:limit]):
            if found.group(1) in _KEYWORDS:
                continue
            line_no = body.count("\n", 0, found.start()) + 1
            changed = body[:found.start()] + f"(volatile {found.group(1)}{found.group(2)})" + body[found.end():]
            emit(f"cast #{number + 1} line {line_no}: {found.group(0)} -> volatile", "volatile",
                 head + signature + changed + tail, True)
        for found in list(_referenced_externs(source, body, start))[:limit]:
            if "volatile" in found.group(2):
                replacement = found.group(1) + found.group(2).replace("volatile ", "") + found.group(3)
                label = f"global {found.group(5)}: drop volatile"
            else:
                replacement = found.group(1) + found.group(2) + "volatile " + found.group(3)
                label = f"global {found.group(5)}: volatile"
            text = source[:found.start()] + replacement + found.group(4) + found.group(5) + found.group(6) + ";" \
                + source[found.end():]
            emit(label, "volatile", text, True)

    if "globals" in families:
        for found in list(_referenced_externs(source, body, start))[:limit]:
            prefix, qualifiers, kind, stars, symbol, dims = found.groups()
            def rewrite(new_kind=kind, new_stars=stars, new_dims=dims):
                return (source[:found.start()] + prefix + qualifiers + new_kind
                        + (new_stars if new_stars.strip() else " ") + symbol + new_dims + ";" + source[found.end():])
            if kind in INT_TYPES and not stars.strip():
                for other in INT_TYPES:
                    if other != kind:
                        emit(f"global {symbol}: {kind} -> {other}", "globals", rewrite(new_kind=other), True)
            if dims.strip() == "[]" and not stars.strip():
                emit(f"global {symbol}: array -> pointer", "globals", rewrite(new_stars=" *", new_dims=""), True)
            elif stars.strip() == "*" and not dims.strip():
                emit(f"global {symbol}: pointer -> array", "globals", rewrite(new_stars=" ", new_dims="[]"), True)
            elif not stars.strip() and not dims.strip() and kind in INT_TYPES:
                emit(f"global {symbol}: scalar -> array", "globals", rewrite(new_dims="[]"), True)

    if "pointer" in families:
        forms = ((re.compile(r"\*\(\s*([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*|\d+)\s*\)"), lambda m: f"{m[1]}[{m[2]}]",
                  "deref-sum to index"),
                 (re.compile(r"(?<![\w.>\]])([A-Za-z_]\w*)\[([A-Za-z_]\w*|\d+)\](?!\s*\[)"), lambda m: f"*({m[1]} + {m[2]})",
                  "index to deref-sum"),
                 (re.compile(r"\(\*\s*([A-Za-z_]\w*)\s*\)\.([A-Za-z_]\w*)"), lambda m: f"{m[1]}->{m[2]}", "(*p).f to p->f"),
                 (re.compile(r"(?<![\w.>\]])([A-Za-z_]\w*)->([A-Za-z_]\w*)"), lambda m: f"(*{m[1]}).{m[2]}", "p->f to (*p).f"))
        for pattern, replacement, label in forms:
            for number, found in enumerate(list(pattern.finditer(body))[:12]):
                if found.group(1) in _KEYWORDS or found.group(1) in INT_TYPES:
                    continue
                changed = body[:found.start()] + replacement(found) + body[found.end():]
                emit(f"{label} #{number + 1}", "pointer", head + signature + changed + tail, False)

    if "control" in families:
        try:
            from .controlflow import variants as control_variants
            for item in control_variants(body, limit):
                text = item.get("source")
                if text:
                    emit("control: " + str(item.get("form") or item.get("label") or "form"), "control",
                         head + signature + text + tail, True)
        except Exception:                 # controlflow is optional context, never a reason to fail
            pass
    seen, unique = set(), []
    for item in out:
        if item.source not in seen:
            seen.add(item.source)
            unique.append(item)
    return unique
