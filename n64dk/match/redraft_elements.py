"""Pointer sums a decompiler wrote in bytes, written in elements.

``&D_80100000 + (i * 8)`` with ``extern s32 D_80100000`` means bytes; C scales it by four.  One
repair is to cast to a byte pointer (the optimised-build generators do).  The other is to say
what the programmer most likely wrote, an index: ``&D_80100000 + (i * 2)``.  The two compile to
the same code under GCC.  Under IDO they do not: the cast changes the shape of the expression
tree and with it the temporary registers IDO hands out, so only the element form reproduces the
target.  This generator offers the element form where every byte multiplier and offset divides
evenly by the element size.
"""
from __future__ import annotations

import re

SIZES = {"s16": 2, "u16": 2, "short": 2, "s32": 4, "u32": 4, "f32": 4, "int": 4, "long": 4, "float": 4,
         "M2C_UNK": 4, "s64": 8, "u64": 8, "f64": 8, "double": 8}
_WORD = r"[A-Za-z_]\w*"
_NUMBER = r"(?:0x[0-9A-Fa-f]+|\d+)"
_DECL = re.compile(rf"^[ \t]*(?:extern\s+|static\s+|register\s+|volatile\s+|const\s+)*(?:unsigned\s+|signed\s+)?"
                   rf"({_WORD})\s*(\**)\s*({_WORD})\s*(\[[^\]]*\])?\s*(?:=[^;]*)?;", re.M)
_PARAM = re.compile(rf"(?:unsigned\s+|signed\s+)?({_WORD})\s*(\*+)\s*({_WORD})\s*(?=[,)])")
_TERM = rf"(?:{_WORD}|\((?:[^()]|\([^()]*\))*\))"


def element_sizes(text: str) -> dict[str, tuple[int, bool]]:
    """``{name: (element size, written with '&')}`` for names whose pointer arithmetic C scales."""
    found: dict[str, tuple[int, bool]] = {}
    for match in _DECL.finditer(text):
        base, stars, name, array = match.groups()
        if stars:
            size = SIZES.get(base) if len(stars) == 1 else 4
            if size:
                found[name] = (size, False)
        elif base in SIZES:
            found[name] = (SIZES[base], array is None)
    for match in _PARAM.finditer(text):
        base, stars, name = match.groups()
        size = SIZES.get(base) if len(stars) == 1 else 4
        if size:
            found[name] = (size, False)
    return found


def _literal(value: int, like: str) -> str:
    return hex(value).replace("0x", "0x").upper().replace("0X", "0x") if like.lower().startswith("0x") and value > 9 \
        else str(value)


def rewrite(text: str) -> tuple[str, int]:
    """Every byte-scaled sum on a sized pointer in elements; the text and how many were changed.
    Nothing is changed unless every such sum in the function divides evenly."""
    sizes = element_sizes(text)
    if not sizes:
        return text, 0
    start = text.rfind("#endif")
    head, body = (text[:start], text[start:]) if start >= 0 else ("", text)
    changed, uneven = 0, False

    def pointer(amp: str, name: str) -> int | None:
        entry = sizes.get(name)
        return entry[0] if entry and entry[1] == bool(amp) else None

    def scaled(term: str, number: str, size: int) -> str | None:
        value = int(number, 0)
        if value % size:
            return None
        quotient = value // size
        return term if quotient == 1 else f"({term} * {_literal(quotient, number)})"

    def product_right(match):                                 # P + (X * C)
        nonlocal changed, uneven
        amp, name, term, number = match.group(1), match.group(2), match.group(3), match.group(4)
        size = pointer(amp, name)
        if size is None:
            return match.group(0)
        new = scaled(term, number, size)
        if new is None:
            uneven = True
            return match.group(0)
        changed += 1
        return f"{amp}{name} + {new}"

    def product_left(match):                                  # (X * C) + P
        nonlocal changed, uneven
        term, number, amp, name = match.group(1), match.group(2), match.group(3), match.group(4)
        size = pointer(amp, name)
        if size is None:
            return match.group(0)
        new = scaled(term, number, size)
        if new is None:
            uneven = True
            return match.group(0)
        changed += 1
        return f"{new} + {amp}{name}"

    def constant(match):                                      # P + C
        nonlocal changed, uneven
        amp, name, number = match.group(1), match.group(2), match.group(3)
        size = pointer(amp, name)
        if size is None:
            return match.group(0)
        value = int(number, 0)
        if value % size:
            uneven = True
            return match.group(0)
        changed += 1
        return f"{amp}{name} + {_literal(value // size, number)}"

    guard = r"(?<![\w)\]>.*])"                                # not a member, an index, a cast operand or a dereference
    body = re.sub(rf"{guard}(&?)({_WORD})\s*\+\s*\(\s*({_TERM})\s*\*\s*({_NUMBER})\s*\)", product_right, body)
    body = re.sub(rf"\(\s*({_TERM})\s*\*\s*({_NUMBER})\s*\)\s*\+\s*(&?)({_WORD})\b(?![\[(.]|->)", product_left, body)
    body = re.sub(rf"{guard}(&?)({_WORD})\s*\+\s*({_NUMBER})\b(?!\s*\*)", constant, body)
    if uneven or not changed:
        return text, 0
    return head + body, changed


def variants(source: str, name: str, **_context) -> list[tuple[str, str]]:
    """[(label, text)] for a draft that has byte-scaled pointer sums.  Offered for every compiler:
    IDO needs this form, and on six GCC titles it matched 4 of the 80 drafts it applied to that
    the byte-cast form had not."""
    try:
        text, changed = rewrite(source)
    except Exception:                                        # noqa: BLE001 - a rewrite is optional
        return []
    return [("elements", text)] if changed and text != source else []
