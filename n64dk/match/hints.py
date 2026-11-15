"""Residual-to-source hints: a symptom table instead of six generic suggestions.

``hypotheses.suggest`` looks only at residual *class counts*.  The rules here look at the
aligned instruction pairs of a ``diff.Report`` (or its ``as_dict()``) and name the concrete
C-level cause documented for these compilers.  Each hint carries the compiler family it
applies to (``ido``, ``gcc`` = KMC/SN GCC 2.7-2.8, or ``any``) and the offsets that triggered
it, so a contributor or automation client can try the single most specific lever first.  Hints are leads to test with a
compile, not transformations to apply blindly.
"""
from __future__ import annotations

import re

# (compiled mnemonic, retail mnemonic) -> (hint id, text, family)
_PAIR = {
    ("lh", "lhu"): ("u16-load", "field/variable is u16, not s16", "any"),
    ("lhu", "lh"): ("s16-load", "field/variable is s16, not u16", "any"),
    ("lb", "lbu"): ("u8-load", "field/variable is u8, not s8/char", "any"),
    ("lbu", "lb"): ("s8-load", "field/variable is s8 (or plain char with -fsigned-char), not u8", "any"),
    ("slt", "sltu"): ("unsigned-compare", "comparison operands are unsigned (u32/pointer)", "any"),
    ("sltu", "slt"): ("signed-compare", "comparison operands are signed", "any"),
    ("slti", "sltiu"): ("unsigned-compare", "comparison against a constant is unsigned; "
                        "a range check `x >= A && x < B` compiles to `(u32)(x - A) < N`", "any"),
    ("sltiu", "slti"): ("signed-compare", "comparison against a constant is signed", "any"),
    ("sra", "srl"): ("unsigned-shift", "shifted value is unsigned (u32, or a u16/u8 zero-extension)", "any"),
    ("srl", "sra"): ("signed-shift", "shifted value is signed (s32, or an s16/s8 sign-extension)", "any"),
    ("div", "divu"): ("unsigned-divide", "division/modulo operands are unsigned", "any"),
    ("divu", "div"): ("signed-divide", "division/modulo operands are signed", "any"),
    ("mult", "multu"): ("unsigned-multiply", "multiplication operands are unsigned", "any"),
    ("multu", "mult"): ("signed-multiply", "multiplication operands are signed", "any"),
    ("addiu", "ori"): ("unsigned-constant", "constant is unsigned/>= 0x8000 (`li` expanded as ori): "
                       "use a U suffix or an unsigned variable", "any"),
    ("ori", "addiu"): ("signed-constant", "constant is a signed 16-bit value", "any"),
    ("beq", "bne"): ("inverted-branch", "condition is inverted: swap the if/else arms, use an early "
                     "return/continue, or negate the test", "any"),
    ("bne", "beq"): ("inverted-branch", "condition is inverted: swap the if/else arms, use an early "
                     "return/continue, or negate the test", "any"),
    ("c.lt.s", "c.le.s"): ("float-compare-form", "float comparison is the negation of the other form "
                           "(`a < b` vs `!(a >= b)`); swap operands or arms", "any"),
    ("c.le.s", "c.lt.s"): ("float-compare-form", "float comparison is the negation of the other form", "any"),
    ("j", "b"): ("compiler-family", "retail uses `b` for unconditional branches: this is IDO output, "
                 "not GCC", "any"),
    ("b", "j"): ("compiler-family", "retail uses `j` for unconditional branches: this is GCC (KMC/SN) "
                 "output, not IDO", "any"),
    ("lw", "lh"): ("width", "retail loads 16 bits where the candidate loads 32: field is s16", "any"),
    ("lw", "lhu"): ("width", "retail loads 16 bits where the candidate loads 32: field is u16", "any"),
    ("lw", "lbu"): ("width", "retail loads 8 bits where the candidate loads 32: field is u8", "any"),
    ("sw", "sh"): ("width", "retail stores 16 bits: destination field is 16-bit", "any"),
    ("sw", "sb"): ("width", "retail stores 8 bits: destination field is 8-bit", "any"),
    ("lwc1", "lw"): ("float-vs-int", "retail treats the field as an integer, candidate as float", "any"),
    ("lw", "lwc1"): ("float-vs-int", "retail treats the field as float, candidate as an integer", "any"),
}

_LIKELY = {"beql", "bnel", "beqzl", "bnezl", "bgezl", "bltzl", "blezl", "bgtzl"}
_SP = re.compile(r"^addiu \$sp, \$sp, (-?0x[0-9A-Fa-f]+|-?\d+)$")
_SHIFT = re.compile(r"^(sll|sra|srl) (\$\w+), (\$\w+), (0x[0-9A-Fa-f]+|\d+)$")


def _mn(text: str) -> str:
    return text.split(None, 1)[0] if text else ""


def _norm(text: str) -> str:
    return " ".join(text.split())


def hints(report, family: str = "any") -> list[dict]:
    """``report`` is a ``diff.Report`` or its ``as_dict()``; ``family`` is ``ido``/``gcc``/``any``."""
    data = report if isinstance(report, dict) else report.as_dict(limit=10 ** 6)
    entries = data.get("entries", [])
    found: dict[str, dict] = {}

    def add(key, text, fam, offset, confidence=0.7):
        if family != "any" and fam not in ("any", family):
            return
        row = found.setdefault(key, {"hint": key, "try": text, "family": fam, "confidence": confidence,
                                     "offsets": []})
        if offset is not None and len(row["offsets"]) < 8:
            row["offsets"].append(f"0x{offset:X}")

    retail_only, compiled_only = [], []
    for e in entries:
        c, r = _norm(e.get("compiled") or ""), _norm(e.get("retail") or "")
        off = e.get("target_offset") if e.get("target_offset") is not None else e.get("offset")
        cm, rm = _mn(c), _mn(r)
        if c and r and (cm, rm) in _PAIR:
            key, text, fam = _PAIR[(cm, rm)]
            add(key, text, fam, off, 0.85)
        if c and r:
            a, b = _SP.match(c), _SP.match(r)
            if a and b and int(a.group(1), 0) < 0:
                mine, theirs = -int(a.group(1), 0), -int(b.group(1), 0)
                if theirs > mine:
                    add("frame-too-small", f"retail frame is {theirs - mine} bytes larger: a local is missing "
                        "(IDO: unused/pad local, ternary or `x++` in a condition creates a temp, address-taken "
                        "local; GCC: a value lives across a call or a struct/array local is larger)", "any", off, 0.8)
                elif mine > theirs:
                    add("frame-too-large", f"candidate frame is {mine - theirs} bytes larger: remove a temporary, "
                        "avoid taking a local's address, or (IDO) move register-allocated locals to the end of "
                        "the declarations", "any", off, 0.8)
            if (rm in _LIKELY) != (cm in _LIKELY) and rm and cm:
                add("branch-likely", "branch-likely form differs: invert the condition / swap arms; on IDO check "
                    "-mips2 vs -mips1 and that the block is not duplicated by a `goto`-style source", "any", off)
        if r and not c:
            retail_only.append((off, r))
        if c and not r:
            compiled_only.append((off, c))
        if e.get("kind") == "immediate" and cm == rm == "jal":
            add("callee", "call target differs: wrong callee symbol or address", "any", off, 0.95)

    def extension(rows, side):
        for (o1, a), (_o2, b) in zip(rows, rows[1:]):
            x, y = _SHIFT.match(a), _SHIFT.match(b)
            if x and y and x.group(1) == "sll" and x.group(4) == y.group(4):
                bits = 32 - int(x.group(4), 0)
                kind = "s" if y.group(1) == "sra" else "u"
                if bits in (8, 16):
                    verb = "add" if side == "retail" else "remove"
                    add(f"{verb}-{kind}{bits}-cast", f"{verb} a ({kind}{bits}) conversion: retail "
                        f"{'has' if side == 'retail' else 'lacks'} the sll/{y.group(1)} {32 - bits} pair "
                        "(declare the local/parameter/return with that type, or drop the narrower type)",
                        "any", o1, 0.85)
        for off, text in rows:
            m = re.match(r"^andi (\$\w+), (\$\w+), 0x(FF|FFFF)$", text)
            if m:
                bits = 8 if m.group(3) == "FF" else 16
                verb = "add" if side == "retail" else "remove"
                add(f"{verb}-u{bits}-mask", f"{verb} a (u{bits}) conversion or `& 0x{m.group(3)}`", "any", off, 0.8)
            if _mn(text) == "cvt.d.s":
                add("double-promotion", ("retail promotes to double: a literal lacks the `f` suffix, or an "
                    "undeclared/varargs callee takes the float" if side == "retail" else
                    "candidate promotes to double: add the `f` suffix to float literals and declare the "
                    "callee prototype"), "any", off, 0.85)
            if _mn(text) == "break":
                add("divide-check", ("retail has a divide-by-zero/overflow check: the divisor is a variable "
                    "(signed for `break 6` after -1 test)" if side == "retail" else
                    "candidate has a divide check retail lacks: divisor is a constant or a power of two"),
                    "any", off, 0.8)
    extension(retail_only, "retail")
    extension(compiled_only, "candidate")

    counts = data.get("counts", {})
    structural = sum(counts.get(k, 0) for k in ("instruction", "size", "immediate", "branch", "scheduling"))
    if counts.get("register") and not structural:
        swap = data.get("register_swap") or {}
        saved = any(reg.startswith("$s") for reg in list(swap) + list(swap.values()))
        if saved:
            add("regalloc-saved-gcc", "only call-saved registers are permuted. GCC 2.7 global allocation orders "
                "pseudos by floor_log2(refs)*refs/live_length and hands out $s0.. in that order: add or remove a "
                "use of one variable, shorten/extend its live range (declare in an inner block, reuse another "
                "variable), or split one variable into two", "gcc", None, 0.75)
            add("regalloc-saved-ido", "only call-saved registers are permuted. IDO gives $s registers by first "
                "use, then declaration order: reorder the declarations or the first uses; a dead early mention "
                "of a variable also changes the order", "ido", None, 0.75)
        else:
            add("regalloc-temp-gcc", "only temporaries are permuted. GCC local allocation takes the lowest free "
                "register in birth order within a block: reorder independent statements, split an expression "
                "into a named temporary, or fold a temporary back into its use", "gcc", None, 0.7)
            add("regalloc-temp-ido", "only temporaries are permuted. IDO's expression temporaries rotate through "
                "$t6-$t9 then $t0-$t5: change evaluation order (commute operands, compound assignment), or "
                "introduce/remove a temp so one more/fewer value is live", "ido", None, 0.7)
    if counts.get("scheduling") and not counts.get("instruction"):
        add("statement-order", "same instructions in a different order: reorder independent statements or "
            "initialisers; on IDO try putting the statements on one line (and the opposite), on GCC check "
            "whether a load was hoisted because the variable is read before the store in source order",
            "any", None, 0.6)
    return sorted(found.values(), key=lambda row: -row["confidence"])
