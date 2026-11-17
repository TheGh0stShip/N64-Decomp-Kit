"""Assembly normalizers placed between GCC ``-S`` and an old GNU assembler.
``builtin`` makes KMC GCC 2.7.2 output deterministic for GNU as 2.x in the way the
BattleTanx project's normalizer starts out (tools/normalize_kmc_gcc_asm.py, GPL-3.0): GCC
already wraps the transfers whose delay slots it filled in ``.set noreorder`` regions, so
assembler reordering is disabled everywhere else and an explicit ``nop`` is added after each
transfer emitted in reorder mode.  GCC's internal ``b 3f`` of the 64-bit shift helper is
spelled ``bgez $zero,3f`` as the retail assembler expanded it.

Project-specific normalizers run as external hooks (see :func:`run_hook`).
"""
from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

TRANSFER = re.compile(
    r"^(?:b(?:al|eq|ne|gez|gezal|gtz|lez|ltz|ltzal|c1[ft]|c1fl|c1tl|eql|nel|gezl|gtzl|lezl|ltzl)?|"
    r"j|jal|jr|jalr)\s+")
LONG_SHIFT_BRANCH = re.compile(r"^(\s*)b(\s+)3f\b")


def builtin(text: str) -> str:
    out: list[str] = []
    reorder = True
    for line in text.splitlines(keepends=True):
        body = line.split("#", 1)[0].strip()
        if body == ".set\tnoreorder" or re.fullmatch(r"\.set\s+noreorder", body):
            reorder = False
            out.append(line)
            continue
        if re.fullmatch(r"\.set\s+reorder", body):
            reorder = True
            continue  # keep the assembler in noreorder mode
        if reorder and LONG_SHIFT_BRANCH.match(line):
            line = LONG_SHIFT_BRANCH.sub(r"\1bgez\2$0,3f", line, count=1)
            body = line.split("#", 1)[0].strip()
        out.append(line)
        if reorder and TRANSFER.match(body):
            out.append("\tnop\n")
    return "\t.set\tnoreorder\n" + "".join(out)


def run_hook(command: str, src: Path, dst: Path, cwd: Path, extra: list[str] | None = None) -> None:
    """Run an external normalizer.  ``command`` is a shell-style template with ``{input}``,
    ``{output}`` and optional ``{extra}`` placeholders; without placeholders the input and
    output paths are appended."""
    argv = shlex.split(command)
    extra = extra or []
    if not any("{input}" in a or "{output}" in a for a in argv):
        argv = argv + ["{extra}", "{input}", "{output}"]
    final: list[str] = []
    for a in argv:
        if a == "{extra}":
            final.extend(extra)
        else:
            final.append(a.replace("{input}", str(src)).replace("{output}", str(dst)))
    try:
        from .. import safety
        proc = safety.run_tool(final, kind="light", cwd=cwd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("normalizer timed out after 120s") from error
    if proc.returncode:
        raise RuntimeError(f"normalizer failed: {proc.stderr.strip()[-400:]}")


_SYMBOL_LOAD = re.compile(r"^(\s*)(lw|lh|lhu|lb|lbu)(\s+)(\$\d+|\$[a-z][a-z0-9]),\s*([A-Za-z_.$][\w.$]*(?:[+-]\d+)?)\s*(#.*)?$")


def at_symbol_loads(text: str) -> str:
    """Assembler component variant ``atload``: an integer load from a bare symbol (``lw $4,g``,
    which GNU as, KMC as, ASN64 and IRIX as all expand through the destination register) expanded
    through ``$at`` instead: ``lui $at,%hi(g)`` then ``lw $4,%lo(g)($at)``.  Retail code of some
    titles holds exactly this form (round 11, TOOLCHAIN_REGIONS.md: no installed assembler makes
    it).  Behaviour-preserving: the same value reaches the same register; ``$at`` is the
    assembler's temporary.  Everything else is left for the assembler."""
    out = []
    for line in text.splitlines(keepends=True):
        m = _SYMBOL_LOAD.match(line.rstrip("\n"))
        if not m:
            out.append(line)
            continue
        indent, op, _space, reg, sym, _comment = m.groups()
        out.append(f"{indent}.set\tnoat\n{indent}lui\t$1,%hi({sym})\n{indent}{op}\t{reg},%lo({sym})($1)\n"
                   f"{indent}.set\tat\n")
    return "".join(out)
