"""Hand-written code kept as assembly source, proved by assembling it again.

Some of every image was never C: the entry stub, exception and interrupt handlers, cache and TLB
routines, fast memory copies.  No compiler emits their instructions (coprocessor-0 moves, ``eret``,
``cache``, the kernel registers), so no C source can match them and the faithful source *is*
assembly.  For a function the analysis already recognises as hand-written, this module writes that
source (symbolic: calls, branches and address pairs are names, not numbers) and proves it the way
everything else here is proved: it is assembled, relocated and compared with the target, byte for
byte.  Such a function is reported as ``assembly``, apart from the functions matched from C; it is
never offered for a function a compiler could have produced.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from ..elf import Elf
from . import compare as cmp
from . import m2c_bridge

STATUS = "assembly"
# o64: 32-bit addresses with 64-bit registers, so ``sd``/``ld`` are the instructions they name
# (under the 32-bit ABI the assembler expands each into two word accesses).
RECIPE = "gnu-as -march=vr4300 -mabi=o64"
ASSEMBLER_FLAGS = ("-EB", "-march=vr4300", "-mabi=o64", "-G0", "-no-pad-sections")
_STATED = re.compile(r"^(?:func|D|L|jtbl|jpt|lbl|jumptable|data|bss|rodata)_?([0-9A-Fa-f]{8})$")


class _Symbols(dict):
    """Declared names, plus names that state their own address (``func_80001234``)."""

    def __missing__(self, name):
        found = _STATED.match(name)
        if not found:
            raise KeyError(name)
        return int(found.group(1), 16)

    def __contains__(self, name) -> bool:
        return dict.__contains__(self, name) or bool(_STATED.match(str(name)))

    def resolve(self, name):
        try:
            return self[name]
        except KeyError:
            return None


# The system coprocessor's registers, by number: the assembler takes ``$12``, a reader wants
# ``Status``, so the name stays beside the instruction as a comment.
COP0 = ("Index", "Random", "EntryLo0", "EntryLo1", "Context", "PageMask", "Wired", "Reserved07", "BadVaddr",
        "Count", "EntryHi", "Compare", "Status", "Cause", "EPC", "PRevID", "Config", "LLAddr", "WatchLo",
        "WatchHi", "XContext", "Reserved21", "Reserved22", "Reserved23", "Reserved24", "Reserved25", "PErr",
        "CacheErr", "TagLo", "TagHi", "ErrorEPC", "Reserved31")
_COP0_MOVE = re.compile(r"^(\s*(?:/\*.*?\*/\s*)?(?:d?m[ft]c0|c[ft]c0)\s+\$\w+,\s*)(\w+)\s*$")
FPU_CONTROL = {"FpcImpRev": 0, "FpcCsr": 31}                # the floating-point control registers
_FPU_MOVE = re.compile(r"^(\s*(?:/\*.*?\*/\s*)?c[ft]c1\s+\$\w+,\s*)\$(\w+)\s*$")


def _numbered(line: str) -> str:
    control = _FPU_MOVE.match(line)
    if control and control.group(2) in FPU_CONTROL:
        return f"{control.group(1)}${FPU_CONTROL[control.group(2)]} /* {control.group(2)} */"
    found = _COP0_MOVE.match(line)
    if not found:
        return line
    name = found.group(2)
    lowered = {known.lower(): number for number, known in enumerate(COP0)}
    if name.lower() not in lowered:
        return line
    return f"{found.group(1)}${lowered[name.lower()]} /* {name} */"


def source(name: str, code: bytes, vram: int, names: dict[int, str] | None = None,
           jump_tables: list[tuple[int, list[int]]] | None = None) -> str:
    """Assembly source of one function."""
    text = m2c_bridge.emit_asm(name, code, vram, names, jump_tables or [])
    lines, in_tables = [], False
    for line in text.split("\n"):
        if line.startswith(".section .rodata") or line.startswith(".section .rdata"):
            in_tables = True
        elif in_tables and line.startswith("glabel "):
            # each jump table in a section of its own: a function may carry several, and they
            # need not lie next to one another in the image
            lines.append(f'.section .rodata.{line.split()[1]}, "a"')
        lines.append(_numbered(line))
    return "\n".join(lines)


def prove(text: str, code: bytes, vram: int, cfg, names: dict[int, str] | None = None) -> dict:
    """Assemble ``text`` and compare it with ``code``.

    ``{"verdict": "exact" | "mismatch" | "unavailable" | "error", ...}``; ``exact`` only when the
    assembled, relocated section is the target's bytes and nothing follows them."""
    located = cfg.gnu_as() if cfg is not None else None
    if located is None:
        return {"verdict": "unavailable", "notes": ["no MIPS GNU assembler"]}
    assembler, env = located
    import os
    with tempfile.TemporaryDirectory(prefix="n64dk-asm-") as work:
        path, obj = Path(work) / "unit.s", Path(work) / "unit.o"
        path.write_text(text)
        try:
            done = subprocess.run([assembler, *ASSEMBLER_FLAGS, "-o", str(obj), str(path)], capture_output=True,
                                  text=True, timeout=60, env={**os.environ, **env})
        except (OSError, subprocess.TimeoutExpired) as error:
            return {"verdict": "error", "notes": [str(error)[-200:]]}
        if done.returncode != 0 or not obj.is_file():
            return {"verdict": "error", "notes": [done.stderr.replace(str(path), "unit.s")[-300:]]}
        elf = Elf.load(obj)
    section = cmp.find_section(elf, ".text")
    if section is None:
        return {"verdict": "error", "notes": ["no .text in the object"]}
    symbols = _Symbols({name: address for address, name in (names or {}).items()})
    # A jump table the routine carries sits in its own section; its label states where.
    bases = {section.name: vram}
    for symbol in elf.symbols:
        if symbol.section in (0, 0xFFF1, 0xFFF2) or symbol.section >= len(elf.sections) or not symbol.name:
            continue
        held = elf.sections[symbol.section].name
        address = symbols.resolve(symbol.name)
        if held == section.name or address is None:
            continue
        if bases.setdefault(held, address - symbol.value) != address - symbol.value:
            return {"verdict": "error", "notes": [f"labels in {held} are not one contiguous block"]}
    try:
        built = elf.relocate(section.name, bases, symbols)
    except (KeyError, ValueError) as error:
        return {"verdict": "error", "notes": [f"relocation: {error}"]}
    if built[:len(code)] == code and not any(built[len(code):]):
        return {"verdict": "exact", "text_equal": True, "assumptions": [], "conflicts": [], "sections": [],
                "notes": ["assembly source; assembled and compared"], "compiled_size": len(built)}
    first = next((i for i, (a, b) in enumerate(zip(built, code)) if a != b), min(len(built), len(code)))
    return {"verdict": "mismatch", "text_equal": False, "first_diff": f"0x{first & ~3:X}",
            "notes": [f"assembled {len(built)} bytes, target {len(code)}"]}


def attempt(name: str, code: bytes, vram: int, cfg, names: dict[int, str] | None = None,
            jump_tables: list[tuple[int, list[int]]] | None = None) -> tuple[str, dict] | None:
    """(source, proof) when the function's assembly source assembles to its bytes, else None."""
    try:
        text = source(name, code, vram, names, jump_tables)
    except Exception:                                       # noqa: BLE001 - not decodable: not kept
        return None
    proof = prove(text, code, vram, cfg, names)
    if proof.get("verdict") == "exact":
        return text, proof
    if proof.get("verdict") == "unavailable":
        return None
    # Words that are not instructions an assembler will take back (data inside the range, an
    # encoding with reserved bits): the same listing with every instruction given as its word,
    # the mnemonic beside it.  It reproduces the bytes and says plainly that it is not source.
    raw = as_words(text)
    proof = prove(raw, code, vram, cfg, names)
    if proof.get("verdict") == "exact":
        proof["notes"] = ["raw words: the instructions could not be written symbolically"]
        return raw, proof
    return None


_LISTED = re.compile(r"^(\s*)/\* ([0-9A-Fa-f]{8}) ([0-9A-Fa-f]{8}) \*/\s*(.*)$")


def as_words(text: str) -> str:
    """``text`` with each listed instruction replaced by its word (``.word``), the instruction
    kept as a comment; labels and tables stay as they are."""
    out = ["/* raw words: this range does not assemble from mnemonics */"]
    for line in text.split("\n"):
        found = _LISTED.match(line)
        out.append(f"{found.group(1)}.word 0x{found.group(3).upper()} /* {found.group(2)}: {found.group(4).strip()} */"
                   if found else line)
    return "\n".join(out)
