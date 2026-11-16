"""A small MIPS III decoder for the unoptimised-GCC translator (``redraft_gcc_debug``).

Only what GCC 2.x emits for C is decoded; anything else is ``None`` and makes the caller decline.
The instruction stream is *normalised* so that both assembler lanes read the same:

* an instruction an assembler moved into a delay slot is put back in front of its branch (one lane
  fills delay slots, the other never does), so every transfer is followed by nothing;
* the divide-by-zero and overflow checks an assembler expands ``div``/``divu`` into are removed,
  leaving the division itself.
"""
from __future__ import annotations

import struct

REG = ("zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
       "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra")
ZERO, AT, V0, V1, A0, SP, FP, RA = 0, 1, 2, 3, 4, 29, 30, 31

_SPECIAL = {0x00: "sll", 0x02: "srl", 0x03: "sra", 0x04: "sllv", 0x06: "srlv", 0x07: "srav", 0x08: "jr",
            0x09: "jalr", 0x0D: "break", 0x10: "mfhi", 0x12: "mflo", 0x18: "mult", 0x19: "multu",
            0x1A: "div", 0x1B: "divu", 0x21: "addu", 0x23: "subu", 0x24: "and", 0x25: "or", 0x26: "xor",
            0x27: "nor", 0x2A: "slt", 0x2B: "sltu",
            0x14: "dsllv", 0x16: "dsrlv", 0x17: "dsrav", 0x1C: "dmult", 0x1D: "dmultu", 0x1E: "ddiv",
            0x1F: "ddivu", 0x2D: "daddu", 0x2F: "dsubu", 0x38: "dsll", 0x3A: "dsrl", 0x3B: "dsra",
            0x3C: "dsll32", 0x3E: "dsrl32", 0x3F: "dsra32"}
_IMM = {0x04: "beq", 0x05: "bne", 0x06: "blez", 0x07: "bgtz", 0x09: "addiu", 0x0A: "slti", 0x0B: "sltiu",
        0x0C: "andi", 0x0D: "ori", 0x0E: "xori", 0x0F: "lui", 0x19: "daddiu",
        0x20: "lb", 0x21: "lh", 0x22: "lwl", 0x23: "lw", 0x24: "lbu", 0x25: "lhu", 0x26: "lwr",
        0x28: "sb", 0x29: "sh", 0x2A: "swl", 0x2B: "sw", 0x2E: "swr",
        0x31: "lwc1", 0x35: "ldc1", 0x39: "swc1", 0x3D: "sdc1", 0x37: "ld", 0x3F: "sd"}
_FPU = {0x00: "add", 0x01: "sub", 0x02: "mul", 0x03: "div", 0x04: "sqrt", 0x05: "abs", 0x06: "mov",
        0x07: "neg", 0x0D: "trunc.w", 0x20: "cvt.s", 0x21: "cvt.d", 0x24: "cvt.w",
        0x32: "c.eq", 0x3C: "c.lt", 0x3E: "c.le"}
BRANCHES = ("beq", "bne", "blez", "bgtz", "bltz", "bgez", "bc1t", "bc1f")
TRANSFERS = BRANCHES + ("j", "jal", "jr", "jalr")
LOADS = {"lb": (1, True), "lbu": (1, False), "lh": (2, True), "lhu": (2, False), "lw": (4, True)}
STORES = {"sb": 1, "sh": 2, "sw": 4}


class Insn:
    """One decoded instruction.  ``addr`` is where it stands in the image."""
    __slots__ = ("addr", "word", "op", "rs", "rt", "rd", "sa", "imm", "target", "fmt", "fs", "ft", "fd")

    def __init__(self, addr: int, word: int):
        self.addr, self.word = addr, word
        self.rs, self.rt, self.rd, self.sa = (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31, (word >> 6) & 31
        imm = word & 0xFFFF
        self.imm = imm - 0x10000 if imm & 0x8000 else imm
        self.target = None
        self.fmt = None
        self.fs, self.ft, self.fd = self.rd, self.rt, self.sa
        self.op = self._name()

    @property
    def uimm(self) -> int:
        return self.word & 0xFFFF

    def _name(self):
        word, major, funct = self.word, self.word >> 26, self.word & 63
        if word == 0:
            return "nop"
        if major == 0:
            return _SPECIAL.get(funct)
        if major == 1:
            if self.rt in (0, 1):
                self.target = self.addr + 4 + (self.imm << 2)
                return ("bltz", "bgez")[self.rt]
            return None
        if major in (2, 3):
            self.target = ((self.addr + 4) & 0xF0000000) | ((word & 0x03FFFFFF) << 2)
            return ("j", "jal")[major - 2]
        if major == 0x11:
            if self.rs == 0 and not word & 0x7FF:
                return "mfc1"
            if self.rs == 4 and not word & 0x7FF:
                return "mtc1"
            if self.rs == 8 and self.rt in (0, 1):
                self.target = self.addr + 4 + (self.imm << 2)
                return ("bc1f", "bc1t")[self.rt]
            if self.rs in (16, 17, 20):
                self.fmt = {16: "s", 17: "d", 20: "w"}[self.rs]
                return _FPU.get(funct)
            return None
        name = _IMM.get(major)
        if name in ("beq", "bne", "blez", "bgtz"):
            self.target = self.addr + 4 + (self.imm << 2)
        return name

    def __repr__(self):
        return f"<{self.addr:08X} {self.op} rs={REG[self.rs]} rt={REG[self.rt]} rd={REG[self.rd]} imm={self.imm}>"


def _is(insn, op, **fields) -> bool:
    return insn is not None and insn.op == op and all(getattr(insn, k) == v for k, v in fields.items())


def _division_checks(raw: list, index: int):
    """(division instruction, index after its checks) when ``raw[index]`` starts a checked division.

    Two layouts exist.  One assembler writes ``div; bnez d,+; nop; break 7`` and the other
    ``bnez d,+; div (in the delay slot); break 7``; a signed division continues with
    ``li $at,-1; bne d,$at,+; lui $at,0x8000; bne n,$at,+; nop; break 6``."""
    def at(i):
        return raw[i] if 0 <= i < len(raw) else None
    first = raw[index]
    if first.op in ("div", "divu") and first.rd == 0:
        division, cursor = first, index + 1
        if not (_is(at(cursor), "bne", rs=division.rt, rt=0) and _is(at(cursor + 1), "nop")
                and _is(at(cursor + 2), "break") and at(cursor).target == first.addr + 16):
            return None
        cursor += 3
    elif first.op == "bne" and first.rt == 0 and at(index + 1) is not None and at(index + 1).op in ("div", "divu") \
            and at(index + 1).rt == first.rs and at(index + 1).rd == 0 and _is(at(index + 2), "break") \
            and first.target == first.addr + 12:
        division, cursor = raw[index + 1], index + 3
    else:
        return None
    if division.op == "div" and _is(at(cursor), "addiu", rt=AT, rs=0, imm=-1):
        end = at(cursor).addr + 24
        if (_is(at(cursor + 1), "bne", rs=division.rt, rt=AT) and _is(at(cursor + 2), "lui", rt=AT)
                and at(cursor + 2).uimm == 0x8000 and _is(at(cursor + 3), "bne", rs=division.rs, rt=AT)
                and _is(at(cursor + 4), "nop") and _is(at(cursor + 5), "break")
                and at(cursor + 1).target == end and at(cursor + 3).target == end):
            cursor += 6
    return division, cursor


def decode(code: bytes, vram: int) -> list[Insn] | None:
    """The function's instructions, in logical order, or None when a word is not understood."""
    if len(code) % 4 or not code:
        return None
    words = struct.unpack(f">{len(code) // 4}I", code)
    raw = [Insn(vram + 4 * index, word) for index, word in enumerate(words)]
    out, index = [], 0
    while index < len(raw):
        insn = raw[index]
        if insn.op is None:
            return None
        checked = _division_checks(raw, index)
        if checked is not None:
            division, after = checked
            division.addr = insn.addr                        # a label on the sequence names its start
            out.append(division)
            index = after
            continue
        if insn.op in TRANSFERS:
            if index + 1 >= len(raw):
                return None
            slot = raw[index + 1]
            if slot.op is None or slot.op in TRANSFERS:
                return None
            if slot.op != "nop":
                out.append(slot)
            out.append(insn)
            index += 2
            continue
        out.append(insn)
        index += 1
    return out
