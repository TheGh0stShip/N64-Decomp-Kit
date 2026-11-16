"""A statement-level translation of unoptimised IDO code (``cc -g`` / ``-O0``) back to C.

Without optimisation IDO compiles every statement on its own: each local lives in a stack slot,
a register holds a value only inside one statement, and nothing is moved between statements (the
assembler reorders instructions and fills delay slots only inside one statement).  So the function
can be *read back* from its machine code: every store, call and branch closes a statement whose
operands are the expression trees the registers hold at that point, the frame gives the locals in
declaration order (first declared = highest address), and the branches spell the control flow in
source order.

``lift`` returns C text for the body and the declarations it needs, or raises ``Unsupported`` for
anything it does not understand: a wrong guess costs a build, so it declines instead.

Rules that were measured against the compiler (IDO 5.3 ``-g``) and are relied on here:

* a function falls off its end through ``b L; nop; L: <epilogue>``; every ``return`` is one more
  ``b L`` (so ``return;`` at the end of a ``void`` function is visible as a second branch);
* a leaf keeps the parameters it uses in ``a0..a3``/``f12``/``f14`` and stores the unused ones to
  their home slots; any other function homes all register parameters at entry;
* ``for (init; cond; step)`` compiles ``init`` with the first test and ``step`` with the repeated
  test as one statement (the stored value is reused from its register, the store may sit in the
  branch delay slot); ``while`` is ``if (c) do {...} while (c)``;
* ``x = c ? a : b`` is compiled as ``if (c) x = a; else x = b``;
* the operands of ``+ * & | ^ == !=`` are put in a canonical order by class (an expression with a
  ``*p``/``a[i]``/call first, then other operators and narrow variables, then plain ``int``
  variables); operands of one class keep their source order.  ``p->f`` and ``*(T *)(p + n)`` give
  the same instructions but belong to different classes, so the form is chosen to keep the order
  the instruction shows.
"""
from __future__ import annotations

import struct

ZERO, AT, V0, V1, A0, A1, A2, A3 = range(8)
SP, FP, RA = 29, 30, 31
TEMPS = frozenset([1, 2, 3, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25])
SIZES = {"s8": 1, "u8": 1, "s16": 2, "u16": 2, "s32": 4, "u32": 4, "f32": 4, "f64": 8}
LOADS = {"lb": "s8", "lbu": "u8", "lh": "s16", "lhu": "u16", "lw": "s32", "lwc1": "f32", "ldc1": "f64"}
STORES = {"sb": "u8", "sh": "s16", "sw": "s32", "swc1": "f32", "sdc1": "f64"}
_SPECIAL = {0: "sll", 2: "srl", 3: "sra", 4: "sllv", 6: "srlv", 7: "srav", 8: "jr", 9: "jalr", 13: "break",
            16: "mfhi", 18: "mflo", 24: "mult", 25: "multu", 26: "div", 27: "divu", 32: "add", 33: "addu",
            34: "sub", 35: "subu", 36: "and", 37: "or", 38: "xor", 39: "nor", 42: "slt", 43: "sltu"}
_OPS = {2: "j", 3: "jal", 4: "beq", 5: "bne", 6: "blez", 7: "bgtz", 8: "addi", 9: "addiu", 10: "slti", 11: "sltiu",
        12: "andi", 13: "ori", 14: "xori", 15: "lui", 32: "lb", 33: "lh", 35: "lw", 36: "lbu", 37: "lhu",
        40: "sb", 41: "sh", 43: "sw", 49: "lwc1", 53: "ldc1", 57: "swc1", 61: "sdc1"}
_FPOPS = {0: "add", 1: "sub", 2: "mul", 3: "div", 5: "abs", 6: "mov", 7: "neg", 13: "trunc.w", 32: "cvt.s",
          33: "cvt.d", 36: "cvt.w", 50: "c.eq", 60: "c.lt", 62: "c.le"}
BRANCHES = frozenset(["beq", "bne", "blez", "bgtz", "bltz", "bgez", "bc1f", "bc1t"])


class Unsupported(Exception):
    """The code holds something this translation does not model."""


class Ins:
    __slots__ = ("a", "w", "m", "rs", "rt", "rd", "sa", "imm", "uimm", "tgt", "fmt", "x")

    def __repr__(self):
        return f"<{self.a:X} {self.m} rs={self.rs} rt={self.rt} rd={self.rd} imm={self.imm}>"


def decode(code: bytes, vram: int) -> list[Ins]:
    out = []
    for off in range(0, len(code) - 3, 4):
        w, = struct.unpack_from(">I", code, off)
        i = Ins()
        i.a, i.w = vram + off, w
        op = w >> 26
        i.rs, i.rt, i.rd, i.sa = (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31, (w >> 6) & 31
        i.uimm = w & 0xFFFF
        i.imm = i.uimm - 0x10000 if i.uimm & 0x8000 else i.uimm
        i.tgt, i.fmt, i.x, i.m = None, None, None, None
        if w == 0:
            i.m = "nop"
        elif op == 0:
            i.m = _SPECIAL.get(w & 63)
        elif op == 1:
            i.m = {0: "bltz", 1: "bgez"}.get(i.rt)
        elif op == 17:
            if i.rs == 0:
                i.m = "mfc1"
            elif i.rs == 4:
                i.m = "mtc1"
            elif i.rs == 8:
                i.m = {0: "bc1f", 1: "bc1t"}.get(i.rt)
            elif i.rs in (16, 17, 20):
                i.m, i.fmt = _FPOPS.get(w & 63), "sdw"[(16, 17, 20).index(i.rs)]
        else:
            i.m = _OPS.get(op)
        if i.m in BRANCHES:
            i.tgt = i.a + 4 + i.imm * 4
        elif i.m in ("j", "jal"):
            i.tgt = ((i.a + 4) & 0xF0000000) | ((w & 0x3FFFFFF) << 2)
        out.append(i)
    return out


# ---------------------------------------------------------------------------------------------
# expression trees


class X:
    """One value.  ``k`` is the kind, ``a b c`` its parts, ``t`` the C type it has when printed
    (``s32`` unless stated), ``src`` the address of the first instruction that worked on it."""
    __slots__ = ("k", "a", "b", "c", "t", "src", "dst")

    def __init__(self, k, a=None, b=None, c=None, t="s32", src=0):
        self.k, self.a, self.b, self.c, self.t, self.src, self.dst = k, a, b, c, t, src, None

    def __repr__(self):
        return f"X({self.k},{self.a!r},{self.b!r},{self.c!r},{self.t})"


def const(v, src=0):
    return X("c", v, src=src)


def is_const(x, v=None):
    return x.k == "c" and (v is None or x.a == v)


NEG = {"<": ">=", ">=": "<", ">": "<=", "<=": ">", "==": "!=", "!=": "=="}
COMMUTATIVE = frozenset(["+", "*", "&", "|", "^", "==", "!="])


def negate(x: X) -> X:
    if x.k == "cmp" and x.t != "f":
        return X("cmp", NEG[x.a], x.b, x.c, x.t, x.src)
    if x.k == "cmp" and x.a in ("==", "!="):
        y = X("cmp", NEG[x.a], x.b, x.c, x.t, x.src)
        y.dst = x.dst
        return y
    if x.k == "not":
        return x.a
    if x.k == "and":
        return X("or", negate(x.a), negate(x.b), src=x.src)
    if x.k == "or":
        return X("and", negate(x.a), negate(x.b), src=x.src)
    return X("not", x, src=x.src)


def truth(x: X) -> X:
    """``x`` as a condition (``x != 0``)."""
    if x.k in ("cmp", "not", "and", "or"):
        return x
    return X("cmp", "!=", x, const(0), "s", x.src)


class Item:
    """One step of the function in address order: a statement, a conditional branch, a jump or a
    return.  ``end`` is the address after its last instruction."""
    __slots__ = ("k", "end", "stmt", "cond", "tgt", "val", "merged", "at", "store", "fwd", "lv", "rv")

    def __init__(self, k, end, **kw):
        self.k, self.end = k, end
        self.stmt = self.cond = self.tgt = self.val = self.at = self.store = self.lv = self.rv = None
        self.merged, self.fwd = [], False
        for key, value in kw.items():
            setattr(self, key, value)


class Lifter:
    def __init__(self, code: bytes, vram: int, func_name=None, data_name=None, whole: bool = False, read=None):
        self.read = read
        self.ins = decode(code, vram)
        while len(self.ins) > 1 and self.ins[-1].m == "nop" and not (self.ins[-2].m == "jr" and self.ins[-2].rs == RA):
            self.ins.pop()                                   # alignment padding after the return
        if len(self.ins) < 2:
            raise Unsupported("too short")
        if any(i.m is None for i in self.ins):
            bad = next(i for i in self.ins if i.m is None)
            raise Unsupported(f"instruction {bad.w:08X}")
        self.vram, self.whole = vram, whole
        self.func_name = func_name or (lambda a: f"func_{a:08X}")
        self.data_name = data_name or (lambda a: f"D_{a:08X}")
        self.loaded: dict[tuple, str] = {}       # ('l', offset) | ('p', slot) | ('g', address) -> type of its loads
        self.analyse({})
        if self.loaded:
            self.analyse(dict(self.loaded))      # a store alone does not tell signed from unsigned

    def analyse(self, known: dict):
        self.locals: dict[int, str] = {}         # sp offset -> type
        self.local_addr: set[int] = set()        # sp offsets whose address is taken
        self.params: dict[int, str] = {}         # slot -> type
        self.reg_params: set[int] = set()        # slots that live in their register (leaf)
        self.globals: dict[int, str] = {}        # address -> type of the direct accesses
        self.global_arrays: dict[int, str] = {}  # address -> element type of indexed accesses
        self.callees: dict = {}                  # address -> {"args": [...], "ret": type}
        self.ret_type = None
        self.frame()
        self.fold_macros()
        self.labels = {i.tgt for k, i in enumerate(self.ins) if i.m in BRANCHES and k not in self.skip
                       and self.body_lo <= k < self.body_hi}
        self.known = known
        for (kind, key), t in known.items():
            if kind == "l":
                self.locals[key] = t
            elif kind == "g":
                self.globals[key] = t
        self.float_slots = {x.imm for x in self.ins if x.m in ("lwc1", "swc1") and x.rs == SP}
        self.run()

    # -- frame ---------------------------------------------------------------------------------
    def frame(self):
        ins = self.ins
        # The assembler may move a leaf's parameter narrowing (``andi``, ``sll``/``sra`` on an
        # argument register in place) in front of the frame set-up.  Read the frame first.
        lead = 0
        while lead < min(8, len(ins) - 1) and (
                (ins[lead].m == "andi" and A0 <= ins[lead].rs <= A3 and ins[lead].rt == ins[lead].rs)
                or (ins[lead].m in ("sll", "sra") and A0 <= ins[lead].rt <= A3 and ins[lead].rd == ins[lead].rt
                    and ins[lead].sa in (16, 24))):
            lead += 1
        if lead and ins[lead].m == "addiu" and ins[lead].rs == SP and ins[lead].rt == SP and ins[lead].imm < 0:
            ins[:] = [ins[lead]] + ins[:lead] + ins[lead + 1:]
        k, n = 0, 0
        if ins[0].m == "addiu" and ins[0].rs == SP and ins[0].rt == SP and ins[0].imm < 0:
            n, k = -ins[0].imm, 1
        self.size = n
        self.leaf = not any(i.m in ("jal", "jalr") for i in ins)
        self.saved: dict[int, int] = {}
        homed: dict[int, str] = {}
        while k < len(ins):
            i = ins[k]
            if i.m == "sw" and i.rs == SP and (i.rt == RA or 16 <= i.rt <= 23 or i.rt == FP) and i.imm < n:
                self.saved[i.rt] = i.imm
            elif i.m == "sw" and i.rs == SP and A0 <= i.rt <= A3 and i.imm == n + 4 * (i.rt - A0):
                homed[i.rt - A0] = "s32"
            elif i.m == "swc1" and i.rs == SP and i.rt in (12, 14) and i.imm == n + 2 * (i.rt - 12):
                homed[(i.rt - 12) // 2] = "f32"
            elif i.m == "sdc1" and i.rs == SP and i.rt in (12, 14) and i.imm == n + 4 * (i.rt - 12):
                homed[(i.rt - 12)] = "f64"
            elif i.m == "sdc1" and i.rs == SP and i.rt >= 20 and i.imm < n:
                self.saved[32 + i.rt] = i.imm
            else:
                break
            k += 1
        self.homed = homed
        # the end: ... jr ra; (nop | addiu sp)
        e = len(ins) - 2
        if e < 0 or ins[e].m != "jr" or ins[e].rs != RA:
            raise Unsupported("no return at the end")
        last = ins[e + 1]
        if not (last.m == "nop" or (last.m == "addiu" and last.rs == SP and last.rt == SP and last.imm == n)):
            raise Unsupported("return delay slot")
        while e > 0:
            p = ins[e - 1]
            if (p.m == "lw" and p.rs == SP and p.rt in self.saved and self.saved[p.rt] == p.imm) or \
                    (p.m == "ldc1" and p.rs == SP and 32 + p.rt in self.saved) or \
                    (p.m == "addiu" and p.rs == SP and p.rt == SP and p.imm == n):
                e -= 1
            else:
                break
        self.epilogue = ins[e].a
        if e >= 2 and ins[e - 2].m == "beq" and ins[e - 2].rs == 0 and ins[e - 2].rt == 0 \
                and ins[e - 2].tgt == self.epilogue and ins[e - 1].m == "nop":
            self.style = "b"
            self.body_hi = e - 2
        elif n == 0 and not self.saved and e >= 2 and ins[e - 2].m == "jr" and ins[e - 2].rs == RA \
                and ins[e - 1].m == "nop" and self.whole:
            # a frameless leaf returns with `jr ra` in place of every branch to the epilogue
            self.style = "jr"
            self.body_hi = e - 2
        else:
            raise Unsupported("not the unoptimised function shape")
        # a leaf narrows its small parameters in place at entry
        self.narrow: dict[int, str] = {}
        while self.leaf and k + 1 < len(ins):
            i, j = ins[k], ins[k + 1]
            if i.m == "andi" and A0 <= i.rs <= A3 and i.rt == i.rs and i.uimm in (0xFF, 0xFFFF):
                self.narrow[i.rs - A0] = "u8" if i.uimm == 0xFF else "u16"
                k += 1
            elif i.m == "sll" and j.m == "sra" and A0 <= i.rt <= A3 and i.rd == i.rt and j.rt == i.rt \
                    and j.rd == i.rt and i.sa == j.sa and i.sa in (16, 24):
                self.narrow[i.rt - A0] = "s16" if i.sa == 16 else "s8"
                k += 2
            else:
                break
        self.body_lo = k
        if self.body_lo > self.body_hi:
            raise Unsupported("empty frame analysis")
        # the parameters of a leaf that stay in registers: read before written
        self.nargs = 0
        written, used = set(), set()
        for q in range(self.body_lo, len(ins)):
            i = ins[q]
            reads, writes = _int_uses(i)
            for r in reads:
                if A0 <= r <= A3 and r not in written:
                    used.add(r - A0)
            if self.leaf:
                freads, fwrites = _fp_uses(i)
                for r in freads:
                    if r in (12, 14) and (100 + r) not in written:
                        used.add(100 + r)
                written.update(100 + r for r in fwrites)
            written.update(writes)
            if i.m in ("jal", "jalr"):
                written.update(range(A0, A3 + 1))
        if self.leaf:
            for slot in sorted(s for s in used if s < 100):
                self.params[slot] = self.narrow.get(slot, "s32")
                self.reg_params.add(slot)
            for r in sorted(s - 100 for s in used if s >= 100):
                slot = (r - 12) // 2
                if slot in self.params and slot not in homed:
                    raise Unsupported("float and integer parameter in one slot")
                self.params[slot] = "f32"           # corrected to f64 by the first double use
                self.reg_params.add(slot)
        elif used:
            raise Unsupported("argument register read in a function that calls")
        for slot, kind in homed.items():
            self.params.setdefault(slot, kind)
            self.reg_params.discard(slot)

    def fold_macros(self):
        """Assembler macro expansions that branch inside one statement become one pseudo step."""
        ins = self.ins
        self.skip: set[int] = set()
        self.pseudo: dict[int, tuple] = {}
        n = len(ins)
        for k, i in enumerate(ins):
            # divide checks: `bnez d, +2; nop; break 7` and the INT_MIN / -1 check
            if i.m == "bne" and i.rt == 0 and k + 2 < n and ins[k + 1].m == "nop" and ins[k + 2].m == "break" \
                    and i.tgt == ins[k + 2].a + 4:
                self.skip.update((k, k + 1, k + 2))
            if i.m == "addiu" and i.rt == AT and i.rs == 0 and i.imm == -1 and k + 5 < n \
                    and ins[k + 1].m == "bne" and ins[k + 1].rt == AT and ins[k + 2].m == "lui" \
                    and ins[k + 3].m == "bne" and ins[k + 4].m == "nop" and ins[k + 5].m == "break":
                self.skip.update(range(k, k + 6))
            # signed division by a power of two
            if i.m == "bgez" and k + 3 < n and i.tgt == ins[k + 3].a + 4 and ins[k + 1].m == "sra" \
                    and ins[k + 1].rt == i.rs and ins[k + 2].m == "addiu" and ins[k + 2].rt == AT \
                    and ins[k + 2].rs == i.rs and ins[k + 3].m == "sra" and ins[k + 3].rt == AT \
                    and ins[k + 3].rd == ins[k + 1].rd and ins[k + 3].sa == ins[k + 1].sa \
                    and ins[k + 2].imm == (1 << ins[k + 1].sa) - 1:
                self.pseudo[k] = ("divp2", ins[k + 1].rd, i.rs, ins[k + 1].sa, 4)
                self.skip.update(range(k + 1, k + 4))
            # signed remainder by a power of two
            if i.m == "bgez" and k + 4 < n and i.tgt == ins[k + 4].a + 4 and ins[k + 1].m == "andi" \
                    and ins[k + 1].rs == i.rs and ins[k + 2].m == "beq" and ins[k + 2].rs == ins[k + 1].rt \
                    and ins[k + 2].rt == 0 and ins[k + 3].m == "nop" and ins[k + 4].m == "addiu" \
                    and ins[k + 4].rt == ins[k + 1].rt and ins[k + 4].rs == ins[k + 1].rt \
                    and ins[k + 4].imm == -(ins[k + 1].uimm + 1):
                self.pseudo[k] = ("modp2", ins[k + 1].rt, i.rs, ins[k + 1].uimm + 1, 5)
                self.skip.update(range(k + 1, k + 5))
            # a float comparison used as a value
            if i.m in ("c.eq", "c.lt", "c.le"):
                q = k + 1
                if q < n and ins[q].m == "nop":
                    q += 1
                if q + 3 < n and _is_move_zero(ins[q]) and ins[q + 1].m in ("bc1f", "bc1t") \
                        and ins[q + 2].m == "nop" and ins[q + 3].m == "addiu" and ins[q + 3].rs == 0 \
                        and ins[q + 3].imm == 1 and ins[q + 3].rt == ins[q].rd and ins[q + 1].tgt == ins[q + 3].a + 4:
                    self.pseudo[q] = ("fcmpv", ins[q].rd, ins[q + 1].m == "bc1t", None, 4)
                    self.skip.update(range(q + 1, q + 4))

    # -- execution -----------------------------------------------------------------------------
    def run(self):
        ins = self.ins
        self.R: dict[int, X] = {}
        self.F: dict[int, X] = {}
        self.hilo = None
        self.fcc = None
        self.items: list[Item] = []
        self.call = None                 # the last call whose value was not used yet
        self.args: dict = {}
        self.stack_args: dict[int, X] = {}
        self.retval = None
        self.param_typed = set(self.narrow) | {slot for slot, t in self.params.items() if t != "s32"}
        for (kind, key), t in self.known.items():
            if kind == "p" and key not in self.reg_params and self.params.get(key, "s32") == "s32":
                self.params[key] = t
                self.param_typed.add(key)
        self.incs: list = []             # statements `x = x + n` whose old value may still be used
        self.block_start = 0             # index in items where the current basic block began
        self.arg_area_hi = min([self.saved[r] for r in self.saved] or [self.size]) if not self.leaf else 0
        for slot in self.reg_params:
            if self.params[slot] in ("f32", "f64"):
                self.F[12 + 2 * slot] = X("pv", slot, t=self.params[slot])
            else:
                self.R[A0 + slot] = X("pv", slot, t=self.params[slot])
        self._joins()
        pending_logic: dict[int, list] = {}
        k = self.body_lo
        while k < self.body_hi:
            i = ins[k]
            if i.a in self.joins:
                # where a short-circuit value comes together: ``r = a || b`` / ``r = a && b``
                reg, value = self.joins[i.a], self.R.get(self.joins[i.a])
                if value is None:
                    raise Unsupported("short-circuit value without its last operand")
                for kind, left in reversed(pending_logic.pop(i.a, [])):
                    value = X(kind, left, value, src=left.src)
                self.R[reg] = value
                if reg == V0:
                    self.retval = value
            if k in self.tables:
                k = self.do_table(k)
                continue
            if k in self.unsigned_floats:
                # ``(float) u``: converted as signed, then 2^32 added when the sign bit was set
                convert, add, end = self.unsigned_floats[k]
                value = _plain(self.r(i.rt))
                to = "f32" if ins[convert].m == "cvt.s" else "f64"
                wide = value if value.t == "u32" else X("cast", "u32", value, t="u32", src=_src(value) or i.a)
                self.setf(ins[add].sa, X("cast", to, wide, t=to, src=_src(value) or i.a), ins[add], ins[add].a + 4)
                k = end
                continue
            if k in self.ternaries:
                jump, other, end, reg = self.ternaries[k]
                self.step(ins[k + 1], i.a + 8)
                before = len(self.items)
                self.transfer(i)
                if len(self.items) != before + 1 or self.items[-1].k != "B" or self.items[-1].merged:
                    raise Unsupported("conditional expression test")
                taken = self.items.pop().cond                # the branch leads to the second arm
                for n in list(range(k + 2, jump)) + [jump + 1]:
                    self.step(ins[n], ins[n].a + 4)
                first = self.R.get(reg)
                for n in range(other, end):
                    self.step(ins[n], ins[n].a + 4)
                second = self.R.get(reg)
                if first is None or second is None or len(self.items) != before:
                    raise Unsupported("conditional expression arms")
                self.R[reg] = X("tern", negate(taken), first, second, t=first.t, src=taken.src)
                k = end
                continue
            if k in self.logic_sources:
                target = self.logic_sources[k]
                left = self.r(i.rs)
                pending_logic.setdefault(target, []).append(("or" if i.m == "bne" else "and", left))
                k += 2                                       # the branch and its empty delay slot
                continue
            if i.a in self.labels:
                self.label(i.a)
            if k in self.skip:
                k += 1
                continue
            if k in self.pseudo:
                self.do_pseudo(i, self.pseudo[k])
                k += 1
                continue
            if i.m in BRANCHES or i.m in ("jal", "jalr", "jr", "j"):
                d = ins[k + 1]
                if d.a in self.labels:
                    raise Unsupported("label in a delay slot")
                if k + 1 in self.pseudo or (k + 1 in self.skip):
                    raise Unsupported("macro in a delay slot")
                if d.m in BRANCHES or d.m in ("jal", "jalr", "jr", "j"):
                    raise Unsupported("branch in a delay slot")
                self.step(d, i.a + 8)
                self.transfer(i)
                k += 2
            else:
                self.step(i, i.a + 4)
                k += 1
        self.flush_call(ins[self.body_hi].a)
        self.end = ins[self.body_hi].a

    def _joins(self) -> None:
        """Short-circuit *values*.  ``r = a || b`` is compiled as ``r = a; if (r) goto L; r = b;
        L:`` (``&&`` with the opposite test): a branch on a register that was just computed, over
        straight-line code that computes the same register again.  Such a branch is part of an
        expression, not a statement boundary, and its target is not a label."""
        ins = self.ins
        self.joins: dict[int, int] = {}
        self.logic_sources: dict[int, int] = {}
        index_of = {x.a: n for n, x in enumerate(ins)}
        for target in sorted(self.labels):
            sources = [n for n, x in enumerate(ins) if x.tgt == target and x.m in BRANCHES and n not in self.skip]
            at = index_of.get(target)
            if not sources or at is None:
                continue
            first = min(sources)
            if not all(ins[n].m in ("bne", "beq") and ins[n].rt == 0 and ins[n + 1].m == "nop" and first <= n < at
                       for n in sources) or len({ins[n].rs for n in sources}) != 1 or at - first > 48:
                continue
            reg = ins[first].rs
            scratch_argument = A0 <= reg <= A3 and (reg - A0) not in self.reg_params   # a leaf's spare register
            if reg not in TEMPS and reg != V0 and not scratch_argument:
                continue
            fine = True
            for n in range(first, at):
                x = ins[n]
                if n in sources:
                    # the tested value was computed by the instruction in front of the branch
                    fine = fine and n > 0 and reg in _int_uses(ins[n - 1])[1] and ins[n - 1].m in (
                        "slt", "sltu", "slti", "sltiu", "xori", "sltiu", "or", "and")
                elif x.m in BRANCHES or x.m in ("j", "jal", "jalr", "jr", "sb", "sh", "sw", "swc1", "sdc1") \
                        or (x.a in self.labels and x.a != target):
                    fine = False
                if not fine:
                    break
            # every source is followed by a new computation of the register before the join
            for n in sources:
                fine = fine and any(reg in _int_uses(ins[m])[1] for m in range(n + 2, at))
            if fine:
                self.joins[target] = reg
                for n in sources:
                    self.logic_sources[n] = target
        self.labels = self.labels - set(self.joins)
        self._conditionals(index_of)
        self._jump_tables(index_of)
        self.unsigned_floats: dict[int, tuple] = {}          # index of the mtc1 -> (convert, add, index after)
        for k in range(self.body_lo, self.body_hi - 5):
            move, test, convert = ins[k], ins[k + 1], ins[k + 2]
            if not (move.m == "mtc1" and test.m == "bgez" and test.rs == move.rt and test.tgt is not None
                    and convert.m in ("cvt.s", "cvt.d") and convert.fmt == "w" and convert.rd == move.rd):
                continue
            end = index_of.get(test.tgt)
            if end is None or not (k + 4 <= end <= k + 8):
                continue
            body = ins[k + 3:end]
            adds = [n for n, y in enumerate(body) if y.m == "add" and y.fmt is not None and y.sa == convert.sa]
            if len(adds) != 1 or any(y.m not in ("lui", "mtc1", "nop", "add", "ori") for y in body):
                continue
            if sum(1 for y in ins if y.tgt == test.tgt and y.m in BRANCHES) != 1:
                continue
            self.unsigned_floats[k] = (k + 2, k + 3 + adds[0], end)
            self.labels.discard(test.tgt)

    def _jump_tables(self, index_of) -> None:
        """A dense ``switch``: bounds test, scaled index into a table of code addresses, ``jr``.
        The table is data of the image; with a reader for it the cases are known."""
        ins = self.ins
        self.tables: dict[int, tuple] = {}                   # index of the first dispatch instruction -> its facts
        for j in range(self.body_lo + 7, self.body_hi):
            x = ins[j]
            if not (x.m == "jr" and x.rs != RA):
                continue
            load, add, high, scale, test, bound = ins[j - 1], ins[j - 2], ins[j - 3], ins[j - 4], ins[j - 6], ins[j - 7]
            reg = x.rs
            if not (load.m == "lw" and load.rt == reg and load.rs == AT and add.m == "addu" and add.rd == AT
                    and {add.rs, add.rt} == {AT, reg} and high.m == "lui" and high.rt == AT
                    and scale.m == "sll" and scale.rd == reg and scale.rt == reg and scale.sa == 2
                    and ins[j - 5].m == "nop" and ins[j + 1].m == "nop"
                    and test.m == "beq" and test.rs == AT and test.rt == 0 and test.tgt is not None
                    and bound.m == "sltiu" and bound.rs == reg and bound.rt == AT and bound.imm > 0):
                continue
            if self.read is None:
                raise Unsupported("jump table")              # its cases are data this call cannot see
            first, bias = j - 7, 0
            before = ins[j - 8] if j - 8 >= self.body_lo else None
            if before is not None and before.m == "addiu" and before.rt == reg and before.imm < 0x8000:
                first, bias = j - 8, -before.imm             # ``case`` values start above zero
            table = ((high.uimm << 16) + load.imm) & 0xFFFFFFFF
            targets = [self.read(table + 4 * n) for n in range(bound.imm)]
            if any(t is None or t not in index_of or not (self.body_lo <= index_of[t] <= self.body_hi) for t in targets):
                raise Unsupported("jump table entries outside the function")
            self.tables[first] = (j, reg if first == j - 7 else before.rs, bias, targets, test.tgt)
            self.labels |= set(targets) | {test.tgt}

    def do_table(self, k: int) -> int:
        """Emit the dispatch of the jump-table switch that starts at instruction ``k``."""
        jump, reg, bias, targets, default = self.tables[k]
        selector = _plain(self.r(reg))
        end = self.ins[jump + 1].a + 4
        self.flush_call(self.ins[k].a)
        cases = [(bias + n, target) for n, target in enumerate(targets) if target != default]
        self.emit(Item("T", end, val=selector, tgt=default, store=cases))
        self.after_jump()
        return jump + 2

    def _conditionals(self, index_of) -> None:
        """Conditional expressions used as an operand.  ``f(c ? a : b)`` is compiled as ``if (c)
        r = a; else r = b;`` on a saved register: a branch over an arm that only computes ``r``, a
        jump over a second arm that only computes ``r``.  Neither arm holds a statement, so the
        whole is one value."""
        ins = self.ins
        self.ternaries: dict[int, tuple] = {}                # index of the test -> (jump, else, end, register)
        quiet = lambda x: x.m not in BRANCHES and x.m not in ("j", "jal", "jalr", "jr", "sb", "sh", "sw", "swc1", "sdc1")
        for k in range(self.body_lo, self.body_hi):
            x = ins[k]
            if x.m not in BRANCHES or x.tgt is None or k in self.skip or k in self.logic_sources or ins[k + 1].m != "nop":
                continue
            other = index_of.get(x.tgt)
            if other is None or not (k + 3 < other <= k + 40):
                continue
            jump = other - 2                                 # the jump over the else arm, with its delay slot
            j = ins[jump]
            if not (j.m == "beq" and j.rs == 0 and j.rt == 0 and j.tgt is not None):
                continue
            end = index_of.get(j.tgt)
            if end is None or not (other < end <= other + 40) or end > self.body_hi:
                continue
            first, second = ins[k + 2:jump] + [ins[jump + 1]], ins[other:end]
            if not first or not second or not all(quiet(y) for y in first + second):
                continue
            written = [set(_int_uses(arm[-1])[1]) for arm in (first, second)]
            common = [r for r in written[0] & written[1] if 16 <= r <= 23]
            if len(common) != 1:
                continue
            if any(y.tgt in (x.tgt, j.tgt) for n, y in enumerate(ins) if n not in (k, jump) and y.m in BRANCHES):
                continue
            if any(ins[n].a in self.labels for n in range(k + 2, end) if n != other):
                continue
            self.ternaries[k] = (jump, other, end, common[0])
        self.labels = self.labels - {ins[other].a for _j, other, _e, _r in self.ternaries.values()} \
            - {ins[end].a for _j, _o, end, _r in self.ternaries.values()}

    def label(self, addr):
        self.flush_call(addr)
        self.incs = []
        for r in list(self.R):
            if r in TEMPS or (A0 <= r <= A3 and (r - A0) not in self.reg_params):
                del self.R[r]
        self.args.clear()
        for r in list(self.F):
            if r < 20 and not (self.leaf and r in (12, 14) and (r - 12) // 2 in self.reg_params):
                del self.F[r]
        self.hilo = self.fcc = None
        self.retval = None
        self.block_start = len(self.items)

    def emit(self, item: Item):
        self.items.append(item)

    def flush_call(self, end):
        if self.call is not None:
            call, self.call = self.call, None
            self.emit(Item("S", call.dst or end, stmt=("expr", self.used_before(call))))
            if self.R.get(V0) is call:
                del self.R[V0]
            if self.F.get(0) is call:
                del self.F[0]

    def r(self, reg) -> X:
        if reg == 0:
            return const(0)
        if reg == SP:
            return X("sp")
        x = self.R.get(reg)
        if x is None:
            raise Unsupported(f"register {reg} read before it is set")
        if x is self.call:
            self.call = None
        if x.k == "fwd":
            x.a.fwd = True
            return x.b
        return x

    def f(self, reg, fmt="s") -> X:
        x = self.F.get(reg)
        if x is None:
            raise Unsupported(f"float register {reg} read before it is set")
        if x is self.call:
            self.call = None
            x.t = "f32" if fmt == "s" else "f64"
            self.callees[x.c]["ret"] = x.t
        if x.k == "fwd":
            x.a.fwd = True
            return x.b
        if x.k == "pv" and fmt == "d" and x.t == "f32":
            x.t = self.params[x.a] = "f64"
        return x

    def set(self, reg, x: X, ins: Ins, end):
        if reg == 0:
            return
        if not x.src:
            x.src = ins.a
        if self.leaf and A0 <= reg <= A3 and (reg - A0) in self.reg_params:
            lv = X("pv", reg - A0, t=self.params[reg - A0])
            self.store_item(lv, x, end, ins)
            self.R[reg] = X("pv", reg - A0, t=self.params[reg - A0])
            return
        if reg == V0:
            self.retval = x
        self.R[reg] = x
        if A0 <= reg <= A3:
            self.args[reg] = x

    def setf(self, reg, x: X, ins: Ins, end):
        if not x.src:
            x.src = ins.a
        if self.leaf and reg in (12, 14) and (reg - 12) // 2 in self.reg_params \
                and self.params[(reg - 12) // 2] in ("f32", "f64"):
            lv = X("pv", (reg - 12) // 2, t=self.params[(reg - 12) // 2])
            self.store_item(lv, x, end, ins)
            self.F[reg] = X("pv", (reg - 12) // 2, t=self.params[(reg - 12) // 2])
            return
        if reg == 0:
            self.retval = x
        self.F[reg] = x
        if reg in (12, 14):
            self.args[100 + reg] = x

    def store_item(self, lv: X, value: X, end, ins: Ins, reg=None, freg=None):
        self.flush_call(ins.a)
        value = self.used_before(value)
        lv = self.used_before(lv)
        item = Item("S", end, stmt=("=", lv, value), at=ins.a, lv=lv, rv=value)
        self.emit(item)
        # `x = x + n`: the value read may still be used by the rest of the statement (`x++`)
        if value.k == "b" and value.a == "+" and value.c.k == "c" and _same_place(value.b, lv):
            self.incs.append((item, value.b, value.c.a))
        # the register keeps the stored value: a later use inside the same statement reads the variable
        if reg is not None and reg in TEMPS and reg in self.R:
            self.R[reg] = X("fwd", item, lv, value)
        if freg is not None and freg in self.F and freg < 20 and freg not in (12, 14):
            self.F[freg] = X("fwd", item, lv, value)

    def used_before(self, x: X) -> X:
        """``x`` with reads that an earlier `v = v + n` of this statement left behind as ``v++``."""
        for item, old, n in list(self.incs):
            if item in self.items[self.block_start:] and _contains(x, old):
                if _contains(x, item.rv) and not _contains(_swap(x, item.rv, X("c", 0, t="s32")), old):
                    # the statement reads the *new* value from its register (``i + 1`` after
                    # ``i = i + 1``): the store is a statement of its own, e.g. a ``for`` step
                    # compiled together with the repeated test
                    continue
                self.items.remove(item)
                self.incs = [entry for entry in self.incs if entry[0] is not item]
                x = _swap(x, old, X("post", item.lv, n, t=item.lv.t, src=old.src))
        return x

    # -- memory --------------------------------------------------------------------------------
    def place(self, base_reg, off, t, ins, write=False) -> X:
        """The lvalue ``t`` at ``off(base_reg)``."""
        size = SIZES[t]
        if base_reg == SP and t == "s32" and ins is not None and ins.m in ("lw", "sw") and off in self.float_slots:
            # a float's bits on their way through an integer register: a ``float`` argument that
            # travels in $a1..$a3, or a ``float`` parameter that arrived in one
            t = "f32"
        if base_reg == SP:
            if off >= self.size:
                slot, sub = divmod(off - self.size, 4)
                if t == "f64":
                    if sub or self.params.get(slot, "f64") not in ("f64",) and slot in self.params \
                            and self.params[slot] != "s32":
                        raise Unsupported("double access to a parameter")
                    self.params[slot] = "f64"
                    return X("pv", slot, t="f64")
                if sub != 4 - size:
                    raise Unsupported("partial parameter access")
                if not write:
                    self.loaded.setdefault(("p", slot), t)
                have = self.params.get(slot)
                if have is None or slot not in self.param_typed:
                    if have in ("f32", "f64") and t != have:
                        raise Unsupported(f"parameter {slot} used as {have} and {t}")
                    self.params[slot] = t
                    self.param_typed.add(slot)
                elif have != t:
                    if SIZES[have] != size or "f" in have or "f" in t:
                        raise Unsupported(f"parameter {slot} used as {have} and {t}")
                    if write:
                        t = have
                    else:
                        return X("cast", t, X("pv", slot, t=have), t=t)
                return X("pv", slot, t=t)
            if not self.leaf and 16 <= off < self.arg_area_hi:
                raise Unsupported("read of the outgoing argument area")
            if not write:
                self.loaded.setdefault(("l", off), t)
            have = self.locals.get(off)
            if have is None:
                for o, ot in self.locals.items():
                    if o < off + size and off < o + SIZES[ot]:
                        raise Unsupported("overlapping locals")
                self.locals[off] = t
            elif have != t:
                if SIZES[have] != size or "f" in have or "f" in t:
                    raise Unsupported(f"local {off:X} used as {have} and {t}")
                if write:
                    t = have
                else:
                    return X("cast", t, X("lv", off, t=have), t=t)
            return X("lv", off, t=t)
        base = self.r(base_reg)
        return self.deref(base, off, t, ins, write)

    def deref(self, base: X, off: int, t: str, ins, write=False) -> X:
        if base.k == "hi":
            addr = (base.a + off) & 0xFFFFFFFF
            if not write:
                self.loaded.setdefault(("g", addr), t)
            have = self.globals.get(addr)
            if have is None:
                self.globals[addr] = t
            elif have != t:
                if SIZES[have] != SIZES[t] or "f" in have or "f" in t:
                    raise Unsupported(f"global {addr:X} used as {have} and {t}")
                if write:
                    return X("g", addr, t=have)
                return X("cast", t, X("g", addr, t=have), t=t)
            return X("g", addr, t=t)
        if base.k == "spx":
            # an element of a local array: the frame pointer is the base register
            return X("m", X("b", "+", self.local_address(off), base.a, src=base.src), 0, t=t)
        if base.k == "hix":
            addr = (base.a + off) & 0xFFFFFFFF
            have = self.global_arrays.get(addr)
            if have is None:
                self.global_arrays[addr] = t
            elif have != t:
                raise Unsupported(f"global array {addr:X} used as {have} and {t}")
            return X("gi", addr, base.b, t=t)
        return X("m", base, off, t=t)

    # -- one instruction -----------------------------------------------------------------------
    def step(self, i: Ins, end):
        m = i.m
        if m == "nop":
            return
        if m in LOADS:
            t = LOADS[m]
            if m == "lw" and i.rt == AT:
                raise Unsupported("structure copy")
            x = self.place(i.rs, i.imm, t, i)
            x.src = i.a
            if t in ("f32", "f64"):
                self.setf(i.rt, x, i, end)
            else:
                self.set(i.rt, x, i, end)
            return
        if m in STORES:
            t = STORES[m]
            if t in ("f32", "f64"):
                value = self.fval(i.rt, "s" if t == "f32" else "d")
            else:
                value = self.r(i.rt)
            if i.rs == SP and not self.leaf and 16 <= i.imm < self.arg_area_hi and i.imm < self.size:
                self.stack_args[i.imm] = value if t != "f32" and t != "f64" else X("farg", value, t=t)
                return
            lv = self.place(i.rs, i.imm, t, i, write=True)
            if lv.k in ("lv", "pv", "g") and lv.t != t:
                t = lv.t
            if t in ("f32", "f64"):
                self.store_item(lv, value, end, i, freg=i.rt)
            else:
                self.store_item(lv, value, end, i, reg=i.rt)
            return
        if m == "lui":
            self.set(i.rt, X("hi", (i.uimm << 16) & 0xFFFFFFFF, src=i.a), i, end)
            return
        if m in ("addiu", "addi"):
            if i.rs == SP:
                if i.rt == SP:
                    raise Unsupported("stack pointer change")
                self.set(i.rt, self.local_address(i.imm), i, end)
            elif i.rs == 0:
                if i.imm == 0 and A0 <= i.rt <= A3 and not (self.leaf and (i.rt - A0) in self.reg_params):
                    # An integer zero is ``move``d from $zero.  A zero loaded as an immediate into
                    # an argument register is the bit pattern of ``0.0f``: a float argument that
                    # travels in an integer register.
                    self.set(i.rt, X("fc", 0, t="f32", src=i.a), i, end)
                else:
                    self.set(i.rt, const(i.imm, i.a), i, end)
            else:
                s = self.r(i.rs)
                if s.k == "spx":
                    self.set(i.rt, X("b", "+", self.local_address(i.imm), s.a, src=s.src), i, end)
                elif s.k == "hi":
                    self.set(i.rt, X("sym", (s.a + i.imm) & 0xFFFFFFFF, src=s.src), i, end)
                else:
                    self.set(i.rt, self.add(s, const(i.imm), i), i, end)
            return
        if m in ("addu", "add") and i.fmt is None:           # not the float ``add.s``
            if i.rt == 0 or i.rs == 0:
                self.set(i.rd, self.r(i.rs if i.rt == 0 else i.rt), i, end)
                return
            s, t = self.r(i.rs), self.r(i.rt)
            if s.k == "sp" or t.k == "sp":
                other = _plain(t if s.k == "sp" else s)
                self.set(i.rd, X("spx", other, src=_src(other) or i.a), i, end)
            elif s.k == "hi" and i.rd == i.rs:
                self.set(i.rd, X("hix", s.a, t, src=s.src), i, end)
            else:
                self.set(i.rd, self.add(_plain(s), _plain(t), i), i, end)
            return
        if m in ("subu", "sub") and i.fmt is None:           # not the float ``sub.s``
            if i.rs == 0:
                self.set(i.rd, X("u", "-", _plain(self.r(i.rt)), src=i.a), i, end)
                return
            s, t = _plain(self.r(i.rs)), _plain(self.r(i.rt))
            if s.k == "scale" and s.a is t and i.rd == i.rs:
                self.set(i.rd, X("scale", t, s.b - 1, src=s.src), i, end)
            elif s.k == "scale" and t.k == "scale" and s.a is t.a and i.rd == i.rs:
                self.set(i.rd, X("scale", s.a, s.b - t.b, src=s.src), i, end)
            else:
                self.set(i.rd, X("b", "-", s, t, src=min(_src(s), _src(t), i.a)), i, end)
            return
        if m in ("sll", "srl", "sra"):
            s = _plain(self.r(i.rt))
            if m == "sll":
                if s.k == "scale" and i.rd == i.rt:
                    x = X("scale", s.a, s.b << i.sa, src=s.src)
                else:
                    x = X("scale", s, 1 << i.sa, src=_src(s) or i.a)
                    if i.rd != i.rt:
                        x.c = "shift"
            else:
                x = X("b", ">>", s, const(i.sa), t="s32" if m == "sra" else "u32", src=_src(s) or i.a)
            self.set(i.rd, x, i, end)
            return
        if m in ("sllv", "srlv", "srav"):
            s, n = _plain(self.r(i.rt)), _plain(self.r(i.rs))
            op = "<<" if m == "sllv" else ">>"
            self.set(i.rd, X("b", op, s, n, t="u32" if m == "srlv" else "s32", src=min(_src(s), _src(n), i.a)), i, end)
            return
        if m in ("and", "or", "xor", "nor"):
            if m == "or" and (i.rt == 0 or i.rs == 0):
                self.set(i.rd, self.r(i.rs if i.rt == 0 else i.rt), i, end)
                return
            if m == "nor":
                if i.rt != 0 and i.rs != 0:
                    raise Unsupported("nor")
                self.set(i.rd, X("u", "~", _plain(self.r(i.rs if i.rt == 0 else i.rt)), src=i.a), i, end)
                return
            s, t = _plain(self.r(i.rs)), _plain(self.r(i.rt))
            op = {"and": "&", "or": "|", "xor": "^"}[m]
            self.set(i.rd, X("b", op, s, t, src=min(_src(s), _src(t), i.a)), i, end)
            return
        if m in ("andi", "ori", "xori"):
            if m == "ori" and i.rs == 0:
                self.set(i.rt, const(i.uimm, i.a), i, end)
                return
            s = self.r(i.rs)
            if m == "ori" and s.k == "hi":
                self.set(i.rt, const(s.a | i.uimm, s.src), i, end)
                return
            s = _plain(s)
            if m == "xori" and i.uimm == 1 and s.k == "cmp":
                self.set(i.rt, negate(s), i, end)
                return
            op = {"andi": "&", "ori": "|", "xori": "^"}[m]
            self.set(i.rt, X("b", op, s, const(i.uimm), src=_src(s) or i.a), i, end)
            return
        if m in ("slt", "sltu", "slti", "sltiu"):
            sign = "u" if m in ("sltu", "sltiu") else "s"
            if m in ("slt", "sltu"):
                dest = i.rd
                if m == "sltu" and i.rs == 0:
                    x = self.eq(_plain(self.r(i.rt)), "!=", i)
                else:
                    s, t = _plain(self.r(i.rs)), _plain(self.r(i.rt))
                    x = self.less(s, t, sign, i)
            else:
                dest = i.rt
                s = _plain(self.r(i.rs))
                if m == "sltiu" and i.imm == 1:
                    x = self.eq(s, "==", i)
                    if dest not in TEMPS or dest in (V0, V1):
                        x.c = "lnot"
                else:
                    x = X("cmp", "<", s, const(i.imm), sign, src=_src(s) or i.a)
            self.set(dest, x, i, end)
            return
        if m in ("mult", "multu", "div", "divu") and i.fmt is None:   # not the float ``div.s``
            s, t = _plain(self.r(i.rs)), _plain(self.r(i.rt))
            self.hilo = (m, s, t, i.a)
            return
        if m in ("mflo", "mfhi"):
            if self.hilo is None:
                raise Unsupported("hi/lo")
            op, s, t, at = self.hilo
            src = min(_src(s), _src(t), at)
            if op in ("mult", "multu"):
                if m == "mfhi":
                    raise Unsupported("high word of a product")
                x = X("b", "*", s, t, src=src)
            else:
                x = X("b", "/" if m == "mflo" else "%", s, t, t="s32" if op == "div" else "u32", src=src)
            self.set(i.rd, x, i, end)
            return
        if m == "mfc1":
            v = self.f(i.rd)
            if v.k == "toint":
                x = X("cast", "s32", v.a, t="s32", src=_src(v.a))
            else:
                x = X("bits", v, t="f32", src=_src(v))
            self.set(i.rt, x, i, end)
            return
        if m == "mtc1":
            v = self.r(i.rt)
            self.setf(i.rd, X("raw", v, src=_src(v) or i.a), i, end)
            return
        if i.fmt is not None:
            self.fp(i, end)
            return
        raise Unsupported(f"instruction {m}")

    def local_address(self, off) -> X:
        if off >= self.size:
            slot, sub = divmod(off - self.size, 4)
            if sub:
                raise Unsupported("address inside a parameter")
            self.params.setdefault(slot, "s32")
            return X("pa", slot)
        if not self.leaf and off < self.arg_area_hi:
            raise Unsupported("address of the argument area")
        self.local_addr.add(off)
        return X("la", off)

    def add(self, s: X, t: X, i: Ins) -> X:
        s, t = _plain(s), _plain(t)
        # the steps of a multiplication by a constant reuse the destination register
        if i.m in ("addu", "add") and s.k == "scale" and i.rd == i.rs:
            if s.a is t:
                return X("scale", t, s.b + 1, src=s.src)
            if t.k == "scale" and t.a is s.a:
                return X("scale", s.a, s.b + t.b, src=s.src)
        if i.m in ("addu", "add") and t.k == "scale" and i.rd == i.rt and t.a is s:
            return X("scale", s, t.b + 1, src=t.src)
        return X("b", "+", s, t, src=min(_src(s) or i.a, _src(t) or i.a, i.a))

    def eq(self, s: X, op: str, i: Ins) -> X:
        """``s == 0`` / ``s != 0`` where ``s`` may be an exclusive-or of the compared values."""
        if s.k == "b" and s.a == "^":
            return X("cmp", op, s.b, s.c, "s", src=s.src)
        if s.k == "cmp" and op == "==":
            return negate(s)
        if s.k == "cmp":
            return s
        return X("cmp", op, s, const(0), "s", src=_src(s) or i.a)

    def less(self, s: X, t: X, sign: str, i: Ins) -> X:
        return X("cmp", "<", s, t, sign, src=min(_src(s) or i.a, _src(t) or i.a))

    def fp(self, i: Ins, end):
        m, fmt = i.m, i.fmt
        ft, fs, fd = i.rt, i.rd, i.sa
        t = "f32" if fmt == "s" else "f64"
        if m in ("add", "sub", "mul", "div"):
            a, b = self.fval(fs, fmt), self.fval(ft, fmt)
            op = {"add": "+", "sub": "-", "mul": "*", "div": "/"}[m]
            self.setf(fd, X("b", op, a, b, t=t, src=min(_src(a) or i.a, _src(b) or i.a)), i, end)
        elif m in ("neg", "abs"):
            if m == "abs":
                raise Unsupported("abs")
            a = self.fval(fs, fmt)
            self.setf(fd, X("u", "-", a, t=t, src=_src(a) or i.a), i, end)
        elif m == "mov":
            self.setf(fd, self.fval(fs, fmt), i, end)
        elif m == "trunc.w":
            a = self.fval(fs, fmt)
            self.setf(fd, X("toint", a, src=_src(a) or i.a), i, end)
        elif m in ("cvt.s", "cvt.d"):
            to = "f32" if m == "cvt.s" else "f64"
            if fmt == "w":
                a = self.F.get(fs)
                if a is None or a.k != "raw":
                    raise Unsupported("integer conversion source")
                v = _plain(a.a)
                self.setf(fd, X("cast", to, v, t=to, src=_src(v) or i.a), i, end)
            else:
                a = self.fval(fs, fmt)
                self.setf(fd, X("cast", to, a, t=to, src=_src(a) or i.a), i, end)
        elif m in ("c.eq", "c.lt", "c.le"):
            a, b = self.fval(fs, fmt), self.fval(ft, fmt)
            op = {"c.eq": "==", "c.lt": "<", "c.le": "<="}[m]
            self.fcc = X("cmp", op, a, b, "f", src=min(_src(a) or i.a, _src(b) or i.a))
            self.fcc.dst = (i.rd, i.rt)                       # the registers: they tell the operands' order
        else:
            raise Unsupported(f"float {m}")

    def is_double(self, reg) -> bool:
        x = self.F.get(reg)
        if x is None:
            return False
        if x.k == "raw":
            return self.F.get(reg + 1) is not None and self.F[reg + 1].k == "raw"
        return x.t == "f64"

    def fval(self, reg, fmt) -> X:
        x = self.f(reg, fmt)
        t = "f32" if fmt == "s" else "f64"
        if x.k == "raw":
            return _float_const(x, t, self.F.get(reg + 1) if fmt == "d" else None)
        if x.k in ("toint",):
            raise Unsupported("integer bits in a float operation")
        return x

    def do_pseudo(self, i: Ins, p):
        kind, dest, a, b, _n = p
        end = i.a + 4 * _n
        if kind == "divp2":
            s = _plain(self.r(a))
            self.set(dest, X("b", "/", s, const(1 << b), src=_src(s) or i.a), i, end)
        elif kind == "modp2":
            s = _plain(self.r(a))
            self.set(dest, X("b", "%", s, const(b), src=_src(s) or i.a), i, end)
        elif kind == "fcmpv":
            if self.fcc is None:
                raise Unsupported("float condition")
            self.set(dest, negate(self.fcc) if a else self.fcc, i, end)

    # -- control transfers ---------------------------------------------------------------------
    def transfer(self, i: Ins):
        m = i.m
        end = i.a + 8
        if m in ("jal", "jalr"):
            self.do_call(i, end)
            return
        if m == "jr":
            if i.rs != RA:
                raise Unsupported("jump table")
            if self.style != "jr":
                raise Unsupported("return in the body")
            self.do_return(end)
            return
        if m == "j":
            raise Unsupported("j")
        if m == "beq" and i.rs == 0 and i.rt == 0:
            if i.tgt == self.epilogue:
                if self.size == 0 and not self.saved and getattr(self, "style", "b") != "jr" and self.retval is None \
                        and self.F.get(0) is None:
                    # A frameless function that states ``return;`` returns with ``jr $ra`` on the
                    # spot.  A plain branch to its end is therefore not a return statement: it is
                    # control leaving the last statement (a ``break`` out of a final ``switch`` or
                    # loop, the end of an ``if``/``else`` arm).
                    self.flush_call(i.a)
                    self.emit(Item("J", end, tgt=self.ins[self.body_hi].a))
                    self.after_jump()
                    return
                self.do_return(end)
                return
            self.flush_call(i.a)
            self.emit(Item("J", end, tgt=i.tgt))
            self.after_jump()
            return
        # a conditional branch: the condition under which it is taken
        if m in ("beq", "bne"):
            s, t = _plain(self.r(i.rs)), _plain(self.r(i.rt))
            op = "==" if m == "beq" else "!="
            if i.rt == 0:
                if s.k in ("cmp", "and", "or", "not"):
                    cond = s if m == "bne" else negate(s)
                else:
                    cond = X("cmp", op, s, const(0), "s", src=_src(s) or i.a)
            else:
                cond = X("cmp", op, s, t, "s", src=min(_src(s) or i.a, _src(t) or i.a))
        elif m in ("blez", "bgtz", "bltz", "bgez"):
            s = _plain(self.r(i.rs))
            op = {"blez": "<=", "bgtz": ">", "bltz": "<", "bgez": ">="}[m]
            cond = X("cmp", op, s, const(0), "s", src=_src(s) or i.a)
        else:
            if self.fcc is None:
                raise Unsupported("float branch without a comparison")
            cond = self.fcc if m == "bc1t" else negate(self.fcc)
            self.fcc = None
        self.flush_call(i.a)
        cond = self.used_before(cond)
        item = Item("B", end, cond=cond, tgt=i.tgt, at=i.a)
        # stores that belong to the statement of this test (a `for` step or initialiser)
        first = cond.src or i.a
        merged = []
        while len(self.items) > self.block_start and self.items[-1].k == "S" and self.items[-1].at is not None \
                and (self.items[-1].at > first or self.items[-1].fwd):
            merged.append(self.items.pop())
        item.merged = merged[::-1]
        self.emit(item)
        self.after_jump(conditional=True)

    def after_jump(self, conditional=False):
        # registers hold nothing across a statement boundary; forwarded stores end here
        for r in list(self.R):
            x = self.R[r]
            if x.k == "fwd":
                del self.R[r]
        for r in list(self.F):
            if self.F[r].k == "fwd":
                del self.F[r]
        self.retval = None

    def do_return(self, end):
        value = self.retval
        if value is not None and value is self.call:
            value = None                                     # `return f();` and `f(); return;` are the same code
        if value is not None:
            kind = "f" if (self.F.get(0) is value) else "i"
            if value.k == "raw":
                value = _float_const(value, "f32")
            if kind == "f":
                t = value.t if value.t in ("f32", "f64") else "f32"
                if self.ret_type not in (None, t):
                    raise Unsupported("two return types")
                self.ret_type = t
            else:
                if self.ret_type not in (None, "s32"):
                    raise Unsupported("two return types")
                self.ret_type = "s32"
            if self.call is not None and not _contains(value, self.call):
                self.flush_call(end)
            self.call = None
        else:
            self.flush_call(end)
        if value is not None:
            value = self.used_before(value)
        self.emit(Item("R", end, val=value))
        self.after_jump()

    def do_call(self, i: Ins, end):
        if self.call is not None:
            self.flush_call(i.a)
        if i.m == "jal":
            target = i.tgt
            key = target
        else:
            target = _plain(self.r(i.rs))
            key = id(target)
        args = []
        fargs = [self.args.get(112), self.args.get(114)]
        slot = 0
        if fargs[0] is not None:
            for reg in (12, 14):
                if self.args.get(100 + reg) is None:
                    break
                double = self.is_double(reg)
                args.append(self.fval(reg, "d" if double else "s"))
                slot += 2 if double else 1
        while slot < 4 and (A0 + slot) in self.args:
            x = self.r(A0 + slot)
            if x.k == "bits":
                x = x.a if x.a.k != "raw" else _float_const(x.a, "f32")
            elif x.k == "hi":
                x = const(x.a, x.src)
            args.append(_plain(x))
            slot += 1
        if any((A0 + s) in self.args for s in range(slot + 1, 4)):
            raise Unsupported("argument registers are not a prefix")
        if self.stack_args:
            offs = sorted(self.stack_args)
            if slot < 4 or offs[0] != 16:
                if not (offs[0] == 16 and slot >= 2 and fargs[0] is not None):
                    raise Unsupported("stack arguments without register arguments")
            expect = 16
            for off in offs:
                x = self.stack_args[off]
                if off != expect:
                    raise Unsupported("gap in the stack arguments")
                if x.k == "farg":
                    expect += SIZES[x.t]
                    x = x.a if x.a.k != "raw" else _float_const(x.a, x.t)
                else:
                    expect += 4
                    if x.k == "hi":
                        x = const(x.a, x.src)
                args.append(_plain(x))
        self.stack_args = {}
        info = self.callees.setdefault(key, {"args": [], "ret": "s32", "target": target, "sites": []})
        info["sites"].append([a.t if a.t in ("f32", "f64") else "s32" for a in args])
        call = X("call", target, args, t="s32", src=min([_src(a) or i.a for a in args] + [i.a]))
        call.dst = end
        call.c = key
        # the call clobbers every caller-saved register
        for r in list(self.R):
            if r in TEMPS or A0 <= r <= A3:
                del self.R[r]
        for r in list(self.F):
            if r < 20:
                del self.F[r]
        self.args.clear()
        self.hilo = self.fcc = None
        self.R[V0] = call
        self.F[0] = call
        self.call = call
        self.retval = call


def _is_move_zero(i: Ins) -> bool:
    return (i.m in ("or", "addu") and i.rs == 0 and i.rt == 0) or (i.m == "addiu" and i.rs == 0 and i.imm == 0)


def _int_uses(i: Ins):
    """(registers read, registers written) of one instruction, integer registers only."""
    m = i.m
    if m in ("nop", "break", None) or i.fmt is not None or m in ("bc1f", "bc1t"):
        return (), ()
    if m in ("sll", "srl", "sra"):
        return (i.rt,), (i.rd,)
    if m in ("sllv", "srlv", "srav", "addu", "add", "subu", "sub", "and", "or", "xor", "nor", "slt", "sltu"):
        return (i.rs, i.rt), (i.rd,)
    if m in ("mult", "multu", "div", "divu", "beq", "bne"):
        return (i.rs, i.rt), ()
    if m in ("mfhi", "mflo"):
        return (), (i.rd,)
    if m in ("jr", "blez", "bgtz", "bltz", "bgez"):
        return (i.rs,), ()
    if m == "jalr":
        return (i.rs,), (RA,)
    if m in ("addiu", "addi", "slti", "sltiu", "andi", "ori", "xori"):
        return (i.rs,), (i.rt,)
    if m == "lui":
        return (), (i.rt,)
    if m in ("lb", "lbu", "lh", "lhu", "lw"):
        return (i.rs,), (i.rt,)
    if m in ("sb", "sh", "sw"):
        return (i.rs, i.rt), ()
    if m in ("lwc1", "ldc1", "swc1", "sdc1"):
        return (i.rs,), ()
    if m == "mfc1":
        return (), (i.rt,)
    if m == "mtc1":
        return (i.rt,), ()
    return (), ()


def _fp_uses(i: Ins):
    m = i.m
    if m in ("lwc1", "ldc1"):
        return (), (i.rt,)
    if m in ("swc1", "sdc1"):
        return (i.rt,), ()
    if m == "mfc1":
        return (i.rd,), ()
    if m == "mtc1":
        return (), (i.rd,)
    if i.fmt is not None:
        if m in ("c.eq", "c.lt", "c.le"):
            return (i.rd, i.rt), ()
        if m in ("add", "sub", "mul", "div"):
            return (i.rd, i.rt), (i.sa,)
        return (i.rd,), (i.sa,)
    return (), ()


def _src(x: X) -> int:
    return x.src or 0


def _plain(x: X) -> X:
    """A value as an operand: a bare ``lui`` is the constant it loads."""
    if x.k == "hi":
        return const(x.a, x.src)
    if x.k in ("hix", "spx", "sp"):
        raise Unsupported("indexed address without an access")
    if x.k == "bits":
        raise Unsupported("float bits in integer arithmetic")
    return x


def _same_place(a: X, b: X) -> bool:
    """Do two lvalues name the same object?"""
    if a.k != b.k or a.t != b.t:
        return False
    if a.k in ("lv", "pv", "g"):
        return a.a == b.a
    if a.k == "m":
        return a.a is b.a and a.b == b.b
    if a.k == "gi":
        return a.a == b.a and a.b is b.b
    return False


def _same_object(a: X, b: X) -> bool:
    """The same variable, field or element, whatever signedness each access gave it."""
    if not isinstance(a, X) or not isinstance(b, X) or a.k != b.k or SIZES.get(a.t) != SIZES.get(b.t):
        return False
    if a.k in ("lv", "pv", "g"):
        return a.a == b.a
    if a.k == "m":
        return a.b == b.b and same(_plain(a.a), _plain(b.a))
    return False


def _swap(x, old: X, new: X):
    """``x`` with the node ``old`` (by identity) replaced by ``new``."""
    if x is old:
        return new
    if not isinstance(x, X):
        return x
    parts, changed = [], False
    for part in (x.a, x.b, x.c):
        if isinstance(part, X):
            q = _swap(part, old, new)
        elif isinstance(part, list):
            q = [_swap(p, old, new) for p in part]
            if all(u is v for u, v in zip(q, part)):
                q = part
        else:
            q = part
        changed = changed or q is not part
        parts.append(q)
    if not changed:
        return x
    y = X(x.k, parts[0], parts[1], parts[2], x.t, x.src)
    y.dst = x.dst
    return y


def _contains(x, needle) -> bool:
    if x is needle:
        return True
    if not isinstance(x, X):
        return False
    for part in (x.a, x.b, x.c):
        if isinstance(part, X) and _contains(part, needle):
            return True
        if isinstance(part, list) and any(_contains(p, needle) for p in part):
            return True
    return False


def _float_const(raw: X, t: str, high: X | None = None) -> X:
    """The constant a ``mtc1`` of an integer constant loads."""
    v = raw.a
    if v.k == "hi":
        bits = v.a
    elif v.k == "c":
        bits = v.a & 0xFFFFFFFF
    else:
        raise Unsupported("integer register moved to a float register")
    if t == "f32":
        return X("fc", bits, t="f32", src=raw.src)
    hi = 0
    if high is not None:
        if high.k != "raw" or high.a.k not in ("hi", "c"):
            raise Unsupported("double constant")
        hi = high.a.a & 0xFFFFFFFF
    return X("fc", (hi << 32) | bits, t="f64", src=raw.src)


# ---------------------------------------------------------------------------------------------
# control flow: the branches spell the statements in source order


class Shape:
    def __init__(self, lifter: Lifter):
        self.L = lifter
        self.items = lifter.items
        self.ends = {it.end for it in self.items}
        self.start0 = lifter.ins[lifter.body_lo].a
        self.end = lifter.end

    def index(self, addr) -> int:
        """The item that starts at ``addr``."""
        if addr == self.end:
            return len(self.items)
        if addr != self.start0 and addr not in self.ends:
            raise Unsupported("branch into a statement")
        for k, it in enumerate(self.items):
            if it.end > addr:
                return k
        return len(self.items)

    def start(self, k) -> int:
        if k >= len(self.items):
            return self.end
        if k == 0:
            return self.start0
        return self.items[k - 1].end

    def build(self, lo=0, hi=None, brk=None, cont=None) -> list:
        items = self.items
        hi = len(items) if hi is None else hi
        out = []
        k = lo
        while k < hi:
            it = items[k]
            head = self.start(k)
            bottom = None
            if head in self.L.labels:
                for j in range(hi - 1, k - 1, -1):
                    if items[j].k in ("B", "J") and items[j].tgt == head:
                        bottom = j
                        break
            if bottom is not None:
                k = self.loop(out, k, bottom, hi, brk, cont)
                continue
            if it.k == "S":
                out.append(it.stmt)
                k += 1
            elif it.k == "R":
                out.append(("return", it.val))
                k += 1
            elif it.k == "J":
                if it.tgt == brk:
                    out.append(("break",))
                elif it.tgt == cont:
                    out.append(("continue",))
                else:
                    raise Unsupported("goto")
                k += 1
            elif it.k == "T":
                k = self.sections(out, it.val, list(it.store), it.tgt, k, hi, cont)
                if k is None:
                    raise Unsupported("jump table layout")
            else:
                after = self.switch(out, k, hi, cont)
                k = after if after is not None else self.branch(out, k, hi, brk, cont)
        return out

    def switch(self, out, k, hi, cont):
        """A small ``switch``: IDO tests the selector against each case value in turn (``beq`` to
        the case's code), jumps to the default or past the end, and lays the bodies out in source
        order; a ``break`` is a jump to the end.  Returns the item after the statement, or None
        when the items at ``k`` are not this shape."""
        items = self.items
        tests, n, selector, default = [], k, None, None
        while n < hi and items[n].k == "B" and not items[n].merged and (n == k or self.start(n) not in self.L.labels):
            cond = items[n].cond
            if not (cond.k == "cmp" and cond.a in ("==", "!=") and isinstance(cond.c, X) and cond.c.k == "c"
                    and isinstance(cond.c.a, int)):
                break
            if selector is None:
                selector = cond.b
            elif not same(cond.b, selector):
                break
            if cond.a == "!=":
                # the last test the other way round: not this value -> the default, else a jump
                # to the case's code
                if n + 1 >= hi or items[n + 1].k != "J" or self.start(n + 1) in self.L.labels:
                    return None
                default = items[n].tgt
                tests.append((cond.c.a, items[n + 1].tgt))
                n += 1
                break
            tests.append((cond.c.a, items[n].tgt))
            n += 1
        if not tests or n >= hi or items[n].k != "J" or self.start(n) in self.L.labels:
            return None
        if default is None:
            default = items[n].tgt
        return self.sections(out, selector, tests, default, n, hi, cont)

    def sections(self, out, selector, tests, default, n, hi, cont):
        """The bodies of a ``switch`` whose dispatch ends at item ``n``: one section per label, in
        address order, up to where the breaks go."""
        items = self.items
        try:
            places = sorted({self.index(target) for _value, target in tests} | {self.index(default)})
        except Unsupported:
            return None
        if places[0] != n + 1 or places[-1] > hi:
            return None                                      # the first body follows the dispatch
        # the end: where the breaks go, or the last label when nothing jumps past it
        end = places[-1]
        for j in range(n + 1, places[-1]):
            if items[j].k == "J" and items[j].tgt is not None:
                try:
                    end = max(end, self.index(items[j].tgt))
                except Unsupported:
                    return None
        if end > hi:
            return None
        end_addr = self.start(end)
        if len(set(value for value, _target in tests)) != len(tests):
            return None
        bounds = [place for place in places if place < end] + [end]
        sections = []
        for lo, nxt in zip(bounds, bounds[1:]):
            addr = self.start(lo)
            labels = [value for value, target in tests if target == addr]
            if default == addr:
                labels.append(None)                           # ``default:``
            sections.append((labels, self.build(lo, nxt, end_addr, cont)))
        if any(target == end_addr for _value, target in tests):
            # a case whose code is empty and last: it labels the end of the statement
            sections.append(([value for value, target in tests if target == end_addr], []))
        out.append(("switch", selector, sections))
        return end

    # a run of tests that together decide between two addresses
    def chain(self, m, n, tt, ff):
        """The condition under which tests ``m..n-1`` reach ``tt`` (they reach ``ff`` otherwise)."""
        items = self.items
        it = items[m]
        fall = self.start(n)
        if m == n - 1:
            if it.tgt == ff and fall == tt:
                return negate(it.cond)
            if it.tgt == tt and fall == ff:
                return it.cond
            raise Unsupported("condition shape")
        if it.tgt == ff:
            return X("and", negate(it.cond), self.chain(m + 1, n, tt, ff), src=it.cond.src)
        if it.tgt == tt:
            return X("or", it.cond, self.chain(m + 1, n, tt, ff), src=it.cond.src)
        for q in range(m + 2, n):
            if self.start(q) == it.tgt:
                mid = it.tgt
                try:
                    left = self.chain(m, q, tt, mid)
                    return X("or", left, self.chain(q, n, tt, ff), src=it.cond.src)
                except Unsupported:
                    left = self.chain(m, q, mid, ff)
                    return X("and", left, self.chain(q, n, tt, ff), src=it.cond.src)
        raise Unsupported("condition shape")

    def tests(self, k, hi):
        """The run of consecutive tests starting at item ``k``."""
        n = k
        while n < hi and self.items[n].k == "B" and (n == k or not self.items[n].merged) \
                and (n == k or self.start(n) not in self.L.labels or self.inner_label(k, n)):
            n += 1
        return n

    def inner_label(self, k, n) -> bool:
        """Is the label at test ``n`` only reached from tests ``k..n-1``?"""
        addr = self.start(n)
        for j, it in enumerate(self.items):
            if it.k in ("B", "J") and it.tgt == addr and not (k <= j < n):
                return False
        return True

    def branch(self, out, k, hi, brk, cont) -> int:
        items = self.items
        n = self.tests(k, hi)
        cond = None
        while n > k:
            last = items[n - 1]
            tt, ff = self.start(n), last.tgt
            if ff > tt:
                try:
                    cond = self.chain(k, n, tt, ff)
                    break
                except Unsupported:
                    pass
            n -= 1
        if cond is None:
            raise Unsupported("conditional jump out of order")
        f = self.index(ff)
        if f > hi:
            raise Unsupported("conditional jump out of the block")
        merged = items[k].merged
        then_lo, then_hi = n, f
        # `for (init; cond; step)`: the guarded block is exactly one loop
        if then_hi - 1 >= then_lo and items[then_hi - 1].k == "B" and items[then_hi - 1].tgt == self.start(then_lo) \
                and self.start(then_lo) in self.L.labels:
            made = self.for_loop(out, then_lo, then_hi - 1, merged, brk, cont, guard=cond)
            if made:
                return f
        if merged:
            cond = self.assign_in(cond, merged)
        else_part = None
        last = items[then_hi - 1] if then_hi > then_lo else None
        if last is not None and last.k == "J" and last.tgt > self.start(f) and last.tgt != brk and last.tgt != cont:
            e = self.index(last.tgt)
            if e <= hi:
                then = self.build(then_lo, then_hi - 1, brk, cont)
                else_part = self.build(f, e, brk, cont)
                out.append(("if", cond, then, else_part))
                return e
        then = self.build(then_lo, then_hi, brk, cont)
        out.append(("if", cond, then, None))
        return f

    def assign_in(self, cond: X, merged: list) -> X:
        """Stores made inside the test's own statement: ``if ((x = f()) != 0)``."""
        for item in merged:
            lv, value = item.lv, item.rv
            done = [False]
            cond = _replace_first(cond, lv, value, done)
            if not done[0] and _contains(cond, value):
                # the test reads the stored value from its register: ``if ((x = y) == 0)``
                cond = _swap(cond, value, X("asg", lv, value, t=value.t, src=value.src))
                done[0] = True
            if not done[0]:
                raise Unsupported("store inside a condition")
        return cond

    def loop(self, out, k, bottom, hi, brk, cont) -> int:
        items = self.items
        head = self.start(k)
        exit_ = self.start(bottom + 1)
        last = items[bottom]
        if last.k == "J":
            body = self.build(k, bottom, exit_, head) if bottom > k else []
            out.append(("while1", body))
            return bottom + 1
        if self.for_loop(out, k, bottom, None, brk, cont, guard=None):
            return bottom + 1
        c0, cond = self.bottom_tests(k, bottom, head, exit_)
        if items[c0].merged:
            cond = self.assign_in(cond, items[c0].merged)
        body = self.build(k, c0, exit_, self.start(c0))
        out.append(("dowhile", body, cond))
        return bottom + 1

    def bottom_tests(self, k, bottom, head, exit_):
        """The tests that end the loop ``k..bottom`` and the condition under which it repeats."""
        c0 = bottom
        while c0 > k and self.items[c0 - 1].k == "B" and not self.items[c0].merged:
            c0 -= 1
        while True:
            try:
                return c0, self.chain(c0, bottom + 1, head, exit_)
            except Unsupported:
                if c0 >= bottom:
                    raise
                c0 += 1

    def for_loop(self, out, k, bottom, init_items, brk, cont, guard) -> bool:
        """``for (init; cond; step) body`` when the repeated test carries its step (or the first
        test its initialiser).  ``k..bottom`` is the loop, ``guard`` the first test if there is one."""
        items = self.items
        head = self.start(k)
        exit_ = self.start(bottom + 1)
        try:
            c0, cond = self.bottom_tests(k, bottom, head, exit_)
        except Unsupported:
            return False
        step_items = items[c0].merged
        if not step_items and not init_items:
            return False
        # the test reads the stepped variables from their registers: print the variables
        for item in step_items:
            cond = _replace_all(cond, item.rv, item.lv)
        steps = [("=", item.lv, item.rv) for item in step_items]
        inits = [("=", item.lv, item.rv) for item in (init_items or [])]
        if not inits and (guard is None or not same(guard, cond)):
            # no first test, or one that was folded: the initial values made it constant.  The
            # initialisers are the statements just before the loop that set tested variables
            # to constants.
            tested = _variables(cond)
            while out and out[-1][0] == "=" and _var_key(out[-1][1]) in tested and _is_constant(out[-1][2]) \
                    and len(inits) < 3:
                inits.append(out.pop())
            inits.reverse()
            if not inits and guard is None:
                return False
        if not step_items and not inits:
            return False
        body = self.build(k, c0, exit_, self.start(c0))
        out.append(("for", inits, cond, steps, body))
        return True


def _var_key(x: X):
    return (x.k, x.a) if x.k in ("lv", "pv", "g") else None


def _variables(x) -> set:
    found = set()

    def walk(n):
        if not isinstance(n, X):
            return
        key = _var_key(n)
        if key:
            found.add(key)
        for part in (n.a, n.b, n.c):
            if isinstance(part, X):
                walk(part)
            elif isinstance(part, list):
                for p in part:
                    walk(p)
    walk(x)
    return found


def _is_constant(x: X) -> bool:
    return x.k in ("c", "hi", "fc") or (x.k == "u" and _is_constant(x.b))


EXTEND = {"s16": 16, "s8": 24}
MASK = {"u8": 0xFF, "u16": 0xFFFF}


def _same_lvalue(a: X, b: X) -> bool:
    if a.k != b.k or a.t != b.t:
        return False
    if a.k in ("lv", "pv", "g"):
        return a.a == b.a
    return a is b


def _replace_all(x, old: X, new: X):
    """``x`` with the value ``old`` (by identity) read as the variable ``new`` it was stored to.
    A narrow variable is read back extended, so the extension of the stored value is the variable."""
    if x is old:
        return new
    if not isinstance(x, X):
        return x
    if new.t in EXTEND and x.k == "b" and x.a == ">>" and x.t == "s32" and is_const(x.c, EXTEND[new.t]) \
            and x.b.k == "scale" and x.b.b == 1 << EXTEND[new.t] and x.b.a is old:
        return new
    if new.t in MASK and x.k == "b" and x.a == "&" and is_const(x.c, MASK[new.t]) and x.b is old:
        return new
    parts = []
    changed = False
    for part in (x.a, x.b, x.c):
        if isinstance(part, X):
            q = _replace_all(part, old, new)
            changed = changed or q is not part
            parts.append(q)
        elif isinstance(part, list):
            q = [_replace_all(p, old, new) for p in part]
            changed = changed or any(u is not v for u, v in zip(q, part))
            parts.append(q)
        else:
            parts.append(part)
    if not changed:
        return x
    y = X(x.k, parts[0], parts[1], parts[2], x.t, x.src)
    y.dst = x.dst
    return y


def _replace_first(x, lv: X, value: X, done: list):
    """``x`` with the first read of the stored variable replaced by the assignment itself."""
    if done[0] or not isinstance(x, X):
        return x
    if x is lv or (x.k == lv.k and x.k in ("lv", "pv", "g") and x.a == lv.a and x is not value) \
            or (x.k == "m" and lv.k == "m" and x is not value and x.b == lv.b
                and SIZES.get(x.t) == SIZES.get(lv.t) and same(_plain(x.a), _plain(lv.a))):
        # (a field or element read back after the store: ``if (++p->n == 1)``)
        done[0] = True
        if x.k == "m" and x.t != lv.t:
            lv = X("m", lv.a, lv.b, t=x.t, src=lv.src)       # a store does not tell signed from unsigned: the read does
        return X("asg", lv, value, t=lv.t, src=x.src)
    parts = []
    changed = False
    for part in (x.a, x.b, x.c):
        if isinstance(part, X) and not done[0]:
            q = _replace_first(part, lv, value, done)
            changed = changed or q is not part
            parts.append(q)
        else:
            parts.append(part)
    if not changed:
        return x
    y = X(x.k, parts[0], parts[1], parts[2], x.t, x.src)
    return y


def same(a, b) -> bool:
    """Structural equality of two expressions."""
    if a is b:
        return True
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    if not isinstance(a, X) or not isinstance(b, X):
        return a == b
    if a.k != b.k or a.t != b.t:
        return False
    return same(a.a, b.a) and same(a.b, b.b) and (same(a.c, b.c) or a.k in ("scale", "cmp", "call"))


# ---------------------------------------------------------------------------------------------
# C text


_FLOAT_TEMPS = (4, 6, 8, 10, 16, 18)                         # the order IDO allocates float scratch registers in
FLIP_OP = {"<": ">", "<=": ">=", "==": "==", "!=": "!="}


def _hex(v: int) -> str:
    if -9 <= v <= 9:
        return str(v)
    return f"-0x{-v:X}" if v < 0 else f"0x{v:X}"


def _float_text(bits: int, t: str) -> str:
    if t == "f32":
        value, = struct.unpack(">f", struct.pack(">I", bits & 0xFFFFFFFF))
        if value != value or value in (float("inf"), float("-inf")):
            raise Unsupported("float constant")
        for digits in range(1, 18):
            text = f"{value:.{digits}g}"
            if struct.pack(">f", float(text)) == struct.pack(">I", bits & 0xFFFFFFFF):
                break
        if "." not in text and "e" not in text and "n" not in text:
            text += ".0"
        return text + "f"
    value, = struct.unpack(">d", struct.pack(">Q", bits))
    if value != value or value in (float("inf"), float("-inf")):
        raise Unsupported("float constant")
    text = repr(value)
    if "." not in text and "e" not in text:
        text += ".0"
    return text


class Printer:
    """Writes the statements as C.  ``options``: ``cast_fields`` prints every ``p->f`` access as
    ``*(T *)(p + n)``; ``pad_bottom`` declares the unexplained bottom of the locals as a local;
    ``no_flip`` keeps every ``<`` as the instruction has it."""

    def __init__(self, lifter: Lifter, body: list, name: str, options=()):
        self.L, self.body, self.name, self.options = lifter, body, name, set(options)
        self.cast_form: set[int] = set()
        self.structs: dict[tuple, str] = {}
        self.sym_uses: dict[int, list] = {}
        self.func_syms: set[int] = {info["target"] for info in lifter.callees.values()
                                    if isinstance(info["target"], int)}
        self.is_func = getattr(lifter, "is_func", lambda a: False)
        self.aggregates: dict[int, int] = {}
        self.stepped: dict[tuple, int] = {}                  # variable stepped as a pointer -> element size

    # -- walking -------------------------------------------------------------------------------
    def exprs(self, stmts=None):
        for st in (self.body if stmts is None else stmts):
            kind = st[0]
            if kind == "=":
                yield st[1]
                yield st[2]
            elif kind == "expr":
                yield st[1]
            elif kind == "return":
                if st[1] is not None:
                    yield st[1]
            elif kind == "if":
                yield st[1]
                yield from self.exprs(st[2])
                if st[3]:
                    yield from self.exprs(st[3])
            elif kind == "dowhile":
                yield from self.exprs(st[1])
                yield st[2]
            elif kind == "while1":
                yield from self.exprs(st[1])
            elif kind == "for":
                yield from self.exprs(st[1])
                yield st[2]
                yield from self.exprs(st[3])
                yield from self.exprs(st[4])
            elif kind == "switch":
                yield st[1]
                for _labels, body in st[2]:
                    yield from self.exprs(body)

    def nodes(self, x):
        if not isinstance(x, X):
            return
        yield x
        for part in (x.a, x.b, x.c):
            if isinstance(part, X):
                yield from self.nodes(part)
            elif isinstance(part, list):
                for p in part:
                    yield from self.nodes(p)

    def prepare(self):
        L = self.L
        for e in self.exprs():
            for n in self.nodes(e):
                if n.k == "post" and n.b not in (1, -1) and isinstance(n.a, X) and n.a.k in ("g", "lv"):
                    # ``x = p++`` with a step of several bytes: ``p`` is a pointer to elements of
                    # that size (the old value is used and the step is stored in one statement,
                    # which only a typed pointer's ``++`` compiles to)
                    if self.stepped.setdefault((n.a.k, n.a.a), abs(n.b)) != abs(n.b):
                        raise Unsupported("one pointer stepped by two sizes")
                if n.k == "gi":
                    natural = (n.b.k == "scale" and n.b.b == SIZES[n.t]) or SIZES[n.t] == 1
                    self.sym_uses.setdefault(n.a, []).append((n.t, natural))
                elif n.k == "sym":
                    self.sym_uses.setdefault(n.a, [])
                elif n.k == "m" and n.a.k == "sym":
                    self.sym_uses.setdefault(n.a.a, []).append((n.t, n.b % SIZES[n.t] == 0))
        # every address-taken local without an access of its own is an aggregate reaching up to
        # the next local
        offsets = sorted(set(L.locals) | L.local_addr)
        for k, off in enumerate(offsets):
            if off in L.local_addr and off not in L.locals:
                top = offsets[k + 1] if k + 1 < len(offsets) else L.size
                self.aggregates[off] = top - off
        for e in self.exprs():
            self.solve(e)

    # -- operand classes -----------------------------------------------------------------------
    def cls(self, x: X) -> int:
        k = x.k
        if k in ("c", "fc", "hi"):
            return -1
        if k in ("lv", "pv", "g"):
            return 0 if SIZES.get(x.t, 4) >= 4 else 1
        if k in ("gi", "call"):
            return 2
        if k == "m":
            if x.a.k in ("sym", "la") or self.indexed(x) or id(x) in self.cast_form or "cast_fields" in self.options:
                return 2
            return 1
        if k in ("sym", "la", "pa"):
            return 0
        best = 1
        for part in (x.a, x.b, x.c):
            if isinstance(part, X):
                best = max(best, self.cls(part))
        return best

    @staticmethod
    def indexed(x: X) -> bool:
        return x.a.k == "b" and x.a.a == "+"

    def fields(self, x: X):
        """Field accesses that decide the class of ``x``."""
        if x.k == "m":
            if not (x.a.k in ("sym", "la") or self.indexed(x)):
                yield x
            return
        if x.k in ("call", "gi"):
            return
        for part in (x.a, x.b, x.c):
            if isinstance(part, X):
                yield from self.fields(part)

    def solve(self, x):
        if not isinstance(x, X):
            return
        for part in (x.a, x.b, x.c):
            if isinstance(part, X):
                self.solve(part)
            elif isinstance(part, list):
                for p in part:
                    self.solve(p)
        if (x.k == "b" and x.a in COMMUTATIVE) or (x.k == "cmp" and x.a in ("==", "!=")):
            left, right = x.b, x.c
            if self.cls(left) < self.cls(right):
                for node in self.fields(left):
                    self.cast_form.add(id(node))
                    if self.cls(left) >= self.cls(right):
                        break

    # -- names ---------------------------------------------------------------------------------
    def sym_decl(self, addr):
        """('func',) | ('scalar', T) | ('array', T) | ('bytes',)"""
        L = self.L
        if addr in self.func_syms or self.is_func(addr):
            return ("func",)
        if addr in L.globals:
            return ("scalar", L.globals[addr])
        uses = self.sym_uses.get(addr, [])
        types = {t for t, _n in uses}
        if uses and len(types) == 1 and all(n for _t, n in uses):
            return ("array", uses[0][0])
        return ("bytes",)

    def sym_name(self, addr):
        if addr in self.func_syms or self.is_func(addr):
            return self.L.func_name(addr)
        return self.L.data_name(addr)

    def sym_addr(self, addr) -> str:
        """The address of a symbol as a ``u8 *`` expression."""
        kind = self.sym_decl(addr)
        name = self.sym_name(addr)
        if kind[0] == "bytes":
            return name
        if kind[0] == "func":
            return f"(u8 *){name}"
        if kind[0] == "array":
            return f"(u8 *){name}"
        return f"(u8 *)&{name}"

    def local_name(self, off):
        return f"sp{off:X}"

    def local_addr(self, off) -> str:
        if off in self.aggregates:
            return self.local_name(off)
        return f"(u8 *)&{self.local_name(off)}"

    def struct_for(self, off, t) -> str:
        key = (off, t)
        if key not in self.structs:
            self.structs[key] = f"n64dk_f{off:X}_{t}"
        return self.structs[key]

    # -- expressions ---------------------------------------------------------------------------
    def p(self, x: X) -> str:
        k = x.k
        if k == "c":
            v = x.a
            if v >= 0x80000000:
                return f"0x{v:X}"
            return _hex(v)
        if k == "hi":
            return self.p(const(x.a))
        if k == "fc":
            return _float_text(x.a, x.t)
        if k == "lv":
            return f"((s32){self.local_name(x.a)})" if ("lv", x.a) in self.stepped else self.local_name(x.a)
        if k == "pv":
            return f"arg{x.a}"
        if k == "g":
            return f"((s32){self.sym_name(x.a)})" if ("g", x.a) in self.stepped else self.sym_name(x.a)
        if k == "sym":
            kind = self.sym_decl(x.a)
            name = self.sym_name(x.a)
            return f"(s32){name}" if kind[0] != "scalar" else f"(s32)&{name}"
        if k == "la":
            if x.a in self.aggregates:
                return f"(s32){self.local_name(x.a)}"
            return f"(s32)&{self.local_name(x.a)}"
        if k == "pa":
            return f"(s32)&arg{x.a}"
        if k == "gi":
            kind = self.sym_decl(x.a)
            name = self.sym_name(x.a)
            idx = x.b
            if kind[0] == "array" and kind[1] == x.t:
                if SIZES[x.t] == 1:
                    return f"{name}[{self.bare(idx)}]"
                return f"{name}[{self.bare(idx.a)}]"
            if kind[0] == "bytes" and x.t == "u8":
                return f"{name}[{self.bare(idx)}]"
            return f"*({x.t} *)({self.sym_addr(x.a)} + {self.p(idx)})"
        if k == "m":
            return self.memory(x)
        if k == "scale":
            if x.c == "shift" and x.b & (x.b - 1) == 0:
                return f"({self.p(x.a)} << {x.b.bit_length() - 1})"
            return f"({self.p(x.a)} * {_hex(x.b)})"
        if k == "b":
            return self.binary(x)
        if k == "u":
            return f"({x.a}{self.p(x.b)})"
        if k == "cmp":
            return self.compare(x)
        if k == "not":
            return f"(!{self.p(x.a)})"
        if k == "and":
            return f"({self.p(x.a)} && {self.p(x.b)})"
        if k == "or":
            return f"({self.p(x.a)} || {self.p(x.b)})"
        if k == "call":
            return self.call(x)
        if k == "cast":
            return f"(({x.a}){self.p(x.b)})"
        if k == "tern":
            return f"({self.bare(x.a)} ? {self.p(x.b)} : {self.p(x.c)})"
        if k == "asg":
            lv, value = x.a, x.b
            if value.k == "b" and value.a == "+" and value.c.k == "c" and (
                    _same_lvalue(value.b, lv) or _same_object(_plain(value.b), lv)):
                n = value.c.a
                return f"({self.p(lv)} {'+' if n >= 0 else '-'}= {_hex(abs(n))})"
            return f"({self.p(lv)} = {self.bare(value)})"
        if k == "post":
            n = x.b
            if n in (1, -1):
                return f"{self.p(x.a)}{'++' if n > 0 else '--'}"
            key = (x.a.k, x.a.a) if isinstance(x.a, X) else None
            if self.stepped.get(key) == abs(n):
                name = self.local_name(x.a.a) if x.a.k == "lv" else self.sym_name(x.a.a)
                return f"((s32){name}{'++' if n > 0 else '--'})"
            raise Unsupported("old value of a stepped variable")
        if k == "bits":
            return self.p(x.a)
        if k == "fwd":
            return self.p(x.b)
        raise Unsupported(f"cannot print {k}")

    def bare(self, x: X) -> str:
        text = self.p(x)
        if text.startswith("(") and text.endswith(")") and _balanced(text[1:-1]) and x.k != "cast" \
                and not (x.k in ("sym", "la", "pa")):
            return text[1:-1]
        return text

    def signed(self, x: X) -> str:
        text = self.p(x)
        return f"(s32){text}" if x.t == "u32" or (x.k == "c" and x.a >= 0x80000000) else text

    def unsigned(self, x: X) -> str:
        text = self.p(x)
        if x.k == "c":
            return f"0x{x.a & 0xFFFFFFFF:X}U" if x.a < 0 else text + "U"
        return text if x.t == "u32" else f"(u32){text}"

    def binary(self, x: X) -> str:
        op, a, b = x.a, x.b, x.c
        if x.t in ("f32", "f64"):
            return f"({self.p(a)} {op} {self.p(b)})"
        if op == "+" and b.k == "c" and b.a < 0:
            return f"({self.p(a)} - {_hex(-b.a)})"
        if op in ("/", "%"):
            if x.t == "u32":
                return f"({self.unsigned(a)} {op} {self.unsigned(b)})"
            return f"({self.signed(a)} {op} {self.signed(b)})"
        if op == ">>":
            if x.t == "u32":
                return f"({self.unsigned(a)} >> {self.p(b)})"
            return f"({self.signed(a)} >> {self.p(b)})"
        return f"({self.p(a)} {op} {self.p(b)})"

    def compare(self, x: X) -> str:
        op, a, b = x.a, x.b, x.c
        if x.c == "lnot" and False:
            return f"(!{self.p(a)})"
        if x.t == "f":
            later = _src(a) > _src(b) > 0
            if isinstance(x.dst, tuple) and x.dst[0] != x.dst[1] and all(r in _FLOAT_TEMPS for r in x.dst):
                # IDO hands out float scratch registers in the order it meets the operands, left
                # one first, whatever order their loads are emitted in (a constant is loaded
                # early): the operand in the earlier register is the left one of the source
                later = _FLOAT_TEMPS.index(x.dst[0]) > _FLOAT_TEMPS.index(x.dst[1])
            if "no_flip" in self.options:
                later = not later
            if later and op in ("<", "<=", "==", "!="):
                return f"({self.p(b)} {FLIP_OP[op]} {self.p(a)})"
            return f"({self.p(a)} {op} {self.p(b)})"
        if op in ("==", "!="):
            return f"({self.p(a)} {op} {self.p(b)})"
        flip = "no_flip" not in self.options and b.k != "c" and a.k != "c" and _src(a) > _src(b) > 0
        if flip:
            op = {"<": ">", ">=": "<=", ">": "<", "<=": ">="}[op]
            a, b = b, a
        if x.t == "u":
            return f"({self.unsigned(a)} {op} {self.unsigned(b)})"
        return f"({self.signed(a)} {op} {self.signed(b)})"

    def memory(self, x: X) -> str:
        base, off, t = x.a, x.b, x.t
        if base.k == "sym":
            kind = self.sym_decl(base.a)
            name = self.sym_name(base.a)
            if kind[0] == "array" and kind[1] == t and off % SIZES[t] == 0:
                return f"{name}[{off // SIZES[t]}]"
            if kind[0] == "bytes" and t == "u8":
                return f"{name}[{off}]"
            addr = self.sym_addr(base.a)
            return f"*({t} *)({addr} + {_hex(off)})" if off else f"*({t} *){addr}" if " " not in addr else f"*({t} *)({addr})"
        if base.k == "la":
            if base.a in self.aggregates and t == "u8":
                return f"{self.local_name(base.a)}[{off}]"
            addr = self.local_addr(base.a)
            return f"*({t} *)({addr} + {_hex(off)})" if off else f"*({t} *)({addr})"
        ptr = self.p(base)
        if self.cls(x) == 2:
            return f"*({t} *)({ptr} + {_hex(off)})" if off else f"*({t} *){ptr}"
        return f"(({self.struct_decl(off, t)} *){ptr})->f"

    def struct_decl(self, off, t) -> str:
        return "struct " + self.struct_for(off, t)

    def float_positions(self, key) -> list:
        """Per argument position of one callee: the float type some call passes there, or None.
        Raises when the calls cannot share one prototype."""
        sites = self.L.callees[key]["sites"]
        if not any("f32" in site or "f64" in site for site in sites):
            return []
        if len({len(site) for site in sites}) != 1:
            raise Unsupported("float arguments differ between calls")
        merged = []
        for position in range(len(sites[0])):
            kinds = {site[position] for site in sites if site[position] in ("f32", "f64")}
            if len(kinds) > 1:
                raise Unsupported("float arguments differ between calls")
            merged.append(next(iter(kinds)) if kinds else None)
        return merged

    def call(self, x: X) -> str:
        floats = self.float_positions(x.c) if x.c in self.L.callees else []
        parts = []
        for position, a in enumerate(x.b):
            want = floats[position] if position < len(floats) else None
            if want and a.t not in ("f32", "f64"):
                # another call passes a float here: this constant is that float's bit pattern
                if not (a.k == "c" and isinstance(a.a, int) and want == "f32"):
                    raise Unsupported("float arguments differ between calls")
                parts.append(_float_text(a.a & 0xFFFFFFFF, "f32"))
            else:
                parts.append(self.bare(a))
        args = ", ".join(parts)
        if isinstance(x.a, int):
            return f"{self.L.func_name(x.a)}({args})"
        info = self.L.callees[x.c]
        return f"(({info['ret']} (*)()){self.p(x.a)})({args})"

    # -- statements ----------------------------------------------------------------------------
    def assign(self, lv: X, value: X) -> str:
        if isinstance(lv, X) and (lv.k, lv.a) in self.stepped:
            # the variable is declared as a pointer: what is stored is an address
            name = self.local_name(lv.a) if lv.k == "lv" else self.sym_name(lv.a)
            return f"{name} = (struct n64dk_e{self.stepped[(lv.k, lv.a)]} *){self.p(value)}"
        return f"{self.p(lv)} = {self.bare(value)}"

    def step_text(self, st) -> str:
        lv, value = st[1], st[2]
        if value.k == "b" and value.a == "+" and _same_lvalue(value.b, lv) and value.c.k == "c":
            n = value.c.a
            if n == 1:
                return f"{self.p(lv)}++"
            if n == -1:
                return f"{self.p(lv)}--"
            return f"{self.p(lv)} {'+' if n >= 0 else '-'}= {_hex(abs(n))}"
        return self.assign(lv, value)

    def block(self, stmts, depth) -> list[str]:
        pad = "    " * depth
        out = []
        for st in stmts:
            kind = st[0]
            if kind == "=":
                out.append(f"{pad}{self.assign(st[1], st[2])};")
            elif kind == "expr":
                out.append(f"{pad}{self.bare(st[1])};")
            elif kind == "return":
                out.append(f"{pad}return;" if st[1] is None else f"{pad}return {self.bare(st[1])};")
            elif kind == "break":
                out.append(f"{pad}break;")
            elif kind == "continue":
                out.append(f"{pad}continue;")
            elif kind == "if":
                out.append(f"{pad}if ({self.bare(st[1])}) {{")
                out += self.block(st[2], depth + 1)
                if st[3] is not None:
                    out.append(f"{pad}}} else {{")
                    out += self.block(st[3], depth + 1)
                out.append(f"{pad}}}")
            elif kind == "dowhile":
                out.append(f"{pad}do {{")
                out += self.block(st[1], depth + 1)
                out.append(f"{pad}}} while ({self.bare(st[2])});")
            elif kind == "while1":
                out.append(f"{pad}while (1) {{")
                out += self.block(st[1], depth + 1)
                out.append(f"{pad}}}")
            elif kind == "for":
                init = ", ".join(self.assign(s[1], s[2]) for s in st[1])
                step = ", ".join(self.step_text(s) for s in st[3])
                out.append(f"{pad}for ({init}; {self.bare(st[2])}; {step}) {{")
                out += self.block(st[4], depth + 1)
                out.append(f"{pad}}}")
            elif kind == "switch":
                out.append(f"{pad}switch ({self.bare(st[1])}) {{")
                for labels, body in st[2]:
                    for value in labels:
                        out.append(f"{pad}default:" if value is None else f"{pad}case {_hex(value)}:")
                    out += self.block(body, depth + 1)
                out.append(f"{pad}}}")
            else:
                raise Unsupported(f"statement {kind}")
        return out

    # -- the whole function --------------------------------------------------------------------
    def text(self) -> str:
        L = self.L
        self.prepare()
        body = self.block(self.body, 1)
        lines = []
        for (off, t), name in sorted(self.structs.items()):
            pad = f"u8 pad[{off}]; " if off else ""
            lines.append(f"struct {name} {{ {pad}{t} f; }};")
        for size in sorted(set(self.stepped.values())):
            lines.append(f"struct n64dk_e{size} {{ u8 b[{size}]; }};")
        for addr in sorted(set(L.globals) | set(self.sym_uses)):
            kind = self.sym_decl(addr)
            name = self.sym_name(addr)
            if kind[0] == "func":
                continue
            if kind[0] == "scalar" and ("g", addr) in self.stepped:
                lines.append(f"extern struct n64dk_e{self.stepped[('g', addr)]} *{name};")
            elif kind[0] == "scalar":
                lines.append(f"extern {kind[1]} {name};")
            elif kind[0] == "array":
                lines.append(f"extern {kind[1]} {name}[];")
            else:
                lines.append(f"extern u8 {name}[];")
        declared = set()
        for key, info in L.callees.items():
            target = info["target"]
            if not isinstance(target, int) or target in declared or target == L.vram:
                continue
            declared.add(target)
            floats = self.float_positions(key)
            proto = ", ".join(kind or "s32" for kind in floats)
            lines.append(f"{info['ret']} {L.func_name(target)}({proto});")
        for addr in sorted(self.sym_uses):
            if self.sym_decl(addr)[0] == "func" and addr not in declared and addr != L.vram:
                lines.append(f"s32 {self.sym_name(addr)}();")
        slots = sorted(L.params)
        params = []
        slot = 0
        top = (slots[-1] + 1) if slots else 0
        while slot < top:
            t = L.params.get(slot, "s32")
            params.append(f"{t} arg{slot}")
            slot += 2 if t == "f64" else 1
        lines.append(f"{L.ret_type or 'void'} {self.name}({', '.join(params) or 'void'}) {{")
        cur = L.size
        entries = {off: (t, SIZES[t]) for off, t in L.locals.items()}
        for off, size in self.aggregates.items():
            entries[off] = (None, size)
        for off in sorted(entries, reverse=True):
            t, size = entries[off]
            if off + size > cur:
                raise Unsupported("locals overlap")
            natural = (cur - size) & ~(min(size, 8) - 1) if t else None    # where alignment alone puts a scalar
            if off + size < cur and off != natural:
                lines.append(f"    u8 pad{off + size:X}[{cur - off - size}];")
            if ("lv", off) in self.stepped:
                lines.append(f"    struct n64dk_e{self.stepped[('lv', off)]} *{self.local_name(off)};")
            else:
                lines.append(f"    {t} {self.local_name(off)};" if t else f"    u8 {self.local_name(off)}[{size}];")
            cur = off
        floor = self.floor()
        if "pad_bottom" in self.options and cur > floor:
            lines.append(f"    u8 pad{floor:X}[{cur - floor}];")
        if len(lines) and lines[-1].endswith("{") is False:
            lines.append("")
        return "\n".join(lines + body + ["}"]) + "\n"

    def floor(self) -> int:
        """Where the locals end: above the saved registers (or the bottom of a leaf's frame)."""
        L = self.L
        if L.saved:
            return (max(L.saved.values()) + 4 + 7) & ~7 if not any(r >= 32 for r in L.saved) else \
                (max(off + (8 if r >= 32 else 4) for r, off in L.saved.items()) + 7) & ~7
        return 0

    def unexplained(self) -> int:
        """Bytes between the lowest local and the saved registers."""
        L = self.L
        lowest = min(list(L.locals) + list(L.local_addr) + [L.size])
        return lowest - self.floor()


def _balanced(text: str) -> bool:
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def lift(code: bytes, vram: int, name: str, *, func_name=None, data_name=None, is_func=None, options=(),
         whole: bool = False, read=None) -> str:
    """C for the unoptimised function ``code`` (declarations and definition, no typedef prelude)."""
    lifter = Lifter(code, vram, func_name, data_name, whole=whole, read=read)
    if is_func is not None:
        lifter.is_func = is_func
    body = Shape(lifter).build()
    return Printer(lifter, body, name, options).text()
