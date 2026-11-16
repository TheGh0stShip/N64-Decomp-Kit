"""GCC 2.x without optimisation (-O0): write the function from its machine code.

Unoptimised GCC code is a literal transcript of the source: a frame pointer, every argument stored
to the frame on entry, every local in a stack slot laid out in declaration order, every statement
compiled on its own with its values in scratch registers, every jump kept as written.  So instead
of repairing a general decompiler's rendering, this generator reads the function back statement by
statement:

* the prologue gives the frame size, the saved registers and the parameters (how each is homed
  says how wide it is);
* inside one statement the registers hold expression trees; a store, a call whose value is not
  used, a branch and a jump each end a statement;
* the widths and signs of the loads and stores give the type of every local, parameter and global;
* locals are declared in ascending frame order with fillers, which is how GCC lays the frame out,
  so the frame of the result is the frame of the target;
* the jump skeleton is mapped back to ``if``/``else``, loops and ``goto`` (GCC -O0 keeps one jump
  per source construct, so a faithful reading compiles back to the same skeleton).

Everything is computed from the bytes.  The decompiler draft is used for one thing only: the
typedef prelude the kit compiles every candidate with.  The situation is recognised from the code
(``addu $fp,$sp,$zero`` in the prologue), not from the recipe, so an unoptimised function inside
an optimised title is translated too.  Anything not understood makes the generator decline.
"""
from __future__ import annotations

import re

from .gccdebug_mips import (A0, AT, BRANCHES, FP, LOADS, RA, REG, SP, STORES, V0, V1, decode)

MAX_INSNS = 4000


class Decline(Exception):
    """This function is not (yet) something the translator reads; the draft stands."""


# ----------------------------------------------------------------------------------------------
# expression trees


class Node:
    """A value in a register.  ``uses`` counts readers, ``seq`` orders creation."""
    __slots__ = ("k", "a", "uses", "stmt", "seq")

    def __init__(self, k, *a):
        self.k, self.a, self.uses, self.stmt, self.seq = k, a, 0, None, 0

    def __repr__(self):
        return f"{self.k}{self.a!r}"


def strip(node: Node) -> Node:
    while node.k == "cp":
        node = node.a[0]
    return node


def plain_variable(node) -> bool:
    """A full-width local or global read directly: no code until the instruction that uses it."""
    node = strip(node)
    return node.k == "ld" and node.a[0] == 4 and node.a[2][0] in ("local", "global")


def first_seq(node) -> int:
    """When the first instruction that contributed to ``node`` ran (creation order of its leaves)."""
    best = node.seq if isinstance(node, Node) and node.seq else 1 << 30
    stack = list(node.a) if isinstance(node, Node) else []
    while stack:
        part = stack.pop()
        if isinstance(part, Node):
            if part.seq and part.seq < best:
                best = part.seq
            stack.extend(part.a)
        elif isinstance(part, (list, tuple)):
            stack.extend(part)
    return best


def float_text(bits: int) -> str:
    """The shortest C literal that is exactly this single-precision value."""
    import struct
    value = struct.unpack(">f", struct.pack(">I", bits & 0xFFFFFFFF))[0]
    if value != value or value in (float("inf"), float("-inf")):
        raise Decline("float constant that has no literal")
    for digits in range(1, 18):
        text = f"{value:.{digits}g}"
        if struct.pack(">f", float(text)) == struct.pack(">f", value):
            break
    if "e" not in text and "." not in text:
        text += ".0"
    return text + "f"


def const_of(node: Node):
    node = strip(node)
    if node.k == "const":
        return node.a[0]
    if node.k == "hi":
        return _s32(node.a[0] << 16)
    return None


def _s32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


INT_TYPES = {(1, True): "s8", (1, False): "u8", (2, True): "s16", (2, False): "u16", (4, True): "s32",
             (4, False): "u32"}
NEGATE = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", "<=": ">", ">": "<="}
FLIP = {"==": "==", "!=": "!=", "<": ">", ">": "<", "<=": ">=", ">=": "<="}


class Stmt:
    __slots__ = ("k", "a")

    def __init__(self, k, *a):
        self.k, self.a = k, a

    def __repr__(self):
        return f"S:{self.k}{self.a!r}"


# ----------------------------------------------------------------------------------------------
# the function


class Function:
    def __init__(self, code: bytes, vram: int, name: str):
        self.name, self.vram = name, vram
        insns = decode(code, vram)
        if insns is None or len(insns) < 6 or len(insns) > MAX_INSNS:
            raise Decline("not decodable")
        while len(insns) > 2 and insns[-1].op == "nop":
            insns.pop()                                      # alignment after the return
        self.all = insns
        self._frame()
        self._labels()
        self.vars: dict[int, dict] = {}                      # frame offset -> local variable
        self.globals: dict[int, dict] = {}                   # address -> how it is used
        self.fields: set[tuple[int, str]] = set()            # (offset, type) accessor structs
        self.callees: dict[object, dict] = {}
        self.returns_value = False
        self.return_type = "s32"
        self.label_used: set[int] = set()
        self.float_calls: set[int] = set()
        self.prototypes: dict[int, list[str]] = {}
        self.seq = 0
        self.barrier = 0                                     # sequence number at the last assignment
        self.int_fp = self._integer_fp_accesses()
        self._collect_frame_accesses()
        self.body = self._block(0, len(self.ins), None)

    # -- prologue and epilogue ----------------------------------------------------------------

    def _frame(self):
        ins = self.all
        first = ins[0]
        if not (first.op == "addiu" and first.rs == SP and first.rt == SP and first.imm < 0):
            raise Decline("no frame")
        self.size = -first.imm
        index, saved = 1, {}
        fsaved = {}
        while index < len(ins) and ins[index].rs == SP and (
                (ins[index].op == "sw" and (ins[index].rt in (RA, FP) or 16 <= ins[index].rt <= 23))
                or (ins[index].op == "sdc1" and 20 <= ins[index].ft <= 30)):
            if ins[index].op == "sdc1":                       # a float kept across a call
                fsaved[ins[index].ft] = ins[index].imm
            else:
                saved[ins[index].rt] = ins[index].imm
            index += 1
        if index >= len(ins) or not (ins[index].op == "addu" and ins[index].rd == FP and ins[index].rs == SP
                                     and ins[index].rt == 0) or FP not in saved:
            raise Decline("no frame pointer")
        index += 1
        self.saved = saved
        # epilogue, from the end
        end = len(ins) - 1
        if not (ins[end].op == "jr" and ins[end].rs == RA):
            raise Decline("no return")
        end -= 1
        if not (ins[end].op == "addiu" and ins[end].rs == SP and ins[end].rt == SP and ins[end].imm == self.size):
            raise Decline("epilogue")
        end -= 1
        restored, frestored = {}, {}
        while end > index and ins[end].op in ("lw", "ldc1") and ins[end].rs == SP:
            (restored if ins[end].op == "lw" else frestored)[ins[end].rt] = ins[end].imm
            end -= 1
        self.fsaved = fsaved
        if frestored != fsaved or restored != saved or not (ins[end].op == "addu" and ins[end].rd == SP and ins[end].rs == FP
                                     and ins[end].rt == 0):
            raise Decline("epilogue")
        epilogue = end
        # parameters: how each argument register is put away
        self.params: list[dict] = []
        pending: dict[int, int] = {}
        while index < epilogue:
            x = ins[index]
            number = len(self.params)
            if x.op == "sw" and x.rs == FP and 4 <= x.rt <= 7 and x.rt - 4 == number and \
                    x.imm == self.size + 4 * number:
                self.params.append({"kind": "int", "off": x.imm, "size": 4})
            elif x.op == "addu" and x.rt == 0 and 4 <= x.rs <= 7 and x.rs - 4 == number and x.rd not in pending \
                    and x.rd not in (SP, FP, RA) and x.rd != x.rs:
                pending[x.rd] = number
                self.params.append({"kind": "moved", "reg": x.rd})
            elif x.op == "lw" and x.rs == FP and number >= 4 and x.imm == self.size + 4 * number \
                    and x.rt not in pending and x.rt not in (SP, FP, RA):
                # a narrow parameter passed on the stack: loaded, then stored narrow like the others
                pending[x.rt] = number
                self.params.append({"kind": "moved", "reg": x.rt})
            elif x.op == "swc1" and x.rs == FP and number < 2 and x.ft == 12 + 2 * number \
                    and x.imm == self.size + 4 * number and all(p["kind"] == "float" for p in self.params):
                # leading ``float`` parameters arrive in $f12/$f14
                self.params.append({"kind": "float", "off": x.imm, "size": 4, "type": "f32"})
            elif x.op in ("sh", "sb") and x.rs == FP and x.rt in pending:
                param = self.params[pending.pop(x.rt)]
                param.update(kind="narrow", off=x.imm, size=STORES[x.op], signed=None)
            else:
                break
            index += 1
        if pending:
            raise Decline("register parameter or structure return")
        self.body_start = index
        self.ins = ins[index:epilogue]
        self.ret_addr = ins[epilogue].addr
        calls = [x for x in self.ins if x.op in ("jal", "jalr")]
        stack = [x.imm for x in self.ins if x.op in ("sw", "swc1", "sdc1", "sb", "sh") and x.rs == SP]
        self.args_size = 0
        if calls:
            top = max([16] + [off + (8 if False else 4) for off in stack])
            self.args_size = (top + 7) & ~7
        elif stack:
            raise Decline("stack store without a call")
        self.save_base = min(saved.values())
        top = max(list(saved.values()) + [off + 4 for off in fsaved.values()]) + 4
        self.var_size = top - 4 * len(saved) - 8 * len(fsaved) - self.args_size
        if fsaved:                                            # doubles are saved above the integer registers, aligned
            self.var_size = self.save_base - self.args_size
        if self.var_size < 0 or self.var_size % 8 or self.args_size + self.var_size != self.save_base:
            raise Decline("frame layout")

    def _integer_fp_accesses(self) -> set[int]:
        """Addresses of ``lwc1``/``swc1`` that move an *integer*: a conversion reads its integer
        operand straight from memory into a float register (``lwc1``, ``cvt.s.w``) and writes its
        integer result straight back (``trunc.w.s``, ``swc1``)."""
        found, ins = set(), self.ins
        for i, x in enumerate(ins):
            if x.op == "lwc1":
                for later in ins[i + 1:i + 8]:
                    if later.op in BRANCHES or later.op in ("j", "jal", "jalr", "jr"):
                        break
                    if later.fmt is not None and later.fs == x.ft:
                        if later.op in ("cvt.s", "cvt.d") and later.fmt == "w":
                            found.add(x.addr)
                        break
                    if later.op in ("lwc1", "ldc1", "mtc1") and (later.ft if later.op != "mtc1" else later.fs) == x.ft:
                        break
            elif x.op == "swc1":
                for earlier in reversed(ins[max(0, i - 8):i]):
                    if earlier.fmt is not None and earlier.fd == x.ft:
                        if earlier.op == "trunc.w":
                            found.add(x.addr)
                        break
                    if earlier.op in ("lwc1", "ldc1") and earlier.ft == x.ft or earlier.op == "mtc1" and earlier.fs == x.ft:
                        break
        return found

    def _labels(self):
        self.index_of = {x.addr: i for i, x in enumerate(self.ins)}
        self.index_of[self.ret_addr] = len(self.ins)
        # A label on a transfer whose delay slot the assembler filled stood, in the source, in
        # front of the instruction that was moved into the slot (an assembler never moves an
        # instruction across a label).  In logical order that instruction comes first, so the
        # label names it.
        moved_slots = set()
        for i in range(1, len(self.ins)):
            if self.ins[i - 1].addr > self.ins[i].addr:
                self.index_of[self.ins[i].addr] = i - 1
                moved_slots.add(self.ins[i - 1].addr)
        self.targets: dict[int, list[int]] = {}             # target index -> indices of the jumps to it
        for i, x in enumerate(self.ins):
            if x.op in BRANCHES or x.op == "j":
                if x.target not in self.index_of:
                    raise Decline("jump out of the function")
                if x.target in moved_slots:                   # into a slot: the transfer itself is skipped
                    raise Decline("jump into a filled delay slot")
                self.targets.setdefault(self.index_of[x.target], []).append(i)
            elif x.op == "jr":
                raise Decline("jump table")

    # -- frame accesses -----------------------------------------------------------------------

    def _collect_frame_accesses(self):
        """Every $fp-relative access: which slots exist and how wide they are."""
        direct: dict[int, set] = {}
        self.addr_taken: set[int] = set()
        for x in self.ins:
            if x.rs != FP:
                continue
            if x.op in LOADS:
                width, signed = LOADS[x.op]
                direct.setdefault(x.imm, set()).add((width, "s" if signed else "u"))
            elif x.op in STORES:
                direct.setdefault(x.imm, set()).add((STORES[x.op], "w"))
            elif x.op in ("lwc1", "swc1"):
                integer = x.addr in self.int_fp
                direct.setdefault(x.imm, set()).add((4, ("s" if x.op == "lwc1" else "w") if integer else "f"))
            elif x.op in ("ldc1", "sdc1"):
                direct.setdefault(x.imm, set()).add((8, "d"))
            elif x.op == "addiu":
                self.addr_taken.add(x.imm)
            elif x.op == "addu" and x.rt not in (0, FP):
                continue                                     # an index into a local array (below)
            else:
                raise Decline(f"frame pointer used by {x.op}")
        for param in self.params:
            if param["kind"] == "narrow":
                kinds = direct.get(param["off"], set())
                signed = any(k == (param["size"], "s") for k in kinds)
                self.vars[param["off"]] = {"off": param["off"], "size": param["size"], "param": True,
                                           "type": INT_TYPES[(param["size"], signed)]}
        # Local arrays.  ``a[i]`` on a local array adds the scaled index to the frame pointer and
        # accesses the sum at the array's own frame offset.  The array reaches as far as accesses
        # of its element width go: a neighbouring scalar of that width is spelled as an element,
        # which is the same instruction and the same frame.
        indexed: dict[int, tuple[int, str]] = {}
        for i, x in enumerate(self.ins):
            if x.op == "addu" and FP in (x.rs, x.rt) and x.rt != 0 and x.rd not in (FP, SP) and x.rs != x.rt:
                for later in self.ins[i + 1:i + 5]:
                    if later.rs == x.rd and (later.op in LOADS or later.op in STORES or later.op in ("lwc1", "swc1")):
                        if later.op in LOADS:
                            access = (LOADS[later.op][0], "s" if LOADS[later.op][1] else "u")
                        elif later.op in STORES:
                            access = (STORES[later.op], "w")
                        else:
                            access = (4, "f")
                        if indexed.setdefault(later.imm, access)[0] != access[0]:
                            raise Decline("local array with two element widths")
                        if access[1] != "w":
                            indexed[later.imm] = access
                        break
        for off, (width, kind) in sorted(indexed.items()):
            if not (self.args_size <= off < self.save_base) or off % width:
                raise Decline("indexed frame access outside the locals")
            end = off + width
            while end + width <= self.save_base and end not in indexed and \
                    all(k[0] == width for k in direct.get(end, ())) and \
                    not any(end < other < end + width for other in direct):
                end += width
            kinds = {k[1] for o in range(off, end, width) for k in direct.get(o, ())} | {kind}
            ctype = "f32" if "f" in kinds else INT_TYPES[(width, "s" in kinds or width == 4)]
            self.vars[off] = {"off": off, "size": end - off, "type": ctype, "array": (end - off) // width,
                              "elem": width, "decl": f"{ctype} sp{off:X}[{(end - off) // width}]"}
        # widest first: a narrower access inside a wider slot is a conversion, not a variable
        for width in (8, 4, 2, 1):
            for off in sorted(direct):
                kinds = [k for k in direct[off] if k[0] == width]
                if not kinds or off in self.vars:
                    continue
                holder = self._holder(off, width)
                if holder is not None:
                    continue
                if off >= self.size:
                    index = (off - self.size) // 4
                    if (off - self.size) % 4 == 0 and width == 4:
                        while len(self.params) <= index:
                            number = len(self.params)
                            self.params.append({"kind": "int" if number >= 4 else "unused",
                                                "off": self.size + 4 * number, "size": 4})
                        if any(k[1] == "f" for k in kinds):
                            # a ``float`` that arrived in an integer register or on the stack
                            self.params[index]["type"] = "f32"
                        continue
                    if index >= 4 and width < 4 and off % 4 == 4 - width:
                        # a narrow parameter passed on the stack lives in the low end of its word
                        while len(self.params) <= index:
                            number = len(self.params)
                            self.params.append({"kind": "int" if number >= 4 else "unused",
                                                "off": self.size + 4 * number, "size": 4})
                        signed = any(k[1] == "s" for k in kinds)
                        self.params[index].update(kind="stack-narrow", noff=off, nsize=width,
                                                  type=INT_TYPES[(width, signed)])
                        continue
                    raise Decline("odd access to an incoming argument")
                if not (self.args_size <= off and off + width <= self.save_base):
                    raise Decline("frame access outside the locals")
                if any(k[1] == "d" for k in kinds):
                    ctype = "f64"
                elif any(k[1] == "f" for k in kinds):
                    ctype = "f32"
                else:
                    ctype = INT_TYPES[(width, any(k[1] == "s" for k in kinds) or width == 4)]
                self.vars[off] = {"off": off, "size": width, "type": ctype}
        for off in sorted(self.addr_taken):
            if off >= self.size:
                index = (off - self.size) // 4
                if (off - self.size) % 4 or index >= len(self.params):
                    raise Decline("address of an incoming argument")
                continue
            if off in self.vars or self._holder(off, 1) is not None:
                continue
            if not (self.args_size <= off < self.save_base):
                raise Decline("frame address outside the locals")
            self.vars[off] = {"off": off, "size": 0, "type": None, "aggregate": True}

    def _holder(self, off: int, width: int):
        """The already known wider slot that contains [off, off+width), if any."""
        for start, var in self.vars.items():
            if var.get("aggregate"):
                continue
            if start <= off and off + width <= start + var["size"] and (start, var["size"]) != (off, width):
                return var
        if off >= self.size:
            index = (off - self.size) // 4
            if index < len(self.params) and self.params[index]["kind"] in ("int", "unused") and width < 4:
                return self.params[index]
        return None

    # -- symbolic execution -------------------------------------------------------------------

    def node(self, k, *a) -> Node:
        n = Node(k, *a)
        self.seq += 1
        n.seq = self.seq
        return n

    def _reset(self):
        self.regs: dict[int, Node] = {}
        self.fregs: dict[int, Node] = {}
        self.fcc = None
        self.hilo = None
        self.stack_args: dict[int, Node] = {}
        self.pending_call = None

    def usef(self, reg: int) -> Node:
        n = self.fregs.get(reg)
        if n is None:
            raise Decline(f"read of $f{reg} with no known value")
        if n.k == "call":
            self.float_calls.add(id(n))                       # its value is taken from $f0
        return self.consume(n)

    def is_float(self, n: Node) -> bool:
        n = strip(n)
        return n.k in ("fconst", "fbin", "fun", "cvtf") or (n.k == "ld" and n.a[1] == "f") \
            or (n.k == "call" and id(n) in self.float_calls)

    def float_type(self, n: Node) -> str:
        n = strip(n)
        if n.k == "ld":
            return "f32" if n.a[0] == 4 else "f64"
        if n.k == "cvtf":
            return n.a[0]
        if n.k in ("fbin", "fun"):
            return self.float_type(n.a[1])
        return "f32"

    def use(self, reg: int) -> Node:
        if reg == 0:
            return self.node("const", 0)
        n = self.regs.get(reg)
        if n is None:
            raise Decline(f"read of ${REG[reg]} with no known value")
        return self.consume(n, reg)

    def consume(self, n: Node, reg=None) -> Node:
        if n.seq <= self.barrier:
            n = self._stale(n, reg)
        n.uses += 1
        return n

    def _stale(self, n: Node, reg) -> Node:
        """A value made before the last statement and read again: ``a = b = c`` or ``a = b++``."""
        last = self.out[-1] if self.out else None
        if last is None or last.k != "assign":
            raise Decline("value used across a statement")
        loc, value = last.a[0], last.a[1]
        if n.stmt is last:
            # the value just stored is used again: the assignment is an operand
            self.out.pop()
            merged = self.node("asg", loc, value)
        else:
            inner = strip(value)
            bare = strip(n)
            old = strip(inner.a[1]) if inner.k == "bin" and inner.a[0] == "+" and const_of(inner.a[2]) is not None \
                and value.k != "cp" else None
            if old is not None and old.k == "ld" and old.a[2] == loc and bare is not old \
                    and getattr(self, "deferred", None) is None:
                # Another value from before the store is still in use: the store was the side
                # effect of a post-increment in the middle of an expression (``a[i] = p->q[p->n++]``)
                # and its old value comes later.  The statement becomes that operand; values made
                # before it are current again.
                self.out.pop()
                post = self.node("postinc", loc, const_of(inner.a[2]), old.a[0])
                for where in (self.regs, self.fregs):
                    for key, held in list(where.items()):
                        if strip(held) is old:
                            where[key] = post
                self.barrier = getattr(self, "before_barrier", 0)
                post.seq = max(post.seq, self.barrier + 1)
                self.deferred = post
                return n
            if not (bare.k == "ld" and bare.a[2] == loc and inner.k == "bin" and inner.a[0] == "+"
                    and strip(inner.a[1]) is bare and const_of(inner.a[2]) is not None and value.k != "cp"):
                raise Decline("value used across a statement")
            self.out.pop()
            merged = self.node("postinc", loc, const_of(inner.a[2]), bare.a[0])
        if reg is not None:
            self.regs[reg] = merged
        return merged

    def setreg(self, reg: int, n: Node):
        if reg == 0:
            return
        self.regs[reg] = n

    def emit(self, stmt: Stmt):
        pending = getattr(self, "deferred", None)
        if pending is not None:
            self.deferred = None
            if pending.uses == 0:
                raise Decline("a stored increment whose old value is never used")
        self.out.append(stmt)
        if stmt.k == "assign":
            self.before_barrier = self.barrier
            self.barrier = self.seq

    def flush_call(self):
        """A call whose value nobody read is a statement of its own."""
        call = self.pending_call
        if call is not None and call.uses == 0:
            self.pending_call = None
            for reg in [r for r, n in self.regs.items() if n is call]:
                del self.regs[reg]
            for reg in [r for r, n in self.fregs.items() if n is call]:
                del self.fregs[reg]
            self.emit(Stmt("expr", call))
        self.pending_call = None

    def location(self, base: int, off: int):
        """The lvalue ``off(base)`` names."""
        if base == FP:
            return ("local", off)
        if base == SP:
            raise Decline("stack pointer access")
        n = self.regs.get(base)
        if n is None:
            raise Decline(f"address in ${REG[base]} with no known value")
        if n.k == "hi":
            n.uses += 1
            return ("global", ((n.a[0] << 16) + off) & 0xFFFFFFFF)
        if n.k == "gidx":
            n.uses += 1
            return ("gidx", ((n.a[0] << 16) + off) & 0xFFFFFFFF, n.a[1])
        if n.k == "lidx":
            n.uses += 1
            return ("lidx", off, n.a[0])
        return ("deref", self.use(base), off)

    def step(self, x):
        """Execute one straight-line instruction."""
        op = x.op
        if op in LOADS:
            width, signed = LOADS[op]
            loc = self.location(x.rs, x.imm)
            if loc[0] == "global":
                self.note_global(loc[1], (width, "s" if signed else "u"))
            self.setreg(x.rt, self.node("ld", width, signed, loc))
        elif op in STORES:
            width = STORES[op]
            if x.rs == SP:
                self.stack_args[x.imm] = self.use(x.rt)
                if width != 4:
                    raise Decline("narrow stack argument")
                return
            # the address is formed before the value is read
            loc = self.location(x.rs, x.imm)
            if loc[0] == "global":
                self.note_global(loc[1], (width, "w"))
            value = self.use(x.rt)
            self.flush_call()
            stmt = Stmt("assign", loc, value, width)
            value.stmt = stmt
            self.emit(stmt)
        elif op == "lui":
            self.setreg(x.rt, self.node("hi", x.uimm))
        elif op == "addiu":
            if x.rs == 0:
                self.setreg(x.rt, self.node("const", x.imm))
            elif x.rs == FP:
                self.setreg(x.rt, self.node("lad", x.imm))
            elif x.rs == SP:
                raise Decline("stack pointer arithmetic")
            else:
                src = self.regs.get(x.rs)
                if src is not None and src.k == "hi" and x.rt == x.rs:
                    src.uses += 1
                    self.note_global(((src.a[0] << 16) + x.imm) & 0xFFFFFFFF, "addr")
                    self.setreg(x.rt, self.node("sym", ((src.a[0] << 16) + x.imm) & 0xFFFFFFFF))
                else:
                    self.setreg(x.rt, self.node("bin", "+", self.use(x.rs), self.node("const", x.imm)))
        elif op == "ori":
            src = self.regs.get(x.rs)
            if x.rs == 0:
                self.setreg(x.rt, self.node("const", x.uimm))
            elif src is not None and src.k == "hi" and x.rt == x.rs:
                src.uses += 1
                self.setreg(x.rt, self.node("const", _s32((src.a[0] << 16) | x.uimm)))
            else:
                self.setreg(x.rt, self.node("bin", "|", self.use(x.rs), self.node("const", x.uimm)))
        elif op in ("andi", "xori"):
            self.setreg(x.rt, self.node("bin", {"andi": "&", "xori": "^"}[op], self.use(x.rs),
                                        self.node("const", x.uimm)))
        elif op in ("slti", "sltiu"):
            self.setreg(x.rt, self.node("bin", "<" if op == "slti" else "<u", self.use(x.rs),
                                        self.node("const", x.imm)))
        elif op == "addu":
            if x.rt == 0:
                self.setreg(x.rd, self.node("cp", self.use(x.rs)))
                return
            left = self.regs.get(x.rs)
            if left is not None and left.k == "hi" and x.rd == x.rs == AT:
                left.uses += 1
                self.setreg(x.rd, self.node("gidx", left.a[0], self.use(x.rt)))
                return
            if FP in (x.rs, x.rt):                           # the scaled index of a local array
                self.setreg(x.rd, self.node("lidx", self.use(x.rt if x.rs == FP else x.rs)))
                return
            a, b = self.use(x.rs), self.use(x.rt)
            self.setreg(x.rd, self._add(a, b))
        elif op == "subu":
            if x.rs == 0:
                self.setreg(x.rd, self.node("un", "-", self.use(x.rt)))
                return
            a, b = self.use(x.rs), self.use(x.rt)
            self.setreg(x.rd, self._sub(a, b))
        elif op in ("and", "or", "xor", "slt", "sltu"):
            a, b = self.use(x.rs), self.use(x.rt)
            self.setreg(x.rd, self.node("bin", {"and": "&", "or": "|", "xor": "^", "slt": "<", "sltu": "<u"}[op],
                                        a, b))
        elif op == "nor":
            if x.rs == 0 or x.rt == 0:
                self.setreg(x.rd, self.node("un", "~", self.use(x.rt if x.rs == 0 else x.rs)))
            else:
                raise Decline("nor")
        elif op in ("sll", "srl", "sra"):
            a = self.use(x.rt)
            self.setreg(x.rd, self._shift(op, a, x.sa))
        elif op in ("sllv", "srlv", "srav"):
            a, b = self.use(x.rt), self.use(x.rs)
            self.setreg(x.rd, self.node("bin", {"sllv": "<<", "srlv": ">>u", "srav": ">>"}[op], a, b))
        elif op in ("mult", "multu"):
            self.hilo = (op, self.use(x.rs), self.use(x.rt))
        elif op in ("div", "divu") and x.fmt is None:
            self.hilo = (op, self.use(x.rs), self.use(x.rt))
        elif op in ("mflo", "mfhi"):
            if self.hilo is None:
                raise Decline(op)
            kind = self.hilo[0]
            if kind in ("mult", "multu") and op == "mflo":
                self.setreg(x.rd, self.node("bin", "*", self.hilo[1], self.hilo[2]))
            elif kind in ("div", "divu"):
                sign = "" if kind == "div" else "u"
                self.setreg(x.rd, self.node("bin", ("/" if op == "mflo" else "%") + sign, self.hilo[1], self.hilo[2]))
            else:
                raise Decline(op)
        elif op in ("lwc1", "ldc1"):
            width = 4 if op == "lwc1" else 8
            loc = self.location(x.rs, x.imm)
            if x.addr in self.int_fp:                         # an integer on its way to a conversion
                if loc[0] == "global":
                    self.note_global(loc[1], (4, "s"))
                self.fregs[x.ft] = self.node("ibits", self.node("ld", 4, True, loc))
                return
            if loc[0] == "global":
                self.note_global(loc[1], (width, "f" if width == 4 else "d"))
            self.fregs[x.ft] = self.node("ld", width, "f", loc)
        elif op in ("swc1", "sdc1"):
            width = 4 if op == "swc1" else 8
            if x.rs == SP:
                raise Decline("float stack argument")
            loc = self.location(x.rs, x.imm)
            if loc[0] == "global":
                self.note_global(loc[1], (width, "f" if width == 4 else "d"))
            value = self.usef(x.ft)
            if x.addr in self.int_fp and value.k == "ftrunc":
                value = self.node("cast", "s32", value.a[0])    # the integer result of a conversion
                if loc[0] == "global":
                    self.globals[loc[1]]["acc"][-1] = (4, "w")
            elif not self.is_float(value):
                raise Decline("integer bits stored as a float")
            self.flush_call()
            stmt = Stmt("assign", loc, value, width)
            value.stmt = stmt
            self.emit(stmt)
        elif op == "mtc1":
            src = self.regs.get(x.rt)
            if x.rt == 0:
                self.fregs[x.fs] = self.node("fconst", 0)
            elif src is not None and src.k in ("hi", "const"):
                src.uses += 1
                bits = (src.a[0] << 16) if src.k == "hi" else src.a[0]
                self.fregs[x.fs] = self.node("fconst", bits & 0xFFFFFFFF)
            else:
                self.fregs[x.fs] = self.node("ibits", self.use(x.rt))
        elif op == "mfc1":
            src = self.usef(x.fs)
            if src.k != "ftrunc":
                raise Decline("float moved to an integer register")
            self.setreg(x.rt, self.node("cast", "s32", src.a[0]))
        elif x.fmt is not None and op in ("add", "sub", "mul", "div"):
            a, b = self.usef(x.fs), self.usef(x.ft)
            if not (self.is_float(a) and self.is_float(b)):
                raise Decline("float arithmetic on integer bits")
            self.fregs[x.fd] = self.node("fbin", {"add": "+", "sub": "-", "mul": "*", "div": "/"}[op], a, b)
        elif x.fmt is not None and op == "neg":
            self.fregs[x.fd] = self.node("fun", "-", self.usef(x.fs))
        elif x.fmt is not None and op == "mov":
            self.fregs[x.fd] = self.node("cp", self.usef(x.fs))
        elif op in ("cvt.s", "cvt.d"):
            src, to = self.usef(x.fs), ("f32" if op == "cvt.s" else "f64")
            if x.fmt == "w":
                if src.k != "ibits":
                    raise Decline("conversion of a truncated value")
                self.fregs[x.fd] = self.node("cvtf", to, src.a[0])
            else:
                self.fregs[x.fd] = self.node("cvtf", to, src)
        elif op == "trunc.w":
            self.fregs[x.fd] = self.node("ftrunc", self.usef(x.fs))
        elif op in ("c.eq", "c.lt", "c.le"):
            self.fcc = ({"c.eq": "==", "c.lt": "<", "c.le": "<="}[op], self.usef(x.fs), self.usef(x.ft))
        else:
            raise Decline(f"instruction {op}")

    def _same(self, a: Node, b: Node) -> bool:
        return strip(a) is strip(b)

    def _add(self, a: Node, b: Node) -> Node:
        # a multiplication by a constant is expanded into shifts, additions and subtractions
        if a.k == "mul" and self._same(a.a[0], b):
            return self.node("mul", a.a[0], a.a[1] + 1)
        if b.k == "mul" and self._same(b.a[0], a):
            return self.node("mul", b.a[0], b.a[1] + 1)
        if a.k == "mul" and b.k == "mul" and self._same(a.a[0], b.a[0]):
            return self.node("mul", a.a[0], a.a[1] + b.a[1])
        return self.node("bin", "+", a, b)

    def _sub(self, a: Node, b: Node) -> Node:
        if a.k == "mul" and self._same(a.a[0], b):
            return self.node("mul", a.a[0], a.a[1] - 1)
        if b.k == "mul" and self._same(b.a[0], a):
            return self.node("mul", b.a[0], 1 - b.a[1])
        if a.k == "mul" and b.k == "mul" and self._same(a.a[0], b.a[0]):
            return self.node("mul", a.a[0], a.a[1] - b.a[1])
        return self.node("bin", "-", a, b)

    def _shift(self, op: str, a: Node, amount: int) -> Node:
        if op == "sll":
            if a.k == "cp":
                return self.node("mul", a.a[0], 1 << amount)
            if a.k == "mul":
                return self.node("mul", a.a[0], a.a[1] << amount)
            return self.node("bin", "<<", a, self.node("const", amount))
        if op == "sra" and a.k == "bin" and a.a[0] == "<<" and const_of(a.a[2]) == amount and amount in (16, 24):
            return self.node("cast", "s16" if amount == 16 else "s8", a.a[1])
        if op == "srl" and a.k == "bin" and a.a[0] == "<<" and const_of(a.a[2]) == amount and amount in (16, 24):
            return self.node("cast", "u16" if amount == 16 else "u8", a.a[1])
        return self.node("bin", ">>" if op == "sra" else ">>u", a, self.node("const", amount))

    # -- calls --------------------------------------------------------------------------------

    def call(self, x):
        self.flush_call()
        args, proto = [], []
        for reg in (12, 14):                                  # leading float arguments
            n = self.fregs.get(reg)
            if n is None or n.uses or n.seq <= self.barrier or not self.is_float(n):
                break
            n.uses += 1
            args.append(n)
            proto.append(self.float_type(n))
        floats = len(args)
        # integer arguments follow in the registers the float ones did not shadow (a double two)
        for reg in range(4 + sum(2 if kind == "f64" else 1 for kind in proto), 8):
            n = self.regs.get(reg)
            if n is None or n.uses or n.seq <= self.barrier:
                break
            n.uses += 1
            args.append(n)
            proto.append("s32")
        single = "f32" in proto
        if self.stack_args:
            if len(args) != 4 or sorted(self.stack_args) != list(range(16, 16 + 4 * len(self.stack_args), 4)):
                raise Decline("stack arguments")
            args += [self.stack_args[off] for off in sorted(self.stack_args)]
            self.stack_args = {}
        if x.op == "jal":
            target = self.node("func", x.target)
        else:
            target = self.use(x.rs)
        call = self.node("call", target, tuple(args))
        if single:
            self.prototypes[id(call)] = proto + ["s32"] * (len(args) - len(proto))
        for reg in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 24, 25):
            self.regs.pop(reg, None)
        self.fregs = {reg: n for reg, n in self.fregs.items() if reg in self.fsaved}
        self.fregs[0] = call
        self.regs[V0] = call
        self.pending_call = call

    # -- control flow -------------------------------------------------------------------------

    def condition(self, x):
        """The condition under which the branch ``x`` is taken, as (operator, left, right)."""
        if x.op in ("beq", "bne"):
            a, b = self.use(x.rs), self.use(x.rt)
            taken = "==" if x.op == "beq" else "!="
            # a comparison materialised with slt and then tested against zero
            if const_of(b) == 0 and x.rt == 0 and a.k == "bin" and a.a[0] in ("<", "<u"):
                cond = (a.a[0], a.a[1], a.a[2])
                return cond if taken == "!=" else self._negated(cond)
            return (taken, a, b)
        if x.op in ("blez", "bgtz", "bltz", "bgez"):
            return ({"blez": "<=", "bgtz": ">", "bltz": "<", "bgez": ">="}[x.op], self.use(x.rs),
                    self.node("const", 0))
        if x.op in ("bc1t", "bc1f"):
            if self.fcc is None:
                raise Decline("float branch without a comparison")
            op, a, b = self.fcc
            self.fcc = None
            cond = ("f" + op, a, b)
            return cond if x.op == "bc1t" else self._negated(cond)
        raise Decline(f"branch {x.op}")

    @staticmethod
    def _negated(cond):
        op = cond[0]
        if op.startswith("!f"):                               # not(a < b) is not (a >= b) for floats
            return (op[1:], cond[1], cond[2])
        if op.startswith("f"):
            return ("!" + op, cond[1], cond[2])
        if op.endswith("u"):
            return (NEGATE[op[:-1]] + "u", cond[1], cond[2])
        return (NEGATE[op], cond[1], cond[2])

    def _block(self, start: int, end: int, loop) -> list:
        """Statements of the instructions [start, end)."""
        saved_out = getattr(self, "out", None)
        self.out = out = []
        self._reset()
        loop_from = None                                     # where a loop statement was announced
        try:
            i = start
            while i < end:
                if i in self.targets:
                    self.flush_call()
                    self._reset()
                    out.append(Stmt("label", i))
                closing = self._loop_at(i, end)
                if closing is not None and not (loop is not None and loop[0] == i):
                    self.flush_call()
                    body = self._block_inner(i, closing, (i, closing))
                    init = None
                    if loop_from is not None:
                        # the statements since the announcement are the loop's initialiser
                        chunk, loop_from = out[loop_from:], None
                        del out[len(out) - len(chunk):]
                        out.extend(part for part in chunk if part.k == "label")   # the loop's own top label
                        init = [part for part in chunk if part.k != "label"]
                        if any(part.k not in ("assign", "expr") for part in init):
                            raise Decline("loop initialiser")
                    out.append(Stmt("loop", body, i, closing, init))
                    self._reset()
                    i = closing + 1
                    continue
                x = self.ins[i]
                if x.op == "beq":
                    after = self._switch(i, end)
                    if after is not None:
                        i = after
                        self._reset()
                        continue
                if x.op in BRANCHES:
                    i = self._if(i, end, loop)
                    self._reset()
                elif x.op == "j":
                    target = self.index_of[x.target]
                    self.flush_call()
                    self._jump(i, target, end, loop)
                    self._reset()
                    i += 1
                elif x.op in ("jal", "jalr"):
                    self.call(x)
                    i += 1
                elif x.op == "nop":
                    if i > 0 and self.ins[i - 1].op in ("mtc1", "mfc1", "c.eq", "c.lt", "c.le"):
                        i += 1                                # the delay a coprocessor move or compare needs
                        continue
                    if loop_from is None and (i == 0 or i in self.targets):
                        # Without optimisation the compiler puts a no-op where a ``for``/``while``/
                        # ``do`` statement begins directly after a label or at the very start of
                        # the function.  What follows up to the loop is the ``for`` initialiser.
                        self.flush_call()
                        loop_from = len(out)
                        i += 1
                        continue
                    raise Decline("explicit nop")
                else:
                    self.step(x)
                    i += 1
            self.flush_call()
            if loop_from is not None:
                raise Decline("explicit nop")
        finally:
            self.out = saved_out
        return out

    def _block_inner(self, start, end, loop):
        regs = (self.regs, self.fregs, self.hilo, self.stack_args, self.pending_call)
        body = self._block(start, end, loop)
        self.regs, self.fregs, self.hilo, self.stack_args, self.pending_call = regs
        return body

    def _loop_at(self, i: int, end: int):
        """The index of the closing backward jump of a loop that starts at ``i``."""
        back = [j for j in self.targets.get(i, ()) if j >= i and self.ins[j].op == "j"]
        back = [j for j in back if j < end]
        return max(back) if back else None

    def _jump(self, i: int, target: int, end: int, loop):
        value = None
        if target == len(self.ins):
            n = self.regs.get(V0)
            f = self.fregs.get(0)
            if f is not None and f.uses == 0 and f.seq > self.barrier and f.k != "call" and self.is_float(f) \
                    and (n is None or n.uses or n.seq < f.seq):
                f.uses += 1
                value = f
                kind = self.float_type(f)
                if self.returns_value and self.return_type != kind:
                    raise Decline("two return types")
                self.returns_value, self.return_type = True, kind
            elif n is not None and n.uses == 0 and n.seq > self.barrier and n.k != "call":
                if self.returns_value and self.return_type != "s32":
                    raise Decline("two return types")
                n.uses += 1
                value = n
                self.returns_value = True
            self.emit(Stmt("return", value))
            return
        if loop is not None and target == loop[1] + 1:
            self.emit(Stmt("break"))
            return
        if loop is not None and target == loop[1]:
            self.emit(Stmt("continue"))
            return
        self.label_used.add(target)
        self.emit(Stmt("goto", target))

    def _switch(self, i: int, end: int):
        """A small ``switch``: the selector stays in one register while it is compared with each
        case value in turn (``beq`` to the case's code), a jump goes to the default or past the
        end, and the bodies follow in source order with ``break`` as a jump to the end.  Returns
        the index after the statement, or None when the instructions at ``i`` are not this."""
        ins, first = self.ins, self.ins[i]
        selector, tests = first.rs, []
        if selector == 0:
            return None
        # The dispatch is a decision tree over the selector: equality tests that lead to the
        # cases, range tests (``slti``) that lead to another part of the tree, and jumps to the
        # default.  It ends where the first case's code begins.
        known = self.regs.get(first.rt)
        consts = {first.rt: const_of(known)} if first.rt and known is not None else {}
        ranges, inner, defaults, stop, k = set(), set(), set(), end, i
        while k < stop:
            x = ins[k]
            if x.op == "addiu" and x.rs == 0 and x.rt not in (0, selector):
                consts[x.rt] = x.imm
                ranges.discard(x.rt)
            elif x.op == "beq" and x.rs == selector and (x.rt == 0 or consts.get(x.rt) is not None):
                target = self.index_of.get(x.target)
                if target is None or target <= k:
                    return None
                tests.append((0 if x.rt == 0 else consts[x.rt], target))
                stop = min(stop, target)
            elif x.op in ("slti", "sltiu") and x.rs == selector and x.rt not in (0, selector):
                ranges.add(x.rt)
                consts.pop(x.rt, None)
            elif x.op in ("beq", "bne") and x.rt == 0 and x.rs in ranges:
                target = self.index_of.get(x.target)
                if target is None or target <= k:
                    return None
                inner.add(target)
            elif x.op == "j":
                target = self.index_of.get(x.target)
                if target is None or target <= k:
                    return None
                defaults.add(target)
            else:
                return None
            k += 1
        defaults = {target for target in defaults if target >= stop}
        inner = {target for target in inner if target >= stop} | set()
        if not tests or k != stop or len(defaults) != 1 or inner or ins[k - 1].op != "j":
            return None
        if len(tests) == 1 and not (i + 1 < end and ins[i + 1].op == "j"):
            return None
        k -= 1                                              # the last jump of the dispatch
        default = defaults.pop()
        places = sorted({target for _value, target in tests} | {default})
        if places[0] != k + 1 or places[-1] > end or len({v for v, _t in tests}) != len(tests):
            return None
        # the end: where the breaks go (a jump to the function's end is a return, not a break)
        last = places[-1]
        for j in range(k + 1, places[-1]):
            if ins[j].op == "j":
                target = self.index_of.get(ins[j].target)
                if target is not None and places[-1] < target <= end and target != len(ins):
                    last = max(last, target)
        self.flush_call()
        chosen = self.use(selector)
        bounds = [place for place in places if place < last] + [last]
        sections = []
        for lo, nxt in zip(bounds, bounds[1:]):
            labels = [value for value, target in tests if target == lo] + ([None] if default == lo else [])
            sections.append((labels, self._block_inner(lo, nxt, (i, last - 1))))
        if any(target == last for _value, target in tests):
            sections.append(([value for value, target in tests if target == last], []))
        self.out.append(Stmt("switch", chosen, sections))
        return last

    def _if(self, i: int, end: int, loop) -> int:
        x = self.ins[i]
        target = self.index_of[x.target]
        if target <= i or target > end:
            raise Decline("branch out of its block")
        taken = self.condition(x)
        self.flush_call()
        cond = self._negated(taken)
        last = self.ins[target - 1]
        if target - 1 > i + 1 and last.op == "j":
            after = self.index_of[last.target]
            # a jump to the function's end is a ``return`` (its value may sit in the jump's delay
            # slot), not the jump over an else block: both spell the same instructions, and only
            # the first keeps the value
            if target < after <= end and after != len(self.ins):
                # if/else: the jump over the else block ends the then block
                keep = (set(self.label_used), self.returns_value, self.barrier)
                try:
                    then = self._block_inner(i + 1, target - 1, loop)
                    other = self._block_inner(target, after, loop)
                except Decline:
                    self.label_used, self.returns_value, self.barrier = keep
                else:
                    self.out.append(Stmt("if", cond, then, other))
                    return after
        then = self._block_inner(i + 1, target, loop)
        self.out.append(Stmt("if", cond, then, None))
        return target

    # -- rendering ----------------------------------------------------------------------------

    def symbol(self, addr: int, call: bool = False) -> str:
        known = self.names.get(addr)
        if known:
            return known
        return f"func_{addr:08X}" if call else f"D_{addr:08X}"

    def note_global(self, addr: int, kind):
        self.globals.setdefault(addr, {"acc": [], "addr": False})
        if kind == "addr":
            self.globals[addr]["addr"] = True
        else:
            self.globals[addr]["acc"].append(kind)

    def global_type(self, addr: int) -> str:
        info = self.globals.get(addr) or {"acc": []}
        acc = info["acc"]
        if not acc:
            return "s32"
        width = acc[0][0]
        if acc[0][1] in ("f", "d"):
            return "f32" if acc[0][1] == "f" else "f64"
        same = [a for a in acc if a[0] == width]
        loads = [a[1] for a in same if a[1] in ("s", "u")]
        signed = (loads[0] == "s") if loads else True
        return INT_TYPES[(width, signed)]

    def frame_var(self, off: int, width: int):
        """(text of the variable at this frame slot, its type, exact) for an access of ``width``."""
        if off >= self.size:
            index, rest = divmod(off - self.size, 4)
            if index >= len(self.params):
                raise Decline("unknown incoming argument")
            param = self.params[index]
            if param.get("kind") == "stack-narrow" and (param["noff"], param["nsize"]) == (off, width):
                return f"arg{index}", param["type"], True
            if param.get("kind") == "stack-narrow":
                raise Decline("mixed access to a stack argument")
            if rest == 0 and width == 4:
                return f"arg{index}", param.get("type", "s32"), True
            if rest == 4 - width:
                return f"arg{index}", "s32", False
            raise Decline("odd access to an incoming argument")
        for array in self.vars.values():
            if array.get("array") and array["off"] <= off < array["off"] + array["size"]:
                if width != array["elem"] or (off - array["off"]) % width:
                    raise Decline("access across the elements of a local array")
                return f"{self.var_name(array)}[{(off - array['off']) // width}]", array["type"], True
        var = self.vars.get(off)
        if var is not None and not var.get("aggregate") and var["size"] == width:
            return self.var_name(var), var["type"], True
        holder = self._holder(off, width)
        if holder is not None and "type" in holder and off == holder["off"] + holder["size"] - width:
            return self.var_name(holder), holder["type"], False
        raise Decline("access inside a local")

    def var_name(self, var) -> str:
        if var.get("param"):
            for index, param in enumerate(self.params):
                if param.get("kind") == "narrow" and param["off"] == var["off"]:
                    return f"arg{index}"
        return f"sp{var['off']:X}"

    def field(self, off: int, ctype: str) -> str:
        if off < 0:
            raise Decline("negative displacement")
        size = {"s8": 1, "u8": 1, "s16": 2, "u16": 2, "s32": 4, "u32": 4, "f32": 4, "f64": 8}[ctype]
        if off % min(size, 4):
            raise Decline("unaligned field")
        self.fields.add((off, ctype))
        return f"struct gd_{off:X}_{ctype}"

    def lvalue(self, loc, width: int, signed, store: bool = False) -> tuple[str, str]:
        """(C text, C type) of a location accessed with this width."""
        kind = loc[0]
        if signed == "f":
            want = "f32" if width == 4 else "f64"
        else:
            want = INT_TYPES[(width, True if signed is None else signed)]
        stepped = getattr(self, "stepped", {})
        if (kind, loc[1]) in stepped:                         # declared as a pointer: its value is an address
            if store or width != 4:
                raise Decline("store to a stepped pointer")
            name = self.frame_var(loc[1], 4)[0] if kind == "local" else self.symbol(loc[1])
            return f"((s32){name})", "s32"
        if kind == "local":
            text, ctype, exact = self.frame_var(loc[1], width)
            if exact:
                if signed is not None and ctype in ("s8", "u8", "s16", "u16") and ctype != want:
                    return f"(({want}){text})", want
                return text, ctype
            if store:
                raise Decline("narrow store into a wider local")
            return f"(({want}){text})", want
        if kind == "global":
            addr = loc[1]
            name = self.symbol(addr)
            ctype = self.global_type(addr)
            if ctype == want or (signed is None and ctype[1:] == want[1:]):
                return name, ctype
            return f"(*({want} *)&{name})", want
        if kind == "deref":
            base, off = loc[1], loc[2]
            inner = self.expr(base)
            if off == 0:
                return f"(*({want} *){inner})", want
            return f"(({self.field(off, want)} *){inner})->v", want
        if kind == "lidx":
            array = self.vars.get(loc[1])
            if array is None or not array.get("array") or array["elem"] != width:
                raise Decline("indexed access that is not a local array")
            index = strip(loc[2])
            if width > 1:
                if not (index.k == "mul" and index.a[1] == width):
                    raise Decline("local array index is not scaled by its element")
                index = index.a[0]
            return f"{self.var_name(array)}[{self.unparen(self.expr(index))}]", array["type"]
        raise Decline(f"location {kind}")

    def expr(self, n: Node) -> str:
        k = n.k
        if k == "cp":
            return self.expr(n.a[0])
        if k == "const":
            return self.number(n.a[0])
        if k == "hi":
            return self.number(_s32(n.a[0] << 16))
        if k == "sym":
            return f"((s32)&{self.symbol(n.a[0])})"
        if k == "lad":
            off = n.a[0]
            if off >= self.size:
                index, rest = divmod(off - self.size, 4)
                if rest or index >= len(self.params) or self.params[index].get("kind") == "stack-narrow":
                    raise Decline("address inside an incoming argument")
                return f"((s32)&arg{index})"
            var = self.vars.get(off)
            if var is None:
                raise Decline("address inside a local")
            return f"((s32)&{self.var_name(var)})"
        if k == "ld":
            return self.lvalue(n.a[2], n.a[0], n.a[1])[0]
        if k == "bin":
            op, a, b = n.a
            # The compiler works on the left operand first, and it may finish the right one before
            # it loads the left one's value (``A[i] + B[i]``: address of A, value of B, value of A).
            # The operand whose first instruction came first is the left one, whatever order the
            # final instruction names them in.
            # That only shows for an operand that produces code when the compiler first meets it
            # (a computed value, an element or field whose address is formed, a narrow load that is
            # widened).  A plain variable is loaded when the operation itself is emitted, wherever
            # it stood in the source: with one of those the instruction's own order is the source's.
            if op in ("+", "*", "&", "|", "^") and const_of(a) is None and const_of(b) is None \
                    and not plain_variable(a) and not plain_variable(b) and first_seq(b) < first_seq(a):
                a, b = b, a
            value = const_of(b)
            if op == "+" and value is not None and value < 0 and strip(b).k == "const":
                return f"({self.expr(a)} - {self.number(-value)})"
            if op in ("<u", ">>u", "/u", "%u"):
                return f"((u32){self.expr(a)} {op[:-1]} {self.unsigned(b)})"
            return f"({self.expr(a)} {op} {self.expr(b)})"
        if k == "fconst":
            return float_text(n.a[0])
        if k == "fbin":
            op, a, b = n.a
            if op == "+" and strip(a) is strip(b):
                return f"({self.expr(a)} * 2.0f)"              # a doubling is compiled as an addition
            if op in ("+", "*") and first_seq(b) < first_seq(a):
                a, b = b, a
            return f"({self.expr(a)} {op} {self.expr(b)})"
        if k == "fun":
            return f"({n.a[0]}{self.expr(n.a[1])})"
        if k == "cvtf":
            return f"(({n.a[0]}){self.expr(n.a[1])})"
        if k in ("ibits", "ftrunc"):
            raise Decline("half of a conversion")
        if k == "mul":
            return f"({self.expr(n.a[0])} * {self.number(n.a[1])})"
        if k == "un":
            return f"({n.a[0]}{self.expr(n.a[1])})"
        if k == "cast":
            return f"(({n.a[0]}){self.expr(n.a[1])})"
        if k == "call":
            target, args = n.a
            if target.k == "func":
                name = self.symbol(target.a[0], call=True)
                info = self.callees.setdefault(name, {"ret": "s32"})
                if id(n) in self.float_calls:
                    info["ret"] = "f32"
                if id(n) in self.prototypes:
                    if info.get("proto") not in (None, self.prototypes[id(n)]):
                        raise Decline("one callee, two argument lists")
                    info["proto"] = self.prototypes[id(n)]
            else:
                name = f"((s32 (*)()){self.expr(target)})"
            return f"{name}({', '.join(self.expr(arg) for arg in args)})"
        if k == "asg":
            loc, value = n.a
            return f"({self.assignment(loc, value, None)})"
        if k == "postinc":
            loc, delta, width = n.a
            if getattr(self, "stepped", {}).get((loc[0], loc[1])) == abs(delta):
                name = self.frame_var(loc[1], 4)[0] if loc[0] == "local" else self.symbol(loc[1])
                return f"((s32){name}{'++' if delta > 0 else '--'})"
            text, ctype = self.lvalue(loc, width, None, store=True)
            if delta in (1, -1):
                return f"({text}{'++' if delta > 0 else '--'})"
            raise Decline("post-increment of a pointer")
        raise Decline(f"expression {k}")

    def unsigned(self, n: Node) -> str:
        value = const_of(n)
        if value is not None:
            return self.number(value)
        return f"(u32){self.expr(n)}"

    @staticmethod
    def number(value: int) -> str:
        if -4096 < value < 4096:
            return str(value)
        if value < 0:
            return f"-0x{-value:X}" if value > -0x8000 else f"0x{value & 0xFFFFFFFF:08X}"
        return f"0x{value:X}"

    def assignment(self, loc, value: Node, width) -> str:
        if width is None:
            width = value.a[0] if value.k == "ld" else 4
        text, ctype = self.lvalue(loc, width, "f" if self.is_float(value) else None, store=True)
        inner = strip(value)
        if value.k == "cp" and inner.k == "bin" and inner.a[0] == "+" and const_of(inner.a[2]) in (1, -1):
            source = strip(inner.a[1])
            if source.k == "ld" and source.a[2] == loc:
                return f"{text}{'++' if const_of(inner.a[2]) > 0 else '--'}"
        if inner.k == "ld" and inner.a[2][0] == "local" and inner.a[0] == width and width < 4:
            # a narrowing copy reads the low end of the wider variable directly
            name, _type, exact = self.frame_var(inner.a[2][1], width)
            if not exact:
                return f"{text} = {name}"
        return f"{text} = {self.unparen(self.expr(value))}"

    @staticmethod
    def unparen(text: str) -> str:
        if text.startswith("(") and text.endswith(")"):
            depth = 0
            for index, char in enumerate(text):
                depth += char == "("
                depth -= char == ")"
                if depth == 0 and index < len(text) - 1:
                    return text
            return text[1:-1]
        return text

    def cond(self, cond) -> str:
        op, a, b = cond
        if op.startswith(("f", "!f")):
            negated, op = op.startswith("!"), op.lstrip("!")[1:]
            if op in ("<", "<=") and first_seq(b) < first_seq(a):
                # ``a > b`` is compiled as ``b < a`` with ``a`` still evaluated first
                text = f"{self.expr(b)} {'>' if op == '<' else '>='} {self.expr(a)}"
            else:
                text = f"{self.expr(a)} {op} {self.expr(b)}"
            return f"!({text})" if negated else text
        if op.endswith("u"):
            if const_of(a) is None and const_of(b) is None and first_seq(b) < first_seq(a):
                return f"(u32){self.expr(b)} {FLIP[op[:-1]]} {self.unsigned(a)}"
            return f"(u32){self.expr(a)} {op[:-1]} {self.unsigned(b)}"
        if const_of(a) is None and const_of(b) is None and first_seq(b) < first_seq(a):
            a, b, op = b, a, FLIP[op]                          # ``a > b`` is compiled as ``b < a``, a first
        return f"{self.expr(a)} {op} {self.expr(b)}"

    def simple(self, stmt) -> str:
        """An assignment or expression statement as it stands in a ``for`` header."""
        if stmt.k == "assign":
            return self.assignment(stmt.a[0], stmt.a[1], stmt.a[2])
        if stmt.k == "expr":
            return self.unparen(self.expr(stmt.a[0]))
        raise Decline("statement in a loop header")

    def statements(self, stmts: list, depth: int) -> list[str]:
        pad = "    " * depth
        lines = []
        for index, stmt in enumerate(stmts):
            k = stmt.k
            if k == "assign":
                lines.append(f"{pad}{self.assignment(stmt.a[0], stmt.a[1], stmt.a[2])};")
            elif k == "expr":
                lines.append(f"{pad}{self.unparen(self.expr(stmt.a[0]))};")
            elif k == "if":
                lines.append(f"{pad}if ({self.cond(stmt.a[0])}) {{")
                lines += self.statements(stmt.a[1], depth + 1)
                if stmt.a[2] is not None:
                    lines.append(f"{pad}}} else {{")
                    lines += self.statements(stmt.a[2], depth + 1)
                lines.append(f"{pad}}}")
            elif k == "loop":
                head, inner = getattr(self, "loop_head", "for (;;)"), stmt.a[0]
                init = stmt.a[3] if len(stmt.a) > 3 else None
                init_text = ", ".join(self.simple(part) for part in init) if init else ""
                skip = 0
                while skip < len(inner) and inner[skip].k == "label" and inner[skip].a[0] not in self.label_used:
                    skip += 1                                # a label nothing in the text jumps to
                inner = inner[skip:] if head != "for (;;)" else inner
                first = inner[0] if inner else None
                # leaving the last statement of a ``void`` function is the same as returning from it
                last = depth == 1 and all(later.k == "label" and later.a[0] not in self.label_used
                                          for later in stmts[index + 1:])
                leaves = first is not None and first.k == "if" and first.a[2] is None and len(first.a[1]) == 1 and (
                    first.a[1][0].k == "break" or (last and first.a[1][0].k == "return" and first.a[1][0].a[0] is None))
                if head != "for (;;)" and leaves:
                    # ``for (;;) { if (c) break; ... }`` read as the loop it was
                    test, inner = f"!({self.cond(first.a[0])})", inner[1:]
                    if init is None:
                        lines.append(f"{pad}while ({test}) {{")
                    else:
                        step, tail = "", len(inner)
                        while tail and inner[tail - 1].k == "label" and inner[tail - 1].a[0] not in self.label_used:
                            tail -= 1
                        if head == "while" and tail and inner[tail - 1].k in ("assign", "expr"):
                            # the last statement as the step: the continue label then stands in
                            # front of it instead of in front of the jump back
                            step, inner = self.simple(inner[tail - 1]), inner[:tail - 1]
                        lines.append(f"{pad}for ({init_text}; {test}; {step}) {{")
                else:
                    lines.append(f"{pad}for ({init_text};;) {{")
                lines += self.statements(inner, depth + 1)
                lines.append(f"{pad}}}")
            elif k == "switch":
                lines.append(f"{pad}switch ({self.unparen(self.expr(stmt.a[0]))}) {{")
                for labels, inner in stmt.a[1]:
                    for value in labels:
                        lines.append(f"{pad}default:" if value is None else f"{pad}case {self.number(value)}:")
                    lines += self.statements(inner, depth + 1)
                lines.append(f"{pad}}}")
            elif k == "label":
                if stmt.a[0] in self.label_used:
                    lines.append(f"L{stmt.a[0]}: ;")
            elif k == "goto":
                lines.append(f"{pad}goto L{stmt.a[0]};")
            elif k in ("break", "continue"):
                lines.append(f"{pad}{k};")
            elif k == "return":
                value = stmt.a[0]
                lines.append(f"{pad}return {self.unparen(self.expr(value))};" if value is not None
                             else f"{pad}return;")
            else:
                raise Decline(f"statement {k}")
        return lines

    def locals_text(self) -> list[str]:
        """Declarations in ascending frame order, with fillers: GCC gives the first declared local
        the lowest slot, aligns each to its size and rounds aggregates to eight bytes."""
        lines, cursor, pads = [], self.args_size, 0
        end = self.args_size + self.var_size

        def fill(until):
            nonlocal cursor, pads
            while cursor < until:
                gap = until - cursor
                if cursor % 8 == 0 and gap >= 8:
                    lines.append(f"    s32 pad{pads}[{2 * (gap // 8)}];")
                    cursor += 8 * (gap // 8)
                elif cursor % 4 == 0 and gap >= 4:
                    lines.append(f"    s32 pad{pads};")
                    cursor += 4
                elif cursor % 2 == 0 and gap >= 2:
                    lines.append(f"    s16 pad{pads};")
                    cursor += 2
                else:
                    lines.append(f"    s8 pad{pads};")
                    cursor += 1
                pads += 1

        ordered = sorted(self.vars.values(), key=lambda v: v["off"])
        seen_local = False
        for position, var in enumerate(ordered):
            off = var["off"]
            following = ordered[position + 1]["off"] if position + 1 < len(ordered) else end
            if var.get("aggregate"):
                room = following - off
                if off % 8 == 0 and room >= 8:
                    var["size"], var["decl"] = 8 * (room // 8), f"s32 {self.var_name(var)}[{2 * (room // 8)}]"
                elif off % 4 == 0 and room >= 4:
                    var["size"], var["decl"] = 4, f"s32 {self.var_name(var)}"
                elif off % 2 == 0 and room >= 2:
                    var["size"], var["decl"] = 2, f"s16 {self.var_name(var)}"
                else:
                    var["size"], var["decl"] = 1, f"s8 {self.var_name(var)}"
            size = var["size"]
            align = 8 if var.get("aggregate") and size >= 8 else min(size, 8)
            if var.get("param"):
                if seen_local or (cursor + align - 1) // align * align != off:
                    raise Decline("parameter slot is not first in the frame")
                cursor = off + size
                continue
            seen_local = True
            if off < cursor:
                raise Decline("overlapping locals")
            if (cursor + align - 1) // align * align != off:
                fill(off)
            if (cursor + align - 1) // align * align != off:
                raise Decline("local cannot be placed")
            lines.append(f"    {var.get('decl') or var['type'] + ' ' + self.var_name(var)};")
            cursor = off + size
        if cursor > end:
            raise Decline("locals exceed the frame")
        if (cursor - self.args_size + 7) // 8 * 8 < self.var_size:
            fill(end - 7 if (end - 7) > cursor else cursor + 1)
            if (cursor - self.args_size + 7) // 8 * 8 != self.var_size:
                fill(end)
        return lines

    def _stepped_pointers(self) -> None:
        """``x = p++`` with a step of several bytes: ``p`` is a pointer to elements of that size.
        Only a typed pointer's ``++`` reads the old value and stores the step in one statement
        (a display-list or buffer pointer advanced by a macro), so the variable is declared as one."""
        self.stepped: dict[tuple, int] = {}
        stack = list(self.body)
        while stack:
            part = stack.pop()
            if isinstance(part, (list, tuple)):
                stack.extend(part)
            elif isinstance(part, (Stmt, Node)):
                if isinstance(part, Node) and part.k == "postinc" and abs(part.a[1]) != 1 and part.a[2] == 4 \
                        and part.a[0][0] in ("global", "local"):
                    key = (part.a[0][0], part.a[0][1])
                    if self.stepped.setdefault(key, abs(part.a[1])) != abs(part.a[1]):
                        raise Decline("one pointer stepped by two sizes")
                stack.extend(part.a)
        for (kind, where), size in self.stepped.items():
            if kind == "local":
                var = self.vars.get(where)
                if var is None or var.get("array") or var.get("aggregate") or var["size"] != 4 or where >= self.size:
                    raise Decline("stepped pointer that is not a plain local")
                var["decl"] = f"struct n64dk_e{size} *{self.var_name(var)}"

    def render(self, prelude: str, names: dict[int, str]) -> str:
        self.names = names
        self._stepped_pointers()
        body = self.statements(self.body, 1)
        local_lines = self.locals_text()
        params = []
        for index, param in enumerate(self.params):
            kind = param["kind"]
            if kind in ("int", "unused", "float"):
                params.append(f"{param.get('type', 's32')} arg{index}")
            elif kind == "narrow":
                params.append(f"{self.vars[param['off']]['type']} arg{index}")
            elif kind == "stack-narrow":
                params.append(f"{param['type']} arg{index}")
            else:
                raise Decline("parameter kind")
        out = [prelude.rstrip("\n"), ""]
        for off, ctype in sorted(self.fields):
            pad = f"u8 pad[0x{off:X}]; " if off else ""
            out.append(f"struct gd_{off:X}_{ctype} {{ {pad}{ctype} v; }};")
        for size in sorted(set(self.stepped.values())):
            out.append(f"struct n64dk_e{size} {{ u8 b[{size}]; }};")
        for addr in sorted(self.globals):
            name = self.symbol(addr)
            if name == self.name or name in self.callees:
                continue
            if ("global", addr) in self.stepped:
                out.append(f"extern struct n64dk_e{self.stepped[('global', addr)]} *{name};")
                continue
            out.append(f"extern {self.global_type(addr)} {name};")
        for name, info in sorted(self.callees.items()):
            if name != self.name:
                # a ``float`` passed as a float (not widened to double) means a prototype was in scope
                out.append(f"{info['ret']} {name}({', '.join(info.get('proto') or [])});")
        ret = self.return_type if self.returns_value else "void"
        out.append("")
        out.append(f"{ret} {self.name}({', '.join(params) or 'void'}) {{")
        out += local_lines
        if local_lines:
            out.append("")
        out += body
        out.append("}")
        return "\n".join(out) + "\n"


_NAMED = re.compile(r"\b(?:func|D|jtbl)_([0-9A-Fa-f]{8})\b")


def prelude_of(source: str) -> str:
    """The typedef/macro head the kit compiles every candidate with."""
    cut = source.rfind("#endif")
    if "N64DK_M2C_PRELUDE" in source and cut >= 0:
        return source[:cut + len("#endif")]
    from .autodraft import PRELUDE
    return PRELUDE


def names_in(source: str) -> dict[int, str]:
    """Address-bearing names the draft uses: the same address must get the same name."""
    names = {}
    for found in _NAMED.finditer(source):
        names.setdefault(int(found.group(1), 16), found.group(0))
    return names


def is_unoptimised_gcc(code: bytes) -> bool:
    """``addu $fp,$sp,$zero`` among the first instructions: GCC's frame pointer set-up."""
    head = code[:64]
    return any(head[i:i + 4] == b"\x03\xa0\xf0\x21" for i in range(0, len(head) - 3, 4))


# A loop is read as ``for (;;) { if (c) break; ... }``.  That has the instructions of the loop that
# was written and one label more: ``for (;;)`` puts a continue label in front of the jump back, a
# ``while (!c)`` has it at the top.  An assembler that fills delay slots never moves an instruction
# across a label, so only the second lets the last instruction of the body into the back jump's
# slot; the lane that fills no slots builds the same bytes from both.
LOOP_HEADS = ("for (;;)", "while", "for-nostep")


def translate(source: str, name: str, code: bytes, vram: int, loop_head: str = LOOP_HEADS[0]) -> str:
    function = Function(code, vram, name)
    function.loop_head = loop_head
    return function.render(prelude_of(source), names_in(source))


def variants(source: str, name: str, *, code: bytes, vram: int, pipeline: str, flags: tuple[str, ...] = (),
             family: str | None = None) -> list[tuple[str, str]]:
    """[(label, complete C translation unit)]; [] when this is not unoptimised GCC code."""
    if not is_unoptimised_gcc(code):
        return []
    out, seen = [], set()
    for head in LOOP_HEADS:
        try:
            text = translate(source, name, code, vram, head)
        except Decline:
            return out
        except (KeyError, IndexError, ValueError, TypeError, AttributeError, RecursionError):
            return out
        if text not in seen:
            seen.add(text)
            out.append(("gcc-O0-translated" + ("" if head == LOOP_HEADS[0] else "+" + head), text))
    return out
