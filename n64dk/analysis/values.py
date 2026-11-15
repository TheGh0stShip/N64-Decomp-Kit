"""Forward value tracking over one function: what each register holds, in source terms.

``track`` runs a small abstract interpretation over the blocks of a :class:`flow.Flow`.
A register (or stack slot) holds one of::

    ("param", i)            the i-th incoming integer argument, possibly plus a constant
    ("ret", callee, site)   the value returned by the call at ``site``
    ("gptr", address)       a pointer loaded from the global at ``address``
    ("addr", address)       the address of a global (``lui``/``addiu`` pair)
    ("field", base, off)    a pointer loaded from ``off`` of another tracked pointer
    ("sp",)                 the stack pointer

together with a constant displacement.  From that it records the facts every later solver
needs, independent of compiler and game:

* every memory access through a tracked pointer: base identity, offset, width, signedness,
  load/store, integer/float  (structure layout evidence);
* every access to a global address, and whether it was indexed  (global declaration evidence);
* every call with the values and freshly-set registers of its arguments, and whether the
  result is used  (prototype evidence);
* how each incoming argument is first treated: used as a pointer, masked or extended to a
  narrow type  (parameter type evidence);
* what the function leaves in ``$v0`` when it returns.

At joins a register keeps its value only when every predecessor agrees.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import flow as flowmod
from .flow import A0, ARGS, CALL_CLOBBERED, RA, SP, V0, ZERO, Flow

LOADS = {32: ("lb", 1, True), 36: ("lbu", 1, False), 33: ("lh", 2, True), 37: ("lhu", 2, False),
         35: ("lw", 4, True), 39: ("lwu", 4, False), 55: ("ld", 8, True),
         49: ("lwc1", 4, True), 53: ("ldc1", 8, True)}
STORES = {40: ("sb", 1), 41: ("sh", 2), 43: ("sw", 4), 63: ("sd", 8), 57: ("swc1", 4), 61: ("sdc1", 8)}
POINTERS = {"param", "ret", "gptr", "addr", "field"}


@dataclass(frozen=True)
class Access:
    site: int
    base: tuple              # value key
    offset: int
    op: str
    width: int
    signed: bool | None      # None for stores
    store: bool
    floating: bool


@dataclass(frozen=True)
class GlobalAccess:
    site: int
    address: int
    op: str
    width: int
    signed: bool | None
    store: bool
    indexed: bool
    floating: bool = False


@dataclass
class CallSite:
    site: int
    target: int | None
    args: dict[int, tuple | None]        # a-register -> (key, delta) it holds at the call
    fresh: frozenset[int]                # a-registers written for this call (since the previous call)
    stack_fresh: frozenset[int] = frozenset()   # outgoing stack argument offsets stored for this call
    result_used: bool = False
    result_narrowing: str | None = None  # how the caller first treats $v0 ("s16", "u8", ...)


@dataclass
class Facts:
    flow: Flow
    accesses: list[Access] = field(default_factory=list)
    globals: list[GlobalAccess] = field(default_factory=list)
    calls: list[CallSite] = field(default_factory=list)
    params: dict[int, set[str]] = field(default_factory=dict)      # i -> {"pointer","u8","s16","passed",...}
    returns: list[tuple] = field(default_factory=list)             # value in $v0 at each return
    float_args: tuple[bool, bool] = (False, False)                 # $f12, $f14 read before written
    stack_args_read: list[int] = field(default_factory=list)       # incoming stack argument offsets (0x10, 0x14...)


def _simm(word: int) -> int:
    imm = word & 0xFFFF
    return imm - 0x10000 if imm & 0x8000 else imm


def _float_args(fl: Flow) -> tuple[bool, bool]:
    import rabbitizer
    seen, written = set(), set()
    for insn in fl.insns[:fl.blocks[0].last + 1] if fl.blocks else []:
        ins = rabbitizer.Instruction(insn.word, insn.vram)
        if not ins.isValid() or not ins.isFloat():
            continue
        for reads, name in ((ins.readsFs, "fs"), (ins.readsFt, "ft"), (ins.readsFd, "fd")):
            if reads():
                number = int(getattr(ins, name).value)
                if number in (12, 14) and number not in written:
                    seen.add(number)
        for writes, name in ((ins.modifiesFs, "fs"), (ins.modifiesFt, "ft"), (ins.modifiesFd, "fd")):
            if writes():
                written.add(int(getattr(ins, name).value))
    return (12 in seen, 14 in seen)


def track(fl: Flow) -> Facts:
    facts = Facts(fl, float_args=_float_args(fl))
    insns, blocks = fl.insns, fl.blocks
    if not blocks:
        return facts
    entry = {reg: (("param", reg - A0), 0) for reg in ARGS}
    entry[SP] = (("sp",), 0)
    states_out: dict[int, tuple[dict, dict]] = {}
    recorded: set[tuple] = set()
    order = _reverse_postorder(blocks)

    def note_param(value, trait):
        if value is not None and value[0][0] == "param" and value[1] == 0:
            facts.params.setdefault(value[0][1], set()).add(trait)

    def step(insn, regs, slots, record):
        word = insn.word
        op, rs, rt, rd = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        funct, sa, simm = word & 0x3F, (word >> 6) & 31, _simm(word)
        base = regs.get(rs)
        if op == 15:                                             # lui
            regs[rt] = (("hi", (word & 0xFFFF) << 16), 0)
            return
        if op in (9, 25):                                        # addiu / daddiu
            if base is None:
                regs.pop(rt, None)
            elif base[0][0] == "hi":
                regs[rt] = (("addr", (base[0][1] + simm) & 0xFFFFFFFF), 0)
            elif base[0][0] in POINTERS or base[0][0] == "sp":
                regs[rt] = (base[0], base[1] + simm)
            else:
                regs.pop(rt, None)
            return
        if op == 13:                                             # ori: lui/ori is a constant
            regs.pop(rt, None)
            return
        if op == 12 and rt != ZERO:                              # andi
            if (word & 0xFFFF) in (0xFF, 0xFFFF):
                if record:
                    note_param(base, "u8" if (word & 0xFFFF) == 0xFF else "u16")
                regs[rt] = (("narrow", "u8" if (word & 0xFFFF) == 0xFF else "u16"), 0)
            else:
                regs.pop(rt, None)
            return
        if op == 0 and funct in (0x21, 0x25, 0x2D) and rd != ZERO:   # addu / or / daddu
            left, right = regs.get(rs), regs.get(rt)
            if rt == ZERO and rs != ZERO:
                regs[rd] = left if left is not None else None
            elif rs == ZERO and rt != ZERO:
                regs[rd] = right if right is not None else None
            elif left is not None and left[0][0] == "hi" and funct != 0x25:
                regs[rd] = (("hi-indexed", left[0][1]), 0)
            elif right is not None and right[0][0] == "hi" and funct != 0x25:
                regs[rd] = (("hi-indexed", right[0][1]), 0)
            elif left is not None and left[0][0] in ("addr",) and funct != 0x25:
                regs[rd] = (("addr-indexed", left[0][1] + left[1]), 0)
            elif right is not None and right[0][0] in ("addr",) and funct != 0x25:
                regs[rd] = (("addr-indexed", right[0][1] + right[1]), 0)
            else:
                regs.pop(rd, None)
            if regs.get(rd, 0) is None:
                regs.pop(rd, None)
            return
        if op == 0 and funct == 0 and rd != ZERO:                # sll
            source = regs.get(rt)
            if sa in (16, 24) and source is not None and source[0][0] in ("param", "ret"):
                regs[rd] = (("shl", source[0], sa), source[1])
            elif sa in (16, 24):
                regs[rd] = (("shl", None, sa), 0)
            else:
                regs.pop(rd, None)
            return
        if op == 0 and funct in (2, 3) and rd != ZERO:           # srl / sra
            source = regs.get(rt)
            if source is not None and source[0][0] == "shl" and source[0][2] == sa:
                kind = ("s" if funct == 3 else "u") + ("16" if sa == 16 else "8")
                if record and source[0][1] is not None and source[1] == 0:
                    if source[0][1][0] == "param":
                        facts.params.setdefault(source[0][1][1], set()).add(kind)
                    else:
                        for call in facts.calls:
                            if call.site == source[0][1][2] and call.result_narrowing is None:
                                call.result_narrowing = kind
                regs[rd] = (("narrow", kind), 0)
            else:
                regs.pop(rd, None)
            return
        if op in LOADS or op in STORES:
            store = op in STORES
            name, width = (STORES[op][0], STORES[op][1]) if store else (LOADS[op][0], LOADS[op][1])
            signed = None if store else LOADS[op][2]
            floating = "c1" in name
            if store and rs == SP and op in (43, 63):
                value = regs.get(rt)
                if value is not None and value[0][0] not in ("hi", "hi-indexed", "shl", "narrow"):
                    slots[simm] = value
                else:
                    slots.pop(simm, None)
            if base is not None and record:
                key = (insn.vram, name)
                kind = base[0][0]
                if kind == "hi":
                    if key not in recorded:
                        recorded.add(key)
                        facts.globals.append(GlobalAccess(insn.vram, (base[0][1] + simm) & 0xFFFFFFFF, name, width,
                                                          signed, store, False, floating))
                elif kind in ("hi-indexed", "addr-indexed", "addr"):
                    address = ((base[0][1] + simm) if kind != "addr" else (base[0][1] + base[1] + simm)) & 0xFFFFFFFF
                    if key not in recorded:
                        recorded.add(key)
                        facts.globals.append(GlobalAccess(insn.vram, address, name, width, signed, store,
                                                          kind != "addr", floating))
                elif kind in POINTERS:
                    if key not in recorded:
                        recorded.add(key)
                        facts.accesses.append(Access(insn.vram, base[0], base[1] + simm, name, width, signed,
                                                     store, floating))
                    note_param(base, "pointer")
                elif kind == "sp" and not store and base[1] + simm >= fl.frame.size + 0x10:
                    offset = (base[1] + simm - fl.frame.size) & ~3      # sub-word reads of a narrow argument
                    if offset not in facts.stack_args_read:
                        facts.stack_args_read.append(offset)
            if not store and op not in (49, 53):
                if base is not None and base[0][0] == "sp" and op in (35, 55):
                    value = slots.get(base[1] + simm)
                    if value is not None:
                        regs[rt] = value
                    else:
                        regs.pop(rt, None)
                elif base is not None and base[0][0] == "hi" and op == 35:
                    regs[rt] = (("gptr", (base[0][1] + simm) & 0xFFFFFFFF), 0)
                elif base is not None and base[0][0] in POINTERS and op == 35 and _depth(base[0]) < 2:
                    regs[rt] = (("field", base[0], base[1] + simm), 0)
                else:
                    regs.pop(rt, None)
            return
        for reg in insn.defs:
            regs.pop(reg, None)

    for _pass in range(6):
        changed = False
        record = _pass > 0
        if record:
            facts.accesses.clear(); facts.globals.clear(); facts.calls.clear(); facts.returns.clear()
            facts.params.clear(); facts.stack_args_read.clear(); recorded.clear()
        for number in order:
            block = blocks[number]
            preds = [states_out[p] for p in block.preds if p in states_out]
            if number == 0:
                regs, slots = dict(entry), {}
                if preds:
                    regs, slots = _merge([(regs, slots), *preds])
            elif preds:
                regs, slots = _merge(preds)
            else:
                regs, slots = {SP: (("sp",), 0)}, {}
            index = block.first
            while index <= block.last:
                insn = insns[index]
                if insn.control and index + 1 <= block.last:
                    step(insns[index + 1], regs, slots, record)
                    if V0 in insns[index + 1].defs and V0 not in regs:
                        regs[V0] = (("computed",), 0)
                    if insn.kind == "call":
                        if record:
                            facts.calls.append(_call(fl, insn, regs))
                        for reg in CALL_CLOBBERED:
                            regs.pop(reg, None)
                        regs[V0] = (("ret", insn.target, insn.vram), 0)
                    elif insn.kind == "return" and record:
                        facts.returns.append(regs.get(V0, (("unknown",), 0))[0])
                    index += 2
                    continue
                if insn.kind == "return" and record:
                    facts.returns.append(regs.get(V0, (("unknown",), 0))[0])
                step(insn, regs, slots, record)
                if V0 in insn.defs and V0 not in regs:
                    regs[V0] = (("computed",), 0)
                index += 1
            snapshot = (dict(regs), dict(slots))
            if states_out.get(number) != snapshot:
                states_out[number], changed = snapshot, True
        if record and not changed:
            break
    for call in facts.calls:
        for reg, value in call.args.items():
            if value is not None and value[0][0] == "param" and value[1] == 0:
                facts.params.setdefault(value[0][1], set()).add("passed")
    return facts


def _depth(key: tuple) -> int:
    return 1 + _depth(key[1]) if key[0] == "field" else 0


def _merge(states):
    regs = dict(states[0][0])
    slots = dict(states[0][1])
    for other_regs, other_slots in states[1:]:
        for reg in list(regs):
            if other_regs.get(reg) != regs[reg]:
                del regs[reg]
        for slot in list(slots):
            if other_slots.get(slot) != slots[slot]:
                del slots[slot]
    return regs, slots


def _reverse_postorder(blocks) -> list[int]:
    seen, out = set(), []

    def visit(number):
        stack = [(number, iter(blocks[number].succs))]
        seen.add(number)
        while stack:
            current, children = stack[-1]
            for child in children:
                if child not in seen:
                    seen.add(child)
                    stack.append((child, iter(blocks[child].succs)))
                    break
            else:
                out.append(current)
                stack.pop()
    visit(0)
    return out[::-1]


def _call(fl: Flow, insn, regs) -> CallSite:
    """Argument registers written for this call: scan back (delay slot included) to the previous
    call, or to a block start that is not a plain fall-through from the preceding addresses."""
    fresh, stack, index = set(), set(), min(insn.index + 1, len(fl.insns) - 1)
    while index >= 0 and insn.index + 1 - index <= 40:
        current = fl.insns[index]
        if current.kind == "call" and index != insn.index:
            break
        fresh |= current.defs & ARGS
        word = current.word
        if word >> 26 in (43, 63, 57, 61) and (word >> 21) & 31 == SP and 0x10 <= (word & 0xFFFF) < 0x40 \
                and (word >> 16) & 31 not in flowmod.SAVED and (word >> 16) & 31 != RA:
            stack.add(word & 0xFFFC)
        block = fl.block_of(index)
        if index == block.first and (block.number == 0 or len(block.preds) != 1
                                     or fl.blocks[block.preds[0]].last != index - 1):
            break
        index -= 1
    args = {reg: regs.get(reg) for reg in sorted(ARGS)}
    contiguous, offset = set(), 0x10
    while offset in stack:                     # outgoing arguments are stored contiguously from 0x10($sp)
        contiguous.add(offset)
        offset += 4
    return CallSite(insn.vram, insn.target, args, frozenset(fresh), frozenset(contiguous),
                    V0 in fl.live_after(insn.index))
