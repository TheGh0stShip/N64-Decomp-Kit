"""Project-wide prototype evidence from machine code (MIPS o32).

One function's bytes rarely settle its prototype: an argument register may be read
incidentally, ``$v0`` is also the first scratch register, and a callee may ignore arguments
its callers pass.  ``solve`` therefore combines, for every function, what the callee does with
its incoming registers and what *every* call site prepares and consumes:

* argument count  = max(arguments the callee reads, arguments the callers freshly set), with
  the disagreement kept as an explicit alternative instead of being hidden;
* argument types  from how the callee first treats each register (pointer base, ``andi``
  mask, ``sll``/``sra`` extension) and from ``$f12``/``$f14`` use;
* return type     ``void`` when the callee never writes ``$v0`` or no caller reads it; a
  narrow type when the callee or its callers extend the value; pointer when the callee
  returns a tracked pointer.

The result is evidence with confidence and contradictions, to seed declarations and drive
prototype experiments.  Headers and an exact compile remain the authority.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import flow as flowmod
from . import values as valuemod
from .flow import A0, ARGS

_NARROW = ("s8", "u8", "s16", "u16")


@dataclass
class Prototype:
    vram: int
    name: str
    args: int
    arg_types: list[str]
    returns: str
    confidence: float
    call_sites: int = 0
    alternatives: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)

    def declaration(self, name: str | None = None, struct_names: dict[int, str] | None = None) -> str:
        types = list(self.arg_types)
        for index, struct in (struct_names or {}).items():
            if index < len(types) and types[index] == "void *":
                types[index] = f"{struct} *"
        return f"{self.returns} {name or self.name}({', '.join(types) or 'void'});"

    def as_dict(self) -> dict:
        return {"vram": f"0x{self.vram:08X}", "name": self.name, "declaration": self.declaration(),
                "confidence": round(self.confidence, 2), "call_sites": self.call_sites,
                "alternatives": self.alternatives, "evidence": self.evidence, "conflicts": self.conflicts}


def function_facts(code: bytes, vram: int, jump_tables: dict[int, list[int]] | None = None) -> valuemod.Facts:
    return valuemod.track(flowmod.analyse(code, vram, jump_tables))


def _arg_type(traits: set[str]) -> str:
    if "pointer" in traits:
        return "void *"
    narrow = [t for t in _NARROW if t in traits]
    return narrow[0] if len(narrow) == 1 else "s32"


def solve(functions: dict[int, valuemod.Facts], names: dict[int, str] | None = None) -> dict[int, Prototype]:
    """``functions`` maps a function's address to its tracked facts.  Calls to addresses that
    are not in the map still contribute nothing; functions without known callers are solved
    from the callee side alone (lower confidence)."""
    names = names or {}
    sites: dict[int, list[valuemod.CallSite]] = {}
    for facts in functions.values():
        for call in facts.calls:
            if call.target is not None:
                sites.setdefault(call.target, []).append(call)
    out = {}
    for vram, facts in functions.items():
        name = names.get(vram) or f"func_{vram:08X}"
        evidence, conflicts, alternatives = [], [], []
        read = sorted(r - A0 for r in facts.flow.live_in & ARGS)
        callee_args = (read[-1] + 1) if read else 0
        callers = sites.get(vram, [])
        set_counts = Counter(4 + len(c.stack_fresh) if c.stack_fresh and len(c.fresh) == 4
                             else (max(c.fresh) - A0 + 1) if c.fresh else 0 for c in callers)
        args, confidence = callee_args, 0.6 if callers else 0.5
        if read:
            evidence.append("callee reads " + ", ".join(f"$a{i}" for i in read) + " before writing")
        if read and read != list(range(len(read))):
            conflicts.append("callee skips an argument register (unused parameter, 64-bit/float argument "
                             "alignment, or an incidental read)")
        if facts.float_args[0]:
            evidence.append("callee reads $f12 before writing (float/double first argument)")
        if facts.stack_args_read:
            stack_args = max(facts.stack_args_read) // 4 + 1
            evidence.append(f"callee reads stack argument slot(s) {sorted(hex(o) for o in facts.stack_args_read)}")
            args = max(args, stack_args)
            callee_args = max(callee_args, stack_args)
        if callers:
            mode, votes = set_counts.most_common(1)[0]
            share = votes / len(callers)
            evidence.append(f"{len(callers)} call site(s) set argument counts {dict(sorted(set_counts.items()))}")
            if mode == callee_args:
                confidence = 0.6 + 0.35 * share
            elif mode > callee_args and share >= 0.6 and len(callers) >= 2:
                # callers consistently prepare more than the callee reads: an unused parameter
                args = mode
                confidence = 0.45 + 0.3 * share
                alternatives.append(f"{callee_args} argument(s) (only those the callee reads)")
                conflicts.append(f"callers set {mode} argument register(s) but the callee reads {callee_args}")
            elif mode < callee_args:
                confidence = 0.55
                alternatives.append(f"{mode} argument(s) (as set at most call sites)")
                conflicts.append(f"callee reads {callee_args} argument register(s) but most call sites freshly set "
                                 f"{mode}: an incidental read, or arguments prepared before an earlier branch")
        arg_types = []
        for index in range(min(args, 4)):
            traits = facts.params.get(index, set())
            kind = _arg_type(traits)
            if index == 0 and facts.float_args[0] and index not in read:
                kind = "f32"
            if index == 1 and facts.float_args[1] and index not in read:
                kind = "f32"
            arg_types.append(kind)
        arg_types += ["s32"] * (args - len(arg_types))
        if facts.float_args[0] and args == 0:
            args, arg_types = 1, ["f32"]
            if facts.float_args[1]:
                args, arg_types = 2, ["f32", "f32"]
            alternatives.append("f64 instead of f32 for the floating arguments")

        # half an address or a half-finished extension left in $v0 is scratch, not a result
        kinds = Counter("unknown" if key[0] in ("hi", "hi-indexed", "addr-indexed", "shl") else key[0]
                        for key in facts.returns)
        used = sum(1 for c in callers if c.result_used)
        narrowed = Counter(c.result_narrowing for c in callers if c.result_narrowing)
        written = bool(facts.returns) and not (set(kinds) & {"unknown"})     # $v0 set on every return path
        returns = "s32"
        if facts.returns and set(kinds) <= {"unknown"}:
            returns = "void"
            evidence.append("callee never writes $v0 before returning")
            if used:
                conflicts.append(f"{used} call site(s) read $v0 after the call although the callee does not set it")
        elif callers and not used:
            # $v0 is also the first scratch register: a value left in it proves nothing by itself
            returns = "void"
            evidence.append(f"none of {len(callers)} call site(s) reads $v0 after the call")
            if written:
                alternatives.append("s32 (the callee leaves a value in $v0 on every return path)")
            if len(callers) == 1:
                confidence = min(confidence, 0.6)
        elif not callers and not written:
            returns = "void"
            evidence.append("no call site seen and $v0 is not set on every return path")
            confidence = min(confidence, 0.5)
        else:
            callee_narrow = [key[1] for key in facts.returns if key[0] == "narrow"]
            if callee_narrow and len(set(callee_narrow)) == 1 and len(callee_narrow) == len(facts.returns):
                returns = callee_narrow[0]
                evidence.append(f"callee extends the returned value to {returns}")
            elif narrowed and narrowed.most_common(1)[0][1] >= max(1, used // 2):
                returns = narrowed.most_common(1)[0][0]
                evidence.append(f"callers extend the result to {returns}")
            elif facts.returns and set(kinds) <= {"field", "gptr", "addr", "param"} and \
                    any(key[0] in ("gptr", "addr", "field") for key in facts.returns):
                returns = "void *"
                evidence.append("callee returns a tracked pointer")
            if used:
                evidence.append(f"{used} of {len(callers)} call site(s) use the result")
            else:
                confidence = min(confidence, 0.5)
                alternatives.append("void (no call site seen; $v0 may be a scratch value)")
        out[vram] = Prototype(vram, name, args, arg_types, returns, min(confidence, 0.95), len(callers),
                              alternatives, evidence, conflicts)
    return out
