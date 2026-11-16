"""What a function's machine code says about how it was built, before anything is compiled.

A compiler, its assembler and its flags leave marks that do not depend on the source: how a
register move is encoded, which register holds a scratch value, whether arguments are stored to
the stack on entry, whether a delay slot is ever filled, which instruction set the code uses.
``features(code, vram)`` reads those marks as a set of names.  ``Table`` holds, for each recipe
class seen in proven functions, how often each mark occurs, and ranks the classes for a function
or for a stretch of functions (``Table.rank``): the naive-Bayes posterior over the marks.

The table is learned from functions whose recipe is proven (finished runs, donor builds:
``learn``), so it grows with every title matched; ``n64dk/match/data/idioms.json`` is the one shipped (counts of marks, nothing of any ROM).
The ranking orders what is tried and never decides a match: the compiler and the strict
verifier still do.
"""
from __future__ import annotations

import json
import math
import struct
from pathlib import Path

ZERO, AT, V0, V1, A0, A3, T0, T6, T9, GP, SP, FP, RA = 0, 1, 2, 3, 4, 7, 8, 14, 25, 28, 29, 30, 31
MIN_CLASS = 100          # a class is ranked once this many proven functions stand behind it
# A jump out of a function is what a wrongly split function looks like (GCC jumps with ``j``
# inside a function): it says the catalogue is wrong there, not that the compiler is unknown.
NOT_EVIDENCE = frozenset({"tail=jump"})
RARE = 0.01              # a mark a class shows this seldom is something that class does not do
MISFIT_CHANCE = 1e-4     # a mark this unlikely under a class says the class did not build the stretch
UNKNOWN_WINDOW = 24      # functions judged together when asking whether any known class fits
SHIPPED = Path(__file__).resolve().parent / "data" / "idioms.json"


def _words(code: bytes) -> list[int]:
    return list(struct.unpack(f">{len(code) // 4}I", code[:len(code) // 4 * 4]))


_FUNCT_KIND = {0x21: "addu", 0x25: "or", 0x23: "subu", 0x24: "and", 0x2A: "slt", 0x2B: "sltu", 0x08: "jr",
               0x09: "jalr", 0x00: "sll", 0x02: "srl", 0x03: "sra", 0x18: "mult", 0x19: "mult", 0x1A: "div",
               0x1B: "div", 0x10: "mfhi", 0x12: "mflo"}


def _kind(word: int) -> str:
    """An instruction reduced to what it does, without registers or operands."""
    if word == 0:
        return "nop"
    op = word >> 26
    if op == 0:
        return _FUNCT_KIND.get(word & 0x3F, "special")
    if op == 2:
        return "j"
    if op == 3:
        return "jal"
    if op in (1, 4, 5, 6, 7):
        return "br"
    if op in (0x14, 0x15, 0x16, 0x17):
        return "brl"
    if op in (8, 9):
        rs, rt = (word >> 21) & 31, (word >> 16) & 31
        return "spadj" if rs == SP and rt == SP else "li" if rs == ZERO else "addiu"
    if op == 0x0F:
        return "lui"
    if 0x20 <= op <= 0x26:
        return "ld_sp" if (word >> 21) & 31 == SP else "ld"
    if 0x28 <= op <= 0x2E:
        return "st_sp" if (word >> 21) & 31 == SP else "st"
    if op in (0x0A, 0x0B):
        return "slti"
    if op in (0x0C, 0x0D, 0x0E):
        return "logi"
    if op == 0x11:
        return "fp"
    if op in (0x31, 0x35):
        return "fld"
    if op in (0x39, 0x3D):
        return "fst"
    return "other"


def sequence_marks(code: bytes, triples: bool = False) -> frozenset[str]:
    """Which instruction kinds follow which (pairs; with ``triples`` also runs of three, which
    tell optimisation levels apart a little better and make a table ten times the size).

    An optimisation level shows in the order of instructions more than in the instructions: a
    scheduling compiler interleaves the saves of a prologue with the first computations and
    fills the slot after a call with a store, where a lower level leaves them in source order."""
    kinds = [_kind(word) for word in _words(code)]
    while kinds and kinds[-1] == "nop":
        kinds.pop()
    found = {f"seq:{a}|{b}" for a, b in zip(kinds, kinds[1:])}
    if triples:
        found |= {f"seq:{a}|{b}|{c}" for a, b, c in zip(kinds, kinds[1:], kinds[2:])}
    return frozenset(found)


def features(code: bytes, vram: int = 0, sequences: bool = True) -> frozenset[str]:
    """Marks of one function's code (names; absent means not seen): the encodings and
    conventions below, and with ``sequences`` the instruction-order marks (``seq:``)."""
    if sequences:
        return features(code, vram, False) | sequence_marks(code)
    words = _words(code)
    while words and words[-1] == 0:
        words.pop()                                           # alignment padding
    found: set[str] = set()
    if not words:
        return frozenset()
    count = len(words)
    nops = branches = unfilled = 0
    temps_low = temps_high = 0
    frame = None
    for index, word in enumerate(words):
        op, rs, rt, rd = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31
        funct, imm = word & 0x3F, word & 0xFFFF
        if word == 0:
            nops += 1
            continue
        if op == 0:
            if rt == ZERO and rd != ZERO and (word >> 6) & 31 == 0:
                if funct == 0x21:
                    found.add("move=addu")
                elif funct == 0x25:
                    found.add("move=or")
                elif funct == 0x2D:
                    found.add("move=daddu")
            if funct in (0x2C, 0x2D, 0x2E, 0x2F, 0x14, 0x16, 0x17, 0x38, 0x3A, 0x3B, 0x3C, 0x3E, 0x3F, 0x1C, 0x1D,
                         0x1E, 0x1F):
                found.add("isa=64bit")
            if funct == 0x0D:
                found.add(f"break={(word >> 6) & 0xFFFFF:X}")
            if funct in (0x30, 0x31, 0x32, 0x33, 0x34, 0x36):
                found.add("trap")
            if funct == 0x08 and rs == RA:
                nxt = words[index + 1] if index + 1 < count else 0
                found.add("return=slot-filled" if nxt else "return=slot-empty")
            if funct in (0x2A, 0x2B) and rd == AT:
                found.add("at=compare")
            if funct == 0x21 and rd == FP and rs == SP and rt == ZERO or funct == 0x25 and rd == FP and rs == SP and rt == ZERO:
                found.add("frame=pointer")
        elif op in (0x14, 0x15, 0x16, 0x17) or (op == 1 and rt in (2, 3, 0x12, 0x13)):
            found.add("branch=likely")
        elif op == 0x09:                                      # addiu
            if rs == ZERO and rt != ZERO:
                found.add("li=addiu")
            if rs == SP and rt == SP and imm & 0x8000 and frame is None:
                frame = 0x10000 - imm
                found.add("frame=first" if index == 0 else "frame=later")
        elif op == 0x0D and rs == ZERO and rt != ZERO:        # ori from zero
            found.add("li=ori-small" if imm < 0x8000 else "li=ori")
        elif op in (0x0A, 0x0B) and rt == AT:
            found.add("at=compare")
        elif op == 0x0F and rt == AT:
            found.add("at=address")
        elif op == 2:                                         # j: inside the function, or a tail call
            target = ((vram + 4 * index) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)
            if vram and not vram <= target < vram + 4 * count:
                found.add("tail=jump")
        if op in (0x20, 0x21, 0x23, 0x24, 0x25, 0x27) and rs == AT and rt != AT:
            found.add("at=load")                              # a value read through the assembler's register
            previous = words[index - 1] if index else 0
            if previous >> 26 == 0x0F and (previous >> 16) & 31 == AT:
                found.add("at=direct-load")                   # ... with nothing indexed in between: a plain global
        elif op in (0x37, 0x3F):                              # ld / sd
            found.add("isa=64bit")
            if rt == RA and rs == SP:
                found.add("ra=64bit")
        elif op == 0x2B and rs == SP:                         # sw to the stack
            if rt == RA:
                found.add("ra=32bit")
                if frame is not None:
                    gap = frame - (imm if not imm & 0x8000 else 0)
                    found.add("ra-slot=top" if gap in (4, 8) else "ra-slot=inner")
            if A0 <= rt <= A3 and frame is not None and not imm & 0x8000 and imm >= frame and index < 12:
                found.add("args=homed")
        elif op == 0x2B and rs == FP and A0 <= rt <= A3 and index < 14:
            found.add("args=homed-fp")
        if rs == GP and op in (0x20, 0x21, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2B, 0x31, 0x35, 0x39, 0x3D, 0x09):
            found.add("gp=used")
        # scratch registers: which bank a compiler reaches for first
        written = rd if op == 0 and funct not in (0x08, 0x09, 0x18, 0x19, 0x1A, 0x1B) else (
            rt if op in (0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x20, 0x21, 0x23, 0x24, 0x25) else None)
        if written is not None:
            if V0 <= written <= V1 or A0 <= written <= A3:
                temps_low += 1
            elif T6 <= written <= T9 or T0 <= written < T6:
                temps_high += 1
        is_branch = op in (1, 2, 3, 4, 5, 6, 7, 0x14, 0x15, 0x16, 0x17) or (op == 0 and funct in (8, 9)) \
            or (op == 0x11 and rs == 8)
        if is_branch:
            branches += 1
            if index + 1 < count and words[index + 1] == 0:
                unfilled += 1
    if temps_low + temps_high >= 4:
        share = temps_high / (temps_low + temps_high)
        found.add("scratch=t" if share >= 0.6 else "scratch=v" if share <= 0.2 else "scratch=mixed")
    if branches >= 3:
        found.add("slots=empty" if unfilled == branches else "slots=filled" if unfilled * 3 <= branches else "slots=some")
    if count >= 12:
        found.add("nops=many" if nops * 5 >= count else "nops=few")
    if frame is None and count >= 2:
        found.add("frame=none")
    return frozenset(found)


def recipe_class(label: str) -> str:
    """A recipe reduced to what the marks can tell apart: lane and optimisation level."""
    parts = label.split()
    if not parts:
        return ""
    level = next((p for p in parts[1:] if p in ("-O0", "-O1", "-O2", "-O3", "-g", "-Os")), "-O2")
    if level == "-g" and any(p in ("-O1", "-O2", "-O3") for p in parts[1:]):
        level = next(p for p in parts[1:] if p in ("-O1", "-O2", "-O3"))
    return f"{parts[0]} {level}"


class Table:
    """Occurrence of each mark per recipe class, and the ranking it gives."""

    def __init__(self, classes: dict[str, dict] | None = None):
        self.classes = classes or {}          # class -> {"functions": n, "marks": {mark: count}}

    def add(self, label: str, marks) -> None:
        entry = self.classes.setdefault(recipe_class(label), {"functions": 0, "marks": {}})
        entry["functions"] += 1
        for mark in marks:
            entry["marks"][mark] = entry["marks"].get(mark, 0) + 1

    def _vocabulary(self) -> list[str]:
        return sorted({mark for entry in self.classes.values() for mark in entry["marks"]})

    def score(self, marks_of_functions: list[frozenset[str]]) -> dict[str, float]:
        """Log-likelihood of a stretch of functions under each class.

        The encoding and convention marks are few and each is a yes-or-no fact about a function:
        present and absent both count (Laplace-smoothed Bernoulli).  The instruction-order marks
        are many and a function shows a handful: only those present count, each by how often a
        function of the class shows it."""
        vocabulary = [mark for mark in self._vocabulary() if not mark.startswith("seq:")]
        out = {}
        for name, entry in self.classes.items():
            total = entry["functions"]
            if total < MIN_CLASS:
                continue
            counts = entry["marks"]
            log_present = {m: math.log((counts.get(m, 0) + 0.5) / (total + 1.0)) for m in vocabulary}
            log_absent = {m: math.log((total - counts.get(m, 0) + 0.5) / (total + 1.0)) for m in vocabulary}
            base = sum(log_absent.values())
            floor = math.log(0.5 / (total + 1.0))
            score = 0.0
            for marks in marks_of_functions:
                score += base
                for mark in marks:
                    if mark.startswith("seq:"):
                        seen = counts.get(mark, 0)
                        score += math.log((seen + 0.5) / (total + 1.0)) if seen else floor
                    elif mark in log_present:
                        score += log_present[mark] - log_absent[mark]
            out[name] = score
        return out

    def rank(self, marks_of_functions: list[frozenset[str]], limit: int | None = None) -> list[tuple[str, float]]:
        """Classes, most likely first, with their posterior share (a uniform prior over classes)."""
        scores = self.score(marks_of_functions)
        if not scores:
            return []
        top = max(scores.values())
        weights = {name: math.exp(max(-700.0, value - top)) for name, value in scores.items()}
        whole = sum(weights.values())
        ranked = sorted(((name, weight / whole) for name, weight in weights.items()), key=lambda item: -item[1])
        return ranked[:limit] if limit else ranked

    def excluded(self, marks: frozenset[str], min_functions: int = 200) -> set[str]:
        """Classes that never showed a mark this code has, among classes seen often enough for
        'never' to mean something.  Only the encoding and convention marks count: that an
        instruction order was never seen is a matter of sample size, not of the compiler."""
        return {name for name, entry in self.classes.items() if entry["functions"] >= min_functions
                and any(entry["marks"].get(mark, 0) == 0 for mark in marks if not mark.startswith("seq:"))}

    def misfit(self, marks_of_functions: list[frozenset[str]], chance: float = MISFIT_CHANCE) -> dict[str, list]:
        """Classes this stretch of functions does not fit, each with the marks that say so.

        A class fits unless the stretch keeps doing something the class all but never does (a
        mark in under one in a hundred of its proven functions): ``(mark, seen, of, usual rate)``
        is reported when seeing that many by chance is less likely than ``chance``.  A stretch no class fits
        was built by something the table has not seen."""
        of = len(marks_of_functions)
        seen: dict[str, int] = {}
        for marks in marks_of_functions:
            for mark in marks:
                if not mark.startswith("seq:") and mark not in NOT_EVIDENCE:
                    seen[mark] = seen.get(mark, 0) + 1
        out: dict[str, list] = {}
        for name, entry in self.classes.items():
            total = entry["functions"]
            if total < MIN_CLASS:
                continue
            reasons = []
            for mark, count in seen.items():
                rate = (entry["marks"].get(mark, 0) + 0.5) / (total + 1.0)
                # Only what the class all but never does counts.  How often a class does a common
                # thing differs between a library and a game; that it never does a thing does not.
                if rate <= RARE and count >= 3 and _tail(count, of, rate) < chance:
                    reasons.append((mark, count, of, round(rate, 4)))
            if reasons:
                out[name] = sorted(reasons, key=lambda reason: -reason[1])
        return out

    def unexplained(self, marks_of_functions: list[frozenset[str]]) -> list | None:
        """The marks that rule every known class out for this stretch, or None when one fits."""
        classes = [name for name, entry in self.classes.items() if entry["functions"] >= MIN_CLASS]
        if not classes or not marks_of_functions:
            return None
        found = self.misfit(marks_of_functions)
        if any(name not in found for name in classes):
            return None
        # One and the same thing must rule every class out.  Where each class is ruled out by
        # something different, the stretch is a seam between two known compilers, not a third.
        common = set.intersection(*[{reason[0] for reason in found[name]} for name in classes])
        return sorted(common) or None

    def prune(self, min_count: int = 5) -> "Table":
        """Drop instruction-order marks seen fewer than ``min_count`` times in all (noise, and
        most of a table's size)."""
        seen: dict[str, int] = {}
        for entry in self.classes.values():
            for mark, count in entry["marks"].items():
                seen[mark] = seen.get(mark, 0) + count
        for entry in self.classes.values():
            entry["marks"] = {mark: count for mark, count in entry["marks"].items()
                              if not mark.startswith("seq:") or seen[mark] >= min_count}
        return self

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        lines = ["{", ' "version": 1,', ' "classes": {']
        names = sorted(self.classes)
        for number, name in enumerate(names):                 # one class per line: a readable diff
            lines.append(f"  {json.dumps(name)}: " + json.dumps(self.classes[name], sort_keys=True, separators=(",", ":"))
                         + ("," if number + 1 < len(names) else ""))
        Path(path).write_text("\n".join(lines + [" }", "}"]) + "\n")

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Table":
        path = Path(path) if path else SHIPPED
        if not path.is_file():
            return cls()
        data = json.loads(path.read_text())
        return cls(data.get("classes") or {})


def stretches(functions: list[tuple[int, frozenset[str]]], table: Table, window: int = 12,
              keep: int = 3) -> list[dict]:
    """A map of an image by its marks alone: consecutive functions, in address order, grouped
    while the most likely lane stays the same.  ``functions`` is ``[(address, marks)]``.  Each
    function is ranked together with its neighbours (``window`` functions around it), because a
    single small function carries few marks."""
    functions = sorted(functions)
    out: list[dict] = []
    for index, (address, _marks) in enumerate(functions):
        lo = max(0, min(index - window // 2, len(functions) - window))
        ranked = table.rank([marks for _a, marks in functions[lo:lo + window]])
        if not ranked:
            continue
        lanes: dict[str, float] = {}
        for name, share in ranked:
            lanes[name.split()[0]] = lanes.get(name.split()[0], 0.0) + share
        lane = max(lanes, key=lanes.get)
        if out and out[-1]["lane"] == lane:
            out[-1]["end"], out[-1]["functions"] = address, out[-1]["functions"] + 1
            for name, share in ranked:
                out[-1]["_sum"][name] = out[-1]["_sum"].get(name, 0.0) + share
        else:
            out.append({"start": address, "end": address, "lane": lane, "functions": 1,
                        "_sum": {name: share for name, share in ranked}})
    for row in out:
        total = sum(row["_sum"].values()) or 1.0
        best = sorted(row.pop("_sum").items(), key=lambda item: -item[1])[:keep]
        row["likely"] = [{"recipe": name, "share": round(share / total, 3)} for name, share in best]
    return out


def _tail(seen: int, of: int, rate: float) -> float:
    """Probability of ``seen`` or more among ``of`` when each has probability ``rate``."""
    return sum(math.comb(of, k) * rate ** k * (1.0 - rate) ** (of - k) for k in range(seen, of + 1))


def unknown_stretches(functions: list[tuple[int, frozenset[str]]], table: Table,
                      window: int = UNKNOWN_WINDOW) -> list[dict]:
    """Stretches of an image no class of the table fits: ``[{start, end, functions, marks}]``.

    Each function is judged with its neighbours.  Such code is not badly drafted, it was built by
    a compiler (or with a setting) nothing here reproduces; trying recipes and variants on it
    costs builds and finds nothing."""
    functions = sorted(functions)
    if len(functions) < window:
        return []
    flagged: dict[int, list] = {}
    for index in range(0, len(functions) - window + 1, max(1, window // 4)):
        marks = table.unexplained([m for _a, m in functions[index:index + window]])
        if marks:
            for position in range(index, index + window):
                flagged.setdefault(position, marks)
    out: list[dict] = []
    for position in sorted(flagged):
        address = functions[position][0]
        if out and out[-1]["_last"] == position - 1:
            out[-1].update(end=address, functions=out[-1]["functions"] + 1, _last=position)
            out[-1]["marks"] = sorted(set(out[-1]["marks"]) | set(flagged[position]))
        else:
            out.append({"start": address, "end": address, "functions": 1, "marks": list(flagged[position]),
                        "_last": position})
    for row in out:
        row.pop("_last")
    return out


def _family_level(label: str) -> tuple[str, str]:
    """(compiler family, optimisation level) of a recipe or class label."""
    name = recipe_class(label)
    pipeline, _, level = name.partition(" ")
    return ("ido" if pipeline.startswith(("ido", "custom:ido", "custom:mipspro")) else "gcc"), level


def doubt(functions: list[tuple[int, frozenset[str]]], table: Table, configured: str, window: int = 12,
          sure: float = 0.9, least: int = 10) -> dict:
    """How much of an image contradicts the recipe it is configured with.

    A stretch of at least ``least`` functions counts against the configured recipe when its marks
    put ``sure`` of the likelihood on a class of another compiler family or another optimisation
    level.  Returns the share of functions in such stretches and what they look like instead."""
    want = _family_level(configured)
    against, seen, total = 0, {}, 0
    for row in stretches(functions, table, window, keep=1):
        total += row["functions"]
        top = row["likely"][0] if row["likely"] else None
        if top is None or row["functions"] < least or top["share"] < sure:
            continue
        if _family_level(top["recipe"]) != want:
            against += row["functions"]
            seen[top["recipe"]] = seen.get(top["recipe"], 0) + row["functions"]
    return {"configured": configured, "functions": total, "against": against,
            "share": round(against / total, 3) if total else 0.0,
            "looks_like": dict(sorted(seen.items(), key=lambda item: -item[1])[:4])}


def learn(table: Table, rows) -> int:
    """Add proven functions to ``table``: ``rows`` yields ``(recipe label, code bytes, vram)``."""
    added = 0
    for label, code, vram in rows:
        if label and code:
            table.add(label, features(code, vram))
            added += 1
    return added
