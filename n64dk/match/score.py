"""Community-comparable diff score (asm-differ / decomp-permuter penalty model).

``n64dk.match.diff`` classifies residuals for diagnosis; its score (1-3 per entry) is not
comparable with the numbers contributors and tools quote.  This module scores two relocated
code ranges with the same constants and structure as decomp-permuter's ``src/scorer.py`` and
asm-differ's ``Config`` defaults, so a kit score means the same thing as a permuter or
asm-differ score:

    stack offset difference   1 per byte of offset difference
    branch target difference  1
    register/field difference 5 per differing operand field
    reordered instruction     60
    inserted / deleted        100

Rows are position independent: branch targets are rewritten relative to the function start.
``max_score`` is 100 per target instruction, and ``percent`` is the decomp.me-style match
percentage derived from it.  0 means identical rows; byte equality stays the only proof.
"""
from __future__ import annotations

import difflib
import hashlib
import re
import struct
from collections import Counter
from dataclasses import asdict, dataclass

import rabbitizer

PENALTY_STACKDIFF = 1
PENALTY_BRANCHDIFF = 1
PENALTY_REGALLOC = 5
PENALTY_REORDERING = 60
PENALTY_INSERTION = 100
PENALTY_DELETION = 100

_SPREL = re.compile(r"(-?(?:0x)?[0-9A-Fa-f]+)\(\$sp\)$")
_SPADJ = re.compile(r"^addiu\s+\$sp, \$sp, (-?(?:0x)?[0-9A-Fa-f]+)$")
_MEM = re.compile(r"^(.*)\((\$\w+)\)$")


@dataclass(frozen=True)
class Row:
    mnemonic: str
    text: str            # normalized full row
    fields: tuple[str, ...]
    branch: bool


@dataclass(frozen=True)
class Score:
    total: int
    max_score: int
    stack: int
    branch: int
    regalloc: int
    reordering: int
    insertion: int
    deletion: int
    digest: str          # sha256 of candidate rows: dedupe key for search loops

    @property
    def percent(self) -> float:
        if self.max_score <= 0:
            return 100.0 if self.total == 0 else 0.0
        return max(0.0, 100.0 * (self.max_score - self.total) / self.max_score)

    def as_dict(self) -> dict:
        return {**asdict(self), "percent": round(self.percent, 2)}


def rows(code: bytes, vram: int) -> list[Row]:
    out = []
    for i in range(0, len(code) - len(code) % 4, 4):
        word, = struct.unpack_from(">I", code, i)
        ins = rabbitizer.Instruction(word, vram + i)
        name = ins.getOpcodeName()
        is_branch = bool(ins.isBranch())
        if is_branch:
            target = ins.getBranchVramGeneric() - vram
            text = " ".join(ins.disassemble(immOverride=f"L{target:X}" if target >= 0 else f"Lm{-target:X}").split())
        else:
            text = " ".join(ins.disassemble().split())
        ops = text.split(None, 1)[1] if " " in text else ""
        fields = []
        for field in (f.strip() for f in ops.split(",") if f.strip()):
            mem = _MEM.match(field)
            fields += [mem.group(1), mem.group(2)] if mem else [field]
        out.append(Row(name, text, tuple(fields), is_branch))
    return out


def _int(text: str) -> int:
    return int(text, 0)


def _sameline(old: Row, new: Row, counts: Counter, stack_differences: bool) -> None:
    if old.text == new.text:
        return
    ignore_last = False
    a, b = _SPREL.search(old.text), _SPREL.search(new.text)
    if a and b:
        if stack_differences:
            counts["stack"] += abs(_int(a.group(1)) - _int(b.group(1)))
        ignore_last = True
    a, b = _SPADJ.match(old.text), _SPADJ.match(new.text)
    if a and b:                      # frame size: one stack difference, not a register one
        if stack_differences:
            counts["stack"] += abs(_int(a.group(1)) - _int(b.group(1)))
        return
    if old.branch and new.branch and old.fields[-1:] != new.fields[-1:]:
        counts["branch"] += 1
        ignore_last = True
    fa, fb = list(old.fields), list(new.fields)
    if ignore_last:
        # ``N($sp)`` was split into [N, $sp]; a branch target is one field
        drop = 1 if old.branch else 2
        fa, fb = fa[:-drop] or fa[:0], fb[:-drop] or fb[:0]
    counts["regalloc"] += sum(1 for x, y in zip(fa, fb) if x != y) + abs(len(fa) - len(fb))


def score_rows(target: list[Row], candidate: list[Row], stack_differences: bool = True) -> Score:
    counts: Counter = Counter()
    deletions: list[str] = []
    insertions: list[str] = []
    matcher = difflib.SequenceMatcher(None, [r.mnemonic for r in target], [r.mnemonic for r in candidate],
                                      autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                _sameline(target[i1 + k], candidate[j1 + k], counts, stack_differences)
        if tag in ("replace", "delete"):
            deletions += [r.text for r in target[i1:i2]]
        if tag in ("replace", "insert"):
            insertions += [r.text for r in candidate[j1:j2]]
    ins, dels = Counter(insertions), Counter(deletions)
    for text in set(ins) | set(dels):
        common = min(ins[text], dels[text])
        counts["reordering"] += common
        counts["insertion"] += ins[text] - common
        counts["deletion"] += dels[text] - common
    total = (counts["stack"] * PENALTY_STACKDIFF + counts["branch"] * PENALTY_BRANCHDIFF
             + counts["regalloc"] * PENALTY_REGALLOC + counts["reordering"] * PENALTY_REORDERING
             + counts["insertion"] * PENALTY_INSERTION + counts["deletion"] * PENALTY_DELETION)
    digest = hashlib.sha256("\n".join(r.text for r in candidate).encode()).hexdigest()
    return Score(total, PENALTY_DELETION * len(target), counts["stack"], counts["branch"], counts["regalloc"],
                 counts["reordering"], counts["insertion"], counts["deletion"], digest)


def score(target: bytes, candidate: bytes, vram: int, stack_differences: bool = True) -> Score:
    """Score relocated ``candidate`` code against retail ``target`` code placed at ``vram``."""
    result = score_rows(rows(target, vram), rows(candidate, vram), stack_differences)
    if result.total == 0 and target != candidate:
        # identical rows but different bytes (e.g. an unrelocated field): never report 0
        return Score(1, result.max_score, *list(asdict(result).values())[2:8], result.digest)
    return result
