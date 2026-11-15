"""Similarity-first work queue: find matched siblings of unmatched functions.

Published project studies converge on two results: (1) once the easy
functions are gone, ordering by "has a similar already-matched function" beats ordering by
estimated difficulty, and (2) a plain bounded edit distance over opcode sequences (the coddog
approach) is as good as elaborate structural scores.  This module implements both without
dependencies beyond rabbitizer:

* ``signature``  opcode sequence + difficulty features of one function body;
* ``Index``      inverted opcode n-gram index used as a cheap candidate filter;
* ``similarity`` bounded Levenshtein ratio over opcode sequences (1.0 = same opcodes);
* ``queue``      unmatched functions ranked by best matched sibling, then by difficulty.

Similarity is a lead for source reuse, never evidence of a match.
"""
from __future__ import annotations

import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import rabbitizer

NGRAM = 4
MAX_POSTING = 600          # n-grams shared by more functions than this carry no signal


@dataclass
class Signature:
    name: str
    opcodes: tuple[str, ...]
    matched: bool = False
    source: str | None = None       # source path of a matched function (the reusable asset)
    image: str = ""
    branches: int = 0
    calls: int = 0
    frame: int = 0
    extra: dict = field(default_factory=dict)

    @property
    def difficulty(self) -> float:
        """instruction_count + 3*branches + 2*calls: the published one-shot ordering heuristic
        (stack size was measured to have no predictive value and is left out)."""
        return len(self.opcodes) + 3 * self.branches + 2 * self.calls


def signature(name: str, code: bytes, vram: int, **kw) -> Signature:
    ops, branches, calls, frame = [], 0, 0, 0
    for i in range(0, len(code) - len(code) % 4, 4):
        word, = struct.unpack_from(">I", code, i)
        ins = rabbitizer.Instruction(word, vram + i)
        op = ins.getOpcodeName()
        ops.append(op)
        if ins.isBranch():
            branches += 1
        elif ins.doesLink():
            calls += 1
        if word >> 16 == 0x27BD and word & 0x8000:       # addiu $sp, $sp, -N
            frame = max(frame, 0x10000 - (word & 0xFFFF))
    while ops and ops[-1] == "nop":                       # alignment padding is not code shape
        ops.pop()
    return Signature(name, tuple(ops), branches=branches, calls=calls, frame=frame, **kw)


def similarity(a: tuple[str, ...], b: tuple[str, ...], threshold: float = 0.0) -> float:
    """1 - levenshtein/max(len); returns 0.0 early when ``threshold`` cannot be reached."""
    la, lb = len(a), len(b)
    longest = max(la, lb)
    if longest == 0:
        return 1.0
    budget = int(longest * (1.0 - threshold))
    if abs(la - lb) > budget:
        return 0.0
    if a == b:
        return 1.0
    if la > lb:
        a, b, la, lb = b, a, lb, la
    previous = list(range(la + 1))
    for j in range(1, lb + 1):
        lo, hi = max(1, j - budget), min(la, j + budget)
        current = [j] + [longest + 1] * la
        bj = b[j - 1]
        best = current[0] if lo == 1 else longest + 1
        for i in range(lo, hi + 1):
            cost = previous[i - 1] if a[i - 1] == bj else 1 + min(previous[i - 1], previous[i], current[i - 1])
            current[i] = cost
            if cost < best:
                best = cost
        if best > budget:
            return 0.0
        previous = current
    distance = previous[la]
    return 0.0 if distance > budget else 1.0 - distance / longest


def _grams(ops: tuple[str, ...]) -> set[int]:
    if len(ops) < NGRAM:
        return {hash(ops)}
    return {hash(ops[i:i + NGRAM]) for i in range(len(ops) - NGRAM + 1)}


class Index:
    def __init__(self, signatures: list[Signature]):
        self.items = signatures
        self.grams = [_grams(s.opcodes) for s in signatures]
        postings: dict[int, list[int]] = defaultdict(list)
        for number, grams in enumerate(self.grams):
            for gram in grams:
                postings[gram].append(number)
        self.postings = {g: p for g, p in postings.items() if len(p) <= MAX_POSTING}

    def neighbours(self, query: Signature, limit: int = 5, threshold: float = 0.7,
                   shortlist: int = 12, want_matched: bool | None = None) -> list[tuple[float, Signature]]:
        grams = _grams(query.opcodes)
        shared: Counter = Counter()
        for gram in grams:
            for number in self.postings.get(gram, ()):
                shared[number] += 1
        scored = []
        for number, count in shared.items():
            other = self.items[number]
            if other is query or (other.name == query.name and other.image == query.image):
                continue
            if want_matched is not None and other.matched != want_matched:
                continue
            scored.append((count / (len(grams) + len(self.grams[number]) - count), number))
        out = []
        for _jaccard, number in sorted(scored, reverse=True)[:shortlist]:
            value = similarity(query.opcodes, self.items[number].opcodes, threshold)
            if value >= threshold:
                out.append((value, self.items[number]))
        return sorted(out, key=lambda item: (-item[0], item[1].name))[:limit]


def queue(signatures: list[Signature], threshold: float = 0.8, limit: int | None = None) -> list[dict]:
    """Unmatched functions, best first: similar matched sibling (high to low), then difficulty."""
    index = Index(signatures)
    rows = []
    for item in signatures:
        if item.matched or not item.opcodes:
            continue
        siblings = index.neighbours(item, threshold=threshold, want_matched=True)
        peers = index.neighbours(item, threshold=max(threshold, 0.95), want_matched=False, limit=16)
        best = siblings[0][0] if siblings else 0.0
        rows.append({"name": item.name, "image": item.image, "instructions": len(item.opcodes),
                     "difficulty": item.difficulty, "best_similarity": round(best, 4),
                     "references": [{"name": s.name, "image": s.image, "source": s.source,
                                     "similarity": round(v, 4)} for v, s in siblings],
                     # one new match unlocks every near-identical unmatched peer
                     "unlocks": [s.name for _v, s in peers]})
    rows.sort(key=lambda r: (-(r["best_similarity"] >= threshold), -r["best_similarity"],
                             -len(r["unlocks"]) if r["best_similarity"] < threshold else 0, r["difficulty"]))
    return rows[:limit] if limit else rows
