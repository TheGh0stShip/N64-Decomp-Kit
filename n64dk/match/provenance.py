"""Credit policy for genuine C and positively proven handwritten assembly.

Two questions are kept apart.  ``scan_c`` asks whether a candidate is ordinary C at all (no
assembly escape); a search uses it to decide what it may compile.  ``judge_c`` asks whether a
byte-identical source may be *credited*: it must also pass every [match] code rule
(``n64dk.match.coderules``).  A source that is ordinary C and fails one is ``MATCH_PENDING``:
reported, never counted."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class Verdict(str, Enum):
    GENUINE_C = "genuine-c"
    HANDWRITTEN_ASM = "handwritten-assembly-proven"
    GENERATED_ASM = "generated-or-reference-assembly"
    INSUFFICIENT = "insufficient-provenance"
    FORBIDDEN = "forbidden-matching-escape"
    MATCH_PENDING = "match-pending"


FORBIDDEN_C = {
    "inline-asm": re.compile(r"\b(?:__asm__|__asm|asm)\s*(?:volatile\s*)?\("),
    "register-binding": re.compile(r"\bregister\b[^;]*\basm\s*\("),
    "incbin": re.compile(r"\.incbin\b", re.IGNORECASE),
    "instruction-directive": re.compile(r"^\s*\.(?:word|long|byte)\b", re.MULTILINE),
}


@dataclass(frozen=True)
class ProvenanceResult:
    verdict: Verdict
    reasons: tuple[str, ...]
    evidence: tuple[str, ...] = ()

    @property
    def creditable(self) -> bool:
        return self.verdict in (Verdict.GENUINE_C, Verdict.HANDWRITTEN_ASM)


def scan_c(source: str) -> ProvenanceResult:
    hits = tuple(name for name, pattern in FORBIDDEN_C.items() if pattern.search(source))
    if hits:
        return ProvenanceResult(Verdict.FORBIDDEN, hits)
    return ProvenanceResult(Verdict.GENUINE_C, ("no forbidden assembly escape found",))


def judge_c(source: str, path: str = "<source>.c", profile=None) -> ProvenanceResult:
    """Whether byte-identical C may be credited: no assembly escape and no [match] rule finding.
    The evidence lists each blocking finding (``path:line: rule: message``)."""
    scanned = scan_c(source)
    if scanned.verdict == Verdict.FORBIDDEN:
        return scanned
    from . import coderules
    report = coderules.check_source(source, path, profile)
    if report.blocking:
        return ProvenanceResult(Verdict.MATCH_PENDING,
                                tuple(f"code rule {rule}" for rule in report.by_rule(coderules.MATCH)),
                                tuple(finding.text() for finding in report.blocking))
    return ProvenanceResult(Verdict.GENUINE_C, ("no forbidden assembly escape found", "every [match] code rule passes"))


def classify_source(path: str | Path, handwritten_evidence: tuple[str, ...] = (), profile=None) -> ProvenanceResult:
    path = Path(path)
    if path.suffix.lower() == ".c":
        return judge_c(path.read_text(errors="replace"), path.name, profile)
    if path.suffix.lower() not in (".s", ".asm"):
        return ProvenanceResult(Verdict.INSUFFICIENT, ("unsupported source type",))
    if handwritten_evidence:
        return ProvenanceResult(Verdict.HANDWRITTEN_ASM,
                                ("positive handwritten provenance supplied",),
                                handwritten_evidence)
    return ProvenanceResult(Verdict.INSUFFICIENT,
                            ("assembly existence is not handwritten provenance",))


def credit_bytes(size: int, provenance: ProvenanceResult, exact: bool,
                 ownership_verified: bool, normalizer_specific: bool = False) -> int:
    if size < 0:
        raise ValueError("size must be non-negative")
    if not exact or not ownership_verified or normalizer_specific:
        return 0
    return size if provenance.creditable else 0
