"""Credit policy for genuine C and positively proven handwritten assembly."""
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


def classify_source(path: str | Path, handwritten_evidence: tuple[str, ...] = ()) -> ProvenanceResult:
    path = Path(path)
    if path.suffix.lower() == ".c":
        return scan_c(path.read_text(errors="replace"))
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
