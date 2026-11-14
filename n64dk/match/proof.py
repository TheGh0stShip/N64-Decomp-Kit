"""Proof-grade policy kept separate from a matcher's exploratory capabilities."""
from __future__ import annotations

from dataclasses import dataclass

from .pipeline import BuildSpec
from .provenance import ProvenanceResult


@dataclass(frozen=True)
class ToolchainEmulation:
    name: str
    implementation_digest: str
    cross_project_fixtures: int
    evidence: tuple[str, ...]

    @property
    def validated(self) -> bool:
        return (len(self.implementation_digest) == 64
                and self.cross_project_fixtures >= 2
                and bool(self.evidence))


@dataclass(frozen=True)
class ProofVerdict:
    proof_grade: bool
    reasons: tuple[str, ...]


def evaluate(spec: BuildSpec, provenance: ProvenanceResult, exact: bool,
             ownership_verified: bool,
             emulations: dict[str, ToolchainEmulation] | None = None) -> ProofVerdict:
    reasons: list[str] = []
    if not exact:
        reasons.append("owned target bytes are not exact")
    if not ownership_verified:
        reasons.append("section ownership is not verified")
    if not provenance.creditable:
        reasons.append(f"source provenance is {provenance.verdict.value}")
    if spec.pipeline == "kmc+hook":
        reasons.append("arbitrary project normalizer hooks are diagnostic-only")
    if spec.pipeline == "kmc+builtin":
        reasons.append("the legacy built-in normalizer has no proof-grade profile")
    validated = emulations or {}
    for arg in spec.normalizer_args:
        key = arg.removeprefix("--enable-")
        evidence = validated.get(key)
        if evidence is None or not evidence.validated:
            reasons.append(f"normalizer/emulation {key!r} lacks cross-project validation")
    if spec.pipeline == "as" and provenance.verdict.value != "handwritten-assembly-proven":
        reasons.append("assembly pipeline lacks positive handwritten provenance")
    return ProofVerdict(not reasons, tuple(reasons))
