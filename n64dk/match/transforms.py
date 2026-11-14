"""Bounded, reversible source transformations with explicit proof obligations."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from enum import Enum

from .provenance import Verdict, scan_c
from .residual import Mechanism


class Risk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class Transformation:
    transform_id: str
    description: str
    compiler_profiles: tuple[str, ...]
    mechanisms: tuple[Mechanism, ...]
    risk: Risk
    preconditions: tuple[str, ...]
    evidence: tuple[str, ...]
    expected_change: str


@dataclass(frozen=True, order=True)
class Edit:
    start: int
    end: int
    replacement: str

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError("invalid edit interval")


@dataclass(frozen=True)
class Proposal:
    transform_id: str
    source_digest: str
    compiler_profile: str
    edits: tuple[Edit, ...]
    semantic_evidence: tuple[str, ...]
    hypothesis: str


@dataclass(frozen=True)
class AppliedProposal:
    source: str
    inverse: Proposal
    changed_characters: int


class TransformationError(ValueError):
    pass


class Registry:
    def __init__(self, transformations=()):
        self._items = {item.transform_id: item for item in transformations}

    def add(self, transformation: Transformation) -> None:
        if transformation.transform_id in self._items:
            raise TransformationError(f"duplicate transform {transformation.transform_id}")
        self._items[transformation.transform_id] = transformation

    def get(self, transform_id: str) -> Transformation:
        try:
            return self._items[transform_id]
        except KeyError as error:
            raise TransformationError(f"unknown transform {transform_id}") from error

    def for_mechanism(self, mechanism: Mechanism, compiler_profile: str) -> list[Transformation]:
        return [item for item in self._items.values()
                if mechanism in item.mechanisms
                and (compiler_profile in item.compiler_profiles or "*" in item.compiler_profiles)]

    def apply(self, source: str, proposal: Proposal, max_edits: int = 4,
              max_changed_characters: int = 4096) -> AppliedProposal:
        rule = self.get(proposal.transform_id)
        if (proposal.compiler_profile not in rule.compiler_profiles
                and "*" not in rule.compiler_profiles):
            raise TransformationError("transform is not valid for this compiler profile")
        digest = hashlib.sha256(source.encode()).hexdigest()
        if digest != proposal.source_digest:
            raise TransformationError("proposal source digest is stale")
        if not proposal.semantic_evidence:
            raise TransformationError("semantic evidence is required")
        if not proposal.hypothesis.strip():
            raise TransformationError("a causal hypothesis is required")
        if not proposal.edits or len(proposal.edits) > max_edits:
            raise TransformationError("proposal exceeds the edit bound")
        edits = sorted(proposal.edits)
        for left, right in zip(edits, edits[1:]):
            if right.start < left.end:
                raise TransformationError("proposal edits overlap")
        if edits[-1].end > len(source):
            raise TransformationError("proposal edit lies outside the source")
        changed = sum((edit.end - edit.start) + len(edit.replacement) for edit in edits)
        if changed > max_changed_characters:
            raise TransformationError("proposal exceeds the character bound")

        out, cursor, inverse_edits, shift = [], 0, [], 0
        for edit in edits:
            out.append(source[cursor:edit.start])
            out.append(edit.replacement)
            original = source[edit.start:edit.end]
            new_start = edit.start + shift
            inverse_edits.append(Edit(new_start, new_start + len(edit.replacement), original))
            shift += len(edit.replacement) - (edit.end - edit.start)
            cursor = edit.end
        out.append(source[cursor:])
        candidate = "".join(out)
        provenance = scan_c(candidate)
        if provenance.verdict == Verdict.FORBIDDEN:
            raise TransformationError("proposal introduced a forbidden assembly escape")
        inverse = Proposal(proposal.transform_id, hashlib.sha256(candidate.encode()).hexdigest(),
                           proposal.compiler_profile, tuple(inverse_edits),
                           ("mechanical inverse of accepted proposal",),
                           f"revert {proposal.transform_id}")
        return AppliedProposal(candidate, inverse, changed)

    def describe(self) -> list[dict]:
        return [asdict(item) for item in sorted(self._items.values(), key=lambda item: item.transform_id)]


def default_registry() -> Registry:
    source = "docs/autonomous-matching.md"
    families = [
        ("declaration-lifetime", "Reorder or rescope independent locals", (Mechanism.REGISTER_ALLOCATION, Mechanism.RELOAD), Risk.MEDIUM),
        ("split-fuse-expression", "Introduce or remove a single-use scalar temporary", (Mechanism.SEMANTICS, Mechanism.REGISTER_ALLOCATION, Mechanism.SCHEDULING), Risk.MEDIUM),
        ("width-signedness", "Change a local or field width/sign with a proven value range", (Mechanism.TYPES,), Risk.HIGH),
        ("address-taken-alias", "Route an object through a same-type pointer with escape proof", (Mechanism.TYPES, Mechanism.REGISTER_ALLOCATION), Risk.HIGH),
        ("call-argument-local", "Materialize a side-effect-free call argument as a local", (Mechanism.REGISTER_ALLOCATION, Mechanism.SCHEDULING), Risk.MEDIUM),
        ("loop-induction-shape", "Change index/cursor or loop syntax with iteration proof", (Mechanism.SEMANTICS, Mechanism.REGISTER_ALLOCATION), Risk.HIGH),
        ("switch-cfg-shape", "Change an equivalent switch/if CFG with case proof", (Mechanism.SEMANTICS,), Risk.HIGH),
        ("statement-order", "Reorder independent statements inside one basic block", (Mechanism.SCHEDULING,), Risk.MEDIUM),
        ("compound-assignment", "Change compound versus binary assignment with pure lvalue proof", (Mechanism.SEMANTICS, Mechanism.SCHEDULING), Risk.MEDIUM),
        ("pointer-index-shape", "Change array indexing versus bounded pointer induction", (Mechanism.TYPES, Mechanism.REGISTER_ALLOCATION), Risk.HIGH),
    ]
    return Registry(Transformation(name, description, ("kmc-gcc-2.7.2", "gcc-2.7.x", "ido-5.x", "ido-7.1"),
                                   mechanisms, risk,
                                   ("same observable side effects", "no volatile access change",
                                    "no undefined behavior introduced"),
                                   (source,), "move only the diagnosed residual class")
                    for name, description, mechanisms, risk in families)
