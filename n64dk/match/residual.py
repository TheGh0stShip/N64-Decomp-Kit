"""Interpretable residual signatures and mechanism-first diagnoses."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import Enum

from .diff import Report


class Mechanism(str, Enum):
    EXACT = "exact"
    BOUNDARY = "boundary-or-ownership"
    TOOLCHAIN = "toolchain-or-flags"
    SEMANTICS = "semantics-or-cfg"
    TYPES = "types-width-signedness-alias"
    REGISTER_ALLOCATION = "register-allocation"
    RELOAD = "reload-spill-frame"
    SCHEDULING = "scheduling-delay-slot"
    LITERAL_OWNERSHIP = "literal-pool-or-section-ownership"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ResidualSignature:
    compiled_size: int
    target_size: int
    counts: tuple[tuple[str, int], ...]
    register_swap: tuple[tuple[str, str], ...] = ()
    section_mismatches: tuple[str, ...] = ()
    ownership_conflict: bool = False
    toolchain_conflict: bool = False
    cfg_mismatch: bool = False
    load_width_mismatches: int = 0
    extension_mismatches: int = 0
    stack_memory_mismatches: int = 0

    @classmethod
    def from_report(cls, report: Report, **evidence) -> "ResidualSignature":
        return cls(report.compiled_size, report.target_size,
                   tuple(sorted(report.counts.items())),
                   tuple(sorted((report.register_swap or {}).items())), **evidence)

    @property
    def count_map(self) -> Counter:
        return Counter(dict(self.counts))

    def as_dict(self) -> dict:
        value = asdict(self)
        value["counts"] = dict(self.counts)
        value["register_swap"] = dict(self.register_swap)
        return value


@dataclass(frozen=True)
class Diagnosis:
    mechanism: Mechanism
    confidence: float
    evidence: tuple[str, ...]
    next_experiments: tuple[str, ...]

    def as_dict(self) -> dict:
        out = asdict(self)
        out["mechanism"] = self.mechanism.value
        return out


def classify(signature: ResidualSignature) -> list[Diagnosis]:
    """Return ranked, auditable diagnoses; abstain instead of forcing a label."""
    counts = signature.count_map
    diagnoses: list[Diagnosis] = []
    if (signature.compiled_size == signature.target_size and not counts
            and not signature.section_mismatches):
        return [Diagnosis(Mechanism.EXACT, 1.0, ("no owned byte differs",), ())]

    if signature.ownership_conflict:
        diagnoses.append(Diagnosis(
            Mechanism.BOUNDARY, 0.99,
            ("ownership intervals conflict or are unresolved",),
            ("resolve image/range ownership before source search",)))
    elif counts["size"] or signature.compiled_size != signature.target_size:
        diagnoses.append(Diagnosis(
            Mechanism.BOUNDARY, 0.62,
            (f"compiled size {signature.compiled_size} != target {signature.target_size}",),
            ("verify start/end and false catalogue splits", "compare CFG and call set")))

    if signature.toolchain_conflict:
        diagnoses.append(Diagnosis(
            Mechanism.TOOLCHAIN, 0.98, ("toolchain constraints contradict the target",),
            ("run the per-object fingerprint probe matrix",)))

    if signature.section_mismatches and not counts.get("instruction"):
        diagnoses.append(Diagnosis(
            Mechanism.LITERAL_OWNERSHIP, 0.88,
            ("text is structurally close while owned data sections differ",
             *signature.section_mismatches),
            ("verify literal/jump-table owner and absolute section base",)))

    if signature.cfg_mismatch or counts["instruction"]:
        confidence = 0.84 if signature.cfg_mismatch else 0.63
        diagnoses.append(Diagnosis(
            Mechanism.SEMANTICS, confidence,
            ("control-flow/data-flow or instruction selection differs",),
            ("reconstruct caller/callee/global semantics", "compare loop and switch shape")))

    type_evidence = signature.load_width_mismatches + signature.extension_mismatches
    if type_evidence:
        diagnoses.append(Diagnosis(
            Mechanism.TYPES, min(0.98, 0.7 + 0.04 * type_evidence),
            (f"{signature.load_width_mismatches} load/store width differences",
             f"{signature.extension_mismatches} sign/zero-extension differences"),
            ("test local/field width and signedness with range proof",)))

    structural = sum(counts[k] for k in ("instruction", "size", "immediate", "branch"))
    if signature.register_swap and structural == 0:
        diagnoses.append(Diagnosis(
            Mechanism.REGISTER_ALLOCATION, 0.97,
            ("all residuals form a consistent hard-register bijection",),
            ("inspect .flow/.lreg/.greg priorities", "test declaration/lifetime levers")))

    if signature.stack_memory_mismatches:
        diagnoses.append(Diagnosis(
            Mechanism.RELOAD, min(0.95, 0.68 + 0.04 * signature.stack_memory_mismatches),
            (f"{signature.stack_memory_mismatches} stack spill/reload differences",),
            ("inspect reload dump and pseudo live ranges",)))

    schedule_count = counts["scheduling"] + counts["hazard-nop"] + counts["operand-order"]
    if schedule_count and not counts["instruction"]:
        diagnoses.append(Diagnosis(
            Mechanism.SCHEDULING, min(0.96, 0.66 + 0.03 * schedule_count),
            (f"{schedule_count} ordering/delay-slot residuals",),
            ("inspect sched1/sched2/reorg dependencies", "test one source-order lever")))

    if not diagnoses:
        diagnoses.append(Diagnosis(
            Mechanism.UNKNOWN, 0.25, ("available evidence is not discriminating",),
            ("collect owned sections, compiler fingerprint and pass dumps",)))
    return sorted(diagnoses, key=lambda item: item.confidence, reverse=True)
