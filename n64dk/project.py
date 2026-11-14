"""Stable project-adapter contracts for title-agnostic N64 tooling.

Adapters describe a project's immutable inputs and ownership model.  They do not
teach the core about a particular ROM layout, symbol prefix, or build system.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol, runtime_checkable


@dataclass(frozen=True, order=True)
class OwnedSpan:
    image: str
    section: str
    start: int
    size: int
    kind: str = "code"
    evidence: tuple[str, ...] = ()

    @property
    def end(self) -> int:
        return self.start + self.size

    def __post_init__(self) -> None:
        if self.start < 0 or self.size <= 0:
            raise ValueError("owned spans require a non-negative start and positive size")


@dataclass(frozen=True)
class WorkUnit:
    unit_id: str
    source: Path
    spans: tuple[OwnedSpan, ...]
    toolchain_profile: str
    flags: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict, compare=False, hash=False)

    def __post_init__(self) -> None:
        if not self.unit_id:
            raise ValueError("unit_id must not be empty")
        if not self.spans:
            raise ValueError("a work unit must own at least one span")
        by_image: dict[str, list[OwnedSpan]] = {}
        for span in self.spans:
            by_image.setdefault(span.image, []).append(span)
        for spans in by_image.values():
            ordered = sorted(spans, key=lambda span: span.start)
            for left, right in zip(ordered, ordered[1:]):
                if right.start < left.end:
                    raise ValueError(f"overlapping ownership in unit {self.unit_id}")


@runtime_checkable
class ProjectAdapter(Protocol):
    """Minimum interface implemented by a title-specific adapter."""

    adapter_id: str
    adapter_version: str

    def project_root(self) -> Path: ...

    def discover_units(self) -> list[WorkUnit]: ...

    def image_bytes(self, image: str) -> bytes: ...

    def target_span_bytes(self, unit: WorkUnit, span: OwnedSpan) -> bytes: ...

    def input_files(self, unit: WorkUnit) -> Mapping[str, Path]: ...

    def toolchain_files(self, unit: WorkUnit) -> Mapping[str, Path]: ...

    def allowed_environment(self, unit: WorkUnit) -> tuple[str, ...]: ...

    def oracle_policy(self, unit: WorkUnit) -> str: ...

    def prepare_workspace(self, unit: WorkUnit, workspace: Path) -> None: ...

    def build_command(self, unit: WorkUnit, workspace: Path) -> list[str]: ...

    def build_environment(self, unit: WorkUnit) -> dict[str, str]: ...

    def built_span_bytes(self, unit: WorkUnit, workspace: Path) -> Mapping[OwnedSpan, bytes]: ...
