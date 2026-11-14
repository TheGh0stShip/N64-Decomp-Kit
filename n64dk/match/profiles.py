"""Versioned, open-set compiler/assembler/linker probe profiles.

Profiles are learned from explicitly supplied fixture observations.  The core ships probe
sources but no guessed signatures: a compiler is classified only when the caller provides
reproducible expected observations and the winning profile clears both distance and margin
thresholds.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


PROBE_SOURCES: dict[str, str] = {
    "move": "int f(int x) { int y = x; return y; }\n",
    "signed-width": "int f(short *p) { return *p + 1; }\n",
    "unsigned-width": "unsigned f(unsigned short *p) { return *p + 1; }\n",
    "switch": "int f(int x) { switch (x) { case 0:return 3; case 4:return 7; default:return 9; } }\n",
    "loop-call": "extern void g(int); void f(int n) { int i; for (i=0;i<n;i++) g(i); }\n",
    "float-literal": "float f(float x) { return x * 0.5f + 1.0f; }\n",
    "double-literal": "double f(double x) { return x * 0.5 + 1.0; }\n",
    "aggregate": "typedef struct { int a; short b; char c; } S; int f(S *p) { return p->a+p->b+p->c; }\n",
}


@dataclass(frozen=True)
class ComponentProfile:
    profile_id: str
    component: str
    family: str
    version: str
    observations: tuple[tuple[str, str], ...]
    evidence: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, profile_id: str, value: Mapping) -> "ComponentProfile":
        component = value["component"]
        if component not in ("compiler", "assembler", "linker"):
            raise ValueError(f"invalid toolchain component {component}")
        observations = tuple(sorted((str(k), str(v))
                                    for k, v in value.get("observations", {}).items()))
        unknown = {probe for probe, _ in observations if probe not in PROBE_SOURCES}
        if unknown:
            raise ValueError(f"unknown probes: {sorted(unknown)}")
        return cls(profile_id, component, value["family"], value["version"],
                   observations, tuple(value.get("evidence", ())))


@dataclass(frozen=True)
class ProfileDecision:
    profile_id: str | None
    component: str
    distance: float | None
    margin: float | None
    compared: int
    abstained: bool
    reason: str
    ranking: tuple[tuple[str, float, int], ...]


class ProfileRegistry:
    def __init__(self, profiles=()):
        self.profiles = tuple(profiles)

    @classmethod
    def from_mapping(cls, data: Mapping) -> "ProfileRegistry":
        rows = [ComponentProfile.from_mapping(name, value)
                for name, value in data.get("profiles", {}).items()]
        return cls(rows)

    def classify(self, component: str, observations: Mapping[str, str], *,
                 min_probes: int = 3, max_distance: float = 0.20,
                 min_margin: float = 0.15) -> ProfileDecision:
        ranking = []
        for profile in self.profiles:
            if profile.component != component:
                continue
            expected = dict(profile.observations)
            common = sorted(set(expected) & set(observations))
            if not common:
                continue
            distance = sum(expected[key] != observations[key] for key in common) / len(common)
            ranking.append((profile.profile_id, distance, len(common)))
        ranking.sort(key=lambda row: (row[1], -row[2], row[0]))
        if not ranking:
            return ProfileDecision(None, component, None, None, 0, True,
                                   "no profile shares an observed probe", ())
        winner = ranking[0]
        runner_distance = ranking[1][1] if len(ranking) > 1 else 1.0
        margin = runner_distance - winner[1]
        if winner[2] < min_probes:
            reason = f"only {winner[2]} shared probes; need {min_probes}"
        elif winner[1] > max_distance:
            reason = f"best normalized distance {winner[1]:.3f} exceeds {max_distance:.3f}"
        elif len(ranking) > 1 and margin < min_margin:
            reason = f"winner margin {margin:.3f} is below {min_margin:.3f}"
        else:
            return ProfileDecision(winner[0], component, winner[1], margin, winner[2],
                                   False, "accepted", tuple(ranking))
        return ProfileDecision(None, component, winner[1], margin, winner[2], True,
                               reason, tuple(ranking))
