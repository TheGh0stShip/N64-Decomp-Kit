"""Conservative resource planning for unattended compiler workloads.

Old compiler processes are small individually but a decompilation sweep starts several
interpreters and compiler children at once.  Letting every layer expand to ``cpu_count()`` can
exhaust memory and turn the machine's disk into swap.  This module gives commands one shared,
observable policy instead of independent guesses.

Explicitly setting ``N64DK_ALLOW_OVERSUBSCRIBE=1`` disables the safety ceiling.  It is deliberately
an environment opt-in rather than an ordinary default: unattended and batch commands remain safe
when copied to a machine with many cores and little RAM.
"""
from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path


DEFAULT_MAX_JOBS = 4
SMALL_MACHINE_MB = 12288      # below this much memory in all, the default ceiling is two jobs
SMALL_MACHINE_JOBS = 2
DEFAULT_RESERVE_MB = 2048
DEFAULT_JOB_MB = 512


@dataclass(frozen=True)
class MemorySnapshot:
    total_mb: int | None
    available_mb: int | None
    swap_total_mb: int | None
    swap_free_mb: int | None

    @property
    def swap_used_mb(self) -> int | None:
        if self.swap_total_mb is None or self.swap_free_mb is None:
            return None
        return max(0, self.swap_total_mb - self.swap_free_mb)


@dataclass(frozen=True)
class ResourcePlan:
    requested_jobs: int
    jobs: int
    cpu_count: int
    max_jobs: int
    reserve_mb: int
    memory_per_job_mb: int
    memory: MemorySnapshot
    oversubscribe: bool
    limited_by: tuple[str, ...]

    def as_dict(self) -> dict:
        value = asdict(self)
        value["memory"]["swap_used_mb"] = self.memory.swap_used_mb
        return value


def memory_snapshot(path: str | Path = "/proc/meminfo") -> MemorySnapshot:
    """Read Linux memory counters, returning unknown fields on other hosts."""
    values: dict[str, int] = {}
    try:
        for line in Path(path).read_text().splitlines():
            name, raw = line.split(":", 1)
            if name in {"MemTotal", "MemAvailable", "SwapTotal", "SwapFree"}:
                values[name] = int(raw.strip().split()[0]) // 1024
    except (OSError, ValueError):
        pass
    return MemorySnapshot(values.get("MemTotal"), values.get("MemAvailable"),
                          values.get("SwapTotal"), values.get("SwapFree"))


def _positive_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except ValueError:
        return default
    return value if value > 0 else default


def plan_jobs(requested: int | None = 0, *, snapshot: MemorySnapshot | None = None,
              max_jobs: int | None = None, reserve_mb: int | None = None,
              memory_per_job_mb: int | None = None) -> ResourcePlan:
    """Choose total compiler concurrency.

    ``requested`` of zero means all CPUs *before* safety limits.  Both implicit and explicit
    requests are capped unless ``N64DK_ALLOW_OVERSUBSCRIBE=1`` is set.  This avoids a misleading
    ``--jobs 16`` bypassing the protection while still leaving a deliberate escape hatch.
    """
    memory = snapshot or memory_snapshot()
    cpus = max(1, os.cpu_count() or 1)
    raw = cpus if not requested or requested < 1 else requested
    default = (SMALL_MACHINE_JOBS if memory.total_mb is not None and memory.total_mb < SMALL_MACHINE_MB
               else DEFAULT_MAX_JOBS)
    ceiling = max_jobs or _positive_env("N64DK_MAX_JOBS", default)
    reserve = reserve_mb or _positive_env("N64DK_MEMORY_RESERVE_MB", DEFAULT_RESERVE_MB)
    per_job = memory_per_job_mb or _positive_env("N64DK_MEMORY_PER_JOB_MB", DEFAULT_JOB_MB)
    oversubscribe = os.environ.get("N64DK_ALLOW_OVERSUBSCRIBE", "").lower() in {"1", "true", "yes"}
    jobs, reasons = max(1, raw), []
    if not oversubscribe and jobs > ceiling:
        jobs = ceiling
        reasons.append("safety-ceiling")
    if not oversubscribe and memory.available_mb is not None:
        capacity = max(1, (memory.available_mb - reserve) // per_job)
        if jobs > capacity:
            jobs = capacity
            reasons.append("available-memory")
    if jobs > cpus:
        jobs = cpus
        reasons.append("cpu-count")
    return ResourcePlan(raw, max(1, jobs), cpus, ceiling, reserve, per_job, memory,
                        oversubscribe, tuple(dict.fromkeys(reasons)))
