"""Stage-level profiles of a run: where the time, CPU, I/O, memory and builds go.

``Profiler(out).stage(name, image)`` measures one stage and appends a record to
``<out>/profile.jsonl``:

* ``wall_s``; ``python_cpu_s`` (this process); ``child_cpu_s`` (reaped children: tools and forked
  workers, from ``RUSAGE_CHILDREN``);
* ``io_wait_s`` (this process's delay-accounted block I/O wait, when the kernel keeps it);
  ``read_bytes`` / ``write_bytes`` (this process, ``/proc/self/io``) and ``child_block_io_bytes``
  (children's block reads and writes, 512-byte units from rusage);
* ``peak_rss_mb`` (this process's high-water mark so far);
* ``tools``: per tool family, invocations, wall and CPU seconds (and measured peak RSS when the run
  measures it), this process and its forked workers together;
* ``builds``: builds requested, distinct objects and distinct source texts among them, cache hits
  and misses, and the deduplication rate (1 − distinct objects / builds requested);
* ``gain``: what the stage produced, filled in by the caller.

Forked workers write their counters to the stage's usage folder (``safety.flush_usage``) before
they exit; the stage adds them up.
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import time
from contextlib import contextmanager
from pathlib import Path


def _io() -> dict:
    out = {}
    try:
        for line in Path("/proc/self/io").read_text().splitlines():
            key, _, value = line.partition(":")
            if key in ("read_bytes", "write_bytes"):
                out[key] = int(value)
    except OSError:
        pass
    return out


def _io_wait_ticks() -> int | None:
    try:
        fields = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
        return int(fields[39])          # field 42: delayacct_blkio_ticks
    except (OSError, IndexError, ValueError):
        return None


def _snapshot() -> dict:
    own, children = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
    return {"time": time.monotonic(), "own_cpu": own.ru_utime + own.ru_stime,
            "child_cpu": children.ru_utime + children.ru_stime,
            "child_blocks": children.ru_inblock + children.ru_oublock, "own_rss_kb": own.ru_maxrss,
            "io": _io(), "io_wait": _io_wait_ticks()}


def _tools_delta(before: dict, after: dict) -> dict:
    out = {}
    for family, entry in after.items():
        prior = before.get(family, {})
        count = entry["count"] - prior.get("count", 0)
        if count <= 0:
            continue
        out[family] = {"count": count, "wall_s": round(entry["wall_s"] - prior.get("wall_s", 0.0), 3),
                       "cpu_s": round(entry["cpu_s"] - prior.get("cpu_s", 0.0), 3)}
        if "peak_rss_mb" in entry:
            out[family]["peak_rss_mb"] = round(entry["peak_rss_mb"], 1)
    return out


class Profiler:
    def __init__(self, out: Path):
        self.out = Path(out)
        self.path = self.out / "profile.jsonl"
        self.records: list[dict] = []

    @contextmanager
    def stage(self, name: str, image: str = ""):
        from . import safety
        from .match import pipeline
        record: dict = {"stage": name, "image": image, "gain": {}}
        folder = self.out / "usage" / f"{len(self.records):04d}-{name}"
        folder.mkdir(parents=True, exist_ok=True)
        previous_dir = os.environ.get("N64DK_USAGE_DIR")
        os.environ["N64DK_USAGE_DIR"] = str(folder)      # forked workers report here
        tools_before = json.loads(json.dumps(safety.TOOL_USAGE))
        builds_before = pipeline.build_counters()
        before = _snapshot()
        try:
            yield record
        finally:
            after = _snapshot()
            if previous_dir is None:
                os.environ.pop("N64DK_USAGE_DIR", None)
            else:
                os.environ["N64DK_USAGE_DIR"] = previous_dir
            tools = _tools_delta(tools_before, safety.TOOL_USAGE)
            builds_after = pipeline.build_counters()
            requested = builds_after["requested"] - builds_before["requested"]
            hits = builds_after["hits"] - builds_before["hits"]
            misses = builds_after["misses"] - builds_before["misses"]
            objects = set(builds_after["object_keys"]) - set(builds_before["object_keys"])
            sources = set(builds_after["source_texts"]) - set(builds_before["source_texts"])
            for report in sorted(folder.glob("*.json")):     # forked workers' counters
                try:
                    worker = json.loads(report.read_text())
                except (OSError, ValueError):
                    continue
                for family, entry in worker.get("tools", {}).items():
                    total = tools.setdefault(family, {"count": 0, "wall_s": 0.0, "cpu_s": 0.0})
                    total["count"] += entry["count"]
                    total["wall_s"] = round(total["wall_s"] + entry["wall_s"], 3)
                    total["cpu_s"] = round(total["cpu_s"] + entry["cpu_s"], 3)
                counters = worker.get("builds") or {}
                requested += counters.get("requested", 0)
                hits += counters.get("hits", 0)
                misses += counters.get("misses", 0)
                objects.update(counters.get("object_keys", []))
                sources.update(counters.get("source_texts", []))
            shutil.rmtree(folder, ignore_errors=True)
            ticks = (after["io_wait"] - before["io_wait"]) if after["io_wait"] is not None and \
                before["io_wait"] is not None else None
            record.update({
                "wall_s": round(after["time"] - before["time"], 2),
                "python_cpu_s": round(after["own_cpu"] - before["own_cpu"], 2),
                "child_cpu_s": round(after["child_cpu"] - before["child_cpu"], 2),
                "io_wait_s": None if ticks is None else round(ticks / os.sysconf("SC_CLK_TCK"), 2),
                "read_bytes": after["io"].get("read_bytes", 0) - before["io"].get("read_bytes", 0),
                "write_bytes": after["io"].get("write_bytes", 0) - before["io"].get("write_bytes", 0),
                "child_block_io_bytes": 512 * (after["child_blocks"] - before["child_blocks"]),
                "peak_rss_mb": round(after["own_rss_kb"] / 1024, 1),
                "tools": tools,
                "tool_invocations": sum(entry["count"] for entry in tools.values()),
                "builds": {"requested": requested, "distinct_objects": len(objects), "distinct_sources": len(sources),
                           "cache_hits": hits, "cache_misses": misses,
                           "dedup_rate": round(1 - len(objects) / requested, 3) if requested else None},
            })
            self.records.append(record)
            with self.path.open("a") as sink:
                sink.write(json.dumps(record, sort_keys=True) + "\n")

    def summary(self) -> dict:
        """Totals by stage name over the run's images."""
        out: dict = {}
        for record in self.records:
            total = out.setdefault(record["stage"], {"wall_s": 0.0, "python_cpu_s": 0.0, "child_cpu_s": 0.0,
                                                     "tool_invocations": 0, "builds_requested": 0,
                                                     "distinct_objects": 0})
            for key in ("wall_s", "python_cpu_s", "child_cpu_s", "tool_invocations"):
                total[key] = round(total[key] + (record.get(key) or 0), 2)
            total["builds_requested"] += record["builds"]["requested"]
            total["distinct_objects"] += record["builds"]["distinct_objects"]
        return out
