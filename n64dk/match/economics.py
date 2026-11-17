"""Search economics: spend builds where they have been returning matches.

The variant search (``iterate.descend``) is the expensive part of a run: on one title of the
sixteen measured, a single region whose compiler the kit could not reproduce took 77% of all
builds and returned nothing.  The kit cannot know in advance which part of an image will pay; it
can watch.  This governor keeps, per *stratum* (the recipe a function is built under and how far
its first draft is from the target), what the search has cost and what it has returned, and:

* **plateau** — once a stratum has had ``window`` searches and ``min_builds`` builds with no
  yield (no function made exact, none brought from further than ``near`` to within it), further
  functions of that stratum are not searched; they are drafted and built as before, and their
  case records ``iterate-skipped`` with the stratum's numbers.  Every ``probe``-th function of a
  plateaued stratum is still searched, so a stratum that starts paying is noticed;
* **expected value** — ``ranking`` orders strata by yield per build, for reports and for the
  order of a later pass.

Nothing is decided from a classification of the target (an "unknown compiler" verdict alone
skips nothing): only from builds this run made.  The state is kept beside the case store so a
second pass starts with what the first one learned.  Off unless ``--search-economics`` is given.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

WINDOW = 24          # searches in a stratum before it may be judged
MIN_BUILDS = 600     # ...and builds spent on them
PROBE = 8            # every this-many-th function of a plateaued stratum is still searched
NEAR = 10


def score_band(score: int | None) -> str:
    if score is None:
        return "no-score"
    return "<=10" if score <= 10 else "<=40" if score <= 40 else "<=100" if score <= 100 else ">100"


class Governor:
    def __init__(self, path: Path | None = None, window: int = WINDOW, min_builds: int = MIN_BUILDS,
                 probe: int = PROBE, near: int = NEAR, active: bool = True):
        """``active=False`` observes only: ``allow`` always allows, and every search's prediction
        (the stratum's yield so far, whether an active governor would have skipped it) and its
        outcome go to ``<path stem>.observations.jsonl`` for offline evaluation of policies."""
        self.active = active
        self.path = Path(path) if path else None
        self.observations = self.path.with_suffix(".observations.jsonl") if self.path else None
        self.window, self.min_builds, self.probe, self.near = window, min_builds, probe, near
        self.lock = threading.Lock()
        self.strata: dict[str, dict] = {}
        if self.path and self.path.is_file():
            try:
                self.strata = json.loads(self.path.read_text()).get("strata", {})
            except (OSError, ValueError):
                self.strata = {}

    @staticmethod
    def stratum(recipe: str, start_score: int | None) -> str:
        return f"{recipe} | first draft {score_band(start_score)}"

    def _row(self, key: str) -> dict:
        return self.strata.setdefault(key, {"searches": 0, "builds": 0, "exact": 0, "to_near": 0, "improved": 0,
                                            "skipped": 0, "probes": 0, "builds_saved_estimate": 0})

    def plateaued(self, key: str) -> bool:
        row = self.strata.get(key)
        return bool(row and row["searches"] >= self.window and row["builds"] >= self.min_builds
                    and row["exact"] + row["to_near"] == 0)

    def predict(self, key: str) -> dict:
        """What the governor expects of a search in stratum ``key`` before it runs."""
        with self.lock:
            row = self._row(key)
            yielded = row["exact"] + row["to_near"]
            return {"stratum": key, "searches_before": row["searches"], "builds_before": row["builds"],
                    "yield_per_1000_builds": round(1000 * yielded / row["builds"], 3) if row["builds"] else None,
                    "would_skip": self.plateaued(key)}

    def observe(self, prediction: dict, start: int | None, final: int | None, builds: int, exact: bool,
                seconds: float) -> None:
        """One search's prediction and outcome, appended to the observations file."""
        if self.observations is None:
            return
        line = json.dumps({**prediction, "active": self.active, "builds": builds, "start": start, "final": final,
                           "exact": bool(exact), "improved": final is not None and start is not None and final < start,
                           "seconds": round(seconds, 2)}, sort_keys=True)
        with self.lock, self.observations.open("a") as sink:
            sink.write(line + "\n")

    def allow(self, key: str) -> tuple[bool, str]:
        """Whether to search a function of stratum ``key``; the reason when not.  An observing
        governor always allows."""
        if not self.active:
            return True, ""
        with self.lock:
            row = self._row(key)
            if not self.plateaued(key):
                return True, ""
            seen = row["skipped"] + row["probes"]
            if seen % self.probe == self.probe - 1:
                row["probes"] += 1
                return True, "probe of a plateaued stratum"
            row["skipped"] += 1
            row["builds_saved_estimate"] += round(row["builds"] / max(1, row["searches"]))
            return False, (f"plateau: {row['searches']} searches and {row['builds']} builds in this stratum "
                           "returned no exact or near result")

    def record(self, key: str, start: int | None, final: int | None, builds: int, exact: bool) -> None:
        with self.lock:
            row = self._row(key)
            row["searches"] += 1
            row["builds"] += builds
            row["exact"] += int(bool(exact))
            if start is not None and final is not None:
                row["improved"] += int(final < start)
                row["to_near"] += int(start > self.near >= final and not exact)

    def ranking(self) -> list[dict]:
        out = []
        for key, row in self.strata.items():
            yielded = row["exact"] + row["to_near"]
            out.append({"stratum": key, **row, "yield_per_1000_builds":
                        round(1000 * yielded / row["builds"], 3) if row["builds"] else None,
                        "plateaued": self.plateaued(key)})
        return sorted(out, key=lambda row: (-(row["yield_per_1000_builds"] or 0), -row["builds"]))

    def save(self) -> None:
        if self.path is None:
            return
        with self.lock:
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps({"strata": self.strata, "ranking": self.ranking()}, indent=1))
            temporary.replace(self.path)
