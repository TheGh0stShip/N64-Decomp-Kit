"""One-call cached build, exact oracle and experiment recording."""
from __future__ import annotations

import hashlib
import time
from dataclasses import asdict, dataclass
from typing import Callable

from .cache import ContentCache
from .experiments import Experiment, ExperimentLedger
from .fingerprint import BuildClosure


@dataclass(frozen=True)
class OracleObservation:
    exact: bool
    score: int | None
    residual: dict
    result: bytes = b""


@dataclass(frozen=True)
class CampaignResult:
    experiment: Experiment
    artifact_digest: str
    cache_hit: bool

    def as_dict(self) -> dict:
        return {"experiment": asdict(self.experiment),
                "artifact_digest": self.artifact_digest,
                "cache_hit": self.cache_hit}


class Campaign:
    def __init__(self, cache: ContentCache, ledger: ExperimentLedger):
        self.cache = cache
        self.ledger = ledger

    def evaluate(self, closure: BuildClosure, candidate_source: bytes,
                 producer: Callable[[], bytes], oracle: Callable[[bytes], OracleObservation],
                 transform_id: str, hypothesis: str,
                 parent_id: str | None = None) -> CampaignResult:
        candidate_digest = hashlib.sha256(candidate_source).hexdigest()
        cache_key = f"build:{closure.digest}:{candidate_digest}"
        started = time.monotonic_ns()
        artifact_digest, produced = self.cache.resolve(cache_key, producer)
        artifact = self.cache.get(artifact_digest)
        observation = oracle(artifact)
        result_digest = self.cache.put(observation.result) if observation.result else artifact_digest
        elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
        experiment = Experiment.create(
            closure.unit_id, closure.digest, candidate_digest, transform_id, hypothesis,
            result_digest, observation.exact, observation.score, observation.residual,
            int(elapsed_ms), parent_id,
        )
        self.ledger.append(experiment)
        return CampaignResult(experiment, artifact_digest, not produced)
