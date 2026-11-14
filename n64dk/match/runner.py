"""Isolated, cache-backed execution of a :class:`ProjectAdapter` work unit."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import signal
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from ..project import OwnedSpan, ProjectAdapter, WorkUnit
from .cache import ContentCache
from .campaign import Campaign, CampaignResult, OracleObservation
from .diff import diff
from .experiments import ExperimentLedger
from .fingerprint import BuildClosure, ToolchainFingerprint, sha256_file
from .residual import ResidualSignature, classify


class RunnerError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExecutionLimits:
    """Hard bounds applied to every compiler invocation."""

    timeout_seconds: float = 120.0
    max_output_bytes: int = 8 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")


def _run_bounded(command: list[str], workspace: Path, environment: dict[str, str],
                 limits: ExecutionLimits) -> tuple[int, bytes, int]:
    """Run a build in its own process group with disk-backed bounded diagnostics."""
    started = time.monotonic_ns()
    output_path = workspace / ".n64dk-build.log"
    with output_path.open("w+b") as output:
        process = subprocess.Popen(command, cwd=workspace, env=environment,
                                   stdout=output, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        deadline = time.monotonic() + limits.timeout_seconds
        exceeded_output = False
        while process.poll() is None:
            if output.tell() > limits.max_output_bytes:
                exceeded_output = True
                break
            if time.monotonic() >= deadline:
                break
            time.sleep(0.05)
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            output.flush()
            output.seek(0, os.SEEK_END)
            size = output.tell()
            output.seek(max(0, size - limits.max_output_bytes))
            tail = output.read(limits.max_output_bytes)
            elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
            reason = (f"build output exceeded {limits.max_output_bytes} bytes"
                      if exceeded_output else
                      f"build timed out after {limits.timeout_seconds:g}s")
            raise RunnerError(
                f"{reason} ({elapsed_ms} ms):\n{tail.decode(errors='replace')}"
            )
        returncode = process.returncode
        output.flush()
        output.seek(0, os.SEEK_END)
        size = output.tell()
        output.seek(max(0, size - limits.max_output_bytes))
        tail = output.read(limits.max_output_bytes)
    return returncode, tail, (time.monotonic_ns() - started) // 1_000_000


def _span_key(span: OwnedSpan) -> str:
    return json.dumps(asdict(span), sort_keys=True, separators=(",", ":"))


def _encode_spans(spans) -> bytes:
    payload = {_span_key(span): base64.b64encode(data).decode("ascii")
               for span, data in spans.items()}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _decode_spans(payload: bytes) -> dict[str, bytes]:
    return {key: base64.b64decode(value) for key, value in json.loads(payload).items()}


@dataclass(frozen=True)
class RunSummary:
    result: CampaignResult
    closure: BuildClosure
    toolchain: ToolchainFingerprint
    verification: dict | None = None

    def as_dict(self) -> dict:
        return {"result": self.result.as_dict(), "closure": asdict(self.closure),
                "closure_digest": self.closure.digest,
                "toolchain": asdict(self.toolchain),
                "toolchain_digest": self.toolchain.digest,
                "verification": self.verification}


class UnitRunner:
    def __init__(self, adapter: ProjectAdapter, state_root: str | Path,
                 limits: ExecutionLimits | None = None):
        self.adapter = adapter
        self.state_root = Path(state_root).expanduser().resolve()
        self.cache = ContentCache(self.state_root / "cache")
        self.ledger = ExperimentLedger(self.state_root / "experiments.sqlite")
        self.campaign = Campaign(self.cache, self.ledger)
        self.limits = limits or ExecutionLimits()

    def close(self) -> None:
        self.ledger.close()

    def _unit(self, unit_id: str) -> WorkUnit:
        rows = [unit for unit in self.adapter.discover_units() if unit.unit_id == unit_id]
        if len(rows) != 1:
            raise RunnerError(f"expected exactly one unit named {unit_id}, found {len(rows)}")
        return rows[0]

    def evaluate(self, unit_id: str, transform_id: str = "baseline",
                 hypothesis: str = "establish exact owned-section baseline",
                 parent_id: str | None = None,
                 independent_verify: bool = False,
                 candidate_source: bytes | str | None = None) -> RunSummary:
        unit = self._unit(unit_id)
        environment = self.adapter.build_environment(unit)
        allowed = self.adapter.allowed_environment(unit)
        undeclared = set(environment) - set(allowed)
        if undeclared:
            raise RunnerError("build environment contains unhashed keys: "
                              + ", ".join(sorted(undeclared)))
        tool_files = dict(self.adapter.toolchain_files(unit))
        toolchain = ToolchainFingerprint.create(
            unit.toolchain_profile, tool_files, "mips-n64",
            unit.flags, environment, allowed,
        )
        command = self.adapter.build_command(unit, Path("."))
        input_files = dict(self.adapter.input_files(unit))
        resolved_inputs = {Path(path).resolve() for path in input_files.values()}
        if unit.source.resolve() not in resolved_inputs:
            raise RunnerError("input closure must include the unit's exact source file")
        targets = {span: self.adapter.target_span_bytes(unit, span) for span in unit.spans}
        for span, target in targets.items():
            if len(target) != span.size:
                raise RunnerError("target extraction length differs from owned span size")
        closure = BuildClosure.create(
            self.adapter.adapter_id, self.adapter.adapter_version, unit.unit_id,
            toolchain.digest, input_files, command, environment,
            self.adapter.oracle_policy(unit), allowed,
            ownership={"spans": [asdict(span) for span in unit.spans],
                       "unit_metadata": unit.metadata,
                       "targets": [hashlib.sha256(targets[span]).hexdigest()
                                   for span in unit.spans]},
        )

        def check_inputs() -> None:
            try:
                for label, expected in closure.inputs:
                    if sha256_file(Path(input_files[label])) != expected:
                        raise RunnerError(f"input changed during evaluation: {label}")
                current = ToolchainFingerprint.create(
                    unit.toolchain_profile, tool_files, "mips-n64", unit.flags,
                    environment, allowed,
                )
                if current.digest != toolchain.digest:
                    raise RunnerError("toolchain changed during evaluation")
            except OSError as error:
                raise RunnerError("declared build input became unavailable") from error

        if candidate_source is None:
            candidate_bytes = unit.source.read_bytes()
        elif isinstance(candidate_source, str):
            candidate_bytes = candidate_source.encode()
        else:
            candidate_bytes = bytes(candidate_source)
        check_inputs()

        try:
            relative_source = unit.source.resolve().relative_to(
                self.adapter.project_root().resolve())
        except ValueError as error:
            raise RunnerError("unit source must be inside the adapter project root") from error

        def produce() -> bytes:
            check_inputs()
            with tempfile.TemporaryDirectory(prefix="n64dk-unit-") as name:
                workspace = Path(name)
                self.adapter.prepare_workspace(unit, workspace)
                check_inputs()
                staged_source = workspace / relative_source
                if not staged_source.is_file():
                    raise RunnerError(
                        "adapter did not stage the unit source at its project-relative path: "
                        f"{relative_source}"
                    )
                staged_source.write_bytes(candidate_bytes)
                returncode, output, _ = _run_bounded(
                    command, workspace, dict(environment), self.limits)
                if returncode:
                    raise RunnerError(
                        f"build failed with status {returncode}:\n"
                        + output.decode(errors="replace")
                    )
                built = self.adapter.built_span_bytes(unit, workspace)
                check_inputs()
                if set(built) != set(unit.spans):
                    raise RunnerError("adapter did not return exactly the unit's owned spans")
                return _encode_spans(built)

        def observe(artifact: bytes) -> OracleObservation:
            check_inputs()
            built = _decode_spans(artifact)
            reports, total_score, exact = [], 0, True
            for span in unit.spans:
                candidate = built[_span_key(span)]
                target = targets[span]
                if span.kind == "code" and len(candidate) % 4 == 0 and len(target) % 4 == 0:
                    report = diff(candidate, target, span.start)
                    signature = ResidualSignature.from_report(report)
                    diagnoses = [item.as_dict() for item in classify(signature)]
                    score = report.score
                    detail = report.as_dict()
                else:
                    mismatches = sum(a != b for a, b in zip(candidate, target))
                    mismatches += abs(len(candidate) - len(target))
                    score = mismatches
                    diagnoses = []
                    detail = {"score": score, "compiled_size": len(candidate),
                              "target_size": len(target), "byte_mismatches": mismatches}
                span_exact = candidate == target and len(candidate) == span.size
                exact &= span_exact
                total_score += score
                reports.append({"span": asdict(span), "exact": span_exact,
                                "score": score, "diagnoses": diagnoses, "diff": detail})
            return OracleObservation(exact, total_score, {"spans": reports}, artifact)

        result = self.campaign.evaluate(
            closure, candidate_bytes, produce, observe,
            transform_id, hypothesis, parent_id,
        )
        verification = None
        if independent_verify:
            fresh_artifact = produce()  # intentionally bypass the content cache
            fresh = observe(fresh_artifact)
            cached_artifact = self.cache.get(result.artifact_digest)
            verification = {
                "independent": True,
                "exact": fresh.exact,
                "same_artifact": hashlib.sha256(fresh_artifact).digest()
                                 == hashlib.sha256(cached_artifact).digest(),
                "score": fresh.score,
                "residual": fresh.residual,
            }
            verification["accepted"] = bool(result.experiment.exact and fresh.exact
                                               and verification["same_artifact"])
            verification["scope"] = "owned-span byte reproducibility only"
            verification["production_approved"] = False
            verification["unverified_obligations"] = [
                "complete dependency closure and toolchain qualification",
                "source provenance and absence of output rewriting",
                "relocation, alignment and shared-range obligations",
            ]
            verification["verification_id"] = self.ledger.record_verification(
                result.experiment.experiment_id, verification,
            )
        return RunSummary(result, closure, toolchain, verification)
