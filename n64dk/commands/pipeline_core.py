"""Project-agnostic diagnostics for the evidence-driven matching pipeline."""
from __future__ import annotations

import os
import json
from dataclasses import asdict
from pathlib import Path

from ..cli import command
from ..match import diff
from ..match.fingerprint import ToolchainFingerprint
from ..match.gcc27dump import explain as explain_gcc27
from ..match.provenance import classify_source, credit_bytes
from ..match.residual import ResidualSignature, classify
from ..match.workbench import Workbench
from ..match.transforms import Edit, Proposal, default_registry
from ..research import audit as audit_research
from ..research import plan_rules
from ..handoff import inspect_handoff
from ..research_inventory import inventory as inventory_research
from ..adapter import load as load_adapter
from ..match.runner import ExecutionLimits, UnitRunner
from ..match.jobs import JobConfig, JobStore, MatchJob
from ..match.profiles import PROBE_SOURCES, ProfileRegistry


def _role_path(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise ValueError("toolchain files use ROLE=PATH")
    role, path = value.split("=", 1)
    return role, Path(path)


@command("toolchain-fingerprint", "Hash the complete compiler/assembler/linker identity")
def toolchain_fingerprint(args):
    files = dict(_role_path(value) for value in args.file)
    fingerprint = ToolchainFingerprint.create(args.profile, files, args.target,
                                              args.flag, os.environ, args.env)
    return {"digest": fingerprint.digest, "profile": fingerprint.profile,
            "target": fingerprint.target, "files": [vars(item) for item in fingerprint.files],
            "flags": list(fingerprint.flags), "environment": dict(fingerprint.environment)}


def _fingerprint_args(p):
    p.add_argument("--profile", required=True)
    p.add_argument("--target", default="mips-n64")
    p.add_argument("--file", action="append", default=[], required=True, help="ROLE=PATH")
    p.add_argument("--flag", action="append", default=[])
    p.add_argument("--env", action="append", default=[], help="environment key allowed into identity")


toolchain_fingerprint.arguments = _fingerprint_args


@command("match-diagnose", "Classify an exact-match residual before choosing a source lever")
def match_diagnose(args):
    compiled = Path(args.compiled).read_bytes()
    target = Path(args.target).read_bytes()
    report = diff.diff(compiled, target, args.vram)
    signature = ResidualSignature.from_report(
        report,
        section_mismatches=tuple(args.section_mismatch),
        ownership_conflict=args.ownership_conflict,
        toolchain_conflict=args.toolchain_conflict,
        cfg_mismatch=args.cfg_mismatch,
        load_width_mismatches=args.load_width_mismatches,
        extension_mismatches=args.extension_mismatches,
        stack_memory_mismatches=args.stack_memory_mismatches,
    )
    return {"residual": signature.as_dict(),
            "diagnoses": [item.as_dict() for item in classify(signature)],
            "diff": report.as_dict()}


def _diagnose_args(p):
    p.add_argument("compiled")
    p.add_argument("target")
    p.add_argument("--vram", type=lambda value: int(value, 0), default=0x80000000)
    p.add_argument("--section-mismatch", action="append", default=[])
    p.add_argument("--ownership-conflict", action="store_true")
    p.add_argument("--toolchain-conflict", action="store_true")
    p.add_argument("--cfg-mismatch", action="store_true")
    p.add_argument("--load-width-mismatches", type=int, default=0)
    p.add_argument("--extension-mismatches", type=int, default=0)
    p.add_argument("--stack-memory-mismatches", type=int, default=0)


match_diagnose.arguments = _diagnose_args


@command("provenance-audit", "Reject assembly escapes, fake code (the [match] code rules) and unproven assembly "
                             "progress credit")
def provenance_audit(args):
    from ..match.coderules import Profile
    evidence = tuple(args.handwritten_evidence)
    profile = Profile.load(args.project)
    rows = []
    for name in args.source:
        path = Path(name)
        result = classify_source(path, evidence if path.suffix.lower() in (".s", ".asm") else (), profile)
        rows.append({"source": str(path), "verdict": result.verdict.value,
                     "creditable": result.creditable, "reasons": result.reasons,
                     "evidence": result.evidence,
                     "credited_bytes": credit_bytes(args.size, result, args.exact,
                                                    args.ownership_verified,
                                                    args.normalizer_specific)})
    return {"results": rows, "all_creditable": all(row["creditable"] for row in rows)}


def _provenance_args(p):
    p.add_argument("source", nargs="+")
    p.add_argument("--handwritten-evidence", action="append", default=[])
    p.add_argument("--size", type=int, default=0)
    p.add_argument("--exact", action="store_true")
    p.add_argument("--ownership-verified", action="store_true")
    p.add_argument("--normalizer-specific", action="store_true")
    p.add_argument("--project", help="project directory whose n64dk.toml [code_rules] profile applies")


provenance_audit.arguments = _provenance_args


@command("gcc27-regalloc", "Explain GCC 2.7.x pseudo priorities and hard-register assignments")
def gcc27_regalloc(args):
    local = Path(args.local_dump).read_text(errors="replace")
    global_dump = Path(args.global_dump).read_text(errors="replace") if args.global_dump else ""
    return explain_gcc27(local, global_dump)


def _gcc27_args(p):
    p.add_argument("local_dump", help="the compiler's .lreg dump")
    p.add_argument("--global-dump", help="the compiler's .greg dump")


gcc27_regalloc.arguments = _gcc27_args


@command("research-audit", "Audit a source index and finding ledger before implementation")
def research_audit(args):
    return audit_research(args.sources, args.findings)


def _research_args(p):
    p.add_argument("sources", help="source-index TSV")
    p.add_argument("findings", help="research-ledger TSV")


research_audit.arguments = _research_args


@command("research-inventory", "Inventory and hash collected research without inflating round counts")
def research_inventory(args):
    return inventory_research(args.roots)


def _inventory_args(p):
    p.add_argument("roots", nargs="+")


research_inventory.arguments = _inventory_args


@command("research-plan", "Connect proposed compiler rules to findings and required reproduction probes")
def research_plan(args):
    return plan_rules(args.catalog, args.findings, args.dispositions)


def _research_plan_args(p):
    p.add_argument("catalog")
    p.add_argument("findings")
    p.add_argument("--dispositions", help="reviewed rule dispositions TSV")


research_plan.arguments = _research_plan_args


@command("handoff-inspect", "Inventory fenced research artifacts without executing supplied code")
def handoff_inspect(args):
    return inspect_handoff(args.handoff)


def _handoff_args(p):
    p.add_argument("handoff")


handoff_inspect.arguments = _handoff_args


@command("workbench-diagnose", "Run the N64 Decomp Workbench mechanism view through n64dk")
def workbench_diagnose(args):
    workbench = Workbench.discover(args.executable)
    result = workbench.diagnose_dumps(args.target, args.candidate, args.function)
    return {"workbench": workbench.version(), "diagnosis": result}


def _workbench_args(p):
    p.add_argument("target", help="target GNU objdump text")
    p.add_argument("candidate", help="candidate GNU objdump text")
    p.add_argument("--function")
    p.add_argument("--executable", help="decomp-workbench executable")


workbench_diagnose.arguments = _workbench_args


@command("transform-list", "List evidence-bounded source transformation families")
def transform_list(args):
    rows = default_registry().describe()
    if args.mechanism:
        rows = [row for row in rows
                if args.mechanism in tuple(value.value if hasattr(value, "value") else value
                                           for value in row["mechanisms"])]
    return {"transformations": rows, "count": len(rows)}


def _transform_list_args(p):
    p.add_argument("--mechanism", help="filter by residual mechanism name")


transform_list.arguments = _transform_list_args


@command("transform-apply", "Apply a digest-pinned, reversible transformation proposal")
def transform_apply(args):
    from ..outputs import file_output
    source_path = Path(args.source)
    output_path = file_output(args.output, "output")
    if source_path.resolve() == output_path.resolve():
        raise ValueError("refusing an in-place transformation; use a separate output path")
    payload = json.loads(Path(args.proposal).read_text())
    proposal = Proposal(
        transform_id=payload["transform_id"],
        source_digest=payload["source_digest"],
        compiler_profile=payload["compiler_profile"],
        edits=tuple(Edit(int(item["start"]), int(item["end"]), item["replacement"])
                    for item in payload["edits"]),
        semantic_evidence=tuple(payload.get("semantic_evidence", ())),
        hypothesis=payload.get("hypothesis", ""),
    )
    applied = default_registry().apply(
        source_path.read_text(), proposal,
        max_edits=args.max_edits,
        max_changed_characters=args.max_changed_characters,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(applied.source)
    inverse_path = Path(args.inverse) if args.inverse else output_path.with_suffix(output_path.suffix + ".inverse.json")
    inverse_path.write_text(json.dumps({
        "transform_id": applied.inverse.transform_id,
        "source_digest": applied.inverse.source_digest,
        "compiler_profile": applied.inverse.compiler_profile,
        "edits": [{"start": edit.start, "end": edit.end, "replacement": edit.replacement}
                  for edit in applied.inverse.edits],
        "semantic_evidence": list(applied.inverse.semantic_evidence),
        "hypothesis": applied.inverse.hypothesis,
    }, indent=2, sort_keys=True) + "\n")
    return {"output": str(output_path), "inverse": str(inverse_path),
            "changed_characters": applied.changed_characters}


def _transform_apply_args(p):
    p.add_argument("source")
    p.add_argument("proposal", help="JSON proposal containing byte-independent character offsets")
    p.add_argument("output", help="new candidate path; in-place edits are refused")
    p.add_argument("--inverse", help="path for the generated inverse proposal")
    p.add_argument("--max-edits", type=int, default=4)
    p.add_argument("--max-changed-characters", type=int, default=4096)


transform_apply.arguments = _transform_apply_args


@command("campaign-run", "Build and prove one project-adapter unit through the exact cached oracle")
def campaign_run(args):
    adapter = load_adapter(args.project)
    runner = UnitRunner(adapter, args.state_root, ExecutionLimits(
        args.timeout, args.max_output_bytes))
    try:
        return runner.evaluate(args.unit, args.transform_id, args.hypothesis,
                               args.parent_id, args.independent_verify).as_dict()
    finally:
        runner.close()


def _campaign_run_args(p):
    p.add_argument("project", help="PROJECT.toml with an explicit module:factory adapter")
    p.add_argument("--unit", required=True)
    p.add_argument("--state-root", default=".n64dk/campaign")
    p.add_argument("--transform-id", default="baseline")
    p.add_argument("--hypothesis", default="establish exact owned-section baseline")
    p.add_argument("--parent-id")
    p.add_argument("--independent-verify", action="store_true",
                   help="bypass the cache and rebuild again before accepting an exact result")
    p.add_argument("--timeout", type=float, default=120.0)
    p.add_argument("--max-output-bytes", type=int, default=8 * 1024 * 1024)


campaign_run.arguments = _campaign_run_args


@command("match-job-run", "Create or resume a persistent autonomous source-matching job")
def match_job_run(args):
    adapter = load_adapter(args.project)
    runner = UnitRunner(adapter, args.state_root, ExecutionLimits(
        args.timeout, args.max_output_bytes))
    store = JobStore(Path(args.state_root) / "jobs.sqlite")
    job = MatchJob(runner, store)
    try:
        job_id = args.job_id or job.create(JobConfig(
            args.unit, args.budget, args.beam_width, args.candidates_per_parent))
        result = job.run(job_id)
        result["job_id"] = job_id
        if args.verify and result["exact"]:
            result["verification"] = job.verify_best(job_id)
        return result
    finally:
        store.close()
        runner.close()


def _match_job_run_args(p):
    p.add_argument("project", help="PROJECT.toml with an explicit module:factory adapter")
    p.add_argument("--unit", required=True)
    p.add_argument("--state-root", default=".n64dk/match-jobs")
    p.add_argument("--job-id", help="resume an existing job instead of creating one")
    p.add_argument("--budget", type=int, default=200, help="maximum retained candidates")
    p.add_argument("--beam-width", type=int, default=12)
    p.add_argument("--candidates-per-parent", type=int, default=32)
    p.add_argument("--verify", action="store_true",
                   help="independently rebuild an exact candidate outside the cache")
    p.add_argument("--timeout", type=float, default=120.0,
                   help="hard timeout in seconds for each build")
    p.add_argument("--max-output-bytes", type=int, default=8 * 1024 * 1024,
                   help="kill a build that emits more diagnostic output")


match_job_run.arguments = _match_job_run_args


@command("match-job-status", "Inspect a persistent matching job without running builds")
def match_job_status(args):
    store = JobStore(Path(args.state_root) / "jobs.sqlite")
    try:
        result = store.summary(args.job_id)
        if args.candidates:
            result["candidates"] = [asdict(item) for item in store.candidates(args.job_id)]
        return result
    finally:
        store.close()


def _match_job_status_args(p):
    p.add_argument("job_id")
    p.add_argument("--state-root", default=".n64dk/match-jobs")
    p.add_argument("--candidates", action="store_true")


match_job_status.arguments = _match_job_status_args


@command("match-job-export", "Export a job candidate and evidence without editing project source")
def match_job_export(args):
    state_root = Path(args.state_root)
    store = JobStore(state_root / "jobs.sqlite")
    try:
        candidates = store.candidates(args.job_id)
        if args.candidate_id:
            selected = [item for item in candidates if item.candidate_id == args.candidate_id]
        else:
            selected = sorted((item for item in candidates if item.status == "evaluated"),
                              key=lambda item: (not item.exact,
                                                item.score if item.score is not None else 2**63,
                                                item.created_ns))[:1]
        if not selected:
            raise ValueError("no exportable candidate found")
        candidate = selected[0]
        from ..match.cache import ContentCache
        cache = ContentCache(state_root / "cache")
        source_bytes = cache.get(candidate.source_digest)
        if args.output == "-":
            return {"output": "stdout", "source": source_bytes.decode("utf-8", "replace"),
                    "evidence": {"job": store.summary(args.job_id), "candidate": asdict(candidate),
                                 "proof_grade": False},
                    "candidate_id": candidate.candidate_id, "exact": candidate.exact}
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(source_bytes)
        evidence = output.with_suffix(output.suffix + ".evidence.json")
        evidence.write_text(json.dumps({
            "job": store.summary(args.job_id),
            "candidate": asdict(candidate),
            "proof_grade": False,
            "notice": "Exported candidates require independent verification and project review.",
        }, indent=2, sort_keys=True) + "\n")
        return {"output": str(output), "evidence": str(evidence),
                "candidate_id": candidate.candidate_id, "exact": candidate.exact}
    finally:
        store.close()


def _match_job_export_args(p):
    p.add_argument("job_id")
    p.add_argument("output")
    p.add_argument("--state-root", default=".n64dk/match-jobs")
    p.add_argument("--candidate-id")


match_job_export.arguments = _match_job_export_args


@command("profile-classify", "Classify a compiler/assembler/linker probe set with open-set abstention")
def profile_classify(args):
    registry = ProfileRegistry.from_mapping(json.loads(Path(args.registry).read_text()))
    observations = json.loads(Path(args.observations).read_text())
    decision = registry.classify(args.component, observations,
                                 min_probes=args.min_probes,
                                 max_distance=args.max_distance,
                                 min_margin=args.min_margin)
    return {"decision": vars(decision), "available_probes": PROBE_SOURCES}


def _profile_classify_args(p):
    p.add_argument("registry", help="JSON fixture-backed profile registry")
    p.add_argument("observations", help="JSON mapping probe id to observed signature")
    p.add_argument("--component", choices=("compiler", "assembler", "linker"), required=True)
    p.add_argument("--min-probes", type=int, default=3)
    p.add_argument("--max-distance", type=float, default=0.20)
    p.add_argument("--min-margin", type=float, default=0.15)


profile_classify.arguments = _profile_classify_args
