"""``match-iterate``: one call that searches types, signedness and value lifetimes."""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import tempfile
import time
from pathlib import Path

from ..cli import command
from ..match import iterate as itermod
from ..match.engine import match_source
from ..match.pipeline import split_flags
from ..match.layout import from_inventory, preflight
from ..match.registry import SessionRegistry, standard_store
from ..match.score import score as community_score
from ..match.session import SessionCandidate, SessionStore
from .match import _common, _session_context, _setup


@command("match-iterate", "Search local types, signedness and value lifetimes for one function in a single call")
def match_iterate(args):
    started = time.monotonic()
    cfg, target, syms, _files = _setup(args)
    source = Path(args.source).resolve()
    text = source.read_text()
    name = args.function
    if name is None:
        found = [n for n in re.findall(r"(?m)^[A-Za-z_][\w \*]*?\b(\w+)\s*\([^;{}]*\)\s*\{", text)
                 if n not in {"if", "while", "for", "switch"}]
        if not found:
            raise SystemExit("no function definition found; pass --function")
        name = found[-1]
    spec = split_flags(shlex.split(args.flags), args.pipeline)
    layout_check = None
    inventory_row = getattr(args, "_resolved_inventory_row", None)
    if inventory_row is not None:
        layout_check = preflight(args.rom, from_inventory(inventory_row), strict_entry=True)
        if not layout_check.get("ok") and not args.allow_uncertain_boundary:
            raise ValueError("match-iterate requires a strict-entry-valid target; "
                             + ", ".join(layout_check.get("warnings", [])))
    elif not args.allow_uncertain_boundary:
        raise ValueError("target is absent or ambiguous in project inventory; pass "
                         "--allow-uncertain-boundary only for an explicitly reviewed standalone range")
    # Candidates are built in private folders.  Headers that sit next to the source are copied
    # there by name; adding the source directory itself as an include root would make the
    # pipeline hash every file in it for every build (seconds per build in a large scratch tree).
    local_headers = [(source.parent / header) for header in re.findall(r'(?m)^\s*#\s*include\s+"([^"]+)"', text)
                     if (source.parent / header).is_file()
                     and not any((Path(root) / header).is_file() for root in cfg.include)]
    families = tuple(f for f in args.families.split(",") if f)
    unknown = set(families) - set(itermod.FAMILIES)
    if unknown:
        raise SystemExit(f"unknown families {sorted(unknown)}; choose from {', '.join(itermod.FAMILIES)}")
    target_offset = args.addr - target.delta
    if not 0 <= target_offset <= len(target.rom) - args.size:
        raise ValueError("resolved target range is outside the selected image")
    target_text = target.rom[target_offset:target_offset + args.size]
    observations = []
    with tempfile.TemporaryDirectory(prefix="n64dk-iterate-") as work:
        def evaluate(candidate: str) -> itermod.Evaluation:
            folder = Path(work) / hashlib.sha256(candidate.encode()).hexdigest()[:16]
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / source.name
            path.write_text(candidate)
            for header in local_headers:
                copy = folder / header.relative_to(source.parent)
                copy.parent.mkdir(parents=True, exist_ok=True)
                copy.write_bytes(header.read_bytes())
            try:
                outcome = match_source(path, spec, cfg, target, args.addr, args.size, syms, folder, None)
            except Exception as error:
                return itermod.Evaluation(None, error=str(error)[-400:])
            if outcome.error or outcome.result is None:
                value = itermod.Evaluation(None, error=(outcome.error or "no comparison")[-400:])
                observations.append((candidate, value)); return value
            report = outcome.result.diff
            if report is None:
                value = itermod.Evaluation(0 if outcome.exact else 1, outcome.exact, None,
                                           rank_score=0 if outcome.exact else 1,
                                           object_digest=outcome.digest, outcome=outcome.as_dict())
            else:
                ranked = community_score(target_text, outcome.result.compiled_text[:args.size], args.addr)
                value = itermod.Evaluation(report.score, outcome.exact, report.as_dict(limit=4096),
                                           rank_score=ranked.total, object_digest=outcome.digest,
                                           outcome={**outcome.as_dict(), "community_score": ranked.as_dict()})
            observations.append((candidate, value)); return value
        result = itermod.descend(text, name, evaluate, families, args.rounds, args.jobs or 8,
                                 args.budget, args.per_round, args.beam, args.patience)
    final = result.pop("source", None)
    if final is not None and args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(final)
        result["written"] = args.out
    elif final is not None and args.print_source:
        result["source"] = final
    # Persist all observations and the sensitivity ledger in the standard session store so
    # future tranches and explorers do not repeat equivalent hypotheses.
    args.no_infer = False
    args.strict_entry = True
    context = _session_context(args, cfg, target, _files, source, spec, text.encode())
    context.update({"producer": "match-iterate", "function": name,
                    "layout_preflight": layout_check or context.get("layout_preflight")})
    store_root = Path(args.state_root).resolve() if args.state_root else standard_store(cfg.project)
    store = SessionStore(store_root)
    try:
        session_id = store.create(context)
        baseline_id = None
        seen = set()
        for index, (candidate, value) in enumerate(observations):
            source_bytes = candidate.encode(); source_digest = store.cache.put(source_bytes)
            candidate_id = hashlib.sha256(
                f"{session_id}:{source_digest}:{spec.pipeline}:{spec.flags}".encode()).hexdigest()[:24]
            if candidate_id in seen: continue
            seen.add(candidate_id)
            row = SessionCandidate(candidate_id, baseline_id if index else None, source_digest,
                "baseline" if index == 0 else f"iterate-{index}",
                "bounded type, signedness, expression, and lifetime iteration",
                spec.pipeline, tuple(spec.flags), "evaluated" if value.score is not None else "failed",
                value.exact, value.score, (value.report or {}).get("counts", {}),
                value.outcome or {}, value.error, time.time_ns())
            store.append(session_id, row)
            if baseline_id is None: baseline_id = candidate_id
        signature = hashlib.sha256(json.dumps({"target": context.get("target_text_sha256"),
            "source": context.get("source_sha256"), "families": families}, sort_keys=True).encode()).hexdigest()
        store.record_experiment(session_id, signature, 0, "match-iterate", baseline_id or "none",
                                len(observations), result.get("unique_objects", 0),
                                result.get("final_score", 0) - result.get("start_score", 0),
                                result.get("stopped_reason", "complete"),
                                {"sensitivity": result.get("sensitivity", []),
                                 "edit_path": result.get("edit_path", []),
                                 "semantic_review_required": result.get("semantic_review_required", False)})
        registry = SessionRegistry(cfg.project)
        try: registry.register(session_id, store_root, context,
                               hashlib.sha256((final or text).encode()).hexdigest(), "match-iterate")
        finally: registry.close()
    finally: store.close()
    artifact_root = Path(args.artifact_dir).resolve() if args.artifact_dir else (
        cfg.project / ".n64dk" / "match-iterate" / session_id)
    artifact_root.mkdir(parents=True, exist_ok=True)
    if final is not None:
        (artifact_root / "best.c").write_text(final)
    receipt = artifact_root / "report.json"
    result["function"] = name
    result["session_id"] = session_id
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result["target_preflight"] = layout_check
    result["artifacts"] = {"report": str(receipt), "best_source": str(artifact_root / "best.c")}
    # Keep the complete first-round causal table in the durable receipt.  Only the interactive
    # response is bounded; neutral edits are useful negative evidence and must not disappear.
    receipt.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    result["sensitivity"] = result.get("sensitivity", [])[:args.show]
    if args.summary_only:
        result = {key: value for key, value in result.items()
                  if key not in {"sensitivity", "steps", "edit_path", "target_preflight"}}
    return result


def _args(p):
    _common(p, rom_required=True)
    p.add_argument("source", help="candidate C file (never modified)")
    p.add_argument("--addr", type=lambda s: int(s, 0), required=True, help="function VRAM")
    p.add_argument("--size", type=lambda s: int(s, 0), required=True)
    p.add_argument("--function", help="function name (default: last definition in the file)")
    p.add_argument("--pipeline", default="kmc+builtin")
    p.add_argument("--flags", default="-O2 -G0 -mips3 -mgp32 -mfp32")
    p.add_argument("--families", default=",".join(itermod.FAMILIES))
    p.add_argument("--rounds", type=int, default=8)
    p.add_argument("--budget", type=int, default=400, help="maximum builds")
    p.add_argument("--per-round", type=int, default=160)
    p.add_argument("--beam", type=int, default=4)
    p.add_argument("--patience", type=int, default=2)
    p.add_argument("--show", type=int, default=15, help="sensitivity rows to print")
    p.add_argument("--state-root", help="session store (default: <project>/.n64dk/match-sessions)")
    p.add_argument("--artifact-dir", help="durable report and best-source directory")
    p.add_argument("--summary-only", action="store_true")
    p.add_argument("--allow-uncertain-boundary", action="store_true",
                   help="override mandatory project inventory and strict-entry validation")
    p.add_argument("--out", help="write the best source here")
    p.add_argument("--print-source", action="store_true")


match_iterate.arguments = _args
