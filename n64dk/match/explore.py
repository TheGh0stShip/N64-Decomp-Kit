"""Bounded residual-guided multi-round source exploration."""
from __future__ import annotations

import difflib
import hashlib
import json
import re

from .hypotheses import suggest
from .provenance import Verdict, scan_c
from .session import MatchSession, SessionCandidate, SessionStore, frontier, residual_delta
from .typed_explore import (call_chain_variants, lifetime_graph, lifetime_variants,
                            narrowing_variants, prototype_variants, residual_offsets, source_shape)


_DECL = re.compile(r"(?m)^(\s*)(s8|u8|s16|u16|s32|u32|int|unsigned int|float|double)\s+([A-Za-z_]\w*)\s*=\s*([^;]+);$")
_ASSIGN = re.compile(r"(?m)^(\s*)([A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)\s*=\s*\2\s*([+\-*|&^])\s*([^;]+);$")
_COMPOUND = re.compile(r"(?m)^(\s*)([A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)\s*([+\-*|&^])=\s*([^;]+);$")
_COMMUTE = re.compile(r"\b([A-Za-z_]\w*(?:->\w+|\.\w+)?)\s*([+*|&^])\s*([A-Za-z_]\w*(?:->\w+|\.\w+)?)\b")


def _replace_each(pattern, source: str, replacement, family: str, limit: int) -> list[dict]:
    out = []
    for index, found in enumerate(pattern.finditer(source)):
        if len(out) >= limit:
            break
        text = replacement(found)
        candidate = source[:found.start()] + text + source[found.end():]
        if candidate != source and scan_c(candidate).verdict != Verdict.FORBIDDEN:
            out.append({"label": f"{family}-{index + 1}", "source": candidate, "family": family})
    return out


def variants(source: str, counts: dict[str, int], limit: int,
             compiler_family: str = "any") -> list[dict]:
    """Generate small ordinary-C edits selected by residual evidence."""
    proposed = []
    if counts.get("register") or counts.get("scheduling"):
        proposed += _replace_each(_ASSIGN, source,
            lambda m: f"{m[1]}{m[2]} {m[3]}= {m[4]};", "compound-assignment", limit)
        proposed += _replace_each(_COMPOUND, source,
            lambda m: f"{m[1]}{m[2]} = {m[2]} {m[3]} {m[4]};", "expanded-assignment", limit)
        if compiler_family != "gcc":
            proposed += _replace_each(_DECL, source,
                lambda m: f"{m[1]}{m[2]} {m[3]};\n{m[1]}{m[3]} = {m[4]};",
                "declaration-lifetime-separation", limit)
    if counts.get("operand-order") or (counts.get("register") and compiler_family != "gcc"):
        proposed += _replace_each(_COMMUTE, source,
            lambda m: f"{m[3]} {m[2]} {m[1]}", "commutative-operand-order", limit)
    unique = {}
    for item in proposed:
        digest = hashlib.sha256(item["source"].encode()).hexdigest()
        unique.setdefault(digest, item)
    return list(unique.values())[:limit]


def _signature(session_id: str, parent: SessionCandidate, family: str, candidates: list[dict]) -> str:
    def opcode(value):
        parts = str(value or "").split(None, 1)
        return parts[0] if parts else "missing"
    value = {"pipeline": parent.pipeline, "flags": parent.flags, "family": family,
             "residual": parent.counts,
             "transitions": [(row.get("kind"), opcode(row.get("compiled")), opcode(row.get("retail")))
                             for row in parent.outcome.get("diff", {}).get("entries", [])],
             "source_shapes": sorted(source_shape(item["source"]) for item in candidates)}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def explore(store: SessionStore, session: MatchSession, session_id: str, jobs: int = 4,
            rounds: int = 4, variants_per_round: int = 12, stop_on_exact: bool = True,
            target_window: tuple[int, int] | None = None,
            dimensions: set[str] | None = None) -> dict:
    context = store.context(session_id)
    preflight = context.get("layout_preflight")
    if not preflight or not preflight.get("ok"):
        raise ValueError("residual exploration requires a recorded successful image-layout preflight")
    baseline = store.best(session_id)
    baseline_score = baseline.score
    unique_sources = set()
    unique_objects = set()
    cache_reused = 0
    executed_rounds = 0
    stagnant_rounds = 0
    round_reports = []
    disproved = set()
    window_rejected = 0
    dimensions = dimensions or {"spelling", "prototype", "lifetime", "narrowing", "control-flow", "flags"}
    previous_frontier = {item.candidate_id for item in frontier(store.candidates(session_id))}

    for round_number in range(1, max(0, rounds) + 1):
        executed_rounds = round_number
        before_objects = set(unique_objects)
        before_frontier = previous_frontier
        experiments = []
        remaining = max(1, variants_per_round)
        parents = frontier(store.candidates(session_id))
        for parent in parents:
            if remaining <= 0:
                break
            source = store.cache.get(parent.source_digest).decode()
            compiler_family = ("ido" if parent.pipeline.startswith("ido") else
                               "gcc" if parent.pipeline.startswith(("kmc", "gcc", "sn")) else "any")
            generated = variants(source, parent.counts, remaining, compiler_family) if "spelling" in dimensions else []
            graph = lifetime_graph(parent.outcome, context)
            ownership = graph.get("call_result_ownership", {})
            if "lifetime" in dimensions and ownership.get("transfers"):
                generated = call_chain_variants(source, ownership, remaining) + generated
            if "lifetime" in dimensions and (parent.counts.get("register") or parent.counts.get("scheduling")):
                generated += lifetime_variants(source, graph, remaining - len(generated))
            if "narrowing" in dimensions and parent.counts.get("instruction"):
                generated += narrowing_variants(source, remaining - len(generated))
            residual_entries = parent.outcome.get("diff", {}).get("entries", [])
            call_residual = bool(ownership.get("transfers")) or any(
                str(entry.get(side) or "").split(None, 1)[0] in {"jal", "jalr", "bal"}
                for entry in residual_entries for side in ("compiled", "retail"))
            if "prototype" in dimensions and (compiler_family != "gcc" or call_residual):
                declarations = re.findall(r"(?m)^\s*(?:extern\s+)?[\w *]+\s+(func_[0-9A-Fa-f]{8})\s*\([^;]*\)\s*;", source)
                for symbol in declarations[:2]:
                    generated += prototype_variants(source, symbol, ["void", "s16", "u16", "s32"],
                                                    max(0, remaining - len(generated)))
            if "control-flow" in dimensions and (parent.counts.get("branch") or parent.counts.get("instruction")):
                from .controlflow import variants as control_variants
                generated += control_variants(source, max(0, remaining - len(generated)))
            unique_generated = {}
            for item in generated:
                item.setdefault("family", "control-flow" if "form" in item else "typed")
                unique_generated.setdefault(hashlib.sha256(item["source"].encode()).hexdigest(), item)
            generated = list(unique_generated.values())[:remaining]
            by_family: dict[str, list[dict]] = {}
            for item in generated:
                by_family.setdefault(item.pop("family"), []).append(item)
            # Compiler flags are a bounded residual discriminator, not an open-ended sweep.
            if "flags" in dimensions and round_number == 1 and (parent.counts.get("instruction") or parent.counts.get("scheduling")):
                by_family["optimization-pressure"] = []
            for family, items in by_family.items():
                signature = _signature(session_id, parent, family, items)
                if store.experiment_seen_global(signature):
                    continue
                proposal = {"parent": parent.candidate_id,
                            "hypothesis": f"residual-guided {family}",
                            "variants": items or [{}]}
                if family == "optimization-pressure":
                    proposal["flag_variants"] = [["-fno-gcse"], ["-fno-expensive-optimizations"]]
                result = session.try_proposal(session_id, proposal, jobs, False)
                results = result["results"]
                if target_window:
                    low, high = target_window
                    parent_outside = {value for value in residual_offsets(parent.outcome)
                                      if not low <= value < high}
                    for item in results:
                        retained = store.get(session_id, item["candidate_id"])
                        child_outside = {value for value in residual_offsets(retained.outcome)
                                         if not low <= value < high} if retained else set()
                        if child_outside != parent_outside:
                            store.db.execute("UPDATE session_candidates SET status='rejected-window' "
                                             "WHERE session_id=? AND candidate_id=?",
                                             (session_id, item["candidate_id"]))
                            item["window_status"] = "rejected: disturbed frozen residual region"
                            window_rejected += 1
                        else:
                            item["window_status"] = "preserved"
                    store.db.commit()
                for item in results:
                    unique_sources.add(item["source_digest"])
                    digest = item.get("outcome", {}).get("sha256_text")
                    if not digest:
                        retained = store.get(session_id, item["candidate_id"])
                        digest = retained.outcome.get("sha256_text") if retained else None
                    if digest:
                        unique_objects.add(digest)
                    cache_reused += bool(item.get("cache_hit"))
                deltas = [item["delta"]["score"] for item in results
                          if item["delta"].get("score") is not None]
                best_delta = min(deltas) if deltas else None
                object_digests = {store.get(session_id, item["candidate_id"]).outcome.get("sha256_text")
                                  for item in results if store.get(session_id, item["candidate_id"])}
                object_digests.discard(None)
                conclusion = ("improved frontier" if best_delta is not None and best_delta < 0 else
                              "source forms compiled identically" if len(object_digests) <= 1 else
                              "no residual improvement")
                if best_delta is None or best_delta >= 0:
                    disproved.add(family)
                payload = {"result_ids": [item["candidate_id"] for item in results],
                           "rejected": result["rejected"], "object_digests": sorted(object_digests)}
                store.record_experiment(session_id, signature, round_number, family,
                                        parent.candidate_id, len(items) or 2, len(object_digests),
                                        best_delta, conclusion, payload)
                experiments.append({"family": family, "variants": len(items) or 2,
                                    "unique_objects": len(object_digests),
                                    "best_delta": best_delta, "conclusion": conclusion})
                remaining -= len(items) or 2
                if stop_on_exact and store.best(session_id).exact:
                    break
            if stop_on_exact and store.best(session_id).exact:
                break
        current = frontier(store.candidates(session_id))
        previous_frontier = {item.candidate_id for item in current}
        changed = previous_frontier != before_frontier
        new_objects = len(unique_objects - before_objects)
        stagnant_rounds = 0 if changed else stagnant_rounds + 1
        round_reports.append({"round": round_number, "experiments": experiments,
                              "frontier_changed": changed, "new_unique_objects": new_objects,
                              "best_score": store.best(session_id).score})
        if store.best(session_id).exact or not experiments or stagnant_rounds >= 2:
            break

    best = store.best(session_id)
    invariant = best.counts if stagnant_rounds >= 2 or not round_reports or not round_reports[-1]["experiments"] else {}
    next_steps = [item["try"] for item in suggest(best.counts)]
    if invariant:
        next_steps += ["translation-unit context", "compiler recipe", "original typedef or macro expansion"]
    family_reports = []
    for family in sorted({item["family"] for report in round_reports for item in report["experiments"]}):
        items = [item for report in round_reports for item in report["experiments"] if item["family"] == family]
        family_reports.append({"family": family, "trials": sum(item["variants"] for item in items),
            "unique_objects": sum(item["unique_objects"] for item in items),
            "best_delta": min((item["best_delta"] for item in items if item["best_delta"] is not None), default=None),
            "conclusions": sorted({item["conclusion"] for item in items}),
            "disproved": family in disproved})
    return {"session_id": session_id, "rounds": executed_rounds,
            "source_variants": len(unique_sources), "unique_objects": len(unique_objects),
            "cache_reused": cache_reused, "exact": best.exact,
            "baseline_score": baseline_score, "best_score": best.score,
            "stagnated": bool(invariant), "invariant_residual": invariant,
            "disproved_hypothesis_classes": sorted(disproved),
            "target_window": ({"start": target_window[0], "end": target_window[1],
                               "rejected": window_rejected} if target_window else None),
            "dimensions": sorted(dimensions),
            "routing": {"observed": {"register_only": bool(best.counts.get("register") and
                not best.counts.get("instruction")), "call_barrier": lifetime_graph(best.outcome, context)["call_barrier"],
                "signed_narrowing": lifetime_graph(best.outcome, context)["signed_narrowing"]},
                "priority": ["call-result ownership", "prototype", "carrier lifetime",
                             "declaration scope", "translation-unit context"]},
            "next_discriminators": list(dict.fromkeys(next_steps)),
            "frontier": [item.summary(False) for item in frontier(store.candidates(session_id))],
            "family_reports": family_reports, "round_reports": round_reports}


def explain(store: SessionStore, session_id: str, from_id: str, to_id: str) -> dict:
    left, right = store.get(session_id, from_id), store.get(session_id, to_id)
    if left is None or right is None:
        raise ValueError("both candidate IDs must belong to this session")
    left_source = store.cache.get(left.source_digest).decode().splitlines()
    right_source = store.cache.get(right.source_digest).decode().splitlines()
    delta = residual_delta(left, right)
    improved = {key: -value for key, value in delta["counts"].items() if value < 0}
    worsened = {key: value for key, value in delta["counts"].items() if value > 0}
    same_object = bool(left.outcome.get("sha256_text") and
                       left.outcome.get("sha256_text") == right.outcome.get("sha256_text"))
    return {"session_id": session_id, "from": left.summary(False), "to": right.summary(False),
            "residual_delta": delta, "improved": improved, "worsened": worsened,
            "compiled_identically": same_object,
            "source_diff": list(difflib.unified_diff(left_source, right_source,
                                                      fromfile=left.candidate_id, tofile=right.candidate_id,
                                                      lineterm="")),
            "hypothesis": right.hypothesis,
            "conclusion": "refuted" if same_object or (delta["score"] is not None and delta["score"] >= 0)
                          else "supported",
            "next_discriminators": [item["try"] for item in suggest(right.counts)]}
