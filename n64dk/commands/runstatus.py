"""``decompile-status RUN_DIR``: the rounds of a ``decompile-run`` and what is left, read-only.

Reads ``rounds.jsonl``, ``solver/invocation.json``, ``solver/observations.json`` and the case
store, which is opened read-only (``CaseStore(readonly=True)``: immutable when no write-ahead log
is present), so inspecting a run, finished or still running, writes nothing anywhere."""
from __future__ import annotations

import json
from pathlib import Path

from ..cli import command
from ..match import resolve as resolvemod
from ..match import solver


def round_line(record: dict) -> str:
    """``Round N [image]: <sieve> +k exact, ...``"""
    parts = []
    for name, row in (record.get("techniques") or {}).items():
        parts.append(f"{name} +{row.get('exact', 0)} exact ({row.get('cases', 0)} cases, {row.get('builds', 0)} builds"
                     + (f", {row['model_calls']} model calls" if row.get("model_calls") else "") + ")")
    declare = (record.get("cascade") or {}).get("declare") or {}
    if declare.get("ran"):
        parts.append(f"declare +{declare.get('promoted', 0)} exact ({declare.get('new_names', 0)} new declarations)")
    neighbours = (record.get("cascade") or {}).get("neighbours") or {}
    if neighbours.get("marked"):
        parts.append(f"neighbours: {neighbours['marked']} cases with new evidence")
    for name, row in (record.get("skipped") or {}).items():
        parts.append(f"{name} skipped for {row.get('cases')} cases ({row.get('reason')})")
    gains = record.get("gains") or {}
    return (f"Round {record.get('round')} [{record.get('image')}]: " + ("; ".join(parts) or record.get("sieve", "-"))
            + f" | new exact {gains.get('new_exact', 0)}, awaiting declarations "
              f"{gains.get('awaiting_declarations', 0):+d}, evidence {gains.get('evidence', 0)}")


def status(run: Path, image: str | None = None, show: int = 5) -> dict:
    run = Path(run)
    log = solver.RoundsLog(run / "rounds.jsonl")
    records = log.read()
    session = log.latest_session()
    current = [r for r in records if r.get("session") == session and (image is None or r.get("image") == image)]
    invocation = {}
    path = run / "solver" / "invocation.json"
    if path.is_file():
        invocation = json.loads(path.read_text())
    mode = solver.policy(invocation.get("effort"))
    observations = solver.Observations(run / "solver" / "observations.json")     # read, never saved here
    ceiling = invocation.get("search_ceiling")
    ceiling = resolvemod.SEARCH_CEILING if ceiling is None else ceiling
    store = resolvemod.CaseStore(run / "state", readonly=True)
    try:
        cases = [c for c in store.all() if image is None or c.image == image]
    finally:
        store.close()
    stretches: dict[str, solver.Stretches] = {}
    for case in cases:
        if case.image not in stretches:
            saved = run / "solver" / f"round1_{case.image}.json"
            info = None
            if saved.is_file():
                try:
                    info = (json.loads(saved.read_text()).get("resolve") or {}).get("unknown_toolchain")
                except ValueError:
                    info = None
            stretches[case.image] = solver.Stretches(info)
    groups: dict[str, dict] = {}
    for case in cases:
        if case.status not in solver.UNRESOLVED:
            continue
        decision = solver.decide(case, mode, observations, unknown=stretches[case.image], ceiling=ceiling,
                                 model=bool(invocation.get("refine_command")))
        group = groups.setdefault(decision.cause, {"functions": 0, "bytes": 0, "next": {}, "cases": []})
        group["functions"] += 1
        group["bytes"] += case.size
        key = decision.technique or "stop"
        group["next"][key] = group["next"].get(key, 0) + 1
        group["cases"].append((case.best_score if case.best_score is not None else 1 << 30, case.size, case.name,
                               decision.technique or decision.reason))
    for group in groups.values():
        group["cases"].sort()
        group["examples"] = [{"name": n, "score": None if s == 1 << 30 else s, "size": z, "next": t}
                             for s, z, n, t in group.pop("cases")[:show]]
    return {"run": str(run), "session": session, "mode": mode.name,
            "rounds": [round_line(r) for r in current if r.get("kind") == "round"],
            "stops": [{"image": r.get("image"), "after_round": r.get("after_round"), "reason": r.get("reason")}
                      for r in current if r.get("kind") == "stop"],
            "credit": solver.credit(cases),
            "remaining_by_cause": dict(sorted(groups.items(), key=lambda kv: -kv[1]["bytes"]))}


def render(result: dict) -> str:
    lines = [f"run {result['run']} (effort {result['mode']}, session {result['session']})", ""]
    lines += result["rounds"] or ["no completed round"]
    lines += [f"Stopped [{s['image']}] after round {s['after_round']}: {s['reason']}" for s in result["stops"]]
    credit = result["credit"]
    lines += ["", f"exact C {credit['exact_c']} ({credit['exact_c_bytes']} bytes); awaiting declarations "
                  f"{credit['awaiting_declarations']}; hand-written assembly {credit['handwritten_assembly']}; "
                  f"unresolved {credit['unresolved']}", "", "remaining queue by primary cause:"]
    for cause, group in result["remaining_by_cause"].items():
        nexts = ", ".join(f"{k} {v}" for k, v in sorted(group["next"].items(), key=lambda kv: -kv[1]))
        lines.append(f"  {cause}: {group['functions']} functions, {group['bytes']} bytes; next: {nexts}")
        for example in group["examples"]:
            lines.append(f"    {example['name']} size {example['size']} score {example['score']}: {example['next']}")
    return "\n".join(lines)


@command("decompile-status", "Read-only rounds table and remaining queue by primary cause of a decompile-run")
def decompile_status(args):
    result = status(Path(args.run_dir), getattr(args, "image", None), getattr(args, "show", 5))
    if getattr(args, "format", "text") == "text":
        print(render(result))
        return 0
    return result


def _args(p):
    p.add_argument("run_dir", help="the --out directory of a decompile-run")
    p.add_argument("--image", help="only this image")
    p.add_argument("--show", type=int, default=5, help="example functions per cause")


decompile_status.arguments = _args
