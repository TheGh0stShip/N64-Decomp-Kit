"""Historical observation indexing, querying, and residual clustering."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from ..cli import command
from ..match.inventory import build
from ..match.results import ResultIndex


def _index_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--roots", nargs="+", required=True)
    p.add_argument("--database", default=".n64dk/results.sqlite")
    p.add_argument("--refresh", action="store_true")


@command("result-index", "Index historical match JSON, logs and candidate sources with target validity")
def result_index(args):
    index = ResultIndex(args.database)
    try:
        return index.index(args.roots, build(args.project), args.refresh)
    finally:
        index.close()


result_index.arguments = _index_args


def _query_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--state-root")
    p.add_argument("--database", default=".n64dk/results.sqlite")
    p.add_argument("--function")
    p.add_argument("--max-score", type=int)
    p.add_argument("--exact-only", action="store_true")
    p.add_argument("--stale-mapping", action="store_true")
    p.add_argument("--missing-source", action="store_true")
    p.add_argument("--timeline", action="store_true")
    p.add_argument("--validity", choices=("valid_current_target", "valid_historical_target",
                                          "stale_image", "stale_mapping", "boundary_changed",
                                          "unknown_provenance"))
    p.add_argument("--remaining", action="store_true",
                   help="reserved compatibility selector; invalid targets remain excluded")
    p.add_argument("--not-in-manifest", action="store_true")
    p.add_argument("--same-residual")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--summary-only", action="store_true")


@command("result-query", "Query valid historical frontiers while excluding stale target observations")
def result_query(args):
    database = args.database
    if database == ".n64dk/results.sqlite":
        database = str(__import__("pathlib").Path(args.project).resolve() / database)
    index = ResultIndex(database)
    try:
        inventory = build(args.project)
        rows = index.query(args.function or args.same_residual, args.max_score, args.exact_only,
                           args.validity, args.stale_mapping, args.missing_source,
                           args.timeline, args.limit, args.project, inventory, args.not_in_manifest)
        if args.same_residual and rows:
            residual = rows[0]["residual"]
            rows = [row for row in index.query(max_score=args.max_score, limit=100000,
                                               project=args.project, inventory=inventory,
                                               not_in_manifest=args.not_in_manifest)
                    if row["residual"] == residual][:args.limit]
        rows = rows[args.offset:]
        result = {"count": len(rows), "observations": [] if args.summary_only else rows}
        if args.function:
            result["bracketed_target"] = index.brackets(args.function)
        return result
    finally:
        index.close()


result_query.arguments = _query_args


def _clusters_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--state-root")
    p.add_argument("--database", default=".n64dk/results.sqlite")
    p.add_argument("--max-score", type=int, default=32)
    p.add_argument("--remaining", action="store_true")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--summary-only", action="store_true")


@command("residual-clusters", "Group address-independent residual signatures across functions")
def residual_clusters(args):
    database = args.database
    if database == ".n64dk/results.sqlite":
        database = str(__import__("pathlib").Path(args.project).resolve() / database)
    index = ResultIndex(database)
    try:
        rows = index.clusters(args.max_score, args.limit)
        rows = rows[args.offset:]
        return {"count": len(rows), "clusters": [] if args.summary_only else rows}
    finally:
        index.close()


residual_clusters.arguments = _clusters_args


def _reproduce_args(p):
    p.add_argument("result_id")
    p.add_argument("--project", default=".")
    p.add_argument("--database", default=".n64dk/results.sqlite")


@command("reproduce", "Independently replay a content-addressed matching observation")
def reproduce(args):
    project = Path(args.project).resolve(); database = Path(args.database)
    if not database.is_absolute(): database = project / database
    index = ResultIndex(database)
    try:
        row = index.db.execute("SELECT payload,source_path,source_digest FROM observations WHERE observation_id=?",
                               (args.result_id,)).fetchone()
        if not row: raise ValueError("unknown result ID")
        payload, source_path, source_digest = json.loads(row[0]), row[1], row[2]
        replay = payload.get("replay")
        if not replay: raise ValueError("result predates replay bundles")
        source = Path(source_path) if source_path else Path(replay["source"])
        if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != source_digest:
            equivalent = index.db.execute("SELECT path FROM sources WHERE digest=?", (source_digest,)).fetchone()
            if not equivalent or not Path(equivalent[0]).is_file(): raise ValueError("replay source digest no longer resolves")
            source = Path(equivalent[0])
    finally: index.close()
    image = Path(replay["image"])
    if not image.is_file() or hashlib.sha256(image.read_bytes()).hexdigest() != replay["image_digest"]:
        raise ValueError("replay image digest no longer resolves")
    argv = ["match", str(source), "--project", str(project), "--rom", str(image),
            "--addr", f"0x{replay['address']:X}", "--size", f"0x{replay['size']:X}",
            "--vram-delta", f"0x{replay['vram_delta']:X}", "--pipeline", replay["pipeline"],
            "--flags", " ".join(replay["flags"])]
    for include in replay.get("include_paths", []): argv += ["-I", include]
    for symbols in replay.get("symbol_files", []): argv += ["--symbols", symbols]
    environment = dict(os.environ); environment.update(replay.get("environment", {}))
    run = subprocess.run([sys.executable, "-m", "n64dk", "--format", "json", *argv], cwd=project,
                         env=environment, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try: result = json.loads(run.stdout)
    except json.JSONDecodeError: result = {"output": run.stdout[-12000:]}
    reproduced = bool(run.returncode == 0 and result.get("exact") and
                      result.get("sha256_text") == replay.get("target_digest"))
    return {"result_id": args.result_id, "reproduced": reproduced, "exit_code": run.returncode,
            "replay": replay, "result": result, "stderr": run.stderr[-12000:]}


reproduce.arguments = _reproduce_args
