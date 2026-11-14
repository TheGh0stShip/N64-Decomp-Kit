"""Historical observation indexing, querying, and residual clustering."""
from __future__ import annotations

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


@command("result-query", "Query valid historical frontiers while excluding stale target observations")
def result_query(args):
    index = ResultIndex(args.database)
    try:
        rows = index.query(args.function or args.same_residual, args.max_score, args.exact_only,
                           args.validity, args.stale_mapping, args.missing_source,
                           args.timeline, args.limit)
        if args.same_residual and rows:
            residual = rows[0]["residual"]
            rows = [row for row in index.query(max_score=args.max_score, limit=100000)
                    if row["residual"] == residual][:args.limit]
        result = {"count": len(rows), "observations": rows}
        if args.function:
            result["bracketed_target"] = index.brackets(args.function)
        return result
    finally:
        index.close()


result_query.arguments = _query_args


def _clusters_args(p):
    p.add_argument("--database", default=".n64dk/results.sqlite")
    p.add_argument("--max-score", type=int, default=32)
    p.add_argument("--remaining", action="store_true")
    p.add_argument("--limit", type=int, default=100)


@command("residual-clusters", "Group address-independent residual signatures across functions")
def residual_clusters(args):
    index = ResultIndex(args.database)
    try:
        rows = index.clusters(args.max_score, args.limit)
        return {"count": len(rows), "clusters": rows}
    finally:
        index.close()


residual_clusters.arguments = _clusters_args
