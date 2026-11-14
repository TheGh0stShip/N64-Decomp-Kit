"""Project script discovery and machine-readable operation gateway."""
from __future__ import annotations

import json
import sys

from ..cli import command
from ..operations import ScriptIndex, command_schema, invoke


def _index_args(p):
    p.add_argument("roots", nargs="+", help="project roots containing Python tools")
    p.add_argument("--database", default=".n64dk/script-index.sqlite")
    p.add_argument("--refresh", action="store_true")


@command("script-index", "Inventory and classify project-local decompilation scripts incrementally")
def script_index(args):
    index = ScriptIndex(args.database)
    try:
        return index.index(args.roots, args.refresh)
    finally:
        index.close()


script_index.arguments = _index_args


def _query_args(p):
    p.add_argument("--database", default=".n64dk/script-index.sqlite")
    p.add_argument("--kind", choices=("sweep", "score", "transform", "audit", "extract", "build",
                                      "process-wrapper", "cli", "uncategorized"))
    p.add_argument("--text")
    p.add_argument("--limit", type=int, default=100)


@command("script-query", "Find reusable project scripts by purpose, path, or declared argument")
def script_query(args):
    index = ScriptIndex(args.database)
    try:
        rows = index.query(args.kind, args.text, args.limit)
    finally:
        index.close()
    return {"count": len(rows), "scripts": rows}


script_query.arguments = _query_args


@command("operation-schema", "Describe every N64 Decomp Kit operation and its typed arguments")
def operation_schema(_args):
    return command_schema()


def _serve_args(p):
    p.add_argument("--timeout", type=float, default=1800.0, help="per-operation timeout in seconds")


@command("automation-serve", "Execute newline-delimited JSON operation requests on standard input")
def automation_serve(args):
    for line in sys.stdin:
        request = {}
        try:
            request = json.loads(line)
            request_id = request.get("id")
            if request.get("method") == "schema":
                response = {"ok": True, "result": command_schema()}
            elif request.get("method", "invoke") == "invoke":
                argv = request.get("argv")
                if not isinstance(argv, list) or not all(isinstance(value, str) for value in argv):
                    raise ValueError("invoke requests require a string argv array")
                response = invoke(argv, min(float(request.get("timeout", args.timeout)), args.timeout))
            else:
                raise ValueError("method must be schema or invoke")
            response["id"] = request_id
        except Exception as error:
            response = {"id": request.get("id") if isinstance(request, dict) else None,
                        "ok": False, "error": f"{type(error).__name__}: {error}"}
        print(json.dumps(response, sort_keys=True), flush=True)


automation_serve.arguments = _serve_args
