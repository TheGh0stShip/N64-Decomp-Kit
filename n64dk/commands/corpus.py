"""Local function-corpus indexing, querying, and one-call investigation dossiers."""
from __future__ import annotations

import json
from pathlib import Path

from ..cli import command
from ..match.corpus import CorpusIndex, binary_signature
from ..match.inventory import build
from ..match.investigate import dossier
from ..match.layout import from_inventory, resolve_image_map


def _index_args(p):
    p.add_argument("roots", nargs="+", help="N64 project roots to index")
    p.add_argument("--database", default=".n64dk/function-corpus.sqlite")


@command("corpus-index", "Incrementally index local N64 assembly by exact and normalized signatures")
def corpus_index(args):
    index = CorpusIndex(args.database)
    try:
        return index.index(args.roots)
    finally:
        index.close()


corpus_index.arguments = _index_args


def _query_args(p):
    p.add_argument("--database", default=".n64dk/function-corpus.sqlite")
    p.add_argument("--image", required=True)
    p.add_argument("--addr", required=True, type=lambda value: int(value, 0))
    p.add_argument("--size", required=True, type=lambda value: int(value, 0))
    p.add_argument("--vram-delta", type=lambda value: int(value, 0))
    p.add_argument("--project")
    p.add_argument("--image-name")
    p.add_argument("--limit", type=int, default=20)


@command("corpus-query", "Find exact, relocation-only, register-renamed and opcode-shape analogues")
def corpus_query(args):
    data = Path(args.image).read_bytes()
    if args.vram_delta is None and not args.project:
        raise ValueError("--vram-delta is required without --project")
    offset = args.addr - args.vram_delta if args.vram_delta is not None else 0
    if args.project:
        rows = [row for row in build(args.project)["functions"]
                if int(row["vram"], 0) == args.addr and int(row["size"]) == args.size]
        if args.image_name: rows = [row for row in rows if row["image"] == args.image_name]
        if len(rows) != 1: raise ValueError("corpus target must resolve to one catalogue interval")
        mapping = resolve_image_map(args.image, from_inventory(rows[0])); canonical = mapping["selected"]["offset"]
        if args.vram_delta is not None and args.addr - args.vram_delta != canonical:
            raise ValueError(f"vram delta selects 0x{args.addr - args.vram_delta:X}; canonical mapping selects 0x{canonical:X}")
        offset = canonical
    if offset < 0 or offset + args.size > len(data):
        raise ValueError("query interval is outside the loaded image")
    signature = binary_signature(data[offset:offset + args.size], args.addr)
    index = CorpusIndex(args.database)
    try:
        matches = index.query(signature, args.limit)
    finally:
        index.close()
    return {"target": {"addr": f"0x{args.addr:08X}", "size": args.size,
                       "instruction_count": signature["instruction_count"]},
            "matches": matches}


corpus_query.arguments = _query_args


def _prototype_infer_args(p):
    p.add_argument("symbol")
    p.add_argument("--database", default=".n64dk/function-corpus.sqlite")
    p.add_argument("--limit", type=int, default=100)


@command("corpus-prototype", "Infer callee prototypes from declarations and call-site ABI evidence")
def corpus_prototype(args):
    index = CorpusIndex(args.database)
    try: return index.infer_prototype(args.symbol, args.limit)
    finally: index.close()


corpus_prototype.arguments = _prototype_infer_args


def _investigate_args(p):
    p.add_argument("function", help="catalogue function name or VRAM")
    p.add_argument("--project", default=".")
    p.add_argument("--image", required=True, help="loaded image selected for this function")
    p.add_argument("--image-name", help="disambiguate overlapping overlay VRAM")
    p.add_argument("--corpus", help="function-corpus SQLite database")
    p.add_argument("--all", action="store_true", help="include complete disassembly and references")
    p.add_argument("--output")
    p.add_argument("--bundle", help="write target assembly, candidate source and dossier to a scratch directory")


@command("investigate", "Build a verified function dossier from layout, code, source, history and corpus evidence")
def investigate(args):
    inventory = build(args.project)
    rows = inventory["functions"]
    if args.image_name:
        rows = [row for row in rows if row["image"] == args.image_name]
    try:
        address = int(args.function, 0)
    except ValueError:
        rows = [row for row in rows if row["name"] == args.function]
    else:
        rows = [row for row in rows if int(row["vram"], 0) == address]
    if len(rows) != 1:
        raise ValueError(f"function selector resolved to {len(rows)} catalogue rows; use --image-name")
    corpus = args.corpus
    if corpus is None:
        conventional = Path(args.project).resolve() / ".n64dk" / "function-corpus.sqlite"
        corpus = str(conventional) if conventional.is_file() else None
    result = dossier(args.project, inventory, rows[0], args.image, corpus, args.all or bool(args.bundle))
    if args.bundle:
        root = Path(args.bundle).resolve()
        root.mkdir(parents=True, exist_ok=True)
        name = result["function"]["name"]
        lines = [".set noreorder", ".set noat", ".text", f".globl {name}", f".ent {name}", f"{name}:"]
        lines += ["    " + line.split(None, 2)[2] for line in result["context"]["disassembly"]]
        lines += [f".end {name}"]
        assembly = root / "target.s"
        assembly.write_text("\n".join(lines) + "\n")
        candidate_out = None
        if result.get("candidate"):
            candidate_out = root / "candidate.c"
            candidate_out.write_bytes(Path(args.project, result["candidate"]["path"]).read_bytes())
        metadata = root / "dossier.json"
        metadata.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        result["bundle"] = {"directory": str(root), "assembly": str(assembly),
                            "candidate": str(candidate_out) if candidate_out else None,
                            "metadata": str(metadata)}
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        result["output"] = str(output.resolve())
    return result


investigate.arguments = _investigate_args
