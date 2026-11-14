"""Project-wide interval inventory, context bundles, and persistent tranche planning."""
from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..cli import command
from ..match import context as contextmod
from ..match import inventory as invmod


def _inventory_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--output", help="write the complete JSON inventory")
    p.add_argument("--remaining", action="store_true", help="include ranked remaining functions")


@command("match-inventory", "Build an interval-correct function and translation-unit inventory")
def match_inventory(args):
    result = invmod.build(args.project)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not args.remaining:
        result = {key: value for key, value in result.items() if key != "functions"}
    return result


match_inventory.arguments = _inventory_args


def _context_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--image", required=True, help="decompressed/loaded image containing the function")
    selector = p.add_mutually_exclusive_group(required=True)
    selector.add_argument("--function")
    selector.add_argument("--addr", type=lambda value: int(value, 0))
    p.add_argument("--image-name", help="disambiguate catalogues with overlapping VRAM")
    p.add_argument("--vram-delta", type=lambda value: int(value, 0),
                   help="VRAM minus image offset (default: use catalogue ROM offset)")
    p.add_argument("--output")


@command("context-bundle", "Emit disassembly, call/reference and access-pattern evidence in one call")
def context_bundle(args):
    inventory = invmod.build(args.project)
    rows = inventory["functions"]
    if args.image_name:
        rows = [row for row in rows if row["image"] == args.image_name]
    if args.function:
        rows = [row for row in rows if row["name"] == args.function]
    else:
        rows = [row for row in rows if int(row["vram"], 0) == args.addr]
    if len(rows) != 1:
        raise ValueError(f"function selector resolved to {len(rows)} catalogue rows")
    row = rows[0]
    start = int(row["vram"], 0)
    offset = start - args.vram_delta if args.vram_delta is not None else int(row["rom"], 0)
    same = [item for item in inventory["functions"] if item["image"] == row["image"]]
    index = same.index(row)
    neighbours = [{key: item[key] for key in ("name", "vram", "size", "state")}
                  for item in same[max(0, index - 2):index + 3] if item is not row]
    result = contextmod.bundle(args.image, start, row["size"], offset, neighbours)
    result["inventory"] = row
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


context_bundle.arguments = _context_args


def _sweep_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--all-images", action="store_true")
    p.add_argument("--image", action="append", default=[], help="restrict to an image name (repeatable)")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--jobs", type=int, default=1,
                   help="worker allocation recorded for execution/resume (default: 1)")
    p.add_argument("--state-root", default=".n64dk/quickwin-sweeps")
    p.add_argument("--resume", help="existing tranche ID")
    p.add_argument("--report", help="write a concise Markdown report")
    p.add_argument("--run", action="store_true", help="launch baseline transactional sessions for ready items")
    p.add_argument("--image-file", action="append", default=[], metavar="NAME=PATH",
                   help="loaded image/ROM for an inventory image (repeatable; required by --run)")
    p.add_argument("--pipeline", help="matching pipeline for launched sessions")
    p.add_argument("--flags", help="compiler flags for launched sessions")


def _state(root: Path) -> sqlite3.Connection:
    root.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(root / "sweeps.sqlite")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS tranches (
          tranche_id TEXT PRIMARY KEY, project TEXT NOT NULL, inventory_digest TEXT NOT NULL,
          jobs INTEGER NOT NULL, created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS tranche_items (
          tranche_id TEXT NOT NULL, ordinal INTEGER NOT NULL, function_id TEXT NOT NULL,
          image TEXT NOT NULL, name TEXT NOT NULL, vram TEXT NOT NULL, size INTEGER NOT NULL,
          rank REAL NOT NULL, status TEXT NOT NULL, session_id TEXT, reason TEXT NOT NULL,
          PRIMARY KEY (tranche_id, function_id));
    """)
    return db


@command("quickwin-sweep", "Create or resume a persistent interval-aware cross-function tranche")
def quickwin_sweep(args):
    inventory = invmod.build(args.project)
    selected = None if args.all_images or not args.image else set(args.image)
    ranked = invmod.rank(inventory, args.limit, selected)
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    db = _state(Path(args.state_root))
    try:
        now = time.time_ns()
        tranche_id = args.resume or hashlib.sha256(
            f"{inventory['project']}:{digest}:{now}".encode()).hexdigest()[:20]
        existing = db.execute("SELECT inventory_digest FROM tranches WHERE tranche_id = ?",
                              (tranche_id,)).fetchone()
        if existing and existing[0] != digest:
            raise ValueError("project inventory changed; start a new tranche for auditable ranking")
        if not existing:
            db.execute("INSERT INTO tranches VALUES (?, ?, ?, ?, ?, ?)",
                       (tranche_id, inventory["project"], digest, max(1, args.jobs), now, now))
            for ordinal, row in enumerate(ranked, 1):
                status = "ready" if row.get("candidate_source") else "needs-source"
                db.execute("INSERT INTO tranche_items VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                           (tranche_id, ordinal, row["id"], row["image"], row["name"], row["vram"],
                            row["size"], row["rank"], status, row["reason"]))
            db.commit()
        if args.run:
            mappings = dict(value.split("=", 1) for value in args.image_file if "=" in value)
            inventory_by_id = {row["id"]: row for row in inventory["functions"]}
            pending = db.execute("""SELECT function_id FROM tranche_items
                                    WHERE tranche_id = ? AND status = 'ready' ORDER BY ordinal""",
                                 (tranche_id,)).fetchall()

            def launch(function_id: str):
                from .match import _session_evaluator
                from ..match.engine import default_pipelines
                from ..match.pipeline import split_flags
                from ..match.session import MatchSession, SessionStore
                from ..match.symbols import discover
                from ..match.toolchain import PROFILES, load_config
                from ..rom import Rom
                import shlex

                row = inventory_by_id[function_id]
                image_path = mappings.get(row["image"])
                if not image_path:
                    return function_id, "blocked", None, f"missing --image-file {row['image']}=PATH"
                source_path = Path(inventory["project"], row["candidate_source"])
                if not source_path.is_file():
                    return function_id, "needs-source", None, "candidate source disappeared"
                cfg = load_config(inventory["project"], None, None)
                pipeline = args.pipeline or ((default_pipelines(cfg) or ["kmc+builtin"])[0])
                family = {"ido5.3": "ido53", "ido7.1": "ido71", "sn": "sn"}.get(pipeline, "kmc")
                flags = shlex.split(args.flags) if args.flags else list(PROFILES[family].default_flags)
                image = Rom.load(image_path)
                rom = int(row["rom"], 0)
                vram = int(row["vram"], 0)
                symbol_files = discover(cfg.project)
                context = {
                    "source_name": source_path.name, "source_suffix": source_path.suffix or ".c",
                    "rom": str(Path(image_path).resolve()),
                    "rom_sha256": hashlib.sha256(image.data).hexdigest(),
                    "project": str(cfg.project),
                    "toolchain_root": str(cfg.toolchain_root) if cfg.toolchain_root else None,
                    "toolchains": {key: str(value) for key, value in cfg.toolchains.items()},
                    "include": [str(value) for value in cfg.include],
                    "symbols": [str(value.resolve()) for value in symbol_files],
                    "normalizer": cfg.normalizer, "vram_delta": vram - rom,
                    "addr": vram, "size": row["size"], "infer_externals": True,
                    "default_pipeline": pipeline, "default_flags": flags,
                    "inventory_id": function_id, "inventory_image": row["image"],
                }
                store = SessionStore(Path(args.state_root) / "sessions")
                try:
                    session = MatchSession(store, _session_evaluator(context))
                    session_id, baseline = session.create(context, source_path.read_bytes(),
                                                          pipeline, tuple(split_flags(flags, pipeline).flags))
                    return function_id, "exact" if baseline.exact else "active", session_id, \
                        baseline.error or (f"score {baseline.score}" if baseline.score is not None else "baseline retained")
                finally:
                    store.close()

            with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
                launched = list(pool.map(lambda row: launch(row[0]), pending))
            for function_id, status, session_id, reason in launched:
                db.execute("""UPDATE tranche_items SET status = ?, session_id = ?, reason = ?
                              WHERE tranche_id = ? AND function_id = ?""",
                           (status, session_id, reason, tranche_id, function_id))
            db.execute("UPDATE tranches SET updated_ns = ? WHERE tranche_id = ?", (time.time_ns(), tranche_id))
            db.commit()
        rows = db.execute("""SELECT ordinal, function_id, image, name, vram, size, rank, status,
                                    session_id, reason FROM tranche_items
                             WHERE tranche_id = ? ORDER BY ordinal""", (tranche_id,)).fetchall()
        items = [dict(zip(("ordinal", "function_id", "image", "name", "vram", "size", "rank",
                          "status", "session_id", "reason"), row)) for row in rows]
        counts = {status: sum(item["status"] == status for item in items)
                  for status in sorted({item["status"] for item in items})}
        result = {"tranche_id": tranche_id, "inventory_digest": digest, "jobs": max(1, args.jobs),
                  "selected": len(items), "status": counts, "items": items,
                  "next": [item for item in items if item["status"] != "exact"][:20]}
        if args.report:
            report = Path(args.report)
            report.parent.mkdir(parents=True, exist_ok=True)
            lines = [f"# Quick-win tranche {tranche_id}", "", f"Inventory: `{digest}`",
                     f"Selected: {len(items)}; workers: {max(1, args.jobs)}", "",
                     "| Rank | Image | Function | VRAM | Size | State |", "|---:|---|---|---:|---:|---|"]
            lines += [f"| {item['ordinal']} | {item['image']} | {item['name']} | {item['vram']} | "
                      f"{item['size']} | {item['status']} |" for item in items]
            report.write_text("\n".join(lines) + "\n")
            result["report"] = str(report)
        return result
    finally:
        db.close()


quickwin_sweep.arguments = _sweep_args
