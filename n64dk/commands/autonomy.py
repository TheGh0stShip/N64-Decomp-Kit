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
from ..match.layout import from_inventory, preflight
from ..match.registry import SessionRegistry, standard_store


def _inventory_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--output", help="write the complete JSON inventory")
    p.add_argument("--remaining", action="store_true", help="include ranked remaining functions")
    p.add_argument("--refresh-sources", action="store_true")
    p.add_argument("--coverage-authority", choices=("manifest",), default="manifest")
    p.add_argument("--show-suspect-coverage", action="store_true")
    p.add_argument("--explain", help="explain classification for a function name or VRAM")
    p.add_argument("--assert-consistent", action="store_true")
    p.add_argument("--image")
    p.add_argument("--state")
    p.add_argument("--exclude", help="comma-separated ownership states")
    p.add_argument("--after", type=lambda value: int(value, 0))
    p.add_argument("--before", type=lambda value: int(value, 0))
    p.add_argument("--fields", help="comma-separated output fields")
    p.add_argument("--names-only", action="store_true")
    p.add_argument("--count-only", action="store_true")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--offset", type=int, default=0)
    p.add_argument("--summary-only", action="store_true")
    p.add_argument("--image-file", action="append", default=[], metavar="NAME=PATH")
    p.add_argument("--boundary-aware", action="store_true")


@command("match-inventory", "Build an interval-correct function and translation-unit inventory")
def match_inventory(args):
    result = invmod.build(args.project, args.refresh_sources)
    if args.boundary_aware:
        mappings = dict(value.split("=", 1) for value in args.image_file)
        for row in result["functions"]:
            image_path = mappings.get(row["image"])
            if not image_path or row["state"] == "covered":
                continue
            try:
                evidence = preflight(image_path, from_inventory(row), row.get("catalogue_status", ""))
                row["entry_preflight"] = evidence["entry_preflight"]
                if evidence["entry_preflight"]["entry_status"] == "reject" and not evidence["entry_preflight"]["call_target_evidence"]:
                    row["state"] = "excluded"; row["ownership_state"] = "fragment"
                    row["reason"] = "CFG/prologue fragment evidence: " + ", ".join(evidence["entry_preflight"]["reason_codes"])
            except ValueError as error:
                row["state"] = "excluded"; row["ownership_state"] = "fragment"
                row["reason"] = str(error)
    if args.assert_consistent and not result["consistency"]["ok"]:
        raise ValueError(f"inventory inconsistent: {len(result['consistency']['conflicts'])} conflicts; "
                         f"{len(result['consistency']['missing_ownership'])} unowned intervals; "
                         f"denominator={result['consistency'].get('denominator_mismatch')}")
    if args.explain:
        try:
            address = int(args.explain, 0)
        except ValueError:
            rows = [row for row in result["functions"] if row["name"] == args.explain]
        else:
            rows = [row for row in result["functions"] if int(row["vram"], 0) == address]
        result = {"coverage_authority": args.coverage_authority, "matches": rows}
    elif args.show_suspect_coverage:
        result["suspect_coverage"] = [row for row in result["functions"]
                                      if row["candidate_source"] and row["state"] != "covered"]
    elif args.remaining or args.image or args.state or args.exclude or args.after is not None or args.before is not None:
        rows = result["functions"]
        if args.remaining:
            rows = [row for row in rows if row["state"] == "remaining"]
        if args.image:
            rows = [row for row in rows if row["image"] == args.image]
        if args.state:
            rows = [row for row in rows if row["state"] == args.state or row["ownership_state"] == args.state]
        excluded = set((args.exclude or "").split(",")) - {""}
        rows = [row for row in rows if row["ownership_state"] not in excluded]
        if args.after is not None:
            rows = [row for row in rows if int(row["vram"], 0) >= args.after]
        if args.before is not None:
            rows = [row for row in rows if int(row["vram"], 0) < args.before]
        total = len(rows)
        page = rows[args.offset:args.offset + max(0, args.limit)]
        if args.names_only:
            page = [row["name"] for row in page]
        elif args.fields:
            fields = args.fields.split(",")
            page = [{key: row.get(key) for key in fields} for row in page]
        result = {"summary": result["summary"], "count": total,
                  "items": [] if args.count_only or args.summary_only else page,
                  "next_cursor": args.offset + len(page) if args.offset + len(page) < total else None,
                  "truncated": args.offset + len(page) < total}
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if not args.remaining and not args.explain and not args.show_suspect_coverage:
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
    layout = from_inventory(row)
    layout_check = preflight(args.image, layout, row.get("catalogue_status", ""))
    offset = int(layout_check["selected_image_offset"], 0)
    canonical_delta = start - offset
    if args.vram_delta is not None and args.vram_delta != canonical_delta:
        raise ValueError(f"--vram-delta 0x{args.vram_delta:X} conflicts with canonical image "
                         f"delta 0x{canonical_delta:X}")
    same = [item for item in inventory["functions"] if item["image"] == row["image"]]
    index = same.index(row)
    neighbours = [{key: item[key] for key in ("name", "vram", "size", "state")}
                  for item in same[max(0, index - 2):index + 3] if item is not row]
    result = contextmod.bundle(args.image, start, row["size"], offset, neighbours)
    result["inventory"] = row
    result["layout_preflight"] = layout_check
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
    p.add_argument("--refresh-sources", action="store_true",
                   help="incrementally refresh the persistent candidate-source index")
    p.add_argument("--run-ready-only", action="store_true",
                   help="resume stored ready items without rebuilding inventory or scanning sources")
    p.add_argument("--details", action="store_true", help="include every tranche item")


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
    columns = {row[1] for row in db.execute("PRAGMA table_info(tranche_items)")}
    additions = {"candidate_source": "TEXT", "layout": "TEXT", "best_score": "INTEGER",
                 "residual_counts": "TEXT", "historical_session_id": "TEXT",
                 "historical_score": "INTEGER", "comparison": "TEXT", "updated_ns": "INTEGER"}
    for name, kind in additions.items():
        if name not in columns:
            db.execute(f"ALTER TABLE tranche_items ADD COLUMN {name} {kind}")
    db.commit()
    return db


def _launch_one(args, project: str, row: dict, mappings: dict[str, str]):
    from .match import _session_evaluator
    from ..match.engine import default_pipelines
    from ..match.pipeline import split_flags
    from ..match.session import MatchSession, SessionStore
    from ..match.symbols import discover
    from ..match.toolchain import PROFILES, load_config
    from ..rom import Rom
    import shlex

    function_id = row["id"]
    image_path = mappings.get(row["image"])
    if not image_path:
        return function_id, "blocked", None, None, {}, None, None, "blocked", \
            f"missing --image-file {row['image']}=PATH"
    source_value = row.get("candidate_source")
    source_path = Path(project, source_value) if source_value else None
    if source_path is None or not source_path.is_file():
        return function_id, "needs-source", None, None, {}, None, None, "blocked", \
            "candidate source disappeared"
    layout = from_inventory(row)
    check = preflight(image_path, layout, row.get("catalogue_status", ""), strict_entry=True)
    check["cross_checks"] = row.get("mapping_evidence", [])
    cfg = load_config(project, None, None)
    pipeline = args.pipeline or ((default_pipelines(cfg) or ["kmc+builtin"])[0])
    family = {"ido5.3": "ido53", "ido7.1": "ido71", "sn": "sn"}.get(pipeline, "kmc")
    flags = shlex.split(args.flags) if args.flags else list(PROFILES[family].default_flags)
    image = Rom.load(image_path)
    symbol_files = discover(cfg.project)
    context = {
        "source_name": source_path.name, "source_suffix": source_path.suffix or ".c",
        "rom": str(Path(image_path).resolve()), "rom_sha256": hashlib.sha256(image.data).hexdigest(),
        "project": str(cfg.project), "toolchain_root": str(cfg.toolchain_root) if cfg.toolchain_root else None,
        "toolchains": {key: str(value) for key, value in cfg.toolchains.items()},
        "include": [str(value) for value in cfg.include],
        "symbols": [str(value.resolve()) for value in symbol_files], "normalizer": cfg.normalizer,
        "vram_delta": layout.function_vram - int(check["selected_image_offset"], 0),
        "addr": layout.function_vram, "size": layout.function_size,
        "infer_externals": True, "default_pipeline": pipeline, "default_flags": flags,
        "inventory_id": function_id, "inventory_image": row["image"], "layout_preflight": check,
        "target_text_sha256": check["mapping"].get("target_digest"),
    }
    store_root = standard_store(project)
    store = SessionStore(store_root)
    try:
        session = MatchSession(store, _session_evaluator(context))
        session_id, baseline = session.create(context, source_path.read_bytes(), pipeline,
                                              tuple(split_flags(flags, pipeline).flags))
        registry = SessionRegistry(project)
        try:
            registry.register(session_id, store_root, context, baseline.source_digest, "quickwin-sweep")
            history = registry.same_target(context)
        finally:
            registry.close()
        previous = next((item for item in history if item["session_id"] != session_id), None)
        historical_score = previous["score"] if previous else None
        comparison = ("new" if previous is None else "improved" if baseline.exact or
                      (baseline.score is not None and historical_score is not None and baseline.score < historical_score)
                      else "tied" if baseline.score == historical_score else "regressed")
        reason = baseline.error or (f"score {baseline.score}" if baseline.score is not None else "baseline retained")
        return function_id, "exact" if baseline.exact else "active", session_id, baseline.score, \
            baseline.counts, previous["session_id"] if previous else None, historical_score, comparison, reason
    finally:
        store.close()


@command("quickwin-sweep", "Create or resume a persistent interval-aware cross-function tranche")
def quickwin_sweep(args):
    overall_started = time.monotonic()
    compile_seconds = 0.0
    if args.run_ready_only and not args.resume:
        raise ValueError("--run-ready-only requires --resume")
    db = _state(Path(args.state_root))
    if args.run_ready_only:
        existing = db.execute("SELECT project, inventory_digest FROM tranches WHERE tranche_id = ?",
                              (args.resume,)).fetchone()
        if not existing:
            db.close()
            raise ValueError(f"unknown tranche {args.resume}")
        project, digest = existing
        stored = db.execute("""SELECT function_id, image, name, vram, size, rank, reason,
                                      candidate_source, layout FROM tranche_items
                               WHERE tranche_id = ? AND status = 'ready' ORDER BY ordinal""",
                            (args.resume,)).fetchall()
        inventory = {"project": project, "functions": []}
        for values in stored:
            layout_value = json.loads(values[8]) if values[8] else None
            if not layout_value:
                continue
            inventory["functions"].append({"id": values[0], "image": values[1], "name": values[2],
                "vram": values[3], "size": values[4], "rank": values[5], "reason": values[6],
                "candidate_source": values[7], **layout_value})
        ranked = inventory["functions"]
        tranche_id = args.resume
    else:
        inventory = invmod.build(args.project, args.refresh_sources)
        selected = None if args.all_images or not args.image else set(args.image)
        ranked = invmod.rank(inventory, args.limit, selected)
        stable_inventory = {key: value for key, value in inventory.items() if key != "source_index"}
        digest = hashlib.sha256(json.dumps(stable_inventory, sort_keys=True).encode()).hexdigest()
        tranche_id = args.resume
    try:
        now = time.time_ns()
        tranche_id = tranche_id or hashlib.sha256(
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
                layout_value = {key: row.get(key) for key in
                                ("section_rom", "section_vram", "section_size", "catalogue_status", "rom")}
                db.execute("""INSERT INTO tranche_items
                    (tranche_id, ordinal, function_id, image, name, vram, size, rank, status,
                     session_id, reason, candidate_source, layout, updated_ns)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)""",
                    (tranche_id, ordinal, row["id"], row["image"], row["name"], row["vram"],
                     row["size"], row["rank"], status, row["reason"], row.get("candidate_source"),
                     json.dumps(layout_value, sort_keys=True), now))
            db.commit()
        if args.run or args.run_ready_only:
            mappings = dict(value.split("=", 1) for value in args.image_file if "=" in value)
            inventory_by_id = {row["id"]: row for row in inventory["functions"]}
            pending = db.execute("""SELECT function_id FROM tranche_items
                                    WHERE tranche_id = ? AND status = 'ready' ORDER BY ordinal""",
                                 (tranche_id,)).fetchall()

            def launch(function_id: str):
                try:
                    return _launch_one(args, inventory["project"], inventory_by_id[function_id], mappings)
                except Exception as error:
                    return function_id, "blocked", None, None, {}, None, None, "blocked", str(error)

            with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
                compile_started = time.monotonic()
                launched = list(pool.map(lambda row: launch(row[0]), pending))
                compile_seconds = time.monotonic() - compile_started
            for (function_id, status, session_id, score, counts, historical_session,
                 historical_score, comparison, reason) in launched:
                db.execute("""UPDATE tranche_items SET status = ?, session_id = ?, reason = ?,
                              best_score = ?, residual_counts = ?, historical_session_id = ?,
                              historical_score = ?, comparison = ?, updated_ns = ?
                              WHERE tranche_id = ? AND function_id = ?""",
                           (status, session_id, reason, score, json.dumps(counts, sort_keys=True),
                            historical_session, historical_score, comparison, time.time_ns(),
                            tranche_id, function_id))
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
                  "selected": len(items), "status": counts,
                  "next": [item for item in items if item["status"] != "exact"][:20],
                  "timing": {"discovery_seconds": inventory.get("source_index", {}).get("elapsed_seconds", 0.0),
                             "compilation_and_matching_seconds": round(compile_seconds, 6),
                             "total_seconds": round(time.monotonic() - overall_started, 6)}}
        if args.details:
            result["items"] = items
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


def _sweep_status_args(p):
    p.add_argument("tranche_id")
    p.add_argument("--state-root", default=".n64dk/quickwin-sweeps")
    p.add_argument("--status", action="append", default=[])
    p.add_argument("--summary-only", action="store_true")
    p.add_argument("--best-details", action="store_true")
    p.add_argument("--exact-only", action="store_true")
    p.add_argument("--needs-source", action="store_true")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--changed-since", type=int, help="nanosecond timestamp from a prior response")


@command("quickwin-sweep-status", "Inspect a tranche with compact status and history filters")
def quickwin_sweep_status(args):
    db = _state(Path(args.state_root))
    try:
        tranche = db.execute("""SELECT project, inventory_digest, jobs, created_ns, updated_ns
                                FROM tranches WHERE tranche_id = ?""", (args.tranche_id,)).fetchone()
        if not tranche:
            raise ValueError(f"unknown tranche {args.tranche_id}")
        requested = list(args.status)
        if args.exact_only:
            requested.append("exact")
        if args.needs_source:
            requested.append("needs-source")
        where = ["tranche_id = ?"]
        values: list = [args.tranche_id]
        if requested:
            where.append("status IN (" + ",".join("?" for _ in requested) + ")")
            values += requested
        if args.changed_since is not None:
            where.append("COALESCE(updated_ns, 0) > ?")
            values.append(args.changed_since)
        query = f"""SELECT ordinal, image, name, vram, size, status, session_id, reason,
                           best_score, residual_counts, historical_session_id, historical_score,
                           comparison, updated_ns FROM tranche_items
                    WHERE {' AND '.join(where)} ORDER BY ordinal LIMIT ?"""
        rows = db.execute(query, (*values, max(0, args.limit))).fetchall()
        items = []
        for row in rows:
            item = dict(zip(("ordinal", "image", "name", "vram", "size", "status", "session_id",
                             "reason", "best_score", "residual_counts", "historical_session_id",
                             "historical_score", "comparison", "updated_ns"), row))
            item["residual_counts"] = json.loads(item["residual_counts"] or "{}")
            if item["session_id"]:
                from ..match.registry import resolve_store
                from ..match.session import SessionStore
                store = SessionStore(resolve_store(item["session_id"], tranche[0]))
                try:
                    current = store.best(item["session_id"])
                    registry = SessionRegistry(tranche[0])
                    try:
                        history = registry.same_target(store.context(item["session_id"]))
                    finally:
                        registry.close()
                    project_best = history[0] if history else None
                    item["project_best"] = project_best
                    if project_best:
                        item["historical_session_id"] = project_best["session_id"]
                        item["historical_score"] = project_best["score"]
                        item["comparison"] = ("tied" if project_best["session_id"] == item["session_id"] or
                                              project_best["score"] == current.score else "regressed")
                    if args.best_details:
                        item["best"] = current.summary(True)
                finally:
                    store.close()
            items.append(item)
        counts = dict(db.execute("""SELECT status, COUNT(*) FROM tranche_items
                                   WHERE tranche_id = ? GROUP BY status""", (args.tranche_id,)).fetchall())
        result = {"tranche_id": args.tranche_id, "project": tranche[0],
                  "inventory_digest": tranche[1], "jobs": tranche[2], "status": counts,
                  "created_ns": tranche[3], "updated_ns": tranche[4], "matched": len(items)}
        aggregate = db.execute("""SELECT COUNT(*), COUNT(candidate_source), COUNT(DISTINCT candidate_source),
                                  COUNT(session_id), COUNT(DISTINCT session_id),
                                  SUM(CASE WHEN status='exact' THEN 1 ELSE 0 END),
                                  SUM(CASE WHEN comparison='improved' THEN 1 ELSE 0 END),
                                  SUM(CASE WHEN comparison='tied' THEN 1 ELSE 0 END)
                           FROM tranche_items WHERE tranche_id=?""", (args.tranche_id,)).fetchone()
        result["quality_metrics"] = dict(zip(("catalogue_selected", "with_candidate_source",
            "unique_candidate_sources", "compiled", "unique_sessions", "exact_matches",
            "improved_frontiers", "unchanged_frontiers"), aggregate))
        if not args.summary_only:
            result["items"] = items
        return result
    finally:
        db.close()


quickwin_sweep_status.arguments = _sweep_status_args
