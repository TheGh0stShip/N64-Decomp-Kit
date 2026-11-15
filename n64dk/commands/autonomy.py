"""Project-wide interval inventory, context bundles, and persistent tranche planning."""
from __future__ import annotations

import csv
import contextlib
import hashlib
import json
import random
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..cli import command
from ..match import context as contextmod
from ..match import inventory as invmod
from ..match.layout import boundary_proposals, from_inventory, preflight
from ..match.registry import SessionRegistry, standard_store
from ..match.project_context import ProjectContext


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
    p.add_argument("--draft-missing", action="store_true",
                   help="use m2c to create transient starter C for verified source-less intervals")
    p.add_argument("--m2c-context", help="preprocessed declarations/types supplied to m2c drafts")
    p.add_argument("--details", action="store_true", help="include every tranche item")


def _state(root: Path) -> sqlite3.Connection:
    root.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(root / "sweeps.sqlite", timeout=30, check_same_thread=False,
                         isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
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
                 "historical_score": "INTEGER", "comparison": "TEXT", "updated_ns": "INTEGER",
                 "phase": "TEXT", "worker_id": "TEXT", "started_ns": "INTEGER",
                 "heartbeat_ns": "INTEGER", "finished_ns": "INTEGER", "recipe": "TEXT",
                 "timing": "TEXT", "source_digest": "TEXT"}
    for name, kind in additions.items():
        if name not in columns:
            try:
                db.execute(f"ALTER TABLE tranche_items ADD COLUMN {name} {kind}")
            except sqlite3.OperationalError as error:
                if "duplicate column" not in str(error).lower(): raise
    db.commit()
    return db


@contextlib.contextmanager
def _immediate(db: sqlite3.Connection, attempts: int = 8):
    """Serialize a short metadata write and retry external WAL contention with jitter."""
    delay = 0.01
    for attempt in range(attempts):
        try:
            db.execute("BEGIN IMMEDIATE")
            break
        except sqlite3.OperationalError as error:
            if "locked" not in str(error).lower() or attempt + 1 == attempts:
                raise
            time.sleep(delay + random.random() * delay)
            delay = min(delay * 2, 0.5)
    try:
        yield
    except BaseException:
        db.rollback()
        raise
    else:
        db.commit()


def _launch_one(args, context_cache: ProjectContext, row: dict, phase=None):
    from .match import _session_evaluator
    from ..match.pipeline import split_flags
    from ..match.session import MatchSession, SessionStore
    function_id = row["id"]
    started = time.monotonic(); phase = phase or (lambda *_args: None)
    phase("preflight")
    layout = from_inventory(row)
    check = context_cache.preflight(row, True)
    source_check = context_cache.validate_source(row)
    if not source_check["ok"]:
        return function_id, source_check["state"], None, None, {}, None, None, "blocked", source_check["reason"], {}, {}
    if row.get("_stored_source_digest") and source_check.get("digest") != row["_stored_source_digest"]:
        return function_id, "source_changed", None, None, {}, None, None, "blocked", \
            "candidate source digest changed since tranche planning", row.get("_stored_recipe") or {}, {}
    source_path = Path(source_check["path"])
    recipe = row.get("_stored_recipe") or context_cache.infer_recipe(
        row, getattr(args, "pipeline", None), getattr(args, "flags", None))
    if recipe["confidence"] < 0.3:
        return function_id, "recipe_unknown", None, None, {}, None, None, "blocked", recipe["evidence"], recipe, {}
    pipeline, flags = recipe["pipeline"], recipe["flags"]
    image = context_cache.image(row["image"]); cfg = context_cache.config
    phase("compilation")
    context = {
        "source_name": source_path.name, "source_suffix": source_path.suffix or ".c",
        "rom": str(image.path), "rom_sha256": image.digest,
        "project": str(cfg.project), "toolchain_root": str(cfg.toolchain_root) if cfg.toolchain_root else None,
        "toolchains": {key: str(value) for key, value in cfg.toolchains.items()},
        "include": [str(value) for value in cfg.include],
        "symbols": [str(value) for value in context_cache.symbol_files], "normalizer": cfg.normalizer,
        "vram_delta": layout.function_vram - int(check["selected_image_offset"], 0),
        "addr": layout.function_vram, "size": layout.function_size,
        "infer_externals": True, "default_pipeline": pipeline, "default_flags": flags,
        "inventory_id": function_id, "inventory_image": row["image"], "layout_preflight": check,
        "inventory_name": row["name"],
        "target_text_sha256": check["mapping"].get("target_digest"),
        "compiler_recipe": recipe,
    }
    store_root = standard_store(context_cache.project)
    store = SessionStore(store_root)
    try:
        session = MatchSession(store, _session_evaluator(context))
        session_id, baseline = session.create(context, source_path.read_bytes(), pipeline,
                                              tuple(split_flags(flags, pipeline).flags))
        phase("matching")
        try:
            registry = SessionRegistry(context_cache.project)
            try:
                registry.register(session_id, store_root, context, baseline.source_digest, "quickwin-sweep")
            finally:
                registry.close()
            history = context_cache.history(context)
        except Exception as error:
            return function_id, "metadata_failed", session_id, baseline.score, baseline.counts, None, None, \
                "blocked", f"session retained; metadata update failed: {error}", recipe, \
                {"compilation_matching_seconds": round(time.monotonic() - started, 6)}
        previous = next((item for item in history if item["session_id"] != session_id), None)
        historical_score = previous["score"] if previous else None
        comparison = ("new" if previous is None else "tied" if baseline.exact and previous.get("exact") else
                      "improved" if baseline.exact or
                      (baseline.score is not None and historical_score is not None and baseline.score < historical_score)
                      else "tied" if baseline.score == historical_score else "regressed")
        reason = baseline.error or (f"score {baseline.score}" if baseline.score is not None else "baseline retained")
        timing = {"compilation_matching_seconds": round(time.monotonic() - started, 6)}
        status = "build_failed" if baseline.error or baseline.score is None else "exact" if baseline.exact else "near_match"
        return function_id, status, session_id, baseline.score, \
            baseline.counts, previous["session_id"] if previous else None, historical_score, comparison, reason, recipe, timing
    finally:
        store.close()


def _draft_missing_source(args, context_cache: ProjectContext, row: dict, check: dict,
                          recipe: dict) -> dict:
    """Create a content-addressed, non-project draft for one verified interval."""
    import tempfile

    from ..match import autodraft
    from ..match.engine import Target, match_source
    from ..match.pipeline import split_flags

    image = context_cache.image(row["image"])
    offset = int(check["selected_image_offset"], 0)
    size = int(row["size"])
    vram = int(row["vram"], 0)
    if offset < 0 or offset + size > len(image.data):
        return {"ok": False, "state": "draft_failed", "reason": "verified interval is outside loaded image"}
    delta = vram - offset
    context = Path(args.m2c_context).expanduser().resolve() if getattr(args, "m2c_context", None) else None
    root = Path(args.state_root).expanduser().resolve() / "drafts" / image.digest[:16]
    root.mkdir(parents=True, exist_ok=True)
    spec = split_flags(list(recipe["flags"]), recipe["pipeline"])
    target = Target(image.data, delta, (0, len(image.data)))
    with tempfile.TemporaryDirectory(prefix="n64dk-autodraft-build-") as work:
        def evaluate(path, address, length):
            return match_source(path, spec, context_cache.config, target, address, length,
                                context_cache.symbols, Path(work), None)

        draft = autodraft.draft_one(row["name"], vram, size, image.data[offset:offset + size],
                                    lambda _address: None, evaluate, root,
                                    compiler=recipe["pipeline"], context=context,
                                    family="ido" if recipe["pipeline"].startswith("ido") else "gcc",
                                    image=image.data, image_vram=delta)
    if draft.status not in {"compiled", "exact"} or not draft.source_path:
        return {"ok": False, "state": "draft_failed", "reason": draft.error or draft.status,
                "draft_status": draft.status, "jump_tables": draft.jump_tables,
                "repairs": draft.repairs}
    source = Path(draft.source_path).read_text()
    digest = hashlib.sha256(source.encode()).hexdigest()
    path = root / f"{row['name']}-{digest[:16]}.c"
    path.write_text(source)
    return {"ok": True, "state": "ready_verified", "path": str(path), "digest": digest,
            "draft_status": draft.status, "draft_score": draft.score,
            "jump_tables": draft.jump_tables, "repairs": draft.repairs}


@command("quickwin-sweep", "Create or resume a persistent interval-aware cross-function tranche")
def quickwin_sweep(args):
    overall_started = time.monotonic()
    compile_seconds = 0.0; database_seconds = 0.0
    if args.run_ready_only and not args.resume:
        raise ValueError("--run-ready-only requires --resume")
    db = _state(Path(args.state_root)); mappings = dict(value.split("=", 1)
        for value in getattr(args, "image_file", []) if "=" in value)
    context_cache = None; planning_exclusions = {"counts": {}, "examples": {}}
    if args.run_ready_only:
        existing = db.execute("SELECT project, inventory_digest FROM tranches WHERE tranche_id = ?",
                              (args.resume,)).fetchone()
        if not existing:
            db.close()
            raise ValueError(f"unknown tranche {args.resume}")
        project, digest = existing
        stored = db.execute("""SELECT function_id, image, name, vram, size, rank, reason,
                                      candidate_source, layout, recipe, source_digest FROM tranche_items
                               WHERE tranche_id = ? AND status IN
                                 ('ready_verified','interrupted','stale_running') ORDER BY ordinal""",
                            (args.resume,)).fetchall()
        inventory = {"project": project, "functions": []}
        for values in stored:
            layout_value = json.loads(values[8]) if values[8] else None
            if not layout_value:
                continue
            inventory["functions"].append({"id": values[0], "image": values[1], "name": values[2],
                "vram": values[3], "size": values[4], "rank": values[5], "reason": values[6],
                "candidate_source": values[7], "_stored_recipe": json.loads(values[9]) if values[9] else None,
                "_stored_source_digest": values[10], **layout_value})
        ranked = inventory["functions"]
        tranche_id = args.resume
        context_cache = ProjectContext(project, mappings, inventory_snapshot=inventory)
    else:
        context_cache = ProjectContext(args.project, mappings, getattr(args, "refresh_sources", False))
        inventory = context_cache.inventory
        selected = None if args.all_images or not args.image else set(args.image)
        candidates = invmod.rank(inventory, len(inventory["functions"]), selected)
        ranked = []; valid_targets = 0; exclusion_counts = {}; exclusion_examples = {}
        for row in candidates:
            if args.limit <= 0: break
            planned = dict(row); excluded = False
            if row["image"] not in mappings:
                planned["planned_status"] = "mapping_ambiguous"
                planned["planned_reason"] = f"missing image mapping {row['image']}=PATH"
                excluded = bool(mappings)
            else:
                try:
                    planned["layout_preflight"] = context_cache.preflight(row, True)
                except ValueError as error:
                    planned["planned_status"] = ("boundary_rejected" if any(word in str(error) for word in
                        ("entry preflight", "terminator", "delay slot", "outside its catalogue")) else "mapping_ambiguous")
                    planned["planned_reason"] = str(error)
                    if planned["planned_status"] == "boundary_rejected":
                        image = context_cache.image(row["image"])
                        planned["boundary_proposals"] = boundary_proposals(
                            image.path, from_inventory(row), data=image.data)
                    excluded = True
                else:
                    planned["compiler_recipe"] = context_cache.infer_recipe(
                        row, getattr(args, "pipeline", None), getattr(args, "flags", None))
                    source = context_cache.validate_source(row)
                    if (not source["ok"] and source["state"] == "source_missing"
                            and getattr(args, "draft_missing", False)):
                        source = _draft_missing_source(args, context_cache, row,
                                                       planned["layout_preflight"],
                                                       planned["compiler_recipe"])
                        if source["ok"]:
                            planned["candidate_source"] = source["path"]
                            row["candidate_source"] = source["path"]
                    planned["source_validation"] = source
                    if not source["ok"]:
                        planned["planned_status"] = source["state"]
                        planned["planned_reason"] = source["reason"]
                    elif planned["compiler_recipe"]["confidence"] < 0.3:
                        planned["planned_status"] = "recipe_unknown"
                        planned["planned_reason"] = planned["compiler_recipe"]["evidence"]
                    else:
                        planned["planned_status"] = "ready_verified"
                        planned["planned_reason"] = "ownership, boundary, mapping, recipe and source identity verified"
                    valid_targets += 1
            if excluded:
                state = planned["planned_status"]
                exclusion_counts[state] = exclusion_counts.get(state, 0) + 1
                examples = exclusion_examples.setdefault(state, [])
                if len(examples) < 10:
                    examples.append({"function": row["name"], "image": row["image"],
                                     "reason": planned["planned_reason"],
                                     "boundary_proposals": planned.get("boundary_proposals", [])})
            else:
                ranked.append(planned)
            if valid_targets >= max(0, args.limit) or (not mappings and len(ranked) >= max(0, args.limit)): break
        planning_exclusions = {"counts": exclusion_counts, "examples": exclusion_examples}
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
                status = row.get("planned_status", "source_missing" if not row.get("candidate_source") else "ready_verified")
                layout_value = {key: row.get(key) for key in
                                ("section_rom", "section_vram", "section_size", "catalogue_status", "rom")}
                db.execute("""INSERT INTO tranche_items
                    (tranche_id, ordinal, function_id, image, name, vram, size, rank, status,
                     session_id, reason, candidate_source, layout, updated_ns)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)""",
                    (tranche_id, ordinal, row["id"], row["image"], row["name"], row["vram"],
                     row["size"], row["rank"], status, row.get("planned_reason", row["reason"]), row.get("candidate_source"),
                     json.dumps(layout_value, sort_keys=True), now))
                recipe = row.get("compiler_recipe")
                db.execute("""UPDATE tranche_items SET recipe=?, source_digest=?, phase=?
                              WHERE tranche_id=? AND function_id=?""",
                           (json.dumps(recipe, sort_keys=True) if recipe else None,
                            row.get("source_validation", {}).get("digest"), "queued" if status == "ready_verified" else "planning",
                            tranche_id, row["id"]))
            db.commit()
        if args.run or args.run_ready_only:
            inventory_by_id = {row["id"]: row for row in inventory["functions"]}
            stale_before = time.time_ns() - 60_000_000_000
            db.execute("""UPDATE tranche_items SET status='stale_running',phase='stale'
                          WHERE tranche_id=? AND status='running' AND COALESCE(heartbeat_ns,0) < ?""",
                       (tranche_id, stale_before)); db.commit()
            pending = db.execute("""SELECT function_id FROM tranche_items
                                    WHERE tranche_id = ? AND status IN
                                      ('ready_verified','interrupted','stale_running') ORDER BY ordinal""",
                                 (tranche_id,)).fetchall()
            missing_mappings = sorted({inventory_by_id[row[0]]["image"] for row in pending} - set(mappings))
            if missing_mappings:
                raise ValueError("missing image mappings for ready tranche: " + ", ".join(missing_mappings))
            write_lock = threading.Lock(); cancel_event = threading.Event()
            def checkpoint(function_id, phase, status="running", worker=None, finished=False):
                nonlocal database_seconds
                if cancel_event.is_set():
                    raise InterruptedError("tranche interrupted")
                with write_lock:
                    db_started = time.monotonic()
                    now_ns = time.time_ns()
                    with _immediate(db):
                        db.execute("""UPDATE tranche_items SET phase=?,status=?,worker_id=?,heartbeat_ns=?,
                                      started_ns=COALESCE(started_ns,?),finished_ns=CASE WHEN ? THEN ? ELSE finished_ns END,
                                      updated_ns=? WHERE tranche_id=? AND function_id=?""",
                                   (phase, status, worker or threading.current_thread().name, now_ns, now_ns,
                                    int(finished), now_ns, now_ns, tranche_id, function_id))
                    database_seconds += time.monotonic() - db_started
            def launch(function_id: str):
                with write_lock:
                    with _immediate(db):
                        claimed = db.execute("""UPDATE tranche_items SET status='running',phase='claimed',
                            worker_id=?,started_ns=COALESCE(started_ns,?),heartbeat_ns=?,updated_ns=?
                            WHERE tranche_id=? AND function_id=? AND status IN
                            ('ready_verified','interrupted','stale_running')""",
                            (threading.current_thread().name, time.time_ns(), time.time_ns(), time.time_ns(),
                             tranche_id, function_id)).rowcount
                if not claimed:
                    return function_id, "skipped_claimed", None, None, {}, None, None, "blocked", \
                        "row was claimed by another worker", None, {}
                callback = lambda value: checkpoint(function_id, value)
                try:
                    return _launch_one(args, context_cache, inventory_by_id[function_id], callback)
                except InterruptedError:
                    return function_id, "interrupted", None, None, {}, None, None, "interrupted", \
                        "worker stopped after tranche interruption", None, {}
                except KeyboardInterrupt:
                    return function_id, "interrupted", None, None, {}, None, None, "interrupted", \
                        "worker interrupted", {}, {}
                except Exception as error:
                    state = "boundary_rejected" if "preflight" in str(error).lower() else "failed"
                    return function_id, state, None, None, {}, None, None, "blocked", str(error), {}, {}

            with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
                compile_started = time.monotonic()
                futures = {pool.submit(launch, row[0]): row[0] for row in pending}
                launched = []
                heartbeat_stop = threading.Event()
                def heartbeat():
                    nonlocal database_seconds
                    while not heartbeat_stop.wait(5):
                        with write_lock:
                            db_started = time.monotonic(); now_ns = time.time_ns()
                            with _immediate(db):
                                db.execute("""UPDATE tranche_items SET heartbeat_ns=?,updated_ns=?
                                              WHERE tranche_id=? AND status='running'""",
                                           (now_ns, now_ns, tranche_id))
                            database_seconds += time.monotonic() - db_started
                heartbeat_thread = threading.Thread(target=heartbeat, name="n64dk-tranche-heartbeat", daemon=True)
                heartbeat_thread.start()
                try:
                    for future in as_completed(futures):
                        result = future.result(); launched.append(result)
                        (function_id, status, session_id, score, counts, historical_session,
                         historical_score, comparison, reason, recipe, timing) = result
                        with write_lock:
                            db_started = time.monotonic()
                            with _immediate(db):
                                db.execute("""UPDATE tranche_items SET status=?,phase='complete',session_id=?,reason=?,
                                  best_score=?,residual_counts=?,historical_session_id=?,historical_score=?,comparison=?,
                                  recipe=?,timing=?,finished_ns=?,heartbeat_ns=?,updated_ns=?
                                  WHERE tranche_id=? AND function_id=?""", (status, session_id, reason, score,
                                  json.dumps(counts, sort_keys=True), historical_session, historical_score, comparison,
                                  json.dumps(recipe, sort_keys=True) if recipe is not None else None,
                                  json.dumps(timing, sort_keys=True), time.time_ns(),
                                  time.time_ns(), time.time_ns(), tranche_id, function_id))
                            database_seconds += time.monotonic() - db_started
                except KeyboardInterrupt:
                    cancel_event.set()
                    for future in futures: future.cancel()
                    with write_lock:
                        with _immediate(db):
                            db.execute("""UPDATE tranche_items SET status='interrupted',phase='cancelled',updated_ns=?
                                          WHERE tranche_id=? AND status='running'""", (time.time_ns(), tranche_id))
                    raise
                finally:
                    heartbeat_stop.set(); heartbeat_thread.join()
                compile_seconds = time.monotonic() - compile_started
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
                  "preflight_exclusions": planning_exclusions,
                  "next": [item for item in items if item["status"] != "exact"][:20],
                  "timing": {"discovery_seconds": inventory.get("source_index", {}).get("elapsed_seconds", 0.0),
                             "context_seconds": context_cache.metrics.get("context_seconds", 0.0) if context_cache else 0.0,
                             "compilation_and_matching_seconds": round(compile_seconds, 6),
                             "database_seconds": round(database_seconds, 6),
                             "total_seconds": round(time.monotonic() - overall_started, 6)},
                  "project_context": context_cache.snapshot() if context_cache else None}
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
        from ..match.pipeline import object_cache_stats, pipeline_stats
        result["object_cache"] = object_cache_stats()
        result["pipeline_timing"] = pipeline_stats()
        return result
    finally:
        if context_cache is not None:
            context_cache.close()
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
            requested += ["needs-source", "source_missing"]
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
                           comparison, updated_ns,phase,worker_id,started_ns,heartbeat_ns,finished_ns,recipe,timing
                    FROM tranche_items
                    WHERE {' AND '.join(where)} ORDER BY ordinal LIMIT ?"""
        rows = db.execute(query, (*values, max(0, args.limit))).fetchall()
        items = []; registry = SessionRegistry(tranche[0])
        try:
            for row in rows:
                item = dict(zip(("ordinal", "image", "name", "vram", "size", "status", "session_id",
                                 "reason", "best_score", "residual_counts", "historical_session_id",
                                 "historical_score", "comparison", "updated_ns", "phase", "worker_id",
                                 "started_ns", "heartbeat_ns", "finished_ns", "recipe", "timing"), row))
                item["residual_counts"] = json.loads(item["residual_counts"] or "{}")
                item["recipe"] = json.loads(item["recipe"] or "null")
                item["timing"] = json.loads(item["timing"] or "{}")
                if item["session_id"]:
                    from ..match.registry import resolve_store
                    from ..match.session import SessionStore
                    store = SessionStore(resolve_store(item["session_id"], tranche[0]))
                    try:
                        current = store.best(item["session_id"])
                        history = registry.same_target(store.context(item["session_id"]), refresh=False)
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
        finally:
            registry.close()
        counts = dict(db.execute("""SELECT status, COUNT(*) FROM tranche_items
                                   WHERE tranche_id = ? GROUP BY status""", (args.tranche_id,)).fetchall())
        result = {"tranche_id": args.tranche_id, "project": tranche[0],
                  "inventory_digest": tranche[1], "jobs": tranche[2], "status": counts,
                  "created_ns": tranche[3], "updated_ns": tranche[4],
                  "historical_observations_found": sum(bool(item.get("historical_session_id")) for item in items)}
        aggregate = db.execute("""SELECT COUNT(*), COUNT(candidate_source), COUNT(DISTINCT candidate_source),
                                  COUNT(session_id), COUNT(DISTINCT session_id),
                                  SUM(CASE WHEN status='exact' THEN 1 ELSE 0 END),
                                  SUM(CASE WHEN comparison='improved' THEN 1 ELSE 0 END),
                                  SUM(CASE WHEN comparison='tied' THEN 1 ELSE 0 END)
                           FROM tranche_items WHERE tranche_id=?""", (args.tranche_id,)).fetchone()
        result["quality_metrics"] = dict(zip(("catalogue_targets_considered", "with_candidate_source",
            "unique_candidate_sources", "candidates_compiled", "unique_sessions", "exact_matches",
            "improved_frontiers", "unchanged_frontiers"), aggregate))
        result["quality_metrics"].update({"near_matches": counts.get("near_match", 0),
            "preflight_rejected": counts.get("boundary_rejected", 0),
            "source_missing": counts.get("source_missing", 0),
            "mapping_ambiguous": counts.get("mapping_ambiguous", 0)})
        if not args.summary_only:
            result["items"] = items
        return result
    finally:
        db.close()


quickwin_sweep_status.arguments = _sweep_status_args


def _tranche_run_args(p):
    p.add_argument("--project", default=".")
    p.add_argument("--limit", type=int, default=500)
    p.add_argument("--jobs", type=int, default=16)
    p.add_argument("--image-file", action="append", default=[], metavar="NAME=PATH")
    p.add_argument("--image", action="append", default=[])
    p.add_argument("--all-images", action="store_true")
    p.add_argument("--state-root", default=".n64dk/quickwin-sweeps")
    p.add_argument("--preflight", action="store_true")
    p.add_argument("--infer-recipes", action="store_true")
    p.add_argument("--run-ready", action="store_true")
    p.add_argument("--explore-top", type=int, default=0)
    p.add_argument("--prepare-exact", action="store_true")
    p.add_argument("--gate-exact", action="store_true")
    p.add_argument("--checkpoint-every", type=int, default=1)
    p.add_argument("--no-draft-missing", action="store_false", dest="draft_missing", default=True,
                   help="leave source-less verified intervals queued instead of generating m2c drafts")
    p.add_argument("--m2c-context", help="preprocessed declarations/types supplied to m2c drafts")
    p.add_argument("--pipeline")
    p.add_argument("--flags")
    p.add_argument("--report")


@command("tranche-run", "Run cached planning, verified baselines, bounded exploration and winner preparation")
def tranche_run(args):
    from argparse import Namespace
    if args.checkpoint_every != 1:
        raise ValueError("durable tranche execution requires --checkpoint-every 1")
    sweep_args = Namespace(project=args.project, all_images=args.all_images, image=args.image,
        limit=args.limit, jobs=args.jobs, state_root=args.state_root, resume=None, report=args.report,
        run=args.run_ready, image_file=args.image_file, pipeline=args.pipeline, flags=args.flags,
        refresh_sources=False, run_ready_only=False, details=False, format=getattr(args, "format", "json"),
        draft_missing=args.draft_missing, m2c_context=args.m2c_context)
    result = quickwin_sweep(sweep_args); tranche_id = result["tranche_id"]
    db = _state(Path(args.state_root)); explored = []; prepared = []
    try:
        if args.explore_top:
            sessions = db.execute("""SELECT session_id,name,image FROM tranche_items WHERE tranche_id=?
                AND status='near_match' AND session_id IS NOT NULL
                ORDER BY best_score IS NULL,best_score LIMIT ?""",
                (tranche_id, args.explore_top)).fetchall()
            from .match import match_session_explore
            for session_id, name, image in sessions:
                try:
                    value = match_session_explore(Namespace(session_id=session_id, project=args.project,
                        state_root=None, strategy="residual-guided", jobs=args.jobs, rounds=2,
                        variants_per_round=8, stop_on_exact=True, best_details=False,
                        target_window=None, freeze_prefix=None, freeze_suffix=None,
                        dimensions="prototype,lifetime,narrowing,control-flow", format="json"))
                    explored.append({"function": name, "session_id": session_id,
                                     "exact": value["exact"], "best_score": value["best_score"]})
                    if value["exact"]:
                        db.execute("""UPDATE tranche_items SET status='exact',best_score=?,updated_ns=?
                                      WHERE tranche_id=? AND session_id=?""",
                                   (value["best_score"], time.time_ns(), tranche_id, session_id)); db.commit()
                except Exception as error: explored.append({"function": name, "error": str(error)})
        if args.prepare_exact:
            exact = db.execute("SELECT session_id,name,image FROM tranche_items WHERE tranche_id=? AND status='exact'",
                               (tranche_id,)).fetchall()
            prepared = [{"function": name, "image": image, "session_id": session,
                "command": f"n64dk match-session-prepare-winner {session} .n64dk/winners/{image}/{name} --project {Path(args.project).resolve()}"}
                for session, name, image in exact]
        counts = dict(db.execute("SELECT status,COUNT(*) FROM tranche_items WHERE tranche_id=? GROUP BY status",
                                 (tranche_id,)).fetchall())
    finally: db.close()
    result.update({"exploration": explored, "exact_winner_queue": prepared,
        "gate_state": "commands-prepared" if args.gate_exact else "not-requested",
        "performance": {**result.get("timing", {}),
            "exact_matches_per_wall_hour": round(counts.get("exact", 0) * 3600 /
                max(result.get("timing", {}).get("total_seconds", 0.001), 0.001), 3)},
        "remaining_by_state": counts, "checkpoint_every": args.checkpoint_every})
    return result


tranche_run.arguments = _tranche_run_args
