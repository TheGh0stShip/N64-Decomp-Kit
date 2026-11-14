"""Content-addressed historical matching observation index."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path


FUNCTION = re.compile(r"func_[0-9A-Fa-f]{8}")


def _source_digest(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    normalized = re.sub(r"/\*.*?\*/|//[^\n]*|\s+", "", text, flags=re.S)
    return hashlib.sha256(normalized.encode()).hexdigest()


def _walk(value, trail="root"):
    if isinstance(value, dict):
        yield trail, value
        for key, child in value.items():
            yield from _walk(child, f"{trail}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, f"{trail}[{index}]")


def _integer(value):
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _opcode(text) -> str:
    return str(text or "").strip().split(None, 1)[0] if text else "missing"


def _residual(value: dict) -> str:
    """Address-independent typed residual fingerprint."""
    diff = value.get("diff") if isinstance(value.get("diff"), dict) else value
    counts = diff.get("counts") or value.get("residual_counts") or {}
    size = _integer(diff.get("target_size")) or _integer(value.get("size")) or 1
    transitions = []
    for entry in diff.get("entries", []) if isinstance(diff.get("entries"), list) else []:
        offset = _integer(entry.get("target_offset", entry.get("offset"))) or 0
        transitions.append({"kind": entry.get("kind"), "from": _opcode(entry.get("compiled")),
                            "to": _opcode(entry.get("retail")),
                            "position": min(3, (4 * offset) // max(1, size))})
    result = {"counts": counts}
    if transitions:
        result["transitions"] = transitions
    if diff.get("register_swap"):
        result["register_flow"] = sorted(diff["register_swap"].items())
    return json.dumps(result, sort_keys=True)


class ResultIndex:
    def __init__(self, database: str | Path):
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path)
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
            digest TEXT NOT NULL, indexed_ns INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS sources (
            digest TEXT NOT NULL, path TEXT NOT NULL, text_digest TEXT NOT NULL,
            size INTEGER NOT NULL, PRIMARY KEY(digest,path));
          CREATE TABLE IF NOT EXISTS observations (
            observation_id TEXT PRIMARY KEY, file_path TEXT NOT NULL, json_path TEXT NOT NULL,
            function_name TEXT, address INTEGER, size INTEGER, score INTEGER, exact INTEGER NOT NULL,
            source_path TEXT, source_digest TEXT, image_digest TEXT, vram_delta INTEGER,
            target_digest TEXT, residual TEXT NOT NULL, validity TEXT NOT NULL,
            provenance TEXT NOT NULL, payload TEXT NOT NULL, observed_ns INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS observations_function ON observations(function_name,score);
          CREATE INDEX IF NOT EXISTS observations_validity ON observations(validity,exact,score);
        """)
        self.db.commit()

    def close(self):
        self.db.close()

    def _inventory_maps(self, inventory: dict | None):
        by_name, by_addr = {}, {}
        for row in (inventory or {}).get("functions", []):
            by_name.setdefault(row["name"], []).append(row)
            by_addr.setdefault(int(row["vram"], 0), []).append(row)
        return by_name, by_addr

    def index(self, roots: list[str], inventory: dict | None = None, refresh: bool = False) -> dict:
        by_name, by_addr = self._inventory_maps(inventory)
        scanned = changed = observations = sources = invalid = skipped_large = 0
        for root_value in roots:
            root = Path(root_value).expanduser().resolve()
            paths = [root] if root.is_file() else root.rglob("*") if root.exists() else []
            for path in paths:
                if path.resolve() == self.path.resolve() or not path.is_file() or any(part in {".git", ".venv", "venv", "site-packages"}
                                             for part in path.parts):
                    continue
                if path.suffix.lower() not in {".json", ".log", ".txt", ".c", ".h", ".sqlite"}:
                    continue
                scanned += 1
                stat = path.stat()
                if (path.suffix.lower() == ".json" and stat.st_size > 2_000_000 and
                        not any(word in path.name.lower() for word in
                                ("match", "score", "result", "session", "candidate"))):
                    skipped_large += 1
                    continue
                old = self.db.execute("SELECT size,mtime_ns FROM files WHERE path=?", (str(path),)).fetchone()
                if old and not refresh and old == (stat.st_size, stat.st_mtime_ns):
                    continue
                raw = path.read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                self.db.execute("DELETE FROM observations WHERE file_path=?", (str(path),))
                if path.suffix.lower() in {".c", ".h"}:
                    text_digest = _source_digest(raw)
                    self.db.execute("INSERT OR REPLACE INTO sources VALUES (?,?,?,?)",
                                    (digest, str(path), text_digest, len(raw)))
                    sources += 1
                elif path.suffix.lower() == ".sqlite":
                    try:
                        session_db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                        tables = {row[0] for row in session_db.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'")}
                        if {"sessions", "session_candidates"} <= tables:
                            for session_id, context_raw, candidate_id, source_digest, exact, score, counts, outcome, created in session_db.execute(
                                "SELECT s.session_id,s.context,c.candidate_id,c.source_digest,c.exact,c.score,c.counts,c.outcome,c.created_ns "
                                "FROM sessions s JOIN session_candidates c ON c.session_id=s.session_id"):
                                context = json.loads(context_raw); payload = json.loads(outcome)
                                function = context.get("function")
                                if not function:
                                    found = FUNCTION.search(str(context.get("source_name", "")))
                                    function = found.group(0) if found else None
                                address, size = _integer(context.get("addr")), _integer(context.get("size"))
                                delta = _integer(context.get("vram_delta"))
                                rows = by_name.get(function, []) if function else by_addr.get(address, [])
                                validity = "unknown_provenance"
                                if rows:
                                    expected = int(rows[0]["section_vram"], 0) - int(rows[0]["section_rom"], 0)
                                    validity = ("stale_mapping" if delta is not None and delta != expected else
                                                "boundary_changed" if size is not None and size != int(rows[0]["size"]) else
                                                "valid_current_target")
                                observation_id = hashlib.sha256(f"{path}:{session_id}:{candidate_id}".encode()).hexdigest()[:24]
                                residual = _residual(payload)
                                self.db.execute("INSERT OR REPLACE INTO observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                    (observation_id, str(path), f"session:{session_id}:{candidate_id}", function,
                                     address, size, score, exact, None, source_digest, context.get("rom_sha256"),
                                     delta, context.get("target_text_sha256"), residual, validity, "session-store",
                                     json.dumps(payload, sort_keys=True, default=str), created))
                                observations += 1
                        session_db.close()
                    except sqlite3.DatabaseError:
                        pass
                else:
                    try:
                        parsed = json.loads(raw)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        parsed = None
                    if parsed is not None:
                        for json_path, value in _walk(parsed):
                            if not any(key in value for key in ("score", "exact", "best_score", "best_diff")):
                                continue
                            score = _integer(value.get("score", value.get("best_score")))
                            if score is None and isinstance(value.get("diff"), dict):
                                score = _integer(value["diff"].get("score"))
                            exact = bool(value.get("exact", score == 0))
                            source_path = value.get("source") or value.get("source_path")
                            if not source_path and isinstance(value.get("name"), str) and value["name"].endswith((".c", ".h")):
                                source_path = value["name"]
                            function = value.get("function") or value.get("name")
                            if not (isinstance(function, str) and FUNCTION.fullmatch(function)):
                                found = FUNCTION.search(" ".join(str(x) for x in
                                    (function or "", source_path or "", path.name)))
                                function = found.group(0) if found else None
                            address = _integer(value.get("addr", value.get("vram")))
                            size = _integer(value.get("size", value.get("target_size")))
                            delta = _integer(value.get("vram_delta"))
                            image_digest = value.get("rom_sha256") or value.get("image_digest")
                            target_digest = value.get("target_text_sha256") or value.get("target_digest")
                            residual = _residual(value)
                            rows = by_name.get(function, []) if function else by_addr.get(address, [])
                            validity = "unknown_provenance"
                            if rows:
                                expected = int(rows[0]["section_vram"], 0) - int(rows[0]["section_rom"], 0)
                                if delta is not None and delta != expected:
                                    validity = "stale_mapping"
                                    invalid += 1
                                elif size is not None and size != int(rows[0]["size"]):
                                    validity = "boundary_changed"
                                    invalid += 1
                                elif delta is not None or target_digest:
                                    validity = "valid_current_target"
                            source_digest = value.get("source_digest")
                            observation_id = hashlib.sha256(
                                f"{path}:{json_path}:{digest}".encode()).hexdigest()[:24]
                            self.db.execute("INSERT OR REPLACE INTO observations VALUES "
                                "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (observation_id, str(path), json_path, function, address, size, score,
                                 int(exact), str(source_path) if source_path else None, source_digest,
                                 image_digest, delta, target_digest, residual, validity, "json",
                                 json.dumps(value, sort_keys=True, default=str), stat.st_mtime_ns))
                            observations += 1
                    elif path.suffix.lower() in {".log", ".txt"}:
                        text = raw.decode("utf-8", "replace")
                        for line_number, line in enumerate(text.splitlines(), 1):
                            found = FUNCTION.search(line)
                            score_found = re.search(r"\b(?:score|best(?:_score)?)\s*[:= ]\s*(\d+)", line, re.I)
                            if not found or not score_found:
                                continue
                            function, score = found.group(0), int(score_found.group(1))
                            observation_id = hashlib.sha256(f"{path}:{line_number}:{line}".encode()).hexdigest()[:24]
                            self.db.execute("INSERT OR REPLACE INTO observations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                                (observation_id, str(path), f"line:{line_number}", function, None, None,
                                 score, int(score == 0), None, None, None, None, None, "{}",
                                 "unknown_provenance", "log-summary", json.dumps({"line": line}), stat.st_mtime_ns))
                            observations += 1
                self.db.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?,?)",
                                (str(path), stat.st_size, stat.st_mtime_ns, digest, time.time_ns()))
                changed += 1
        self._resolve_sources()
        self.db.commit()
        return {"database": str(self.path.resolve()), "scanned": scanned, "changed": changed,
                "observations": observations, "sources": sources, "invalid": invalid,
                "skipped_large_unrelated_json": skipped_large}

    def _resolve_sources(self):
        rows = self.db.execute("SELECT observation_id,source_path,source_digest FROM observations").fetchall()
        for observation_id, source_path, digest in rows:
            if source_path and Path(source_path).is_file():
                raw = Path(source_path).read_bytes()
                digest = hashlib.sha256(raw).hexdigest()
                self.db.execute("UPDATE observations SET source_digest=? WHERE observation_id=?",
                                (digest, observation_id))
            if digest:
                equivalent = self.db.execute("SELECT path FROM sources WHERE digest=? LIMIT 1", (digest,)).fetchone()
                if equivalent and (not source_path or not Path(source_path).is_file()):
                    payload = json.loads(self.db.execute(
                        "SELECT payload FROM observations WHERE observation_id=?", (observation_id,)).fetchone()[0])
                    payload["resolved_source"] = equivalent[0]
                    payload["source_resolution"] = "exact_textual_equivalent"
                    self.db.execute("UPDATE observations SET source_path=?,payload=? WHERE observation_id=?",
                                    (equivalent[0], json.dumps(payload, sort_keys=True), observation_id))
            elif source_path and not Path(source_path).is_file():
                basename = Path(source_path).name
                equivalent = self.db.execute("SELECT path FROM sources WHERE path LIKE ? ORDER BY path LIMIT 1",
                                             (f"%/{basename}",)).fetchone()
                if equivalent:
                    payload = json.loads(self.db.execute(
                        "SELECT payload FROM observations WHERE observation_id=?", (observation_id,)).fetchone()[0])
                    payload["resolved_source"] = equivalent[0]
                    payload["source_resolution"] = "basename_candidate_unverified"
                    self.db.execute("UPDATE observations SET source_path=?,payload=? WHERE observation_id=?",
                                    (equivalent[0], json.dumps(payload, sort_keys=True), observation_id))

    def query(self, function=None, max_score=None, exact_only=False, validity=None,
              stale_mapping=False, missing_source=False, timeline=False, limit=100):
        sql = "SELECT observation_id,file_path,function_name,address,size,score,exact,source_path,source_digest,residual,validity,payload,observed_ns FROM observations WHERE 1=1"
        args = []
        if function:
            sql += " AND function_name=?"; args.append(function)
        if max_score is not None:
            sql += " AND score<=?"; args.append(max_score)
        if exact_only:
            sql += " AND exact=1"
        if stale_mapping:
            sql += " AND validity IN ('stale_mapping','boundary_changed','stale_image')"
        elif validity:
            sql += " AND validity=?"; args.append(validity)
        else:
            sql += " AND validity NOT IN ('stale_mapping','boundary_changed','stale_image')"
        sql += " ORDER BY " + ("observed_ns" if timeline else "exact DESC,score IS NULL,score,observed_ns DESC")
        result = []
        for row in self.db.execute(sql, args):
            item = dict(zip(("observation_id","file","function","address","size","score","exact",
                             "source","source_digest","residual","validity","payload","observed_ns"), row))
            item["exact"] = bool(item["exact"])
            item["residual"] = json.loads(item["residual"])
            item["payload"] = json.loads(item["payload"])
            if missing_source and item["source"] and Path(item["source"]).exists():
                continue
            result.append(item)
            if len(result) >= limit:
                break
        return result

    def clusters(self, max_score=32, limit=100):
        rows = self.query(max_score=max_score, limit=100000)
        groups: dict[str, list[dict]] = {}
        for row in rows:
            key = json.dumps(row["residual"], sort_keys=True)
            if key == "{}":
                continue
            groups.setdefault(key, []).append(row)
        output = []
        for residual, members in groups.items():
            functions = sorted({row["function"] for row in members if row["function"]})
            if len(functions) < 2:
                continue
            cluster_id = hashlib.sha256(residual.encode()).hexdigest()[:16]
            fingerprint = json.loads(residual)
            transitions = fingerprint.get("transitions", [])
            forms = []
            if any(row["from"].rstrip("l") == row["to"].rstrip("l") and
                   row["from"] != row["to"] for row in transitions):
                forms += ["branch polarity", "conditional selection shape", "direct argument selection"]
            if fingerprint.get("register_flow") or fingerprint.get("counts", {}).get("register"):
                forms += ["temporary lifetime and ownership", "assignment inside call argument"]
            if not forms:
                forms = ["typed source form inferred from residual transitions"]
            output.append({"cluster_id": cluster_id, "residual": json.loads(residual),
                           "functions": functions, "observations": len(members),
                           "best_score": min(row["score"] for row in members if row["score"] is not None),
                           "candidate_forms": list(dict.fromkeys(forms))})
        output.sort(key=lambda row: (-len(row["functions"]), row["best_score"]))
        return output[:limit]

    def brackets(self, function: str) -> list[dict]:
        rows = self.query(function=function, limit=1000)
        candidates = []
        for row in rows:
            transitions = row["residual"].get("transitions", [])
            key = {(item.get("position"), item.get("kind"), item.get("from"), item.get("to"))
                   for item in transitions}
            if key:
                candidates.append((row, key))
        pairs = []
        for index, (left, left_set) in enumerate(candidates):
            for right, right_set in candidates[index + 1:]:
                if left_set == right_set or left["source_digest"] == right["source_digest"]:
                    continue
                left_only, right_only = left_set - right_set, right_set - left_set
                if not left_only or not right_only:
                    continue
                pairs.append({"candidate_a": left["observation_id"],
                              "candidate_b": right["observation_id"],
                              "a_remaining_components": [list(x) for x in sorted(left_only, key=str)],
                              "b_remaining_components": [list(x) for x in sorted(right_only, key=str)],
                              "shared_components": [list(x) for x in sorted(left_set & right_set, key=str)],
                              "likely_discriminator": "typed data-flow edge or promoted expression mode"})
        return pairs[:20]
