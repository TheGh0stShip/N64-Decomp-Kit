"""Reconcile exact matching-session candidates with manifests, and audit workspace litter.

Everything here is read-only except :func:`workspace_clean` with ``apply=True``.

* :func:`stranded_exacts` lists every ``exact`` candidate in every session store and
  classifies it against the manifests (integrated, covered elsewhere, stale, duplicate,
  or *stranded*: proven exact but never integrated).
* :func:`workspace_audit` / :func:`workspace_clean` find and remove compiler dumps
  (GCC ``-da`` passes, ``*.raw.s``, stray root objects) that are not tracked by Git.

Manifest rows are ``ROM_START  SIZE  SOURCE ...`` in the offset space of one image. They are
bound only by explicit project configuration or ``bindings``. Filenames are labels rather
than coordinate evidence; an unbound manifest is reported and never used for classification.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

SQLITE_MAGIC = b"SQLite format 3\x00"
CLASSES = ("integrated", "covered-different-source", "covered-by-aggregate",
           "stale-target", "unverified-proof", "duplicate", "stranded")
DUMP_SUFFIXES = ("rtl", "jump", "cse", "loop", "cse2", "flow", "combine", "sched", "lreg",
                 "greg", "sched2", "jump2", "dbr", "stack")
DEFAULT_EXCLUDES = (".git", ".n64dk", "build", "venv", "node_modules")
_HEX = re.compile(r"^0x[0-9A-Fa-f]+$")
_DUMP = re.compile(r"^.+\.(c|i)\.(" + "|".join(DUMP_SUFFIXES) + r")$")


def _digest(data: bytes) -> str:
    """Same digest as ``ContentCache.digest`` (used for ``source_digest``)."""
    return hashlib.sha256(data).hexdigest()


def _connect_ro(path: Path) -> sqlite3.Connection:
    """Open without writing anything: a WAL database with no ``-wal`` file has no writer
    attached, and opening it ``mode=ro`` would still create ``-wal``/``-shm`` sidecars, so it
    is opened ``immutable`` instead."""
    path = Path(path).resolve()
    with open(path, "rb") as stream:
        header = stream.read(20)
    quiet = header[18:20] == b"\x02\x02" and not Path(f"{path}-wal").exists()
    mode = "immutable=1" if quiet else "mode=ro"
    return sqlite3.connect(f"{path.as_uri()}?{mode}", uri=True, timeout=1.0)


@dataclass
class StoreScan:
    stores: list[Path] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


def find_stores(project: Path, extra: Iterable[Path] = ()) -> StoreScan:
    """Every SQLite file under ``<project>/.n64dk`` (recursive) plus ``extra`` that holds a
    ``session_candidates`` table; unreadable files go to ``skipped`` with the reason."""
    scan = StoreScan()
    state = Path(project) / ".n64dk"
    paths = sorted(p for p in state.rglob("*") if p.is_file()) if state.is_dir() else []
    extra = [Path(p) for p in extra]
    seen = set()
    for path in [*paths, *extra]:
        key = path.resolve()
        if key in seen:
            continue
        seen.add(key)
        try:
            with open(path, "rb") as stream:
                if stream.read(16) != SQLITE_MAGIC:
                    if path in extra:
                        scan.skipped.append({"path": str(path), "reason": "not an SQLite file"})
                    continue
            con = _connect_ro(path)
            try:
                hit = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND "
                                  "name='session_candidates'").fetchone()
            finally:
                con.close()
        except (OSError, sqlite3.Error) as exc:
            scan.skipped.append({"path": str(path), "reason": f"{type(exc).__name__}: {exc}"})
            continue
        if hit:
            scan.stores.append(path)
    return scan


def _truthy(value) -> bool:
    if isinstance(value, (bytes, str)):
        value = value.strip().lower() if isinstance(value, str) else value.decode().strip().lower()
        return value in ("1", "true", "yes")
    return bool(value)


def _int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def image_token(image: str | None) -> str | None:
    if not image:
        return None
    stem = Path(str(image)).name.split(".")[0]
    return re.sub(r"[^0-9a-z]", "", stem.lower()) or None


def _target_of(context: dict) -> dict:
    """Target identity from a session context; absent fields are None (never guessed)."""
    ctx = context if isinstance(context, dict) else {}
    vram = _int(ctx.get("addr", ctx.get("vram")))
    size = _int(ctx.get("size"))
    delta = _int(ctx.get("vram_delta"))
    rom_offset = _int(ctx.get("rom_offset"))
    if rom_offset is None and vram is not None and delta is not None:
        rom_offset = vram - delta
    # Prefer an explicit logical identity.  A physical filename is provenance, not a binding:
    # ``overlay4_composite.z64`` must not silently invent the logical token
    # ``overlay4composite`` when the project declared ``overlay4``.
    image = (ctx.get("inventory_image") or ctx.get("image_name") or
             ctx.get("logical_image") or ctx.get("image_identity") or
             ctx.get("image") or ctx.get("rom"))
    name = ctx.get("function") or ctx.get("inventory_name") or ctx.get("name")
    if not name and ctx.get("source_name"):
        name = Path(str(ctx["source_name"])).stem
    return {"name": name, "vram": vram, "size": size, "image": image,
            "image_token": image_token(image), "rom_offset": rom_offset,
            "target_digest": ctx.get("target_text_sha256") or ctx.get("target_digest")}


def parse_manifest(path: Path, project: Path) -> list[dict]:
    """``0xSTART<TAB>0xSIZE<TAB>SOURCE...`` rows; other rows are ignored."""
    rows = []
    for lineno, line in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split("\t") if "\t" in line else line.split()
        if len(cols) >= 3 and _HEX.match(cols[0]) and _HEX.match(cols[1]) and not _HEX.match(cols[2]):
            rows.append({"start": int(cols[0], 16), "size": int(cols[1], 16), "source": cols[2],
                         "path": Path(project) / cols[2], "manifest": str(path), "line": lineno})
    return rows


def is_manifest(path: Path) -> bool:
    try:
        return bool(parse_manifest(path, Path(".")))
    except (OSError, UnicodeError):
        return False


def _bind(manifests: list[Path], tokens: set[str], bindings: dict | None) -> tuple[dict[str, list[Path]], list[Path]]:
    """Explicit image token -> manifests plus unbound manifests (which fail closed)."""
    out: dict = {}; unbound = []
    for path in manifests:
        explicit = (bindings or {}).get(str(path)) or (bindings or {}).get(str(Path(path).resolve()))
        if explicit is None:
            unbound.append(Path(path)); continue
        token = image_token(explicit)
        if token not in tokens:
            unbound.append(Path(path)); continue
        out.setdefault(token, []).append(Path(path))
    return out, unbound


def _cache_object(store: Path, digest: str) -> Path | None:
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return None
    return Path(store).parent / "cache" / "objects" / digest[:2] / digest[2:]


def export_source(store_path: Path, session_id: str, candidate_id: str) -> str | None:
    """The candidate's source text from the store's content cache (read-only)."""
    try:
        con = _connect_ro(store_path)
        try:
            row = con.execute("SELECT source_digest FROM session_candidates WHERE session_id=? "
                              "AND candidate_id=?", (session_id, candidate_id)).fetchone()
        finally:
            con.close()
    except sqlite3.Error:
        return None
    obj = _cache_object(store_path, row[0]) if row else None
    if obj is None or not obj.is_file():
        return None
    data = obj.read_bytes()
    if _digest(data) != row[0]:
        return None
    return data.decode("utf-8", errors="replace")


def _read_exacts(store: Path) -> list[dict]:
    con = _connect_ro(store)
    try:
        cols = {r[1] for r in con.execute("PRAGMA table_info(sessions)")}
        updated = "s.updated_ns" if "updated_ns" in cols else "0"
        rows = con.execute(f"""
            SELECT c.session_id, c.candidate_id, c.source_digest, c.pipeline, c.flags, c.exact,
                   c.score, c.label, c.outcome, s.context, {updated}
            FROM session_candidates c LEFT JOIN sessions s ON s.session_id = c.session_id
        """).fetchall()
    finally:
        con.close()
    out = []
    for sid, cid, digest, pipeline, flags, exact, score, label, outcome, ctx, upd in rows:
        if not _truthy(exact):
            continue
        try:
            context = json.loads(ctx) if ctx else None
        except (TypeError, ValueError):
            context = None
        try:
            flags = json.loads(flags) if isinstance(flags, str) else flags
        except ValueError:
            pass
        try:
            outcome = json.loads(outcome) if isinstance(outcome, str) else (outcome or {})
        except ValueError:
            outcome = {}
        proof = outcome.get("proof") if isinstance(outcome, dict) else None
        out.append({"store": str(store), "session_id": sid, "candidate_id": cid,
                    "source_digest": digest, "pipeline": pipeline, "flags": flags,
                    "score": score, "label": label, "updated_ns": upd or 0,
                    "strict_proof": isinstance(proof, dict) and proof.get("verdict") == "exact",
                    "proof": proof,
                    "context_keys": sorted(context) if isinstance(context, dict) else None,
                    **_target_of(context)})
    return out


def stranded_exacts(project: Path, manifests: list[Path], stores=None,
                    image_bytes: Callable | None = None, bindings: dict | None = None) -> dict:
    """Classify every exact candidate; see the module docstring for manifest binding."""
    project = Path(project)
    scan = stores if isinstance(stores, StoreScan) else (
        StoreScan(list(map(Path, stores))) if stores is not None else find_stores(project))
    skipped = list(scan.skipped)
    items: list[dict] = []
    for store in scan.stores:
        try:
            items.extend(_read_exacts(store))
        except sqlite3.Error as exc:
            skipped.append({"path": str(store), "reason": f"{type(exc).__name__}: {exc}"})
    tokens = {i["image_token"] for i in items if i["image_token"]}
    bound, unbound = _bind(list(manifests), tokens, bindings)
    claimed = {t for t in bound if t}
    rows_by_token: dict = {}
    for token, paths in bound.items():
        for path in paths:
            try:
                rows_by_token.setdefault(token, []).extend(parse_manifest(path, project))
            except (OSError, UnicodeError) as exc:
                skipped.append({"path": str(path), "reason": f"manifest: {exc}"})
    digests: dict[Path, str | None] = {}

    def disk_digest(path: Path) -> str | None:
        if path not in digests:
            digests[path] = _digest(path.read_bytes()) if path.is_file() else None
        return digests[path]

    # Duplicates: same target identity; the newest session wins.
    def identity(item):
        if item["rom_offset"] is not None and item["size"] is not None:
            return (item["image_token"], item["rom_offset"], item["size"])
        if item["vram"] is not None:
            return (item["image_token"], "vram", item["vram"], item["size"])
        return ("candidate", item["store"], item["session_id"], item["candidate_id"])

    items.sort(key=lambda i: (-int(i["updated_ns"] or 0), i["store"], i["session_id"], i["candidate_id"]))
    primary: dict = {}
    for item in items:
        item.update({"class": None, "target_checked": False, "manifest_rows": [], "duplicates": []})
        key = identity(item)
        if key in primary:
            first = primary[key]
            item["class"], item["duplicate_of"] = "duplicate", first["candidate_id"]
            first["duplicates"].append({k: item[k] for k in ("store", "session_id", "candidate_id")})
            continue
        primary[key] = item
        item["class"] = ("unverified-proof" if not item["strict_proof"] else
                         _classify(item, rows_by_token, claimed, image_bytes, disk_digest))
    summary = {c: 0 for c in CLASSES}
    for item in items:
        summary[item["class"]] += 1
    replay = ("store", "session_id", "candidate_id", "source_digest", "pipeline", "flags",
              "name", "vram", "size", "image", "rom_offset", "target_digest", "duplicates")
    queue = [{k: i[k] for k in replay} for i in items if i["class"] == "stranded"]
    queue.sort(key=lambda q: (-(q["size"] or 0), str(q["name"])))
    return {"stores": [str(s) for s in scan.stores], "skipped": skipped,
            "bindings": {str(t): [str(p) for p in ps] for t, ps in bound.items()},
            "unbound_manifests": [str(path) for path in unbound],
            "summary": summary, "exact_candidates": len(items), "queue": queue,
            "uninterpreted": sum(1 for i in items if i["rom_offset"] is None or i["size"] is None),
            "items": items}


def _classify(item, rows_by_token, claimed, image_bytes, disk_digest) -> str:
    start, size = item["rom_offset"], item["size"]
    if start is None or size is None:
        return "stranded"   # cannot place it; surfaced via ``uninterpreted``
    token = item["image_token"] if item["image_token"] in claimed else None
    rows = rows_by_token.get(token, [])
    if image_bytes is not None and item["image"] and item["target_digest"]:
        data = image_bytes(item["image"], start, size)
        if data is not None:
            item["target_checked"] = True
            if len(data) != size or _digest(data) != item["target_digest"]:
                item["stale_reason"] = "image bytes changed"
                return "stale-target"
    exact = [r for r in rows if r["start"] == start and r["size"] == size]
    if exact:
        item["manifest_rows"] = [f"{r['manifest']}:{r['line']}" for r in exact]
        same = any(disk_digest(r["path"]) == item["source_digest"] for r in exact)
        return "integrated" if same else "covered-different-source"
    resized = [r for r in rows if r["start"] == start]
    if resized:
        item["manifest_rows"] = [f"{r['manifest']}:{r['line']}" for r in resized]
        item["stale_reason"] = f"manifest size 0x{resized[0]['size']:X} != session size 0x{size:X}"
        return "stale-target"
    outer = [r for r in rows if r["start"] < start and start + size <= r["start"] + r["size"]]
    if outer:
        item["manifest_rows"] = [f"{r['manifest']}:{r['line']}" for r in outer]
        return "covered-by-aggregate"
    overlap = [r for r in rows if r["start"] < start + size and start < r["start"] + r["size"]]
    if overlap:   # partial overlap: report, but nothing integrates this exact interval
        item["manifest_rows"] = [f"{r['manifest']}:{r['line']}" for r in overlap]
        item["partial_overlap"] = True
    return "stranded"


def file_image_bytes(image, offset: int, size: int) -> bytes | None:
    """Default ``image_bytes`` reader: the image is a file path; None when unavailable."""
    try:
        with open(image, "rb") as stream:
            stream.seek(offset)
            return stream.read(size)
    except (OSError, ValueError, TypeError):
        return None


# ---------------------------------------------------------------- workspace litter

def _kind(rel: Path, at_root: bool) -> str | None:
    name = rel.name
    if _DUMP.match(name):
        return "gcc-dump"
    if name.endswith(".raw.s"):
        return "raw-asm"
    if at_root and (name.endswith(".o") or name == "a.out"):
        return "root-object"
    return None


def _tracked(project: Path) -> set[str] | None:
    try:
        proc = subprocess.run(["git", "-C", str(project), "ls-files", "-z"],
                              capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return {p for p in proc.stdout.decode(errors="surrogateescape").split("\0") if p}


def _excluded(name: str, excludes: Iterable[str]) -> bool:
    return name in excludes or name.startswith(".venv")


def workspace_audit(project: Path, state_dir: str = ".n64dk",
                    excludes: Iterable[str] = DEFAULT_EXCLUDES, max_entries: int = 500_000) -> dict:
    project = Path(project)
    excludes = set(excludes) | {state_dir}
    tracked = _tracked(project)
    found, seen, truncated = [], 0, False
    for root, dirs, files in os.walk(project):
        dirs[:] = sorted(d for d in dirs if not _excluded(d, excludes)
                         and not os.path.islink(os.path.join(root, d)))
        seen += len(dirs) + len(files)
        if seen > max_entries:
            truncated = True
            break
        here = Path(root)
        for name in sorted(files):
            path = here / name
            rel = path.relative_to(project)
            kind = _kind(rel, here == project)
            if kind is None or path.is_symlink():
                continue
            found.append({"path": rel.as_posix(), "kind": kind, "bytes": path.stat().st_size,
                          "tracked": bool(tracked and rel.as_posix() in tracked)})
    by_kind: dict[str, int] = {}
    for item in found:
        by_kind[item["kind"]] = by_kind.get(item["kind"], 0) + 1
    return {"project": str(project), "git": tracked is not None, "truncated": truncated,
            "generated": found,
            "summary": {"files": len(found), "bytes": sum(i["bytes"] for i in found),
                        "by_kind": by_kind, "tracked": sum(i["tracked"] for i in found)},
            "plan": [i["path"] for i in found if not i["tracked"]]}


def workspace_clean(project: Path, plan: list[str], apply: bool = False) -> dict:
    """Dry-run by default; with ``apply`` delete only re-verified untracked generated files."""
    if not apply:
        return {"applied": False, "plan": list(plan), "removed": [], "refused": []}
    project = Path(project).resolve()
    tracked = _tracked(project)
    removed, refused = [], []
    for entry in plan:
        path = Path(entry) if Path(entry).is_absolute() else project / entry
        reason = None
        try:
            parent = path.parent.resolve()
            rel = (parent / path.name).relative_to(project)
        except ValueError:
            rel, reason = None, "outside project"
        if reason is None:
            if path.is_symlink():
                reason = "symlink"
            elif not path.is_file():
                reason = "not a regular file"
            elif _kind(rel, rel.parent == Path(".")) is None:
                reason = "not a generated pattern"
            elif tracked is not None and rel.as_posix() in tracked:
                reason = "tracked by git"
        if reason:
            refused.append({"path": str(entry), "reason": reason})
            continue
        path.unlink()
        removed.append(rel.as_posix())
    return {"applied": True, "plan": list(plan), "removed": removed, "refused": refused}
