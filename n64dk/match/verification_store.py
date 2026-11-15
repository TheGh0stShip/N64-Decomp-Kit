"""Durable strict-verification receipts used by inventory and integration.

A manifest is a desired ownership declaration, not evidence that its source currently builds.
This store records the independent inputs and strict proof produced by ``match-batch``.  A
receipt is current only while the source bytes, dependency closure, toolchain, target image,
interval and recipe retain the recorded identities.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path

from .pipeline import BuildSpec, dependency_digest, toolchain_digest


def _db(project: Path) -> sqlite3.Connection:
    path = project / ".n64dk" / "verification.sqlite"
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=60)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=60000")
    db.execute("""
      CREATE TABLE IF NOT EXISTS receipts (
        receipt_id TEXT PRIMARY KEY, source TEXT NOT NULL, source_digest TEXT NOT NULL,
        dependency_digest TEXT NOT NULL, pipeline TEXT NOT NULL, flags TEXT NOT NULL,
        toolchain_digest TEXT NOT NULL, image_digest TEXT NOT NULL, vram INTEGER NOT NULL,
        size INTEGER NOT NULL, target_digest TEXT NOT NULL, verdict TEXT NOT NULL,
        proof TEXT NOT NULL, created_ns INTEGER NOT NULL
      )
    """)
    columns = {row[1] for row in db.execute("PRAGMA table_info(receipts)")}
    for name, declaration in (("image_path", "TEXT"), ("image_name", "TEXT"),
                              ("target_offset", "INTEGER"), ("catalogue_vram", "INTEGER")):
        if name not in columns:
            db.execute(f"ALTER TABLE receipts ADD COLUMN {name} {declaration}")
    db.commit()
    return db


def record(project, cfg, target, units, outcomes, image_name: str | None = None,
           catalogue_vrams: dict[tuple[int, int], int] | None = None) -> int:
    """Record current strictly exact outcomes; assumed/text-only observations are excluded."""
    root = Path(project).resolve(); image_digest = hashlib.sha256(target.rom).hexdigest(); rows = 0
    db = _db(root)
    try:
        for unit, outcome in zip(units, outcomes):
            if not outcome.exact or outcome.proof is None or not outcome.proof.exact:
                continue
            source = Path(unit.source).resolve()
            try:
                relative = str(source.relative_to(root))
            except ValueError:
                relative = str(source)
            source_digest = hashlib.sha256(source.read_bytes()).hexdigest()
            deps = dependency_digest(source, unit.spec, cfg)
            compiler = toolchain_digest(cfg, unit.spec.pipeline)
            offset = unit.vram - target.delta
            target_digest = hashlib.sha256(target.rom[offset:offset + unit.size]).hexdigest()
            identity = {"source": relative, "source_digest": source_digest, "dependencies": deps,
                        "pipeline": unit.spec.pipeline, "flags": unit.spec.flags,
                        "toolchain": compiler, "image": image_digest, "vram": unit.vram,
                        "size": unit.size, "target": target_digest}
            receipt_id = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
            image_path = Path(cfg.rom).resolve() if cfg.rom else None
            image_path_value = (str(image_path.relative_to(root)) if image_path and image_path.is_relative_to(root)
                                else str(image_path) if image_path else None)
            db.execute("""INSERT OR REPLACE INTO receipts
                (receipt_id,source,source_digest,dependency_digest,pipeline,flags,
                 toolchain_digest,image_digest,vram,size,target_digest,verdict,proof,created_ns,
                image_path,image_name,target_offset,catalogue_vram)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (receipt_id, relative, source_digest, deps, unit.spec.pipeline,
                        json.dumps(unit.spec.flags), compiler, image_digest, unit.vram, unit.size,
                        target_digest, "exact", json.dumps(outcome.proof.as_dict(), sort_keys=True),
                        time.time_ns(), image_path_value, image_name, offset,
                        (catalogue_vrams or {}).get((unit.vram, unit.size), unit.vram)))
            rows += 1
        db.commit()
        return rows
    finally:
        db.close()


def current(project, cfg=None) -> dict[tuple[str, int, int], dict]:
    """Return receipts whose local source/dependency/toolchain identities are still current."""
    root = Path(project).resolve(); path = root / ".n64dk" / "verification.sqlite"
    if not path.is_file():
        return {}
    # SQLite can create ``-shm`` even for a mode=ro WAL connection.  When no live WAL exists,
    # immutable mode is both genuinely read-only and sidecar-free; if a writer is active we
    # use mode=ro so committed WAL records remain visible (the writer already owns sidecars).
    access = "mode=ro" if Path(f"{path}-wal").exists() else "immutable=1"
    uri = f"file:{path}?{access}"
    db = sqlite3.connect(uri, uri=True, timeout=30)
    result = {}
    image_cache: dict[Path, tuple[bytes, str]] = {}
    try:
        columns = {row[1] for row in db.execute("PRAGMA table_info(receipts)")}
        if not {"image_path", "target_offset"} <= columns:
            return {}
        catalogue_column = "catalogue_vram" if "catalogue_vram" in columns else "vram"
        rows = db.execute("SELECT source,source_digest,dependency_digest,pipeline,flags,"
                          "toolchain_digest,image_digest,vram,size,target_digest,verdict,proof,created_ns,"
                          f"image_path,image_name,target_offset,{catalogue_column} "
                          "FROM receipts WHERE verdict='exact'").fetchall()
        for row in rows:
            source = Path(row[0]); source = source if source.is_absolute() else root / source
            if not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != row[1]:
                continue
            if cfg is not None:
                spec = BuildSpec(row[3], list(json.loads(row[4])))
                if dependency_digest(source, spec, cfg) != row[2]:
                    continue
                if toolchain_digest(cfg, row[3]) != row[5]:
                    continue
            if not row[13] or row[15] is None:
                continue
            image = Path(row[13]); image = image if image.is_absolute() else root / image
            if not image.is_file():
                continue
            cached = image_cache.get(image)
            if cached is None:
                image_bytes = image.read_bytes()
                cached = (image_bytes, hashlib.sha256(image_bytes).hexdigest())
                image_cache[image] = cached
            image_bytes, current_image_digest = cached
            if current_image_digest != row[6]:
                continue
            offset = int(row[15]); size = int(row[8])
            if offset < 0 or offset + size > len(image_bytes) or \
                    hashlib.sha256(image_bytes[offset:offset + size]).hexdigest() != row[9]:
                continue
            result[(row[0], row[16], row[8])] = {
                "source": row[0], "image_digest": row[6], "target_digest": row[9],
                "proof": json.loads(row[11]), "created_ns": row[12],
                "image_path": row[13], "image_name": row[14], "target_offset": offset,
                "linked_vram": row[7], "catalogue_vram": row[16],
            }
        return result
    finally:
        db.close()
