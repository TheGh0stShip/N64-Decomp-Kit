"""Cached strict verification of manifest units (``match-inventory --verify``).

A manifest row is a *declaration*.  This module turns it into evidence: every unit is rebuilt
from its current source and compared with :func:`n64dk.match.verify.strict_compare`.  Verdicts
are cached in ``<state>/verification.sqlite`` under a key that covers everything the verdict
depends on:

* sha256 of the source bytes and the include-closure digest (headers the preprocessor reads);
* pipeline, flags, section bases, ``--symbol`` pins and normalizer arguments;
* the toolchain digest of the pipeline's binaries;
* sha256 of the retail ``.text`` slice and of the whole image (data sections are read too);
* the declared symbol map (project symbol files plus the definitions of every other unit in
  the verified set, so the key also covers the manifest set);
* the kit's own verification code.

Only deterministic verdicts are cached (``exact``, ``assumed``, ``mismatch``).  ``build-failed``
(which may be a timeout or a missing toolchain) and ``source-missing`` are always recomputed.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..elf import Elf
from . import compare as cmp
from . import pipeline as pipemod
from . import symbols as symmod
from . import verify as verifymod
from .manifest import Unit
from .toolchain import Config

CACHEABLE = ("exact", "assumed", "mismatch")


def _code_digest() -> str:
    digest = hashlib.sha256()
    for module in (verifymod, cmp, pipemod):
        digest.update(Path(module.__file__).read_bytes())
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()


class VerdictCache:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("CREATE TABLE IF NOT EXISTS verdicts (key TEXT PRIMARY KEY, unit TEXT, verdict TEXT, "
                        "record TEXT, created_ns INTEGER)")

    def get(self, key: str) -> dict | None:
        row = self.db.execute("SELECT record FROM verdicts WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, unit: str, record: dict) -> None:
        for attempt in range(5):
            try:
                self.db.execute("INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?, ?)",
                                (key, unit, record["verdict"], json.dumps(record, sort_keys=True), time.time_ns()))
                self.db.commit()
                return
            except sqlite3.OperationalError:
                if attempt == 4:
                    raise
                time.sleep(0.1 * (2 ** attempt))

    def close(self) -> None:
        self.db.close()


def unit_identity(unit: Unit, cfg: Config, rom: bytes, vram_to_rom) -> dict:
    """Everything about one unit that its verdict depends on, except the symbol context."""
    spec = unit.spec
    offset = vram_to_rom(unit.vram)
    return {
        "unit": unit.name,
        "source_sha256": hashlib.sha256(unit.source.read_bytes()).hexdigest(),
        "include_closure": pipemod.include_closure_digest(unit.source, spec, cfg),
        "pipeline": spec.pipeline, "flags": list(spec.flags),
        "section_bases": {k: v for k, v in sorted(spec.section_bases.items())},
        "symbols": {k: v for k, v in sorted(spec.symbols.items())},
        "normalizer_args": list(spec.normalizer_args),
        "section_sizes": dict(sorted(unit.section_sizes.items())),
        "toolchain": pipemod._compiler_digest(cfg, spec.pipeline),
        "vram": unit.vram, "size": unit.size,
        "target_text_sha256": hashlib.sha256(rom[offset:offset + unit.size]).hexdigest(),
    }


def verify_units(units: list[Unit], cfg: Config, rom: bytes, vram_to_rom, symbols: symmod.SymbolMap,
                 state_dir: Path, jobs: int = 4, function_starts: set[int] | None = None) -> list[dict]:
    """Strict verdict per unit: exact | assumed | mismatch | build-failed | source-missing."""
    rom_digest = hashlib.sha256(rom).hexdigest()
    symbol_digest = hashlib.sha256(json.dumps(sorted(symbols.items())).encode()).hexdigest()
    code = _code_digest()
    rows: list[dict] = []
    identities: list[dict | None] = []
    for unit in units:
        row = {"unit": unit.name, "source": str(unit.source), "vram": unit.vram, "size": unit.size,
               "pipeline": unit.spec.pipeline}
        if not unit.source.is_file():
            row.update(verdict="source-missing", cached=False)
            identities.append(None)
        else:
            try:
                identities.append(unit_identity(unit, cfg, rom, vram_to_rom))
            except (OSError, ValueError, pipemod.BuildError) as error:
                row.update(verdict="build-failed", error=str(error)[-300:], cached=False)
                identities.append(None)
        rows.append(row)
    set_digest = hashlib.sha256(json.dumps([i for i in identities if i], sort_keys=True).encode()).hexdigest()
    keys = [hashlib.sha256(json.dumps({"unit": identity, "set": set_digest, "rom": rom_digest,
                                       "symbols": symbol_digest, "starts": sorted(function_starts or []),
                                       "code": code}, sort_keys=True).encode()).hexdigest()
            if identity else None for identity in identities]
    cache = VerdictCache(Path(state_dir) / "verification.sqlite")
    try:
        pending = []
        for index, key in enumerate(keys):
            if key is None:
                continue
            hit = cache.get(key)
            if hit is not None:
                rows[index].update(hit, cached=True)
            else:
                pending.append(index)
        if not pending:
            return rows
        # Cross-unit symbol definitions need every buildable unit's object (object-cache hits).
        with tempfile.TemporaryDirectory(prefix="n64dk-unit-verify-") as tmp:
            def compile_unit(index: int):
                folder = Path(tmp) / f"u{index}"
                folder.mkdir()
                try:
                    return Elf.load(pipemod.build(units[index].source, units[index].spec, cfg, folder)), None
                except (pipemod.BuildError, RuntimeError, OSError, ValueError) as error:
                    return None, str(error)[-300:]
            buildable = [index for index, key in enumerate(keys) if key is not None]
            with ThreadPoolExecutor(max_workers=max(1, min(jobs, 4))) as pool:
                built = dict(zip(buildable, pool.map(compile_unit, buildable)))
        declared = symbols.copy()
        for index, (elf, _error) in built.items():
            if elf is not None:
                unit = units[index]
                for name, address in verifymod.unit_defines(elf, unit.vram, unit.spec.section_bases).items():
                    declared.setdefault(name, address)
        starts = set(function_starts or ()) | {unit.vram for unit in units} if function_starts is not None else None
        for index in pending:
            unit, (elf, error) = units[index], built[index]
            row = rows[index]
            if elf is None:
                row.update(verdict="build-failed", error=error, cached=False)
                continue
            local = declared.copy()
            try:
                local.update(symmod.from_source(unit.source.read_text(errors="replace"), local))
            except OSError:
                pass
            local.update(unit.spec.symbols)
            verdict = verifymod.strict_compare(elf, rom, vram_to_rom, unit.vram, unit.size, local,
                                               unit.spec.section_bases, unit.section_sizes or None, starts)
            record = {"verdict": verdict.verdict,
                      "assumptions": [a.as_dict() for a in verdict.assumptions],
                      "conflicts": verdict.conflicts, "notes": verdict.notes[:8],
                      "first_diff": verdict.as_dict()["first_diff"]}
            row.update(record, cached=False)
            if verdict.verdict in CACHEABLE:
                cache.put(keys[index], unit.name, record)
    finally:
        cache.close()
    return rows


def strict_source(source: bytes, suffix: str, spec, cfg: Config, rom: bytes, vram_to_rom, vram: int, size: int,
                  symbols: symmod.SymbolMap, section_sizes: dict[str, int] | None = None,
                  function_starts: set[int] | None = None) -> verifymod.Verdict:
    """Build one candidate source and return its strict verdict (declared information only:
    symbol files, ``--symbol``/``--section-base`` pins and source markers)."""
    with tempfile.TemporaryDirectory(prefix="n64dk-strict-") as tmp:
        path = Path(tmp) / ("candidate" + (suffix or ".c"))
        path.write_bytes(source)
        elf = Elf.load(pipemod.build(path, spec, cfg, Path(tmp) / "build"))
        local = symbols.copy()
        local.update(symmod.from_source(source.decode(errors="replace"), local))
        local.update(spec.symbols)
        return verifymod.strict_compare(elf, rom, vram_to_rom, vram, size, local, spec.section_bases,
                                        section_sizes, function_starts)
