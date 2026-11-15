"""Function catalogues in the formats projects actually keep them in.

Returns ``[(name, vram, size)]`` for:

* n64dk catalogue TOML and splat ``symbol_addrs.txt`` (delegated to ``functions.load_catalogue``);
* tab- or comma-separated tables with a header naming their columns, as a ``#`` comment or a
  first row, e.g. ``# ROM_START  SIZE  VRAM  NAME  EVIDENCE``.  Columns are found by name
  (``vram``/``address``/``addr``, ``name``/``symbol``/``function``, ``size``/``length``); a table
  with only ROM offsets needs ``vram_delta``.

Rows that are not functions (``type`` column other than ``func``/``function``/empty) are skipped.
"""
from __future__ import annotations

import re
from pathlib import Path

from .functions import load_catalogue

_VRAM = ("vram", "address", "addr", "vaddr")
_NAME = ("name", "symbol", "function", "func")
_SIZE = ("size", "length", "len")
_ROM = ("rom_start", "rom", "rom_offset", "offset")


def _number(text: str) -> int | None:
    try:
        return int(text.strip(), 0)
    except ValueError:
        return None


def load(path: str | Path, vram_delta: int | None = None) -> list[tuple[str, int, int]]:
    path = Path(path)
    if path.suffix.lower() in (".tsv", ".csv"):
        rows = _table(path, vram_delta)
        if rows:
            return rows
    return load_catalogue(path)


def _table(path: Path, vram_delta: int | None) -> list[tuple[str, int, int]]:
    separator = "," if path.suffix.lower() == ".csv" else "\t"
    header: list[str] | None = None
    out = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        cells = [c.strip() for c in line.lstrip("# ").split(separator)] if line.startswith("#") else \
            [c.strip() for c in line.split(separator)]
        lowered = [c.lower() for c in cells]
        if header is None and any(c in _VRAM + _ROM for c in lowered) and any(c in _SIZE for c in lowered):
            header = lowered
            continue
        if line.startswith("#") or header is None:
            continue
        row = dict(zip(header, cells))
        kind = (row.get("type") or row.get("kind") or "").lower()
        if kind and kind not in ("func", "function", "text", "code"):
            continue
        size = next((_number(row[c]) for c in _SIZE if c in row), None)
        vram = next((_number(row[c]) for c in _VRAM if c in row), None)
        if vram is None and vram_delta is not None:
            rom = next((_number(row[c]) for c in _ROM if c in row), None)
            vram = rom + vram_delta if rom is not None else None
        if vram is None or size is None:
            continue
        name = next((row[c] for c in _NAME if row.get(c)), None)
        if not name or not re.fullmatch(r"[A-Za-z_.$][\w.$]*", name):
            name = f"func_{vram:08X}"
        out.append((name, vram, size))
    return sorted(set(out), key=lambda item: item[1])
