"""Interval-correct project inventory and quick-win ranking.

The inventory deliberately treats names as labels, not proof of coverage.  Catalogue
functions are intersected with source-manifest intervals, so one translation unit may cover
many functions and tiny assembly/shared-tail units cannot accidentally change the denominator.
"""
from __future__ import annotations

import csv
import hashlib
import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path


_ROW = re.compile(
    r'\{\s*name\s*=\s*"([^"]+)"\s*,\s*vram\s*=\s*(0x[0-9a-fA-F]+)\s*,'
    r'\s*size\s*=\s*(0x[0-9a-fA-F]+)[^}]*\}\s*,?\s*(?:#\s*(.*))?$'
)
_IMAGE = re.compile(r"functions_(.+)\.toml$")
_MANIFEST = re.compile(r"matching_(.+?)_(?:asm_|kmc_|ido[^_]*_|sn_)?units\.tsv$")
_EXCLUDED_WORDS = {"fragment", "shared", "tail", "epilogue", "padding", "data",
                   "handwritten", "stub", "offset", "call"}


@dataclass(frozen=True)
class Interval:
    start: int
    end: int
    source: str
    kind: str

    def covers(self, start: int, end: int) -> bool:
        return self.start <= start and self.end >= end


@dataclass(frozen=True)
class InventoryFunction:
    id: str
    image: str
    name: str
    vram: int
    end: int
    size: int
    rom: int
    catalogue_status: str
    state: str
    reason: str
    owner: str | None
    candidate_source: str | None
    rank: float | None

    def as_dict(self) -> dict:
        value = asdict(self)
        for key in ("vram", "end", "rom"):
            value[key] = f"0x{value[key]:X}"
        return value


def _catalogues(project: Path) -> list[Path]:
    return sorted(project.glob("config/**/functions_*.toml"))


def _sections(path: Path) -> list[tuple[int, int, int]]:
    """Return (vram, rom, size) sections, accepting the catalogue dialect."""
    data = tomllib.loads(path.read_text())
    return [(int(row["vram"]), int(row.get("rom", 0)), int(row["size"]))
            for row in data.get("section", [])]


def _manifest_intervals(project: Path, image: str,
                        sections: list[tuple[int, int, int]]) -> list[Interval]:
    result: list[Interval] = []
    patterns = list(project.glob(f"config/**/matching_{image}_*units.tsv"))
    patterns += list(project.glob(f"config/**/matching_{image}_units.tsv"))
    for path in sorted(set(patterns)):
        with path.open(newline="") as stream:
            for row in csv.reader((line for line in stream if line.strip() and not line.startswith("#")),
                                  delimiter="\t"):
                if len(row) < 3:
                    continue
                try:
                    rom, size = int(row[0], 0), int(row[1], 0)
                except ValueError:  # unit-row manifests use VRAM in column two
                    try:
                        vram, size = int(row[1], 0), int(row[2], 0)
                    except (ValueError, IndexError):
                        continue
                    source = row[0]
                else:
                    source = row[2]
                    section = next((s for s in sections if s[1] <= rom < s[1] + s[2]), None)
                    if section is None:
                        continue
                    vram = section[0] + rom - section[1]
                suffix = Path(source).suffix.lower()
                kind = "assembly" if suffix in {".s", ".asm"} else "source"
                result.append(Interval(vram, vram + size, source, kind))
    return result


def _candidate_source(project: Path, name: str, vram: int) -> str | None:
    candidates = [project / ".tmp" / f"{name}_candidate.c",
                  project / ".tmp" / f"func_{vram:08X}_candidate.c"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.relative_to(project))
    return None


def _splat(project: Path) -> list[dict]:
    """Read the stable, useful subset of Splat YAML without adding a YAML dependency."""
    result = []
    scalar = re.compile(r"^\s*(target_path|symbol_addrs_path|compiler)\s*:\s*['\"]?([^#'\"]+)")
    segment = re.compile(r"^\s*-\s*\[\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*([^,\]]+)(?:,\s*([^\]]+))?\]")
    for path in sorted(project.glob("**/splat*.y*ml")):
        values: dict[str, str] = {}
        subsegments = []
        for line in path.read_text().splitlines():
            found = scalar.match(line)
            if found:
                values[found.group(1)] = found.group(2).strip()
            found = segment.match(line)
            if found:
                start, kind, name = found.groups()
                subsegments.append({"rom": f"0x{int(start, 0):X}", "type": kind.strip(),
                                    "name": name.strip() if name else None})
        result.append({"config": str(path.relative_to(project)), **values,
                       "subsegments": subsegments})
    return result


def build(project: str | Path) -> dict:
    root = Path(project).expanduser().resolve()
    functions: list[InventoryFunction] = []
    images = []
    for catalogue in _catalogues(root):
        match = _IMAGE.search(catalogue.name)
        if not match:
            continue
        image = match.group(1)
        sections = _sections(catalogue)
        claims = _manifest_intervals(root, image, sections)
        image_rows = []
        comments = {}
        for line in catalogue.read_text().splitlines():
            found = _ROW.search(line.strip())
            if found:
                name, start_s, _size_s, comment = found.groups()
                comments[(name, int(start_s, 0))] = (comment or "").strip()
        data = tomllib.loads(catalogue.read_text())
        catalogue_rows = [row for section_data in data.get("section", [])
                          for row in section_data.get("functions", [])]
        for raw in catalogue_rows:
            name, start, size = str(raw["name"]), int(raw["vram"]), int(raw["size"])
            end = start + size
            section = next((s for s in sections if s[0] <= start < s[0] + s[2]), None)
            if section is None:
                continue
            rom = section[1] + start - section[0]
            status = comments.get((name, start), str(raw.get("kind", "")))
            owners = [claim for claim in claims if claim.covers(start, end)]
            source_owners = [claim for claim in owners if claim.kind == "source"]
            asm_owners = [claim for claim in owners if claim.kind == "assembly"]
            words = set(re.findall(r"[a-z]+", f"{name} {status}".lower()))
            structural = words & _EXCLUDED_WORDS
            if size < 12:
                structural.add("undersized")
            candidate = _candidate_source(root, name, start)
            if source_owners or status.startswith("c"):
                state, reason = "covered", "covered by a C translation-unit interval"
                owner = source_owners[0].source if source_owners else None
                rank = None
            elif structural and not candidate:
                state, reason = "excluded", "non-independent interval: " + ", ".join(sorted(structural))
                owner, rank = asm_owners[0].source if asm_owners else None, None
            elif asm_owners:
                state, reason, owner = "remaining", "assembly-backed complete function", asm_owners[0].source
                rank = round(1000.0 / max(size, 4), 6)
            else:
                state, reason, owner = "remaining", "uncovered complete catalogue interval", candidate
                rank = round(1000.0 / max(size, 4) + (25 if candidate else 0), 6)
            identity = hashlib.sha256(f"{root.name}:{image}:{start:x}:{end:x}".encode()).hexdigest()[:20]
            item = InventoryFunction(identity, image, name, start, end, size, rom, status,
                                     state, reason, owner, candidate, rank)
            functions.append(item)
            image_rows.append(item)
        images.append({"name": image, "catalogue": str(catalogue.relative_to(root)),
                       "functions": len(image_rows),
                       "covered": sum(row.state == "covered" for row in image_rows),
                       "remaining": sum(row.state == "remaining" for row in image_rows),
                       "excluded": sum(row.state == "excluded" for row in image_rows)})
    functions.sort(key=lambda row: (row.image, row.vram))
    return {
        "project": str(root),
        "model": "interval-v1",
        "images": images,
        "splat": _splat(root),
        "summary": {"functions": len(functions),
                    "covered": sum(row.state == "covered" for row in functions),
                    "remaining": sum(row.state == "remaining" for row in functions),
                    "excluded": sum(row.state == "excluded" for row in functions)},
        "functions": [row.as_dict() for row in functions],
    }


def rank(inventory: dict, limit: int = 500, images: set[str] | None = None) -> list[dict]:
    rows = [row for row in inventory["functions"]
            if row["state"] == "remaining" and (not images or row["image"] in images)]
    rows.sort(key=lambda row: (-float(row["rank"]), int(row["size"]), row["image"], row["vram"]))
    return rows[:max(0, limit)]
