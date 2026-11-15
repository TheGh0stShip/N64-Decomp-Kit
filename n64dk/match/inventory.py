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
_STRUCTURAL_KINDS = {"fragment", "shared_tail", "shared-epilogue", "epilogue", "padding",
                     "data", "handwritten", "assembly-fragment", "delay-slot"}


@dataclass(frozen=True)
class Interval:
    start: int
    end: int
    source: str
    kind: str
    manifest: str = ""
    declared_digest: str | None = None

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
    section_rom: int
    section_vram: int
    section_size: int
    catalogue_status: str
    state: str
    reason: str
    owner: str | None
    ownership_state: str
    coverage_authority: str | None
    candidate_source: str | None
    mapping_evidence: tuple[str, ...]
    rank: float | None
    library_identity: str | None = None

    def as_dict(self) -> dict:
        value = asdict(self)
        for key in ("vram", "end", "rom", "section_rom", "section_vram"):
            value[key] = f"0x{value[key]:X}"
        return value


def _inventory_config(project: Path) -> dict:
    path = project / "n64dk.toml"
    if not path.is_file():
        return {}
    try:
        return tomllib.loads(path.read_text()).get("inventory", {})
    except tomllib.TOMLDecodeError:
        return {}


def _catalogues(project: Path) -> list[Path]:
    configured = _inventory_config(project).get("catalogues", [])
    if configured:
        return sorted((project / value).resolve() for value in configured)
    conventional = set(project.glob("config/**/functions_*.toml"))
    # Game-agnostic fallback: accept TOML files that actually contain section/function tables,
    # while excluding kit/progress configuration by content rather than filename convention.
    candidates = list(project.glob("config/**/*.toml")) + list(project.glob("analysis/**/functions.toml"))
    if (project / "functions.toml").is_file():
        candidates.append(project / "functions.toml")
    for path in candidates:
        try:
            text = path.read_text()
            if "[[section]]" in text and "functions" in text:
                conventional.add(path)
        except OSError:
            continue
    return sorted(conventional)


def _image_name(path: Path) -> str:
    match = _IMAGE.search(path.name)
    if match:
        return match.group(1)
    stem = path.stem.removeprefix("functions_")
    return "main" if stem == "functions" else stem


def _sections(path: Path) -> list[tuple[int, int, int]]:
    """Return (vram, rom, size) sections, accepting the catalogue dialect."""
    data = tomllib.loads(path.read_text())
    return [(int(row["vram"]), int(row.get("rom", 0)), int(row["size"]))
            for row in data.get("section", [])]


def _manifest_intervals(project: Path, image: str,
                        sections: list[tuple[int, int, int]]) -> list[Interval]:
    result: list[Interval] = []
    configured = _inventory_config(project).get("manifests", {})
    configured_rows = configured.get(image, []) if isinstance(configured, dict) else []
    patterns = [(project / value).resolve() for value in configured_rows]
    patterns += list(project.glob(f"config/**/matching_{image}_*units.tsv"))
    patterns += list(project.glob(f"config/**/matching_{image}_units.tsv"))
    # The resident/main image commonly predates image-qualified manifest names.
    # Include only generic compiler/assembler manifests, never overlay/loader/data rows.
    if image in {"resident", "main"}:
        for path in project.glob("config/**/matching_*units.tsv"):
            stem = path.name.removeprefix("matching_").removesuffix("_units.tsv")
            if (stem in {"kmc", "ido", "asm"} or stem.startswith("ido")) \
                    and not any(word in stem for word in ("data", "asset", "rodata")):
                patterns.append(path)

    def number(value: str) -> int:
        value = value.strip()
        try:
            return int(value, 0)
        except ValueError:
            return int(value, 16)

    for path in sorted(set(patterns)):
        with path.open(newline="") as stream:
            for row in csv.reader((line for line in stream if line.strip() and not line.startswith("#")),
                                  delimiter="\t"):
                if len(row) < 3:
                    continue
                try:
                    rom, size = number(row[0]), number(row[1])
                except ValueError:  # unit-row manifests use VRAM in column two
                    try:
                        vram, size = number(row[1]), number(row[2])
                    except (ValueError, IndexError):
                        continue
                    source = row[0]
                else:
                    source = row[2]
                    section = next((s for s in sections if s[1] <= rom < s[1] + s[2]), None)
                    if section is None:
                        # A row outside every declared coordinate space is retained as a
                        # contradiction rather than silently shifted by a game-specific bias.
                        result.append(Interval(-1, -1, source, "unmapped",
                                               str(path.relative_to(project)),
                                               row[4] if len(row) > 4 and re.fullmatch(r"[0-9a-fA-F]{64}", row[4]) else None))
                        continue
                    vram = section[0] + rom - section[1]
                suffix = Path(source).suffix.lower()
                kind = "assembly" if suffix in {".s", ".asm"} else "source"
                result.append(Interval(vram, vram + size, source, kind,
                                       str(path.relative_to(project)),
                                       next((value for value in row[3:] if re.fullmatch(r"[0-9a-fA-F]{64}", value)), None)))
    return result


def _candidate_source(project: Path, name: str, vram: int, index=None) -> str | None:
    if index is not None:
        found = index.find(name, vram)
        if found:
            return found[0]["path"]
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
    paths = set(project.rglob("splat*.yml")) | set(project.rglob("splat*.yaml"))
    paths = {path for path in paths
             if path.is_file() and not any(part in {"build", ".tmp", ".git", ".n64dk", ".venv"}
                                           for part in path.relative_to(project).parts)}
    for path in sorted(paths):
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


def build(project: str | Path, refresh_sources: bool = False) -> dict:
    root = Path(project).expanduser().resolve()
    from .source_index import SourceIndex
    source_index = SourceIndex(root)
    source_stats = source_index.refresh() if refresh_sources or source_index.empty() else {
        "scanned": 0, "hashed": 0, "elapsed_seconds": 0.0, "cache_hit": True}
    from .toolchain import load_config
    from .verification_store import current as current_verifications
    cfg = load_config(root)
    receipts = current_verifications(root, cfg)
    functions: list[InventoryFunction] = []
    images = []
    unmapped_claims = []
    for catalogue in _catalogues(root):
        image = _image_name(catalogue)
        sections = _sections(catalogue)
        claims = _manifest_intervals(root, image, sections)
        unmapped_claims += [{"image": image, "manifest": claim.manifest, "source": claim.source}
                            for claim in claims if claim.kind == "unmapped"]
        claims = [claim for claim in claims if claim.kind != "unmapped"]
        image_rows = []
        comments = {}
        for line in catalogue.read_text().splitlines():
            found = _ROW.search(line.strip())
            if found:
                name, start_s, _size_s, comment = found.groups()
                comments[(name, int(start_s, 0))] = (comment or "").strip()
        data = tomllib.loads(catalogue.read_text())
        catalogue_rows = sorted((row for section_data in data.get("section", [])
                                 for row in section_data.get("functions", [])),
                                key=lambda row: int(row["vram"]))
        ordered_claims = sorted(claims, key=lambda claim: (claim.start, claim.end))
        claim_cursor = 0
        active_claims: list[Interval] = []
        for raw in catalogue_rows:
            name, start, size = str(raw["name"]), int(raw["vram"]), int(raw["size"])
            end = start + size
            section = next((s for s in sections if s[0] <= start < s[0] + s[2]), None)
            if section is None:
                continue
            rom = section[1] + start - section[0]
            status = comments.get((name, start), str(raw.get("kind", "")))
            active_claims = [claim for claim in active_claims if start < claim.end]
            while claim_cursor < len(ordered_claims) and ordered_claims[claim_cursor].start < end:
                claim = ordered_claims[claim_cursor]; claim_cursor += 1
                if start < claim.end: active_claims.append(claim)
            intersecting = list(active_claims)
            owners = [claim for claim in intersecting if claim.covers(start, end)]
            partial = [claim for claim in intersecting if not claim.covers(start, end)]
            clipped = sorted(
                ((max(start, claim.start), min(end, claim.end), claim)
                 for claim in intersecting),
                key=lambda item: (
                    item[0], item[1], item[2].start, item[2].end,
                    item[2].kind, item[2].source, item[2].manifest,
                ),
            )
            cursor = start
            for left, right, _claim in clipped:
                if left > cursor: break
                cursor = max(cursor, right)
            partitioned = cursor >= end and not any(
                left < previous_right for (_pl, previous_right, _pc), (left, _r, _c)
                in zip(clipped, clipped[1:]))
            source_owners = [claim for claim in owners if claim.kind == "source"]
            asm_owners = [claim for claim in owners if claim.kind == "assembly"]
            normalized_status = re.sub(r"[\s-]+", "_", status.strip().lower())
            structural = {normalized_status} & {value.replace("-", "_") for value in _STRUCTURAL_KINDS}
            candidate = _candidate_source(root, name, start, source_index)
            # A catalogue comment and a discovered source file are evidence, not proof of
            # coverage.  Only an exact matching manifest may remove an interval from work.
            padding_partition = (partitioned and any("padding" in claim.source.lower() for claim in intersecting)
                                 and len([claim for claim in intersecting if claim.kind == "source"]) == 1
                                 and all(claim.kind == "source" or "padding" in claim.source.lower()
                                         for claim in intersecting))
            verified_owners = [claim for claim in source_owners
                               if (claim.source, claim.start, claim.end - claim.start) in receipts]
            if padding_partition and next((claim for claim in intersecting if claim.kind == "source"), None) in verified_owners:
                claim = next(claim for claim in intersecting if claim.kind == "source")
                state, reason, owner = "covered", "C unit plus explicit padding partition owns catalogue interval", claim.source
                ownership_state, coverage_authority, rank = "manifest_exact_member", "manifest", None
                owners, partial = intersecting, []
            elif len(source_owners) > 1:
                state, reason, owner = "conflict", "multiple authoritative C owners", None
                ownership_state, coverage_authority, rank = "duplicate_owner", None, None
            elif partial:
                state, reason, owner = "conflict", "manifest boundary partially overlaps catalogue interval", None
                ownership_state, coverage_authority, rank = "boundary_conflict", None, None
            elif verified_owners:
                state, reason = "covered", "covered by a C translation-unit interval"
                owner = verified_owners[0].source
                claim = verified_owners[0]
                ownership_state = ("manifest_exact_unit" if claim.start == start and claim.end == end
                                   else "manifest_exact_member")
                coverage_authority = "manifest"
                rank = None
            elif source_owners:
                claim = source_owners[0]
                source_path = Path(claim.source)
                source_path = source_path if source_path.is_absolute() else root / source_path
                digest_ok = (claim.declared_digest is not None and source_path.is_file())
                state = "claimed"
                reason = ("manifest ownership claim awaits strict rebuild verification" if source_path.is_file()
                          else "manifest ownership claim references missing source")
                owner = claim.source
                ownership_state = "manifest_nonexact"
                coverage_authority = "manifest-claim"
                rank = None
            elif structural and not candidate:
                state, reason = "excluded", "non-independent interval: " + ", ".join(sorted(structural))
                owner, rank = asm_owners[0].source if asm_owners else None, None
                ownership_state = ("data" if "data" in structural else "padding" if "padding" in structural
                                   else "fragment")
                coverage_authority = None
            elif asm_owners:
                state, reason, owner = "assembly", "authoritatively owned by assembly", asm_owners[0].source
                claim = asm_owners[0]
                ownership_state = ("assembly_unit" if claim.start == start and claim.end == end
                                   else "assembly_member")
                coverage_authority = None
                rank = round(1000.0 / max(size, 4), 6)
            else:
                state, reason, owner = "remaining", "uncovered complete catalogue interval", candidate
                if candidate:
                    ownership_state = ("scratch_candidate" if ".tmp" in Path(candidate).parts
                                       else "tracked_source_unverified")
                else:
                    ownership_state = "unowned"
                coverage_authority = None
                rank = round(1000.0 / max(size, 4) + (25 if candidate else 0), 6)
            identity = hashlib.sha256(f"{root.name}:{image}:{start:x}:{end:x}".encode()).hexdigest()[:20]
            evidence = [f"catalogue:{catalogue.relative_to(root)}:{section[1]:#x}->{section[0]:#x}"]
            evidence += [f"manifest:{claim.manifest}:{claim.source}:{claim.start:#x}-{claim.end:#x}"
                         for claim in owners + partial]
            item = InventoryFunction(identity, image, name, start, end, size, rom,
                                     section[1], section[0], section[2], status,
                                     state, reason, owner, ownership_state, coverage_authority,
                                     candidate, tuple(evidence), rank,
                                     ("libultra" if any("libultra" in value.lower() for value in
                                        ([owner] if owner else []) + [claim.source for claim in owners])
                                      else None))
            functions.append(item)
            image_rows.append(item)
        images.append({"name": image, "catalogue": str(catalogue.relative_to(root)),
                       "functions": len(image_rows),
                       "covered": sum(row.state == "covered" for row in image_rows),
                       "claimed": sum(row.state == "claimed" for row in image_rows),
                       "remaining": sum(row.state == "remaining" for row in image_rows),
                       "assembly": sum(row.state == "assembly" for row in image_rows),
                       "excluded": sum(row.state == "excluded" for row in image_rows),
                       "conflicts": sum(row.state == "conflict" for row in image_rows)})
    functions.sort(key=lambda row: (row.image, row.vram))
    source_index.close()
    conflicts = [row for row in functions if row.state == "conflict"]
    unowned = [row for row in functions if row.ownership_state == "unowned"]
    declared_functions = None
    for progress_path in sorted(root.glob("config/**/progress.toml")):
        try:
            declared_functions = int(tomllib.loads(progress_path.read_text()).get("image", {}).get("total_functions"))
            break
        except (TypeError, ValueError, tomllib.TOMLDecodeError):
            continue
    denominator_delta = (len(functions) - declared_functions
                         if declared_functions is not None else None)
    def count(state): return sum(row.ownership_state == state for row in functions)
    def bytes_for(predicate): return sum(row.size for row in functions if predicate(row))
    reconciliation = [
        {"source": "catalogue_intervals", "functions": len(functions),
         "bytes": sum(row.size for row in functions), "explanation": "parsed catalogue boundaries"},
        {"source": "declared_denominator", "functions": declared_functions, "bytes": None,
         "explanation": "project progress declaration"},
        {"source": "individually_owned_c", "functions": count("manifest_exact_unit"),
         "bytes": bytes_for(lambda row: row.ownership_state == "manifest_exact_unit"),
         "explanation": "manifest unit equals catalogue interval"},
        {"source": "aggregate_owned_c", "functions": count("manifest_exact_member"),
         "bytes": bytes_for(lambda row: row.ownership_state == "manifest_exact_member"),
         "explanation": "catalogue intervals expanded from aggregate translation units"},
        {"source": "assembly_owned", "functions": sum(row.state == "assembly" for row in functions),
         "bytes": bytes_for(lambda row: row.state == "assembly"), "explanation": "authoritative assembly ownership"},
        {"source": "fragments_padding_data", "functions": sum(row.state == "excluded" for row in functions),
         "bytes": bytes_for(lambda row: row.state == "excluded"), "explanation": "excluded non-functions"},
        {"source": "truly_remaining", "functions": sum(row.state == "remaining" for row in functions),
         "bytes": bytes_for(lambda row: row.state == "remaining"), "explanation": "complete unowned intervals"},
    ]
    return {
        "project": str(root),
        "model": "interval-v2-authoritative-coverage",
        "images": images,
        "splat": _splat(root),
        "source_index": source_stats,
        "summary": {"functions": len(functions),
                    "declared_functions": declared_functions,
                    "denominator_delta": denominator_delta,
                    "covered": sum(row.state == "covered" for row in functions),
                    "claimed": sum(row.state == "claimed" for row in functions),
                    "remaining": sum(row.state == "remaining" for row in functions),
                    "assembly": sum(row.state == "assembly" for row in functions),
                    "excluded": sum(row.state == "excluded" for row in functions),
                    "conflicts": len(conflicts), "unowned": len(unowned)},
        "consistency": {"ok": bool(functions) and not conflicts and not unowned and not unmapped_claims
                              and denominator_delta in (None, 0),
                        "reason": "no catalogue functions discovered" if not functions else None,
                        "conflicts": [row.id for row in conflicts],
                        "unmapped_manifest_rows": unmapped_claims,
                        "missing_ownership": [row.id for row in unowned],
                        "denominator_mismatch": ({"catalogue_functions": len(functions),
                                                   "declared_functions": declared_functions,
                                                   "delta": denominator_delta}
                                                  if denominator_delta not in (None, 0) else None)},
        "reconciliation": reconciliation,
        "functions": [row.as_dict() for row in functions],
    }


def rank(inventory: dict, limit: int = 500, images: set[str] | None = None) -> list[dict]:
    rows = [row for row in inventory["functions"]
            if row["state"] == "remaining" and (not images or row["image"] in images)]
    rows.sort(key=lambda row: (-float(row["rank"]), int(row["size"]), row["image"], row["vram"]))
    return rows[:max(0, limit)]
