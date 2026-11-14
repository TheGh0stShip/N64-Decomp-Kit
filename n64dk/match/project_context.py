"""Immutable, shared project state for tranche planning and matching workers."""
from __future__ import annotations

import csv
import hashlib
import json
import re
import shlex
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from . import inventory as invmod
from .layout import from_inventory, preflight
from .symbols import discover, load
from .toolchain import PROFILES, load_config
from .registry import SessionRegistry
from ..sdk import Database as SdkDatabase
from ..sdk.matcher import scan as scan_sdk
from .. import mips


@dataclass(frozen=True)
class ImageSnapshot:
    path: Path
    data: bytes
    digest: str


class ProjectContext:
    """One scan/config/symbol/image snapshot shared by every function in a tranche."""

    def __init__(self, project: str | Path, image_files: dict[str, str] | None = None,
                 refresh_sources: bool = False, inventory_snapshot: dict | None = None):
        started = time.monotonic()
        self.project = Path(project).expanduser().resolve()
        self.config = load_config(self.project, None, None)
        self.inventory = inventory_snapshot or invmod.build(self.project, refresh_sources)
        self.symbol_files = tuple(discover(self.config.project))
        self.symbols = load(self.symbol_files)
        self.image_files = {key: Path(value).expanduser().resolve()
                            for key, value in (image_files or {}).items()}
        self._images: dict[Path, ImageSnapshot] = {}
        self._preflights: dict[tuple[str, bool], dict] = {}
        self._library_matches: dict[str, dict | None] = {}
        self._history: dict[str, list[dict]] = {}
        self._recipes = self._load_recipes()
        self._lock = threading.RLock()
        self._sdk = None
        self._registry = SessionRegistry(self.project)
        self._registry.refresh()
        self.metrics = {"project_scans": 1, "symbol_discoveries": 1,
                        "image_loads": 0, "image_hashes": 0,
                        "preflight_cache_hits": 0, "history_scans": 1,
                        "context_seconds": round(time.monotonic() - started, 6)}

    def image(self, image_name: str) -> ImageSnapshot:
        path = self.image_files.get(image_name)
        if path is None:
            raise ValueError(f"missing image mapping {image_name}=PATH")
        with self._lock:
            cached = self._images.get(path)
            if cached is not None:
                return cached
            data = path.read_bytes()
            value = ImageSnapshot(path, data, hashlib.sha256(data).hexdigest())
            self._images[path] = value
            self.metrics["image_loads"] += 1; self.metrics["image_hashes"] += 1
            return value

    def preflight(self, row: dict, strict: bool = True) -> dict:
        key = (row["id"], strict)
        with self._lock:
            cached = self._preflights.get(key)
            if cached is not None:
                self.metrics["preflight_cache_hits"] += 1
                return cached
        image = self.image(row["image"])
        sibling = image.path.with_name(image.path.name.replace("_composite", "", 1))
        raw_data = self._snapshot_path(sibling).data if sibling != image.path and sibling.is_file() else None
        check = preflight(image.path, from_inventory(row), row.get("catalogue_status", ""),
                          strict_entry=strict, data=image.data, raw_data=raw_data)
        check["cross_checks"] = row.get("mapping_evidence", [])
        with self._lock: self._preflights[key] = check
        return check

    def history(self, context: dict) -> list[dict]:
        """Return a target frontier without rescanning project stores per worker."""
        from .registry import target_signature
        signature = target_signature(context)
        with self._lock:
            if signature not in self._history:
                self._history[signature] = self._registry.same_target(context, refresh=False)
            return list(self._history[signature])

    def detect_library(self, row: dict) -> dict | None:
        """Match one verified interval against the pinned SDK signature database."""
        key = row["id"]
        with self._lock:
            if key in self._library_matches:
                return self._library_matches[key]
        try:
            check = self.preflight(row, True)
            if not check.get("ok"):
                result = None
            else:
                image = self.image(row["image"])
                offset = int(check["selected_image_offset"], 0)
                size = int(row["size"])
                with self._lock:
                    if self._sdk is None:
                        self._sdk = SdkDatabase.load()
                matches = scan_sdk(image.data, offset, offset + size, int(row["vram"], 0), self._sdk)
                exact = [match for match in matches if match.rom == offset and match.size == size
                         and match.kind == "exact"]
                if exact:
                    match = max(exact, key=lambda value: value.confidence)
                    result = {"library": "libultra" if any("ultra" in source.lower()
                              for source in match.sources) else "sdk",
                              "name": match.name, "confidence": match.confidence,
                              "compilers": match.compilers, "sources": match.sources}
                else:
                    result = None
        except (OSError, ValueError):
            result = None
        with self._lock:
            self._library_matches[key] = result
        return result

    def close(self) -> None:
        self._registry.close()

    def _snapshot_path(self, path: Path) -> ImageSnapshot:
        with self._lock:
            cached = self._images.get(path)
            if cached is not None: return cached
            data = path.read_bytes(); value = ImageSnapshot(path, data, hashlib.sha256(data).hexdigest())
            self._images[path] = value
            self.metrics["image_loads"] += 1; self.metrics["image_hashes"] += 1
            return value

    def _load_recipes(self) -> list[dict]:
        recipes = []
        sections = {image["name"]: [] for image in self.inventory.get("images", [])}
        for row in self.inventory["functions"]:
            value = (int(row["section_vram"], 0), int(row["section_rom"], 0), int(row["section_size"]))
            if value not in sections.setdefault(row["image"], []): sections[row["image"]].append(value)
        for path in sorted(self.project.glob("config/**/matching_*units.tsv")):
            name = path.name.lower()
            pipeline = ("ido5.3" if "ido" in name and not ("ido7" in name or "ido71" in name) else
                        "ido7.1" if "ido7" in name or "ido71" in name else
                        "sn" if re.search(r"(?:^|_)sn(?:_|\.)", name) else "kmc+asn64")
            image_match = re.search(r"matching_(overlay\d+|resident|main)_", name)
            image_name = image_match.group(1) if image_match else "resident"
            with path.open(newline="") as stream:
                for values in csv.reader((line for line in stream if line.strip() and not line.startswith("#")),
                                         delimiter="\t"):
                    if len(values) < 4: continue
                    symbolic = values[0].startswith("func_")
                    try:
                        if symbolic:
                            vram, size = int(values[1], 16), int(values[2], 16)
                            section = next((value for value in sections.get(image_name, [])
                                            if value[0] <= vram < value[0] + value[2]), None)
                            rom = section[1] + vram - section[0] if section else 0
                        else:
                            rom, size = int(values[0], 0), int(values[1], 0)
                            section = next((value for value in sections.get(image_name, [])
                                            if value[1] <= rom < value[1] + value[2]), None)
                    except ValueError: continue
                    if section is None: continue
                    if not symbolic: vram = section[0] + rom - section[1]
                    flags = ([] if symbolic else shlex.split(values[3]))
                    if symbolic: flags = list(PROFILES["ido53" if pipeline == "ido5.3" else "ido71"].default_flags)
                    assembler = "asn64" if "--assembler=asn64" in flags else "native"
                    if pipeline.startswith("kmc"):
                        pipeline = ("kmc+asn64" if "--assembler=asn64" in flags else
                                    "kmc+hook" if "--assembler=normalizer" in flags or
                                    any(flag.startswith("--normalizer-") for flag in flags) else "kmc+as")
                    flags = [flag for flag in flags if not flag.startswith("--assembler=")]
                    recipes.append({"image": image_name, "start": vram, "end": vram + size,
                        "section_vram": section[0], "section_rom": section[1],
                        "source": values[0] if symbolic else values[2], "pipeline": pipeline, "flags": flags,
                        "assembler": assembler, "manifest": str(path.relative_to(self.project))})
        return recipes

    def infer_recipe(self, row: dict, override_pipeline: str | None = None,
                     override_flags: str | None = None) -> dict:
        address = int(row["vram"], 0); image = row["image"]
        same = [item for item in self._recipes if item["image"] == image]
        containing = [item for item in same if item["start"] <= address < item["end"]]
        if containing:
            chosen = min(containing, key=lambda item: item["end"] - item["start"])
            inferred = {**chosen, "confidence": 0.995, "evidence": "same verified translation-unit interval"}
            return self._apply_recipe_overrides(inferred, override_pipeline, override_flags)
        library = self.detect_library(row) if row["image"] in self.image_files else None
        if library and any(value.lower().startswith("ido") for value in library["compilers"]):
            version = "ido7.1" if any("7" in value for value in library["compilers"]) else "ido5.3"
            inferred = {"pipeline": version,
                    "flags": list(PROFILES["ido71" if version == "ido7.1" else "ido53"].default_flags),
                    "confidence": library["confidence"],
                    "evidence": f"pinned SDK signature {library['name']}", "assembler": "ido"}
            return self._apply_recipe_overrides(inferred, override_pipeline, override_flags)
        if same:
            same = [item for item in same if item.get("section_vram") == int(row["section_vram"], 0)
                    and item.get("section_rom") == int(row["section_rom"], 0)]
        if same:
            chosen = min(same, key=lambda item: min(abs(address - item["start"]), abs(address - item["end"])))
            distance = min(abs(address - chosen["start"]), abs(address - chosen["end"]))
            confidence = max(0.05, 0.96 - distance / 0x4000)
            evidence = f"nearest verified manifest unit ({distance:#x} bytes away)"
            if "libultra" in chosen["source"].lower(): evidence += "; pinned library provenance"
            flags = [flag for flag in chosen["flags"] if not flag.startswith(("--section-base=", "--symbol="))]
            inferred = {**chosen, "flags": flags, "confidence": round(confidence, 3), "evidence": evidence}
            return self._apply_recipe_overrides(inferred, override_pipeline, override_flags)
        pipeline = "kmc+asn64"; family = "kmc"
        inferred = {"pipeline": pipeline, "flags": list(PROFILES[family].default_flags),
                "confidence": 0.25, "evidence": "image default; no neighboring recipe evidence",
                "assembler": "asn64"}
        return self._apply_recipe_overrides(inferred, override_pipeline, override_flags)

    @staticmethod
    def _apply_recipe_overrides(inferred: dict, pipeline: str | None, flags: str | None) -> dict:
        if not pipeline and not flags: return inferred
        result = dict(inferred)
        if pipeline: result["pipeline"] = pipeline
        if flags: result["flags"] = shlex.split(flags)
        result["confidence"] = 1.0
        result["evidence"] = inferred["evidence"] + "; explicit tranche override"
        result["assembler"] = "explicit" if pipeline else inferred.get("assembler")
        return result

    def validate_source(self, row: dict) -> dict:
        value = row.get("candidate_source")
        if not value: return {"ok": False, "state": "source_missing", "reason": "no candidate source"}
        path = (self.project / value).resolve()
        if not path.is_file(): return {"ok": False, "state": "source_missing", "reason": "candidate source disappeared"}
        text = path.read_text(errors="replace")
        named = bool(re.search(rf"(?m)^[^;{{}}]*\b{re.escape(row['name'])}\s*\([^;]*\)\s*\{{", text))
        template = "N64DK_TEMPLATE_FUNCTION" in text
        if not named and not template:
            return {"ok": False, "state": "source_wrong_function",
                    "reason": "candidate does not define the target function or a declared template"}
        calls = set(re.findall(r"\bfunc_[0-9A-Fa-f]{8}\s*(?=\()", text)) - {row["name"]}
        plausible_size = len(text) <= max(4096, int(row["size"]) * 80)
        target_calls = set(); target_globals = set()
        if row["image"] in self.image_files:
            try:
                check = self.preflight(row, False); image = self.image(row["image"])
                offset = int(check["selected_image_offset"], 0)
                code = image.data[offset:offset + int(row["size"])]
                target_calls = {f"func_{ins.getInstrIndexAsVram():08X}" for ins in mips.instructions(
                    code, int(row["vram"], 0)) if ins.getOpcodeName() == "jal"}
                target_globals = {f"D_{ref.address:08X}" for ref in mips.scan_refs(code, int(row["vram"], 0))
                                  if ref.kind not in {"call", "jump"}}
            except (ValueError, OSError): pass
        source_globals = set(re.findall(r"\bD_[0-9A-Fa-f]{8}\b", text))
        call_overlap = sorted(calls & target_calls); global_overlap = sorted(source_globals & target_globals)
        if not plausible_size:
            return {"ok": False, "state": "source_wrong_function", "reason": "candidate size is implausible for target interval"}
        if calls and target_calls and not call_overlap:
            return {"ok": False, "state": "source_wrong_function",
                    "reason": "candidate callees do not overlap target call evidence"}
        return {"ok": True, "state": "ready_verified", "path": str(path),
                "digest": hashlib.sha256(path.read_bytes()).hexdigest(), "calls": sorted(calls),
                "plausible_size": plausible_size, "target_calls": sorted(target_calls),
                "call_overlap": call_overlap, "global_overlap": global_overlap,
                "image_provenance": row["image"] if row["image"].lower() in str(path).lower() else "unconfirmed"}

    def snapshot(self) -> dict:
        return {"project": str(self.project), "config": {"include": [str(x) for x in self.config.include],
                "symbols": [str(x) for x in self.symbol_files]}, "metrics": dict(self.metrics),
                "images": {str(path): {"digest": value.digest, "size": len(value.data)}
                           for path, value in self._images.items()},
                "recipe_count": len(self._recipes),
                "digest": hashlib.sha256(json.dumps({"project": str(self.project),
                    "symbols": [str(x) for x in self.symbol_files], "recipes": self._recipes},
                    sort_keys=True).encode()).hexdigest()}
