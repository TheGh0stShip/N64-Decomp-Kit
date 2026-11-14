"""Action-oriented function dossier assembled from project and retained evidence."""
from __future__ import annotations

import csv
import hashlib
import re
import subprocess
from pathlib import Path

from .. import mips
from . import context as contextmod
from .corpus import CorpusIndex, binary_signature
from .layout import from_inventory, preflight
from .provenance import scan_c
from .registry import SessionRegistry
from .source_index import SourceIndex


def _recipes(project: Path, row: dict, limit: int = 6) -> list[dict]:
    target_rom = int(row["rom"], 0)
    result = []
    for path in project.glob(f"config/**/matching_{row['image']}_*units.tsv"):
        header = path.read_text(errors="replace").splitlines()[:2]
        heading = " ".join(header).lower()
        pipeline = ("ido" if "ido" in heading else "as" if "gnu assembler" in heading
                    else "kmc" if "kmc" in heading else "sn" if re.search(r"\bsn\b", heading) else "unknown")
        with path.open(newline="") as stream:
            for values in csv.reader((line for line in stream if line.strip() and not line.startswith("#")),
                                     delimiter="\t"):
                if len(values) < 4:
                    continue
                try:
                    rom, size = int(values[0], 0), int(values[1], 0)
                except ValueError:
                    continue
                if Path(values[2]).suffix.lower() in {".s", ".asm"}:
                    continue
                result.append({"pipeline_family": pipeline, "flags": values[3],
                               "source": values[2], "rom": f"0x{rom:X}",
                               "distance": min(abs(target_rom - rom), abs(target_rom - (rom + size))),
                               "evidence": str(path.relative_to(project))})
    result.sort(key=lambda item: (item["distance"], item["pipeline_family"], item["flags"]))
    unique = []
    seen = set()
    for item in result:
        key = (item["pipeline_family"], item["flags"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique[:limit]


def _candidate(project: Path, row: dict) -> dict | None:
    index = SourceIndex(project)
    try:
        found = index.find(row["name"], int(row["vram"], 0))
    finally:
        index.close()
    known = {item["path"] for item in found}
    scratch = project / ".tmp"
    if scratch.is_dir():
        scan = subprocess.run(["rg", "--files", str(scratch), "-g", f"*{row['name']}*.c"],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        for value in scan.stdout.splitlines():
            path = Path(value)
            relative = str(path.relative_to(project))
            if relative not in known:
                raw = path.read_bytes()
                found.append({"path": relative, "digest": hashlib.sha256(raw).hexdigest(),
                              "mtime_ns": path.stat().st_mtime_ns, "size": len(raw)})
                known.add(relative)
    if not found:
        return None
    selected = found[0]
    path = project / selected["path"]
    text = path.read_text(errors="replace")
    verdict = scan_c(text)
    named = bool(re.search(rf"\b{re.escape(row['name'])}\s*\(", text))
    prototypes = re.findall(r"(?m)^\s*([\w\s*]+\b\w+\s*\([^;{{]*\))\s*\{", text)
    return {**selected, "selected_because": "exact function name/address candidate index match",
            "archived_sources": found,
            "function_name_present": named, "prototypes": prototypes[:4],
            "provenance": verdict.verdict.value, "provenance_reasons": list(verdict.reasons)}


def dossier(project: str | Path, inventory: dict, row: dict, image_path: str | Path,
            corpus_path: str | Path | None = None, include_all: bool = False) -> dict:
    root = Path(project).resolve()
    layout = from_inventory(row)
    data = Path(image_path).read_bytes()
    try:
        check = preflight(image_path, layout, row.get("catalogue_status", ""))
        selected_offset = int(check["selected_image_offset"], 0)
    except ValueError as error:
        candidates = []
        for authority, offset in (("raw-overlay", layout.rom),
                                  ("resident-composite", layout.function_vram - 0x80000400 + 0x1000)):
            if 0 <= offset <= len(data) - layout.function_size:
                candidate_code = data[offset:offset + layout.function_size]
                decoded = list(mips.instructions(candidate_code, layout.function_vram))
                valid = sum(ins.getRaw() == 0 or (ins.isValid() and ins.isImplemented()) for ins in decoded)
                terminal = any(ins.isJrRa() or ins.isJrNotRa() or ins.isBranch() or ins.isJumpWithAddress()
                               for ins in decoded[-2:])
                candidates.append({"authority": authority, "offset": f"0x{offset:X}",
                                   "score": valid + int(terminal) * len(decoded)})
        selected = max(candidates, key=lambda item: item["score"]) if candidates else {"offset": f"0x{layout.rom:X}"}
        selected_offset = int(selected["offset"], 0)
        check = {"ok": False, "error": str(error), "mapping": layout.as_dict(),
                 "mapping_candidates": candidates, "selected_image_offset": selected["offset"],
                 "warnings": ["preflight disagreement; dossier evidence retained"], "returns": []}
    code = data[selected_offset:selected_offset + layout.function_size]
    same = [item for item in inventory["functions"] if item["image"] == row["image"]]
    index = same.index(row)
    neighbours = [{key: item[key] for key in ("name", "vram", "size", "state", "catalogue_status")}
                  for item in same[max(0, index - 3):index + 4] if item is not row]
    context = contextmod.bundle(image_path, layout.function_vram, layout.function_size,
                                selected_offset, neighbours)
    callers = len(context["callers"])
    returns = len(check["returns"])
    confidence = 0.45 + min(callers, 3) * 0.1 + (0.2 if returns else 0)
    if layout.function_size < 24:
        confidence -= 0.2
    if check["warnings"]:
        confidence -= 0.15
    confidence = max(0.0, min(1.0, confidence))
    target_context = {"rom_sha256": hashlib.sha256(data).hexdigest(), "vram_delta": layout.delta,
                      "addr": layout.function_vram, "size": layout.function_size}
    registry = SessionRegistry(root)
    try:
        history = registry.same_target(target_context)
    finally:
        registry.close()
    similar = []
    if corpus_path:
        corpus = CorpusIndex(corpus_path)
        try:
            similar = corpus.query(binary_signature(code, layout.function_vram))
        finally:
            corpus.close()
    body = list(mips.instructions(code, layout.function_vram))
    stack = [ins.getImmediate() for ins in body[:8]
             if ins.getOpcodeName() in {"addiu", "daddiu"} and mips.reg(ins.rs) == 29 and mips.reg(ins.rt) == 29]
    likely_prototype = {"arguments_observed": sorted({mips.reg(ins.rs) - 4 for ins in body[:12]
                                                       if ins.readsRs() and 4 <= mips.reg(ins.rs) <= 7}),
                        "stack_frame": (-((stack[0] - 0x10000) if stack and stack[0] & 0x8000 else stack[0])
                                        if stack else 0)}
    result = {"function": {key: row[key] for key in
                           ("id", "image", "name", "vram", "size", "state", "reason")},
              "layout_preflight": check, "boundary": {"confidence": round(confidence, 3),
              "callers": callers, "returns": returns,
              "handwritten_likelihood": "high" if "handwritten" in row.get("catalogue_status", "") else
                                        "medium" if layout.function_size < 24 else "low"},
              "likely_prototype": likely_prototype, "candidate": _candidate(root, row),
              "qualified_recipes": _recipes(root, row), "session_history": history,
              "best_historical": history[0] if history else None, "similar_functions": similar,
              "next_actions": []}
    if not result["candidate"]:
        result["next_actions"].append("reconstruct an ordinary-C candidate from the verified context")
    if confidence < 0.6:
        result["next_actions"].append("audit the function boundary before spending matching budget")
    if history:
        result["next_actions"].append("branch from the retained project-wide frontier")
    if similar:
        result["next_actions"].append("inspect the highest-ranked corpus analogue before proposing new source")
    compact_context = dict(context)
    if not include_all:
        compact_context["disassembly"] = context["disassembly"][:12]
        compact_context["globals"] = context["globals"][:12]
    result["context"] = compact_context
    return result
