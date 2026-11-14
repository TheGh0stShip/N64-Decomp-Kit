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
from .layout import from_inventory, preflight, resolve_image_map
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
    calls = sorted(set(re.findall(r"\b(func_[0-9A-Fa-f]{8})\s*\(", text)) - {row["name"]})
    return {**selected, "selected_because": "exact function name/address candidate index match",
            "archived_sources": found,
            "function_name_present": named, "prototypes": prototypes[:4],
            "include_order": re.findall(r'(?m)^\s*#\s*include\s*[<"]([^>"]+)', text),
            "callees": calls,
            "provenance": verdict.verdict.value, "provenance_reasons": list(verdict.reasons)}


def _declarations(project: Path, candidate: dict | None) -> dict:
    if not candidate: return {"callees": [], "conflicts": [], "historical_style": "unknown"}
    symbols = candidate.get("callees", [])
    if not symbols: return {"callees": [], "conflicts": [], "historical_style": "unknown"}
    expression = "|".join(re.escape(symbol) for symbol in symbols)
    scan = subprocess.run(["rg", "-n", "--glob", "*.c", "--glob", "*.h", expression,
                           str(project / "src"), str(project / "include")], text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    grouped = {symbol: [] for symbol in symbols}
    candidate_text = (project / candidate["path"]).read_text(errors="replace")
    def declaration_for(text: str, symbol: str):
        return re.search(rf"(?:^|;)\s*(?:extern\s+|static\s+)?[A-Za-z_]\w*(?:\s*\*)?\s+"
                         rf"{re.escape(symbol)}\s*\([^)]*\)\s*(?:;|\{{)", text)

    for number, text in enumerate(candidate_text.splitlines(), 1):
        for symbol in symbols:
            if not re.search(rf"\b{re.escape(symbol)}\s*\(", text): continue
            declaration_form = declaration_for(text, symbol)
            grouped[symbol].append({"path": candidate["path"], "line": number, "text": text.strip(),
                                    "kind": "definition" if declaration_form and "{" in text else
                                            "declaration" if declaration_form and ";" in text else "call"})
    for line in scan.stdout.splitlines():
        match = re.match(r"([^:]+):(\d+):(.*)", line)
        if not match: continue
        path, line_number, text = match.groups()
        for symbol in symbols:
            if re.search(rf"\b{re.escape(symbol)}\s*\(", text):
                declaration_form = declaration_for(text, symbol)
                grouped[symbol].append({"path": str(Path(path).relative_to(project)),
                                        "line": int(line_number), "text": text.strip(),
                                        "kind": "definition" if declaration_form and "{" in text else
                                                "declaration" if declaration_form and ";" in text else "call"})
    conflicts = []
    for symbol, rows in grouped.items():
        forms = sorted({row["text"] for row in rows if row["kind"] == "declaration"})
        if len(forms) > 1: conflicts.append({"symbol": symbol, "declarations": forms})
    declarations = [row for rows in grouped.values() for row in rows if row["kind"] == "declaration"]
    return {"callees": [{"symbol": symbol, "evidence": rows,
                          "compiled_against": [row for row in rows if row["path"] == candidate["path"] or
                                               any(row["path"].endswith(header) for header in candidate.get("include_order", []))]}
                         for symbol, rows in grouped.items()],
            "conflicts": conflicts,
            "include_order": candidate.get("include_order", []),
            "historical_style": ("implicit-or-old-style-plausible" if not declarations else "prototyped"),
            "neighbor_exact_evidence": [row for row in declarations if row["path"] == candidate["path"]]}


def dossier(project: str | Path, inventory: dict, row: dict, image_path: str | Path,
            corpus_path: str | Path | None = None, include_all: bool = False) -> dict:
    root = Path(project).resolve()
    layout = from_inventory(row)
    data = Path(image_path).read_bytes()
    try:
        check = preflight(image_path, layout, row.get("catalogue_status", ""))
        selected_offset = int(check["selected_image_offset"], 0)
    except ValueError as error:
        try:
            resolved = resolve_image_map(image_path, layout)
            candidates = [{key: (f"0x{value:X}" if key == "offset" else value)
                           for key, value in item.items() if key != "code"} for item in resolved["candidates"]]
            selected_offset = resolved["selected"]["offset"]
        except ValueError:
            candidates = []; selected_offset = layout.rom
        check = {"ok": False, "error": str(error), "mapping": layout.as_dict(),
                 "mapping_candidates": candidates, "selected_image_offset": f"0x{selected_offset:X}",
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
    target_context = {"rom_sha256": hashlib.sha256(data).hexdigest(),
                      "vram_delta": layout.function_vram - selected_offset,
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
    candidate = _candidate(root, row)
    result = {"function": {key: row[key] for key in
                           ("id", "image", "name", "vram", "size", "state", "reason")},
              "layout_preflight": check, "boundary": {"confidence": round(confidence, 3),
              "callers": callers, "returns": returns,
              "handwritten_likelihood": "high" if "handwritten" in row.get("catalogue_status", "") else
                                        "medium" if layout.function_size < 24 else "low"},
              "likely_prototype": likely_prototype, "candidate": candidate,
              "translation_unit_declarations": _declarations(root, candidate),
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
