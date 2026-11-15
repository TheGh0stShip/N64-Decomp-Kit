"""Image-layout derivation and mandatory target preflight."""
from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass, asdict
from pathlib import Path

from .. import mips

PREFLIGHT_VERSION = "image-map-v3"


def configured_image_path(project: str | Path, image: str) -> Path:
    """Resolve a logical image name through ``n64dk.toml`` without filename guessing."""
    project = Path(project).expanduser().resolve()
    config = project / "n64dk.toml"
    if not config.is_file():
        raise ValueError(f"logical image {image!r} has no n64dk.toml configuration")
    entries = tomllib.loads(config.read_text()).get("images", {})
    normalized = image.replace("_", "").replace("-", "").lower()
    matches = [(name, value) for name, value in entries.items()
               if name.replace("_", "").replace("-", "").lower() == normalized]
    if len(matches) != 1:
        available = ", ".join(sorted(entries)) or "none"
        raise ValueError(f"logical image {image!r} resolved to {len(matches)} entries; available: {available}")
    _name, entry = matches[0]
    value = entry if isinstance(entry, str) else next(
        (entry[key] for key in ("composite", "path", "raw") if entry.get(key)), None)
    if not value:
        raise ValueError(f"logical image {image!r} has no path/composite/raw file")
    path = Path(value)
    path = path if path.is_absolute() else project / path
    path = path.resolve()
    if not path.is_file():
        raise ValueError(f"configured image is missing: {path}")
    return path


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _raw_sibling(path: Path) -> Path | None:
    name = path.name
    for marker in ("_composite", "-composite"):
        if marker in name:
            candidate = path.with_name(name.replace(marker, "", 1))
            return candidate if candidate.is_file() else None
    return None


def resolve_image_map(path: str | Path, layout: "Layout", data: bytes | None = None,
                      raw_data: bytes | None = None) -> dict:
    """Resolve physical bytes using an anchored image region, never a VRAM guess alone."""
    image_path = Path(path).expanduser().resolve()
    data = image_path.read_bytes() if data is None else data
    relative = layout.function_vram - layout.section_vram
    raw_offset = layout.section_rom + relative
    header_vram = int.from_bytes(data[8:12], "big") if len(data) >= 12 else None
    composite_image = any(marker in image_path.stem.lower()
                          for marker in ("composite", "with_resident", "resident_rodata"))
    candidates: list[dict] = []

    def add(authority: str, offset: int, linked_vram: int | None, transform: str,
            agreement: list[str], canonical: bool = False) -> None:
        if offset < 0 or offset + layout.function_size > len(data): return
        code = data[offset:offset + layout.function_size]
        decoded = list(mips.instructions(code, layout.function_vram))
        valid = sum(ins.getRaw() == 0 or (ins.isValid() and ins.isImplemented()) for ins in decoded)
        terminal = int(any(ins.isJrRa() or ins.isJrNotRa() or ins.isJumpWithAddress()
                           or ins.isBranch() for ins in decoded[-2:]))
        candidates.append({"authority": authority, "offset": offset, "linked_vram": linked_vram,
                           "catalogue_vram": layout.section_vram, "transform": transform,
                           "agreement": agreement, "canonical": canonical, "digest": _digest(code),
                           "score": valid + terminal * max(2, len(decoded)), "code": code})

    add("raw-overlay", raw_offset, layout.section_vram,
        "section_rom + (catalogue_vram - catalogue_base)", ["catalogue"],
        not composite_image)
    sibling = _raw_sibling(image_path)
    region_offset = None
    raw_target_digest = None
    if sibling:
        raw_data = sibling.read_bytes() if raw_data is None else raw_data
        payload = raw_data[layout.section_rom:layout.section_rom + layout.section_size]
        positions = []
        cursor = 0
        while payload and (found := data.find(payload, cursor)) >= 0:
            positions.append(found); cursor = found + 1
            if len(positions) > 2: break
        if len(positions) == 1:
            region_offset = positions[0]
        elif not positions and len(payload) >= 256:
            anchor = payload[:min(4096, len(payload))]
            cursor = 0
            while (found := data.find(anchor, cursor)) >= 0:
                if data[found:found + len(payload)] == payload: positions.append(found)
                cursor = found + 1
            if len(positions) == 1: region_offset = positions[0]
        if region_offset is not None:
            linked_base = ((header_vram or 0x80000400) + region_offset - 0x1000)
            canonical_offset = region_offset + relative
            raw_code = raw_data[raw_offset:raw_offset + layout.function_size]
            raw_target_digest = _digest(raw_code)
            add("anchored-composite-region", canonical_offset, linked_base,
                "region_offset + (catalogue_vram - catalogue_base)",
                ["catalogue", "raw-image", "composite-payload", "image-header"], True)
    canonical = [row for row in candidates if row["canonical"]]
    if canonical:
        selected = canonical[0]
        if raw_target_digest and selected["digest"] != raw_target_digest:
            raise ValueError("anchored composite bytes disagree with the raw overlay image")
    else:
        ranked = sorted(candidates, key=lambda row: row["score"], reverse=True)
        if not ranked:
            raise ValueError("target interval is outside every image mapping")
        if composite_image:
            raise ValueError("ambiguous composite image mapping: no unique raw-image anchor")
        selected = ranked[0]
        if len(ranked) > 1 and ranked[0]["score"] == ranked[1]["score"] and ranked[0]["digest"] != ranked[1]["digest"]:
            raise ValueError("ambiguous image mapping: equally plausible offsets contain different bytes")
    competing = [row for row in candidates if row["offset"] != selected["offset"]
                 and row["digest"] == selected["digest"]]
    return {"image": str(image_path), "image_digest": _digest(data), "image_size": len(data),
            "image_region": {"offset": f"0x{region_offset:X}" if region_offset is not None else None,
                             "size": layout.section_size, "raw_sibling": str(sibling) if sibling else None},
            "raw_rom": f"0x{raw_offset:X}",
            "coordinates": {"loaded_image_offset": f"0x{relative:X}",
                "manifest_rom_offset": f"0x{raw_offset:X}", "physical_rom_offset": None,
                "selected_image_offset": f"0x{selected['offset']:X}",
                "linked_vram": (f"0x{selected['linked_vram'] + relative:X}"
                                if selected["linked_vram"] is not None else None),
                "image_vram_delta": (f"0x{layout.function_vram - selected['offset']:X}"),
                "section_vram": f"0x{layout.section_vram:X}",
                "section_rom": f"0x{layout.section_rom:X}",
                "coordinate_space": "catalogue-section+loaded-image"},
            "catalogue_vram": f"0x{layout.function_vram:X}",
            "catalogue_base": f"0x{layout.section_vram:X}",
            "linked_vram": (f"0x{selected['linked_vram'] + relative:X}"
                            if selected["linked_vram"] is not None else None),
            "linked_base": (f"0x{selected['linked_vram']:X}" if selected["linked_vram"] is not None else None),
            "selected": selected, "target_digest": selected["digest"],
            "raw_target_digest": raw_target_digest, "duplicate_byte_candidates": len(competing),
            "candidates": candidates}


def physical_collisions(path: str | Path, layout: "Layout", mapping: dict,
                        inventory_rows: list[dict]) -> list[dict]:
    """Identify candidate offsets/digests already owned by another catalogue member."""
    data = Path(path).read_bytes(); region = mapping["image_region"].get("offset")
    if not region: return []
    region_offset = int(region, 0)
    result = []
    for candidate in mapping["candidates"]:
        for row in inventory_rows:
            if row.get("image") != layout.image or int(row["vram"], 0) == layout.function_vram:
                continue
            physical = region_offset + int(row["vram"], 0) - int(row["section_vram"], 0)
            size = int(row["size"])
            digest = _digest(data[physical:physical + size]) if 0 <= physical <= len(data) - size else None
            same_interval = candidate["offset"] == physical and layout.function_size == size
            same_digest = candidate["digest"] == digest and layout.function_size == size
            if not (same_interval or same_digest): continue
            result.append({"candidate_authority": candidate["authority"],
                           "candidate_offset": f"0x{candidate['offset']:X}",
                           "owner": row["name"], "owner_path": row.get("owner"),
                           "ownership_state": row.get("ownership_state"),
                           "physical_interval": f"0x{physical:X}:0x{physical + size:X}",
                           "target_digest": digest, "same_interval": same_interval,
                           "same_digest": same_digest,
                           "mapping_error_delta": f"{candidate['offset'] - mapping['selected']['offset']:+#x}"})
    return result


def _entry_evidence(data: bytes, layout: Layout, function_offset: int | None = None) -> dict:
    """Conservative entry analysis over the authoritative containing section."""
    reasons: list[str] = []
    start_off = layout.rom if function_offset is None else function_offset
    section_lo = start_off - (layout.function_vram - layout.section_vram)
    if section_lo < 0:
        return {"entry_status": "reject", "reason_codes": ["section_mapping_before_image"],
                "confidence": 0.99, "incoming_edges": [], "call_target_evidence": [],
                "predecessor_fallthrough": False, "saved_register_live_ins": [],
                "saved_register_diagnostics": [], "saved_register_restores": []}
    section_hi = min(len(data), section_lo + layout.section_size)
    entry = layout.function_vram
    incoming = []
    for off in range(section_lo, section_hi - 3, 4):
        address = layout.section_vram + off - section_lo
        ins = mips.decode(int.from_bytes(data[off:off + 4], "big"), address)
        if ins.isBranch():
            try:
                target = ins.getBranchVramGeneric()
            except Exception:
                target = None
            if target == entry:
                incoming.append(address)
        elif ins.isJumpWithAddress() and ins.getInstrIndexAsVram() == entry:
            incoming.append(address)
    predecessor_fallthrough = False
    label_in_delay_slot = False
    if start_off >= section_lo + 4:
        previous = mips.decode(int.from_bytes(data[start_off - 4:start_off], "big"), entry - 4)
        label_in_delay_slot = previous.hasDelaySlot()
    if start_off >= section_lo + 8:
        control_off = start_off - 8
        # Alignment padding can follow a completed return. Walk over extra zero words,
        # preserving the ordinary control+delay-slot interpretation otherwise.
        if int.from_bytes(data[start_off - 4:start_off], "big") == 0:
            cursor = start_off - 8
            while cursor >= section_lo and int.from_bytes(data[cursor:cursor + 4], "big") == 0:
                cursor -= 4
            if cursor >= section_lo:
                control_off = cursor
        control = mips.decode(int.from_bytes(data[control_off:control_off + 4], "big"),
                              entry - (start_off - control_off))
        # The immediately preceding word is this instruction's delay slot. Conditional
        # branches can still flow into the proposed entry; jumps and returns cannot.
        predecessor_fallthrough = not (control.hasDelaySlot() and
                                       (control.isJrRa() or control.isJrNotRa() or
                                        control.isUnconditionalBranch() or
                                        (control.isJumpWithAddress() and not control.doesLink())))
    elif start_off > section_lo:
        predecessor_fallthrough = True
    if label_in_delay_slot:
        reasons.append("label_inside_predecessor_delay_slot")
    if predecessor_fallthrough and not incoming:
        reasons.append("predecessor_fallthrough")

    defined = {0, 4, 5, 6, 7, 28, 29, 31}  # zero, ABI args, gp, sp, ra
    suspicious = set()
    suspicious_sites = []
    restored_without_save = set()
    saved_to_stack = set()
    code = data[start_off:start_off + layout.function_size]
    for ins in mips.instructions(code, entry):
        preservation = ins.doesStore() and mips.reg(ins.rs) == 29 and ins.readsRt()
        if preservation:
            source_value = mips.reg(ins.rt)
            if source_value in set(range(16, 24)) | {30, 31}:
                saved_to_stack.add(source_value)
        for attr in ("rs", "rt", "rd"):
            reads = getattr(ins, "reads" + attr.upper()[0] + attr[1:], None)
            if reads and reads():
                value = mips.reg(getattr(ins, attr))
                if preservation and attr == "rt" and value in set(range(16, 24)) | {30, 31}:
                    continue
                if value in set(range(16, 24)) | {30} and value not in defined:
                    suspicious.add(value)
                    suspicious_sites.append({"address": f"0x{ins.vram:08X}",
                                             "instruction": ins.disassemble(), "register": value})
        destination = ins.getDestinationGpr()
        if destination is not None:
            destination_value = mips.reg(destination)
            if (ins.doesLoad() and destination_value in set(range(16, 24)) | {30}
                    and mips.reg(ins.rs) == 29 and destination_value not in saved_to_stack):
                restored_without_save.add(destination_value)
            defined.add(destination_value)
        if ins.hasDelaySlot():
            break
    if suspicious:
        reasons.append("saved_register_read_before_definition")
    if restored_without_save:
        reasons.append("saved_register_restore_without_save")
    first_names = [ins.getOpcodeName() for ins in list(mips.instructions(code, entry))[:4]]
    if (suspicious or restored_without_save) and any(name in {"lw", "ld", "lwc1", "ldc1"} for name in first_names):
        reasons.append("epilogue_without_prologue")
    call_targets = [site for site in incoming if mips.decode(
        int.from_bytes(data[section_lo + site - layout.section_vram:
                            section_lo + site - layout.section_vram + 4], "big"), site).doesLink()]
    confidence = min(0.99, 0.55 + 0.14 * len(reasons) + (0.20 if suspicious else 0))
    return {"entry_status": "reject" if reasons else "accept", "reason_codes": reasons,
            "confidence": round(confidence if reasons else 0.85, 3),
            "incoming_edges": [f"0x{x:08X}" for x in incoming],
            "call_target_evidence": [f"0x{x:08X}" for x in call_targets],
            "predecessor_fallthrough": predecessor_fallthrough,
            "saved_register_live_ins": sorted(suspicious),
            "saved_register_diagnostics": suspicious_sites,
            "saved_register_restores": sorted(restored_without_save)}


@dataclass(frozen=True)
class Layout:
    image: str
    section_rom: int
    section_vram: int
    section_size: int
    function_vram: int
    function_size: int
    authority: str = "catalogue-section"

    @property
    def delta(self) -> int:
        return self.section_vram - self.section_rom

    @property
    def rom(self) -> int:
        return self.section_rom + self.function_vram - self.section_vram

    def as_dict(self) -> dict:
        value = asdict(self)
        for key in ("section_rom", "section_vram", "function_vram"):
            value[key] = f"0x{value[key]:X}"
        value["vram_delta"] = f"0x{self.delta:X}"
        value["function_rom"] = f"0x{self.rom:X}"
        value["raw_rom"] = f"0x{self.rom:X}"
        value["catalogue_composite_rom"] = f"0x{self.function_vram - 0x80000400 + 0x1000:X}"
        return value


def from_inventory(row: dict) -> Layout:
    required = ("section_rom", "section_vram", "section_size")
    missing = [key for key in required if key not in row]
    if missing:
        raise ValueError("inventory lacks authoritative section mapping: " + ", ".join(missing))
    return Layout(row["image"], int(row["section_rom"], 0), int(row["section_vram"], 0),
                  int(row["section_size"]), int(row["vram"], 0), int(row["size"]))


def preflight(path: str | Path, layout: Layout, catalogue_status: str = "",
              strict_entry: bool = False, data: bytes | None = None,
              raw_data: bytes | None = None) -> dict:
    data = Path(path).read_bytes() if data is None else data
    errors: list[str] = []
    warnings: list[str] = []
    section_end = layout.section_vram + layout.section_size
    function_end = layout.function_vram + layout.function_size
    if not layout.section_vram <= layout.function_vram < function_end <= section_end:
        errors.append("target VRAM interval is outside its catalogue section")
    if layout.rom < layout.section_rom or layout.rom + layout.function_size > layout.section_rom + layout.section_size:
        errors.append("target ROM interval is outside its catalogue section")
    try:
        mapping = resolve_image_map(path, layout, data, raw_data)
        selected = mapping["selected"]
        selected_authority, selected_offset, code = selected["authority"], selected["offset"], selected["code"]
        candidates = mapping["candidates"]
    except ValueError as error:
        errors.append(str(error)); mapping = None
        selected_authority, selected_offset, code, candidates = "none", layout.rom, b"", []
    analysis_layout = layout
    if mapping and mapping.get("linked_base"):
        linked_base = int(mapping["linked_base"], 0)
        linked_function = linked_base + (layout.function_vram - layout.section_vram)
        analysis_layout = Layout(layout.image, layout.section_rom, linked_base,
                                 layout.section_size, linked_function,
                                 layout.function_size, "linked-image-region")
    decoded = list(mips.instructions(code, analysis_layout.function_vram))
    valid = sum(ins.getRaw() == 0 or (ins.isValid() and ins.isImplemented()) for ins in decoded)
    ratio = valid / len(decoded) if decoded else 0.0
    if not decoded or ratio < 0.90:
        errors.append(f"target bytes are data-like or invalid code ({valid}/{len(decoded)} valid words)")
    first = decoded[0].disassemble() if decoded else None
    last = decoded[-1].disassemble() if decoded else None
    returns = mips.returns(code, analysis_layout.function_vram)
    tail = decoded[-2:] if len(decoded) >= 2 else decoded
    terminal = any(ins.isJrRa() or ins.isJrNotRa() or
                   (ins.isJumpWithAddress() and not ins.doesLink()) or
                   (ins.isUnconditionalBranch() and not ins.doesLink()) or
                   ins.getOpcodeName() in {"eret", "break"} for ins in tail)
    falls = "fall" in catalogue_status.lower()
    if not terminal and not falls:
        errors.append("catalogue boundary has no return/tail terminator in its final two words")
    delay = {"owned": True, "terminator": None, "delay_slot": None}
    if decoded:
        terminal_indexes = [i for i, ins in enumerate(decoded) if ins.hasDelaySlot() and
                            (ins.isJrRa() or ins.isJrNotRa() or ins.isJumpWithAddress() or
                             ins.isBranch())]
        if terminal_indexes:
            last_index = terminal_indexes[-1]
            delay["terminator"] = f"0x{decoded[last_index].vram:08X}"
            if last_index + 1 >= len(decoded):
                delay["owned"] = False
                errors.append("catalogue interval ends before terminator delay slot")
            else:
                delay["delay_slot"] = f"0x{decoded[last_index + 1].vram:08X}"
    if terminal and falls:
        warnings.append("catalogue says fall-through but target ends in a terminator")
    entry = _entry_evidence(data, analysis_layout, selected_offset) if code else {"entry_status": "reject",
                                                          "reason_codes": ["no_target_bytes"],
                                                          "confidence": 1.0}
    if strict_entry and entry["entry_status"] == "reject":
        errors.append("entry preflight rejected interval: " + ", ".join(entry["reason_codes"]))
    if errors:
        raise ValueError("image-layout preflight failed: " + "; ".join(errors))
    return {"ok": True, "preflight_version": PREFLIGHT_VERSION,
            "mapping": {**layout.as_dict(), **({
                "composite_rom": f"0x{selected_offset:X}",
                "linked_vram": mapping["linked_vram"], "linked_base": mapping["linked_base"],
                "image_region": mapping["image_region"], "target_digest": mapping["target_digest"],
                "image_digest": mapping["image_digest"]} if mapping else {})},
            "mapping_authority": layout.authority,
            "selected_image_mapping": selected_authority,
            "selected_image_offset": f"0x{selected_offset:X}",
            "mapping_candidates": [{key: (f"0x{value:X}" if key == "offset" else value)
                                    for key, value in candidate.items() if key != "code"}
                                   for candidate in candidates],
            "image": str(Path(path).resolve()), "image_size": len(data),
            "first_instruction": first, "last_instruction": last,
            "valid_words": valid, "total_words": len(decoded), "valid_ratio": ratio,
            "returns": [f"0x{value:08X}" for value in returns],
            "boundary": "fall-through" if falls else "return-or-tail", "entry_preflight": entry,
            "delay_slot_ownership": delay, "warnings": warnings}


def boundary_proposals(path: str | Path, layout: Layout, radius: int = 0x40,
                       data: bytes | None = None) -> list[dict]:
    """Suggest bounded aligned intervals with a plausible entry and owned terminator slot."""
    image = Path(path).read_bytes() if data is None else data
    try: mapping = resolve_image_map(path, layout, image)
    except ValueError: return []
    current = mapping["selected"]["offset"]; proposals = []
    lower = max(0, current - radius); upper = min(len(image) - 8, current + layout.function_size + radius)
    starts = []
    for offset in range(lower - lower % 4, min(current + 1, upper), 4):
        ins = mips.decode(int.from_bytes(image[offset:offset + 4], "big"),
                          layout.function_vram + offset - current)
        if (ins.getOpcodeName() in {"addiu", "daddiu"} and mips.reg(ins.rs) == 29 and mips.reg(ins.rt) == 29) or offset == current:
            starts.append(offset)
    for start in starts[-4:]:
        body = list(mips.instructions(image[start:upper + 8], layout.function_vram + start - current))
        for index, ins in enumerate(body[:-1]):
            if ins.isJrRa() or ins.isJrNotRa() or (ins.isJumpWithAddress() and not ins.doesLink()):
                end = start + (index + 2) * 4
                if end <= upper + 8:
                    proposals.append({"start": f"0x{layout.function_vram + start - current:08X}",
                        "end": f"0x{layout.function_vram + end - current:08X}",
                        "size": end - start, "evidence": ["aligned entry/prologue",
                            "terminator plus owned delay slot", "bounded local CFG search"]})
                break
    unique = {(row["start"], row["end"]): row for row in proposals}
    return sorted(unique.values(), key=lambda row: (abs(int(row["start"], 0) - layout.function_vram), row["size"]))[:8]
