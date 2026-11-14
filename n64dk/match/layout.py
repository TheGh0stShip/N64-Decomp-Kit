"""Image-layout derivation and mandatory target preflight."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

from .. import mips

PREFLIGHT_VERSION = "entry-delay-v2"


def _entry_evidence(data: bytes, layout: Layout, function_offset: int | None = None) -> dict:
    """Conservative entry analysis over the authoritative containing section."""
    reasons: list[str] = []
    start_off = layout.rom if function_offset is None else function_offset
    section_lo = start_off - (layout.function_vram - layout.section_vram)
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
        control = mips.decode(int.from_bytes(data[start_off - 8:start_off - 4], "big"), entry - 8)
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
        value["composite_rom"] = f"0x{self.function_vram - 0x80000400 + 0x1000:X}"
        return value


def from_inventory(row: dict) -> Layout:
    required = ("section_rom", "section_vram", "section_size")
    missing = [key for key in required if key not in row]
    if missing:
        raise ValueError("inventory lacks authoritative section mapping: " + ", ".join(missing))
    return Layout(row["image"], int(row["section_rom"], 0), int(row["section_vram"], 0),
                  int(row["section_size"]), int(row["vram"], 0), int(row["size"]))


def preflight(path: str | Path, layout: Layout, catalogue_status: str = "",
              strict_entry: bool = False) -> dict:
    data = Path(path).read_bytes()
    errors: list[str] = []
    warnings: list[str] = []
    section_end = layout.section_vram + layout.section_size
    function_end = layout.function_vram + layout.function_size
    if not layout.section_vram <= layout.function_vram < function_end <= section_end:
        errors.append("target VRAM interval is outside its catalogue section")
    if layout.rom < layout.section_rom or layout.rom + layout.function_size > layout.section_rom + layout.section_size:
        errors.append("target ROM interval is outside its catalogue section")
    raw_offset = layout.rom
    composite_offset = layout.function_vram - 0x80000400 + 0x1000
    candidates = []
    for authority, offset in (("raw-overlay", raw_offset), ("resident-composite", composite_offset)):
        if offset < 0 or offset + layout.function_size > len(data):
            continue
        candidate_code = data[offset:offset + layout.function_size]
        candidate_decoded = list(mips.instructions(candidate_code, layout.function_vram))
        candidate_valid = sum(ins.getRaw() == 0 or (ins.isValid() and ins.isImplemented()) for ins in candidate_decoded)
        terminal_score = int(any(ins.isJrRa() or ins.isJrNotRa() or ins.isJumpWithAddress()
                                 or ins.isBranch() for ins in candidate_decoded[-2:]))
        candidates.append((candidate_valid + terminal_score * max(2, len(candidate_decoded)),
                           authority, offset, candidate_code))
    if not candidates:
        errors.append("target interval is outside every canonical image mapping")
        selected_authority, selected_offset, code = "none", raw_offset, b""
    else:
        _score, selected_authority, selected_offset, code = max(candidates, key=lambda item: item[0])
    decoded = list(mips.instructions(code, layout.function_vram))
    valid = sum(ins.getRaw() == 0 or (ins.isValid() and ins.isImplemented()) for ins in decoded)
    ratio = valid / len(decoded) if decoded else 0.0
    if not decoded or ratio < 0.90:
        errors.append(f"target bytes are data-like or invalid code ({valid}/{len(decoded)} valid words)")
    first = decoded[0].disassemble() if decoded else None
    last = decoded[-1].disassemble() if decoded else None
    returns = mips.returns(code, layout.function_vram)
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
    entry = _entry_evidence(data, layout, selected_offset) if code else {"entry_status": "reject",
                                                          "reason_codes": ["no_target_bytes"],
                                                          "confidence": 1.0}
    if strict_entry and entry["entry_status"] == "reject":
        errors.append("entry preflight rejected interval: " + ", ".join(entry["reason_codes"]))
    if errors:
        raise ValueError("image-layout preflight failed: " + "; ".join(errors))
    return {"ok": True, "preflight_version": PREFLIGHT_VERSION,
            "mapping": layout.as_dict(), "mapping_authority": layout.authority,
            "selected_image_mapping": selected_authority,
            "selected_image_offset": f"0x{selected_offset:X}",
            "mapping_candidates": [{"authority": authority, "offset": f"0x{offset:X}", "score": score}
                                   for score, authority, offset, _code in candidates],
            "image": str(Path(path).resolve()), "image_size": len(data),
            "first_instruction": first, "last_instruction": last,
            "valid_words": valid, "total_words": len(decoded), "valid_ratio": ratio,
            "returns": [f"0x{value:08X}" for value in returns],
            "boundary": "fall-through" if falls else "return-or-tail", "entry_preflight": entry,
            "delay_slot_ownership": delay, "warnings": warnings}
