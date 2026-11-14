"""Image-layout derivation and mandatory target preflight."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

from .. import mips


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
        return value


def from_inventory(row: dict) -> Layout:
    required = ("section_rom", "section_vram", "section_size")
    missing = [key for key in required if key not in row]
    if missing:
        raise ValueError("inventory lacks authoritative section mapping: " + ", ".join(missing))
    return Layout(row["image"], int(row["section_rom"], 0), int(row["section_vram"], 0),
                  int(row["section_size"]), int(row["vram"], 0), int(row["size"]))


def preflight(path: str | Path, layout: Layout, catalogue_status: str = "") -> dict:
    data = Path(path).read_bytes()
    errors: list[str] = []
    warnings: list[str] = []
    section_end = layout.section_vram + layout.section_size
    function_end = layout.function_vram + layout.function_size
    if not layout.section_vram <= layout.function_vram < function_end <= section_end:
        errors.append("target VRAM interval is outside its catalogue section")
    if layout.rom < layout.section_rom or layout.rom + layout.function_size > layout.section_rom + layout.section_size:
        errors.append("target ROM interval is outside its catalogue section")
    if layout.rom < 0 or layout.rom + layout.function_size > len(data):
        errors.append("target interval is outside the loaded image")
        code = b""
    else:
        code = data[layout.rom:layout.rom + layout.function_size]
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
    if terminal and falls:
        warnings.append("catalogue says fall-through but target ends in a terminator")
    if errors:
        raise ValueError("image-layout preflight failed: " + "; ".join(errors))
    return {"ok": True, "mapping": layout.as_dict(), "mapping_authority": layout.authority,
            "image": str(Path(path).resolve()), "image_size": len(data),
            "first_instruction": first, "last_instruction": last,
            "valid_words": valid, "total_words": len(decoded), "valid_ratio": ratio,
            "returns": [f"0x{value:08X}" for value in returns],
            "boundary": "fall-through" if falls else "return-or-tail", "warnings": warnings}
