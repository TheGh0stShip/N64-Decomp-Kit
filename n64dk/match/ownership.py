"""Byte-ownership ledger derived from the authoritative interval inventory.

Every catalogue section is partitioned into non-overlapping classified spans.  The ledger does
not turn claims into proof: verified C, assembly, structural exclusions, manifest claims,
conflicts and unknown bytes remain distinct.  This makes numerator and denominator changes
auditable instead of presenting boundary corrections as decompilation progress.
"""
from __future__ import annotations

from collections import Counter


STATE_CLASS = {
    "manifest_exact_unit": "verified_c",
    "manifest_exact_member": "verified_c",
    "manifest_nonexact": "claimed_c",
    "assembly_unit": "assembly",
    "assembly_member": "assembly",
    "fragment": "fragment",
    "padding": "padding",
    "data": "data",
    "duplicate_owner": "conflict",
    "boundary_conflict": "conflict",
    "scratch_candidate": "unowned_code",
    "tracked_source_unverified": "unowned_code",
    "unowned": "unowned_code",
}
AUTHORITATIVE = {"verified_c", "assembly", "fragment", "padding", "data"}


def build(inventory: dict, image: str | None = None) -> dict:
    rows = [row for row in inventory.get("functions", []) if image is None or row["image"] == image]
    sections = {}
    for row in rows:
        key = (row["image"], int(row["section_vram"], 0), int(row["section_size"]))
        sections.setdefault(key, []).append(row)
    ledgers, all_segments, problems = [], [], []
    for (image_name, start, size), members in sorted(sections.items()):
        end = start + size; cursor = start; segments = []
        ordered = sorted(members, key=lambda row: (int(row["vram"], 0), int(row["size"]), row["name"]))
        for row in ordered:
            left = int(row["vram"], 0); right = left + int(row["size"])
            if left < cursor:
                problems.append({"image": image_name, "kind": "overlap", "at": f"0x{left:X}",
                                 "function": row["name"]})
            if left > cursor:
                segments.append({"start": cursor, "end": left, "size": left - cursor,
                                 "class": "unknown", "owner": None, "evidence": "catalogue gap"})
            cls = STATE_CLASS.get(row.get("ownership_state"), "unowned_code")
            segments.append({"start": left, "end": right, "size": right - left, "class": cls,
                             "owner": row.get("owner") or row["name"], "function": row["name"],
                             "evidence": row.get("reason"), "inventory_id": row.get("id")})
            cursor = max(cursor, right)
        if cursor < end:
            segments.append({"start": cursor, "end": end, "size": end - cursor,
                             "class": "unknown", "owner": None, "evidence": "catalogue gap"})
        totals = Counter()
        for segment in segments: totals[segment["class"]] += segment["size"]
        authoritative = sum(value for key, value in totals.items() if key in AUTHORITATIVE)
        unresolved = size - authoritative
        ledgers.append({"image": image_name, "section_vram": f"0x{start:X}", "size": size,
                        "classified_bytes": size, "authoritative_bytes": authoritative,
                        "unresolved_bytes": unresolved, "totals": dict(totals), "segments": segments})
        all_segments.extend((image_name, segment) for segment in segments)
    totals = Counter()
    for _image, segment in all_segments: totals[segment["class"]] += segment["size"]
    section_bytes = sum(section["size"] for section in ledgers)
    authoritative_bytes = sum(section["authoritative_bytes"] for section in ledgers)
    return {"model": "byte-ownership-v1", "images": len({key[0] for key in sections}),
            "sections": len(ledgers), "section_bytes": section_bytes,
            "classified_bytes": sum(section["classified_bytes"] for section in ledgers),
            "authoritative_bytes": authoritative_bytes,
            "unresolved_bytes": section_bytes - authoritative_bytes,
            "totals": dict(totals), "problems": problems,
            "complete_partition": all(section["classified_bytes"] == section["size"] for section in ledgers),
            "authoritative_complete": not problems and authoritative_bytes == section_bytes,
            "ledgers": ledgers}


def progress(inventory: dict, ledger: dict) -> dict:
    summary = inventory.get("summary", {})
    verified_functions = sum(row.get("ownership_state") in {"manifest_exact_unit", "manifest_exact_member"}
                             for row in inventory.get("functions", []))
    claimed_functions = sum(row.get("ownership_state") == "manifest_nonexact"
                            for row in inventory.get("functions", []))
    return {"functions": {"catalogue": summary.get("functions"),
                          "declared": summary.get("declared_functions"),
                          "verified_c": verified_functions, "claimed_c": claimed_functions,
                          "denominator_delta": summary.get("denominator_delta")},
            "bytes": {"catalogue_sections": ledger["section_bytes"],
                      "verified_c": ledger["totals"].get("verified_c", 0),
                      "claimed_c": ledger["totals"].get("claimed_c", 0),
                      "assembly": ledger["totals"].get("assembly", 0),
                      "structural": sum(ledger["totals"].get(key, 0)
                                        for key in ("fragment", "padding", "data")),
                      "unresolved": ledger["unresolved_bytes"]},
            "invariants": {"one_class_per_byte": ledger["complete_partition"] and not ledger["problems"],
                           "all_bytes_authoritatively_owned": ledger["authoritative_complete"]}}
