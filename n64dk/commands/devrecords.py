"""``dev-records-scan`` / ``dev-records-decode``: development records left in a ROM.

Scan reports every candidate (accepted, or rejected with its reason); facts keep their image,
record offset, record digest and kind, and are marked direct (read from a record) or inferred.
Nothing here edits a catalogue: the facts go to an evidence file beside the project's other
outputs, and catalogue conflicts are listed, never resolved silently."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ..cli import command


def _scan_bytes(data: bytes, image: str) -> dict:
    from ..analysis import devrecords
    objects = devrecords.scan_objects(data)
    facts = [fact for decoded in objects["accepted"] for fact in devrecords.facts(decoded, image=image)]
    headerless = devrecords.scan_functions(data)
    for fact in headerless["accepted"]:
        fact["image"] = image
    names = devrecords.source_names(data)
    return {"image": image, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
            "objects": {"accepted": len(objects["accepted"]), "rejected": objects["rejected"][:200],
                        "rejected_total": len(objects["rejected"])},
            "object_facts": facts, "headerless_functions": headerless["accepted"],
            "headerless_examined": headerless["examined"], "source_names": names}


@command("dev-records-scan", "Scan a ROM or a project's logical images for SN/PsyQ object records, headerless function "
                             "debug records and source-file names; write raw records and normalised facts")
def dev_records_scan(args):
    from ..analysis import devrecords
    reports = []
    if args.rom:
        data = Path(args.rom).read_bytes()
        reports.append(_scan_bytes(data, "rom"))
    else:
        from ..match.images import load_registry
        registry = load_registry(Path(args.project))
        for name, spec in registry.items():
            if args.image and name not in args.image:
                continue
            data = spec.load()
            report = _scan_bytes(data, name)
            rows = spec.rows()
            # unit-name evidence: functions that take the address of a source-name string
            report["unit_name_evidence"] = devrecords.attribute_functions(data, spec.delta, rows,
                                                                          report["source_names"], spec.delta)
            catalogue = {fname for fname, _v, _s in rows}
            report["conflicts"] = [
                {"fact": fact["name"], "record_offset": fact["record_offset"],
                 "conflict": "a record names a function the catalogue does not hold; records carry no linked "
                             "address, so the fact stays unplaced"}
                for fact in report["object_facts"] + report["headerless_functions"]
                if fact.get("fact") == "function" and fact["name"] not in catalogue]
            reports.append(report)
    out = Path(args.out)
    out.write_text(json.dumps({"schema": "n64dk.devrecords/1", "images": reports}, indent=1) + "\n")
    return {"out": str(out), "images": [{"image": r["image"], "objects": r["objects"]["accepted"],
                                         "objects_rejected": r["objects"]["rejected_total"],
                                         "headerless_functions": len(r["headerless_functions"]),
                                         "source_names": len(r["source_names"]),
                                         "unit_name_evidence": len(r.get("unit_name_evidence", [])),
                                         "conflicts": len(r.get("conflicts", []))} for r in reports]}


def _scan_args(p):
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--project", help="a decompile-init project: scan its logical images")
    group.add_argument("--rom", help="a ROM file (scanned as one image)")
    p.add_argument("--image", action="append", help="only these images (repeatable)")
    p.add_argument("--out", required=True, help="evidence file to write (JSON)")


dev_records_scan.arguments = _scan_args


@command("dev-records-decode", "Decode one SN/PsyQ object at an explicit offset of a file (fails with the reason)")
def dev_records_decode(args):
    from ..analysis import devrecords
    data = Path(args.file).read_bytes()
    at = int(args.at, 0)
    try:
        decoded = devrecords.decode_object(data, at, int(args.length, 0) if args.length else 1 << 24)
    except devrecords.RecordError as error:
        return {"accepted": False, "offset": at, "reason": str(error)}
    return {"accepted": True, "offset": at, "end": decoded["end"], "records": decoded["records"],
            "facts": devrecords.facts(decoded, image=Path(args.file).name, base=0)}


def _decode_args(p):
    p.add_argument("--file", required=True)
    p.add_argument("--at", required=True, help="offset of the LNK header")
    p.add_argument("--length", help="bytes the object may span (default 16 MB)")


dev_records_decode.arguments = _decode_args
