"""Account for every function of a title after a source tree was offered to it.

The donor stage reports what it verified and what it refused.  A function it never saw a
candidate for is silent there, and "not imported" alone says nothing about why.  This module
gives every function of the title one cause:

``strict``                     verified from the tree, every address independently known
``awaiting-symbols``           byte-identical from the tree; some address only from the title
``other-donor``                verified from another donor (the SDK build, another title)
``refused``                    a tree function had the same bytes but verification refused it
                               (with the stage's reason: another function's shape, a conflict)
``near``                       a tree function differs in one or two words
``tree-function-differs``      the tree has the function at this place (its neighbours in the
                               same unit were found around it) and it compiles to other bytes
``tree-function-not-compiled`` ... and it does not compile on its own
``tree-function-assembly``     ... and its body is inline assembly, which is not imported as C
``no-tree-function``           nothing of the tree's C stands here: written in assembly in the
                               tree, data, or absent from the tree

"At this place" comes from source order: functions of one unit are laid out by the compiler in
the order the unit defines them, so a title function found between two functions of the same
unit is, when the counts agree, the tree function written between them.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

VERIFIED = {"exact-with-transferred-symbols": "strict", "identical-awaiting-symbols": "awaiting-symbols"}


def _unit_label(relative: str) -> tuple[str, str] | None:
    """``("src/a.c", "label")`` for a split source ``src/a/label.c``."""
    path = Path(relative)
    if path.suffix != ".c" or len(path.parts) < 2:
        return None
    return str(path.parent) + ".c", path.stem


def _donor_functions(folder: Path) -> dict[tuple[str, str], tuple[int, int]]:
    """``{(unit, label): (offset in the donor image, size)}`` from the donor's manifests."""
    out = {}
    for manifest in sorted(folder.glob("manifest.*.tsv")):
        for line in manifest.read_text().splitlines():
            columns = line.split("\t")
            if line.startswith("#") or len(columns) < 3:
                continue
            key = _unit_label(columns[2])
            if key:
                out[key] = (int(columns[0], 16), int(columns[1], 16))
    return out


def account(project: Path, run: Path, folder: Path, donor) -> dict:
    """Causes for every function of every image of ``project`` after ``run`` used the tree donor
    described in ``folder`` (named ``donor``)."""
    from . import images as imagemod
    images = []
    for image in sorted(imagemod.load_registry(project)):
        spec = imagemod.resolve(project, image)
        images.append((image, spec.load(), spec.delta, spec.rows()))
    return account_images(images, run, folder, donor)


def account_images(images, run: Path, folder: Path, donor) -> dict:
    """``images``: ``[(name, bytes, vram - offset, [(function, vram, size)])]``.  ``donor`` is
    the tree's donor name, or a set of names when the tree was imported as several donors (one
    unit per function and whole units); rows carry ``via`` naming the one that verified."""
    donors = {donor} if isinstance(donor, str) else set(donor)
    from .transplant import mask, strip_padding
    folder = Path(folder)
    order_file = folder / "split" / "order.json"
    split_info = json.loads(order_file.read_text()) if order_file.is_file() else {"order": {}, "excluded": {}}
    order: dict[str, list[str]] = split_info.get("order", {})
    excluded: dict[str, dict[str, str]] = split_info.get("excluded", {})
    compiled = _donor_functions(folder)
    donor_image = (folder / "image.bin").read_bytes() if (folder / "image.bin").is_file() else b""
    rows, counts = [], Counter()
    for image, data, delta, image_rows in images:
        functions = sorted(image_rows, key=lambda row: row[1])
        report_path = Path(run) / image / "donors" / "report.json"
        report = json.loads(report_path.read_text()) if report_path.is_file() else {}
        cause: dict[int, dict] = {}
        placed: dict[tuple[str, str], int] = {}               # tree function -> title address
        by_name = {name: vram for name, vram, _size in functions}

        def note(vram, **fields):
            if vram is not None and vram not in cause:
                cause[vram] = fields

        for row in report.get("rows", []):
            vrams = [by_name[name] for name in row.get("functions", []) if name in by_name]
            from_tree = row.get("donor") in donors
            key = _unit_label(str(row.get("donor_unit", ""))) if from_tree else None
            if key and vrams and row.get("verdict") in VERIFIED:
                placed[key] = vrams[0]
            for vram in vrams:
                if row.get("verdict") in VERIFIED:
                    note(vram, cause=VERIFIED[row["verdict"]] if from_tree else "other-donor",
                         donor=row.get("donor"), unit=row.get("donor_unit"),
                         **({"via": row.get("donor")} if from_tree else {}))
        for row in report.get("rows", []):
            if row.get("donor") not in donors or row.get("verdict") in VERIFIED:
                continue
            for name in row.get("functions", []):
                why = (row.get("notes") or [None])[0] or row.get("cause") or row.get("verdict")
                note(by_name.get(name), cause="refused", unit=row.get("donor_unit"), detail=str(why)[:160])
                key = _unit_label(str(row.get("donor_unit", "")))
                if key and name in by_name:
                    placed.setdefault(key, by_name[name])
        for hit in report.get("needs_review", []):
            if hit.get("donor") in donors and hit.get("target") in by_name:
                note(by_name[hit["target"]], cause="refused", unit=hit.get("donor_unit"),
                     detail="the addresses its symbols would take contradict other functions")
                key = _unit_label(str(hit.get("donor_unit", "")))
                if key:
                    placed.setdefault(key, by_name[hit["target"]])
        for hit in report.get("near_hits", []):
            if hit.get("donor") in donors and hit.get("target") in by_name:
                note(by_name[hit["target"]], cause="near", unit=hit.get("donor_unit"),
                     detail="; ".join(hit.get("notes") or [])[:160])
                key = _unit_label(str(hit.get("donor_unit", "")))
                if key:
                    placed.setdefault(key, by_name[hit["target"]])

        # the rest, placed by source order between two found functions of the same unit
        order_index = {vram: index for index, (_n, vram, _s) in enumerate(functions)}
        for unit, labels in order.items():
            known = [(position, placed[(unit, label)]) for position, label in enumerate(labels) if (unit, label) in placed]
            for (first, low), (last, high) in zip(known, known[1:]):
                if last - first < 2 or high <= low:
                    continue
                between_tree = labels[first + 1:last]
                between_title = [functions[k] for k in range(order_index[low] + 1, order_index[high])]
                if len(between_tree) != len(between_title):
                    continue
                for label, (_name, vram, size) in zip(between_tree, between_title):
                    if vram in cause:
                        continue
                    if label in excluded.get(unit, {}):
                        note(vram, cause="tree-function-assembly", unit=unit, tree_function=label,
                             detail=excluded[unit][label])
                    elif (unit, label) not in compiled:
                        note(vram, cause="tree-function-not-compiled", unit=unit, tree_function=label)
                    else:
                        offset, length = compiled[(unit, label)]
                        theirs = strip_padding(donor_image[offset:offset + length])
                        ours = strip_padding(data[vram - delta:vram - delta + size])
                        if len(theirs) == len(ours):
                            a, _ = mask(theirs, 0x80000000 + offset)
                            b, _ = mask(ours, vram)
                            differ = sum(1 for x, y in zip(a, b) if x != y)
                            detail = f"same length, {differ} of {len(a)} words differ"
                        else:
                            detail = f"{len(theirs)} bytes in the tree, {len(ours)} in the title"
                        note(vram, cause="tree-function-differs", unit=unit, tree_function=label, detail=detail)
        for name, vram, size in functions:
            found = cause.get(vram) or {"cause": "no-tree-function"}
            counts[found["cause"]] += 1
            rows.append({"image": image, "function": name, "vram": f"0x{vram:08X}", "size": size, **found})
    total = sum(counts.values())
    return {"functions": total, "causes": dict(counts.most_common()),
            "shares": {key: round(value / total, 4) for key, value in counts.most_common()} if total else {},
            "rows": rows}
