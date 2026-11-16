"""A library of finished runs: what was matched in one title is offered to every later one.

Titles share code that no SDK signature names: a studio's engine, a middleware library, the same
library built with the same compiler.  A function matched once (by the search, or by a refiner
that costs something every time it is asked) should never have to be matched again.  The donor
stage already transplants matched units between projects and verifies each transplant by
rebuilding it for the target; this module makes a finished ``decompile-run`` a donor:

* ``write_donor`` describes a run's strictly exact functions as donor entries (one per image):
  the sources and per-pipeline manifests under ``<out>/queue``, the image, its catalogue and its
  symbol files.  It adds nothing to the run's claims and moves no file.
* ``register`` copies that description into a library directory under the ROM's digest, and
  ``donors`` loads every other title's description from it.

Nothing transplanted is trusted: the receiving run compiles each donor unit for its own image and
compares bytes and relocations, exactly as for a hand-written donor project.
"""
from __future__ import annotations

import hashlib
import json
import re
import os
import shutil
from pathlib import Path

DONOR_FILE = "donor.toml"


def rom_key(data: bytes) -> str:
    """Stable identity of one image: titles are told apart by content, never by file name."""
    return hashlib.sha1(data).hexdigest()[:16]


def _absolute(path) -> str:
    """Absolute without following links: a project's ROM is usually a link, and the link is the
    project's own name for it."""
    return os.path.abspath(os.fspath(path))


def _quote(value) -> str:
    return json.dumps(str(value))


def write_donor(out: Path, project: Path, specs: list, key: str, symbol_files: list[Path]) -> dict:
    """Write ``<out>/donor.toml`` and the per-pipeline manifests it names from ``<out>/queue``.

    ``specs`` are the run's image specs (``n64dk.match.images.ImageSpec``); ``symbol_files`` the
    project's symbol files.  Only strictly exact rows are offered."""
    out, queue = Path(out), Path(out) / "queue"
    table = queue / "queue.tsv"
    if not table.is_file():
        return {"donors": 0, "units": 0, "reason": "the run exported no strictly exact function"}
    groups: dict[tuple[str, str], list[str]] = {}
    current = None
    for line in table.read_text().splitlines():
        header = re.match(r"# image (\S+); pipeline (\S+);", line)
        if header:
            current = (header.group(1), header.group(2))
        elif current and line.strip() and not line.startswith("#"):
            groups.setdefault(current, []).append(line)
    by_name = {spec.name: spec for spec in specs}
    lines, donors, units = ["# Written by `n64dk decompile-run`: this run's strictly exact functions, as donors for other titles.",
                            "# Every transplant is rebuilt and verified by the run that receives it.", ""], 0, 0
    for image in sorted({image for image, _pipeline in groups}):
        spec = by_name.get(image)
        if spec is None:
            continue
        manifests = []
        for (group_image, pipeline), rows in sorted(groups.items()):
            if group_image != image:
                continue
            name = f"{image}.{re.sub(r'[^A-Za-z0-9.]+', '_', pipeline)}.tsv"
            (queue / name).write_text(f"# image {image}; pipeline {pipeline}; ROM_START SIZE SOURCE FLAGS\n"
                                      + "\n".join(rows) + "\n")
            manifests.append((name, pipeline))
            units += len(rows)
        symbols = [Path(p) for p in symbol_files if Path(p).is_file()]
        declared = out / image / "declared_symbols.txt"
        if declared.is_file():
            symbols.append(declared)
        lines += [f"[donor.t{key}_{re.sub(r'[^A-Za-z0-9]+', '_', image)}]", f"root = {_quote(queue)}",
                  f"image = {_quote(_absolute(spec.path))}"]
        if spec.delta_source == "declared" and spec.vram_delta is not None:
            lines.append(f"vram_delta = 0x{spec.vram_delta:08X}")
        lines += ["symbols = [" + ", ".join(_quote(_absolute(p)) for p in symbols) + "]",
                  "catalogue = [" + (_quote(_absolute(spec.catalogue)) if spec.catalogue else "") + "]",
                  "manifests = [", *[f"  {{ path = {_quote(name)}, pipeline = {_quote(pipeline)} }},"
                                     for name, pipeline in manifests], "]", ""]
        donors += 1
    if not donors:
        return {"donors": 0, "units": 0, "reason": "no exported row belongs to a configured image"}
    (out / DONOR_FILE).write_text("\n".join(lines))
    return {"donors": donors, "units": units, "file": str(out / DONOR_FILE)}


def register(library: Path, out: Path, key: str) -> str | None:
    """Copy a run's donor description into the library under its ROM key."""
    source = Path(out) / DONOR_FILE
    if not source.is_file():
        return None
    library = Path(library)
    library.mkdir(parents=True, exist_ok=True)
    target = library / f"{key}.toml"
    shutil.copyfile(source, target)
    return str(target)


def files(library: Path | None, exclude_key: str | None = None) -> list[Path]:
    """Donor descriptions of every other title in the library (a title is never its own donor)."""
    if not library or not Path(library).is_dir():
        return []
    return [path for path in sorted(Path(library).glob("*.toml")) if path.stem != exclude_key]


def donors(library: Path | None, exclude_key: str | None = None) -> list:
    """Donor specs of every other title in the library whose image still exists."""
    from . import transplant
    out = []
    for path in files(library, exclude_key):
        try:
            found = transplant.load_donors(path)
        except Exception:                                    # a damaged entry is skipped, not fatal
            continue
        out += [spec for spec in found if Path(spec.image).is_file()]
    return out


def identity(library: Path | None, exclude_key: str | None = None) -> list:
    """What a checkpointed donor stage depends on: the entries and when each last changed."""
    return [(path.name, path.stat().st_size, path.stat().st_mtime_ns) for path in files(library, exclude_key)]
