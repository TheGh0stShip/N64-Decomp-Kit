"""``decompile-init``: a project for ``decompile-run`` from nothing but a ROM.

``decompile-run`` needs each image's function catalogue, a symbol list and a build recipe.  A
title nobody has worked on has none of these.  This command derives them from the ROM alone and
writes a self-contained project directory::

    <out>/
      baserom.z64            link to the ROM (the ROM itself is only read)
      n64dk.toml             [images.main], [run] with the starting recipe and a calibration size
      survey/                the survey's outputs: functions.toml, symbol_addrs.txt, report.json,
                             report.md, ledger.tsv, main_segment.bin, sdk_symbols.txt

* **Code and boundaries** come from the survey (boot segment or, for a packed program, the
  loader's output), not from any reference project.
* **Library names** are the SDK matcher's confident identifications (``sdk_symbols.txt``); they
  are labels, the addresses are the catalogue's.
* **The starting recipe** is the compiler family the SDK fingerprint attributes to the game code,
  at that family's usual retail settings.  It is only a starting point: ``[run] calibrate`` makes
  ``decompile-run`` measure the title's real recipe on a sample of its own functions first.

* **Code nothing points at.**  The rest of the ROM is scanned for the density of compiled code and
  placed by one vote over all of it (``segments.discover_regions``): a linked program keeps one
  distance between ROM offset and address, so overlays and later-loaded programs are found even
  when the loader that reads them was not recognised.

* **Further code segments.**  A ROM range that a loader reads raw, looks like code and whose own
  calls agree on one load address (``n64dk.analysis.segments``) becomes an image of its own
  (``survey/seg_<ROM offset>.bin`` with its catalogue).  Ranges that look like code but cannot be
  placed are listed, not guessed.

What the project covers is stated in ``survey/blind.json``: the images and their code ranges, how
many bytes the survey saw loaded from elsewhere, and the code-like ranges that were not placed.
Code inside a compressed stream the codec scan can decode (zlib, gzip, header-less deflate, MIO0,
Yay0, Yaz0) is unpacked to ``survey/seg_<ROM offset>.bin`` and placed the same way; a stream in
another format is not seen.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from ..cli import command

# usual retail settings per compiler family: where a title nobody has built starts from
STARTING_RECIPES = {
    "ido": ("ido5.3", "-O2 -mips2 -non_shared -G 0 -Xcpluscomm -Wab,-r4300_mul"),
    "kmc": ("kmc+asn64", "-O2 -G0 -mips3 -mgp32 -mfp32"),
    "sn": ("sn", "-O2 -G0 -mcpu=vr4300 -mhard-float -meb -mips3"),
}
DEFAULT_CALIBRATE = 96


def starting_recipe(sdk: dict | None) -> tuple[str, str, str]:
    """(pipeline, flags, why) for a survey's SDK summary."""
    family = (sdk or {}).get("game_compiler")
    share = ((sdk or {}).get("game_compiler_share") or {}).get(family)
    if family in STARTING_RECIPES:
        pipeline, flags = STARTING_RECIPES[family]
        return pipeline, flags, f"SDK fingerprint attributes {share:.0%} of the game code to {family}" \
            if isinstance(share, (int, float)) else f"SDK fingerprint: {family}"
    pipeline, flags = STARTING_RECIPES["ido"]
    return pipeline, flags, "no compiler fingerprint: the most common toolchain is assumed"


def build_project(rom_path: Path, out: Path, mode: str = "auto", calibrate: int = DEFAULT_CALIBRATE,
                  toolchain: str | None = None, lzari_brute: bool = True, compressed: bool = True,
                  regions: bool = True,
                  refine_command: str | None = None) -> dict:
    """Survey ``rom_path`` and write the project under ``out``.  Returns the summary that is also
    written to ``survey/blind.json``."""
    from .. import sdk as sdkmod
    from .. import survey as surveymod
    from ..analysis import functions
    from ..ledger import Ledger
    from ..rom import Rom

    rom_path, out = Path(rom_path).resolve(), Path(out).resolve()
    rom = Rom.load(rom_path)
    result = surveymod.run(rom, mode=mode, lzari_brute=lzari_brute)
    report, catalogue, program = result["report"], result["catalogue"], result["program"]
    if catalogue is None:
        raise SystemExit("the survey found no function catalogue: "
                         + str((report.get("errors") or {}).get("functions", "no code segment"))[:300])
    survey_dir = out / "survey"
    survey_dir.mkdir(parents=True, exist_ok=True)
    Ledger.write_tsv(result["ledger"], survey_dir / "ledger.tsv")
    if (report.get("dev_records") or {}).get("runs") or (report.get("dev_records") or {}).get("objects"):
        from ..analysis import devrecords as devrecmod
        (survey_dir / "devrecords.json").write_text(json.dumps(devrecmod.scan_rom(rom.data, with_facts=True)["facts"],
                                                               indent=1) + "\n")
    (survey_dir / "report.json").write_text(json.dumps(report, indent=1, default=str) + "\n")
    (survey_dir / "report.md").write_text(surveymod.render_markdown(report))
    main = program.main()
    # a debug build's frameless functions end in returns nothing reaches: they are not functions
    tails = functions.merge_dead_returns(catalogue, main.data, main.vram) if main.data else {"merged": 0}
    # the original build's debug records, placed in the image: names, prototypes and types
    context_headers = []
    if (survey_dir / "devrecords.json").is_file() and main.data:
        from ..analysis import devrecords as devrecmod
        placement, declarations = devrecmod.apply_to_catalogue(
            json.loads((survey_dir / "devrecords.json").read_text()), main.data, main.vram, catalogue.functions)
        (survey_dir / "devrecords_placed.json").write_text(json.dumps(placement, indent=1) + "\n")
        if declarations:
            (survey_dir / "devrecords_context.h").write_text(declarations)
            context_headers.append("survey/devrecords_context.h")
    (survey_dir / "functions.toml").write_text(functions.to_toml(catalogue, report["rom"].get("title", "")))
    (survey_dir / "symbol_addrs.txt").write_text(functions.to_symbol_addrs(catalogue))
    main = program.main()
    if main.data:
        (survey_dir / "main_segment.bin").write_bytes(main.data)

    # library names: confident SDK identifications at catalogued starts only
    starts = {f.start for f in catalogue.functions}
    named = []
    try:
        matches = sdkmod.analyse(rom, program=program).matches
    except Exception:                                        # names are a convenience, never a requirement
        matches = []
    seen = set()
    for match in sorted(matches, key=lambda m: (-m.confidence, m.vram)):
        if match.confidence >= 0.8 and match.vram in starts and match.name not in seen \
                and match.name.isidentifier():
            seen.add(match.name)
            named.append((match.vram, match.name))
    (survey_dir / "sdk_symbols.txt").write_text(
        "".join(f"{name} = 0x{vram:08X}; // type:func\n" for vram, name in sorted(named)))

    # code a loader reads raw from elsewhere in the ROM: each range whose calls agree on one load
    # address becomes an image of its own, with its own catalogue
    from ..analysis import segments as segmod
    from ..image import ProgramImage, Segment
    extra, undecided = [], []
    known = [(seg.vram, seg.end) for seg in program.segments if seg.kind != "bss"]
    candidates = segmod.discover(rom.data, result["ledger"], known)
    if compressed:
        placed = known + [(c.vram, c.vram + c.size) for c in candidates if c.vram is not None]
        boot_rom = [(item.start, item.end) for item in result["ledger"]
                    if getattr(item, "category", "") == "program"]
        candidates += segmod.discover_compressed(rom.data, placed, boot_rom)
    if regions:
        # code no loader range or stream points at: found by density, placed by one vote over the ROM
        placed = known + [(c.vram, c.vram + c.size) for c in candidates if c.vram is not None]
        taken = [(item.start, item.end) for item in result["ledger"] if getattr(item, "category", "") == "program"]
        taken += [(c.rom_start, c.rom_end) for c in candidates if c.vram is not None or c.codec]
        found_regions = segmod.discover_regions(rom.data, placed, taken)
        solved = [(c.rom_start, c.rom_end) for c in found_regions if c.vram is not None]
        seen = [(c.rom_start, c.rom_end) for c in found_regions]      # a range is reported once
        candidates = [c for c in candidates if c.vram is not None
                      or not any(c.rom_start < hi and lo < c.rom_end for lo, hi in solved + seen)] + found_regions
    for candidate in candidates:
        if candidate.vram is None:
            if candidate.text_bytes:                         # looks like code, could not be placed
                undecided.append(candidate.as_dict())
            continue
        data = candidate.data if candidate.data is not None else rom.data[candidate.rom_start:candidate.rom_end]
        name = f"seg_{candidate.rom_start:X}"
        try:
            image = ProgramImage(method="emulated", entry=candidate.vram, hand_over=candidate.vram, stack_top=None,
                                 segments=[Segment(vram=candidate.vram, size=len(data), kind="packed", data=data,
                                                   evidence=f"{candidate.codec or 'raw'} loader range")], boot=None)
            seeds = [candidate.vram + offset for offset in segmod.profile(data)["prologues"]] \
                if candidate.by_density else ()
            found = functions.discover(rom, program=image, seeds=seeds)
            functions.merge_dead_returns(found, data, candidate.vram)
        except Exception as error:
            undecided.append({**candidate.as_dict(), "reason": f"function discovery failed: {str(error)[-120:]}"})
            continue
        (survey_dir / f"{name}.bin").write_bytes(data)
        (survey_dir / f"functions_{name}.toml").write_text(functions.to_toml(found, name))
        (survey_dir / f"symbol_addrs_{name}.txt").write_text(functions.to_symbol_addrs(found))
        info = functions.summary(found)
        extra.append({"name": name, **candidate.as_dict(), "functions": info.get("functions"),
                      "text_bytes": info.get("text_size"), "function_kinds": info.get("kinds")})

    if (getattr(program, "loader", None) or {}).get("stub"):
        # The boot image turned out to be a stub that unpacks the program.  The stub is code of
        # the title too: it becomes an image of its own, so that no function is left out.
        try:
            from .. import image as imagemod
            static = imagemod.static_image(rom, program.boot)
            stub = static.main()
            found = functions.discover(rom, program=static)
            data = stub.data[:max(function.end for function in found.functions) - stub.vram]
            functions.merge_dead_returns(found, data, stub.vram)
            name = f"seg_{stub.rom:X}"
            (survey_dir / f"{name}.bin").write_bytes(data)
            (survey_dir / f"functions_{name}.toml").write_text(functions.to_toml(found, name))
            (survey_dir / f"symbol_addrs_{name}.txt").write_text(functions.to_symbol_addrs(found))
            info = functions.summary(found)
            extra.append({"name": name, "rom": f"0x{stub.rom:X}", "rom_end": f"0x{stub.rom + len(data):X}",
                          "size": len(data), "vram": f"0x{stub.vram:08X}", "functions": info.get("functions"),
                          "text_bytes": info.get("text_size"), "function_kinds": info.get("kinds"),
                          "evidence": ["the boot stub that unpacks the program"]})
        except Exception as error:                           # noqa: BLE001 - the program itself is surveyed
            undecided.append({"rom": "0x1000", "reason": f"boot stub not catalogued: {str(error)[-120:]}"})

    link = out / "baserom.z64"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(rom_path)

    packed = main.kind == "packed" or report["program"].get("method") != "static"
    pipeline, flags, why = starting_recipe(report.get("sdk"))
    image = ['[images.main]']
    if packed:
        image += ['path = "survey/main_segment.bin"       # the loader\'s output, not the ROM',
                  f'vram_delta = 0x{main.vram:08X}']
    else:
        image += ['path = "baserom.z64"']
    image += ['catalogue = "survey/functions.toml"', 'manifests = []']
    symbol_files = ["survey/symbol_addrs.txt", "survey/sdk_symbols.txt"]
    for segment in extra:
        image += ["", f"[images.{segment['name']}]            # ROM {segment['rom']}..{segment['rom_end']}, "
                      f"{segment.get('codec') or 'raw'}, placed by its own calls", f'path = "survey/{segment["name"]}.bin"',
                  f"vram_delta = {segment['vram']}", f'catalogue = "survey/functions_{segment["name"]}.toml"',
                  "manifests = []"]
        symbol_files.append(f"survey/symbol_addrs_{segment['name']}.txt")
    lines = ["# Written by `n64dk decompile-init` from the ROM alone.  Everything here is a starting point.", ""]
    lanes = {}
    if toolchain:
        lines += ["[toolchains]", f'root = "{toolchain}"', ""]
        # a lane for every installed compiler the kit has no built-in pipeline for: calibration and
        # the per-function alternatives then cover every compiler on this machine
        from ..match import compilers as compilermod
        lanes = compilermod.project_pipelines(Path(toolchain))
    lines += [*image, "", "[run]", f'pipeline = "{pipeline}"            # {why}', f'flags = "{flags}"',
              "symbols = [" + ", ".join(f'"{name}"' for name in symbol_files) + "]",
              *(["context_headers = [" + ", ".join(f'"{name}"' for name in context_headers)
                 + "]   # recorded declarations, ahead of recovered ones"] if context_headers else []),
              f"calibrate = {calibrate}                 # functions sampled to measure the title's real recipe",
              "declare_assumed = true         # declare D_<address> data the identical cases lean on, verify again", ""]
    if lanes:
        from ..match import compilers as compilermod
        lines += ["# Compilers without a built-in pipeline, as configured lanes (`n64dk compilers` lists them).",
                  compilermod.toml_tables(lanes)]
    if refine_command:
        lines += ["[run.refine]                   # asked about every case the mechanical pass leaves; answers are",
                  "                               # untrusted C, built and strictly verified like any other source",
                  "command = " + json.dumps(refine_command), ""]
    (out / "n64dk.toml").write_text("\n".join(lines))

    functions_info = report.get("functions") or {}
    assets = (report.get("assets") or {}).get("ledger_bytes") or {}
    summary = {
        "rom": str(rom_path), "title": report["rom"].get("title"), "sha1": report["rom"].get("sha1"),
        "rom_bytes": report["rom"].get("size"), "program": report["program"].get("method"),
        "image": {"vram": f"0x{main.vram:08X}", "bytes": len(main.data) if main.data else None,
                  "packed": bool(packed)},
        "text": functions_info.get("text"), "text_bytes": functions_info.get("text_size"),
        "functions": len(catalogue.functions), "function_kinds": functions_info.get("kinds"),
        "dead_returns_merged": tails,
        "sdk_named": len(named), "sdk_version": (report.get("sdk") or {}).get("sdk_version"),
        "compiler_fingerprint": (report.get("sdk") or {}).get("game_compiler_share"),
        "starting_recipe": {"pipeline": pipeline, "flags": flags, "why": why},
        "compiler_lanes": sorted(lanes),
        "loaded_from_elsewhere_bytes": assets.get("loader_range"),
        "segments": extra, "code_not_placed": undecided,
        "functions_all_images": len(catalogue.functions) + sum(seg["functions"] or 0 for seg in extra),
        "survey_errors": sorted((report.get("errors") or {}).keys()),
        "project": str(out),
    }
    layout = rom_layout(report, extra, undecided, result["ledger"])
    layout["extracted"] = extract_layout(layout, rom.data, main.data, survey_dir / "extract")
    (survey_dir / "layout.json").write_text(json.dumps(layout, indent=1, default=str) + "\n")
    summary["layout"] = "survey/layout.json"
    (survey_dir / "blind.json").write_text(json.dumps(summary, indent=1) + "\n")
    return summary


def rom_layout(report: dict, extra: list[dict], undecided: list[dict], ledger) -> dict:
    """One map of the whole ROM from what the survey established: header, boot code, the main
    program's sections and uninitialised memory, RSP code and data inside it, further code
    segments, and every other classified range by category.  Ranges nothing explains stay
    ``unknown``; nothing is guessed to make the map look complete."""
    import re
    program = report.get("program") or {}
    main = program.get("main") or {}
    datamap = report.get("datamap") or {}
    rom_base = int(str(main.get("rom") or "0x1000"), 0) if main.get("rom") else None
    vram = int(main["vram"], 0) if main.get("vram") else None
    rows = [{"rom": "0x0", "rom_end": "0x40", "kind": "header", "name": "header"},
            {"rom": "0x40", "rom_end": "0x1000", "kind": "boot", "name": "ipl3",
             "note": f"CIC {(report.get('rom') or {}).get('cic')}"}]
    sections = []
    for text in datamap.get("sections") or []:
        found = re.match(r"(\.\w+) 0x([0-9A-Fa-f]+)\.\.0x([0-9A-Fa-f]+)", text)
        if not found:
            continue
        lo, hi = int(found.group(2), 16), int(found.group(3), 16)
        row = {"section": found.group(1), "vram": f"0x{lo:08X}", "vram_end": f"0x{hi:08X}", "size": hi - lo}
        if rom_base is not None and vram is not None and main.get("kind") == "rom":
            row.update(rom=f"0x{lo - vram + rom_base:X}", rom_end=f"0x{hi - vram + rom_base:X}")
        sections.append(row)
    if datamap.get("bss"):
        lo, _, hi = datamap["bss"].partition("..")
        sections.append({"section": ".bss", "vram": lo, "vram_end": hi, "size": int(hi, 0) - int(lo, 0),
                         "note": "no ROM bytes: cleared at start-up"})
    rsp = [{"vram": item.partition("..")[0], "vram_end": item.partition("..")[2], "kind": "rsp",
            "note": "RSP microcode or its data inside the program image: not R4300 code"}
           for item in report.get("rsp_in_text") or []]
    totals: dict[str, int] = {}
    for item in ledger:
        key = (getattr(item, "category", "") or "-") + "/" + (getattr(item, "kind", "") or getattr(item, "cls", "") or "-")
        totals[key] = totals.get(key, 0) + (item.end - item.start)
    return {"rom_bytes": (report.get("rom") or {}).get("size"), "entry": program.get("entry"),
            "fixed": rows, "main": {"method": program.get("method"), **{k: main.get(k) for k in ("vram", "end", "rom", "rom_end", "kind")},
                                    "sections": sections, "rsp": rsp},
            "microcode": (report.get("sdk") or {}).get("microcode") or [],
            "sdk_version": (report.get("sdk") or {}).get("sdk_version"),
            "audio": (report.get("audio") or {}).get("counts"), "graphics": {k: (report.get("gfx") or {}).get(k)
                                                                           for k in ("family", "display_lists")},
            "code_segments": [{k: seg.get(k) for k in ("name", "rom", "rom_end", "vram", "codec", "functions")} for seg in extra],
            "code_not_placed": [{k: seg.get(k) for k in ("rom", "rom_end", "reason")} for seg in undecided],
            "classified_bytes": dict(sorted(totals.items())), "unknown_bytes": report.get("unknown_bytes"),
            "largest_unknown": (report.get("next_steps") or [])[:8]}


def extract_layout(layout: dict, rom_data: bytes, main_data: bytes | None, out: Path) -> list[str]:
    """Write each piece of ``layout`` that has bytes as its own file under ``out``."""
    out.mkdir(parents=True, exist_ok=True)
    written = []

    def put(name: str, data: bytes) -> None:
        if data:
            (out / name).write_bytes(data)
            written.append(name)

    for row in layout["fixed"]:
        put(f"{row['name']}.bin", rom_data[int(row["rom"], 0):int(row["rom_end"], 0)])
    main = layout["main"]
    base = int(main["vram"], 0) if main.get("vram") else None
    for row in main["sections"] + main["rsp"]:
        if base is None or not main_data or row.get("section") == ".bss":
            continue
        lo, hi = int(row["vram"], 0) - base, int(row["vram_end"], 0) - base
        label = row.get("section", "").lstrip(".") or f"rsp_{row['vram'][2:]}"
        put(f"main.{label}.bin", main_data[max(0, lo):max(0, hi)])
    return written


@command("decompile-init", "Build a decompile-run project from a ROM alone: survey, catalogue, symbols, starting recipe")
def decompile_init(args):
    out = Path(args.out).resolve()
    if (out / "n64dk.toml").exists() and not args.force:
        raise SystemExit(f"{out / 'n64dk.toml'} exists; pass --force to rebuild the project")
    summary = build_project(Path(args.rom), out, args.image, args.calibrate,
                            args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN"), not args.no_lzari_brute, not args.no_compressed, not args.no_region_scan,
                            args.refine_command)
    summary["next"] = (f"n64dk decompile-run --project {out} --all-images --out {out / 'run'} "
                       "--allow-project-output [--donors donors.toml]")
    return summary


def _args(p):
    p.add_argument("rom", help="ROM image (z64, v64 or n64 byte order); it is read, never written")
    p.add_argument("--out", required=True, help="project directory to create")
    p.add_argument("--image", choices=("auto", "static", "emulated"), default="auto",
                   help="program image: emulate the boot only when a loader runs (auto), never, or always")
    p.add_argument("--calibrate", type=int, default=DEFAULT_CALIBRATE,
                   help="functions decompile-run samples to measure the title's recipe (0: none)")
    p.add_argument("--toolchain-dir", help="toolchain root to record in the project (default: N64DK_TOOLCHAIN)")
    p.add_argument("--no-lzari-brute", action="store_true", help="probe LZARI only at loader-evidenced starts")
    p.add_argument("--refine-command",
                   help="record a refiner in the project ([run.refine] command): decompile-run then asks it about "
                        "every case the mechanical pass leaves.  It receives disassembly and candidate sources")
    p.add_argument("--no-compressed", action="store_true",
                   help="do not look for code inside compressed streams (zlib, gzip, deflate, MIO0, Yay0, Yaz0)")
    p.add_argument("--no-region-scan", action="store_true",
                   help="do not scan the whole ROM for code that no loader range points at")
    p.add_argument("--force", action="store_true", help="rebuild an existing project")


decompile_init.arguments = _args
