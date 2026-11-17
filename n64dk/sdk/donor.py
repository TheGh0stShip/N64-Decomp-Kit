"""The SDK as a donor: every title links libultra, and its source is known.

The SDK matcher names many library functions in a ROM, but a name is not a match: matching needs
source that the right compiler turns into the same bytes.  A reconstruction of the library's source
exists (the public ``ultralib`` tree: one source tree, version switches ``D`` to ``L``, the GCC and
the IDO build).  This module compiles one (version, flavour) of it with the kit's own compilers and
describes the result as a *donor project* for the transplant stage (``n64dk.match.transplant``):

* every unit that compiles is linked into one image at a fixed address (undefined externals are
  left at zero: the transplant masks every relocated field anyway);
* the image, a function catalogue, a symbol file and one manifest (unit offset, size, source and
  the exact flags of that unit) are written to an output directory, with a ``[donor.<name>]``
  entry ready for ``decompile-run --donors``.

Nothing here is trusted by the receiving run: a library function counts only when the transplant
stage rebuilds the unit for the target and bytes and relocations agree.

The flags are the library's own (read from the source tree's makefiles): per-directory and per-file
optimisation levels, ISA overrides, the GBI and version defines, ``-D_FINALROM`` for the ``_rom``
flavour.  A unit that does not compile is reported and left out.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ..match import sourcedonor

VERSIONS = tuple("DEFGHIJKL")
FLAVOURS = ("libgultra_rom", "libgultra", "libgultra_d", "libultra_rom", "libultra", "libultra_d")
BASE = sourcedonor.BASE
_OLD = set("DEFGHI")
_IDO_O3_DIRS = ("libc", "sched", "gu", "mgu", "sp", "audio", "rg", "gt")
_IDO_O1_DIRS = ("debug", "host", "os", "rmon", "log")
_NO_GBI = {"gu/us2dex_emu.c", "gu/us2dex2_emu.c", "sp/spriteex.c", "sp/spriteex2.c"}
_F3D_GBI = {"gu/parse_gbi.c", "sp/sprite.c"}
# What the boot code leaves in low memory for the library: fixed addresses on every console, which a
# game's link script states and a library on its own does not.
BOOT_GLOBALS = {"osTvType": 0x80000300, "osRomType": 0x80000304, "osRomBase": 0x80000308,
                "osResetType": 0x8000030C, "osCicId": 0x80000310, "osVersion": 0x80000314,
                "osMemSize": 0x80000318, "osAppNMIBuffer": 0x8000031C}
_SKIP_DIRS = ("voice",)                                     # needs a text-encoding step of its own
_MATRIX = ("mtxcatf", "normalize", "scale", "translate")    # C up to 2.0J, assembly from 2.0K
_ASM_DEFINES = ["-DMIPSEB", "-D_LANGUAGE_ASSEMBLY", "-D_MIPS_SIM=1", "-D_ULTRA64"]


def unit_recipe(version: str, flavour: str, relative: str) -> tuple[str, list[str]]:
    """(pipeline, flags) the library's makefiles give ``src/<relative>`` in this build."""
    gcc, rom, debug = flavour.startswith("libgultra"), flavour.endswith("_rom"), flavour.endswith("_d")
    folder, name = relative.split("/")[0], relative
    defines = ["-D_MIPS_SZLONG=32"]
    if name in _F3D_GBI:
        defines.append("-DF3D_GBI")
    elif name not in _NO_GBI:
        defines.append("-DF3DEX_GBI")
    defines += [f"-DBUILD_VERSION=VERSION_{version}", f'-DBUILD_VERSION_STRING="2.0{version}"']
    if debug:
        defines.append("-D_DEBUG")
    elif not (gcc and version == "I" and rom):              # 2.0I libgultra_rom was built without NDEBUG
        defines.append("-DNDEBUG")
    if rom:
        defines.append("-D_FINALROM")
    if gcc:
        opt = "-O0" if debug else "-O3"
        if name == "os/initialize_isv.c":
            opt = "-O2"
        elif name == "os/assert.c" or (name == "os/seterrorhandler.c" and version not in _OLD):
            opt = "-O0"
        flags = [opt, "-w", "-nostdinc", "-G", "0", "-mips3", "-mgp32", "-mfp32", "-D_LANGUAGE_C", "-D__USE_ISOC99"]
        if version in _OLD or version == "J":
            flags.append("-funsigned-char")
        return "kmc+as", flags + defines
    if debug:
        opt = ["-O1", "-g2"]
    elif version in _OLD:
        opt = ["-O3"] if folder in _IDO_O3_DIRS else ["-O1"]
    else:
        opt = ["-O1"] if folder in _IDO_O1_DIRS else ["-O2"]
    isa = ["-mips2"]
    if name in ("libc/ll.c", "libc/llbit.c", "libc/llcvt.c"):
        opt, isa = (["-O1"] if not debug else opt), ["-mips3", "-32"]
    if name == "os/initialize_isv.c":
        opt = ["-O2"]
    return "ido5.3", [*opt, *isa, "-non_shared", "-G", "0", "-nostdinc", "-Xcpluscomm", "-Wab,-r4300_mul",
                      "-woff", "516,649,838,712", *defines]


def assembly_recipe(version: str, flavour: str, relative: str) -> list[str]:
    """Flags the IDO build gives the hand-written unit ``src/<relative>`` (the GCC build's
    assembly is preprocessed here and handed to the assembler as it is)."""
    folder = relative.split("/")[0]
    opt = ["-O0", "-g2"] if flavour.endswith("_d") else (["-O2"] if folder in ("libc", "mgu") else ["-O1"])
    isa = ["-mips3", "-32"] if relative == "os/exceptasm.s" else ["-mips2"]
    defines = ["-D_MIPS_SZLONG=32", f"-DBUILD_VERSION=VERSION_{version}"]
    defines.append("-D_DEBUG" if flavour.endswith("_d") else "-DNDEBUG")
    if flavour.endswith("_rom"):
        defines.append("-D_FINALROM")
    return [*opt, *isa, "-non_shared", "-G", "0", "-nostdinc", "-Wab,-r4300_mul", "-woff", "516,649,838,712",
            *_ASM_DEFINES, *defines]


def units_of(source: Path, version: str, flavour: str) -> list[str]:
    """Source files (relative to ``src``) that belong to this build: the archive's member list
    when the tree states one, every C file otherwise."""
    found = sorted(str(path.relative_to(source / "src")) for pattern in ("*.c", "*.s")
                   for path in (source / "src").rglob(pattern)
                   if len(path.relative_to(source / "src").parts) > 1
                   and path.relative_to(source / "src").parts[0] not in _SKIP_DIRS)
    late = version in ("K", "L")
    found = [name for name in found
             if not (name in [f"gu/{m}.c" for m in _MATRIX] and late)
             and not (name in [f"mgu/{m}.s" for m in _MATRIX] and not late)]
    listing = source / "base" / version / f"{flavour}.txt"
    if listing.is_file():
        members = {line.strip()[:-2] for line in listing.read_text().split() if line.strip().endswith(".o")}
        found = [name for name in found if Path(name).stem in members]
    return found


def sort_symbols(path: Path) -> bool:
    """Put an object's local symbols in front of its global ones.

    IDO's assembler writes them mixed, which ELF does not allow and a modern linker refuses.  The
    table is reordered (locals first, order otherwise kept), ``sh_info`` set to the number of
    locals and every relocation's symbol index renumbered.  Returns whether anything changed."""
    import struct
    data = bytearray(Path(path).read_bytes())
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 2:           # 32-bit big-endian only
        return False
    shoff, = struct.unpack_from(">I", data, 0x20)
    shentsize, shnum = struct.unpack_from(">HH", data, 0x2E)
    sections = [list(struct.unpack_from(">10I", data, shoff + n * shentsize)) for n in range(shnum)]
    changed = False
    for index, sec in enumerate(sections):
        if sec[1] != 2:                                       # SHT_SYMTAB
            continue
        offset, size, entsize = sec[4], sec[5], sec[9] or 16
        entries = [bytes(data[offset + n * entsize:offset + (n + 1) * entsize]) for n in range(size // entsize)]
        local = [n for n, e in enumerate(entries) if e[12] >> 4 == 0]
        other = [n for n, e in enumerate(entries) if e[12] >> 4 != 0]
        order = local + other
        if order == list(range(len(entries))) and sec[7] == len(local):
            continue
        renumber = {old: new for new, old in enumerate(order)}
        data[offset:offset + size] = b"".join(entries[n] for n in order)
        struct.pack_into(">I", data, shoff + index * shentsize + 28, len(local))
        for rel in sections:
            if rel[1] in (9, 4) and rel[6] == index:          # SHT_REL / SHT_RELA using this table
                step = rel[9] or (8 if rel[1] == 9 else 12)
                for at in range(rel[4], rel[4] + rel[5], step):
                    info, = struct.unpack_from(">I", data, at + 4)
                    struct.pack_into(">I", data, at + 4, (renumber.get(info >> 8, info >> 8) << 8) | (info & 0xFF))
        changed = True
    if changed:
        Path(path).write_bytes(bytes(data))
    return changed


_LEVELS = ("-O0", "-O1", "-O2", "-O3", "-g", "-g2", "-g3")


def build(source: Path, out: Path, version: str, flavour: str, cfg, jobs: int = 4,
          recipe: tuple[str, list[str]] | None = None) -> dict:
    """Compile and describe one (version, flavour).  Returns the donor entry and the counts.

    With ``recipe`` (``(pipeline, [level flags])``) every C unit is built by that compiler at that
    level instead of the library's own, and the hand-written units are left out: not a donor of
    anything retail, but the same sources under a known recipe, which is what the marks a recipe
    leaves are learned from (``n64dk recipe-prior --learn-build``)."""
    import os
    from ..match.pipeline import BuildError, build as compile_unit, split_flags
    source, out = Path(source).resolve(), Path(out).resolve()
    name = f"sdk_2_0{version}_{flavour}"
    if recipe:
        name += "__" + re.sub(r"[^A-Za-z0-9]+", "_", f"{recipe[0]} {' '.join(recipe[1])}").strip("_")
    folder = out / name
    objects = folder / "obj"
    objects.mkdir(parents=True, exist_ok=True)
    gcc = flavour.startswith("libgultra")
    includes = [source / "include", source / "include" / "compiler" / ("gcc" if gcc else "ido"), source / "include" / "PR"]
    rows, failed = [], []

    plain = folder / "asm"                                  # the GCC build's assembly, preprocessed

    def one(relative: str):
        target = objects / (relative.replace("/", "__")[:-2] + ("_s.o" if relative.endswith(".s") else ".o"))
        if relative.endswith(".s"):
            return assemble(relative, target)
        pipeline, flags = unit_recipe(version, flavour, relative)
        if recipe:
            pipeline, flags = recipe[0], [*recipe[1], *[flag for flag in flags if flag not in _LEVELS]]
        if target.is_file():
            return relative, pipeline, flags, target, None
        try:
            with tempfile.TemporaryDirectory(prefix="n64dk-sdk-") as work:
                built = compile_unit(source / "src" / relative, split_flags(list(flags), pipeline), cfg, Path(work),
                                     includes=[*includes, (source / "src" / relative).parent, source / "src"])
                shutil.copyfile(built, target)
        except (BuildError, OSError, RuntimeError) as error:
            return relative, pipeline, flags, None, str(error)[-300:]
        return relative, pipeline, flags, target, None

    def assemble(relative: str, target: Path):
        """A hand-written unit.  IDO's driver preprocesses and assembles it; for the GCC build the
        text is preprocessed here once, so that what the donor stage rebuilds needs no headers."""
        try:
            with tempfile.TemporaryDirectory(prefix="n64dk-sdk-") as work:
                text = plain / relative
                text.parent.mkdir(parents=True, exist_ok=True)
                defines = [f for f in (unit_recipe(version, flavour, relative)[1] if gcc
                                       else assembly_recipe(version, flavour, relative))
                           if f.startswith("-D") and f not in ("-D_LANGUAGE_C", "-D__USE_ISOC99")]
                from .. import safety
                done = safety.run_tool(
                    ["gcc", "-E", "-P", "-undef", "-x", "assembler-with-cpp", "-Dmips=1", "-D_MIPS_SIM_ABI32=1",
                     *dict.fromkeys(_ASM_DEFINES + defines),
                     *[f"-I{path}" for path in (*includes, (source / "src" / relative).parent, source / "src")],
                     str(source / "src" / relative), "-o", str(text)], kind="light", capture_output=True, text=True)
                if done.returncode != 0:
                    return relative, "as", [], None, done.stderr[-300:]
                if gcc:
                    built = compile_unit(text, split_flags([], "as"), cfg, Path(work), includes=[])
                    shutil.copyfile(built, target)
                    return str(text), "as", [], target, None
                # IDO's own assembler encodes several instructions its own way: the text goes
                # through its driver, already preprocessed (the driver's preprocessor is not used)
                flags = [f for f in assembly_recipe(version, flavour, relative)
                         if not f.startswith("-D") and f not in ("-nostdinc", "-woff", "516,649,838,712")]
                built = compile_unit(text, split_flags(list(flags), "ido5.3"), cfg, Path(work), includes=[])
                shutil.copyfile(built, target)
                sort_symbols(target)                          # IDO's assembler mixes local and global symbols
                return str(text), "ido5.3-asm", flags, target, None
        except (BuildError, OSError, RuntimeError) as error:
            return relative, "as", [], None, str(error)[-300:]

    with ThreadPoolExecutor(max(1, jobs)) as pool:
        wanted = [unit for unit in units_of(source, version, flavour) if not (recipe and unit.endswith(".s"))]
        for relative, pipeline, flags, target, error in pool.map(one, wanted):
            if error:
                failed.append({"unit": relative, "error": error})
            else:
                rows.append((relative, pipeline, flags, target))
    if not rows:
        return {"name": name, "units": 0, "failed": failed, "reason": "no unit compiled"}
    described = sourcedonor.describe(
        folder, name, source,
        [(relative if pipeline in ("as", "ido5.3-asm") else f"src/{relative}", pipeline, flags, target)
         for relative, pipeline, flags, target in rows],
        includes, cfg, f"libultra 2.0{version} {flavour}", defsyms=BOOT_GLOBALS)
    shutil.rmtree(objects, ignore_errors=True)               # the image holds what the donor stage needs
    if not described.get("units"):
        return {"name": name, "units": 0, "failed": failed, "reason": described.get("reason", "nothing linked")}
    described.pop("symbols_not_written_in_c", None)
    described.pop("symbols_the_tree_does_not_define", None)
    return {**described, "failed": failed}
