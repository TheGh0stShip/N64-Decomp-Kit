"""A source tree as a donor, with nothing told about how it is built.

A title somebody has already decompiled comes with C that is known to give its bytes.  The donor
stage (``n64dk.match.transplant``) can use such source, but it wants what a build system knows:
which files are units, where their headers are, which compiler and flags each unit takes and which
configuration macros are set.  Every tree says that differently (a Makefile, a build generator, a
splitter's configuration), and reading those is reading a program.

This module asks the compiler and the target instead, the way the rest of the kit does:

* **units** are the C files that hold a function body;
* **include directories** are found from the ``#include`` lines themselves: a name that is not
  beside the including file is looked up among the tree's files by its path suffix, and the
  directory that makes the name resolve becomes a search directory;
* the **recipe of each unit** is the candidate recipe under which most of its functions are found
  in the target (compared by masked signature, the donor stage's own comparison);
* **configuration macros** are the names the tree tests in ``#if`` lines and never defines.  Each
  is tried on the units that can see it and kept when more of the target is found with it than
  without it.  A version switch, a display-list dialect and a build option are all found this way,
  and a macro that would select another release is rejected by the same measurement.

The result is one donor: the units, each built under its recipe, linked into an image at a fixed
address, with a manifest row per unit (offset, size, source, flags).  Nothing in it is trusted by
the run that uses it: a function counts only when the donor stage rebuilds its unit for the target
and the bytes and relocations agree.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BASE = 0x80200000                     # where a donor image is linked: looks like an address, belongs to no title
UNDEFINED = BASE + 0x00C00000         # where what the tree does not define is given a place (see ``link``)
SKIP_DIRS = frozenset({"build", "tools", "expected", "nonmatchings", "node_modules", "venv", "__pycache__"})
MIN_WORDS = 5                         # a shorter function is found in every title and says nothing
SAMPLE = 32                           # units a configuration macro is measured on
MAX_MACROS = 48                       # configuration macros measured, most used first
BASE_DEFINES = ("-D_LANGUAGE_C",)     # every N64 header set tests it

INCLUDE = re.compile(r'^[ \t]*#[ \t]*include[ \t]*([<"])([^>"]+)[>"]', re.M)
CONDITION = re.compile(r"^[ \t]*#[ \t]*(?:if|ifdef|ifndef|elif)\b((?:\\\n|[^\n])*)", re.M)
DIRECTIVE = re.compile(r"^[ \t]*#[ \t]*(ifdef|ifndef|if|elif|else|endif|define)\b[ \t]*([A-Za-z_]\w*)?", re.M)
IDENT = re.compile(r"[A-Za-z_]\w*")
COMPARISON = re.compile(r"([A-Za-z_]\w*|\d\w*)\s*(?:==|!=|<=|>=|<|>)\s*([A-Za-z_]\w*|\d\w*)")
MAX_VALUES = 12                       # values tried for one macro that the tree compares with something
FUNCTION_BODY = re.compile(r"\)\s*(?:/\*[^*]*\*/\s*)?\{")
DEFINITION = re.compile(r"(?=\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{)")
COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


# --------------------------------------------------------------------------- the tree

class Tree:
    """The C and header files of a source tree, and what their ``#include`` lines mean."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.units: list[str] = []
        self.by_name: dict[str, list[str]] = {}
        self._text: dict[str, str] = {}
        self._includes: dict[str, list[str]] = {}
        self._tested: dict[str, set[str]] = {}
        self._defined: dict[str, set[str]] = {}
        self.roots: list[str] = []
        for folder, dirs, files in os.walk(self.root):
            relative = Path(folder).relative_to(self.root).as_posix()
            relative = "" if relative == "." else relative
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            generated = any(part in SKIP_DIRS for part in relative.split("/"))
            for name in sorted(files):
                path = f"{relative}/{name}" if relative else name
                if name.endswith((".h", ".inc", ".inc.c", ".def")):
                    self.by_name.setdefault(name, []).append(path)
                elif name.endswith(".c") and not generated and FUNCTION_BODY.search(self.text(path)):
                    self.units.append(path)

    def text(self, relative: str) -> str:
        if relative not in self._text:
            try:
                self._text[relative] = COMMENT.sub(" ", (self.root / relative).read_text(errors="replace"))
            except OSError:
                self._text[relative] = ""
        return self._text[relative]

    def find(self, name: str, near: str, quoted: bool) -> str | None:
        """The file of the tree that ``#include`` of ``name`` in the file ``near`` means.  A name
        found by its suffix adds the directory that resolves it to the search directories."""
        name = os.path.normpath(name).replace(os.sep, "/")
        if quoted:
            beside = os.path.normpath(os.path.join(os.path.dirname(near), name)).replace(os.sep, "/")
            if not beside.startswith("../") and (self.root / beside).is_file():
                return beside
        if name.startswith("../"):
            return None
        for root in self.roots:
            path = f"{root}/{name}" if root else name
            if (self.root / path).is_file():
                return path
        found = [path for path in self.by_name.get(name.rsplit("/", 1)[-1], [])
                 if path == name or path.endswith("/" + name)]
        if not found:
            return None
        # a file of the tree before a generated one, the shortest path first
        found.sort(key=lambda path: (any(part in SKIP_DIRS for part in path.split("/")), path.count("/"), path))
        self.roots.append(found[0][:-len(name)].rstrip("/"))
        return found[0]

    def includes(self, relative: str) -> list[str]:
        if relative not in self._includes:
            self._includes[relative] = [found for quote, name in INCLUDE.findall(self.text(relative))
                                        if (found := self.find(name, relative, quote == '"')) is not None]
        return self._includes[relative]

    def closure(self, relative: str, limit: int = 600) -> list[str]:
        """``relative`` and every file of the tree it includes, directly or not."""
        seen, todo = {relative: None}, [relative]
        while todo and len(seen) < limit:
            for found in self.includes(todo.pop()):
                if found not in seen:
                    seen[found] = None
                    todo.append(found)
        return list(seen)

    def defines(self, unit: str, label: str) -> bool:
        """Whether ``label`` is a function written in C in ``unit`` or a file it includes.

        A unit can also carry code that is not C: a macro that pulls a disassembled function in
        through the assembler, as trees in progress do for what is not decompiled yet.  Such a
        function would compare equal to the title, being the title's own bytes, and must never be
        offered as a decompilation.  Only a name followed by a parameter list and a body counts."""
        if unit not in self._defined:
            names: set[str] = set()
            for relative in self.closure(unit):
                names.update(DEFINITION.findall(self.text(relative)))
            self._defined[unit] = names
        return label in self._defined[unit]

    def resolve_all(self) -> list[Path]:
        """Walk every unit's includes (which fixes the search directories) and return them."""
        for unit in self.units:
            self.closure(unit)
        return [self.root / root if root else self.root for root in self.roots]

    def tested(self, relative: str) -> set[str]:
        """Names the preprocessor conditions of ``relative`` test."""
        if relative not in self._tested:
            names: set[str] = set()
            for condition in CONDITION.findall(self.text(relative)):
                names.update(IDENT.findall(condition))
            names.discard("defined")
            self._tested[relative] = names
        return self._tested[relative]

    def macros(self) -> list[tuple[str, int]]:
        """Configuration macros: names the tree's conditions test and the tree does not define
        unconditionally, with the number of files testing each, most used first.  Names the
        compiler defines (two leading underscores) are left out.

        A macro the tree compares with something (``#if RELEASE >= RELEASE_C``, ``#if LEVEL > 1``)
        is offered as ``NAME=VALUE`` once for each thing it is compared with (a number also one
        higher, for ``>``); one that is only tested for being set is offered as ``NAME``."""
        defined: set[str] = set()
        tested: dict[str, int] = {}
        values: dict[str, dict[str, None]] = {}
        files: dict[str, None] = {}
        for unit in self.units:
            files.update(dict.fromkeys(self.closure(unit)))
        for relative in files:
            text = self.text(relative)
            defined.update(always_defined(text))
            for name in self.tested(relative):
                tested[name] = tested.get(name, 0) + 1
            for condition in CONDITION.findall(text):
                for left, right in COMPARISON.findall(condition):
                    for name, value in ((left, right), (right, left)):
                        if not name[0].isdigit():
                            values.setdefault(name, {})[value] = None
                            if value.isdigit():
                                values[name][str(int(value) + 1)] = None
        out = []
        for name, count in tested.items():
            if name in defined or name.startswith("__") or name[0].isdigit():
                continue
            compared = [value for value in values.get(name, {}) if value[0].isdigit() or value in defined]
            if compared:
                out += [(f"{name}={value}", count) for value in sorted(compared)[:MAX_VALUES]]
            else:
                out.append((name, count))
        return sorted(out, key=lambda item: (-item[1], item[0]))

    def seeing(self, macro: str) -> list[str]:
        """Units that can see ``macro``: it is tested in the unit or in something it includes."""
        name = macro.split("=", 1)[0]
        return [unit for unit in self.units
                if any(name in self.tested(relative) for relative in self.closure(unit))]


def always_defined(text: str) -> set[str]:
    """Names ``text`` defines whatever the configuration: outside every condition, an include
    guard not counting as one.  A name defined only under a condition can still be set from
    outside (a header that derives one dialect macro from another), so it stays a candidate."""
    found = DIRECTIVE.findall(text)
    names: set[str] = set()
    frames: list[bool] = []                                  # True: an include guard
    for index, (kind, name) in enumerate(found):
        if kind in ("if", "ifdef", "ifndef"):
            following = found[index + 1] if index + 1 < len(found) else ("", "")
            frames.append(kind == "ifndef" and following == ("define", name))
        elif kind == "endif":
            if frames:
                frames.pop()
        elif kind == "define" and name and all(frames):
            names.add(name)
    return names


LICENCE_NAMES = re.compile(r"^(?:licen[cs]e|copying|unlicense|notice)(?:[._-].*)?$", re.I)


def provenance(root: Path) -> dict:
    """Where a source tree came from, read without changing it: its version-control state (no
    lock, no index refresh), its licence files by digest and first line, and its own digest
    over the files the importer reads (C and headers)."""
    root = Path(root)
    out: dict = {"path": str(root)}
    if (root / ".git").exists():
        def git(*args):
            try:
                from .. import safety
                done = safety.run_tool(["git", "--no-optional-locks", "-C", str(root), *args], kind="light",
                                       capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                return None
            return done.stdout.strip() if done.returncode == 0 else None
        out.update(commit=git("rev-parse", "HEAD"), remote=git("config", "--get", "remote.origin.url"),
                   commit_date=git("log", "-1", "--format=%cI"))
        status = git("status", "--porcelain", "--untracked-files=no")
        out["modified_files"] = None if status is None else len([line for line in status.splitlines() if line.strip()])
    licences = []
    for path in sorted(root.iterdir()) if root.is_dir() else []:
        if path.is_file() and LICENCE_NAMES.match(path.name):
            data = path.read_bytes()
            first = next((line.strip() for line in data.decode(errors="replace").splitlines() if line.strip()), "")
            licences.append({"file": path.name, "sha256": hashlib.sha256(data).hexdigest(), "first_line": first[:120]})
    out["licence_files"] = licences
    if not licences:
        out["licence_note"] = "no licence file at the top of the tree: redistribution terms unknown"
    digest, count = hashlib.sha256(), 0
    for folder, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        for name in sorted(files):
            if name.endswith((".c", ".h", ".inc", ".inc.c", ".def")):
                path = Path(folder) / name
                digest.update(str(path.relative_to(root)).encode())
                digest.update(hashlib.sha256(path.read_bytes()).digest())
                count += 1
    out.update(source_files=count, source_digest=digest.hexdigest())
    return out


def prepared_copy(source: Path, where: Path, command: str, timeout: int = 1800) -> dict:
    """Copy ``source`` to ``where`` (version control left out) and run ``command`` there, for a
    tree whose headers its own build generates.  The tree itself is never written.  Returns what
    ran and how it ended."""
    shutil.rmtree(where, ignore_errors=True)
    shutil.copytree(source, where, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    try:
        from .. import safety
        # a tree's own build step (make): one compile token, run serially inside it
        done = safety.run_tool(["bash", "-c", command], kind="compile", cwd=where, capture_output=True, text=True,
                               timeout=timeout, env={**os.environ, "MAKEFLAGS": os.environ.get("MAKEFLAGS", "-j1")})
        result = {"command": command, "exit": done.returncode, "output_tail": (done.stdout + done.stderr)[-800:]}
    except subprocess.TimeoutExpired:
        result = {"command": command, "exit": None, "output_tail": f"timed out after {timeout} s"}
    return result


def spread(items: list, count: int) -> list:
    """At most ``count`` of ``items``, evenly spaced."""
    if len(items) <= count:
        return list(items)
    return [items[index * len(items) // count] for index in range(count)]


# --------------------------------------------------------------------------- selection (no compiler)

def choose_recipes(found: dict[str, dict[str, int]], recipes: list[str]) -> tuple[dict[str, str], str | None]:
    """``found[recipe][unit]`` = functions of the target found in the unit built that way.
    Returns the recipe of each unit that found any (the first listed wins a tie) and the recipe
    most units took, which is what a unit that found nothing is built with."""
    chosen: dict[str, str] = {}
    for unit in sorted({unit for table in found.values() for unit in table}):
        best = max(recipes, key=lambda recipe: (found.get(recipe, {}).get(unit, 0), -recipes.index(recipe)))
        if found.get(best, {}).get(unit, 0) > 0:
            chosen[unit] = best
    tally: dict[str, int] = {}
    for recipe in chosen.values():
        tally[recipe] = tally.get(recipe, 0) + 1
    majority = max(recipes, key=lambda recipe: (tally.get(recipe, 0), -recipes.index(recipe))) if recipes else None
    return chosen, majority


def choose_macros(candidates: list[str], measure, rounds: int = 4) -> tuple[list[str], list[dict]]:
    """Keep the macros that find more of the target.

    ``measure(macros, candidate)`` returns the number of target functions found on the units that
    see ``candidate`` when ``macros`` are defined.  In each round every candidate not yet kept is
    measured on top of the ones kept; those that gain are added in order of gain, each only if it
    still gains on top of what the round has added before it.  Two macros that exclude each other
    (two releases of a title) both gain at first; the larger is taken and the other then gains
    nothing.  A macro that only counts once another is set (nothing compiles without the first)
    is found in the next round, which is why there are several."""
    kept: list[str] = []
    taken: set[str] = set()
    rows: dict[str, dict] = {}
    for number in range(1, rounds + 1):
        base = list(kept)
        gains = []
        for candidate in candidates:
            if candidate.split("=", 1)[0] in taken:           # kept, or another value of the same macro is
                continue
            before, after = measure(base, candidate), measure([*base, candidate], candidate)
            rows[candidate] = {"macro": candidate, "round": number, "without": before, "with": after, "kept": False}
            if after > before:
                gains.append((after - before, candidate))
        added = False
        for _gain, candidate in sorted(gains, key=lambda item: -item[0]):
            row = rows[candidate]
            if kept != base:                                  # something was added since it was measured
                row["without"], row["with"] = measure(kept, candidate), measure([*kept, candidate], candidate)
                if row["with"] <= row["without"]:
                    continue
            if candidate.split("=", 1)[0] in taken:           # a better value of the same macro went first
                continue
            row["kept"] = added = True
            kept.append(candidate)
            taken.add(candidate.split("=", 1)[0])
        if not added:
            break
    return kept, [rows[candidate] for candidate in candidates if candidate in rows]


# --------------------------------------------------------------------------- compiling and linking

def tool(cfg, name: str) -> tuple[str, dict]:
    located = cfg.gnu_as()
    if located is None:
        raise RuntimeError("a MIPS GNU binutils (mips-linux-gnu-ld) is needed to describe sources as an image")
    assembler, env = located
    path = Path(assembler).with_name(Path(assembler).name.replace("-as", f"-{name}"))
    if not path.is_file():
        found = shutil.which(path.name)
        if not found:
            raise RuntimeError(f"{path.name} not found")
        path = Path(found)
    return str(path), env


def split_recipe(recipe: str) -> tuple[str, list[str]]:
    parts = shlex.split(recipe)
    return parts[0], parts[1:]


def object_key(source: Path, pipeline: str, flags: list[str], cfg, includes: list[Path]) -> str:
    """What an object depends on: the source, every header it reaches (recursively, by content),
    the include search, the flags and macros, and the compiler's own files.  An object kept under
    this key is reused only when none of them changed."""
    from .pipeline import dependency_digest, split_flags, toolchain_digest
    spec = split_flags(list(flags), pipeline)
    try:
        closure = dependency_digest(Path(source), spec, cfg, [Path(source).parent, *includes])
    except OSError:
        closure = "unreadable"
    material = [str(source), hashlib.sha256(Path(source).read_bytes()).hexdigest() if Path(source).is_file() else "missing",
                closure, pipeline, *flags, toolchain_digest(cfg, pipeline)]
    return hashlib.sha256("\0".join(material).encode()).hexdigest()[:24]


class Builder:
    """Compiles units of a tree and keeps every object, so that no (unit, recipe, macros) is built twice."""

    def __init__(self, tree: Tree, includes: list[Path], cfg, objects: Path, jobs: int = 4):
        self.tree, self.includes, self.cfg, self.objects, self.jobs = tree, includes, cfg, Path(objects), max(1, jobs)
        self.objects.mkdir(parents=True, exist_ok=True)
        self.errors: dict[str, str] = {}
        self.builds = 0

    def flags(self, recipe: str, macros: list[str]) -> list[str]:
        return [*split_recipe(recipe)[1], *BASE_DEFINES,
                *[f"-D{macro}" if "=" in macro else f"-D{macro}=1" for macro in macros]]

    def one(self, unit: str, recipe: str, macros: list[str]) -> Path | None:
        import tempfile
        from .pipeline import BuildError, build as compile_unit, split_flags
        pipeline, flags = split_recipe(recipe)[0], self.flags(recipe, macros)
        key = object_key(self.tree.root / unit, pipeline, flags, self.cfg, list(self.includes))
        target, failed = self.objects / f"{key}.o", self.objects / f"{key}.err"
        if target.is_file():
            return target
        if failed.is_file():
            self.errors[unit] = failed.read_text()
            return None
        self.builds += 1
        source = self.tree.root / unit
        try:
            with tempfile.TemporaryDirectory(prefix="n64dk-tree-") as work:
                built = compile_unit(source, split_flags(list(flags), pipeline), self.cfg, Path(work),
                                     includes=[source.parent, *self.includes])
                shutil.copyfile(built, target)
        except (BuildError, OSError, RuntimeError) as error:
            self.errors[unit] = str(error)[-300:]
            failed.write_text(self.errors[unit])
            return None
        return target

    def many(self, units: list[str], recipe_of, macros: list[str]) -> dict[str, Path]:
        """``{unit: object}`` for the units that compile; ``recipe_of(unit)`` names each one's recipe."""
        with ThreadPoolExecutor(self.jobs) as pool:
            built = pool.map(lambda unit: (unit, self.one(unit, recipe_of(unit), macros)), units)
            return {unit: target for unit, target in built if target is not None}


def link(objects: list[Path], folder: Path, cfg, defsyms: dict[str, int] | None = None,
         place_undefined: bool = False) -> dict:
    """Link ``objects`` at ``BASE``.  Returns the image path, the symbol listing and where each
    object's code went; ``{"error": ...}`` when no image comes out.

    What the objects do not define stays at zero (every relocated field is masked when code is
    compared).  With ``place_undefined`` each such symbol gets an address of its own instead.
    At zero, every call to an undefined function reads as a call to the first address of
    memory: all of them look like one symbol, at an address that is the same on every console,
    and a unit that calls one is refused as contradicting the target.  With a place of its own
    each name can be followed to the one target address its callers agree on."""
    folder.mkdir(parents=True, exist_ok=True)
    linker, env = tool(cfg, "ld")
    script, listing = folder / "link.ld", folder / "objects.txt"
    elf, image, map_file = folder / "library.elf", folder / "image.bin", folder / "library.map"
    for stale in (elf, image, map_file):
        stale.unlink(missing_ok=True)
    script.write_text(
        "SECTIONS {\n  . = 0x%08X;\n  .text : { *(.text*) }\n  .rodata : { *(.rodata*) *(.rdata*) *(.lit*) }\n"
        "  .data : { *(.data*) *(.sdata*) }\n  .bss (NOLOAD) : { *(.bss*) *(.sbss*) *(COMMON) *(.scommon*) }\n"
        "  /DISCARD/ : { *(.reginfo) *(.MIPS.abiflags) *(.mdebug*) *(.pdr) *(.comment) *(.options) *(.gptab*) "
        "*(.note*) *(.debug*) *(.gnu.attributes) }\n}\n" % BASE)
    listing.write_text("\n".join(str(target) for target in objects) + "\n")
    environment = {**os.environ, **env}
    placed_symbols: dict[str, int] = {}

    def run_linker():
        given = {**placed_symbols, **(defsyms or {})}
        from .. import safety
        return safety.run_tool([linker, "-EB", "-T", str(script), "-Map", str(map_file), "-o", str(elf),
                               "--unresolved-symbols=ignore-all", "-z", "muldefs", "--no-warn-mismatch",
                               "--no-check-sections", "--noinhibit-exec",
                               # quoted: ld reads a name made only of hex digits ("bb", "fh") as a number
                               *[f'--defsym="{symbol}"=0x{address:08X}' for symbol, address in given.items()],
                               f"@{listing}"],
                              kind="compile", capture_output=True, text=True, env=environment)

    linked = run_linker()
    if place_undefined and elf.is_file():
        nm, _env = tool(cfg, "nm")
        # what the objects ask for, less what the linked image defines (the image itself no
        # longer says what was left open)
        from .. import safety
        wanted = safety.run_tool([nm, "--undefined-only", f"@{listing}"], capture_output=True, text=True,
                                 env=environment)
        defined = safety.run_tool([nm, "--defined-only", str(elf)], capture_output=True, text=True, env=environment)
        names = sorted({line.split()[-1] for line in wanted.stdout.splitlines() if line.split()[:1] == ["U"]}
                       - {line.split()[-1] for line in defined.stdout.splitlines() if line.split()}
                       - set(defsyms or {}))
        names = [name for name in names if re.fullmatch(r"[A-Za-z_]\w*", name)]
        if names:
            placed_symbols.update({name: UNDEFINED + 0x10 * number for number, name in enumerate(names)})
            elf.unlink()
            linked = run_linker()
    # A call to a function outside the image cannot be encoded from here to address zero; the
    # linker says so and still writes the image, and every call target is masked anyway.
    if not elf.is_file():
        return {"error": "link failed: " + linked.stderr[-400:]}
    objcopy, _env = tool(cfg, "objcopy")
    from .. import safety
    copied = safety.run_tool([objcopy, "-O", "binary", str(elf), str(image)], capture_output=True, text=True,
                            env=environment)
    if copied.returncode != 0 or not image.is_file():        # objects that hold no code or data at all
        return {"error": "no image: " + copied.stderr[-300:]}
    nm, _env = tool(cfg, "nm")
    listed = safety.run_tool([nm, "-n", "-S", "--defined-only", str(elf)], capture_output=True, text=True,
                            env=environment)
    if listed.returncode != 0:
        return {"error": "no symbols: " + listed.stderr[-300:]}
    symbols = listed.stdout
    placed: dict[str, tuple[int, int]] = {}
    for found in re.finditer(r"^ \.text\S*\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+(\S+\.o)$", map_file.read_text(), re.M):
        start, size, path = int(found.group(1), 16), int(found.group(2), 16), found.group(3)
        if size:
            first, total = placed.get(path, (start, 0))
            placed[path] = (min(first, start), max(first + total, start + size) - min(first, start))
    return {"image": image, "symbols": symbols, "placed": placed, "undefined": placed_symbols,
            "scratch": (elf, map_file, listing, script)}


def functions_of(symbols: str, spans: list[tuple[int, int]],
                 assembly: list[tuple[int, int]] = ()) -> tuple[list[list], list[str]]:
    """``[[label, address, size]]`` for the functions of a linked image and its symbol-file lines.

    A label inside a hand-written routine is a symbol too, and not a function: where a unit states
    sizes, only its sized symbols are functions.  A symbol without a size ends at the next one."""
    text_end = max((end for _start, end in spans), default=BASE)
    functions, lines = [], []
    for line in symbols.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[2] in "TtDdRrBbSs":
            address, size, kind, label = int(parts[0], 16), int(parts[1], 16), parts[2], parts[3]
        elif len(parts) == 3 and parts[1] in "TtDdRrBbSs":
            address, size, kind, label = int(parts[0], 16), 0, parts[1], parts[2]
        else:
            continue
        if not re.fullmatch(r"[A-Za-z_]\w*", label):
            continue
        lines.append(f"{label} = 0x{address:08X};" + (f" // size:0x{size:X}" if size else ""))
        if kind in "Tt" and BASE <= address < text_end:
            if kind == "t" and any(start <= address < end for start, end in assembly):
                continue                                     # a local label inside a hand-written routine
            functions.append([label, address, size])
    functions.sort(key=lambda row: row[1])
    sized_units = {span for span in spans if any(span[0] <= address < span[1] and size for _l, address, size in functions)}
    functions = [row for row in functions
                 if row[2] or not any(start <= row[1] < end for start, end in sized_units)]
    for index, row in enumerate(functions):
        if not row[2]:
            limit = min([end for start, end in spans if start <= row[1] < end] or [text_end])
            following = functions[index + 1][1] if index + 1 < len(functions) else limit
            row[2] = max(4, min(following, limit) - row[1])
    return functions, lines


def quote(value) -> str:
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def describe(folder: Path, name: str, source: Path, rows: list[tuple[str, str, list[str], Path]],
             includes: list[Path], cfg, title: str, defsyms: dict[str, int] | None = None,
             keep_objects: Path | None = None, is_function=None, place_undefined: bool = False) -> dict:
    """Link ``rows`` (``(source path, pipeline, flags, object)``) and write the donor: image,
    function catalogue, symbol file, one manifest per pipeline and the ``[donor.<name>]`` table.

    A source path is relative to ``source`` or absolute.  The pipelines ``as`` and ``ido5.3-asm``
    mark hand-written units (preprocessed text): they go to the manifests of the lanes that
    assemble them, and local labels inside them are not functions.  ``is_function(source path,
    label)``, when given, says which symbols of a unit are catalogued."""
    linked = link([target for _s, _p, _f, target in rows], folder, cfg, defsyms, place_undefined)
    if "error" in linked:
        return {"name": name, "units": 0, "reason": linked["error"]}
    image = linked["image"]
    by_object = {str(target): (relative, pipeline, flags) for relative, pipeline, flags, target in rows}
    manifests: dict[str, list[str]] = {}
    spans, assembly, owners = [], [], []
    for path, (start, size) in sorted(linked["placed"].items(), key=lambda item: item[1]):
        if path not in by_object:
            continue
        relative, pipeline, flags = by_object[path]
        owners.append((start, start + size, relative))
        if pipeline == "as":                                  # preprocessed text: an absolute path, no flags
            manifests.setdefault("kmc+as", []).append(f"0x{start - BASE:X}\t0x{size:X}\t{relative}")
        elif pipeline == "ido5.3-asm":                        # preprocessed text through IDO's assembler
            manifests.setdefault("ido5.3", []).append(
                f"0x{start - BASE:X}\t0x{size:X}\t{relative}\t{' '.join(shlex.quote(flag) for flag in flags)}")
        else:
            manifests.setdefault(pipeline, []).append(
                f"0x{start - BASE:X}\t0x{size:X}\t{relative}\t{' '.join(shlex.quote(flag) for flag in flags)}")
        spans.append((start, start + size))
        if pipeline in ("as", "ido5.3-asm"):
            assembly.append((start, start + size))
    functions, lines = functions_of(linked["symbols"], spans, assembly)
    left_out = 0
    if is_function is not None:
        kept = [row for row in functions
                if is_function(next((unit for start, end, unit in owners if start <= row[1] < end), ""), row[0])]
        left_out, functions = len(functions) - len(kept), kept
    lines += [f"{label} = 0x{address:08X};" for label, address in sorted(linked["undefined"].items())]
    (folder / "symbols.txt").write_text("\n".join(lines) + "\n")
    (folder / "functions.tsv").write_text("# ROM SIZE VRAM NAME\n" + "".join(
        f"0x{address - BASE:X}\t0x{size:X}\t0x{address:08X}\t{label}\n" for label, address, size in functions))
    entries = []
    for pipeline, table in sorted(manifests.items()):
        path = folder / f"manifest.{re.sub(r'[^A-Za-z0-9.]+', '_', pipeline)}.tsv"
        path.write_text(f"# {title}; pipeline {pipeline}; ROM_START SIZE SOURCE FLAGS\n" + "\n".join(table) + "\n")
        entries.append((path, pipeline))
    if keep_objects is None:
        for _s, _p, _f, target in rows:                       # the image holds what the donor stage needs
            target.unlink(missing_ok=True)
    for stale in linked["scratch"]:
        stale.unlink(missing_ok=True)
    toml = [f"[donor.{name}]", f"root = {quote(source)}", f"image = {quote(image)}", f"vram_delta = 0x{BASE:08X}",
            f"symbols = [{quote(folder / 'symbols.txt')}]", f"catalogue = [{quote(folder / 'functions.tsv')}]",
            "include = [" + ", ".join(quote(path) for path in includes) + "]",
            'kmc_lane = "kmc+as"', "manifests = ["]
    toml += [f"  {{ path = {quote(path)}, pipeline = {quote(pipeline)} }}," for path, pipeline in entries] + ["]", ""]
    return {"name": name, "units": len(spans), "functions": len(functions), "symbols_not_written_in_c": left_out,
            "symbols_the_tree_does_not_define": len(linked["undefined"]),
            "image_bytes": image.stat().st_size, "toml": "\n".join(toml), "folder": str(folder)}


# --------------------------------------------------------------------------- measuring against a target

def target_signatures(project) -> dict[tuple[str, int], list[tuple[str, int]]]:
    """``{(masked signature, length): [(image, address)]}`` for the functions of a surveyed
    project that are long enough to identify anything."""
    from . import images as imagemod
    from .transplant import mask, signature, strip_padding
    out: dict[tuple[str, int], list[tuple[str, int]]] = {}
    for image in sorted(imagemod.load_registry(project)):
        spec = imagemod.resolve(project, image)
        data, delta = spec.load(), spec.delta
        for _name, vram, size in spec.rows():
            code = strip_padding(data[vram - delta:vram - delta + size])
            if len(code) >= 4 * MIN_WORDS:
                out.setdefault((signature(mask(code, vram)[0]), len(code)), []).append((image, vram))
    return out


def found_in_target(objects: dict[str, Path], folder: Path, cfg, signatures: dict, is_function=None,
                    totals: dict | None = None) -> dict[str, set]:
    """``{unit: {target functions found}}`` for units built to ``objects``, linked together.
    With ``is_function(unit, label)``, only the symbols it accepts are compared.  ``totals``, when
    given, receives the number of functions long enough to compare in each unit."""
    from .transplant import mask, signature, strip_padding
    if not objects:
        return {}
    linked = link(list(objects.values()), folder, cfg)
    if "error" in linked:
        return {}
    data = linked["image"].read_bytes()
    unit_of = {str(target): unit for unit, target in objects.items()}
    spans = sorted((start, start + size, unit_of[path]) for path, (start, size) in linked["placed"].items()
                   if path in unit_of)
    functions, _lines = functions_of(linked["symbols"], [(start, end) for start, end, _u in spans])
    found: dict[str, set] = {unit: set() for unit in objects}
    for _label, address, size in functions:
        unit = next((unit for start, end, unit in spans if start <= address < end), None)
        code = strip_padding(data[address - BASE:address - BASE + size])
        if unit is None or len(code) < 4 * MIN_WORDS or (is_function is not None and not is_function(unit, _label)):
            continue
        if totals is not None:
            totals[unit] = totals.get(unit, 0) + 1
        for place in signatures.get((signature(mask(code, address)[0]), len(code)), ()):
            found[unit].add(place)
    for stale in linked["scratch"]:
        stale.unlink(missing_ok=True)
    return found


def calibrate(tree: Tree, signatures: dict, recipes: list[str], cfg, work: Path, jobs: int = 4,
              macros: list[str] | None = None, max_macros: int = MAX_MACROS, emit=None,
              objects: Path | None = None) -> dict:
    """Find, by building and comparing with the target, each unit's recipe and the tree's
    configuration macros.  ``macros`` are taken as given and not measured."""
    emit = emit or (lambda *_a, **_k: None)
    includes = tree.resolve_all()
    given = list(macros or [])
    # files the tree's own build would generate: stand-ins, so that a unit including one is
    # still measured (see ``preprocessed``)
    standins = Path(work) / "standins"
    for unit in tree.units:
        preprocessed(tree.root / unit, split_recipe(recipes[0])[0] if recipes else "ido5.3",
                     [*BASE_DEFINES, *[f"-D{m}" if "=" in m else f"-D{m}=1" for m in given]], includes, standins, [])
    if standins.is_dir():
        includes = [*includes, standins]
    builder = Builder(tree, includes, cfg, objects or work / "obj", jobs)
    totals: dict[str, int] = {}

    def survey(defined: list[str]) -> dict[str, dict[str, int]]:
        table = {}
        for recipe in recipes:
            built = builder.many(tree.units, lambda _unit: recipe, defined)
            counted: dict[str, int] = {}
            table[recipe] = {unit: len(places) for unit, places in
                             found_in_target(built, work / "probe", cfg, signatures, tree.defines, counted).items()}
            for unit, count in counted.items():
                totals[unit] = max(totals.get(unit, 0), count)
            emit("recipe", recipe=recipe, compiled=len(built), found=sum(table[recipe].values()))
        return table

    first = survey(given)
    chosen, majority = choose_recipes(first, recipes)
    recipe_of = lambda unit: chosen.get(unit, majority)       # noqa: E731

    candidates = [name for name, _count in tree.macros() if name not in given]
    measured, skipped = candidates[:max_macros], candidates[max_macros:]
    samples: dict[str, list[str]] = {}

    # A macro is measured on the units that can see it, those with the most functions not yet
    # found first: a setting that changes few functions shows there, and nowhere else.
    best = {unit: max((table.get(unit, 0) for table in first.values()), default=0) for unit in tree.units}
    unfound = {unit: totals.get(unit, 0) - best[unit] for unit in tree.units}

    def measure(defined: list[str], candidate: str) -> int:
        if candidate not in samples:
            seeing = tree.seeing(candidate)
            ranked = sorted(seeing, key=lambda unit: -unfound.get(unit, 0))
            worst = [unit for unit in ranked if unfound.get(unit, 0) > 0][:SAMPLE // 2]
            samples[candidate] = worst + [unit for unit in spread(seeing, SAMPLE) if unit not in worst][:SAMPLE - len(worst)]
        built = builder.many(samples[candidate], recipe_of, [*given, *defined])
        return sum(len(places) for places in found_in_target(built, work / "probe", cfg, signatures, tree.defines).values())

    kept, trials = choose_macros(measured, measure)
    emit("macros", kept=kept)
    final = survey([*given, *kept]) if kept else first
    chosen, majority = choose_recipes(final, recipes)
    return {"includes": includes, "macros": [*given, *kept], "macro_trials": trials, "macros_not_measured": skipped,
            "recipes": chosen, "majority": majority, "builder": builder,
            "found_by_recipe": {recipe: sum(table.values()) for recipe, table in final.items()},
            "first_found_by_recipe": {recipe: sum(table.values()) for recipe, table in first.items()}}


IDO_PREDEFINED = ("-D__sgi", "-Dsgi", "-D__mips=2", "-Dmips", "-D__host_mips", "-D_MIPSEB", "-DMIPSEB", "-D__unix",
                  "-Dunix", "-D_MIPS_SZINT=32", "-D_MIPS_SZLONG=32", "-D_MIPS_SZPTR=32", "-D_MIPS_ISA=2",
                  "-D_MIPS_SIM=1")
GCC_PREDEFINED = ("-D__GNUC__=2", "-D__GNUC_MINOR__=7", "-Dmips", "-D__mips__", "-D__mips", "-DMIPSEB", "-D_MIPSEB",
                  "-D__MIPSEB__", "-D__LANGUAGE_C__", "-D_MIPS_SZINT=32", "-D_MIPS_SZLONG=32", "-D_MIPS_SZPTR=32")


MISSING_INCLUDE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+):\d+: fatal error: (?P<name>[^:\n]+): No such file",
                             re.M)
MAX_STANDINS = 40


def _inside_braces(path: Path, line: int) -> bool:
    """Whether line ``line`` of ``path`` stands inside braces (an initialiser), comments and
    literals left out."""
    try:
        text = COMMENT.sub(lambda found: re.sub(r"[^\n]", " ", found.group()), path.read_text(errors="replace"))
    except OSError:
        return False
    from .splitunit import blank_literals
    before = blank_literals("\n".join(text.split("\n")[:max(0, line - 1)]))
    return before.count("{") > before.count("}")


def preprocessed(source: Path, pipeline: str, flags: list[str], includes: list[Path],
                 standins: Path | None = None, used: list | None = None) -> str | None:
    """``source`` after the preprocessor, with what its compiler would have predefined; None
    when it does not go through.

    With ``standins`` (a directory), an included file that does not exist (a file the tree's
    own build would generate: converted text, an image as an array) is given a stand-in there:
    ``0`` where it is included inside an initialiser, nothing elsewhere.  A function never
    depends on the contents of another object's initialiser, which the split leaves out; a
    function that needs the real file fails to compile or compiles to other bytes, and the
    comparison with the title refuses it.  Each stand-in is appended to ``used``."""
    ido = pipeline.startswith(("ido", "custom:ido", "custom:mipspro"))
    search = [source.parent, *includes, *([standins] if standins else [])]
    # -std=gnu89: both compilers are C89 compilers and define no __STDC_VERSION__; a host
    # preprocessor's default (C17) makes headers that test it take their C99 branch (``bool`` as
    # ``_Bool``), which neither compiler accepts
    command = [os.environ.get("N64DK_CPP", "cpp"), "-P", "-nostdinc", "-undef", "-std=gnu89",
               *(IDO_PREDEFINED if ido else GCC_PREDEFINED),
               *[flag for flag in flags if flag.startswith(("-D", "-U"))],
               *[f"-I{path}" for path in search], str(source)]
    for _attempt in range(MAX_STANDINS + 1):
        try:
            from .. import safety
            done = safety.run_tool(command, kind="light", capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if done.returncode == 0:
            return done.stdout
        missing = MISSING_INCLUDE.search(done.stderr)
        if standins is None or missing is None:
            return None
        name = missing.group("name").strip()
        if name.startswith("/") or ".." in Path(name).parts:
            return None
        stand_in = standins / name
        if stand_in.exists():                                # already given: something else is wrong
            return None
        initialiser = _inside_braces(Path(missing.group("file")), int(missing.group("line")))
        stand_in.parent.mkdir(parents=True, exist_ok=True)
        stand_in.write_text("0\n" if initialiser else "/* stand-in: generated by the tree's own build */\n")
        if used is not None:
            used.append({"file": name, "in_initialiser": initialiser})
    return None


def split_units(tree: Tree, built: dict[str, Path], recipe_of, flags_of, includes: list[Path], root: Path, cfg,
                objects: Path, jobs: int = 4) -> tuple[list[tuple[str, str, list[str], Path]], dict]:
    """Write one source file per function of every unit of the tree under ``root`` and compile
    each (see ``n64dk.match.splitunit``).  Returns the donor rows and what was left out.

    A unit that did not compile whole (a generated header missing) is split all the same: its
    functions that do not need what is missing compile on their own.  ``root/order.json`` keeps
    the functions of each unit in source order, which places a function the title holds between
    two that were found."""
    import tempfile
    from . import splitunit
    from .pipeline import BuildError, build as compile_unit, split_flags
    todo, not_split, written = [], [], 0
    errors: dict[str, str] = {}
    order: dict[str, list[str]] = {}
    excluded: dict[str, dict[str, str]] = {}
    standins_used: dict[str, list] = {}
    standins = root.parent / "standins"
    for unit in sorted(tree.units):
        pipeline, flags = split_recipe(recipe_of(unit))[0], flags_of(unit)
        used: list = []
        text = preprocessed(tree.root / unit, pipeline, flags, includes, standins, used)
        if used:
            standins_used[unit] = used
        left_out: dict[str, str] = {}
        parts = splitunit.split(text, unit, left_out) if text else {}
        if left_out:
            excluded[unit] = left_out
        if not parts:
            not_split.append({"unit": unit, "reason": "preprocessing failed" if text is None else
                              "the configuration leaves no function in it" if not left_out else
                              "every function holds inline assembly"})
            continue
        order[unit] = list(parts)
        # the preprocessor has applied the macros and found the headers: neither is needed again
        plain = [flag for flag in flags if not flag.startswith(("-D", "-U", "-I"))]
        for label, source in parts.items():
            relative = f"{unit[:-2]}/{label}.c"
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            written += len(source)
            todo.append((relative, pipeline, plain))
    (root / "order.json").write_text(json.dumps({"order": order, "excluded": excluded, "standins": standins_used},
                                                indent=1) + "\n")

    def one(item):
        relative, pipeline, plain = item
        key = object_key(root / relative, pipeline, plain, cfg, [])
        target = objects / f"f{key}.o"
        if target.is_file():
            return relative, pipeline, plain, target
        try:
            with tempfile.TemporaryDirectory(prefix="n64dk-split-") as work:
                made = compile_unit(root / relative, split_flags(list(plain), pipeline), cfg, Path(work), includes=[])
                shutil.copyfile(made, target)
        except (BuildError, OSError, RuntimeError) as error:
            errors[relative] = str(error)[-600:]
            return relative, pipeline, plain, None
        return relative, pipeline, plain, target

    objects.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max(1, jobs)) as pool:
        done = list(pool.map(one, todo))
    rows = [row for row in done if row[3] is not None]
    failed = [row[0] for row in done if row[3] is None]
    for relative in failed:                                  # kept apart, for diagnosis, out of the donor
        kept = root.parent / "split_failed" / relative
        kept.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(root / relative), kept)
        kept.with_suffix(".err").write_text(errors.get(relative, ""))
    return rows, {"functions_written": len(todo), "functions_compiled": len(rows), "functions_not_compiled": len(failed),
                  "not_compiled": failed[:40], "units_not_split": not_split, "units_not_split_count": len(not_split),
                  "functions_excluded_inline_assembly": sum(len(v) for v in excluded.values()),
                  "units_given_standins": len(standins_used),
                  "standin_files": sorted({item["file"] for items in standins_used.values() for item in items}),
                  "split_source_bytes": written}


def build(tree: Tree, plan: dict, out: Path, name: str, cfg, signatures: dict | None = None,
          by_function: bool = True) -> dict:
    """Write the donor that ``plan`` (from ``calibrate``) describes.

    ``by_function`` (the default) gives the donor one unit per function, so that the stage that
    uses it can take each function of the tree for itself.  Without it the tree's own units are
    the donor's units, and a unit is taken only when all of it stands in the target; its data
    then comes with it."""
    builder: Builder = plan["builder"]
    recipe_of = lambda unit: plan["recipes"].get(unit, plan["majority"])   # noqa: E731
    built = builder.many(tree.units, recipe_of, plan["macros"])
    folder = Path(out) / name
    failed = [{"unit": unit, "error": builder.errors.get(unit, "")[-160:]} for unit in tree.units if unit not in built]
    tally: dict[str, int] = {}
    for unit in built:
        tally[recipe_of(unit)] = tally.get(recipe_of(unit), 0) + 1
    common = dict(units_in_tree=len(tree.units), compiled=len(built), failed_units=len(failed), failed=failed[:12],
                  units_by_recipe=tally)
    if by_function:
        root = folder / "split"
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(folder / "split_failed", ignore_errors=True)      # no failure kept from an earlier import
        rows, left_out = split_units(tree, built, recipe_of, lambda unit: builder.flags(recipe_of(unit), plan["macros"]),
                                     plan["includes"], root, cfg, builder.objects, builder.jobs)
        own = lambda relative, label: Path(relative).stem == label         # noqa: E731
        objects = {relative: target for relative, _p, _f, target in rows}
        found = found_in_target(objects, folder / "probe", cfg, signatures, own) if signatures is not None else {}
        shutil.rmtree(folder / "probe", ignore_errors=True)
        result = describe(folder, name, root, rows, [], cfg, f"source tree {tree.root.name}, one unit per function",
                          keep_objects=builder.objects, is_function=own, place_undefined=True)
        places = set().union(*found.values()) if found else set()
        result.update(common, **left_out, target_functions_found=len(places), builds=builder.builds)
        return result
    found = found_in_target(built, folder / "probe", cfg, signatures, tree.defines) if signatures is not None else {}
    shutil.rmtree(folder / "probe", ignore_errors=True)
    rows = [(unit, split_recipe(recipe_of(unit))[0], builder.flags(recipe_of(unit), plan["macros"]), target)
            for unit, target in sorted(built.items())]
    result = describe(folder, name, tree.root, rows, plan["includes"], cfg,
                      f"source tree {tree.root.name}", keep_objects=builder.objects, is_function=tree.defines,
                      place_undefined=True)
    places = set().union(*found.values()) if found else set()
    result.update(common, units_found_in_target=sum(1 for places_ in found.values() if places_),
                  target_functions_found=len(places), builds=builder.builds)
    return result
