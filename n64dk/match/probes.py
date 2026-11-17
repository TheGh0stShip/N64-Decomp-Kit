"""Synthetic probes: small C functions that each isolate one code-generation feature, built
under every runnable recipe, to fingerprint recipes stage by stage.

Each probe is one translation unit with one function ``probe`` (plus declarations).  Built
under a recipe and flag set, the function's ``.text`` (relocated fields masked, padding
stripped) is hashed.  From the table of hashes:

* **determinism** — every probe is built twice; a recipe whose two builds differ is not
  deterministic and cannot be fingerprinted;
* **equivalence classes** — recipes that give the same bytes for every probe cannot be told
  apart by code and need not both be tried;
* **stage attribution** — two recipes that share every stage but one (``components.
  shared_stages``) differ only through that stage: the probes they disagree on are that stage's
  fingerprint (e.g. ``kmc+as`` against ``kmc+asn64``: the assembler);
* **line attribution** — pairs of probes with identical tokens laid out on different lines show
  whether a recipe's output depends on line structure (debug line records can move code).
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import time
from pathlib import Path

PRELUDE = ("typedef signed char s8; typedef unsigned char u8; typedef short s16; typedef unsigned short u16;\n"
           "typedef int s32; typedef unsigned int u32; typedef float f32; typedef double f64;\n")

# name -> (feature, body).  Every body defines ``probe``; externs are declared in it.
PROBES: dict[str, tuple[str, str]] = {
    "load_s8": ("scalar types: signed byte load", "s32 probe(s8 *p) { return *p + 1; }"),
    "load_u8": ("scalar types: unsigned byte load", "s32 probe(u8 *p) { return *p + 1; }"),
    "load_s16": ("scalar types: signed half load", "s32 probe(s16 *p) { return p[3] * 2; }"),
    "narrow_arg": ("signedness: narrow argument", "s32 probe(s16 a, u8 b) { return a + b; }"),
    "ptr_arith": ("pointer arithmetic", "s32 *probe(s32 *p, s32 i) { return p + i * 3 + 1; }"),
    "struct_rw": ("structures: field read and write",
                  "struct S { s32 a; s16 b; u8 c; f32 d; };\nvoid probe(struct S *s) { s->b = s->a; s->c++; s->d = 0.5f; }"),
    "array_loop": ("arrays and a counted loop",
                   "s32 probe(s32 *a, s32 n) { s32 i, t = 0; for (i = 0; i < n; i++) t += a[i]; return t; }"),
    "while_loop": ("loops: while with pointer walk", "s32 probe(u8 *s) { s32 n = 0; while (*s++) n++; return n; }"),
    "do_loop": ("loops: do-while", "void probe(s32 *a, s32 n) { do { *a++ = 0; } while (--n); }"),
    "switch_dense": ("switch: dense (jump table)",
                     "s32 probe(s32 x) { switch (x) { case 0: return 5; case 1: return 9; case 2: return 2; "
                     "case 3: return 7; case 4: return 1; case 5: return 3; default: return 0; } }"),
    "switch_sparse": ("switch: sparse (compare chain)",
                      "s32 probe(s32 x) { switch (x) { case 3: return 1; case 100: return 2; case 4000: return 3; "
                      "default: return 0; } }"),
    "calls": ("calls with arguments", "extern s32 f(s32, s32);\ns32 probe(s32 a) { return f(a, 1) + f(2, a); }"),
    "stack_args": ("calls: stack arguments",
                   "extern s32 g(s32, s32, s32, s32, s32, s32);\ns32 probe(s32 a) { return g(a, 1, 2, 3, 4, 5); }"),
    "tail_call": ("calls: tail position", "extern s32 h(s32);\ns32 probe(s32 a) { return h(a + 1); }"),
    "float_ops": ("floating point arithmetic", "f32 probe(f32 a, f32 b) { return a * b + 2.0f; }"),
    "float_cmp": ("floating point compare", "s32 probe(f32 a, f32 b) { return a < b ? 1 : 2; }"),
    "double_ops": ("double arithmetic", "f64 probe(f64 a) { return a * 3.0 - 1.0; }"),
    "int_to_float": ("conversion int to float", "f32 probe(s32 a) { return (f32)a * 0.25f; }"),
    "float_to_int": ("conversion float to int", "s32 probe(f32 a) { return (s32)a + 1; }"),
    "div_const": ("division by constant", "s32 probe(s32 a) { return a / 10; }"),
    "div_var": ("division by variable", "s32 probe(s32 a, s32 b) { return a / b + a % b; }"),
    "udiv": ("unsigned division", "u32 probe(u32 a, u32 b) { return a / b; }"),
    "mul_const": ("multiplication by constant", "s32 probe(s32 a) { return a * 12; }"),
    "mul_var": ("multiplication by variable", "s32 probe(s32 a, s32 b) { return a * b; }"),
    "volatile_rw": ("volatile access", "extern volatile s32 reg;\nvoid probe(void) { reg = 1; reg = reg + 1; }"),
    "static_data": ("static data", "static s32 counter;\ns32 probe(void) { return ++counter; }"),
    "rodata_string": ("rodata: string literal", "extern void puts(const char *);\nvoid probe(void) { puts(\"probe\"); }"),
    "rodata_float": ("rodata: float literal", "f32 probe(f32 a) { return a * 3.14159f; }"),
    "global_rw": ("global read and write", "extern s32 gA, gB;\nvoid probe(void) { gA = gB + 1; }"),
    "bitfield": ("bit operations", "u32 probe(u32 a) { return (a >> 3) & 0x1F | (a << 5); }"),
    "branch_likely": ("branches in a loop", "s32 probe(s32 *a, s32 n) { s32 m = 0; while (n--) { if (*a > m) m = *a; a++; } return m; }"),
    "frame_locals": ("stack frame with locals and a call",
                     "extern void use(s32 *);\ns32 probe(s32 a) { s32 buf[4]; buf[0] = a; use(buf); return buf[1]; }"),
    "macro_expand": ("macro expansion",
                     "#define SQR(x) ((x) * (x))\n#define CLAMP(x, l, h) ((x) < (l) ? (l) : (x) > (h) ? (h) : (x))\n"
                     "s32 probe(s32 a) { return CLAMP(SQR(a), 0, 100); }"),
    # identical tokens, different lines
    "lines_one": ("line attribution: one line",
                  "extern s32 gA, gB;\ns32 probe(s32 a) { s32 t = a + gA; gB = t * 2; return t - gB; }"),
    "lines_many": ("line attribution: one statement per line",
                   "extern s32 gA, gB;\ns32 probe(s32 a)\n{\n    s32 t = a + gA;\n\n    gB = t * 2;\n\n\n"
                   "    return t - gB;\n}"),
}

# lane -> flag sets probed (the usual retail settings)
# IDO always with the retail fixed flags (engine.IDO_FIXED): without -non_shared IDO emits
# position-independent code no N64 title contains.
_IDO_FIXED = ("-non_shared", "-Xcpluscomm", "-Wab,-r4300_mul")
FLAG_SETS: dict[str, tuple[tuple[str, ...], ...]] = {
    "ido5.3": (("-O2", "-mips2", "-G", "0", *_IDO_FIXED), ("-g", "-mips2", "-G", "0", *_IDO_FIXED),
               ("-O1", "-mips2", "-G", "0", *_IDO_FIXED), ("-g", "-mips1", "-G", "0", *_IDO_FIXED)),
    "ido7.1": (("-O2", "-mips2", "-G", "0", *_IDO_FIXED), ("-g", "-mips2", "-G", "0", *_IDO_FIXED)),
    "kmc+as": (("-O2", "-G0", "-mips3", "-mgp32", "-mfp32"), ("-O1", "-G0", "-mips3", "-mgp32", "-mfp32"),
               ("-O2", "-G0", "-mips2", "-mgp32", "-mfp32"), ("-O0", "-G0", "-mips3", "-mgp32", "-mfp32")),
    "kmc+asn64": (("-O2", "-G0", "-mips3", "-mgp32", "-mfp32"),),
    "sn": (("-O2", "-G0", "-mips3", "-mgp32", "-mfp32"),),
}


def probe_source(name: str) -> str:
    return PRELUDE + PROBES[name][1] + "\n"


def masked_text(object_path: Path, function: str = "probe") -> str | None:
    """SHA-256 of the function's masked, padding-stripped code; None when it is absent."""
    from ..elf import Elf
    from .transplant import mask, strip_padding
    elf = Elf.load(object_path)
    text = next((section for section in elf.sections if section.name == ".text"), None)
    symbol = next((sym for sym in elf.symbols if sym.name == function and 0 < sym.section < len(elf.sections)
                   and elf.sections[sym.section].name == ".text"), None)
    if text is None or symbol is None:
        return None
    size = symbol.size or (len(text.data) - symbol.value)
    code = strip_padding(text.data[symbol.value:symbol.value + size])
    masked, _ = mask(code, 0x80000000)
    return hashlib.sha256(b"".join(word.to_bytes(4, "big") for word in masked)).hexdigest()[:16] + f":{len(code)}"


def lanes_to_probe(root: Path) -> dict[str, tuple[tuple[str, ...], ...]]:
    """Built-in lanes with their flag sets, plus every installed configured lane with its
    default flags and usual settings."""
    from . import compilers
    out = dict(FLAG_SETS)
    for name, table in compilers.project_pipelines(root).items():
        sets = [tuple(table["default_flags"])] + [tuple(flags) for flags in table.get("flag_sets", [])][:2]
        out[f"custom:{name}"] = tuple(sets)
    return out


def run(root: Path, work: Path, probes: list[str] | None = None, lanes: list[str] | None = None,
        repeat: int = 2, emit=None) -> dict:
    """Build every probe under every lane and flag set (``repeat`` times) and fingerprint."""
    from . import compilers
    from .pipeline import BuildError, build, split_flags
    from .toolchain import load_config
    emit = emit or (lambda *_a, **_k: None)
    work = Path(work)
    # one project (and so one object cache) per repetition: a repeated build must really run
    configs = []
    for attempt in range(max(1, repeat)):
        project = work / f"project{attempt}"
        project.mkdir(parents=True, exist_ok=True)
        (project / "n64dk.toml").write_text(f'[toolchains]\nroot = "{root}"\n\n'
                                            + compilers.toml_tables(compilers.project_pipelines(root)))
        configs.append(load_config(project, None, str(root)))
    names = probes or list(PROBES)
    plan = lanes_to_probe(root)
    if lanes:
        plan = {lane: sets for lane, sets in plan.items() if lane in lanes}
    sources = work / "src"
    sources.mkdir(exist_ok=True)
    for name in names:
        (sources / f"{name}.c").write_text(probe_source(name))
    table: dict[str, dict[str, str | None]] = {}
    errors: dict[str, dict[str, str]] = {}
    nondeterministic: dict[str, list[str]] = {}
    started = time.time()
    for lane, sets in plan.items():
        for flags in sets:
            key = f"{lane} {' '.join(flags)}"
            row, failed, unstable = {}, {}, []
            for name in names:
                results = []
                for attempt in range(repeat):
                    with tempfile.TemporaryDirectory(prefix="n64dk-probe-", dir=work) as scratch:
                        try:
                            built = build(sources / f"{name}.c", split_flags(list(flags), lane), configs[attempt],
                                          Path(scratch), includes=[])
                            results.append(masked_text(built))
                        except (BuildError, OSError, ValueError, RuntimeError) as error:
                            results.append(None)
                            failed[name] = str(error)[:200]
                if len(set(results)) > 1:
                    unstable.append(name)
                row[name] = results[0]
            table[key] = row
            if failed:
                errors[key] = failed
            if unstable:
                nondeterministic[key] = unstable
            emit("recipe", recipe=key, built=sum(1 for value in row.values() if value), failed=len(failed),
                 nondeterministic=len(unstable), seconds=round(time.time() - started))
    return {"probes": {name: PROBES[name][0] for name in names}, "table": table, "errors": errors,
            "nondeterministic": nondeterministic, **analyse(table), "seconds": round(time.time() - started, 1)}


def analyse(table: dict[str, dict[str, str | None]]) -> dict:
    """Equivalence classes, pairwise distances and line-attribution findings from a probe table."""
    from . import components
    recipes = sorted(table)
    usable = [key for key in recipes if sum(1 for value in table[key].values() if value) >= len(table[key]) // 2]
    vector = {key: tuple(table[key].get(name) for name in sorted(table[key])) for key in usable}
    classes: dict[tuple, list[str]] = {}
    for key in usable:
        classes.setdefault(vector[key], []).append(key)
    distance = {}
    for i, a in enumerate(usable):
        for b in usable[i + 1:]:
            both = [name for name in table[a] if table[a].get(name) and table[b].get(name)]
            differ = [name for name in both if table[a][name] != table[b][name]]
            distance[f"{a} | {b}"] = {"compared": len(both), "differ": len(differ), "probes": differ}
    # stage attribution: lanes whose recipes share all but some stages, same flags
    attribution = []
    for pair, found in distance.items():
        a, b = pair.split(" | ")
        lane_a, flags_a = a.split(" ", 1)
        lane_b, flags_b = b.split(" ", 1)
        if flags_a != flags_b or lane_a not in components.RECIPES or lane_b not in components.RECIPES:
            continue
        shared = components.shared_stages(lane_a, lane_b)
        attribution.append({"recipes": [a, b], "differing_stages": [row["stage"] for row in shared["different"]],
                            "components": shared["different"], "probes_differ": found["differ"],
                            "of": found["compared"], "probes": found["probes"]})
    lines = {key: (table[key].get("lines_one") is not None and table[key].get("lines_many") is not None
                   and table[key]["lines_one"] != table[key]["lines_many"])
             for key in recipes if "lines_one" in table[key]}
    return {"equivalence_classes": [sorted(members) for members in classes.values()],
            "distinct_recipes": len(classes), "usable_recipes": len(usable),
            "distance": distance, "stage_attribution": attribution,
            "line_layout_changes_code": {key: value for key, value in lines.items()}}
