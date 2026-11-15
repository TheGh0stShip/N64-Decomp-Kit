"""Unattended first pass over unmatched functions: draft, compile, compare, rank.

For every function without source this runs ``m2c`` on the retail bytes, builds the draft with
the project's real pipeline and compares it relocated against the ROM.  The outcome is a
ranked worklist: drafts that are already exact, drafts that compile with a small residual
(with the specific hints for that residual), drafts that need a compile fix, and functions
m2c could not lift.  Nothing is written into the project; exact drafts are candidates to be
re-verified and integrated through the normal winner path, and m2c-styled source should be
cleaned before it is kept.
"""
from __future__ import annotations

import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import m2c_bridge
from .hints import hints as residual_hints
from .score import score as community_score

PRELUDE = """\
#ifndef N64DK_M2C_PRELUDE
#define N64DK_M2C_PRELUDE
typedef signed char s8; typedef unsigned char u8; typedef signed short s16; typedef unsigned short u16;
typedef signed int s32; typedef unsigned int u32; typedef signed long long s64; typedef unsigned long long u64;
typedef float f32; typedef double f64;
typedef s32 M2C_UNK; typedef s8 M2C_UNK8; typedef s16 M2C_UNK16; typedef s32 M2C_UNK32; typedef s64 M2C_UNK64;
#define M2C_FIELD(expr, type_ptr, offset) (*(type_ptr)((s8 *)(expr) + (offset)))
#define M2C_BITWISE(type, expr) ((type)(expr))
/* unhandled instructions become calls to an unprototyped function: any argument list compiles */
extern s32 m2c_unhandled();
#define M2C_ERROR m2c_unhandled
#define M2C_TRAP_IF m2c_unhandled
#define M2C_BREAK m2c_unhandled
#define M2C_LWL(expr) (expr)
#define M2C_FIRST3BYTES(expr) (expr)
#define M2C_UNALIGNED32(expr) (expr)
#define MULT_HI(a, b) ((s32)(((s64)(a) * (s64)(b)) >> 32))
#define MULTU_HI(a, b) ((u32)(((u64)(a) * (u64)(b)) >> 32))
#define M2C_CARRY 0
#ifndef NULL
#define NULL ((void *)0)
#endif
#endif
"""
_BAD_TYPE = re.compile(r"(?<![\w?])\?(?![\w?])")           # m2c's unknown type marker


_UNDECLARED = re.compile(r":(\d+): `(\w+)' undeclared")
_UNARY = re.compile(r":(\d+): invalid type argument of `unary \*'")
_VOID_VALUE = re.compile(r":(\d+): void value not ignored")
_DEREF = re.compile(r"(?<![\w)\]])\*\(")
_BODY = re.compile(r"(?m)^[\w \*]+\([^;{}]*\)\s*\{\n")


def repair(source: str, error: str) -> str | None:
    """One mechanical fix for a compiler diagnostic on an m2c draft, or None.

    * an undeclared ``spXX``/temporary gets an ``s32`` declaration at the top of the body;
    * a dereference of an integer expression on the reported line gets an ``(s32 *)`` cast;
    * a callee declared ``void`` whose value is used becomes ``s32``.
    These make the draft compile so it can be scored; types still need a human or model."""
    lines = source.split("\n")
    found = _UNDECLARED.search(error)
    if found:
        body = list(_BODY.finditer(source))
        if not body:
            return None
        at = body[-1].end()
        return source[:at] + f"    s32 {found.group(2)};\n" + source[at:]
    found = _UNARY.search(error)
    if found and 0 < int(found.group(1)) <= len(lines):
        number = int(found.group(1)) - 1
        fixed = _DEREF.sub("*(s32 *)(", lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
    found = _VOID_VALUE.search(error)
    if found and 0 < int(found.group(1)) <= len(lines):
        for callee in re.findall(r"\b(\w+)\(", lines[int(found.group(1)) - 1]):
            changed = re.sub(rf"(?m)^void ({re.escape(callee)}\(\);)", r"s32 \1", source)
            if changed != source:
                return changed
    return None


@dataclass
class Draft:
    name: str
    vram: int
    size: int
    status: str = "pending"      # exact | compiled | compile-error | m2c-error | skipped
    score: int | None = None
    counts: dict = field(default_factory=dict)
    asm_score: dict = field(default_factory=dict)
    hints: list[str] = field(default_factory=list)
    error: str | None = None
    source_path: str | None = None
    jump_tables: int = 0
    repairs: int = 0

    def as_dict(self) -> dict:
        out = {"name": self.name, "vram": f"0x{self.vram:08X}", "size": self.size, "status": self.status}
        for key in ("score", "counts", "asm_score", "hints", "error", "source_path", "repairs"):
            if getattr(self, key):
                out[key] = getattr(self, key)
        if self.score == 0 and self.status != "exact":
            out["score"] = 0
        return out


_EXTERN_PROTO = re.compile(r"(?m)^([\w \*]+?\b\w+)\([^;{}]*\);(\s*/\* (?:extern|static) \*/)")


def prepare(source: str) -> str:
    """Make an m2c ``--valid-syntax`` draft a self-contained C89 file.

    m2c guesses each callee's prototype from one call site, so two calls with different
    argument counts fail to compile; callee declarations are therefore made unprototyped
    (``T f();``), which the real prototype replaces once it is known."""
    source = _EXTERN_PROTO.sub(lambda m: f"{m.group(1)}();{m.group(2)}", source)
    return PRELUDE + "\n" + _BAD_TYPE.sub("s32", source)


def draft_one(name: str, vram: int, size: int, code: bytes, read_word, evaluate, out_dir: Path,
              compiler: str = "kmc", context: Path | None = None, names: dict[int, str] | None = None,
              family: str = "gcc", max_size: int = 0x1000,
              max_repairs: int = 12, image: bytes | None = None,
              image_vram: int | None = None) -> Draft:
    """``evaluate(path, vram, size) -> Outcome`` is the project's build+compare (``match_source``
    bound to its spec/config/target)."""
    row = Draft(name, vram, size)
    if size > max_size or size < 8:
        row.status, row.error = "skipped", "size outside the draft range"
        return row
    # The shared function analyser needs the containing image so it can read table words.
    # A direct caller may omit it; the draft remains useful but switch recovery is disabled.
    tables = (m2c_bridge.find_jump_tables(image, image_vram, vram, size)
              if image is not None and image_vram is not None else [])
    row.jump_tables = len(tables)
    result = m2c_bridge.draft(name, code, vram, compiler, context, names, tables)
    (out_dir / f"{name}.s").write_text(result["asm"])
    if result["error"]:
        row.status, row.error = "m2c-error", result["error"][-300:]
        return row
    path = out_dir / f"{name}.c"
    source = prepare(result["source"])
    outcome = None
    for _attempt in range(max_repairs + 1):
        path.write_text(source)
        row.source_path = str(path)
        try:
            outcome = evaluate(path, vram, size)
            failure = outcome.error if (outcome.error or outcome.result is None) else None
            if outcome.result is None and not failure:
                failure = "no comparison"
        except Exception as error:                           # build failures are data here
            outcome, failure = None, str(error)
        if not failure:
            break
        fixed = repair(source, failure)
        if fixed is None or fixed == source:
            row.status, row.error = "compile-error", failure[-300:]
            return row
        source, row.repairs = fixed, row.repairs + 1
    else:
        row.status, row.error = "compile-error", failure[-300:]
        return row
    report = outcome.result.diff
    row.status = "exact" if outcome.exact else "compiled"
    if outcome.result.compiled_text:
        # MatchEngine may retain assembler alignment beyond the function-owned interval.
        # The community scorer has no ownership model, so compare exactly the same byte
        # range as the typed matcher.  Otherwise a byte-exact 8-byte leaf can misleadingly
        # receive insertion penalties for harmless trailing alignment.
        row.asm_score = community_score(code, outcome.result.compiled_text[:size], vram).as_dict()
    if report is not None:
        row.score, row.counts = report.score, dict(report.counts)
        row.hints = [h["hint"] for h in residual_hints(report, family)][:6]
    elif outcome.exact:
        row.score = 0
    return row


def sweep(functions: list[tuple[str, int, int]], image: bytes, vram_delta: int, evaluate, out_dir: Path,
          jobs: int = 8, **options) -> dict:
    """``functions`` are (name, vram, size) of unmatched code inside ``image`` (file offset =
    vram - vram_delta).  Returns a summary and rows ranked best first."""
    out_dir.mkdir(parents=True, exist_ok=True)

    def read_word(address: int):
        off = address - vram_delta
        return int.from_bytes(image[off:off + 4], "big") if 0 <= off <= len(image) - 4 else None

    def one(item):
        name, vram, size = item
        off = vram - vram_delta
        if off < 0 or off + size > len(image):
            return Draft(name, vram, size, status="skipped",
                         error="interval is outside the loaded image")
        return draft_one(name, vram, size, image[off:off + size], read_word, evaluate, out_dir,
                         image=image, image_vram=vram_delta, **options)

    with ThreadPoolExecutor(max(1, jobs)) as pool:
        rows = list(pool.map(one, functions))
    order = {"exact": 0, "compiled": 1, "compile-error": 2, "m2c-error": 3, "skipped": 4}
    rows.sort(key=lambda r: (order[r.status], r.score if r.score is not None else 1 << 30, r.size))
    summary: dict = {"functions": len(rows)}
    for row in rows:
        summary[row.status] = summary.get(row.status, 0) + 1
    summary["exact_bytes"] = sum(r.size for r in rows if r.status == "exact")
    summary["near_bytes"] = sum(r.size for r in rows if r.status == "compiled" and (r.score or 0) <= 10)
    return {"summary": summary, "rows": [r.as_dict() for r in rows]}


def temporary_workdir() -> tempfile.TemporaryDirectory:
    return tempfile.TemporaryDirectory(prefix="n64dk-autodraft-")
