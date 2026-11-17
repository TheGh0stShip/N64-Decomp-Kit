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


# Diagnostics are matched for both compiler families: GCC prints ``file:LINE: message``, IDO's
# front end prints ``cfe: Error: file, line LINE: message`` followed by the source line and a caret.
_LINE = r"(?::|, line )(\d+): "
_UNDECLARED = re.compile(_LINE + r"(?:`(\w+)' undeclared|'(\w+)' undefined)")
_UNARY = re.compile(_LINE + r"(?:invalid type argument of `unary \*'|Dereferenced a non-pointer)")
_VOID_VALUE = re.compile(_LINE + r"void value not ignored")
_VOID_ARITHMETIC = re.compile(_LINE + r"(?:Unacceptable operand of '[-+]'|Bad operand type for \+= or -=)")
_ARGUMENT_COUNT = re.compile(_LINE + r"(?:(?:The n|N)umber of arguments doesn't agree with the number in the declaration|"
                             r"too (?:few|many) arguments to function)")
_REDECLARED = re.compile(_LINE + r"redeclaration of [`'](\w+)'")
_VOID_DEREFERENCE = re.compile(_LINE + r"(?:warning: dereferencing `void \*' pointer|"
                               r"Reference of an expression of void type or an incomplete type)")
_POINTER_INTEGER = re.compile(_LINE + r"illegal combination of pointer and integer")
_NOT_CALLABLE = re.compile(_LINE + r"(?:Non-function name referenced in function call|called object is not a function)")
_STARRED_CALL = re.compile(r"(?<![\w)\]])(\*+)((?!M2C_)[A-Za-z_]\w*)\(")
_STARRED_NAME = re.compile(r"(?<![\w)\]*])\*([A-Za-z_]\w*)\b(?!\s*\()")
_INTEGER_MINUS_ADDRESS = re.compile(r"((?:\b0x[0-9A-Fa-f]+|\b\w+|\)))(\s*-\s*)&(\w+)")
_POINTER_COMPARE = re.compile(_LINE + r"Unacceptable operand of == or !=")
_NULL_TO_INTEGER = re.compile(_LINE + r"Constants must have arithmetic type")
_DEREF = re.compile(r"(?<![\w)\]])\*\(")
# a definition starts in column 0: an indented ``if (...) {`` is a nested block, not a body
_BODY = re.compile(r"(?m)^[A-Za-z_][\w \*]*\([^;{}]*\)\s*\{\n")
_IDENT = re.compile(r"[A-Za-z_]\w*")


def _closing(text: str, opening: int) -> int | None:
    """Index of the parenthesis that closes the one at ``opening``, or None."""
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def call_through_loaded_pointer(line: str) -> str:
    """``*M2C_FIELD(p, T (***)(...), n)(args)`` -> ``(*M2C_FIELD(p, T (***)(...), n))(args)``.

    A call binds tighter than ``*``, so the decompiler's rendering of a call through a function
    pointer loaded from a table (a virtual call: object -> table -> function) calls the table
    itself.  Parenthesising the dereference is what the instructions do."""
    at = 0
    while True:
        at = line.find("*M2C_FIELD(", at)
        if at < 0:
            return line
        end = _closing(line, at + len("*M2C_FIELD"))
        if end is not None and line[end + 1:].lstrip().startswith("("):
            line = line[:at] + "(" + line[at:end + 1] + ")" + line[end + 1:]
            at = end + 2
        else:
            at += 1


def call_through_dereference(line: str) -> str:
    """``*(table + i)(args)`` -> ``((s32 (*)()) *(table + i))(args)``: a function pointer read from
    a computed address and called."""
    at = 0
    while True:
        found = _DEREF.search(line, at)
        if found is None:
            return line
        start = found.start()
        end = _closing(line, start + 1)
        if end is not None and line[end + 1:].lstrip().startswith("("):
            line = line[:start] + "((s32 (*)()) " + line[start:end + 1] + ")" + line[end + 1:]
            at = end + len("((s32 (*)()) ") + 2
        else:
            at = start + 1


def repair(source: str, error: str) -> str | None:
    """One mechanical fix for a compiler diagnostic (GCC or IDO) on an m2c draft, or None.

    * an undeclared ``spXX``/temporary gets an ``s32`` declaration at the top of the body;
    * a dereference of an integer expression on the reported line gets an ``(s32 *)`` cast;
    * a callee declared ``void`` whose value is used becomes ``s32``;
    * arithmetic on a ``void *`` (an extension IDO rejects) retypes that variable ``s8 *``,
      which keeps the byte-wise arithmetic the draft meant;
    * a call through a function-pointer cast, or to a callee, whose argument count disagrees
      with a guessed prototype makes that prototype unprototyped;
    * an assignment mixing pointer and integer casts the right-hand side to the target's type.
    * a call through a function pointer loaded from a table is parenthesised so the dereference
      happens before the call;
    * an integer constant minus the address of a symbol casts the address to an integer.
    These make the draft compile so it can be scored; types still need a human or model."""
    lines = source.split("\n")

    def line_of(found) -> int | None:
        number = int(found.group(1)) - 1
        return number if 0 <= number < len(lines) else None

    found = _UNDECLARED.search(error)
    if found:
        body = list(_BODY.finditer(source))
        if not body:
            return None
        at = body[-1].end()
        return source[:at] + f"    s32 {found.group(2) or found.group(3)};\n" + source[at:]
    found = _UNARY.search(error)
    if found and line_of(found) is not None:
        number = line_of(found)
        fixed = _DEREF.sub("*(s32 *)(", lines[number])
        if fixed == lines[number]:
            # ``*name`` where the draft declared ``name`` as an integer: it holds an address
            def as_pointer(found_name):
                name = found_name.group(1)
                declared = re.search(rf"(?m)^\s+(?:s8|u8|s16|u16|s32|u32|M2C_UNK)\s+{re.escape(name)}\s*[;=]", source)
                parameter = re.search(rf"[(,]\s*(?:s8|u8|s16|u16|s32|u32|M2C_UNK)\s+{re.escape(name)}\s*[,)]", source)
                return f"*(s32 *){name}" if declared or parameter else found_name.group(0)
            fixed = _STARRED_NAME.sub(as_pointer, lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
    found = _VOID_VALUE.search(error)
    if found and line_of(found) is not None:
        for callee in re.findall(r"\b(\w+)\(", lines[line_of(found)]):
            changed = re.sub(rf"(?m)^void ({re.escape(callee)}\(\);)", r"s32 \1", source)
            if changed != source:
                return changed
    found = _REDECLARED.search(error)
    if found and line_of(found) is not None:
        # a decompiler declares one stack slot twice when it is used with two types: the later
        # declaration goes, the first one stands
        number = line_of(found)
        if re.fullmatch(rf"\s*(?:[A-Za-z_]\w*[\s\*]+)+{re.escape(found.group(2))}\s*(?:\[[^\]]*\])*\s*;\s*",
                        lines[number]):
            del lines[number]
            return "\n".join(lines)
    found = _VOID_DEREFERENCE.search(error) or _VOID_VALUE.search(error)
    if found and line_of(found) is not None and "*(void *)" in lines[line_of(found)]:
        # a word read through a ``void *`` cast (a hardware register, an absolute address)
        lines[line_of(found)] = lines[line_of(found)].replace("*(void *)", "*(s32 *)")
        return "\n".join(lines)
    found = _VOID_DEREFERENCE.search(error)
    if found and line_of(found) is not None:
        # ``*p`` with ``void *p``: the draft meant a word
        for name in dict.fromkeys(_IDENT.findall(lines[line_of(found)])):
            changed = re.sub(rf"\bvoid \*(?=\s*{re.escape(name)}\b\s*[;,)=])", "s32 *", source)
            if changed != source:
                return changed
    found = _VOID_ARITHMETIC.search(error)
    if found and line_of(found) is not None:
        for name in dict.fromkeys(_IDENT.findall(lines[line_of(found)])):
            changed = re.sub(rf"\bvoid \*(?=\s*{re.escape(name)}\b\s*[;,)=])", "s8 *", source)
            if changed != source:
                return changed
        # ``M2C_FIELD(p, void **, n) + i``: arithmetic on a loaded ``void *`` is byte arithmetic
        number = line_of(found)
        fixed = re.sub(r"\bvoid \*\*(?=\s*,)", "s8 **", lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
        # ``CONSTANT - &symbol``: an integer minus an address is integer arithmetic on the address
        number = line_of(found)
        fixed = _INTEGER_MINUS_ADDRESS.sub(r"\1\2(s32) &\3", lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
    found = _NOT_CALLABLE.search(error)
    if found and line_of(found) is not None:
        number = line_of(found)
        fixed = call_through_loaded_pointer(lines[number])
        if fixed == lines[number]:
            # ``**p(args)``: the same precedence slip on a plain variable.  The loaded value is
            # called, whatever type the draft gave the variable.
            fixed = _STARRED_CALL.sub(r"((s32 (*)()) \1\2)(", lines[number])
        if fixed == lines[number]:
            fixed = call_through_dereference(lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
    found = _ARGUMENT_COUNT.search(error)
    if found and line_of(found) is not None:
        number = line_of(found)
        # a guessed prototype inside a function-pointer cast, at any depth of indirection
        fixed = re.sub(r"\((\*+)\)\([^()]+\)", r"(\1)()", lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
        for callee in re.findall(r"\b(\w+)\(", lines[number]):
            # a declaration starts in column 0; an indented ``callee(a, b);`` is the call itself
            changed = re.sub(rf"(?m)^([A-Za-z_][\w \*]*?\b{re.escape(callee)})\([^;{{}}()]+\);", r"\1();", source)
            if changed != source:
                return changed
        # no declaration to relax: the compiler's own prototype of a built-in (memcpy, strlen, ...)
        # is in force.  Calling through a cast keeps the direct call and drops that prototype.
        named = re.search(r"arguments to function [`'](\w+)'", error)
        if named and not re.search(rf"(?m)^[A-Za-z_][\w \*]*?\b{re.escape(named.group(1))}\s*\(", source):
            fixed = re.sub(rf"(?<![\w)]){re.escape(named.group(1))}\(", f"((s32 (*)()) {named.group(1)})(", lines[number])
            if fixed != lines[number]:
                lines[number] = fixed
                return "\n".join(lines)
    found = _POINTER_COMPARE.search(error)
    if found and line_of(found) is not None:
        # a pointer compared with an integer (IDO rejects it): the comparison is of the address
        number = line_of(found)
        fixed = lines[number]
        for name in dict.fromkeys(_IDENT.findall(lines[number])):
            if not re.search(rf"\*\s*{re.escape(name)}\s*[;,)=]", source):
                continue                                     # not declared as a pointer
            fixed = re.sub(rf"(?<![\w.>])(?<!\(s32\) ){re.escape(name)}\b(?=\s*(?:==|!=))", f"(s32) {name}", fixed)
            fixed = re.sub(rf"((?:==|!=)\s*)(?<!\(s32\) ){re.escape(name)}\b(?![\w(\[.]|\s*->)", rf"\1(s32) {name}", fixed)
        if fixed == lines[number]:                           # an address expression on one side
            fixed = re.sub(r"(?<!\(s32\) )(?<![\w)\]&])&(?=[A-Za-z_])", "(s32) &", lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
    found = _NULL_TO_INTEGER.search(error)
    if found and line_of(found) is not None:
        number = line_of(found)
        fixed = re.sub(r"=\s*NULL\s*;", "= 0;", lines[number])
        if fixed != lines[number]:
            lines[number] = fixed
            return "\n".join(lines)
    found = _POINTER_INTEGER.search(error)
    if found and line_of(found) is not None:
        number = line_of(found)
        assignment = re.match(r"^(\s*)([A-Za-z_]\w*) = (.+);\s*$", lines[number])
        if assignment:
            declared = re.search(rf"(?m)^\s+([\w ]+?\s*\**)\s*{re.escape(assignment.group(2))}\s*;", source)
            if declared and not assignment.group(3).startswith(f"({declared.group(1).strip()})"):
                lines[number] = (f"{assignment.group(1)}{assignment.group(2)} = "
                                 f"({declared.group(1).strip()}) ({assignment.group(3)});")
                return "\n".join(lines)
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


# A top-level declaration: no indentation (statements inside a function body are indented in a
# decompiler draft), at least one type word before the name.
_TOP_DECLARATION = re.compile(r"^(?:extern\s+|static\s+)?(?:(?:const|volatile|unsigned|signed|struct|union|enum)\s+)*"
                              r"[A-Za-z_]\w*(?:\s+|\s*\*+\s*)(?:\*+\s*)?(\w+)\s*(?:\([^{]*\)|\[[^\]]*\])?\s*;")
_DECLARED_NAMES = re.compile(r"(?m)^(?:extern\s+|static\s+)?[\w \*]+?\b(\w+)\s*(?:\(|\[|;)")


def drop_redeclared(draft_body: str, declarations: str) -> str:
    """The draft's own top-level guesses for names ``declarations`` declares, removed; nothing
    inside a function body is touched (a call statement ``f();`` is not a declaration)."""
    declared = set(_DECLARED_NAMES.findall(declarations))
    kept = []
    for line in draft_body.split("\n"):
        found = _TOP_DECLARATION.match(line)
        if found and found.group(1) in declared and "{" not in line:
            continue
        kept.append(line)
    return "\n".join(kept)


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
