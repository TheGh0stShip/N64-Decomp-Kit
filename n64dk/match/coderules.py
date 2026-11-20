"""Code rules for matching-decompilation source: which byte-identical functions count as matched.

Identical bytes prove that a source is faithful; they do not prove that it is the source.  A
dummy local, a ``volatile`` carrier, an empty block or an offset cast can all steer a compiler to
the retail bytes without being anything the original programmer typed.  Such a *fakematch* is a
clue to the real source, not a match.  This module makes that distinction mechanical:

* a **[match]** finding blocks credit.  A function whose bytes are identical and that carries one
  is ``MATCH-PENDING``: reported, not counted;
* an **advisory** finding is open work (placeholder names, a missing header comment, braceless
  bodies) and never blocks a match;
* an **exception** is a [match] finding of a style rule that the source records with
  ``RULE-EXCEPTION: <rule>, <reason the bytes give>``.  Fake code (R17) and assembly bodies
  (R18) cannot be excepted;
* an **original-asm** finding marks a function the evidence shows was written in assembly.  It is
  listed apart and counted neither as matched nor in the total.

The [match] checks, by rule number (the numbers are stable identifiers shared with the rule
catalogue, see ``docs/code-rules.md``):

``R1``   one type name defined in two files with different bodies; a struct that copies the
         leading fields of another and is reached through a cast; ``class``/``struct`` keyword
         mismatch
``R2``   an ``extern`` object declared outside a header; one global declared with two types
``R4``   a constant offset added to a byte-pointer cast and dereferenced through another cast
``R13``  a virtual named ``pad``/``dummy``
``R17``  ``volatile`` on a local, or elsewhere without a ``volatile: <evidence>`` note; an unused
         local; a statement marked as a probe or as scaffolding; an empty ``if``/``else`` block; a
         bare ``;``; ``do { } while (0)`` outside a macro; ``if (0)``/``if (1)``; a
         self-assignment; ``+ 0`` and ``* 1``; a padding member the SDK or file format does not name
``R18``  inline assembly and ``INCLUDE_ASM``/``GLOBAL_ASM`` stand-ins

Each check is deliberately narrow: hardware ``volatile`` through a cast of a literal or macro
address, empty loop bodies, ``case X: ;``, C struct inheritance and placeholder names all pass.
The checker reads text, not a parse tree: it does not expand macros or follow includes, and a
K&R-style definition is not seen as a function.  It errs towards silence.

Pure functions over text; no I/O except ``Profile.load`` and ``check_paths``.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path

MATCH, ADVISORY, EXCEPTION, ORIGINAL_ASM = "match", "advisory", "exception", "original-asm"
MATCHED, MATCH_PENDING, NOT_MATCHED = "matched", "MATCH-PENDING", "not-matched"
MATCH_RULES = ("R1", "R2", "R4", "R13", "R17", "R18")
NEVER_EXCEPTED = ("R17", "R18")                 # an exception bends a style rule, never licenses fake code
HEADER_SUFFIXES = (".h", ".hh", ".hpp", ".inc")
SOURCE_SUFFIXES = (".c", ".cc", ".cpp", ".cxx", *HEADER_SUFFIXES)

# Names a disassembler or decompiler made up.  They are open naming work (R7), not a failed match.
DEFAULT_PLACEHOLDERS = (
    r"FUN_\w+", r"DAT_\w+", r"sub_\w+", r"unk_\w+", r"local_\w+", r"param_\w+", r"var\d+", r"field_0x\w+",
    r"m_Unk\w*", r"UnkType_\w+", r"uStack\w*", r"[a-z]Var\d+",
    r"func_[0-9A-Fa-f]{6,8}", r"D_[0-9A-Fa-f]{6,8}", r"jtbl_[0-9A-Fa-f]{6,8}", r"M2C_\w+", r"unk[0-9A-Fa-f]+",
    r"temp_[a-z]+\d+(?:_\d+)?", r"var_[a-z]+\d+(?:_\d+)?", r"phi_[a-z]+\d+(?:_\d+)?", r"sp[0-9A-F]{1,4}",
    r"arg\d+", r"temp\d+", r"ptr\d+", r"result\d+", r"v\d+",
)
_ADDRESS_LIKE = re.compile(r"^[A-Za-z_]*?_?(?=[0-9a-fA-F]*[0-9])[0-9a-fA-F]{6,8}$")

_KEYWORDS = frozenset(
    "auto break case char const continue default do double else enum extern float for goto if int long register "
    "return short signed sizeof static struct switch typedef union unsigned void volatile while".split())
_NOT_A_DECLARATION = frozenset("return goto break continue case default else do if while for switch sizeof typedef "
                               "extern static".split())
_BYTE = r"(?:(?:const\s+)?(?:unsigned\s+char|signed\s+char|char|u8|s8|BYTE|uint8_t|int8_t))"
_WORD = r"(?:(?:unsigned\s+|signed\s+)?(?:int|long)|u32|s32|uintptr_t|intptr_t|size_t)"
_OFFSET = r"(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*"
_OPERAND = r"\(?\s*[A-Za-z_][\w.\[\]]*(?:->[\w.\[\]]+)*\s*\)?"
_ANY_POINTER = r"\(\s*(?:(?:const|volatile|struct|union|unsigned|signed)\s+)*\w+\s*\*+\s*\)"
_OFFSET_CAST = re.compile(rf"{_ANY_POINTER}\s*\(\s*\(\s*{_BYTE}\s*\*\s*\)\s*{_OPERAND}\s*[+-]\s*{_OFFSET}\s*\)")
_WORD_OFFSET_CAST = re.compile(rf"{_ANY_POINTER}\s*\(\s*\(\s*{_WORD}\s*\)\s*{_OPERAND}\s*[+-]\s*{_OFFSET}\s*\)")
_THIS_OFFSET = re.compile(rf"\(\s*(?:{_BYTE}\s*\*|{_WORD})\s*\)\s*this\s*[+-]")
_V_TYPES = r"(?:v[us](?:8|16|32|64)|vf(?:32|64))"
_VOLATILE = re.compile(rf"\bvolatile\b|\b{_V_TYPES}\b")
_VOLATILE_LOCAL = re.compile(
    rf"^\s*(?:(?:static|register|const)\s+)*(?:(?:volatile\s+(?:(?:const|unsigned|signed|struct|union)\s+)*\w+)"
    rf"|(?:(?:(?:const|unsigned|signed|struct|union)\s+)*\w+\s+volatile)|{_V_TYPES})\s+[A-Za-z_]\w*\s*"
    r"(?:\[[^\]]*\]\s*)*(?:=|;|,)")
_VOLATILE_POINTER_OBJECT = re.compile(r"\*\s*volatile\s+[A-Za-z_]\w*\s*(?:=|;|,)")
_HARDWARE_CAST = re.compile(
    rf"\(\s*(?:volatile\s+(?:(?:unsigned|signed)\s+)?\w+|\w+\s+volatile|{_V_TYPES})\s*\*+\s*\)\s*\(?\s*"
    r"(?:0[xX][0-9a-fA-F]+|(?![A-Z]_[0-9A-F]{6,8}\b)[A-Z][A-Z0-9_]{2,}\b)")
_VOLATILE_TYPEDEF = re.compile(r"^\s*typedef\b[^;{]*;\s*$")
_SELF_ASSIGN = re.compile(r"(?<![\w.>\]*&])([A-Za-z_]\w*(?:(?:\.|->)\w+|\[[^\][]*\])*)\s*=\s*\1\s*;")
_PLUS_ZERO = re.compile(r"(?<![eE+])\+\s*0\b(?![.xX])")
_TIMES_ONE = re.compile(r"\*\s*1\b(?!\.)")
_DOUBLE_NOT = re.compile(r"!\s*!\s*[\w(]")
_VOID_USE = re.compile(r"\(\s*void\s*\)\s*[A-Za-z_]\w*\s*;")
_PAD_MEMBER = re.compile(r"^(?:_*pad\d*|_pad\w*)$")
_PAD_VIRTUAL = re.compile(r"\bvirtual\b[^;{()]*\b((?:pad|dummy)\w*)\s*\(", re.I)
_PROBE_NOTE = re.compile(r"^\W*(?:probe\s*:|fake\s*-?match\b|n64dk: frame padding)|\b(?:PROBE|FAKEMATCH)\b")
_ASM_TOKEN = re.compile(r"\b(?:__asm__|__asm|asm)\b\s*(?:(?:volatile|__volatile__)\s*)?[({]")
_ASM_STANDIN = re.compile(r"\b(?:INCLUDE_ASM|GLOBAL_ASM)\s*\(|^\s*#\s*pragma\s+GLOBAL_ASM\b", re.M)
_EXTERN = re.compile(r"\bextern\b(?!\s*\")([^;{}]*);")
_ATTRIBUTE = re.compile(r"\b(?:__asm__|__asm|asm|__attribute__)\s*\(\(?[^()]*\)?\)")
_TYPE_DEFINITION = re.compile(r"\b(struct|union|enum|class)\b\s*([A-Za-z_]\w*)?\s*(?::[^{;()]*)?\{")
_KEYWORD_USE = re.compile(r"\b(class|struct)\s+([A-Za-z_]\w*)\s*[;{:]")
_CONTROL = re.compile(r"\b(if|else|for|while|switch|do)\b")
_PLAIN_ASSIGN = re.compile(r"(?<![=!<>+\-*/%&|^])=(?!=)")
_FOR_DECLARATION = re.compile(r"\bfor\s*\(\s*(?:(?:unsigned|signed|const)\s+)*(?:int|char|short|long|[us](?:8|16|32|64)|"
                              r"f32|f64|size_t)\s+[A-Za-z_]\w*\s*=")
_DECIMAL_MASK = re.compile(r"(?<![&|])[&|^]\s*([1-9]\d{2,})\b(?![.xX])")
_RULE_EXCEPTION = re.compile(r"RULE-EXCEPTION:\s*(R\d+)")
_QUIRK_NOTE = re.compile(r"\bR36\b|\bBUG:|\bNOTE:|\bguess:")
_IDENTIFIER = re.compile(r"(?<![\w.])[A-Za-z_]\w*")
_HEAD = re.compile(r"^\s*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*[\s*]+([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*$")
_NEXT_DECLARATOR = re.compile(r"^\s*\**\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*(?:=.*)?$", re.S)


@dataclass(frozen=True)
class Finding:
    """One rule finding.  ``function`` is None for a finding at file scope, which concerns every
    function of the unit."""
    rule: str
    tier: str
    path: str
    line: int
    function: str | None
    message: str

    def as_dict(self) -> dict:
        return {"rule": self.rule, "tier": self.tier, "path": self.path, "line": self.line,
                "function": self.function, "message": self.message}

    def text(self) -> str:
        where = f" in {self.function}" if self.function else ""
        return f"{self.path}:{self.line}: {self.rule} [{self.tier}]{where}: {self.message}"


@dataclass(frozen=True)
class Profile:
    """What a project says about itself (``[code_rules]`` in ``n64dk.toml``; the prose profile is the
    project's ``AGENTS.md``).  ``relax`` maps a rule to the reason it does not apply; ``tighten``
    promotes advisory rules to [match]."""
    relax: dict = field(default_factory=dict)
    tighten: tuple[str, ...] = ()
    placeholders: tuple[str, ...] = DEFAULT_PLACEHOLDERS
    naming_whitelist: tuple[str, ...] = ()
    sdk_padding: tuple[str, ...] = ()
    asm_helpers: tuple[str, ...] = ()
    original_asm: tuple[str, ...] = ()
    braceless: bool = False
    banners: bool = True

    def __post_init__(self):
        for rule, reason in self.relax.items():
            if rule in NEVER_EXCEPTED:
                raise ValueError(f"{rule} cannot be relaxed: fake code and assembly bodies are never source")
            if not str(reason).strip():
                raise ValueError(f"relaxing {rule} needs its reason")

    @classmethod
    def from_mapping(cls, table: dict | None) -> "Profile":
        table = dict(table or {})
        unknown = set(table) - {"relax", "tighten", "placeholders", "naming_whitelist", "sdk_padding", "asm_helpers",
                                "original_asm", "braceless", "banners"}
        if unknown:
            raise ValueError(f"unknown [code_rules] keys: {', '.join(sorted(unknown))}")
        relax = table.get("relax") or {}
        if not isinstance(relax, dict):
            raise ValueError("[code_rules] relax is a table of rule = \"reason\"")
        names = lambda key: tuple(str(item) for item in table.get(key) or ())      # noqa: E731
        return cls(relax={str(k): str(v) for k, v in relax.items()}, tighten=names("tighten"),
                   placeholders=DEFAULT_PLACEHOLDERS + names("placeholders"), naming_whitelist=names("naming_whitelist"),
                   sdk_padding=names("sdk_padding"), asm_helpers=names("asm_helpers"),
                   original_asm=names("original_asm"), braceless=bool(table.get("braceless", False)),
                   banners=bool(table.get("banners", True)))

    @classmethod
    def load(cls, project: str | Path | None) -> "Profile":
        """The profile of a project directory; the defaults when it has none."""
        if project is None:
            return cls()
        config = Path(project) / "n64dk.toml"
        if not config.is_file():
            return cls()
        import tomllib
        return cls.from_mapping(tomllib.loads(config.read_text()).get("code_rules"))


# ============================================================================== text model
@dataclass(frozen=True)
class _Function:
    name: str
    start: int          # offset of the first character of the definition's header
    open: int           # offset of the body's opening brace
    end: int            # offset after the body's closing brace


@dataclass(frozen=True)
class _TypeDefinition:
    keyword: str
    names: tuple[str, ...]
    body: str           # whitespace-normalised
    fields: tuple[tuple[str, tuple[str, ...]], ...]     # (normalised declaration, declared names)
    offset: int


class _Unit:
    """One file: its code with comments, literals and preprocessor lines blanked, its comments by
    line, its functions and its type definitions."""

    def __init__(self, path: str, source: str):
        self.path = path
        self.raw = source
        text, self.comments = _blank(source)
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.directives = _directive_lines(text)
        self.with_directives = text
        lines = text.split("\n")
        for number in self.directives:
            lines[number - 1] = " " * len(lines[number - 1])
        self.code = "\n".join(lines)
        self.functions = _functions(self.code)
        self._function_starts = [fn.start for fn in self.functions]
        self.types = _type_definitions(self.code)
        self.header = Path(path).suffix.lower() in HEADER_SUFFIXES
        self.cplusplus = Path(path).suffix.lower() in (".cc", ".cpp", ".cxx", ".hh", ".hpp")

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def line_text(self, number: int, code: str | None = None) -> str:
        code = self.code if code is None else code
        start = self.starts[number - 1]
        end = self.starts[number] - 1 if number < len(self.starts) else len(code)
        return code[start:end]

    def function_at(self, offset: int) -> _Function | None:
        index = bisect.bisect_right(self._function_starts, offset) - 1
        return self.functions[index] if index >= 0 and offset < self.functions[index].end else None

    def in_body(self, offset: int) -> bool:
        fn = self.function_at(offset)
        return fn is not None and offset > fn.open

    def note(self, number: int, pattern: re.Pattern) -> re.Match | None:
        """A comment on the line or the line above that matches ``pattern``."""
        for candidate in (number, number - 1):
            for text in self.comments.get(candidate, ()):
                found = pattern.search(text)
                if found:
                    return found
        return None


def _blank(source: str) -> tuple[str, dict[int, list[str]]]:
    """``source`` with comments and string/character literals replaced by spaces (same length,
    newlines kept), and the comments by every line they touch."""
    out, comments, i, line, n = [], {}, 0, 1, len(source)
    while i < n:
        ch, two = source[i], source[i:i + 2]
        if two == "//" or two == "/*":
            end = source.find("\n", i) if two == "//" else source.find("*/", i + 2)
            end = n if end < 0 else end + (0 if two == "//" else 2)
            text = source[i:end]
            body = text[2:] if two == "//" else text[2:-2]
            for offset in range(text.count("\n") + 1):
                comments.setdefault(line + offset, []).append(body)
            out.append(re.sub(r"[^\n]", " ", text))
            line += text.count("\n")
            i = end
        elif ch in "\"'":
            j = i + 1
            while j < n and source[j] != ch and source[j] != "\n":
                j += 2 if source[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(ch + " " * (j - i - 2) + ch if j - i >= 2 else source[i:j])
            i = j
        else:
            out.append(ch)
            line += ch == "\n"
            i += 1
    return "".join(out), comments


def _directive_lines(text: str) -> set[int]:
    """Line numbers of preprocessor directives, continuation lines included."""
    found, continued = set(), False
    for number, line in enumerate(text.split("\n"), 1):
        if continued or line.lstrip().startswith("#"):
            found.add(number)
            continued = line.rstrip().endswith("\\")
        else:
            continued = False
    return found


def _close(text: str, start: int, opening: str = "(", closing: str = ")") -> int:
    """Offset after the bracket that closes the one at ``start``; -1 when it never closes."""
    depth = 0
    for i in range(start, len(text)):
        if text[i] == opening:
            depth += 1
        elif text[i] == closing:
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


def _open(text: str, end: int) -> int:
    """Offset of the ``(`` that the ``)`` at ``end`` closes; -1 when there is none."""
    depth = 0
    for i in range(end, -1, -1):
        if text[i] == ")":
            depth += 1
        elif text[i] == "(":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _functions(code: str) -> list[_Function]:
    out, depth, i, n = [], 0, 0, len(code)
    while i < n:
        ch = code[i]
        if ch == "{":
            if depth == 0:
                found = _function_header(code, i)
                end = _close(code, i, "{", "}")
                if end < 0:
                    break
                if found:
                    out.append(_Function(found[0], found[1], i, end))
                i = end
                continue
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        i += 1
    return out


def _function_header(code: str, brace: int) -> tuple[str, int] | None:
    """(name, header start) when the ``{`` at ``brace`` opens a function body."""
    j = brace - 1
    while j >= 0 and code[j].isspace():
        j -= 1
    if j >= 4 and code[j - 4:j + 1] == "const":             # C++ const method
        j -= 5
        while j >= 0 and code[j].isspace():
            j -= 1
    if j < 0 or code[j] != ")":
        return None
    opening = _open(code, j)
    if opening <= 0:
        return None
    k = opening - 1
    while k >= 0 and code[k].isspace():
        k -= 1
    end = k + 1
    while k >= 0 and (code[k].isalnum() or code[k] in "_:~"):
        k -= 1
    name = code[k + 1:end]
    if not name or name in _KEYWORDS or name[0].isdigit():
        return None
    start = max(code.rfind(";", 0, k + 1), code.rfind("}", 0, k + 1)) + 1
    if "=" in code[start:k + 1]:                           # an initialiser, not a definition
        return None
    while start < k + 1 and code[start].isspace():
        start += 1
    return name, start


def _type_definitions(code: str) -> list[_TypeDefinition]:
    out = []
    for found in _TYPE_DEFINITION.finditer(code):
        opening = found.end() - 1
        end = _close(code, opening, "{", "}")
        if end < 0:
            continue
        names = [found.group(2)] if found.group(2) else []
        statement = max(code.rfind(";", 0, found.start()), code.rfind("}", 0, found.start()),
                        code.rfind("{", 0, found.start())) + 1
        if re.match(r"\s*typedef\b", code[statement:found.start()]):
            trailer = code[end:code.find(";", end) if code.find(";", end) >= 0 else end]
            names += [name for name in _IDENTIFIER.findall(trailer) if name not in _KEYWORDS]
        body = code[opening + 1:end - 1]
        fields = tuple(_fields(body)) if found.group(1) in ("struct", "union", "class") else ()
        out.append(_TypeDefinition(found.group(1), tuple(names), " ".join(body.split()), fields, found.start()))
    return out


def _fields(body: str) -> list[tuple[str, tuple[str, ...]]]:
    out, depth, start = [], 0, 0
    for i, ch in enumerate(body):
        if ch in "{(":
            depth += 1
        elif ch in "})":
            depth -= 1
        elif ch == ";" and depth == 0:
            text = " ".join(body[start:i].split())
            start = i + 1
            if not text or text.endswith(":") or "(" in text and "(*" not in text.replace(" ", ""):
                continue                                    # an access label or a method
            pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)", text)
            if pointer:
                names = (pointer.group(1),)
            else:
                names = tuple(m.group(1) for part in _split_commas(text)
                              for m in [re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*(?::\s*\d+\s*)?$", part)] if m)
            out.append((text, names))
    return out


def _split_commas(text: str) -> list[str]:
    parts, depth, start = [], 0, 0
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    return parts + [text[start:]]


def _declared_locals(statement: str) -> list[str]:
    """Names a simple local declaration introduces; empty when the line is anything else."""
    text = statement.strip()
    if not text.endswith(";") or "{" in text or "}" in text:
        return []
    parts = _split_commas(text[:-1])
    head = parts[0].split("=", 1)[0]
    if "(" in head or ")" in head:
        return []
    first = _IDENTIFIER.match(head.strip())
    if not first or first.group(0) in _NOT_A_DECLARATION:
        return []
    found = _HEAD.match(head)
    if not found or found.group(1) in _KEYWORDS:
        return []
    names = [found.group(1)]
    for part in parts[1:]:
        more = _NEXT_DECLARATOR.match(part)
        if not more:
            return []
        names.append(more.group(1))
    return names


# ============================================================================== the checks
class _Checker:
    def __init__(self, units: list[_Unit], profile: Profile):
        self.units, self.profile = units, profile
        self.findings: list[Finding] = []
        self.placeholder = re.compile("^(?:" + "|".join(profile.placeholders) + ")$")
        self.whitelist = [re.compile(f"^(?:{pattern})$") for pattern in profile.naming_whitelist]

    def add(self, unit: _Unit, rule: str, offset: int, message: str, tier: str | None = None,
            function: str | None = None) -> None:
        line = unit.line(offset)
        fn = unit.function_at(offset)
        name = (function if function is not None else fn.name if fn else None) or None
        if rule in self.profile.relax:
            return
        if tier is None:
            tier = MATCH if rule in MATCH_RULES else ADVISORY
        if tier == ADVISORY and rule in self.profile.tighten:
            tier = MATCH
        if tier in (MATCH, ADVISORY) and rule not in NEVER_EXCEPTED:
            excepted = unit.note(line, _RULE_EXCEPTION)
            if excepted and excepted.group(1) == rule:
                tier = EXCEPTION
        if rule == "R18" and name is not None:
            if name in self.profile.original_asm or self._marked_original(unit, fn):
                tier = ORIGINAL_ASM
            elif name in self.profile.asm_helpers:
                tier, message = EXCEPTION, message + " (listed helper)"
        self.findings.append(Finding(rule, tier, unit.path, line, name, message))

    @staticmethod
    def _marked_original(unit: _Unit, fn: _Function | None) -> bool:
        if fn is None:
            return False
        return any("ORIGINAL-ASM" in text for number in range(unit.line(fn.start) - 1, unit.line(fn.open) + 1)
                   for text in unit.comments.get(number, ()))

    def run(self) -> list[Finding]:
        for unit in self.units:
            self.offsets(unit)
            self.assembly(unit)
            self.volatile(unit)
            self.fake_statements(unit)
            self.control(unit)
            self.unused_locals(unit)
            self.padding(unit)
            self.local_externs(unit)
            self.naming(unit)
            self.readability(unit)
        self.across_units()
        self.findings.sort(key=lambda f: (f.path, f.line, f.rule, f.message))
        return self.findings

    # ---- R4 / R13
    def offsets(self, unit: _Unit) -> None:
        for text in (unit.code, None):                       # None: the #define lines
            code = unit.with_directives if text is None else text
            for found in _OFFSET_CAST.finditer(code):
                if (text is None) != (unit.line(found.start()) in unit.directives):
                    continue
                what = "an offset macro" if text is None else "a constant offset from a byte-pointer cast"
                self.add(unit, "R4", found.start(), f"{what}, dereferenced through a cast: use a typed member")
        for found in _WORD_OFFSET_CAST.finditer(unit.code):
            self.add(unit, "R4", found.start(), "a constant offset from an integer cast of a pointer: "
                     "is the pointer typed this way only to dodge the real type?", ADVISORY)
        for found in _THIS_OFFSET.finditer(unit.code):
            self.add(unit, "R4", found.start(), "offset arithmetic on a cast of `this`: use a typed member")
        for found in _PAD_VIRTUAL.finditer(unit.code):
            self.add(unit, "R13", found.start(), f"virtual `{found.group(1)}` pads the vtable: declare the real slot")

    # ---- R18
    def assembly(self, unit: _Unit) -> None:
        for found in _ASM_TOKEN.finditer(unit.code):
            if unit.in_body(found.start()):
                self.add(unit, "R18", found.start(), "inline assembly in a function body")
            elif not unit.code[unit.starts[unit.line(found.start()) - 1]:found.start()].strip():
                self.add(unit, "R18", found.start(), "file-scope assembly")
        for found in _ASM_STANDIN.finditer(unit.with_directives):
            self.add(unit, "R18", found.start(), "an assembly stand-in for a function body")

    # ---- R17: volatile
    def volatile(self, unit: _Unit) -> None:
        seen = set()
        for found in _VOLATILE.finditer(unit.code):
            number = unit.line(found.start())
            if number in seen:
                continue
            seen.add(number)
            text = unit.line_text(number)
            if _VOLATILE_TYPEDEF.match(text):
                continue                                    # naming a volatile type is not using one
            if unit.in_body(found.start()) and (_VOLATILE_LOCAL.match(text) or _VOLATILE_POINTER_OBJECT.search(text)):
                self.add(unit, "R17", found.start(), "`volatile` on a local: find the type, pointer or helper it "
                         "stands in for")
                continue
            hardware = [cast.span() for cast in _HARDWARE_CAST.finditer(text)]
            if all(_inside(hardware, hit.start()) for hit in _VOLATILE.finditer(text)):
                continue                                    # a literal or macro address: a hardware register
            if unit.note(number, re.compile(r"volatile:\s*\S")):
                continue
            self.add(unit, "R17", found.start(), "`volatile` without a `volatile: <evidence>` note (hardware "
                     "register, data shared with an interrupt handler)")

    # ---- R17: statements that only steer the compiler
    def fake_statements(self, unit: _Unit) -> None:
        for number, texts in sorted(unit.comments.items()):
            first = number - 1 not in unit.comments or texts[0] not in unit.comments[number - 1]
            if first and any(_PROBE_NOTE.search(text) for text in texts):
                self.add(unit, "R17", unit.starts[number - 1], "marked as a probe or as reconstruction scaffolding")
        for fn in unit.functions:
            body = unit.code[fn.open:fn.end]
            for pattern, rule, tier, message in (
                    (_SELF_ASSIGN, "R17", None, "self-assignment"),
                    (_PLUS_ZERO, "R17", None, "`+ 0`"),
                    (_TIMES_ONE, "R17", None, "`* 1`"),
                    (_DOUBLE_NOT, "F", ADVISORY, "`!!x`: sometimes human, sometimes a width or sequence-point trick"),
                    (_VOID_USE, "F", ADVISORY, "`(void)x;` only keeps a name alive"),
                    (_FOR_DECLARATION, "R22", ADVISORY, "a declaration in a `for` header is not C89"),
                    (_DECIMAL_MASK, "R9", ADVISORY, "a mask written in decimal")):
                if rule == "R22" and unit.cplusplus:
                    continue
                for found in pattern.finditer(body):
                    self.add(unit, rule, fn.open + found.start(), message, tier)
            depth, previous = 0, "{"
            for i in range(1, len(body) - 1):
                ch = body[i]
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    depth -= 1
                elif ch == ";" and depth == 0 and previous in ";{" and not _empty_loop_block(body, i):
                    self.add(unit, "R17", fn.open + i, "a bare `;` statement")
                if not ch.isspace():
                    previous = ch

    # ---- R17 / R35: control statements
    def control(self, unit: _Unit) -> None:
        for fn in unit.functions:
            code, limit = unit.code, fn.end
            for found in _CONTROL.finditer(code, fn.open, limit):
                word, at = found.group(1), found.start()
                after = found.end()
                condition = ""
                if word in ("if", "for", "while", "switch"):
                    opening = _skip(code, after)
                    if opening >= limit or code[opening] != "(":
                        continue
                    after = _close(code, opening)
                    if after < 0:
                        continue
                    condition = code[opening + 1:after - 1]
                body = _skip(code, after)
                first = code[body] if body < limit else ""
                tail = word == "while" and first == ";" and code[:at].rstrip().endswith("}")
                if tail and condition.strip() == "0":
                    self.add(unit, "R17", at, "`do { } while (0)` outside a macro: restore the macro it expands")
                    continue
                if word in ("if", "else") and (first == ";" or first == "{" and code[_skip(code, body + 1)] == "}"):
                    self.add(unit, "R17", at, f"an empty `{word}` block")
                    continue
                if word == "else" and code.startswith("if", body) and not (code[body + 2].isalnum() or code[body + 2] == "_"):
                    continue
                if word == "if" and condition.strip() in ("0", "1"):
                    self.add(unit, "R17", at, f"`if ({condition.strip()})` is a block that only steers the compiler")
                if word == "if" and _PLAIN_ASSIGN.search(condition) and "(" not in condition.split("=", 1)[1]:
                    self.add(unit, "R35", at, "an assignment inside a condition", ADVISORY)
                braced = first == "{" or word == "switch" or word in ("for", "while") and first == ";"
                if not braced and not self.profile.braceless:
                    self.add(unit, "R35", at, f"`{word}` body without braces", ADVISORY)

    # ---- R17: unused locals
    def unused_locals(self, unit: _Unit) -> None:
        for fn in unit.functions:
            body = unit.code[fn.open:fn.end]
            first = unit.line(fn.open)
            for index, text in enumerate(body.split("\n")):
                for name in _declared_locals(text if index else text.split("{", 1)[-1]):
                    if len(re.findall(rf"\b{re.escape(name)}\b", body)) != 1:
                        continue
                    if unit.note(first + index, _QUIRK_NOTE) or                             any(_PROBE_NOTE.search(note) for note in unit.comments.get(first + index, ())):
                        continue                            # labelled as original, or already reported as scaffolding
                    self.add(unit, "R17", unit.starts[first + index - 1], f"local `{name}` is never used")

    # ---- R17: padding members
    def padding(self, unit: _Unit) -> None:
        for definition in unit.types:
            for _text, names in definition.fields:
                for name in names:
                    if _PAD_MEMBER.match(name) and name not in self.profile.sdk_padding:
                        self.add(unit, "R17", definition.offset, f"padding member `{name}` in "
                                 f"`{' '.join(definition.names) or definition.keyword}`: name unknown members by "
                                 "offset, or list the name the SDK or file format gives it", function="")

    # ---- R2 / R25
    def local_externs(self, unit: _Unit) -> None:
        for name, kind, _declared, offset in _externs(unit):
            inside = unit.in_body(offset)
            if kind == "function":
                if inside or not unit.header:
                    self.add(unit, "R25", offset, f"prototype of `{name}` outside a header", ADVISORY)
            elif not unit.header:
                self.add(unit, "R2", offset, f"`extern` of `{name}` outside its header")

    # ---- R7
    def naming(self, unit: _Unit) -> None:
        seen = set()
        for found in _IDENTIFIER.finditer(unit.code):
            name = found.group(0)
            fn = unit.function_at(found.start())
            key = (name, fn.name if fn else None)
            if key in seen or name in _KEYWORDS:
                continue
            seen.add(key)
            if any(pattern.match(name) for pattern in self.whitelist):
                continue
            if self.placeholder.match(name) or _ADDRESS_LIKE.match(name):
                self.add(unit, "R7", found.start(), f"placeholder name `{name}`", ADVISORY)

    # ---- R33 / R37
    def readability(self, unit: _Unit) -> None:
        if self.profile.banners and not unit.header:
            for fn in unit.functions:
                number = unit.line(fn.start) - 1
                while number >= 1 and not unit.line_text(number, unit.raw).strip():
                    number -= 1
                if number < 1 or number not in unit.comments:
                    self.add(unit, "R33", fn.start, "no header comment", ADVISORY)
        for found in re.finditer(r"^[ \t]*#[ \t]*if[ \t]+0\b", unit.with_directives, re.M):
            self.add(unit, "R37", found.start(), "`#if 0` block: code no build compiles is not source", ADVISORY,
                     function="")

    # ---- R1 / R2 across files
    def across_units(self) -> None:
        bodies: dict[str, dict[str, list[tuple[_Unit, _TypeDefinition]]]] = {}
        structs: list[tuple[_Unit, _TypeDefinition]] = []
        for unit in self.units:
            for definition in unit.types:
                for name in definition.names:
                    bodies.setdefault(name, {}).setdefault(definition.body, []).append((unit, definition))
                if definition.keyword != "enum" and definition.names and definition.fields:
                    structs.append((unit, definition))
        for name, variants in sorted(bodies.items()):
            files = {unit.path for places in variants.values() for unit, _definition in places}
            if len(variants) > 1 and len(files) > 1:
                for places in variants.values():
                    for unit, definition in places:
                        self.add(unit, "R1", definition.offset, f"`{name}` is defined with {len(variants)} different "
                                 f"bodies in {len(files)} files: declare it once, in a shared header", function="")
        by_first: dict[str, list[tuple[_TypeDefinition, list[str]]]] = {}
        for _unit, whole in structs:
            texts = [text for text, _names in whole.fields]
            by_first.setdefault(texts[0], []).append((whole, texts))
        for unit, view in structs:
            declared = [text for text, _names in view.fields]
            for whole, texts in by_first[declared[0]]:
                if whole is view or len(declared) >= len(texts) or set(view.names) & set(whole.names) or \
                        declared != texts[:len(declared)]:
                    continue
                if self._cast_between(view, whole):
                    self.add(unit, "R1", view.offset, f"`{view.names[0]}` copies the leading fields of "
                             f"`{whole.names[0]}` and is reached through a cast: a layout view, not a type",
                             function="")
                    break
        keywords: dict[str, dict[str, tuple[_Unit, int]]] = {}
        for unit in self.units:
            for found in _KEYWORD_USE.finditer(unit.code):
                keywords.setdefault(found.group(2), {}).setdefault(found.group(1), (unit, found.start()))
        for name, uses in sorted(keywords.items()):
            if len(uses) > 1:
                for unit, offset in uses.values():
                    self.add(unit, "R1", offset, f"`{name}` is declared both `class` and `struct`", function="")
        declared: dict[str, dict[str, list[tuple[_Unit, int]]]] = {}
        for unit in self.units:
            for name, kind, text, offset in _externs(unit):
                if kind == "object":
                    declared.setdefault(name, {}).setdefault(text, []).append((unit, offset))
        for name, variants in sorted(declared.items()):
            if len(variants) > 1:
                for places in variants.values():
                    for unit, offset in places:
                        self.add(unit, "R2", offset, f"`{name}` is declared with {len(variants)} different types: "
                                 + " / ".join(f"`{text}`" for text in sorted(variants)))

    def _cast_between(self, view: _TypeDefinition, whole: _TypeDefinition) -> bool:
        def cast(names):
            return re.compile(r"\(\s*(?:const\s+)?(?:struct\s+|union\s+)?(?:" + "|".join(map(re.escape, names))
                              + r")\s*\*+\s*\)")
        def mention(names):
            return re.compile(r"\b(?:" + "|".join(map(re.escape, names)) + r")\b")
        for unit in self.units:
            for fn in unit.functions:
                text = unit.code[fn.start:fn.end]
                if cast(view.names).search(text) and mention(whole.names).search(text) or \
                        cast(whole.names).search(text) and mention(view.names).search(text):
                    return True
        return False


def _inside(spans, offset: int) -> bool:
    return any(start <= offset < end for start, end in spans)


def _empty_loop_block(body: str, semicolon: int) -> bool:
    """Whether the ``;`` is all of a ``{ ; }`` block that is the body of a ``for`` or ``while``."""
    before, after = body[:semicolon].rstrip(), body[semicolon + 1:].lstrip()
    if not before.endswith("{") or not after.startswith("}"):
        return False
    header = before[:-1].rstrip()
    if not header.endswith(")"):
        return False
    opening = _open(header, len(header) - 1)
    return opening > 0 and re.search(r"\b(?:for|while)\s*$", header[:opening]) is not None


def _skip(code: str, offset: int) -> int:
    while offset < len(code) and code[offset].isspace():
        offset += 1
    return min(offset, len(code) - 1)


def _externs(unit: _Unit) -> list[tuple[str, str, str, int]]:
    """``(name, "object" | "function", normalised declaration, offset)`` of every ``extern``."""
    out = []
    for found in _EXTERN.finditer(unit.code):
        text = " ".join(_ATTRIBUTE.sub(" ", found.group(1)).split())
        if not text:
            continue
        prototype = re.match(r"^(.*?)([A-Za-z_]\w*)\s*\((.*)\)$", text)
        if prototype and prototype.group(1).strip() and not prototype.group(1).rstrip().endswith("("):
            out.append((prototype.group(2), "function", text, found.start()))
            continue
        parts = _split_commas(text)
        first = re.match(r"^(.*?)([A-Za-z_]\w*)\s*((?:\[[^\]]*\]\s*)*)$", parts[0].strip())
        pointer = re.match(r"^(.*?)\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*(\(.*\))$", parts[0].strip())
        if pointer:
            out.append((pointer.group(2), "object", f"{pointer.group(1).strip()} (*)" + pointer.group(3), found.start()))
            continue
        if not first or not first.group(1).strip():
            continue
        base = first.group(1).strip()
        out.append((first.group(2), "object", (base + " " + re.sub(r"\[[^\]]*\]", "[]", first.group(3))).strip(),
                    found.start()))
        root = re.sub(r"[\s*]+$", "", base)
        for part in parts[1:]:
            more = re.match(r"^\s*(\**)\s*([A-Za-z_]\w*)\s*((?:\[[^\]]*\]\s*)*)$", part)
            if more:
                out.append((more.group(2), "object",
                            (root + " " + more.group(1) + " " + re.sub(r"\[[^\]]*\]", "[]", more.group(3))).strip(),
                            found.start()))
    return out


# ============================================================================== results
def _rule_order(rule: str) -> tuple[int, str]:
    return (int(rule[1:]), rule) if rule[1:].isdigit() else (10 ** 6, rule)


@dataclass
class Report:
    """Findings over a set of files, and what they mean for each function."""
    findings: list[Finding]
    functions: dict[str, list[str]]        # path -> the functions defined in it, in source order

    def of(self, tier: str) -> list[Finding]:
        return [finding for finding in self.findings if finding.tier == tier]

    @property
    def blocking(self) -> list[Finding]:
        return self.of(MATCH)

    @cached_property
    def _by_unit(self) -> dict[tuple[str, str], dict[str | None, set[str]]]:
        """(tier, path) -> function (None at file scope) -> rules."""
        index: dict[tuple[str, str], dict[str | None, set[str]]] = {}
        for finding in self.findings:
            index.setdefault((finding.tier, finding.path), {}).setdefault(finding.function, set()).add(finding.rule)
        return index

    def blocked_rules(self, path: str, function: str | None = None) -> list[str]:
        """The [match] rules that block ``function`` of ``path`` (the whole unit when None).  A
        finding at file scope blocks every function of its unit."""
        found = self._by_unit.get((MATCH, path), {})
        names = found if function is None else (None, function)
        return sorted(set().union(*(found.get(name, ()) for name in names)), key=_rule_order)

    def original_asm(self, path: str, function: str) -> bool:
        return function in self._by_unit.get((ORIGINAL_ASM, path), {})

    def status(self, path: str, function: str | None = None, exact: bool = True) -> str:
        """``matched`` only when the bytes are identical *and* no [match] rule fires."""
        if not exact:
            return NOT_MATCHED
        return MATCH_PENDING if self.blocked_rules(path, function) else MATCHED

    def by_rule(self, tier: str = MATCH) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.of(tier):
            counts[finding.rule] = counts.get(finding.rule, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: _rule_order(item[0])))

    def summary(self) -> dict:
        functions = [(path, name) for path, names in self.functions.items() for name in names]
        original = [key for key in functions if self.original_asm(*key)]
        pending = [key for key in functions if key not in original and self.blocked_rules(*key)]
        counted = len(functions) - len(original)
        return {"files": len(self.functions), "functions": len(functions),
                "status": MATCH_PENDING if self.blocking else "pass",
                "pass": counted - len(pending), "match_pending": len(pending), "original_asm": len(original),
                "match_findings": self.by_rule(MATCH), "exceptions": self.by_rule(EXCEPTION),
                "advisory": self.by_rule(ADVISORY)}

    def as_dict(self, advisory: bool = True) -> dict:
        keep = [f for f in self.findings if advisory or f.tier != ADVISORY]
        return {**self.summary(), "findings": [finding.as_dict() for finding in keep]}


def check(sources: dict[str, str], profile: Profile | None = None) -> Report:
    """Check ``{path: text}``.  The cross-file rules (R1, R2) see every file given, so pass the
    headers a unit includes together with the unit."""
    units = [_Unit(path, text) for path, text in sources.items()]
    findings = _Checker(units, profile or Profile()).run()
    return Report(findings, {unit.path: [fn.name for fn in unit.functions] for unit in units})


def check_source(source: str, path: str = "<source>.c", profile: Profile | None = None) -> Report:
    return check({path: source}, profile)


def collect(paths) -> list[Path]:
    """The C and C++ sources among ``paths``; directories are walked."""
    found = []
    for item in map(Path, paths):
        if item.is_dir():
            found += sorted(p for p in item.rglob("*") if p.is_file() and p.suffix.lower() in SOURCE_SUFFIXES)
        else:
            found.append(item)
    return found


def check_paths(paths, profile: Profile | None = None, root: str | Path | None = None) -> Report:
    files = collect(paths)
    def label(path: Path) -> str:
        try:
            return path.resolve().relative_to(Path(root).resolve()).as_posix() if root else path.as_posix()
        except ValueError:
            return path.as_posix()
    return check({label(path): path.read_text(errors="replace") for path in files}, profile)


def verdict(exact: bool, report: Report, path: str | None = None, function: str | None = None) -> str:
    """The status of one function, one unit or (``path`` None) everything checked."""
    if not exact:
        return NOT_MATCHED
    if path is None:
        return MATCH_PENDING if report.blocking else MATCHED
    return report.status(path, function, exact)


def declarations(sources: dict[str, str]) -> list[dict]:
    """Every ``extern`` over ``sources``, grouped by name: how it is declared and where.  The work
    list for giving each global one declaration in one header (R2, R25)."""
    table: dict[tuple[str, str], dict[str, set[str]]] = {}
    for path, text in sources.items():
        unit = _Unit(path, text)
        for name, kind, declared, _offset in _externs(unit):
            table.setdefault((name, kind), {}).setdefault(declared, set()).add(path)
    return [{"name": name, "kind": kind, "declarations": sorted(variants), "conflict": len(variants) > 1,
             "files": len(set().union(*variants.values()))}
            for (name, kind), variants in sorted(table.items())]
