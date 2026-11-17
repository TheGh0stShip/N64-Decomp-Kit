"""Parsing, span mapping and printing for the AST source-transformation engine (``astforms``).

The engine never re-prints a file.  A source is preprocessed only so that pycparser can
understand it; every edit is expressed as a replacement of a character span of the ORIGINAL
text.  How spans are found:

1.  ``__asm__("label")`` aliases are blanked (same length, newlines kept) and the host ``cpp``
    runs with ``-P``.  Missing ``#include`` files are dropped one by one (reported by
    ``diagnose``) and common N64 integer typedefs are supplied instead.
2.  The target function is located by token scan in both the original text and the
    preprocessed text.  Everything outside the function is parsed once per distinct
    preprocessed context (cached) to build the type environment; the function itself is
    parsed separately behind a one-line typedef prelude, so pycparser coordinates map 1:1 to
    offsets in the preprocessed text.
3.  A small token-level statement parser builds the statement tree (compound / if / while /
    do / for / switch / label / simple) for the function body of BOTH texts.  The two trees
    must have the same shape (otherwise a macro changes statement structure: unmapped).
    Each original statement then knows its exact character span, the spans of its
    condition/for-head, and whether its tokens are identical before and after preprocessing
    (``faithful``).  pycparser statements are attached to tree nodes by order and coordinate.
4.  Editing policy: a statement or condition is re-printed (from the AST) only when it is
    faithful and contains no comment; anything else can still be moved, wrapped or deleted
    as original text but is never re-printed.  Moved text is re-indented by whole lines.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import threading
from dataclasses import dataclass, field

from pycparser import c_ast, c_generator, c_parser

sys.setrecursionlimit(max(sys.getrecursionlimit(), 20000))

INCLUDE_DIRS: list[str] = [p for p in os.environ.get("N64DK_AST_INCLUDE", "").split(os.pathsep) if p]
DEFINES: list[str] = []

STD_TYPEDEFS = {
    "s8": "signed char", "u8": "unsigned char", "s16": "short", "u16": "unsigned short",
    "s32": "int", "u32": "unsigned int", "s64": "long long", "u64": "unsigned long long",
    "f32": "float", "f64": "double", "vs8": "volatile signed char", "vu8": "volatile unsigned char",
    "vs16": "volatile short", "vu16": "volatile unsigned short", "vs32": "volatile int",
    "vu32": "volatile unsigned int", "bool": "int", "BOOL": "int", "size_t": "unsigned int",
}
KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "int", "long", "register", "return", "short", "signed",
    "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
    "inline", "restrict",
}
ASM_LABEL = re.compile(r"\b__asm__\s*\(\s*\"[^\"]*\"\s*\)")
_TOKEN = re.compile(r"""
 (?P<ws>\s+)
|(?P<comment>//[^\n]*|/\*.*?\*/)
|(?P<string>"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')
|(?P<number>\.?\d(?:[eEpP][+-]|[\w.])*)
|(?P<ident>[A-Za-z_]\w*)
|(?P<punct>\.\.\.|<<=|>>=|->|\+\+|--|<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%&|^]=|\#\#|[^\s])
""", re.S | re.X)


class PrepError(Exception):
    """Why a source/function cannot be parsed or mapped; ``code`` is a short category."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# ------------------------------------------------------------------------------ tokens
@dataclass(frozen=True)
class Tok:
    kind: str
    text: str
    start: int
    end: int


def tokenize(text: str) -> list[Tok]:
    """All tokens except whitespace; comments and preprocessor lines are kept as tokens."""
    out: list[Tok] = []
    position, length = 0, len(text)
    line_start_clean = True                 # only whitespace since the start of this line
    while position < length:
        m = _TOKEN.match(text, position)
        if not m:
            raise PrepError("tokenize", f"bad character at {position}")
        kind = m.lastgroup
        if kind == "ws":
            if "\n" in m.group():
                line_start_clean = True
            position = m.end()
            continue
        if kind == "punct" and m.group() == "#" and line_start_clean:
            end = position
            while True:
                newline = text.find("\n", end)
                if newline < 0:
                    end = length
                    break
                if text[newline - 1:newline] == "\\" or text[newline - 2:newline] == "\\\r":
                    end = newline + 1
                    continue
                # a block comment opened on the directive line may continue past it
                segment = text[position:newline]
                opened = segment.rfind("/*")
                if opened > segment.rfind("*/"):
                    close = text.find("*/", position + opened)
                    end = close + 2 if close >= 0 else length
                    continue
                end = newline
                break
            out.append(Tok("pp", text[position:end], position, end))
            position = end
            continue
        out.append(Tok(kind, m.group(), position, m.end()))
        if kind != "comment" or "\n" not in m.group():
            line_start_clean = False
        position = m.end()
    return out


def code_tokens(tokens: list[Tok]) -> list[Tok]:
    return [t for t in tokens if t.kind not in ("comment", "pp")]


def _match(code: list[Tok], i: int) -> int:
    """Index of the bracket closing ``code[i]``."""
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack = []
    for j in range(i, len(code)):
        text = code[j].text
        if text in pairs:
            stack.append(pairs[text])
        elif text in (")", "]", "}"):
            if not stack or stack.pop() != text:
                raise PrepError("structure", f"unbalanced {text!r}")
            if not stack:
                return j
    raise PrepError("structure", "unbalanced brackets")


def list_functions(code: list[Tok]) -> list[tuple[str, int, int, int]]:
    """(name, first token, ``{`` index, ``}`` index) of every function definition."""
    out, depth, i, last_boundary = [], 0, 0, -1
    while i < len(code):
        text = code[i].text
        if text == "{":
            depth += 1
        elif text == "}":
            depth -= 1
            if depth == 0:
                last_boundary = i
        elif text == ";" and depth == 0:
            last_boundary = i
        elif depth == 0 and code[i].kind == "ident" and i + 1 < len(code) and code[i + 1].text == "(" \
                and text not in KEYWORDS:
            close = _match(code, i + 1)
            if close + 1 < len(code) and code[close + 1].text == "{":
                end = _match(code, close + 1)
                out.append((text, last_boundary + 1, close + 1, end))
                i, last_boundary = end, end
            else:
                i = close
        i += 1
    return out


def find_function(code: list[Tok], name: str) -> tuple[int, int, int] | None:
    """(first token of the definition, index of ``{`` of the body, index of the closing ``}``)."""
    depth, i = 0, 0
    last_boundary = -1
    while i < len(code):
        text = code[i].text
        if text == "{":
            depth += 1
        elif text == "}":
            depth -= 1
            if depth == 0:
                last_boundary = i
        elif text == ";" and depth == 0:
            last_boundary = i
        elif depth == 0 and code[i].kind == "ident" and text == name and i + 1 < len(code) \
                and code[i + 1].text == "(":
            close = _match(code, i + 1)
            if close + 1 < len(code) and code[close + 1].text == "{":
                return last_boundary + 1, close + 1, _match(code, close + 1)
            i = close
        i += 1
    return None


# ------------------------------------------------------------------------------ statement tree
@dataclass(eq=False)
class SNode:
    kind: str                     # compound if while do for switch label caselabel simple
    t0: int                       # first code-token index
    t1: int                       # last code-token index (inclusive)
    children: list = field(default_factory=list)
    cond: tuple | None = None     # token range (inclusive) inside the condition parentheses
    parts: list | None = None     # for-head parts as token ranges (or None when empty)
    has_else: bool = False
    # filled by Prepared
    start: int = 0
    end: int = 0
    faithful: bool = False
    cond_faithful: bool = False
    ast: object = None            # pycparser statement (first of a declaration group)
    group: list = field(default_factory=list)   # all pycparser items of this statement
    opaque: bool = False          # macro statement(s) whose expansion differs in shape
    barrier: bool = False         # opaque with unknown effects
    children_opaque: bool = False
    parent: "SNode | None" = None


def parse_statement(code: list[Tok], i: int) -> SNode:
    text = code[i].text
    if text == "{":
        j = _match(code, i)
        node, k = SNode("compound", i, j), i + 1
        while k < j:
            child = parse_statement(code, k)
            node.children.append(child)
            k = child.t1 + 1
        return node
    if text in ("if", "while", "switch") and code[i].kind == "ident":
        if code[i + 1].text != "(":
            raise PrepError("structure", f"{text} without (")
        close = _match(code, i + 1)
        body = parse_statement(code, close + 1)
        node = SNode(text, i, body.t1, [body], cond=(i + 2, close - 1))
        if text == "if" and body.t1 + 1 < len(code) and code[body.t1 + 1].text == "else":
            other = parse_statement(code, body.t1 + 2)
            node.children.append(other)
            node.t1, node.has_else = other.t1, True
        return node
    if text == "do" and code[i].kind == "ident":
        body = parse_statement(code, i + 1)
        k = body.t1 + 1
        if code[k].text != "while" or code[k + 1].text != "(":
            raise PrepError("structure", "do without while")
        close = _match(code, k + 1)
        if code[close + 1].text != ";":
            raise PrepError("structure", "do-while without ;")
        return SNode("do", i, close + 1, [body], cond=(k + 2, close - 1))
    if text == "for" and code[i].kind == "ident":
        close = _match(code, i + 1)
        parts, start, depth = [], i + 2, 0
        for k in range(i + 2, close + 1):
            t = code[k].text
            if t in "([{" and len(t) == 1:
                depth += 1
            elif t in ")]}" and len(t) == 1 and k != close:
                depth -= 1
            if (t == ";" and depth == 0) or k == close:
                parts.append((start, k - 1) if k - 1 >= start else None)
                start = k + 1
        if len(parts) != 3:
            raise PrepError("structure", "for head")
        body = parse_statement(code, close + 1)
        return SNode("for", i, body.t1, [body], cond=(i + 2, close - 1), parts=parts)
    if text in ("case", "default") and code[i].kind == "ident":
        k, depth = i + 1, 0
        while k < len(code):
            t = code[k].text
            if t in ("(", "[", "{"):
                depth += 1
            elif t in (")", "]", "}"):
                depth -= 1
            elif t == ":" and depth == 0:
                break
            k += 1
        return SNode("caselabel", i, k)
    if code[i].kind == "ident" and text not in KEYWORDS and i + 1 < len(code) and code[i + 1].text == ":":
        body = parse_statement(code, i + 2)
        return SNode("label", i, body.t1, [body])
    k, depth = i, 0
    while k < len(code):
        t = code[k].text
        if t in ("(", "[", "{"):
            depth += 1
        elif t in (")", "]", "}"):
            depth -= 1
            if depth < 0:
                raise PrepError("structure", "unexpected closing bracket")
        elif t == ";" and depth == 0:
            return SNode("simple", i, k)
        k += 1
    raise PrepError("structure", "statement without ;")


def _walk_snodes(node: SNode):
    yield node
    for child in node.children:
        yield from _walk_snodes(child)


# ------------------------------------------------------------------------------ preprocessing
_PP_DEFINES = ["-D__attribute__(x)=", "-D__extension__=", "-D__inline__=inline", "-D__inline=inline",
               "-D__asm__(...)=", "-D__asm(...)=", "-Dasm(...)=", "-D__restrict=", "-D__volatile__=volatile", "-D__const=const",
               "-D_LANGUAGE_C", "-D_MIPS_SZLONG=32", "-D_MIPS_SZINT=32", "-D_MIPS_SZPTR=32"]
_MISSING = re.compile(r"(?m)^[^:\n]*:(\d+):\d+: fatal error: ([^:\n]+): No such file")


_INLINE_ASM = re.compile(r"\b(?:__asm__|__asm|asm)\s*(?:volatile|__volatile__)?\s*\(")
ASM_BARRIER = "__n64dk_asm"


def blank_asm(text: str) -> str:
    """Blank ``__asm__("label")`` aliases; turn inline asm statements into a call of
    ``__n64dk_asm()`` (the analysis treats it as a barrier nothing moves across)."""
    text = ASM_LABEL.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), text)
    out, position = [], 0
    for m in _INLINE_ASM.finditer(text):
        if m.start() < position:
            continue
        depth, k = 0, m.end() - 1
        while k < len(text):
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        out.append(text[position:m.start()])
        out.append(ASM_BARRIER + "()" + "\n" * text.count("\n", m.start(), k + 1))
        position = k + 1
    out.append(text[position:])
    return "".join(out)


def preprocess(text: str, includes: list[str], defines: list[str]) -> tuple[str, list[str]]:
    """(preprocessed text, missing include names)."""
    if len(text.encode()) > int(os.environ.get("N64DK_AST_MAX_SOURCE", 4 * 1024 * 1024)):
        raise PrepError("cpp", "source exceeds the bounded AST preprocessing input size")
    lines = blank_asm(text).split("\n")
    missing: list[str] = []
    cpp = os.environ.get("N64DK_CPP", "cpp")
    timeout = float(os.environ.get("N64DK_AST_CPP_TIMEOUT", "15"))
    for _attempt in range(30):
        try:
            from .. import safety
            proc = safety.run_tool([cpp, "-P", "-nostdinc", "-undef", *_PP_DEFINES, *defines,
                                    *[f"-I{p}" for p in includes], "-"],
                                   kind="light", input="\n".join(lines), capture_output=True, text=True,
                                   timeout=timeout)
        except subprocess.TimeoutExpired:
            raise PrepError("cpp", f"preprocessor timed out after {timeout:g}s") from None
        except OSError as error:
            raise PrepError("cpp", f"cannot run {cpp}: {error}") from None
        if proc.returncode == 0:
            return proc.stdout, missing
        m = _MISSING.search(proc.stderr)
        if not m:
            raise PrepError("cpp", proc.stderr.strip()[-300:])
        number = int(m.group(1)) - 1
        if number >= len(lines) or not lines[number].lstrip().startswith("#"):
            raise PrepError("cpp", f"missing include inside a header: {m.group(2)}")
        missing.append(m.group(2))
        lines[number] = ""
    raise PrepError("cpp", "too many missing includes")


# ------------------------------------------------------------------------------ parsing
_PARSE_AT = re.compile(r":(\d+):(\d+): before: (.*)")


def _parse_with_typedef_retry(text: str, typedefs: list[str]) -> tuple[c_ast.FileAST, list[str]]:
    """Parse; an unknown type name in front of a parse error becomes ``typedef int NAME;``.
    The prelude is always ONE line so coordinates of the rest are stable."""
    added = list(typedefs)
    for _attempt in range(40):
        prelude = " ".join(f"typedef int {n};" for n in added)
        try:
            return c_parser.CParser().parse(prelude + "\n" + text, "<pp>"), added
        except c_parser.ParseError as error:
            m = _PARSE_AT.search(str(error))
            if not m:
                raise PrepError("parse", str(error)[:200])
            line, column = int(m.group(1)) - 2, int(m.group(2)) - 1
            lines = text.split("\n")
            if line < 0 or line >= len(lines):
                raise PrepError("parse", str(error)[:200])
            before = re.findall(r"[A-Za-z_]\w*", lines[line][:column])
            candidate = before[-1] if before else None
            if (candidate is None or candidate in KEYWORDS or candidate in added):
                raise PrepError("parse", str(error)[:200])
            added.append(candidate)
    raise PrepError("parse", "too many unknown type names")


@dataclass
class Env:
    typedefs: dict            # name -> type node
    structs: dict             # tag -> Struct/Union node with decls
    globals: dict             # name -> Decl
    enumerators: set
    typedef_names: list
    volatile_fields: bool


def _build_env(ast: c_ast.FileAST, extra: list[str]) -> Env:
    typedefs, structs, globals_, enumerators, volatile_fields = {}, {}, {}, set(), False

    def walk(node):
        nonlocal volatile_fields
        if isinstance(node, (c_ast.Struct, c_ast.Union)) and node.decls is not None:
            if node.name:
                structs.setdefault(node.name, node)
            for d in node.decls:
                if "volatile" in c_generator.CGenerator().visit(d):
                    volatile_fields = True
        if isinstance(node, c_ast.Enumerator):
            enumerators.add(node.name)
        for _, child in node.children():
            walk(child)

    for ext in ast.ext:
        walk(ext)
        if isinstance(ext, c_ast.Typedef):
            typedefs[ext.name] = ext.type
        elif isinstance(ext, c_ast.Decl) and ext.name:
            globals_[ext.name] = ext
        elif isinstance(ext, c_ast.FuncDef):
            globals_[ext.decl.name] = ext.decl
    for name in extra:
        if name not in typedefs:
            typedefs[name] = c_ast.TypeDecl(name, [], None, c_ast.IdentifierType(["int"]))
    return Env(typedefs, structs, globals_, enumerators, sorted(typedefs), volatile_fields)


_ENV_CACHE: dict[str, tuple[Env, list[str]]] = {}
_PREP_CACHE: dict[tuple, "Prepared"] = {}
_LOCK = threading.Lock()


def _std_prelude(pp: str, missing: list[str]) -> str:
    if not missing:
        return ""
    have = set(re.findall(r"\btypedef\b[^;]*?\b([A-Za-z_]\w*)\s*;", pp))
    used = set(re.findall(r"[A-Za-z_]\w*", pp))
    return "".join(f"typedef {c} {n};" for n, c in STD_TYPEDEFS.items() if n in used and n not in have)


# ------------------------------------------------------------------------------ prepared function
class Prepared:
    """Parsed target function with original-text spans."""

    def __init__(self, source: str, name: str, includes: list[str] | None = None,
                 defines: list[str] | None = None):
        self.source, self.name = source, name
        includes = list(INCLUDE_DIRS if includes is None else includes)
        pp, self.missing_includes = preprocess(source, includes, list(DEFINES if defines is None else defines))
        prelude = _std_prelude(pp, self.missing_includes)
        self.tokens = tokenize(source)
        self.code = code_tokens(self.tokens)
        pp_code = code_tokens(tokenize(pp))
        found_o, found_p = find_function(self.code, name), find_function(pp_code, name)
        if (found_o is None) != (found_p is None):
            # the function name is itself a macro (``#define FUNCTION func_80001234``): pair
            # definitions by position
            lo, lp = list_functions(self.code), list_functions(pp_code)
            if len(lo) == len(lp):
                names = [x[0] for x in (lo if found_o is not None else lp)]
                if names.count(name) == 1:
                    k = names.index(name)
                    found_o, found_p = lo[k][1:], lp[k][1:]
                    name = lp[k][0]
        if found_o is None:
            raise PrepError("function-not-found", f"no definition of {name} in the source")
        if found_p is None:
            raise PrepError("function-not-found", f"{name} disappears after preprocessing")
        o0, ob, oe = found_o
        p0, pb, pe = found_p
        self.fstart, self.fend = self.code[o0].start, self.code[oe].end
        if any(t.kind == "pp" and self.fstart < t.start < self.fend for t in self.tokens):
            raise PrepError("directive-in-function", "preprocessor directive inside the function")
        fs, fe = pp_code[p0].start, pp_code[pe].end
        # ---- environment from everything outside the function (cached)
        outside = prelude + pp[:fs] + ";\n" + pp[fe:]
        key = hashlib.sha256(outside.encode()).hexdigest()
        with _LOCK:
            cached = _ENV_CACHE.get(key)
        if cached is None:
            try:
                ast, extra = _parse_with_typedef_retry(outside, [])
            except PrepError as error:
                raise PrepError("parse-context", error.detail)
            cached = (_build_env(ast, extra), extra)
            with _LOCK:
                if len(_ENV_CACHE) > 64:
                    _ENV_CACHE.clear()
                _ENV_CACHE[key] = cached
        self.env, _extra = cached
        # ---- the function alone, behind a one-line typedef prelude
        line_start = pp.rfind("\n", 0, fs) + 1
        ftext = " " * (fs - line_start) + pp[fs:fe]
        try:
            fast, _added = _parse_with_typedef_retry(ftext, self.env.typedef_names)
        except PrepError as error:
            raise PrepError("parse-function", error.detail)
        self.c_name = name
        defs = [e for e in fast.ext if isinstance(e, c_ast.FuncDef) and e.decl.name == name]
        if len(defs) != 1:
            raise PrepError("parse-function", "function definition not found in parse")
        self.fn: c_ast.FuncDef = defs[0]
        lines = ftext.split("\n")
        starts, total = [], 0
        for line in lines:
            starts.append(total)
            total += len(line) + 1

        def pp_offset(coord) -> int:
            return starts[coord.line - 2] + coord.column - 1 - (fs - line_start) + fs

        self._pp_offset = pp_offset
        # ---- statement trees for both texts, paired by shape
        self.body = parse_statement(self.code, ob)
        pbody = parse_statement(pp_code, pb)
        self._ppc = pp_code
        self._attach(self.fn.body, pbody)
        self._pair(self.body, pbody, pp_code)
        for node in _walk_snodes(self.body):
            node.start, node.end = self.code[node.t0].start, self.code[node.t1].end
            for child in node.children:
                child.parent = node
        # ---- parameters (token ranges in the header)
        self.params = self._params(self.code, o0, ob, pp_code, p0, pb)
        self.header_start = self.code[o0].start
        self.comment_starts = [t.start for t in self.tokens if t.kind == "comment"]

    # -- pairing and attaching
    def _pair(self, o: SNode, p: SNode, pp_code: list[Tok]) -> None:
        """Pair an original statement with its preprocessed counterpart (which carries the
        AST).  Inside blocks, children are aligned by token identity so that statement-level
        macros expanding to several statements become one *opaque* original statement whose
        effects are those of its expansion; opaque statements are moved as text, never re-printed."""
        if o.kind != p.kind or o.has_else != p.has_else or \
                (o.kind != "compound" and len(o.children) != len(p.children)):
            raise PrepError("macro-structure", f"statement shapes differ at line {self.line(self.code[o.t0].start)}")
        texts_o = lambda n: tuple(t.text for t in self.code[n.t0:n.t1 + 1])
        texts_p = lambda n: tuple(t.text for t in pp_code[n.t0:n.t1 + 1])
        o.faithful = texts_o(o) == texts_p(p)
        if o.cond and p.cond:
            o.cond_faithful = [t.text for t in self.code[o.cond[0]:o.cond[1] + 1]] == \
                [t.text for t in pp_code[p.cond[0]:p.cond[1] + 1]]
        o.ast, o.group = p.ast, list(p.group)
        if o.kind != "compound" or len(o.children) == len(p.children):
            pairs = list(zip(o.children, p.children))
            try:
                for a, b in pairs:
                    self._pair(a, b, pp_code)
                return
            except PrepError:
                if o.kind != "compound":
                    raise
        import difflib
        ko, kp = [texts_o(c) for c in o.children], [texts_p(c) for c in p.children]
        matcher = difflib.SequenceMatcher(None, ko, kp, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                for a, b in zip(o.children[i1:i2], p.children[j1:j2]):
                    self._pair(a, b, pp_code)
                continue
            if i2 - i1 == j2 - j1:
                try:
                    for a, b in zip(o.children[i1:i2], p.children[j1:j2]):
                        self._pair(a, b, pp_code)
                    continue
                except PrepError:
                    pass
            run = p.children[j1:j2]
            group = [x for n in run for x in n.group]
            if any(n.ast is None for n in run):
                group = []
            for k, a in enumerate(o.children[i1:i2]):
                a.ast, a.faithful, a.opaque = None, False, True
                a.group = group if k == 0 else []
                a.children_opaque = True
                if k > 0 or not group:
                    a.group = []
                    a.barrier = True

    def _attach(self, ast, pnode: SNode) -> None:
        kinds = {c_ast.Compound: "compound", c_ast.If: "if", c_ast.While: "while", c_ast.DoWhile: "do",
                 c_ast.For: "for", c_ast.Switch: "switch", c_ast.Label: "label",
                 c_ast.Case: "caselabel", c_ast.Default: "caselabel"}
        kind = kinds.get(type(ast), "simple")
        if kind != pnode.kind:
            raise PrepError("mapping", f"{type(ast).__name__} vs {pnode.kind}")
        pnode.ast, pnode.group = ast, [ast]
        if kind == "compound":
            items = ast.block_items or []
            k = 0
            for pc in pnode.children:
                if k >= len(items):
                    raise PrepError("mapping", "fewer AST items than statements")
                if pc.kind == "simple" and isinstance(items[k], c_ast.Decl):
                    group = [items[k]]
                    k += 1
                    lo, hi = self._pp_tok_start(pc), self._pp_tok_end(pc)
                    while k < len(items) and isinstance(items[k], c_ast.Decl) and items[k].coord and \
                            lo <= self._pp_offset(items[k].coord) < hi:
                        group.append(items[k])
                        k += 1
                    pc.ast, pc.group = group[0], group
                    continue
                self._attach(items[k], pc)
                k += 1
            if k != len(items):
                raise PrepError("mapping", "unmatched AST items in block")
        elif kind == "if":
            self._attach(ast.iftrue, pnode.children[0])
            if pnode.has_else:
                if ast.iffalse is None:
                    raise PrepError("mapping", "else")
                self._attach(ast.iffalse, pnode.children[1])
        elif kind in ("while", "do", "for", "label"):
            self._attach(ast.stmt, pnode.children[0])
        # switch bodies and case labels are opaque: kept as text, never entered

    def _pp_tok_start(self, pnode):
        return self._ppc[pnode.t0].start

    def _pp_tok_end(self, pnode):
        return self._ppc[pnode.t1].end

    def _params(self, code, o0, ob, pp_code, p0, pb):
        def split(tokens, close):
            open_ = close
            depth = 0
            for k in range(close, -1, -1):
                t = tokens[k].text
                if t == ")":
                    depth += 1
                elif t == "(":
                    depth -= 1
                    if depth == 0:
                        open_ = k
                        break
            out, start, depth = [], open_ + 1, 0
            for k in range(open_ + 1, close + 1):
                t = tokens[k].text
                if t in "([" and len(t) == 1:
                    depth += 1
                elif t in ")]" and len(t) == 1 and k != close:
                    depth -= 1
                if (t == "," and depth == 0) or k == close:
                    out.append((start, k - 1))
                    start = k + 1
            return out
        oparts, pparts = split(code, ob - 1), split(pp_code, pb - 1)
        params = (self.fn.decl.type.args.params if self.fn.decl.type.args else [])
        result = []
        if len(oparts) == len(pparts) == len(params):
            for (a, b), (c, d), param in zip(oparts, pparts, params):
                if b < a:
                    continue
                faithful = [t.text for t in code[a:b + 1]] == [t.text for t in pp_code[c:d + 1]]
                result.append((param, code[a].start, code[b].end, faithful))
        return result

    # -- helpers
    def line(self, offset: int) -> int:
        return self.source.count("\n", 0, offset) + 1

    def indent_at(self, offset: int) -> str:
        start = self.source.rfind("\n", 0, offset) + 1
        m = re.match(r"[ \t]*", self.source[start:])
        return m.group()

    def starts_line(self, offset: int) -> bool:
        start = self.source.rfind("\n", 0, offset) + 1
        return self.source[start:offset].strip() == ""

    def has_comment(self, start: int, end: int) -> bool:
        return any(start <= c < end for c in self.comment_starts)

    def text(self, node: SNode) -> str:
        return self.source[node.start:node.end]

    def cond_span(self, node: SNode) -> tuple[int, int]:
        a, b = node.cond
        if b < a:
            p = self.code[a - 1].end
            return p, p
        return self.code[a].start, self.code[b].end

    def part_span(self, node: SNode, index: int) -> tuple[int, int] | None:
        part = node.parts[index]
        if part is None:
            return None
        return self.code[part[0]].start, self.code[part[1]].end

    def printable(self, node: SNode) -> bool:
        return node.faithful and not self.has_comment(node.start, node.end) and len(node.group) == 1

    def cond_printable(self, node: SNode) -> bool:
        a, b = self.cond_span(node)
        return node.cond_faithful and not self.has_comment(a, b)


def onode_start(prep: Prepared, node: SNode) -> int:
    return prep.code[node.t0].start


def prepare(source: str, name: str, includes: list[str] | None = None,
            defines: list[str] | None = None) -> Prepared:
    key = (hashlib.sha256(source.encode()).hexdigest(), name,
           tuple(INCLUDE_DIRS if includes is None else includes), tuple(DEFINES if defines is None else defines))
    with _LOCK:
        hit = _PREP_CACHE.get(key)
    if hit is not None:
        return hit
    prepared = Prepared(source, name, includes, defines)
    with _LOCK:
        if len(_PREP_CACHE) > 512:
            _PREP_CACHE.clear()
        _PREP_CACHE[key] = prepared
    return prepared


# ------------------------------------------------------------------------------ printing
def gen() -> c_generator.CGenerator:
    return c_generator.CGenerator(reduce_parentheses=True)


def expr_text(node) -> str:
    return gen().visit(node)


def simple_stmt_text(node) -> str:
    """One-line C for a simple (non-compound) statement AST."""
    if isinstance(node, c_ast.Return):
        return "return;" if node.expr is None else f"return {expr_text(node.expr)};"
    if isinstance(node, c_ast.Break):
        return "break;"
    if isinstance(node, c_ast.Continue):
        return "continue;"
    if isinstance(node, c_ast.Goto):
        return f"goto {node.name};"
    if isinstance(node, c_ast.EmptyStatement):
        return ";"
    return expr_text(node) + ";"


def reindent(text: str, old: str, new: str) -> str:
    """Re-indent continuation lines of ``text`` (whose first line is already placed) from the
    base indentation ``old`` to ``new``."""
    lines = text.split("\n")
    out = [lines[0]]
    for line in lines[1:]:
        if line.startswith(old):
            out.append(new + line[len(old):])
        elif line.strip() == "":
            out.append(line)
        else:
            out.append(new + line.lstrip())
    return "\n".join(out)


def apply_edits(source: str, edits: list[tuple[int, int, str]]) -> str:
    edits = sorted(edits, key=lambda e: (e[0], e[1]))
    for (a0, a1, _), (b0, b1, _) in zip(edits, edits[1:]):
        if b0 < a1:
            raise ValueError("overlapping edits")
    out, position = [], 0
    for start, end, text in edits:
        out.append(source[position:start])
        out.append(text)
        position = end
    out.append(source[position:])
    return "".join(out)
