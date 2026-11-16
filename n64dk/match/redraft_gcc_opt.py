"""Rewrites of a decompiler draft for code built by GCC 2.x with optimisation (-O1/-O2).

An optimising GCC keeps nothing of the source's layout in the frame, so what separates a draft
from the original is not where the locals live but which *source form* was written: the
decompiler renders the instructions it saw, and several of its renderings are not the C that
produces those instructions.  Every rule here is decided by the target's machine code and
rewrites the draft's syntax tree; nothing is searched for.

Rules (each is described where it is implemented):

``bytes``    pointer arithmetic the decompiler wrote in bytes on a pointer whose type has a
             larger element (``&D_80089A6C + (i * 0x4C)`` with ``D`` an ``s32``): C scales it,
             the target does not.  The arithmetic is made byte-wise; a dereference takes the
             width of the load or store the target performs on that address.
``symbols``  a constant the target builds with ``lui``/``addiu``.  GCC builds an integer with
             ``lui``/``ori`` and only an address with ``lui``/``addiu``, so the constant is the
             address of a symbol the linker placed (a ROM offset, a segment address).
``passed``   a call for which the target sets a higher argument register and leaves a lower one
             exactly as the function received it: the lower one is passed through.  The
             decompiler drops it; the call gets it back and the function its parameter.
"""
from __future__ import annotations

import copy
import re
import threading

try:                                                        # the parser is optional for the kit
    from pycparser import c_ast, c_generator, c_parser
except Exception:                                           # pragma: no cover
    c_ast = c_generator = c_parser = None

from ..analysis import flow as flowmod

MAX_VARIANTS = 6
_TYPE_ARGUMENT = {"M2C_FIELD": 1, "M2C_BITWISE": 0}         # macros that take a type name as an argument
_LOCK = threading.Lock()
_PARSER = None
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_LOADS = {"lb": "s8", "lbu": "u8", "lh": "s16", "lhu": "u16", "lw": "s32", "lwu": "u32", "lwc1": "f32",
          "ldc1": "f64", "ld": "s64"}
_STORES = {"sb": 1, "sh": 2, "sw": 4, "swc1": 4, "sdc1": 8, "sd": 8}
_SIZES = {"s8": 1, "u8": 1, "s16": 2, "u16": 2, "s32": 4, "u32": 4, "f32": 4, "f64": 8, "s64": 8, "u64": 8}


# --------------------------------------------------------------------------------- situation
def _optimised_gcc(pipeline: str, flags: tuple[str, ...], family: str | None, insns) -> bool:
    """GCC family, and the code is not an unoptimised build (which addresses its frame through
    ``$fp`` set from ``$sp`` in the prologue)."""
    if family == "ido" or (family is None and pipeline.startswith("ido")):
        return False
    for insn in insns[:12]:
        word = insn.word
        # addu/or/daddu $fp, $sp, $zero
        if word >> 26 == 0 and (word >> 11) & 31 == 30 and (word & 0x3F) in (0x21, 0x25, 0x2D) and \
                {(word >> 21) & 31, (word >> 16) & 31} == {29, 0}:
            return False
    if family is None and not pipeline.startswith(("kmc", "sn", "gcc", "custom")):
        return False
    return True


# --------------------------------------------------------------------------------- the draft
def _blank_comments(text: str) -> str:
    return _COMMENT.sub(lambda found: re.sub(r"[^\n]", " ", found.group(0)), text)


def _split_arguments(text: str) -> list[tuple[int, int]]:
    """Spans of the top-level comma separated parts of ``text``."""
    out, depth, start = [], 0, 0
    for index, char in enumerate(text):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            out.append((start, index))
            start = index + 1
    out.append((start, len(text)))
    return out


def _wrap_type_arguments(text: str) -> str | None:
    """``M2C_FIELD(e, T, off)`` -> ``M2C_FIELD(e, (T)0, off)`` so that a C parser accepts it."""
    found = [m for m in re.finditer(r"\b(M2C_FIELD|M2C_BITWISE)\s*\(", text)]
    for match in reversed(found):                           # inner calls first
        depth, position = 1, match.end()
        while position < len(text) and depth:
            depth += (text[position] == "(") - (text[position] == ")")
            position += 1
        if depth:
            return None
        inside = text[match.end():position - 1]
        spans = _split_arguments(inside)
        index = _TYPE_ARGUMENT[match.group(1)]
        if index >= len(spans):
            return None
        a, b = spans[index]
        inside = f"{inside[:a]} ({inside[a:b].strip()})0{inside[b:]}"
        text = text[:match.end()] + inside + text[position - 1:]
    return text


class _Generator(c_generator.CGenerator if c_generator else object):
    """Prints the type-taking macros back in their macro form."""

    def visit_FuncCall(self, n):
        name = n.name.name if isinstance(n.name, c_ast.ID) else None
        if name in _TYPE_ARGUMENT and n.args is not None:
            parts = []
            for index, argument in enumerate(n.args.exprs):
                if index == _TYPE_ARGUMENT[name] and isinstance(argument, c_ast.Cast):
                    parts.append(self._generate_type(argument.to_type, emit_declname=False))
                else:
                    parts.append(self._visit_expr(argument))
            return f"{name}({', '.join(parts)})"
        return super().visit_FuncCall(n)


def _parse(text: str):
    global _PARSER
    with _LOCK:
        if _PARSER is None:
            _PARSER = c_parser.CParser()
        return _PARSER.parse(text, "<draft>")


def _type(names: str, pointers: int = 0):
    """A type node for ``names`` (space separated identifier words) with ``pointers`` stars."""
    node = c_ast.TypeDecl(None, [], None, c_ast.IdentifierType(names.split()))
    for _ in range(pointers):
        node = c_ast.PtrDecl([], node)
    return node


def _typename(node) -> "c_ast.Typename":
    return c_ast.Typename(None, [], None, _undeclared(node))


def _undeclared(node):
    """A copy of a declaration's type without the declared name (for a cast)."""
    node = copy.deepcopy(node)
    cursor = node
    while cursor is not None:
        if isinstance(cursor, c_ast.TypeDecl):
            cursor.declname = None
            break
        cursor = getattr(cursor, "type", None)
    return node


def _cast(type_node, expression):
    return c_ast.Cast(_typename(type_node), expression)


def _number(node) -> int | None:
    """Value of an integer constant expression made of a literal and unary minus."""
    if isinstance(node, c_ast.UnaryOp) and node.op == "-":
        inner = _number(node.expr)
        return None if inner is None else -inner
    if isinstance(node, c_ast.Constant) and node.type in ("int", "long int", "unsigned int", "unsigned long int",
                                                          "long long int", "unsigned long long int"):
        try:
            return int(node.value.rstrip("uUlL"), 0)
        except ValueError:
            return None
    return None


def _function_span(source: str, name: str) -> tuple[int, int]:
    """(start of the definition's first line, offset of its closing brace)."""
    blank = _blank_comments(source)
    found = re.search(rf"(?m)^[A-Za-z_][\w \t\*]*?\b{re.escape(name)}\s*\([^;{{}}]*\)\s*\{{", blank)
    if found is None:
        raise ValueError("function not found")
    depth, position = 0, found.end() - 1
    while position < len(blank):
        depth += (blank[position] == "{") - (blank[position] == "}")
        if depth == 0:
            return found.start(), position
        position += 1
    raise ValueError("function not closed")


class Draft:
    """A draft split into the text before the function, the function's syntax tree and the rest."""

    def __init__(self, source: str, name: str):
        if c_parser is None:
            raise ValueError("no parser")
        start, close = _function_span(source, name)
        self.name = name
        self.head, self.tail = source[:start], source[close + 1:]
        function = source[start:close + 1]
        # everything up to the last preprocessor line is kept verbatim; typedefs in it are read
        lines = self.head.split("\n")
        last = max((i for i, line in enumerate(lines) if line.lstrip().startswith("#")), default=-1)
        prelude, declarations = "\n".join(lines[:last + 1]), "\n".join(lines[last + 1:])
        typedefs = " ".join(re.findall(r"\btypedef\b[^;{}#]*;", _blank_comments(prelude)))
        text = _wrap_type_arguments(_blank_comments(declarations + "\n" + function))
        if text is None or "#" in text:
            raise ValueError("not parseable")
        self.ast = _parse(typedefs + "\n" + text)
        self.typedefs: dict[str, object] = {}
        self.structs: dict[str, object] = {}
        self.globals: dict[str, object] = {}
        self.function = None
        for item in self.ast.ext:
            self._collect_structs(item)
            if isinstance(item, c_ast.Typedef):
                self.typedefs[item.name] = item.type
            elif isinstance(item, c_ast.FuncDef):
                if item.decl.name == name:
                    self.function = item
                self.globals[item.decl.name] = item.decl.type
            elif isinstance(item, c_ast.Decl) and item.name:
                self.globals.setdefault(item.name, item.type)
        if self.function is None or self.function.body is None:
            raise ValueError("function not parsed")
        self.added: list[str] = []                           # declarations to place before the function
        self.dropped: set[str] = set()                       # global declarations replaced by ``added``
        self.locals: dict[str, object] = {}
        self._collect_locals()

    # -- declarations
    def _collect_structs(self, node) -> None:
        if isinstance(node, (c_ast.Struct, c_ast.Union)) and node.decls is not None and node.name:
            self.structs.setdefault(node.name, node)
        for _name, child in node.children():
            self._collect_structs(child)

    def _collect_locals(self) -> None:
        self.locals = {}
        arguments = self.function.decl.type.args
        for parameter in (arguments.params if arguments else []):
            if isinstance(parameter, c_ast.Decl) and parameter.name:
                self.locals[parameter.name] = parameter.type

        def walk(node):
            if isinstance(node, c_ast.Decl) and node.name and not isinstance(node.type, c_ast.FuncDecl):
                self.locals.setdefault(node.name, node.type)
            for _name, child in node.children():
                walk(child)
        walk(self.function.body)

    def parameters(self) -> list:
        arguments = self.function.decl.type.args
        out = []
        for parameter in (arguments.params if arguments else []):
            if isinstance(parameter, c_ast.Typename) or (isinstance(parameter, c_ast.Decl) and not parameter.name):
                continue                                     # (void)
            out.append(parameter)
        return out

    # -- types
    def resolve(self, node, depth: int = 0):
        while depth < 30 and isinstance(node, c_ast.TypeDecl) and isinstance(node.type, c_ast.IdentifierType) \
                and len(node.type.names) == 1 and node.type.names[0] in self.typedefs:
            node, depth = self.typedefs[node.type.names[0]], depth + 1
        if isinstance(node, c_ast.Typename):
            return self.resolve(node.type, depth + 1)
        return node

    def size_of(self, node, depth: int = 0) -> int | None:
        node = self.resolve(node)
        if node is None or depth > 12:
            return None
        if isinstance(node, c_ast.PtrDecl):
            return 4
        if isinstance(node, c_ast.ArrayDecl):
            count, element = _number(node.dim) if node.dim is not None else None, self.size_of(node.type, depth + 1)
            return None if count is None or element is None else count * element
        if isinstance(node, c_ast.TypeDecl):
            inner = node.type
            if isinstance(inner, c_ast.IdentifierType):
                names = inner.names
                if "void" in names or "char" in names:
                    return 1
                if "short" in names:
                    return 2
                if "double" in names or names.count("long") >= 2:
                    return 8
                return 4
            if isinstance(inner, c_ast.Enum):
                return 4
            if isinstance(inner, (c_ast.Struct, c_ast.Union)):
                layout = self.layout(inner, depth + 1)
                return None if layout is None else layout[0]
        return None

    def align_of(self, node, depth: int = 0) -> int | None:
        node = self.resolve(node)
        if isinstance(node, c_ast.ArrayDecl):
            return self.align_of(node.type, depth + 1)
        if isinstance(node, c_ast.TypeDecl) and isinstance(node.type, (c_ast.Struct, c_ast.Union)):
            layout = self.layout(node.type, depth + 1)
            return None if layout is None else layout[1]
        size = self.size_of(node, depth + 1)
        return None if size is None else min(size, 8)

    def layout(self, struct, depth: int = 0):
        """(size, alignment, {field: (offset, type)}) of a struct or union, or None."""
        if struct.decls is None:
            struct = self.structs.get(struct.name)
            if struct is None:
                return None
        offset, alignment, fields = 0, 1, {}
        union = isinstance(struct, c_ast.Union)
        extent = 0
        for field in struct.decls:
            if not isinstance(field, c_ast.Decl) or field.bitsize is not None:
                return None
            size, align = self.size_of(field.type, depth + 1), self.align_of(field.type, depth + 1)
            if size is None or not align:
                return None
            if not union:
                offset = (offset + align - 1) // align * align
            fields[field.name] = (0 if union else offset, field.type)
            extent = max(extent, (0 if union else offset) + size)
            if not union:
                offset += size
            alignment = max(alignment, align)
        return (extent + alignment - 1) // alignment * alignment, alignment, fields

    def pointee(self, node):
        """The element type when ``node`` is a pointer or an array, else None."""
        node = self.resolve(node)
        if isinstance(node, (c_ast.PtrDecl, c_ast.ArrayDecl)):
            return node.type
        return None

    def is_float(self, node) -> bool:
        node = self.resolve(node)
        return isinstance(node, c_ast.TypeDecl) and isinstance(node.type, c_ast.IdentifierType) and \
            bool({"float", "double"} & set(node.type.names))

    def type_of(self, node, depth: int = 0):
        """The C type of an expression as a declaration type node, or None when unknown."""
        if depth > 60:
            return None
        if isinstance(node, c_ast.ID):
            return self.locals.get(node.name, self.globals.get(node.name))
        if isinstance(node, c_ast.Constant):
            if node.type in ("float", "double", "long double"):
                return _type("float" if node.value.rstrip().endswith(("f", "F")) else "double")
            if node.type == "string":
                return _type("char", 1)
            return _type("int")
        if isinstance(node, c_ast.Cast):
            return node.to_type.type
        if isinstance(node, c_ast.UnaryOp):
            inner = self.type_of(node.expr, depth + 1)
            if node.op == "&":
                return None if inner is None else c_ast.PtrDecl([], inner)
            if node.op == "*":
                return self.pointee(inner)
            if node.op in ("!", "sizeof"):
                return _type("int")
            return inner
        if isinstance(node, c_ast.BinaryOp):
            if node.op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return _type("int")
            left, right = self.type_of(node.left, depth + 1), self.type_of(node.right, depth + 1)
            if node.op in ("+", "-"):
                if self.pointee(left) is not None and self.pointee(right) is not None:
                    return _type("int")
                if self.pointee(left) is not None:
                    return c_ast.PtrDecl([], self.pointee(left))
                if self.pointee(right) is not None and node.op == "+":
                    return c_ast.PtrDecl([], self.pointee(right))
            if node.op in ("<<", ">>"):
                return left
            for side in (left, right):
                if side is not None and self.is_float(side):
                    return side
            return left if left is not None else right
        if isinstance(node, c_ast.Assignment):
            return self.type_of(node.lvalue, depth + 1)
        if isinstance(node, c_ast.TernaryOp):
            found = self.type_of(node.iftrue, depth + 1)
            return found if found is not None else self.type_of(node.iffalse, depth + 1)
        if isinstance(node, c_ast.FuncCall):
            name = node.name.name if isinstance(node.name, c_ast.ID) else None
            if name in _TYPE_ARGUMENT and node.args is not None:
                index = _TYPE_ARGUMENT[name]
                if index < len(node.args.exprs) and isinstance(node.args.exprs[index], c_ast.Cast):
                    stated = node.args.exprs[index].to_type.type
                    return self.pointee(stated) if name == "M2C_FIELD" else stated
                return None
            callee = self.resolve(self.type_of(node.name, depth + 1))
            if isinstance(callee, c_ast.PtrDecl):
                callee = self.resolve(callee.type)
            return callee.type if isinstance(callee, c_ast.FuncDecl) else None
        if isinstance(node, c_ast.ArrayRef):
            return self.pointee(self.type_of(node.name, depth + 1))
        if isinstance(node, c_ast.StructRef):
            base = self.resolve(self.type_of(node.name, depth + 1))
            if node.type == "->":
                base = self.resolve(self.pointee(base))
            if isinstance(base, c_ast.TypeDecl) and isinstance(base.type, (c_ast.Struct, c_ast.Union)):
                layout = self.layout(base.type)
                if layout is not None and node.field.name in layout[2]:
                    return layout[2][node.field.name][1]
            return None
        if isinstance(node, c_ast.ExprList) and node.exprs:
            return self.type_of(node.exprs[-1], depth + 1)
        return None

    # -- output
    def text(self) -> str:
        head = self.head
        if self.dropped:
            kept = []
            for line in head.split("\n"):
                found = re.match(r"^(?:extern\s+)?[\w \*]+?\b(\w+)\s*(?:\([^{]*\)|\[[^\]]*\])?;", line)
                if found and found.group(1) in self.dropped and "{" not in line:
                    continue
                kept.append(line)
            head = "\n".join(kept)
        if self.added:
            head = head.rstrip("\n") + "\n" + "\n".join(dict.fromkeys(self.added)) + "\n\n"
        return head + _Generator().visit(self.function) + self.tail


def _replace(root, old, new) -> bool:
    """Replace the node ``old`` (by identity) below ``root`` with ``new``."""
    for node in _walk(root):
        for slot in node.__slots__:
            if slot in ("coord", "__weakref__"):
                continue
            value = getattr(node, slot, None)
            if value is old:
                setattr(node, slot, new)
                return True
            if isinstance(value, list):
                for index, item in enumerate(value):
                    if item is old:
                        value[index] = new
                        return True
    return False


def _walk(node):
    yield node
    for _name, child in node.children():
        yield from _walk(child)


# --------------------------------------------------------------------------------- machine code
INCOMING, SET, STALE, MIXED = 0, 1, 2, 3


def _argument_writes(insn, state: list) -> None:
    """Record what ``insn`` writes of the argument registers ($a0-$a3 -> 0-3, $f12 -> 4, $f14 -> 5)."""
    for register in insn.defs:
        if 4 <= register <= 7:
            state[register - 4] = SET
    word = insn.word
    opcode = word >> 26
    written = None
    if opcode in (0x31, 0x35):                               # lwc1, ldc1
        written = (word >> 16) & 31
    elif opcode == 0x11:
        kind = (word >> 21) & 31
        if kind in (4, 5):                                   # mtc1, dmtc1
            written = (word >> 11) & 31
        elif kind in (16, 17, 20, 21) and (word & 0x3F) < 0x30:
            written = (word >> 6) & 31
    if written in (12, 13):
        state[4] = SET
    elif written in (14, 15):
        state[5] = SET


class Code:
    """Facts read from the target's instructions."""

    def __init__(self, code: bytes, vram: int):
        self.vram = vram
        self._code = code
        self._sites = None
        self.insns = flowmod.decode(code, vram)
        self.addresses: dict[int, int] = {}                  # value built by lui/addiu -> times
        self.integers: dict[int, int] = {}                   # value built by lui/ori -> times
        self.accesses: dict[int, set[str]] = {}              # absolute address -> load/store mnemonics
        self.frame_accesses = 0                              # loads from the frame that restore no register
        self.events: list[tuple[int, str, str, int]] = []    # (instruction, mnemonic, "at"|"off", address|offset)
        self._pairs()
        self._frame()

    def _pairs(self) -> None:
        upper: dict[int, int] = {}                           # register -> value of a pending lui
        indexed: dict[int, int] = {}                         # register -> lui value after ``addu r, r, x``
        for insn in self.insns:
            word = insn.word
            opcode, rs, rt, immediate = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
            signed = immediate - 0x10000 if immediate & 0x8000 else immediate
            if opcode == 0x0F:                               # lui
                upper[rt] = immediate << 16
                indexed.pop(rt, None)
                continue
            if opcode == 0x09 and rs == rt and rs in upper:  # addiu r, r, lo
                value = (upper.pop(rs) + signed) & 0xFFFFFFFF
                self.addresses[value] = self.addresses.get(value, 0) + 1
                continue
            if opcode == 0x0D and rs == rt and rs in upper:  # ori r, r, lo
                value = (upper.pop(rs) | immediate) & 0xFFFFFFFF
                self.integers[value] = self.integers.get(value, 0) + 1
                continue
            if insn.op in _LOADS or insn.op in _STORES:
                base = upper.get(rs, indexed.get(rs))
                if base is not None:
                    self.accesses.setdefault((base + signed) & 0xFFFFFFFF, set()).add(insn.op)
                    self.events.append((insn.index, insn.op, "at", (base + signed) & 0xFFFFFFFF))
                elif rs != 29:
                    self.events.append((insn.index, insn.op, "off", signed))
            if opcode == 0 and (word & 0x7FF) == 0x21:       # addu rd, rs, rt
                rd = (word >> 11) & 31
                for a, b in ((rs, rt), (rt, rs)):
                    if rd == a and a in upper and b not in upper:
                        indexed[rd] = upper.pop(a)
                        break
                else:
                    upper.pop(rd, None)
                    indexed.pop(rd, None)
                continue
            for register in insn.defs:
                if insn.op in _LOADS and register == rs:
                    pass
                upper.pop(register, None)
                indexed.pop(register, None)

    def _frame(self) -> None:
        """Count reads of the function's own frame other than the epilogue's restores: a local
        that lives in memory (its address was taken) or an argument that arrived on the stack."""
        saved = set()
        for insn in self.insns:
            word = insn.word
            opcode, base, register, offset = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
            if base != 29 or offset & 0x8000:
                continue
            if opcode in (0x2B, 0x3F) and (register in (31, 30) or 16 <= register <= 23):   # sw/sd of a saved register
                saved.add((register, offset))
            elif insn.op in _LOADS and not (opcode in (0x23, 0x37) and (register, offset) in saved):
                self.frame_accesses += 1

    def call_sites(self) -> list[tuple[int | None, tuple[int, ...]]]:
        """For every call in address order: (target address or None, the state of ``$a0-$a3`` and
        of ``$f12``/``$f14`` when control leaves for the callee).

        A state says where the register's value comes from: ``INCOMING`` (untouched since the
        function was entered, so it still holds the function's own argument), ``SET`` (written
        since the previous call), ``STALE`` (a call returned since it was last written) or
        ``MIXED`` (it depends on the path)."""
        if self._sites is not None:
            return self._sites
        flow = flowmod.analyse(bytes(self._code), self.vram)
        insns, blocks = flow.insns, flow.blocks
        entry: list[tuple[int, ...] | None] = [None] * len(blocks)
        found: dict[int, tuple[int, ...]] = {}
        if blocks:
            entry[0] = (INCOMING,) * 6
        work = [0] if blocks else []
        while work:
            number = work.pop()
            block, state = blocks[number], list(entry[number])
            index = block.first
            while index <= block.last:
                insn = insns[index]
                if insn.kind == "call":
                    if index + 1 <= block.last:
                        _argument_writes(insns[index + 1], state)
                    found[index] = tuple(state)
                    state = [STALE] * 6
                    index += 2
                    continue
                _argument_writes(insn, state)
                index += 1
            for successor in block.succs:
                merged = tuple(state) if entry[successor] is None else tuple(
                    a if a == b else MIXED for a, b in zip(entry[successor], state))
                if merged != entry[successor]:
                    entry[successor] = merged
                    work.append(successor)
        self._sites = [(insn.target, found.get(insn.index, (MIXED,) * 6)) for insn in insns if insn.kind == "call"]
        return self._sites

    def access_type(self, address: int, declared_size: int | None, declared_unsigned: bool) -> str | None:
        """The type the target reads or writes at ``address`` with, when it uses one width."""
        operations = self.accesses.get(address)
        if not operations:
            return None
        loads = {_LOADS[o] for o in operations if o in _LOADS}
        widths = {_SIZES[t] for t in loads} | {_STORES[o] for o in operations if o in _STORES}
        if len(widths) != 1 or len(loads) > 1:
            return None
        if loads:
            return loads.pop()
        width = widths.pop()
        if any(o in ("swc1", "sdc1") for o in operations):
            return "f32" if width == 4 else "f64"
        if declared_size == width:
            return None
        return {1: "u8" if declared_unsigned else "s8", 2: "u16" if declared_unsigned else "s16", 4: "s32",
                8: "s64"}[width]


# --------------------------------------------------------------------------------- rule: bytes
def _symbol_address(node) -> int | None:
    """Address stated by the name of the global a pointer expression starts from."""
    if isinstance(node, c_ast.UnaryOp) and node.op == "&":
        node = node.expr
    if isinstance(node, c_ast.ID):
        found = re.fullmatch(r"D_([0-9A-Fa-f]{8})", node.name)
        if found:
            return int(found.group(1), 16)
    return None


def byte_arithmetic(draft: Draft, code: Code) -> int:
    """Make additions to a pointer with a wide element byte-wise, as the decompiler meant them.

    The decompiler writes every address computation in bytes.  When the operand happens to have a
    pointer type whose element is wider than a byte (``&D`` of an ``s32``, a parameter it typed
    ``s32 *`` because it is dereferenced), C multiplies the offset by the element size and the
    build computes another address.  ``p + n`` becomes ``(T *) ((s8 *) p + n)``; ``p += n`` with a
    constant multiple of the element size becomes ``p += n / size``.  A dereference of the sum of
    a global's address takes the type of the access the target makes at that address."""
    changed = 0
    body = draft.function.body
    byte = _type("s8", 1)

    def wide(expression):
        kind = draft.type_of(expression)
        element = draft.pointee(kind)
        if element is None:
            return None
        size = draft.size_of(element)
        if size is None or size <= 1:
            return None
        return c_ast.PtrDecl([], element), size

    nodes = list(_walk(body))
    parents = {}
    for node in nodes:
        for _name, child in node.children():
            parents[id(child)] = node
    for node in nodes:
        if isinstance(node, c_ast.Assignment) and node.op in ("+=", "-="):
            found = wide(node.lvalue)
            if found is None or draft.pointee(draft.type_of(node.rvalue)) is not None:
                continue
            kind, size = found
            amount = _number(node.rvalue)
            if amount is not None and amount % size == 0 and amount != 0:
                value = abs(amount) // size
                node.rvalue = c_ast.Constant("int", str(value) if value < 10 else hex(value).upper().replace("X", "x"))
                if amount < 0:
                    node.op = "-=" if node.op == "+=" else "+="
            else:
                node.rvalue = _cast(kind, c_ast.BinaryOp(node.op[0], _cast(byte, copy.deepcopy(node.lvalue)),
                                                         node.rvalue))
                node.op = "="
            changed += 1
        elif isinstance(node, c_ast.BinaryOp) and node.op in ("+", "-"):
            left, right = wide(node.left), wide(node.right)
            if left is not None and draft.pointee(draft.type_of(node.right)) is None:
                side, (kind, _size) = "left", left
            elif right is not None and node.op == "+" and draft.pointee(draft.type_of(node.left)) is None:
                side, (kind, _size) = "right", right
            else:
                continue
            pointer = getattr(node, side)
            address = _symbol_address(pointer)
            # ``n + (s8 *) p`` would be reordered to pointer-first by the compiler; an integer
            # addition keeps the operands in the order the target adds them
            setattr(node, side, _cast(byte if side == "left" else _type("s32"), pointer))
            parent = parents.get(id(node))
            result = kind
            if address is not None and isinstance(parent, c_ast.UnaryOp) and parent.op == "*":
                # the target's own access to this address decides the width
                element = draft.resolve(kind.type)
                names = element.type.names if isinstance(element, c_ast.TypeDecl) and \
                    isinstance(element.type, c_ast.IdentifierType) else []
                stated = code.access_type(address, draft.size_of(kind.type), "unsigned" in names)
                if stated is not None and (draft.size_of(kind.type) != _SIZES[stated] or stated in ("f32", "f64")
                                           or (stated.startswith("u") != ("unsigned" in names)
                                               and _SIZES[stated] < 4)):
                    result = _type(stated, 1)
            replacement = _cast(result, copy.copy(node))
            if parent is not None and _replace(parent, node, replacement):
                # the copy now stands in the tree: later visits must see it, not ``node``
                parents[id(replacement)] = parent
                parents[id(replacement.expr)] = replacement
                for _name, child in replacement.expr.children():
                    parents[id(child)] = replacement.expr
                changed += 1
            else:
                setattr(node, side, pointer)
    return changed


# --------------------------------------------------------------------------------- rule: symbols
def symbol_addresses(draft: Draft, code: Code) -> int:
    """Turn a constant the target builds with ``lui``/``addiu`` into the address of a symbol.

    GCC loads an integer constant with ``lui``/``ori`` and an address with ``lui``/``addiu``
    (the assembler's expansion of ``la``).  A draft that shows such a value as a number therefore
    cannot match: the source named something the linker placed there (a ROM offset, a segment
    address).  The number becomes ``(s32) &D_<address>``, declared here; the name states its own
    address, which is what lets the verifier accept it."""
    wanted = {value for value in code.addresses if value not in code.integers}
    if not wanted:
        return 0
    changed = 0
    nodes = list(_walk(draft.function.body))
    parents = {}
    for node in nodes:
        for _name, child in node.children():
            parents[id(child)] = node
    for node in nodes:
        if not isinstance(node, c_ast.Constant):
            continue
        value = _number(node)
        if value is None:
            continue
        parent = parents.get(id(node))
        target = node
        if isinstance(parent, c_ast.UnaryOp) and parent.op == "-":
            value, target = -value, parent
            parent = parents.get(id(parent))
        value &= 0xFFFFFFFF
        if value not in wanted or value < 0x10000 or parent is None:
            continue
        symbol = f"D_{value:08X}"
        if symbol in draft.locals:
            continue
        replacement = _cast(_type("s32"), c_ast.UnaryOp("&", c_ast.ID(symbol)))
        if _replace(parent, target, replacement):
            if symbol not in draft.globals:
                draft.added.append(f"extern M2C_UNK {symbol};")
                draft.globals[symbol] = _type("M2C_UNK")
            changed += 1
    return changed


# --------------------------------------------------------------------------------- rule: passed
_MACRO_CALL = re.compile(r"M2C_\w+|MULTU?_HI")


def _calls(draft: Draft) -> list:
    """The function's calls in evaluation order (the arguments of a call before the call)."""
    out = []

    def walk(node):
        for _name, child in node.children():
            walk(child)
        if isinstance(node, c_ast.FuncCall):
            name = node.name.name if isinstance(node.name, c_ast.ID) else None
            if name is None or not _MACRO_CALL.fullmatch(name):
                out.append(node)
    walk(draft.function.body)
    return out


def _pair_calls(draft: Draft, code: Code) -> list[tuple[object, tuple[int, ...]]]:
    """(call in the draft, argument register states at the target's call) for the calls that can
    be told apart: a callee named by its address is paired by that address, the others in order."""
    sites, calls = code.call_sites(), _calls(draft)
    by_target: dict[int | None, list] = {}
    for target, state in sites:
        by_target.setdefault(target, []).append(state)
    by_name: dict[str | None, list] = {}
    for call in calls:
        name = call.name.name if isinstance(call.name, c_ast.ID) and call.name.name not in draft.locals else None
        by_name.setdefault(name, []).append(call)
    pairs, used = [], set()
    for name, group in by_name.items():
        found = re.fullmatch(r"func_([0-9A-Fa-f]{8})", name or "")
        if found:
            states = by_target.get(int(found.group(1), 16), [])
            used.add(int(found.group(1), 16))
            if len(states) == len(group):
                pairs += list(zip(group, states))
    indirect = by_name.get(None, [])
    if indirect and len(indirect) == len(by_target.get(None, [])):
        pairs += list(zip(indirect, by_target[None]))
    named = [call for call in calls if isinstance(call.name, c_ast.ID) and call.name.name not in draft.locals
             and not re.fullmatch(r"func_[0-9A-Fa-f]{8}", call.name.name)]
    rest = [(target, state) for target, state in sites if target is not None and target not in used]
    if named and len(named) == len(rest):
        seen: dict[str, int] = {}
        if all(seen.setdefault(call.name.name, target) == target for call, (target, _state) in zip(named, rest)):
            pairs += [(call, state) for call, (_target, state) in zip(named, rest)]
    return pairs


def passed_arguments(draft: Draft, code: Code) -> int:
    """Give a call the arguments the function passes on unchanged.

    When the target sets ``$a1`` for a call and has not touched ``$a0`` since the function was
    entered, the callee receives the function's own first argument.  The decompiler, which does
    not know the callee, lists only the registers it saw written.  The call gets the missing
    arguments back, the function the parameters they come from, and a prototype that says
    otherwise is replaced by an unprototyped declaration."""
    own = draft.parameters()
    if any(draft.is_float(parameter.type) or (draft.size_of(parameter.type) or 4) > 4 for parameter in own):
        return 0                                             # argument registers shift: not handled
    # the decompiler names a parameter after its argument slot: arg0-arg3 are $a0-$a3
    slots: dict[int, object] = {}
    for parameter in own:
        found = re.fullmatch(r"arg(\d+)", parameter.name or "")
        if not found:
            return 0
        slots[int(found.group(1))] = parameter
    changed, wanted = 0, set()
    for call, state in _pair_calls(draft, code):
        registers, floats = state[:4], state[4:]
        if SET in floats or MIXED in registers:
            continue
        written = [index for index in range(4) if registers[index] == SET]
        arguments = list(call.args.exprs) if call.args is not None else []
        if any(draft.is_float(draft.type_of(argument)) for argument in arguments):
            continue
        if len(arguments) < len(written):
            continue
        if len(arguments) > len(written):                    # the rest travel on the stack
            top = 3
            if any(registers[index] not in (SET, INCOMING) for index in range(4)):
                continue
        elif written:
            top = written[-1]
        else:
            continue
        missing = [index for index in range(top + 1) if registers[index] == INCOMING]
        if not missing or any(registers[index] == STALE for index in range(top + 1)):
            continue
        rebuilt, supply = [], iter(arguments)
        for index in range(top + 1):
            rebuilt.append(c_ast.ID(f"arg{index}") if registers[index] == INCOMING else next(supply))
        rebuilt += list(supply)
        callee = call.name.name if isinstance(call.name, c_ast.ID) else None
        declared = draft.resolve(draft.globals.get(callee)) if callee else None
        if isinstance(declared, c_ast.FuncDecl) and declared.args is not None:
            # a prototype would reject the longer list: keep its return type only
            draft.dropped.add(callee)
            bare = c_ast.Decl(callee, [], [], [], [], c_ast.FuncDecl(None, _declared(declared.type, callee)), None, None)
            draft.added.append(_Generator().visit(bare) + ";")
            draft.globals[callee] = bare.type
        call.args = c_ast.ExprList(rebuilt)
        wanted.update(missing)
        changed += 1
    if changed and wanted - set(slots):
        for index in wanted - set(slots):
            slots[index] = c_ast.Decl(f"arg{index}", [], [], [], [], c_ast.TypeDecl(f"arg{index}", [], None,
                                      c_ast.IdentifierType(["s32"])), None, None)
        if sorted(slots) != list(range(len(slots))) and min(set(slots) - wanted, default=4) < 4:
            return -1                                        # a register argument in between is unknown
        for index in range(min(4, max(slots) + 1)):          # stack arguments need every register slot
            slots.setdefault(index, c_ast.Decl(f"arg{index}", [], [], [], [], c_ast.TypeDecl(
                f"arg{index}", [], None, c_ast.IdentifierType(["s32"])), None, None))
        draft.function.decl.type.args = c_ast.ParamList([slots[index] for index in sorted(slots)])
        draft.dropped.add(draft.name)                        # an earlier prototype of the function itself
        draft._collect_locals()
    return changed


def _declared(node, name: str):
    """A copy of a return type declaring ``name``."""
    node = copy.deepcopy(node)
    cursor = node
    while cursor is not None:
        if isinstance(cursor, c_ast.TypeDecl):
            cursor.declname = name
            break
        cursor = getattr(cursor, "type", None)
    return node


# --------------------------------------------------------------------------------- rule: order
_LOAD_OF = {("s", 1): "lb", ("u", 1): "lbu", ("s", 2): "lh", ("u", 2): "lhu"}
_STORE_OF = {1: "sb", 2: "sh", 4: "sw", 8: "sd"}


def _memory_events(draft: Draft, statement) -> tuple[list, set, set, bool] | None:
    """What an expression statement does: ([(mnemonic, "at"|"off", address|offset)] of its loads and
    stores, locals read, locals written, whether it has an effect that cannot be placed)."""
    events, reads, writes = [], set(), set()
    opaque = False

    def access(kind, where, key, store: bool):
        nonlocal opaque
        resolved = draft.resolve(kind)
        size = draft.size_of(kind)
        if size is None or isinstance(resolved, (c_ast.ArrayDecl, c_ast.FuncDecl)) or (
                isinstance(resolved, c_ast.TypeDecl) and isinstance(resolved.type, (c_ast.Struct, c_ast.Union))):
            opaque = True
            return
        if draft.is_float(kind):
            name = {4: "swc1" if store else "lwc1", 8: "sdc1" if store else "ldc1"}.get(size)
        elif store:
            name = _STORE_OF.get(size)
        elif size == 4:
            name = "lw"
        else:
            names = resolved.type.names if isinstance(resolved, c_ast.TypeDecl) and \
                isinstance(resolved.type, c_ast.IdentifierType) else []
            name = _LOAD_OF.get(("u" if "unsigned" in names else "s", size))
        if name is None:
            opaque = True
            return
        events.append((name, where, key))

    def visit(node, store=False, both=False):
        nonlocal opaque
        if isinstance(node, c_ast.Assignment):
            visit(node.rvalue)
            visit(node.lvalue, store=True, both=node.op != "=")
            return
        if isinstance(node, c_ast.UnaryOp) and node.op in ("p++", "p--", "++", "--"):
            visit(node.expr, store=True, both=True)
            return
        if isinstance(node, c_ast.ID):
            if node.name in draft.locals:
                (writes if store else reads).add(node.name)
                if both:
                    reads.add(node.name)
                return
            kind = draft.globals.get(node.name)
            found = re.fullmatch(r"D_([0-9A-Fa-f]{8})", node.name)
            resolved = draft.resolve(kind)
            if isinstance(resolved, (c_ast.FuncDecl, c_ast.ArrayDecl)):
                return                                       # an address, not an access
            if kind is None or not found:
                opaque = True
                return
            if both:
                access(kind, "at", int(found.group(1), 16), False)
            access(kind, "at", int(found.group(1), 16), store)
            return
        if isinstance(node, c_ast.UnaryOp) and node.op == "&":
            inner = node.expr
            if isinstance(inner, c_ast.ID):
                if inner.name in draft.locals:
                    opaque = True                            # a local in memory
                return
            visit(inner.name if isinstance(inner, (c_ast.StructRef, c_ast.ArrayRef)) else inner)
            return
        call = _field_call(node)
        if call is not None:
            visit(call[0])
            if both:
                access(draft.pointee(call[1]), "off", call[2], False)
            access(draft.pointee(call[1]), "off", call[2], store)
            return
        if isinstance(node, c_ast.StructRef):
            base = draft.resolve(draft.type_of(node.name))
            if node.type == "->":
                base = draft.resolve(draft.pointee(base))
                visit(node.name)
            elif not (isinstance(node.name, c_ast.ID) and node.name.name not in draft.locals):
                opaque = True
                return
            layout = draft.layout(base.type) if isinstance(base, c_ast.TypeDecl) and isinstance(
                base.type, (c_ast.Struct, c_ast.Union)) else None
            if layout is None or node.field.name not in layout[2]:
                opaque = True
                return
            offset, kind = layout[2][node.field.name]
            where = "off"
            if node.type == ".":
                found = re.fullmatch(r"D_([0-9A-Fa-f]{8})", node.name.name)
                if not found:
                    opaque = True
                    return
                where, offset = "at", int(found.group(1), 16) + offset
            if both:
                access(kind, where, offset, False)
            access(kind, where, offset, store)
            return
        if isinstance(node, c_ast.UnaryOp) and node.op == "*":
            visit(node.expr)
            kind = draft.pointee(draft.type_of(node.expr))
            if kind is None:
                opaque = True
                return
            if both:
                access(kind, "off", 0, False)
            access(kind, "off", 0, store)
            return
        if isinstance(node, (c_ast.FuncCall, c_ast.ArrayRef)):
            opaque = True
            return
        if isinstance(node, c_ast.Cast):
            visit(node.expr, store, both)
            return
        if store and not isinstance(node, c_ast.Cast):
            opaque = True
            return
        for _name, child in node.children():
            visit(child)

    visit(statement)
    return events, reads, writes, opaque


def statement_order(draft: Draft, code: Code) -> int:
    """Put consecutive assignments in the order in which the target starts them.

    A decompiler lists statements in the order of their last instruction (the store).  GCC's
    scheduler keeps the order in which statements begin but moves a store of a loaded value away
    from its load, so ``a->x = b->y; a->z = 0;`` is emitted as load, store z, store x, and the draft
    has the two statements the other way round, which builds to a different order.  Each load and
    store of a run of assignments is located in the target by its width and offset (only when
    that is unique in the function); the run is then sorted by where each statement starts."""
    positions: dict[tuple, list[int]] = {}
    for index, name, where, key in code.events:
        positions.setdefault((name, where, key), []).append(index)
    changed = 0
    for node in list(_walk(draft.function.body)):
        if not isinstance(node, c_ast.Compound) or not node.block_items:
            continue
        items = node.block_items
        start = 0
        while start < len(items):
            run = []
            cursor = start
            while cursor < len(items) and isinstance(items[cursor], c_ast.Assignment):
                found = _memory_events(draft, items[cursor])
                if found is None or found[3]:
                    break
                first = None
                for event in found[0]:
                    where = positions.get(event, [])
                    if len(where) != 1:
                        first = None
                        break
                    first = where[0] if first is None else min(first, where[0])
                if first is None:
                    break
                run.append((first, cursor, found[1], found[2]))
                cursor += 1
            if len(run) > 1:
                ordered = sorted(run, key=lambda row: (row[0], row[1]))
                if [row[1] for row in ordered] != [row[1] for row in run]:
                    rank = {row[1]: place for place, row in enumerate(ordered)}
                    safe = True
                    for i, a in enumerate(run):
                        for b in run[i + 1:]:
                            if rank[a[1]] > rank[b[1]] and (a[3] & (b[2] | b[3]) or b[3] & a[2]):
                                safe = False                 # one needs a local the other sets
                    if safe:
                        items[start:start + len(run)] = [items[row[1]] for row in ordered]
                        changed += 1
            start = cursor + 1                               # the statement that ended the run is a barrier
    return changed


# --------------------------------------------------------------------------------- rule: fields
def _parents(root) -> dict:
    out = {}
    for node in _walk(root):
        for _name, child in node.children():
            out[id(child)] = node
    return out


def _field_call(node):
    """(base, pointer type, offset) of an ``M2C_FIELD(base, T *, offset)`` with a constant offset."""
    if not (isinstance(node, c_ast.FuncCall) and isinstance(node.name, c_ast.ID) and node.name.name == "M2C_FIELD"
            and node.args is not None and len(node.args.exprs) == 3 and isinstance(node.args.exprs[1], c_ast.Cast)):
        return None
    offset = _number(node.args.exprs[2])
    if offset is None or offset < 0:
        return None
    return node.args.exprs[0], node.args.exprs[1].to_type.type, offset


def struct_fields(draft: Draft, code: Code) -> int:
    """Turn the decompiler's offset accesses into members of structures.

    ``M2C_FIELD(p, s32 *, 0x20)`` is ``*(s32 *) ((s8 *) p + 0x20)``: to GCC 2.x a scalar reached
    through a pointer, which may alias any other scalar, so a load after a store to a global stays
    after it.  ``p->unk_20`` is a member of an aggregate at a varying address, which GCC 2.x
    assumes cannot be a scalar variable at a fixed address; its scheduler then moves the access
    across such stores, and the instruction order of the build changes.  Which of the two the
    source had is decided by building both.  Each pointer the function reaches members through
    (a parameter, a local, a global pointer, the address of a global, a pointer member) gets a
    structure laid out from the offsets and widths of its accesses."""
    body = draft.function.body
    parents = _parents(body)
    own = {parameter.name for parameter in draft.parameters()}

    def key_of(base, depth=0):
        if depth > 6:
            return None
        if isinstance(base, c_ast.ID):
            if base.name in draft.locals:
                kind = draft.resolve(draft.locals[base.name])
                if isinstance(kind, c_ast.PtrDecl) or (isinstance(kind, c_ast.TypeDecl) and isinstance(
                        kind.type, c_ast.IdentifierType) and draft.size_of(kind) == 4 and not draft.is_float(kind)):
                    return ("var", base.name)
                return None
            kind = draft.resolve(draft.globals.get(base.name))
            if isinstance(kind, c_ast.PtrDecl) or (isinstance(kind, c_ast.TypeDecl) and isinstance(
                    kind.type, c_ast.IdentifierType) and draft.size_of(kind) == 4 and not draft.is_float(kind)):
                return ("global", base.name)
            return None
        if isinstance(base, c_ast.UnaryOp) and base.op == "&" and isinstance(base.expr, c_ast.ID) \
                and base.expr.name not in draft.locals:
            kind = draft.resolve(draft.globals.get(base.expr.name))
            if isinstance(kind, c_ast.TypeDecl) and isinstance(kind.type, c_ast.IdentifierType):
                return ("object", base.expr.name)
            return None
        inner = _field_call(base)
        if inner is not None:
            parent = key_of(inner[0], depth + 1)
            if parent is not None and draft.size_of(draft.pointee(inner[1])) == 4 \
                    and not draft.is_float(draft.pointee(inner[1])):
                return ("member", parent, inner[2])
        return None

    # every access: key -> [(offset, member type, stores, loads, node, kind)]
    found: dict[tuple, list] = {}
    unusable: set[tuple] = set()
    for node in _walk(body):
        call = _field_call(node)
        if call is not None:
            key = key_of(call[0])
            member = draft.pointee(call[1])
            if key is None or member is None:
                continue
            parent = parents.get(id(node))
            stores = isinstance(parent, c_ast.Assignment) and parent.lvalue is node
            loads = not stores or parent.op != "="
            found.setdefault(key, []).append((call[2], member, stores, loads, node, "field"))
        elif isinstance(node, c_ast.UnaryOp) and node.op == "*" and isinstance(node.expr, c_ast.ID) \
                and node.expr.name in draft.locals:
            member = draft.pointee(draft.locals[node.expr.name])
            if member is None or isinstance(draft.resolve(member), c_ast.FuncDecl):
                continue
            parent = parents.get(id(node))
            stores = isinstance(parent, c_ast.Assignment) and parent.lvalue is node
            found.setdefault(("var", node.expr.name), []).append(
                (0, member, stores, not stores or parent.op != "=", node, "deref"))
    if not found:
        return 0
    # a variable used in a way a structure pointer cannot be: leave it
    for node in _walk(body):
        if isinstance(node, (c_ast.ArrayRef, c_ast.StructRef)) and isinstance(node.name, c_ast.ID):
            unusable.add(("var", node.name.name))
            unusable.add(("global", node.name.name))
            unusable.add(("object", node.name.name))
        if isinstance(node, c_ast.UnaryOp) and node.op in ("p++", "p--", "++", "--") and isinstance(node.expr, c_ast.ID):
            unusable.add(("var", node.expr.name))
        if isinstance(node, c_ast.ID) and ("object", node.name) in found:
            parent = parents.get(id(node))
            if not (isinstance(parent, c_ast.UnaryOp) and parent.op == "&"):
                unusable.add(("object", node.name))
        if isinstance(node, c_ast.FuncCall) and isinstance(node.name, c_ast.ID):
            unusable.add(("var", node.name.name))           # called through: a function pointer
    for key in found:
        if key[0] == "var" and all(row[5] == "deref" for row in found[key]):
            unusable.add(key)                                # a plain typed pointer: nothing to gain

    def text_of(kind) -> str:
        return _Generator()._generate_type(kind, emit_declname=False)

    layouts: dict[tuple, dict[int, object]] = {}
    for key, rows in found.items():
        if key in unusable:
            continue
        members: dict[int, tuple] = {}
        valid = True
        for offset, member, stores, loads, _node, _kind in rows:
            size = draft.size_of(member)
            if size is None or size not in (1, 2, 4, 8) or offset % min(size, 4) or \
                    isinstance(draft.resolve(member), (c_ast.ArrayDecl, c_ast.FuncDecl)):
                valid = False
                break
            if offset not in members:
                members[offset] = (member, size, loads)
                continue
            current, held, loaded = members[offset]
            if held != size:
                valid = False
                break
            if text_of(current) == text_of(member):
                members[offset] = (current, held, loaded or loads)
                continue
            pointer_now, pointer_new = draft.pointee(current) is not None, draft.pointee(member) is not None
            if draft.is_float(current) != draft.is_float(member):
                valid = False
                break
            if size == 4 and pointer_now != pointer_new:
                members[offset] = (current if pointer_now else member, held, loaded or loads)
            elif loads and loaded and size < 4:
                valid = False                                # read both signed and unsigned
                break
            elif loads and not loaded:
                members[offset] = (member, held, True)
        ordered = sorted(members)
        if not valid or any(a + members[a][1] > b for a, b in zip(ordered, ordered[1:])):
            continue
        layouts[key] = {offset: members[offset][0] for offset in ordered}
    # a member reached through needs its parent
    for key in sorted(layouts, key=lambda k: -len(repr(k))):
        cursor = key
        while cursor[0] == "member":
            if cursor[1] not in layouts or cursor[2] not in layouts[cursor[1]]:
                layouts.pop(key, None)
                break
            cursor = cursor[1]
    if not layouts:
        return 0
    taken = set(draft.structs)
    tags: dict[tuple, str] = {}
    for key in layouts:
        stem = "Fields_" + re.sub(r"\W", "_", "_".join(str(part) if not isinstance(part, tuple) else "m"
                                                        for part in _flatten(key)))
        tag, number = stem, 1
        while tag in taken:
            number += 1
            tag = f"{stem}_{number}"
        taken.add(tag)
        tags[key] = tag

    def pointer_to(tag: str, name=None):
        return c_ast.PtrDecl([], c_ast.TypeDecl(name, [], None, c_ast.Struct(tag, None)))

    for key, tag in tags.items():
        if key[0] == "member" and key[1] in layouts:
            layouts[key[1]][key[2]] = pointer_to(tag)
    for key, tag in tags.items():
        declarations, cursor = [], 0
        for offset in sorted(layouts[key]):
            if offset > cursor:
                declarations.append(c_ast.Decl(f"pad_{cursor:X}", [], [], [], [], c_ast.ArrayDecl(
                    c_ast.TypeDecl(f"pad_{cursor:X}", [], None, c_ast.IdentifierType(["char"])),
                    c_ast.Constant("int", hex(offset - cursor)), []), None, None))
            member = _declared(layouts[key][offset], f"unk_{offset:X}")
            declarations.append(c_ast.Decl(f"unk_{offset:X}", [], [], [], [], member, None, None))
            cursor = offset + (draft.size_of(layouts[key][offset]) or 4)
        struct = c_ast.Struct(tag, declarations)
        draft.structs[tag] = struct
        draft.added.append(_Generator().visit(c_ast.Decl(None, [], [], [], [], struct, None, None)) + ";")
    # the declarations of the things the members are reached through
    retyped = False
    for key, tag in tags.items():
        if key[0] == "var":
            for node in list(_walk(draft.function.decl)) + list(_walk(body)):
                if isinstance(node, c_ast.Decl) and node.name == key[1] and not isinstance(node.type, c_ast.FuncDecl):
                    node.type = pointer_to(tag, key[1])
            retyped = retyped or key[1] in own
        elif key[0] == "global":
            draft.dropped.add(key[1])
            draft.added.append(f"extern struct {tag} *{key[1]};")
            draft.globals[key[1]] = pointer_to(tag, key[1])
        elif key[0] == "object":
            draft.dropped.add(key[1])
            draft.added.append(f"extern struct {tag} {key[1]};")
            draft.globals[key[1]] = c_ast.TypeDecl(key[1], [], None, c_ast.Struct(tag, None))
    if retyped:
        draft.dropped.add(draft.name)
    draft._collect_locals()
    # the accesses themselves
    changed = 0
    for key, rows in found.items():
        if key not in tags:
            continue
        for offset, _member, _stores, _loads, node, kind in rows:
            base = node.expr if kind == "deref" else node.args.exprs[0]
            if key[0] == "object":
                replacement = c_ast.StructRef(base.expr, ".", c_ast.ID(f"unk_{offset:X}"))
            else:
                replacement = c_ast.StructRef(base, "->", c_ast.ID(f"unk_{offset:X}"))
            if _replace(body, node, replacement):
                changed += 1
    return changed


def _flatten(key):
    for part in key:
        if isinstance(part, tuple):
            yield from _flatten(part)
        else:
            yield part if not isinstance(part, int) else f"{part:X}"


# --------------------------------------------------------------------------------- the generator
def variants(source: str, name: str, *, code: bytes, vram: int, pipeline: str,
             flags: tuple[str, ...] = (), family: str | None = None) -> list[tuple[str, str]]:
    """[(label, complete C translation unit)]; [] when this is not an optimised GCC function."""
    if c_parser is None or not code or len(code) % 4:
        return []
    try:
        facts = Code(code, vram)
        if not _optimised_gcc(pipeline, tuple(flags), family, facts.insns):
            return []
        out: list[tuple[str, str]] = []
        seen = {source}

        def offer(label: str, draft: Draft) -> None:
            text = draft.text()
            if text not in seen:
                seen.add(text)
                out.append((label, text))

        fixes = (("passed", passed_arguments), ("bytes", byte_arithmetic), ("symbols", symbol_addresses))

        def build(rules):
            draft, applied = Draft(source, name), []
            for label, rule in rules:
                count = rule(draft, facts)
                if count < 0:                                # the rule left the tree half changed
                    return None, []
                if count:
                    applied.append(label)
            return draft, applied

        # 1. what the decompiler got wrong, corrected together
        draft, applied = build(fixes)
        if applied:
            offer("+".join(applied), draft)
        draft, applied = build(fixes + (("order", statement_order),))
        if "order" in applied:
            offer("+".join(applied), draft)
        # 2. the same with members of structures in place of offset accesses.  The two forms
        #    differ only in how accesses are ordered around scalars at fixed addresses, so
        #    without a global or a local in memory there is nothing to gain
        if facts.accesses or facts.frame_accesses:
            draft, applied = build((("fields", struct_fields),) + fixes)
            if "fields" in applied:
                offer("+".join(applied), draft)
        return out[:MAX_VARIANTS]
    except Exception:                                        # a rewrite is optional; the draft stands
        return []
