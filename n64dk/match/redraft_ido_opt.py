"""Drafts for code built by SGI IDO with optimisation (-O1/-O2/-O3).

A general decompiler's draft of an optimised IDO function fails to rebuild into the same bytes for
a small number of mechanical reasons.  Each rule below was derived by compiling probes with IDO 5.3
and 7.1 and is applied from facts read from the target's machine code:

* **byte arithmetic** -- the decompiler writes every pointer sum in bytes (``&D + i * 0x10``,
  ``p += 0xB0``); C scales it by the pointee.  Every pointer sum whose pointee is not one byte
  wide is rewritten on a byte pointer, and a dereference of an untyped sum takes the width of the
  instruction that reads or writes that address in the target.
* **calls** -- without prototypes the decompiler lists exactly the argument registers that hold a
  new value at a call.  The target says which registers still hold the function's own, untouched
  arguments, which values were only parked in an argument register, and whether stack arguments
  follow; the argument list and the function's own parameter list are completed from that.
* **frame** -- IDO's front end gives every declared local a slot, top down in declaration order
  (scalars at their natural alignment, aggregates at four bytes or more), the optimiser puts its
  temporaries below, and the frame ends at the lowest slot that is referenced (at the lowest
  declared one as soon as any local's address is taken).  The declarations are therefore
  re-written so that every stack variable lands on the offset the target uses: variables that are
  written but never read in the target are fields of the aggregate whose address escapes, a spill
  copy (``spXX = temp``) is the temporary's own home, and what is left is padding.

``variants`` returns at most six rewrites, the one with every rule first.
"""
from __future__ import annotations

import copy
import re
import struct
import threading

try:                                                    # the parser is optional: no parser, no rewrites
    from pycparser import c_ast, c_generator, c_parser
except Exception:                                       # pragma: no cover
    c_ast = c_generator = c_parser = None

from ..analysis import flow as flowmod

MAX_INSNS = 0x1000 // 4                                 # larger functions are left to the other stages
_PARSER_LOCK = threading.Lock()
_PARSER = None

# ------------------------------------------------------------------------------------------------
# the draft: prelude / declarations / function, parsed

_PARSE_TYPES = ("typedef signed char s8; typedef unsigned char u8; typedef signed short s16; "
                "typedef unsigned short u16; typedef signed int s32; typedef unsigned int u32; "
                "typedef signed long long s64; typedef unsigned long long u64; typedef float f32; "
                "typedef double f64; typedef int M2C_UNK; typedef s8 M2C_UNK8; typedef s16 M2C_UNK16; "
                "typedef s32 M2C_UNK32; typedef s64 M2C_UNK64;\n")
_BASE = {"s8": ("i", 1, True), "u8": ("i", 1, False), "s16": ("i", 2, True), "u16": ("i", 2, False),
         "s32": ("i", 4, True), "u32": ("i", 4, False), "s64": ("i", 8, True), "u64": ("i", 8, False),
         "f32": ("f", 4), "f64": ("f", 8), "M2C_UNK": ("u",), "M2C_UNK8": ("i", 1, True),
         "M2C_UNK16": ("i", 2, True), "M2C_UNK32": ("i", 4, True), "M2C_UNK64": ("i", 8, True)}
_NAME_OF = {("i", 1, True): "s8", ("i", 1, False): "u8", ("i", 2, True): "s16", ("i", 2, False): "u16",
            ("i", 4, True): "s32", ("i", 4, False): "u32", ("i", 8, True): "s64", ("i", 8, False): "u64",
            ("f", 4): "f32", ("f", 8): "f64", ("u",): "M2C_UNK", ("v",): "void"}
_MACRO_CALLS = {"M2C_ERROR", "M2C_TRAP_IF", "M2C_BREAK", "M2C_LWL", "M2C_FIRST3BYTES", "M2C_UNALIGNED32",
                "MULT_HI", "MULTU_HI", "m2c_unhandled"}
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def _parser():
    global _PARSER
    if _PARSER is None:
        _PARSER = c_parser.CParser()
    return _PARSER


def _split_prelude(source: str) -> tuple[str, str] | None:
    """(prelude kept verbatim, the C that follows it)."""
    if "N64DK_M2C_PRELUDE" in source:
        cut = source.rfind("#endif")
        if cut < 0:
            return None
        cut = source.find("\n", cut)
        cut = len(source) if cut < 0 else cut + 1
        return source[:cut], source[cut:]
    return "", source


def _macro_arguments(text: str, start: int) -> tuple[list[str], int] | None:
    """Arguments of a macro call whose ``(`` is at ``start``; (arguments, index after ``)``)."""
    depth, at, out = 0, start, []
    last = start + 1
    while at < len(text):
        char = text[at]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                out.append(text[last:at].strip())
                return out, at + 1
        elif char == "," and depth == 1:
            out.append(text[last:at].strip())
            last = at + 1
        at += 1
    return None


def _expand(text: str) -> str:
    """The two prelude macros that hide a type: written out so the parser sees casts."""
    for _round in range(400):
        found = re.search(r"\b(M2C_FIELD|M2C_BITWISE)\s*\(", text)
        if not found:
            return text
        parsed = _macro_arguments(text, found.end() - 1)
        if parsed is None:
            raise ValueError("unbalanced macro call")
        arguments, end = parsed
        if found.group(1) == "M2C_FIELD":
            if len(arguments) != 3:
                raise ValueError("M2C_FIELD arity")
            new = f"(*({arguments[1]})((s8 *)({arguments[0]}) + ({arguments[2]})))"
        else:
            if len(arguments) != 2:
                raise ValueError("M2C_BITWISE arity")
            new = f"(({arguments[0]})({arguments[1]}))"
        text = text[:found.start()] + new + text[end:]
    raise ValueError("macro expansion did not end")


class Draft:
    """One translation unit: the kept prelude, the external declarations and the function."""

    def __init__(self, source: str, name: str):
        parts = _split_prelude(source)
        if parts is None:
            raise ValueError("prelude")
        self.prelude, body = parts
        body = _COMMENT.sub(" ", body)
        if re.search(r"(?m)^\s*#", body):
            raise ValueError("preprocessor lines after the prelude")
        body = _expand(body)
        with _PARSER_LOCK:
            self.ast = _parser().parse(_PARSE_TYPES + body)
        self.name = name
        self.skip = sum(1 for _ in _parser_typedefs())
        self.function = None
        for node in self.ast.ext:
            if isinstance(node, c_ast.FuncDef) and node.decl.name == name:
                self.function = node
        if self.function is None or self.function.body.block_items is None:
            raise ValueError("function not found")
        self.types = Types(self)

    def text(self) -> str:
        generator = c_generator.CGenerator()
        out = []
        for node in self.ast.ext[self.skip:]:
            if isinstance(node, c_ast.FuncDef):
                out.append(generator.visit(node))
            else:
                out.append(generator.visit(node) + ";\n")
        return self.prelude + "\n" + "".join(out)

    # ---- declarations of the function
    def locals(self) -> list:
        return [item for item in self.function.body.block_items if isinstance(item, c_ast.Decl)]

    def parameters(self) -> list:
        arguments = self.function.decl.type.args
        if arguments is None:
            return []
        return [p for p in arguments.params if isinstance(p, c_ast.Decl) and p.name]


def _parser_typedefs():
    return re.finditer(r"\btypedef\b", _PARSE_TYPES)


# ------------------------------------------------------------------------------------------------
# types: ("i", size, signed) ("f", size) ("v",) ("u",) ("p", T) ("a", T, n) ("s", id) ("fn", T)

def _walk(node):
    """Every node below ``node`` (pre-order), the node first."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed([child for _name, child in current.children()]))


class Types:
    def __init__(self, draft: Draft):
        self.typedefs: dict[str, tuple] = dict(_BASE)
        self.structs: dict[str, c_ast.Node] = {}            # tag -> defining node
        self.anonymous: dict[int, c_ast.Node] = {}
        self.globals: dict[str, tuple] = {}
        self.locals: dict[str, tuple] = {}
        for node in draft.ast.ext:
            self._collect_tags(node)
        for node in draft.ast.ext:
            if isinstance(node, c_ast.Typedef):
                if node.name not in _BASE:
                    self.typedefs[node.name] = self.of_decl(node.type)
            elif isinstance(node, c_ast.Decl) and node.name:
                self.globals[node.name] = self.of_decl(node.type)
            elif isinstance(node, c_ast.FuncDef):
                self.globals[node.decl.name] = self.of_decl(node.decl.type)
        self.refresh(draft)

    def refresh(self, draft: Draft) -> None:
        self.locals = {}
        self._collect_tags(draft.function)
        for parameter in draft.parameters():
            self.locals[parameter.name] = self.of_decl(parameter.type)
        for node in _walk(draft.function.body):
            if isinstance(node, c_ast.Decl) and node.name:
                self.locals[node.name] = self.of_decl(node.type)

    def _collect_tags(self, root) -> None:
        for node in _walk(root):
            if isinstance(node, (c_ast.Struct, c_ast.Union)) and node.decls is not None:
                if node.name:
                    self.structs[node.name] = node
                self.anonymous[id(node)] = node

    def of_decl(self, node) -> tuple | None:
        if isinstance(node, (c_ast.TypeDecl, c_ast.Typename)):
            return self.of_decl(node.type)
        if isinstance(node, c_ast.PtrDecl):
            return ("p", self.of_decl(node.type))
        if isinstance(node, c_ast.ArrayDecl):
            return ("a", self.of_decl(node.type), _constant(node.dim))
        if isinstance(node, c_ast.FuncDecl):
            return ("fn", self.of_decl(node.type))
        if isinstance(node, (c_ast.Struct, c_ast.Union)):
            if node.decls is None and node.name:
                return ("s", node.name)
            return ("s", node.name or id(node))
        if isinstance(node, c_ast.Enum):
            return ("i", 4, True)
        if isinstance(node, c_ast.IdentifierType):
            names = list(node.names)
            if len(names) == 1 and names[0] in self.typedefs:
                return self.typedefs[names[0]]
            if "void" in names:
                return ("v",)
            if "float" in names:
                return ("f", 4)
            if "double" in names:
                return ("f", 8)
            signed = "unsigned" not in names
            if "char" in names:
                return ("i", 1, signed)
            if "short" in names:
                return ("i", 2, signed)
            if names.count("long") >= 2:
                return ("i", 8, signed)
            return ("i", 4, signed)
        return None

    def struct(self, key):
        node = self.structs.get(key) if isinstance(key, str) else self.anonymous.get(key)
        return node if node is not None and node.decls is not None else None

    def layout(self, key) -> tuple[dict, int, int] | None:
        """({field: (offset, type)}, size, alignment) of a struct or union, None when unknown."""
        node = self.struct(key)
        if node is None:
            return None
        fields, offset, alignment, size = {}, 0, 1, 0
        for decl in node.decls:
            kind = self.of_decl(decl.type)
            width, align = self.sizeof(kind), self.alignof(kind)
            if width is None or align is None or decl.bitsize is not None:
                return None
            alignment = max(alignment, align)
            if isinstance(node, c_ast.Union):
                fields[decl.name] = (0, kind)
                size = max(size, width)
                continue
            offset = (offset + align - 1) // align * align
            fields[decl.name] = (offset, kind)
            offset += width
            size = offset
        size = (size + alignment - 1) // alignment * alignment
        return fields, size, alignment

    def sizeof(self, kind) -> int | None:
        if kind is None:
            return None
        if kind[0] in ("i", "f"):
            return kind[1]
        if kind[0] == "p":
            return 4
        if kind[0] == "u":
            return 4
        if kind[0] == "a":
            inner = self.sizeof(kind[1])
            return inner * kind[2] if inner is not None and kind[2] is not None else None
        if kind[0] == "s":
            found = self.layout(kind[1])
            return found[1] if found else None
        return None

    def alignof(self, kind) -> int | None:
        if kind is None:
            return None
        if kind[0] in ("i", "f"):
            return kind[1]
        if kind[0] in ("p", "u"):
            return 4
        if kind[0] == "a":
            return self.alignof(kind[1])
        if kind[0] == "s":
            found = self.layout(kind[1])
            return found[2] if found else None
        return None

    # ---- expressions
    def of(self, node) -> tuple | None:
        try:
            return self._of(node)
        except RecursionError:
            return None

    def _of(self, node) -> tuple | None:
        if isinstance(node, c_ast.ID):
            if node.name in self.locals:
                return self.locals[node.name]
            if node.name == "NULL":
                return ("p", ("v",))
            return self.globals.get(node.name)
        if isinstance(node, c_ast.Constant):
            if node.type in ("float", "double", "long double"):
                return ("f", 4 if node.value.rstrip().lower().endswith("f") else 8)
            if node.type == "string":
                return ("p", ("i", 1, True))
            if node.type == "char":
                return ("i", 4, True)
            value = _constant(node)
            unsigned = "u" in node.value.lower() or (value is not None and value > 0x7FFFFFFF)
            return ("i", 4, not unsigned)
        if isinstance(node, c_ast.Cast):
            return self.of_decl(node.to_type)
        if isinstance(node, c_ast.UnaryOp):
            inner = self._of(node.expr)
            if node.op == "&":
                return ("p", inner) if inner is not None else None
            if node.op == "*":
                if inner is not None and inner[0] in ("p", "a"):
                    return inner[1]
                return None
            if node.op == "!":
                return ("i", 4, True)
            if node.op == "sizeof":
                return ("i", 4, False)
            if node.op in ("-", "+", "~"):
                return _promote(inner)
            return inner                                    # ++ -- p++ p--
        if isinstance(node, c_ast.BinaryOp):
            if node.op in ("==", "!=", "<", ">", "<=", ">=", "&&", "||"):
                return ("i", 4, True)
            left, right = self._of(node.left), self._of(node.right)
            if node.op in ("+", "-"):
                lp, rp = _pointer(left), _pointer(right)
                if lp and rp:
                    return ("i", 4, True)
                if lp:
                    return ("p", left[1])
                if rp and node.op == "+":
                    return ("p", right[1])
            if node.op in ("<<", ">>"):
                return _promote(left)
            if left is None or right is None:
                return None
            if left[0] == "f" or right[0] == "f":
                return ("f", max(k[1] for k in (left, right) if k[0] == "f"))
            left, right = _promote(left), _promote(right)
            if left is None or right is None or left[0] != "i" or right[0] != "i":
                return None
            size = max(left[1], right[1])
            return ("i", size, all(k[2] for k in (left, right) if k[1] == size))
        if isinstance(node, c_ast.ArrayRef):
            inner = self._of(node.name)
            return inner[1] if inner is not None and inner[0] in ("p", "a") else None
        if isinstance(node, c_ast.StructRef):
            inner = self._of(node.name)
            if node.type == "->":
                inner = inner[1] if inner is not None and inner[0] in ("p", "a") else None
            if inner is None or inner[0] != "s":
                return None
            found = self.layout(inner[1])
            if not found or node.field.name not in found[0]:
                return None
            return found[0][node.field.name][1]
        if isinstance(node, c_ast.FuncCall):
            inner = self._of(node.name)
            while inner is not None and inner[0] == "p":
                inner = inner[1]
            if inner is not None and inner[0] == "fn":
                return inner[1]
            return ("i", 4, True)
        if isinstance(node, c_ast.Assignment):
            return self._of(node.lvalue)
        if isinstance(node, c_ast.TernaryOp):
            return self._of(node.iftrue) or self._of(node.iffalse)
        if isinstance(node, c_ast.ExprList):
            return self._of(node.exprs[-1]) if node.exprs else None
        return None


def _promote(kind):
    if kind is not None and kind[0] == "i" and kind[1] < 4:
        return ("i", 4, True)
    if kind is not None and kind[0] == "u":
        return ("i", 4, True)
    return kind


def _pointer(kind) -> bool:
    return kind is not None and kind[0] in ("p", "a")


def _constant(node) -> int | None:
    if isinstance(node, c_ast.Constant) and node.type in ("int", "unsigned int", "long", "unsigned long",
                                                           "long long", "unsigned long long"):
        try:
            return int(node.value.rstrip("uUlL"), 0)
        except ValueError:
            return None
    return None


def _type_node(kind, types: Types | None = None):
    """A pycparser type for ``kind`` (None when it cannot be written)."""
    if kind is None:
        return None
    if kind[0] == "p":
        inner = _type_node(kind[1], types)
        return c_ast.PtrDecl([], inner) if inner is not None else None
    if kind[0] == "a":                                   # an array decays in a cast
        inner = _type_node(kind[1], types)
        return c_ast.PtrDecl([], inner) if inner is not None else None
    if kind in _NAME_OF:
        return c_ast.TypeDecl(None, [], None, c_ast.IdentifierType([_NAME_OF[kind]]))
    if kind[0] == "s" and isinstance(kind[1], str):
        node = types.structs.get(kind[1]) if types is not None else None
        make = c_ast.Union if isinstance(node, c_ast.Union) else c_ast.Struct
        return c_ast.TypeDecl(None, [], None, make(kind[1], None))
    return None


def _cast(kind, expression, types: Types | None = None):
    node = _type_node(kind, types)
    if node is None:
        return None
    return c_ast.Cast(c_ast.Typename(None, [], None, node), expression)


def _replace(root, old, new) -> bool:
    """Replace the child ``old`` (by identity) somewhere below ``root``."""
    for node in _walk(root):
        for name, child in node.children():
            if child is old:
                found = re.fullmatch(r"(\w+)\[(\d+)\]", name)
                if found:
                    getattr(node, found.group(1))[int(found.group(2))] = new
                else:
                    setattr(node, name, new)
                return True
    return False


def _parents(root) -> dict[int, tuple]:
    """id(child) -> (parent, attribute, index or None)."""
    out = {}
    for node in _walk(root):
        for name, child in node.children():
            found = re.fullmatch(r"(\w+)\[(\d+)\]", name)
            out[id(child)] = (node, found.group(1), int(found.group(2))) if found else (node, name, None)
    return out


def _set(parent_entry, new) -> None:
    parent, attribute, index = parent_entry
    if index is None:
        setattr(parent, attribute, new)
    else:
        getattr(parent, attribute)[index] = new


# ------------------------------------------------------------------------------------------------
# the target: facts read from the machine code

_LOADS = {32: ("s8", 1), 33: ("s16", 2), 35: ("s32", 4), 36: ("u8", 1), 37: ("u16", 2), 49: ("f32", 4),
          53: ("f64", 8)}
_STORES = {40: ("s8", 1), 41: ("s16", 2), 43: ("s32", 4), 57: ("f32", 4), 61: ("f64", 8)}
SP, RA = 29, 31
_ARGS = (4, 5, 6, 7)
_SAVED = frozenset([*range(16, 24), 30])


class Call:
    def __init__(self, index: int, target: int | None):
        self.index, self.target = index, target
        self.state = ["E"] * 4          # per a0..a3 at the call: see Target._calls
        self.stack: list[tuple[int, int]] = []   # outgoing stack arguments (offset, width)
        self.floats = False             # $f12..$f15 written for this call


class Target:
    def __init__(self, code: bytes, vram: int):
        self.vram = vram
        self.flow = flowmod.analyse(code, vram)
        self.insns = self.flow.insns
        self.words = [insn.word for insn in self.insns]
        self.frame = self.flow.frame.size
        self.saved = dict(self.flow.frame.saved)             # GPR -> offset
        self.float_saved: dict[int, int] = {}
        self.refs: list[tuple[int, int, str, str, int]] = []  # (index, offset, kind, type name, width)
        self.symbols: dict[int, set[tuple[str, str]]] = {}    # address -> {(kind, type name)} indexed accesses
        self.calls: list[Call] = []
        self._stack()
        self._addresses()
        self._calls()

    # ---- stack
    def _stack(self) -> None:
        written_float: set[int] = set()
        for insn in self.insns:
            word = insn.word
            op, rs, rt, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if op == 17:                                    # COP1: destination register of an operation
                fmt = rs
                if fmt in (16, 17, 20, 21) and (word & 0x3F) < 48:
                    written_float.add((word >> 6) & 31)
                elif fmt == 4:
                    written_float.add((word >> 11) & 31)
            if op in (49, 53) and rs != SP:
                written_float.add(rt)
            if rs != SP:
                continue
            if op == 9 and rt != SP:
                self.refs.append((insn.index, simm, "addr", "", 0))
            elif op in _LOADS:
                if op in (49, 53):
                    if self.float_saved.get(rt) == simm:
                        continue                            # restore of a saved register
                    written_float.add(rt)
                elif self.saved.get(rt) == simm and (rt in _SAVED or rt == RA):
                    continue
                self.refs.append((insn.index, simm, "load", *_LOADS[op]))
            elif op in _STORES:
                if op in (57, 61):
                    if rt >= 20 and rt not in written_float and rt not in self.float_saved:
                        self.float_saved[rt] = simm
                        continue
                elif self.saved.get(rt) == simm and insn.index <= self._last_save():
                    continue
                self.refs.append((insn.index, simm, "store", *_STORES[op]))

    def _last_save(self) -> int:
        if not hasattr(self, "_save_end"):
            last = -1
            pending = dict(self.saved)
            for insn in self.insns:
                word = insn.word
                if word >> 26 == 43 and (word >> 21) & 31 == SP:
                    rt, imm = (word >> 16) & 31, word & 0xFFFF
                    if pending.get(rt) == (imm - 0x10000 if imm & 0x8000 else imm):
                        last = insn.index
                        del pending[rt]
                if not pending:
                    break
            self._save_end = last
        return self._save_end

    @property
    def saved_low(self) -> int | None:
        """Lowest offset of the register save area (None without one)."""
        offsets = list(self.saved.values()) + list(self.float_saved.values())
        return min(offsets) if offsets else None

    @property
    def locals_low(self) -> int:
        """First offset above the register save area: where temporaries and locals may live."""
        offsets = list(self.saved.values())
        top = max(offsets) + 4 if offsets else 0
        if self.float_saved:
            top = max(top, max(self.float_saved.values()) + 8)
        return top

    def slots(self) -> dict[int, dict]:
        """offset -> {"addr": n, "load": n, "store": n, "types": {...}} for the locals area."""
        out: dict[int, dict] = {}
        low = self.locals_low
        for _index, offset, kind, name, _width in self.refs:
            if not low <= offset < self.frame:
                continue
            row = out.setdefault(offset, {"addr": 0, "load": 0, "store": 0, "types": set()})
            row[kind] += 1
            if name:
                row["types"].add(name)
        return out

    # ---- addresses formed with lui: which instruction reads or writes them through an index
    def _addresses(self) -> None:
        leaders = {block.first for block in self.flow.blocks}
        high: dict[int, int] = {}
        for insn in self.insns:
            if insn.index in leaders:
                high = {}
            word = insn.word
            op, rs, rt, rd, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, (word >> 11) & 31, word & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if op == 15:
                high[rt] = imm << 16
                continue
            if op == 0 and (word & 0x3F) == 0x21 and rd:    # addu rd, rs, rt: an index added to %hi
                if rs in high and rt not in high:
                    value = ("x", high[rs])
                elif rt in high and rs not in high:
                    value = ("x", high[rt])
                else:
                    value = None
                high.pop(rd, None)
                if value is not None:
                    high[rd] = value
                continue
            if op in _LOADS or op in _STORES:
                base = high.get(rs)
                if isinstance(base, tuple):
                    address = (base[1] + simm) & 0xFFFFFFFF
                    kind = "load" if op in _LOADS else "store"
                    self.symbols.setdefault(address, set()).add((kind, (_LOADS.get(op) or _STORES.get(op))[0]))
            for reg in insn.defs:
                high.pop(reg, None)
            if insn.index and self.insns[insn.index - 1].kind == "call":
                high = {}                                   # after the delay slot of a call

    # ---- calls
    def _calls(self) -> None:
        """Register state of a0..a3 at every call:

        ``E``  still the function's own argument (never written, no call before);
        ``S``  written since (IDO computes an argument in its register; temporaries go elsewhere);
        ``R``  a variable that lives in the register: written since and then stored to the frame,
               or a copy of another of the function's own arguments that is read again later (it
               may or may not also be an argument);
        ``D``  clobbered by an earlier call."""
        insns, blocks = self.insns, self.flow.blocks
        if not blocks:
            return
        start: list[list[str] | None] = [None] * len(blocks)
        start[0] = ["E"] * 4
        rank = {"E": 0, "S": 1, "R": 2, "D": 3}

        def merge(a, b):
            return a if rank[a] >= rank[b] else b

        def read_later(index: int, reg: int) -> bool:
            """Is the value written at ``index`` read again by this function (not only by a callee)?"""
            for later in insns[index + 1:]:
                if reg in later.uses:
                    return True
                if reg in later.defs:
                    return False
            return False

        def step(insn, state, floats, stack):
            before = list(state)
            word = insn.word
            op, rs, rt, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            low = self.saved_low
            if rs == SP and op in _STORES and simm >= 0x10 and (low is None or simm < low) and simm < self.frame:
                stack[simm] = _STORES[op][1]
            if op == 17:
                dest = None
                if rs in (16, 17, 20, 21) and (word & 0x3F) < 48:
                    dest = (word >> 6) & 31
                elif rs == 4:
                    dest = (word >> 11) & 31
                if dest is not None and 12 <= dest <= 15:
                    floats = True
            if op in (49, 53) and 12 <= rt <= 15:
                floats = True
            if rs == SP and op == 43 and rt in _ARGS and state[rt - 4] == "S":
                state[rt - 4] = "R"                         # kept in the frame: a value parked in the register
            for reg in insn.defs:
                if reg in _ARGS:
                    parked = False
                    if op == 0 and (word & 0x3F) in (0x21, 0x25) and 0 in (rs, rt):      # move
                        source = rs if rt == 0 else rt
                        if source in _ARGS and source != reg and before[source - 4] == "E":
                            parked = read_later(insn.index, reg)
                    state[reg - 4] = "R" if parked else "S"
            return floats

        def run(block, state, record: bool):
            state = list(state)
            index = block.first
            floats, stack = False, {}
            while index <= block.last:
                insn = insns[index]
                if insn.kind == "call":
                    if index + 1 <= block.last:
                        floats = step(insns[index + 1], state, floats, stack)
                    if record:
                        call = Call(index, insn.target)
                        call.state = list(state)
                        call.stack = sorted(stack.items())
                        call.floats = floats
                        self.calls.append(call)
                    state = ["D"] * 4
                    floats, stack = False, {}
                    index += 2
                    continue
                floats = step(insn, state, floats, stack)
                index += 1
            return state

        changed, rounds = True, 0
        while changed and rounds < 64:
            changed, rounds = False, rounds + 1
            for block in blocks:
                if start[block.number] is None:
                    continue
                out = run(block, start[block.number], False)
                for succ in block.succs:
                    merged = out if start[succ] is None else [merge(a, b) for a, b in zip(start[succ], out)]
                    if merged != start[succ]:
                        start[succ] = merged
                        changed = True
        for block in blocks:
            if start[block.number] is not None:
                run(block, start[block.number], True)
        self.calls.sort(key=lambda call: call.index)

    def homes(self) -> list[dict]:
        """Per a0..a3: how the function treats its own argument.

        ``homed``   the register is stored to its slot in the caller's frame while it still holds
                    the argument (IDO does that for a narrow parameter, for one it needs after a
                    call, and for one it never uses);
        ``narrow``  types of the narrow loads from that slot; ``word`` the number of word loads;
        ``mask``    types of the extensions applied to the register itself; ``read`` the register
                    is read as a value while it still holds the argument."""
        out = [{"homed": False, "narrow": set(), "word": 0, "mask": set(), "read": False} for _k in range(4)]
        written: set[int] = set()
        adjust = 0
        words = self.words
        for insn in self.insns:
            word = insn.word
            op, rs, rt, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
            simm = imm - 0x10000 if imm & 0x8000 else imm
            if op == 9 and rs == SP and rt == SP:
                if simm < 0:
                    adjust = -simm
                continue
            store_home = False
            if rs == SP and op == 43 and rt in _ARGS and rt not in written and simm == adjust + 4 * (rt - 4):
                out[rt - 4]["homed"] = True
                store_home = True
            elif rs == SP and op in _LOADS and adjust == self.frame and simm >= self.frame:
                k = (simm - self.frame) // 4
                if 0 <= k < 4:
                    name, width = _LOADS[op]
                    inside = simm - self.frame - 4 * k
                    if width == 4 and inside == 0 and name == "s32":
                        out[k]["word"] += 1
                    elif width + inside == 4:
                        out[k]["narrow"].add(name)
                    else:
                        out[k]["narrow"].add("?")
            if not store_home:
                for reg in insn.uses:
                    if reg in _ARGS and reg not in written:
                        k = reg - 4
                        kind = None
                        if op == 12 and rs == reg and imm in (0xFF, 0xFFFF):
                            kind = "u8" if imm == 0xFF else "u16"
                        elif op == 0 and (word & 0x3F) == 0 and rt == reg and (word >> 6) & 31 in (16, 24) \
                                and insn.index + 1 < len(words):
                            after = words[insn.index + 1]
                            shift = (word >> 6) & 31
                            if after >> 26 == 0 and (after & 0x3F) == 3 and (after >> 6) & 31 == shift \
                                    and (after >> 16) & 31 == (word >> 11) & 31:
                                kind = "s8" if shift == 24 else "s16"
                        if kind is not None:
                            out[k]["mask"].add(kind)
                        else:
                            out[k]["read"] = True
            for reg in insn.defs:
                written.add(reg)
            if insn.kind == "call":
                # the delay slot still sees the arguments; everything after does not
                if insn.index + 1 < len(self.insns):
                    slot = self.insns[insn.index + 1]
                    sword = slot.word
                    sop, srs, srt, simm2 = sword >> 26, (sword >> 21) & 31, (sword >> 16) & 31, sword & 0xFFFF
                    if srs == SP and sop == 43 and srt in _ARGS and srt not in written \
                            and simm2 == adjust + 4 * (srt - 4):
                        out[srt - 4]["homed"] = True
                written.update(_ARGS)
        return out

    def entry_arguments(self) -> set[int]:
        """a0..a3 indices that are read before being written (the function's own arguments)."""
        return {reg - 4 for reg in self.flow.live_in if reg in _ARGS}


# ------------------------------------------------------------------------------------------------
# rule: byte arithmetic

def _u8_pointer(expression):
    return c_ast.Cast(c_ast.Typename(None, [], None, c_ast.PtrDecl([], c_ast.TypeDecl(
        None, [], None, c_ast.IdentifierType(["u8"])))), expression)


def _symbol_address(name: str) -> int | None:
    found = re.fullmatch(r"(?:D|B|jtbl|func)_([0-9A-Fa-f]{8})", name)
    return int(found.group(1), 16) if found else None


def _strip_casts(node):
    while isinstance(node, c_ast.Cast):
        node = node.expr
    return node


def _sum_symbol(node) -> tuple[int, bool] | None:
    """(address, indexed) when ``node`` is ``&D_x`` / ``D_x`` plus optional constants and an index."""
    node = _strip_casts(node)
    if isinstance(node, c_ast.UnaryOp) and node.op == "&":
        node = _strip_casts(node.expr)
    if isinstance(node, c_ast.ID):
        address = _symbol_address(node.name)
        return (address, False) if address is not None else None
    if isinstance(node, c_ast.BinaryOp) and node.op in ("+", "-"):
        left, right = _sum_symbol(node.left), _sum_symbol(node.right)
        if left is not None and right is None:
            value = _constant(_strip_casts(node.right))
            if value is not None:
                return (left[0] + (value if node.op == "+" else -value)) & 0xFFFFFFFF, left[1]
            return left[0], True
        if right is not None and left is None and node.op == "+":
            value = _constant(_strip_casts(node.left))
            if value is not None:
                return (right[0] + value) & 0xFFFFFFFF, right[1]
            return right[0], True
    return None


def byte_arithmetic(draft: Draft, target: Target) -> int:
    """Rewrite pointer sums in bytes; returns the number of rewrites."""
    types = draft.types
    done = 0
    handled: dict[int, object] = {}                     # id -> node (kept alive) of sums already in bytes

    def mark(node) -> None:
        handled[id(node)] = node

    for _round in range(200):
        parents = _parents(draft.function)
        stores = {id(node.lvalue) for node in _walk(draft.function) if isinstance(node, c_ast.Assignment)}
        changed = False
        for node in list(_walk(draft.function.body)):
            entry = parents.get(id(node))
            if entry is None:
                continue
            if isinstance(node, c_ast.BinaryOp) and node.op in ("+", "-") and id(node) not in handled:
                left, right = types.of(node.left), types.of(node.right)
                lp, rp = _pointer(left), _pointer(right)
                if lp and rp and node.op == "-":
                    if types.sizeof(left[1]) != 1 or types.sizeof(right[1]) != 1:
                        node.left, node.right = _u8_pointer(node.left), _u8_pointer(node.right)
                        mark(node)
                        done, changed = done + 1, True
                        break
                    continue
                if lp == rp:
                    continue
                side, kind = ("left", left) if lp else ("right", right)
                if not lp and node.op == "-":
                    continue
                if types.sizeof(kind[1]) == 1:
                    continue
                setattr(node, side, _u8_pointer(getattr(node, side)))
                mark(node)
                wrapped = _cast(("p", kind[1]), node, types)
                if wrapped is not None:
                    _set(entry, wrapped)
                done, changed = done + 1, True
                break
            if isinstance(node, c_ast.Assignment) and node.op in ("+=", "-=") and id(node) not in handled:
                kind = types.of(node.lvalue)
                if _pointer(kind) and types.sizeof(kind[1]) != 1 and not _pointer(types.of(node.rvalue)):
                    summed = c_ast.BinaryOp(node.op[0], _u8_pointer(copy.deepcopy(node.lvalue)), node.rvalue)
                    mark(summed)
                    wrapped = _cast(("p", kind[1]), summed, types)
                    if wrapped is None:
                        continue
                    node.op, node.rvalue = "=", wrapped
                    mark(node)
                    done, changed = done + 1, True
                    break
            if isinstance(node, c_ast.ArrayRef) and id(node) not in handled:
                kind = types.of(node.name)
                if _pointer(kind) and kind[1] == ("u",):
                    summed = c_ast.BinaryOp("+", _u8_pointer(node.name), node.subscript)
                    mark(summed)
                    wrapped = _cast(("p", ("u",)), summed, types)
                    new = c_ast.UnaryOp("*", wrapped)
                    _set(entry, new)
                    done, changed = done + 1, True
                    break
        if not changed:
            break
    # a dereference of a sum on a symbol takes the width the target uses at that address
    parents = _parents(draft.function)
    stores = {id(node.lvalue) for node in _walk(draft.function) if isinstance(node, c_ast.Assignment)}
    for node in list(_walk(draft.function.body)):
        if not (isinstance(node, c_ast.UnaryOp) and node.op == "*"):
            continue
        found = _sum_symbol(node.expr)
        if found is None or not found[1]:
            continue
        seen = target.symbols.get(found[0])
        if not seen:
            continue
        kind = "store" if id(node) in stores else "load"
        names = {name for which, name in seen if which == kind}
        if kind == "store":
            names = {{"s8": "s8", "s16": "s16", "s32": "s32", "f32": "f32", "f64": "f64"}[n] for n in names}
        if len(names) != 1:
            continue
        wanted = _BASE[names.pop()]
        current = types.of(node)
        if current == wanted:
            continue
        if kind == "store" and current is not None and current[0] == wanted[0] and current[1] == wanted[1]:
            continue                                        # same width: the declared signedness stands
        node.expr = _cast(("p", wanted), node.expr, types)
        done += 1
    return done


def unsigned_stores(draft: Draft) -> int:
    """``*(s8 *)p = 0xFF``: the target loaded the constant as written, so the object is unsigned
    (a signed one would have been loaded as -1)."""
    done = 0
    for node in _walk(draft.function.body):
        if not (isinstance(node, c_ast.Assignment) and node.op == "="):
            continue
        value = _constant(node.rvalue)
        target = node.lvalue
        if value is None or not (isinstance(target, c_ast.UnaryOp) and target.op == "*"
                                 and isinstance(target.expr, c_ast.Cast)):
            continue
        kind = draft.types.of_decl(target.expr.to_type)
        if kind is None or kind[0] != "p" or kind[1] is None or kind[1][0] != "i" or not kind[1][2]:
            continue
        width = kind[1][1]
        if width in (1, 2) and (1 << (8 * width - 1)) <= value < (1 << (8 * width)):
            target.expr.to_type = c_ast.Typename(None, [], None, _type_node(("p", ("i", width, False))))
            done += 1
    return done


def address_constants(draft: Draft, target: Target) -> int:
    """A constant that the target forms with ``lui``/``addiu`` (or reads through ``%lo``) is the
    address of a symbol; a number would have been loaded with ``lui``/``ori``."""
    # the two halves may sit in different blocks (IDO hoists the ``lui`` into a branch delay slot),
    # so they are matched by value: ``lui hi`` with the carry of a signed low half and an ``addiu``
    # of that low half, and no ``ori`` of the same low half
    upper, lower, ored = set(), set(), set()
    for insn in target.insns:
        word = insn.word
        op, rs, rt, imm = word >> 26, (word >> 21) & 31, (word >> 16) & 31, word & 0xFFFF
        if op == 15:
            upper.add(imm)
        elif op == 9 and rs == rt and rs not in (0, SP):
            lower.add(imm)
        elif op == 13 and rs == rt:
            ored.add(imm)

    def is_address(value: int) -> bool:
        low = value & 0xFFFF
        return ((value + 0x8000) >> 16) & 0xFFFF in upper and low in lower and low not in ored

    parents = _parents(draft.function.body)
    declared = {node.name for node in draft.ast.ext if isinstance(node, c_ast.Decl)}
    done = 0
    for node in list(_walk(draft.function.body)):
        value = _constant(node) if isinstance(node, c_ast.Constant) else None
        if value is None or not 0x80000000 <= value < 0x80800000 or not is_address(value):
            continue
        entry = parents.get(id(node))
        if entry is None or isinstance(entry[0], (c_ast.Case, c_ast.ArrayDecl)):
            continue
        name = f"D_{value:08X}"
        if name not in declared:
            declared.add(name)
            kind = c_ast.TypeDecl(name, [], None, c_ast.IdentifierType(["u8"]))
            draft.ast.ext.insert(draft.ast.ext.index(draft.function),
                                 c_ast.Decl(name, [], [], ["extern"], [], kind, None, None))
            draft.types.globals[name] = ("i", 1, False)
        _set(entry, _cast(("i", 4, True), c_ast.UnaryOp("&", c_ast.ID(name))))
        done += 1
    return done


def _leaf(node) -> bool:
    return isinstance(node, c_ast.ID)


def _operator(node) -> bool:
    return isinstance(node, c_ast.BinaryOp) and node.op in ("*", "<<", ">>", "+", "-", "&", "|", "^", "/", "%")


def operand_order(draft: Draft) -> int:
    """The decompiler prints a sum in the order of the instruction's operands.  IDO puts a plain
    variable after an operator expression unless the variable is converted, so ``a + (b * 4)``
    comes back as ``(b * 4) + a``: a variable written first gets a cast to its own type."""
    types = draft.types
    done = 0
    for node in list(_walk(draft.function.body)):
        if not (isinstance(node, c_ast.BinaryOp) and node.op in ("+", "|", "^", "&")):
            continue
        if not (_leaf(node.left) and _operator(node.right)):
            continue
        kind = types.of(node.left)
        if kind is None or kind[0] not in ("i", "p") or (kind[0] == "i" and kind[1] != 4):
            continue
        wrapped = _cast(kind, node.left, types)
        if wrapped is None:
            continue
        node.left = wrapped
        done += 1
    return done


def field_bases(draft: Draft) -> int:
    """``(s8 *)(base + index * n) + offset``: the cast belongs to the base, as in a field access
    through an indexed pointer, which keeps the base first in the sum."""
    done = 0
    for node in list(_walk(draft.function.body)):
        if not isinstance(node, c_ast.Cast):
            continue
        kind = draft.types.of_decl(node.to_type)
        if kind is None or kind[0] != "p" or draft.types.sizeof(kind[1]) != 1:
            continue
        inner = node.expr
        if not (isinstance(inner, c_ast.BinaryOp) and inner.op == "+" and _leaf(inner.left)
                and _operator(inner.right)):
            continue
        left = draft.types.of(inner.left)
        if left is None or left[0] not in ("i", "p") or _pointer(draft.types.of(inner.right)):
            continue
        if left[0] == "p" and draft.types.sizeof(left[1]) != 1:
            continue                                        # byte_arithmetic owns this sum
        inner.left = c_ast.Cast(copy.deepcopy(node.to_type), inner.left)
        done += 1
    return done


# ------------------------------------------------------------------------------------------------
# rule: calls and the function's own parameters

def _calls_in_order(function) -> list:
    """Real calls in evaluation order (arguments before the call that takes them)."""
    out = []

    def visit(node):
        for _name, child in node.children():
            visit(child)
        if isinstance(node, c_ast.FuncCall):
            callee = _strip_casts(node.name)
            if isinstance(callee, c_ast.ID) and callee.name in _MACRO_CALLS:
                return
            out.append(node)
    visit(function.body)
    return out


def _slot_of(name: str) -> int | None:
    found = re.fullmatch(r"arg(\d+)", name)
    return int(found.group(1)) if found else None


def _parameter(index: int, kind: str = "s32"):
    name = f"arg{index}"
    return c_ast.Decl(name, [], [], [], [], c_ast.TypeDecl(name, [], None, c_ast.IdentifierType([kind])),
                      None, None)


def complete_parameters(draft: Draft, needed: set[int] = frozenset()) -> int:
    """Fill the gaps of the parameter list (``f(arg0, arg4)`` means five parameters) and add the
    ones in ``needed``; returns how many were added."""
    declaration = draft.function.decl.type
    current = draft.parameters()
    slots = {}
    for parameter in current:
        slot = _slot_of(parameter.name)
        if slot is None:
            return 0                                        # not the decompiler's naming: leave alone
        kind = draft.types.of_decl(parameter.type)
        slots[slot] = (parameter, 2 if kind in (("f", 8), ("i", 8, True), ("i", 8, False)) else 1)
    if not slots and not needed:
        return 0
    top = max([*slots, *needed])
    out, slot, added = [], 0, 0
    while slot <= top:
        if slot in slots:
            out.append(slots[slot][0])
            slot += slots[slot][1]
            continue
        out.append(_parameter(slot))
        added += 1
        slot += 1
    if not added:
        return 0
    declaration.args = c_ast.ParamList(out)
    # an earlier prototype of the function itself would now disagree: make it unprototyped
    for node in draft.ast.ext:
        if isinstance(node, c_ast.Decl) and node.name == draft.name and isinstance(node.type, c_ast.FuncDecl):
            node.type.args = None
    draft.types.refresh(draft)
    return added


def _is_narrow(kind) -> bool:
    return kind is not None and kind[0] == "i" and kind[1] < 4


def parameter_types(draft: Draft, target: Target) -> int:
    """Narrow parameters exactly where the target homes them.

    IDO stores every ``char``/``short`` parameter register to its slot in the caller's frame, in
    leaf functions too, and re-extends it where it is used; a word parameter that is not needed
    after a call is never stored.  A parameter the draft types narrow that the target does not
    home is a word; one that is homed, never reloaded as a word and extended one way is narrow."""
    homes = target.homes()
    done = 0
    for parameter in draft.parameters():
        slot = _slot_of(parameter.name)
        if slot is None or slot > 3 or not isinstance(parameter.type, c_ast.TypeDecl):
            continue
        kind = draft.types.of_decl(parameter.type)
        if kind is None or kind[0] not in ("i", "u") or (kind[0] == "i" and kind[1] > 4):
            continue
        info = homes[slot]
        wanted = None
        if not info["homed"]:
            if _is_narrow(kind):
                wanted = ("i", 4, True)
        else:
            seen = set(info["narrow"])
            if not seen and not info["word"] and not info["read"]:
                seen = set(info["mask"])
            if len(seen) == 1 and "?" not in seen:
                wanted = _BASE[seen.pop()]
                if _is_narrow(kind) and kind[1] == wanted[1] and not info["narrow"] and not info["mask"]:
                    wanted = None
        if wanted is None or wanted == kind:
            continue
        parameter.type.type = c_ast.IdentifierType([_NAME_OF[wanted]])
        done += 1
        if _is_narrow(wanted):                              # the extension is now implied: drop the explicit one
            name = parameter.name
            mask = {1: 0xFF, 2: 0xFFFF}[wanted[1]]
            parents = _parents(draft.function.body)
            for node in list(_walk(draft.function.body)):
                entry = parents.get(id(node))
                if entry is None:
                    continue
                if isinstance(node, c_ast.BinaryOp) and node.op == "&" and not wanted[2]:
                    for side, other in (("left", "right"), ("right", "left")):
                        operand = _strip_casts(getattr(node, side))
                        if isinstance(operand, c_ast.ID) and operand.name == name \
                                and _constant(getattr(node, other)) == mask:
                            _set(entry, c_ast.ID(name))
                            break
                elif isinstance(node, c_ast.Cast) and isinstance(node.expr, c_ast.ID) and node.expr.name == name \
                        and draft.types.of_decl(node.to_type) == wanted:
                    _set(entry, c_ast.ID(name))
    if done:
        draft.types.refresh(draft)
    return done


def _passed_on(draft: Draft, target: Target) -> set[int]:
    """Own register arguments that can only have gone to a callee: the draft declares them, the
    target neither reads nor homes them, and the function calls (IDO homes an unused parameter
    of a function that calls)."""
    if not target.calls:
        return set()
    homes = target.homes()
    out = set()
    for parameter in draft.parameters():
        slot = _slot_of(parameter.name)
        kind = draft.types.of_decl(parameter.type)
        if slot is None or slot > 3 or kind is None or kind[0] == "f" or draft.types.sizeof(kind) != 4:
            continue
        info = homes[slot]
        if not info["homed"] and not info["read"] and not info["mask"] and (slot + 4) not in target.flow.live_in:
            out.add(slot)
    return out


def complete_calls(draft: Draft, target: Target) -> int:
    """Complete the argument lists from the register state at each call in the target."""
    calls = _calls_in_order(draft.function)
    if not calls or len(calls) != len(target.calls):
        return 0
    for node, call in zip(calls, target.calls):               # the two orders must tell the same story
        callee = _strip_casts(node.name)
        address = _symbol_address(callee.name) if isinstance(callee, c_ast.ID) else None
        if address is not None and call.target is not None and address != call.target:
            return 0
    done, needed = 0, set()
    passed = _passed_on(draft, target)
    for node, call in zip(calls, target.calls):
        if call.floats:
            continue
        given = list(node.args.exprs) if node.args is not None else []
        written = [k for k in range(4) if call.state[k] in ("S", "R")]
        if any(call.state[k] == "D" and any(j > k for j in written) for k in range(4)):
            continue
        if len(given) != len(written) + len(call.stack):
            continue
        if call.stack:
            count = 4
        else:
            # the highest register that can only be an argument: written and never read here, or
            # written with every lower register written too
            count = 0
            for k in reversed(written):
                if call.state[k] == "S" or all(j in written for j in range(k)):
                    count = k + 1
                    break
            for k in sorted(passed):
                if call.state[k] == "E" and k + 1 > count:
                    count = k + 1
        if any(call.state[k] == "D" for k in range(count)):
            continue
        new = []
        for k in range(count):
            if k in written:
                new.append(given[written.index(k)])
            else:
                new.append(c_ast.ID(f"arg{k}"))
                needed.add(k)
        new += given[len(written):]
        if len(new) == len(given) and all(a is b for a, b in zip(new, given)):
            continue
        node.args = c_ast.ExprList(new) if new else None
        done += 1
    if needed:
        existing = {_slot_of(p.name) for p in draft.parameters()}
        if None in existing:
            return 0
        complete_parameters(draft, needed)
    return done


# ------------------------------------------------------------------------------------------------
# rule: frame

def _stack_offset(name: str) -> int | None:
    found = re.fullmatch(r"sp([0-9A-F]+)", name)
    return int(found.group(1), 16) if found else None


def _statements(body):
    """(statement, containing list, index) for every statement in a compound, recursively."""
    stack = [body]
    while stack:
        node = stack.pop()
        if isinstance(node, c_ast.Compound):
            items = node.block_items or []
            for index, item in enumerate(items):
                yield item, items, index
                stack.append(item)
        else:
            for _name, child in node.children():
                if isinstance(child, (c_ast.Compound, c_ast.If, c_ast.While, c_ast.DoWhile, c_ast.For, c_ast.Switch,
                                      c_ast.Case, c_ast.Default, c_ast.Label)):
                    stack.append(child)


def _uses(function) -> dict[str, dict]:
    """name -> {"read": n, "write": n, "addr": n} over the function body."""
    out: dict[str, dict] = {}
    writes, addresses = set(), set()
    for node in _walk(function.body):
        if isinstance(node, c_ast.Assignment) and isinstance(node.lvalue, c_ast.ID):
            writes.add(id(node.lvalue))
            row = out.setdefault(node.lvalue.name, {"read": 0, "write": 0, "addr": 0})
            row["write"] += 1
            if node.op != "=":
                row["read"] += 1
        elif isinstance(node, c_ast.UnaryOp) and isinstance(node.expr, c_ast.ID):
            if node.op == "&":
                addresses.add(id(node.expr))
                out.setdefault(node.expr.name, {"read": 0, "write": 0, "addr": 0})["addr"] += 1
            elif node.op in ("++", "--", "p++", "p--"):
                writes.add(id(node.expr))
                row = out.setdefault(node.expr.name, {"read": 0, "write": 0, "addr": 0})
                row["write"] += 1
                row["read"] += 1
    for node in _walk(function.body):
        if isinstance(node, c_ast.ID) and id(node) not in writes and id(node) not in addresses:
            out.setdefault(node.name, {"read": 0, "write": 0, "addr": 0})["read"] += 1
    return out


def _rename(function, old: str, new) -> None:
    """Replace every use of the variable ``old`` by ``new`` (a name, or a function building a node)."""
    parents = _parents(function.body)
    for node in list(_walk(function.body)):
        if isinstance(node, c_ast.ID) and node.name == old:
            entry = parents.get(id(node))
            if entry is None:
                continue
            if isinstance(entry[0], c_ast.StructRef) and entry[1] == "field":
                continue
            if callable(new):
                _set(entry, new())
            else:
                node.name = new


def merge_spills(draft: Draft) -> int:
    """``temp = value; ... spXX = temp;``: the slot is the variable's own home (the decompiler
    shows the store the compiler made to keep the value across a call).  When every write of
    the slot is such a copy of one variable, the variable takes the slot's name and the copies go."""
    body = draft.function.body
    done = 0
    for _round in range(32):
        uses = _uses(draft.function)
        declared = {decl.name: decl for decl in draft.locals()}
        copies: dict[str, list] = {}
        for statement, items, _index in _statements(body):
            if isinstance(statement, c_ast.Assignment) and statement.op == "=" \
                    and isinstance(statement.lvalue, c_ast.ID) and isinstance(statement.rvalue, c_ast.ID):
                copies.setdefault(statement.lvalue.name, []).append((statement, items))
        changed = False
        for slot, rows in copies.items():
            sources = {statement.rvalue.name for statement, _items in rows}
            if len(sources) != 1:
                continue
            temp = sources.pop()
            if _stack_offset(slot) is None or _stack_offset(temp) is not None:
                continue
            if slot not in declared or temp not in declared:
                continue
            a, b = uses.get(slot, {}), uses.get(temp, {})
            if a.get("write") != len(rows) or a.get("addr") or b.get("addr"):
                continue
            if len(rows) > 1 and b.get("write", 0) < 1:
                continue
            if draft.types.sizeof(draft.types.of_decl(declared[slot].type)) != \
                    draft.types.sizeof(draft.types.of_decl(declared[temp].type)):
                continue
            for statement, items in rows:
                for index, item in enumerate(items):
                    if item is statement:
                        del items[index]
                        break
            _rename(draft.function, temp, slot)
            kept = declared[temp]
            for node in _walk(kept):
                if isinstance(node, c_ast.TypeDecl):
                    node.declname = slot
            kept.name = slot
            draft.function.body.block_items.remove(declared[slot])
            done, changed = done + 1, True
            break
        if not changed:
            break
    if done:
        draft.types.refresh(draft)
    return done


def _field(name: str, type_node):
    node = copy.deepcopy(type_node)
    for inner in _walk(node):
        if isinstance(inner, c_ast.TypeDecl):
            inner.declname = name
    return c_ast.Decl(name, [], [], [], [], node, None, None)


def _pad_decl(name: str, words: int | None):
    """``s32 name[words]`` or, for ``words`` None, one ``char name``."""
    if words is None:
        return c_ast.Decl(name, [], [], [], [], c_ast.TypeDecl(name, [], None, c_ast.IdentifierType(["char"])),
                          None, None)
    inner = c_ast.TypeDecl(name, [], None, c_ast.IdentifierType(["s32"]))
    if words == 1:
        return c_ast.Decl(name, [], [], [], [], inner, None, None)
    return c_ast.Decl(name, [], [], [], [], c_ast.ArrayDecl(inner, c_ast.Constant("int", str(words)), []), None, None)


def group_aggregates(draft: Draft, target: Target) -> int:
    """Stack variables the target only writes (or only reads) cannot be variables of their own:
    an optimising compiler would have dropped the store.  They are fields of the local whose
    address is taken below them."""
    slots = target.slots()
    bases = sorted(offset for offset, row in slots.items() if row["addr"])
    if not bases:
        return 0
    declared = {decl.name: decl for decl in draft.locals()}
    stack = {}
    for name, decl in declared.items():
        offset = _stack_offset(name)
        if offset is not None and target.locals_low <= offset < target.frame and isinstance(decl.type, c_ast.TypeDecl):
            stack[offset] = decl
    members: dict[int, list[int]] = {}
    for offset in sorted(stack):
        row = slots.get(offset)
        if row is None or row["addr"] or (row["load"] and row["store"]) or not (row["load"] or row["store"]):
            continue
        below = [base for base in bases if base < offset]
        if not below:
            continue
        members.setdefault(below[-1], []).append(offset)
    done = 0
    types = draft.types
    for base, offsets in members.items():
        fields, layout, position, usable = [], [], 0, True
        every = ([base] if base in stack else []) + offsets
        for offset in every:
            decl = stack[offset]
            kind = types.of_decl(decl.type)
            size, align = types.sizeof(kind), types.alignof(kind)
            if size is None or align is None or (kind[0] == "s"):
                usable = False
                break
            relative = offset - base
            natural = (position + align - 1) // align * align
            if natural > relative:
                usable = False
                break
            if natural < relative:
                gap = relative - position
                pad = c_ast.TypeDecl(f"pad{position:X}", [], None, c_ast.IdentifierType(["char"]))
                fields.append(c_ast.Decl(f"pad{position:X}", [], [], [], [], c_ast.ArrayDecl(
                    pad, c_ast.Constant("int", str(gap)), []), None, None))
            fields.append(_field(f"f{relative:X}", decl.type))
            layout.append((offset, f"f{relative:X}"))
            position = relative + size
        if not usable or not fields:
            continue
        name = f"sp{base:X}"
        struct_decl = c_ast.Decl(name, [], [], [], [], c_ast.TypeDecl(name, [], None, c_ast.Struct(None, fields)),
                                 None, None)
        block = draft.function.body.block_items
        first = block.index(stack[every[0]])
        for offset, field in layout:
            old = f"sp{offset:X}"
            _rename(draft.function, old, lambda field=field: c_ast.StructRef(c_ast.ID(name), ".", c_ast.ID(field)))
        for offset in every:
            block.remove(stack[offset])
        if base not in stack:                               # the address-taken base had another declaration
            for decl in list(block):
                if isinstance(decl, c_ast.Decl) and decl.name == name:
                    block.remove(decl)
        block.insert(min(first, len(block)), struct_decl)
        done += 1
    if done:
        draft.types.refresh(draft)
    return done


def order_frame(draft: Draft, target: Target) -> int:
    """Declare the locals so that each stack variable lands on its offset in the target."""
    if not target.frame:
        return 0
    block = draft.function.body.block_items
    leading = 0
    while leading < len(block) and isinstance(block[leading], c_ast.Decl):
        leading += 1
    if any(isinstance(item, c_ast.Decl) for item in block[leading:]):
        return 0
    declared = block[:leading]
    if any(not decl.name or decl.init is not None or "static" in decl.storage or "extern" in decl.storage
           for decl in declared):
        return 0
    types = draft.types
    uses = _uses(draft.function)
    low, top = target.locals_low, target.frame
    placed, others = [], []
    for decl in declared:
        offset = _stack_offset(decl.name)
        kind = types.of_decl(decl.type)
        size, align = types.sizeof(kind), types.alignof(kind)
        if offset is None or not low <= offset < top:
            others.append(decl)
            continue
        if size is None or align is None:
            return 0
        if kind[0] in ("a", "s"):
            align = max(4, align)
        placed.append((offset, size, align, decl))
    placed.sort(key=lambda row: -row[0])
    out, cursor, pads = [], top, 0
    holes: list[tuple[int, int]] = []                    # (index in out, words) of padding that could hold a temporary
    for offset, size, align, decl in placed:
        natural = (cursor - size) // align * align
        if natural < offset:
            return 0                                        # two variables overlap: not a layout this rule can write
        gap = natural - offset
        while gap > 0 and (cursor % 4 or gap < 4):          # single bytes down to a word boundary
            out.append(_pad_decl(f"pad{pads}", None))
            pads, cursor, gap = pads + 1, cursor - 1, gap - 1
            natural = (cursor - size) // align * align
            gap = natural - offset
        if gap >= 4:
            words = gap // 4
            holes.append((len(out), words))
            out.append(_pad_decl(f"pad{pads}", words))
            pads, cursor = pads + 1, cursor - 4 * words
        if (cursor - size) // align * align != offset:
            return 0
        out.append(decl)
        cursor = offset
    others = [decl for decl in others if uses.get(decl.name, {}).get("read") or uses.get(decl.name, {}).get("write")
              or uses.get(decl.name, {}).get("addr")]
    escaping = any(row.get("addr") for name, row in uses.items() if name in {d.name for d in declared}) or any(
        (types.of_decl(decl.type) or ("?",))[0] in ("a", "s") for decl in out + others)
    if escaping and others:
        # with an address taken the frame ends at the lowest declared local: the temporaries that
        # do not fit below the last stack variable go where the target has unexplained room
        room = max(0, cursor - low) // 4
        below, above = [], []
        for decl in others:
            size = types.sizeof(types.of_decl(decl.type)) or 4
            words = (size + 3) // 4
            if words <= room:
                below.append(decl)
                room -= words
            else:
                above.append(decl)
        for decl in above:
            size = types.sizeof(types.of_decl(decl.type)) or 4
            words = (size + 3) // 4
            for at in range(len(holes) - 1, -1, -1):
                index, free = holes[at]
                if free >= words and size % 4 == 0:
                    pad = out[index]
                    remaining = free - words
                    out.insert(index + 1, decl)
                    if remaining:
                        out[index] = _pad_decl(pad.name, remaining)
                        holes[at] = (index, remaining)
                    else:
                        del out[index]
                        holes[at] = (index, 0)
                        index -= 1
                    holes = [(i + (1 if i > index and j != at else 0) + (0 if remaining or i <= index else -1), w)
                             if j != at else holes[at] for j, (i, w) in enumerate(holes)]
                    break
            else:
                below.append(decl)
        others = below
    new = out + others
    if [id(d) for d in new] == [id(d) for d in declared]:
        return 0
    block[:leading] = new
    draft.types.refresh(draft)
    return 1


def frame_layout(draft: Draft, target: Target) -> int:
    if not target.frame:
        return 0
    done = merge_spills(draft)
    done += group_aggregates(draft, target)
    done += order_frame(draft, target)
    return done


# ------------------------------------------------------------------------------------------------
# situation and entry point

def _optimised(target: Target) -> bool:
    """Unoptimised IDO code keeps every value in the frame: most instructions touch the stack."""
    count = len(target.insns)
    if count < 8 or not target.frame:
        return True
    touching = sum(1 for insn in target.insns if (insn.word >> 21) & 31 == SP and (insn.word >> 26) >= 32)
    return touching * 3 < count


def _mine(pipeline: str, flags: tuple[str, ...], family: str | None) -> bool:
    if pipeline.startswith("ido"):
        return True
    return family == "ido"


def _build(source: str, name: str, target: Target, rules: tuple[str, ...]) -> str | None:
    try:
        draft = Draft(source, name)
    except Exception:
        return None
    applied = 0
    for rule in rules:
        try:
            if rule == "bytes":
                applied += byte_arithmetic(draft, target)
            elif rule == "parameters":
                applied += complete_parameters(draft)
            elif rule == "calls":
                applied += complete_calls(draft, target)
            elif rule == "widths":
                applied += parameter_types(draft, target)
            elif rule == "stores":
                applied += unsigned_stores(draft)
            elif rule == "addresses":
                applied += address_constants(draft, target)
            elif rule == "order":
                applied += operand_order(draft)
            elif rule == "bases":
                applied += field_bases(draft)
            elif rule == "frame":
                applied += frame_layout(draft, target)
        except Exception:
            return None
    if not applied:
        return None
    try:
        return draft.text()
    except Exception:
        return None


def variants(source: str, name: str, *, code: bytes, vram: int, pipeline: str, flags: tuple[str, ...] = (),
             family: str | None = None) -> list[tuple[str, str]]:
    """[(label, complete C translation unit)] for an optimised IDO function, best first."""
    if c_parser is None or not _mine(pipeline, tuple(flags), family):
        return []
    if len(code) < 8 or len(code) // 4 > MAX_INSNS:
        return []
    try:
        target = Target(code, vram)
    except Exception:
        return []
    explicit = any(re.fullmatch(r"-O[123]", flag) for flag in flags) and pipeline.startswith("ido")
    if not explicit and not _optimised(target):
        return []
    out, seen = [], {source}
    base = ("parameters", "widths", "calls", "addresses", "stores", "bases", "bytes")
    for label, rules in (("ido-opt: all", base + ("frame",)),
                         ("ido-opt: all+order", base + ("frame", "order")),
                         ("ido-opt: no frame", base),
                         ("ido-opt: bytes", ("bytes",))):
        text = _build(source, name, target, rules)
        if text and text not in seen:
            seen.add(text)
            out.append((label, text))
    return out[:6]
