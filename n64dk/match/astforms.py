"""Parser-backed source transformations for ``iterate``: deterministic, enumerable single-step
variants of one function, in the spirit of decomp-permuter's randomizer passes.

Families (all labels name the construct and its line):

``temp``         introduce a temporary for a side-effect-free sub-expression (declared at the
                 top of the function, assigned right before the statement or at the earliest
                 commuting point, optionally reused for later identical occurrences)
``inline-temp``  substitute a local that is assigned once and read once or twice
``stmt-order``   move a statement up/down past neighbours it commutes with (any block)
``decl-order``   reorder local declarations; move a declaration into the innermost block that
                 holds all its uses, or out to the function block
``control``      if/else inversion, early-return <-> nested else, while <-> if+do-while <->
                 for(;c;), for <-> init+while, ``&&`` <-> nested ifs, ternary <-> if/else
``expr``         commutation, ``x op= y`` <-> ``x = x op y``, increment spellings, ``!x`` <->
                 ``x == 0``, ``x`` <-> ``x != 0`` in conditions, comparison forms,
                 ``*(p + i)`` <-> ``p[i]``, ``(*p).f`` <-> ``p->f``, ``&p[i]`` <-> ``p + i``
``cast``         add/remove integer casts, change an integer local/parameter type (always
                 ``semantic_review``)
``block``        wrap statements in ``do { } while (0)`` / ``if (1) { }`` and unwrap
``sameline``     join two statements onto one line / split them

Behaviour preservation: ``semantic_review=False`` only when the conservative analysis below
shows the edit preserves behaviour.  See ``Effects`` and ``commute``.
"""
from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field

from pycparser import c_ast

from . import astprep
from .astprep import PrepError, Prepared, SNode, apply_edits, expr_text, reindent, simple_stmt_text
from .iterate import Variant

FAMILIES: tuple[str, ...] = ("temp", "inline-temp", "stmt-order", "decl-order", "control", "expr",
                             "cast", "block", "sameline")
INVERSE = {"temp": "inline-temp", "inline-temp": "temp"}
CAST_NAMES = ("s16", "u16", "s8", "u8", "s32", "u32")
_C_NAMES = {"s16": ["short"], "u16": ["unsigned", "short"], "s8": ["signed", "char"], "u8": ["unsigned", "char"],
            "s32": ["int"], "u32": ["unsigned", "int"]}
_ARITH = {"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"}
_COMMUTATIVE = {"+", "*", "&", "|", "^", "==", "!="}
_FLIP = {"<": ">", ">": "<", "<=": ">=", ">=": "<="}
_NEGATE = {"==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">"}
_LOGICAL = {"&&", "||"}
_COMPARE = {"==", "!=", "<", ">", "<=", ">="}


# ============================================================================== types
def _mk(names):
    return c_ast.TypeDecl(None, [], None, c_ast.IdentifierType(list(names)))


INT, UINT, DOUBLE, FLOAT = _mk(["int"]), _mk(["unsigned", "int"]), _mk(["double"]), _mk(["float"])


class Types:
    """Declared and inferred C types of the function's expressions."""

    def __init__(self, prep: Prepared):
        self.env = prep.env
        self.vars: dict[str, object] = {}
        self.params: dict[str, object] = {}
        self.local_decls: dict[str, list] = {}
        self.static_locals: set[str] = set()
        args = prep.fn.decl.type.args
        for param in (args.params if args else []):
            if isinstance(param, c_ast.Decl) and param.name:
                self.params[param.name] = param.type
                self.vars[param.name] = param.type
        self.local_structs = {}

        def walk(node):
            if isinstance(node, c_ast.Decl) and node.name and not isinstance(node.type, c_ast.FuncDecl):
                self.local_decls.setdefault(node.name, []).append(node)
                self.vars[node.name] = node.type
                if "static" in node.storage or "extern" in node.storage:
                    self.static_locals.add(node.name)
            if isinstance(node, (c_ast.Struct, c_ast.Union)) and node.decls is not None and node.name:
                self.local_structs.setdefault(node.name, node)
            for _, child in node.children():
                walk(child)
        walk(prep.fn.body)

    # -- declared types
    def var_type(self, name):
        if name in self.vars:
            return self.vars[name]
        decl = self.env.globals.get(name)
        if decl is not None:
            return decl.type
        if name in self.env.enumerators:
            return INT
        return None

    def resolve(self, t, depth=0):
        while depth < 30 and isinstance(t, c_ast.TypeDecl) and isinstance(t.type, c_ast.IdentifierType) \
                and len(t.type.names) == 1 and t.type.names[0] in self.env.typedefs:
            nxt = self.env.typedefs[t.type.names[0]]
            if nxt is t:
                break
            t, depth = nxt, depth + 1
        if isinstance(t, c_ast.Typename):
            return self.resolve(t.type, depth + 1)
        return t

    def kind(self, t):
        t = self.resolve(t)
        if t is None:
            return None
        if isinstance(t, c_ast.PtrDecl):
            return ("ptr", t.type)
        if isinstance(t, c_ast.ArrayDecl):
            return ("array", t.type)
        if isinstance(t, c_ast.FuncDecl):
            return ("func", t)
        if isinstance(t, c_ast.TypeDecl):
            inner = t.type
            if isinstance(inner, (c_ast.Struct, c_ast.Union)):
                return ("struct", self.struct_def(inner))
            if isinstance(inner, c_ast.Enum):
                return ("int", 4, True)
            if isinstance(inner, c_ast.IdentifierType):
                names = inner.names
                if "void" in names:
                    return ("void",)
                if "float" in names:
                    return ("float", 4)
                if "double" in names:
                    return ("float", 8)
                signed = False if "unsigned" in names else True if ("signed" in names or "char" not in names) else None
                if "char" in names:
                    return ("int", 1, signed)
                if "short" in names:
                    return ("int", 2, signed)
                if names.count("long") >= 2:
                    return ("int", 8, signed)
                if len(names) == 1 and names[0] not in ("int", "long", "signed", "unsigned"):
                    return None          # unknown typedef stand-in
                return ("int", 4, signed)
        return None

    def struct_def(self, node):
        if node.decls is not None or not node.name:
            return node
        return self.local_structs.get(node.name) or self.env.structs.get(node.name) or node

    def sig(self, t, depth=0):
        k = self.kind(t)
        if k is None or depth > 8:
            return None
        if k[0] in ("ptr", "array"):
            return (k[0], self.sig(k[1], depth + 1))
        if k[0] == "struct":
            return ("struct", id(k[1]))
        if k[0] == "func":
            return ("func",)
        return k

    def is_int(self, t):
        k = self.kind(t)
        return bool(k) and k[0] == "int"

    def is_arith(self, t):
        k = self.kind(t)
        return bool(k) and k[0] in ("int", "float")

    def is_float(self, t):
        k = self.kind(t)
        return bool(k) and k[0] == "float"

    def is_pointer(self, t):
        k = self.kind(t)
        return bool(k) and k[0] in ("ptr", "array")

    def volatile(self, t, depth=0):
        if t is None or depth > 30:
            return False
        if isinstance(t, (c_ast.TypeDecl, c_ast.PtrDecl)) and "volatile" in (t.quals or []):
            return True
        if isinstance(t, c_ast.ArrayDecl):
            return self.volatile(t.type, depth + 1)
        if isinstance(t, c_ast.TypeDecl) and isinstance(t.type, c_ast.IdentifierType) and \
                len(t.type.names) == 1 and t.type.names[0] in self.env.typedefs:
            return self.volatile(self.env.typedefs[t.type.names[0]], depth + 1)
        return False

    # -- inference
    def deref(self, t):
        k = self.kind(t)
        return k[1] if k and k[0] in ("ptr", "array") else None

    def arith(self, a, b):
        ka, kb = self.kind(a), self.kind(b)
        if not ka or not kb or ka[0] not in ("int", "float") or kb[0] not in ("int", "float"):
            return None
        if ka[0] == "float" or kb[0] == "float":
            size = max(k[1] for k in (ka, kb) if k[0] == "float")
            return DOUBLE if size == 8 else FLOAT
        if 8 in (ka[1], kb[1]):
            big = ka if ka[1] == 8 else kb
            return _mk(["unsigned", "long", "long"] if big[2] is False else ["long", "long"])
        if (ka[1] == 4 and ka[2] is False) or (kb[1] == 4 and kb[2] is False):
            return UINT
        return INT

    def promote(self, t):
        k = self.kind(t)
        if k and k[0] == "int" and k[1] < 4:
            return INT
        return t

    def typeof(self, e):
        try:
            return self._typeof(e)
        except RecursionError:
            return None

    def _typeof(self, e):
        if isinstance(e, c_ast.ID):
            return self.var_type(e.name)
        if isinstance(e, c_ast.Constant):
            if e.type == "string":
                return c_ast.PtrDecl([], _mk(["char"]))
            if e.type in ("float", "double"):
                return FLOAT if e.value.lower().endswith("f") else DOUBLE
            if e.type == "char":
                return INT
            value = e.value.lower()
            if "u" in value:
                return UINT
            number = _int_value(e)
            return UINT if number is not None and number > 0x7FFFFFFF else INT
        if isinstance(e, c_ast.Cast):
            return e.to_type.type
        if isinstance(e, c_ast.UnaryOp):
            if e.op in ("-", "+", "~"):
                return self.promote(self.typeof(e.expr))
            if e.op == "!":
                return INT
            if e.op == "*":
                return self.deref(self.typeof(e.expr))
            if e.op == "&":
                inner = self.typeof(e.expr)
                return c_ast.PtrDecl([], inner) if inner is not None else None
            if e.op in ("sizeof", "_Alignof"):
                return UINT
            return self.typeof(e.expr)
        if isinstance(e, c_ast.BinaryOp):
            if e.op in _COMPARE or e.op in _LOGICAL:
                return INT
            lt, rt = self.typeof(e.left), self.typeof(e.right)
            if e.op in ("<<", ">>"):
                return self.promote(lt)
            if e.op in ("+", "-"):
                if self.is_pointer(lt):
                    if e.op == "-" and self.is_pointer(rt):
                        return INT
                    k = self.kind(lt)
                    return c_ast.PtrDecl([], k[1]) if k[0] == "array" else lt
                if self.is_pointer(rt) and e.op == "+":
                    k = self.kind(rt)
                    return c_ast.PtrDecl([], k[1]) if k[0] == "array" else rt
            return self.arith(lt, rt)
        if isinstance(e, c_ast.ArrayRef):
            base = self.typeof(e.name)
            if self.is_pointer(base):
                return self.deref(base)
            return self.deref(self.typeof(e.subscript))
        if isinstance(e, c_ast.StructRef):
            base = self.typeof(e.name)
            if e.type == "->":
                base = self.deref(base)
            k = self.kind(base)
            if not k or k[0] != "struct" or k[1].decls is None:
                return None
            return self._field(k[1], e.field.name)
        if isinstance(e, c_ast.FuncCall):
            callee = self.typeof(e.name)
            k = self.kind(callee)
            if k and k[0] == "ptr":
                k = self.kind(k[1])
            if k and k[0] == "func":
                return k[1].type
            return None
        if isinstance(e, c_ast.TernaryOp):
            a, b = self.typeof(e.iftrue), self.typeof(e.iffalse)
            return self.arith(a, b) if self.is_arith(a) and self.is_arith(b) else a
        if isinstance(e, c_ast.Assignment):
            return self.typeof(e.lvalue)
        if isinstance(e, c_ast.ExprList) and e.exprs:
            return self.typeof(e.exprs[-1])
        return None

    def _field(self, struct, name, depth=0):
        for d in struct.decls or []:
            if d.name == name:
                return d.type
            if d.name is None and depth < 4:        # anonymous member struct/union
                k = self.kind(d.type)
                if k and k[0] == "struct" and k[1].decls:
                    found = self._field(k[1], name, depth + 1)
                    if found is not None:
                        return found
        return None

    # -- printing a declaration of a value of type t
    def alias(self, t):
        """Prefer the project's typedef names for synthetic arithmetic types."""
        if t is INT or t is UINT or t is FLOAT or t is DOUBLE:
            want = {id(INT): ("s32", ("int", 4, True)), id(UINT): ("u32", ("int", 4, False)),
                    id(FLOAT): ("f32", ("float", 4)), id(DOUBLE): ("f64", ("float", 8))}[id(t)]
            if want[0] in self.env.typedefs and self.kind(_mk([want[0]])) == want[1]:
                return _mk([want[0]])
        return t

    def decl_text(self, t, name) -> str | None:
        t = self.alias(t)
        k = self.kind(t)
        if k is None or k[0] not in ("int", "float", "ptr"):
            return None
        t = copy.deepcopy(t)
        node = t
        for _ in range(20):
            if isinstance(node, c_ast.TypeDecl):
                node.declname = name
                if isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum)) and \
                        getattr(node.type, "decls", None) or getattr(node.type, "values", None):
                    return None
                break
            if isinstance(node, c_ast.PtrDecl):
                node = node.type
                continue
            return None
        if isinstance(t, (c_ast.TypeDecl, c_ast.PtrDecl)):
            t.quals = [q for q in t.quals if q not in ("const", "volatile")]
        decl = c_ast.Decl(name, [], [], [], [], t, None, None)
        return expr_text(decl) + ";"

    def type_name(self, t) -> str | None:
        text = self.decl_text(t, "__N__")
        if text is None:
            return None
        return text[:-1].replace("__N__", "").strip()


def _int_value(e) -> int | None:
    if not isinstance(e, c_ast.Constant) or e.type not in ("int", "unsigned int", "long int",
                                                            "unsigned long int", "long long int"):
        return None
    text = e.value.rstrip("uUlL")
    try:
        return int(text, 0) if not (len(text) > 1 and text[0] == "0" and text[1].isdigit()) else int(text, 8)
    except ValueError:
        return None


# ============================================================================== effects
@dataclass
class Effects:
    reads: set = field(default_factory=set)     # register-able locals read
    writes: set = field(default_factory=set)    # register-able locals written
    memr: set = field(default_factory=set)      # memory locations read: "*", "g:name", "l:name"
    memw: set = field(default_factory=set)      # memory locations written
    call: bool = False
    volatile: bool = False
    jump: bool = False                          # escaping return/break/continue/goto or a label
    label: bool = False

    def __or__(self, other: "Effects") -> "Effects":
        return Effects(self.reads | other.reads, self.writes | other.writes, self.memr | other.memr,
                       self.memw | other.memw, self.call or other.call, self.volatile or other.volatile,
                       self.jump or other.jump, self.label or other.label)

    @property
    def side(self) -> bool:
        return bool(self.writes or self.memw or self.call or self.volatile)

    @property
    def memory(self) -> bool:
        return bool(self.memr or self.memw or self.call)


def _locs_conflict(a: set, b: set) -> bool:
    if not a or not b:
        return False
    if "*" in a or "*" in b:
        return True
    return bool(a & b)


def commute(a: Effects, b: Effects, allow_jump: bool = False) -> bool:
    """True when executing ``a`` then ``b`` is equivalent to ``b`` then ``a``."""
    if a.label or b.label or (not allow_jump and (a.jump or b.jump)):
        return False
    if a.writes & (b.reads | b.writes) or b.writes & a.reads:
        return False
    if _locs_conflict(a.memw, b.memr | b.memw) or _locs_conflict(b.memw, a.memr):
        return False
    return True


class Analysis:
    """Per-function facts: locals, memory-resident locals, effects of expressions/statements."""

    def __init__(self, prep: Prepared, types: Types):
        self.prep, self.types = prep, types
        self.address_taken: set[str] = set()
        self.has_volatile_text = "volatile" in prep.source[prep.fstart:prep.fend]

        def walk(node):
            if isinstance(node, c_ast.UnaryOp) and node.op == "&":
                base = node.expr
                while isinstance(base, (c_ast.StructRef, c_ast.ArrayRef)) and \
                        not (isinstance(base, c_ast.StructRef) and base.type == "->"):
                    base = base.name
                if isinstance(base, c_ast.ID):
                    self.address_taken.add(base.name)
            for _, child in node.children():
                walk(child)
        walk(prep.fn)
        self.locals = {n for n in types.vars if n not in types.static_locals}
        self.memlocals = set()
        for name in self.locals:
            k = types.kind(types.vars[name])
            if name in self.address_taken or k is None or k[0] in ("array", "struct"):
                self.memlocals.add(name)
        self.duplicates = {n for n, ds in types.local_decls.items() if len(ds) > 1 or n in types.params and ds}
        self._cache: dict[int, Effects] = {}

    def reg(self, name: str) -> bool:
        return name in self.locals and name not in self.memlocals

    def location(self, name: str) -> str:
        if name in self.locals:
            return "l:" + name
        if name in self.types.env.globals or name in self.types.static_locals:
            return "g:" + name
        return "*"

    def _vol(self, e) -> bool:
        t = self.types.typeof(e)
        if t is None:
            return self.types.env.volatile_fields or self.has_volatile_text
        if self.types.volatile(t):
            return True
        if isinstance(e, c_ast.StructRef):
            base = self.types.typeof(e.name)
            if e.type == "->":
                base = self.types.deref(base)
            return self.types.volatile(base) if base is not None else self.has_volatile_text
        if isinstance(e, c_ast.ArrayRef) or (isinstance(e, c_ast.UnaryOp) and e.op == "*"):
            return False
        return False

    def lvalue(self, e) -> tuple[str | None, str | None, Effects]:
        """(register local name, memory location, effects of computing the address)."""
        if isinstance(e, c_ast.ID):
            if self.reg(e.name):
                return e.name, None, Effects()
            return None, self.location(e.name), Effects()
        if isinstance(e, c_ast.ArrayRef):
            base_t = self.types.typeof(e.name)
            k = self.types.kind(base_t)
            if k and k[0] == "array":
                _r, loc, eff = self.lvalue(e.name)
                return None, loc or "*", eff | self.expr(e.subscript)
            return None, "*", self.expr(e.name) | self.expr(e.subscript)
        if isinstance(e, c_ast.StructRef):
            if e.type == ".":
                reg, loc, eff = self.lvalue(e.name)
                return None, loc or "*", eff
            return None, "*", self.expr(e.name)
        if isinstance(e, c_ast.UnaryOp) and e.op == "*":
            return None, "*", self.expr(e.expr)
        return None, "*", self.expr(e)

    def _access(self, e, write: bool, also_read: bool) -> Effects:
        reg, loc, eff = self.lvalue(e)
        eff = Effects(set(eff.reads), set(eff.writes), set(eff.memr), set(eff.memw), eff.call, eff.volatile,
                      eff.jump, eff.label)
        if reg:
            if write:
                eff.writes.add(reg)
            if also_read or not write:
                eff.reads.add(reg)
        else:
            if write:
                eff.memw.add(loc)
            if also_read or not write:
                eff.memr.add(loc)
            if self._vol(e):
                eff.volatile = True
                eff.memw.add("*")
                eff.memr.add("*")
        return eff

    def expr(self, e) -> Effects:
        if e is None:
            return Effects()
        key = id(e)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        out = self._expr(e)
        self._cache[key] = out
        return out

    def _expr(self, e) -> Effects:
        if isinstance(e, c_ast.ID):
            name = e.name
            if self.reg(name):
                return Effects(reads={name})
            t = self.types.var_type(name)
            k = self.types.kind(t)
            if k and k[0] in ("array", "func"):
                return Effects()
            if name in self.types.env.enumerators and name not in self.types.vars:
                return Effects()
            return self._access(e, False, True)
        if isinstance(e, (c_ast.Constant, c_ast.Typename)):
            return Effects()
        if isinstance(e, c_ast.Assignment):
            return self._access(e.lvalue, True, e.op != "=") | self.expr(e.rvalue)
        if isinstance(e, c_ast.UnaryOp):
            if e.op in ("++", "--", "p++", "p--"):
                return self._access(e.expr, True, True)
            if e.op == "&":
                return self.address(e.expr)
            if e.op in ("sizeof", "_Alignof"):
                return Effects()
            if e.op == "*":
                return self._access(e, False, True)
            return self.expr(e.expr)
        if isinstance(e, (c_ast.ArrayRef, c_ast.StructRef)):
            k = self.types.kind(self.types.typeof(e))
            if k and k[0] in ("array", "func"):
                return self.address(e)
            return self._access(e, False, True)
        if isinstance(e, c_ast.FuncCall):
            out = Effects(memr={"*"}, memw={"*"}, call=True)
            if isinstance(e.name, c_ast.ID) and e.name.name == astprep.ASM_BARRIER:
                out.jump = out.label = out.volatile = True
            if not isinstance(e.name, c_ast.ID):
                out = out | self.expr(e.name)
            for arg in (e.args.exprs if e.args else []):
                out = out | self.expr(arg)
            return out
        if isinstance(e, c_ast.Cast):
            return self.expr(e.expr)
        out = Effects()
        for _, child in e.children():
            out = out | self.expr(child)
        return out

    def address(self, e) -> Effects:
        if isinstance(e, c_ast.ID):
            return Effects()
        if isinstance(e, c_ast.ArrayRef):
            k = self.types.kind(self.types.typeof(e.name))
            base = self.address(e.name) if k and k[0] == "array" else self.expr(e.name)
            return base | self.expr(e.subscript)
        if isinstance(e, c_ast.StructRef):
            return self.address(e.name) if e.type == "." else self.expr(e.name)
        if isinstance(e, c_ast.UnaryOp) and e.op == "*":
            return self.expr(e.expr)
        return self.expr(e)

    def stmt(self, s, loop: bool = False, switch: bool = False) -> Effects:
        """Effects of a statement; ``jump`` is set for control transfers that leave ``s``."""
        if s is None:
            return Effects()
        if isinstance(s, c_ast.Decl):
            if s.init is None:
                return Effects()
            init = self.expr(s.init) if not isinstance(s.init, c_ast.InitList) else self._list(s.init)
            if self.reg(s.name):
                return init | Effects(writes={s.name})
            return init | Effects(memw={self.location(s.name)})
        if isinstance(s, c_ast.Return):
            return self.expr(s.expr) | Effects(jump=True)
        if isinstance(s, c_ast.Goto):
            return Effects(jump=True)
        if isinstance(s, c_ast.Break):
            return Effects(jump=not (loop or switch))
        if isinstance(s, c_ast.Continue):
            return Effects(jump=not loop)
        if isinstance(s, c_ast.Label):
            return self.stmt(s.stmt, loop, switch) | Effects(jump=True, label=True)
        if isinstance(s, c_ast.Compound):
            out = Effects()
            for item in s.block_items or []:
                out = out | self.stmt(item, loop, switch)
            return out
        if isinstance(s, c_ast.If):
            return self.expr(s.cond) | self.stmt(s.iftrue, loop, switch) | self.stmt(s.iffalse, loop, switch)
        if isinstance(s, (c_ast.While, c_ast.DoWhile)):
            return self.expr(s.cond) | self.stmt(s.stmt, True, switch)
        if isinstance(s, c_ast.For):
            init = self.stmt(s.init) if isinstance(s.init, c_ast.DeclList) else self.expr(s.init)
            return init | self.expr(s.cond) | self.expr(s.next) | self.stmt(s.stmt, True, switch)
        if isinstance(s, c_ast.DeclList):
            out = Effects()
            for d in s.decls:
                out = out | self.stmt(d)
            return out
        if isinstance(s, c_ast.Switch):
            return self.expr(s.cond) | self.stmt(s.stmt, loop, True)
        if isinstance(s, (c_ast.Case, c_ast.Default)):
            out = Effects(label=True, jump=True)
            for item in s.stmts or []:
                out = out | self.stmt(item, loop, switch)
            return out
        if isinstance(s, (c_ast.EmptyStatement, c_ast.Pragma)):
            return Effects()
        return self.expr(s)

    def _list(self, init) -> Effects:
        out = Effects()
        for e in init.exprs:
            out = out | (self._list(e) if isinstance(e, c_ast.InitList) else self.expr(e))
        return out

    def node(self, sn: SNode) -> Effects:
        out = Effects()
        for item in sn.group or []:
            out = out | self.stmt(item)
        if sn.ast is None and (sn.barrier or not sn.group):
            out = out | Effects(jump=True, label=True, memr={"*"}, memw={"*"}, call=True)
        return out


def has_escape(s, kinds=("break", "continue")) -> bool:
    """A ``break``/``continue`` in ``s`` that is not enclosed by a loop (or switch, for break)
    inside ``s``."""
    def walk(n, loop, switch):
        if isinstance(n, c_ast.Break):
            return "break" in kinds and not (loop or switch)
        if isinstance(n, c_ast.Continue):
            return "continue" in kinds and not loop
        if isinstance(n, (c_ast.While, c_ast.DoWhile, c_ast.For)):
            return walk(n.stmt, True, switch)
        if isinstance(n, c_ast.Switch):
            return walk(n.stmt, loop, True)
        return any(walk(c, loop, switch) for _, c in n.children())
    if s is None:
        return True
    return walk(s, False, False)


def ids(node) -> list:
    out = []

    def walk(n):
        if isinstance(n, c_ast.ID):
            out.append(n)
        if isinstance(n, c_ast.StructRef):
            walk(n.name)
            return
        if isinstance(n, (c_ast.Typename,)):
            return
        for _, c in n.children():
            walk(c)
    walk(node)
    return out


# ============================================================================== units and sites
@dataclass
class Unit:
    kind: str            # stmt, cond, forpart
    node: SNode
    root: object         # AST re-printed for this unit
    start: int
    end: int
    printable: bool
    index: int = -1      # for-head part index

    def render(self, root) -> str:
        if self.kind == "stmt":
            return simple_stmt_text(root)
        return expr_text(root)


@dataclass
class Site:
    node: object
    parent: object
    lvalue: bool
    addr: bool
    boolctx: bool
    conditional: bool
    sizeof: bool


def sites(root, boolctx_root: bool) -> list[Site]:
    out: list[Site] = []

    def visit(n, parent, lvalue=False, addr=False, boolctx=False, conditional=False, sizeof=False):
        if n is None or isinstance(n, (c_ast.Typename, c_ast.IdentifierType)):
            return
        out.append(Site(n, parent, lvalue, addr, boolctx, conditional, sizeof))
        if isinstance(n, c_ast.Assignment):
            visit(n.lvalue, n, True, False, False, conditional, sizeof)
            visit(n.rvalue, n, False, False, False, conditional, sizeof)
        elif isinstance(n, c_ast.UnaryOp):
            if n.op in ("++", "--", "p++", "p--"):
                visit(n.expr, n, True, False, False, conditional, sizeof)
            elif n.op == "&":
                visit(n.expr, n, False, True, False, conditional, sizeof)
            elif n.op in ("sizeof", "_Alignof"):
                visit(n.expr, n, False, False, False, conditional, True)
            else:
                visit(n.expr, n, False, False, n.op == "!", conditional, sizeof)
        elif isinstance(n, c_ast.BinaryOp):
            logical = n.op in _LOGICAL
            visit(n.left, n, False, False, logical, conditional, sizeof)
            visit(n.right, n, False, False, logical, conditional or logical, sizeof)
        elif isinstance(n, c_ast.TernaryOp):
            visit(n.cond, n, False, False, True, conditional, sizeof)
            visit(n.iftrue, n, False, False, False, True, sizeof)
            visit(n.iffalse, n, False, False, False, True, sizeof)
        elif isinstance(n, c_ast.StructRef):
            visit(n.name, n, False, n.type == "." and (lvalue or addr), False, conditional, sizeof)
        elif isinstance(n, c_ast.ArrayRef):
            visit(n.name, n, False, False, False, conditional, sizeof)
            visit(n.subscript, n, False, False, False, conditional, sizeof)
        elif isinstance(n, c_ast.Decl):
            if n.init is not None and not isinstance(n.init, c_ast.InitList):
                visit(n.init, n, False, False, False, conditional, sizeof)
        elif isinstance(n, c_ast.Return):
            visit(n.expr, n, False, False, False, conditional, sizeof)
        else:
            for _, c in n.children():
                visit(c, n, False, False, False, conditional, sizeof)

    visit(root, None, boolctx=boolctx_root)
    return out


def substitute(root, mapping: dict):
    """Deep copy of ``root`` with nodes replaced (``mapping``: id(old) -> new)."""
    memo = dict(mapping)
    return copy.deepcopy(root, memo)


def _snip(text: str, width: int = 36) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= width else text[:width - 3] + "..."


# ============================================================================== context
@dataclass
class Cand:
    label: str
    edits: list
    review: bool = False


class Ctx:
    def __init__(self, prep: Prepared):
        self.prep = prep
        self.src = prep.source
        self.types = Types(prep)
        self.an = Analysis(prep, self.types)
        self.nodes = [n for n in astprep._walk_snodes(prep.body)]
        self.units: list[Unit] = []
        self.unit_of_id: dict[int, Unit] = {}
        for sn in self.nodes:
            if sn.ast is None:
                continue
            if sn.kind == "simple":
                if isinstance(sn.ast, (c_ast.Decl,)) and len(sn.group) > 1:
                    continue
                self._add(Unit("stmt", sn, sn.ast, sn.start, sn.end, prep.printable(sn)))
            elif sn.kind in ("if", "while", "do", "switch"):
                a, b = prep.cond_span(sn)
                self._add(Unit("cond", sn, sn.ast.cond, a, b, prep.cond_printable(sn)))
            elif sn.kind == "for":
                for index, root in enumerate((sn.ast.init, sn.ast.cond, sn.ast.next)):
                    span = prep.part_span(sn, index)
                    if root is None or span is None or isinstance(root, c_ast.DeclList):
                        continue
                    self._add(Unit("forpart", sn, root, span[0], span[1],
                                   prep.cond_printable(sn), index))
        self.words = set(re.findall(r"[A-Za-z_]\w*", self.src))

    def _add(self, unit: Unit):
        self.units.append(unit)
        for i in ids(unit.root):
            self.unit_of_id[id(i)] = unit

    # -- small helpers
    def line(self, offset: int) -> int:
        return self.prep.line(offset)

    def items(self, compound: SNode) -> list[SNode]:
        return compound.children

    def is_decl(self, sn: SNode) -> bool:
        return sn.kind == "simple" and isinstance(sn.ast, c_ast.Decl)

    def editable_compound(self, sn: SNode) -> bool:
        return sn.kind == "compound" and sn.ast is not None and \
            all(c.ast is not None or (c.opaque and c.group) for c in sn.children)

    def gap_start(self, compound: SNode, index: int) -> int:
        """Offset where the chunk of item ``index`` begins (end of previous item or of ``{``)."""
        if index == 0:
            return self.prep.code[compound.t0].end
        return compound.children[index - 1].end

    def own_lines(self, sn: SNode) -> tuple[int, int] | None:
        """Whole-line span of ``sn`` when it alone occupies its lines (a trailing comment on
        its last line goes with it)."""
        src = self.src
        start = src.rfind("\n", 0, sn.start) + 1
        if src[start:sn.start].strip():
            return None
        end = src.find("\n", sn.end)
        end = len(src) if end < 0 else end
        rest = src[sn.end:end].strip()
        if rest and not (rest.startswith("//") or (rest.startswith("/*") and rest.endswith("*/") and "*/" not in rest[2:-2])):
            return None
        return start, min(end + 1, len(src))

    def chunk(self, compound: SNode, index: int) -> tuple[int, int]:
        lines = self.own_lines(compound.children[index])
        if lines is not None:
            return lines
        return self.gap_start(compound, index), compound.children[index].end

    def insert_before(self, compound: SNode, index: int, chunk_span: tuple[int, int]) -> tuple[int, int, str]:
        text = self.src[chunk_span[0]:chunk_span[1]]
        target = self.own_lines(compound.children[index])
        if target is not None and self.own_lines_text(text):
            return (target[0], target[0], text)
        at = self.gap_start(compound, index)
        return (at, at, self._as_gap_chunk(text, compound.children[index]))

    def insert_after(self, compound: SNode, index: int, chunk_span: tuple[int, int]) -> tuple[int, int, str]:
        text = self.src[chunk_span[0]:chunk_span[1]]
        target = self.own_lines(compound.children[index])
        if target is not None and self.own_lines_text(text):
            return (target[1], target[1], text if target[1] < len(self.src) else "\n" + text)
        at = compound.children[index].end
        return (at, at, self._as_gap_chunk(text, compound.children[index]))

    @staticmethod
    def own_lines_text(text: str) -> bool:
        return text.endswith("\n") and not text.startswith("\n")

    def _as_gap_chunk(self, text: str, near: SNode) -> str:
        if self.own_lines_text(text):
            return "\n" + text[:-1]
        return text

    def indent(self, sn: SNode) -> str:
        return self.prep.indent_at(sn.start)

    def unit_for(self, sn: SNode) -> Unit | None:
        for u in self.units:
            if u.node is sn and u.kind in ("stmt", "cond"):
                return u
        return None

    def fresh(self, base: str = "temp") -> str:
        if base not in self.words:
            return base
        k = 2
        while f"{base}{k}" in self.words:
            k += 1
        return f"{base}{k}"

    def decl_insert(self, compound: SNode, text: str) -> tuple[int, int, str]:
        """Edit inserting a declaration at the start of ``compound`` (after its declarations)."""
        items = compound.children
        decls = [c for c in items if self.is_decl(c)]
        if decls:
            last = decls[-1]
            return (last.end, last.end, "\n" + self.indent(last) + text)
        brace = self.prep.code[compound.t0].end
        if items:
            ind = self.indent(items[0]) if self.prep.starts_line(items[0].start) else self.indent(compound) + "    "
        else:
            ind = self.indent(compound) + "    "
        return (brace, brace, "\n" + ind + text)

    def stmt_insert(self, before: SNode, text: str) -> tuple[int, int, str]:
        if self.prep.starts_line(before.start):
            return (before.start, before.start, text + "\n" + self.indent(before))
        return (before.start, before.start, text + " ")

    def remove(self, compound: SNode, index: int) -> tuple[int, int, str]:
        a, b = self.chunk(compound, index)
        return (a, b, "")

    def body_items_text(self, compound: SNode, new_indent: str) -> str | None:
        """Text of the items of ``compound`` re-indented to ``new_indent`` (first line unindented)."""
        if not compound.children:
            return None
        a, b = compound.children[0].start, compound.children[-1].end
        return reindent(self.src[a:b], self.indent(compound.children[0]), new_indent)

    def wrapped(self, sn: SNode, ind: str) -> str:
        """``sn`` as a braced block placed at indentation ``ind``."""
        if sn.kind == "compound":
            return reindent(self.src[sn.start:sn.end], self.indent(sn) if self.prep.starts_line(sn.start)
                            else self._owner_indent(sn), ind)
        inner = ind + "    "
        return "{\n" + inner + reindent(self.src[sn.start:sn.end], self._owner_indent(sn) + "    "
                                        if not self.prep.starts_line(sn.start) else self.indent(sn), inner) \
            + "\n" + ind + "}"

    def _owner_indent(self, sn: SNode) -> str:
        return self.prep.indent_at(sn.start)

    def stmt_text_at(self, sn: SNode, ind: str) -> str:
        """Original text of ``sn`` re-indented so that its owning line sits at ``ind``."""
        return reindent(self.src[sn.start:sn.end], self.prep.indent_at(sn.start), ind)


# ============================================================================== families
def fam_expr(ctx: Ctx):
    T, an = ctx.types, ctx.an
    for unit in ctx.units:
        if not unit.printable:
            continue
        line = ctx.line(unit.start)
        boolroot = unit.kind == "cond" or (unit.kind == "forpart" and unit.index == 1)
        for site in sites(unit.root, boolroot):
            n = site.node
            if site.sizeof:
                continue
            out = []
            if isinstance(n, c_ast.BinaryOp):
                pure = not an.expr(n.left).side and not an.expr(n.right).side
                if n.op in _COMMUTATIVE and pure:
                    out.append(("commute", c_ast.BinaryOp(n.op, n.right, n.left), False))
                if n.op in _FLIP and pure:
                    out.append(("flip", c_ast.BinaryOp(_FLIP[n.op], n.right, n.left), False))
                if n.op == "==" and _int_value(n.right) == 0:
                    out.append(("not", c_ast.UnaryOp("!", n.left), False))
                if n.op == "!=" and _int_value(n.right) == 0 and site.boolctx:
                    out.append(("drop != 0", n.left, False))
                if n.op in ("<=", ">", "<", ">=") and T.is_int(T.typeof(n.left)):
                    value = _int_value(n.right)
                    if value is not None:
                        k = T.kind(T.promote(T.typeof(n.left)))
                        unsigned = (k and k[2] is False) or "u" in n.right.value.lower() or value > 0x7FFFFFFF
                        new = value + 1 if n.op in ("<=", ">") else value - 1
                        op = {"<=": "<", ">": ">=", "<": "<=", ">=": ">"}[n.op]
                        if (0 <= new if unsigned else -0x80000000 <= new) and new <= (0xFFFFFFFF if unsigned else 0x7FFFFFFF):
                            out.append(("bound", c_ast.BinaryOp(op, n.left, _const_like(n.right, new)), False))
                if n.op == "+" and not site.lvalue and not isinstance(site.parent, c_ast.UnaryOp) and \
                        T.is_pointer(T.typeof(n.left)) and T.is_int(T.typeof(n.right)):
                    out.append(("&index", c_ast.UnaryOp("&", c_ast.ArrayRef(n.left, n.right)), False))
            if isinstance(n, c_ast.UnaryOp):
                if n.op == "!" and not isinstance(n.expr, c_ast.UnaryOp):
                    out.append(("==0", c_ast.BinaryOp("==", n.expr, c_ast.Constant("int", "0")), False))
                if n.op == "*" and isinstance(n.expr, c_ast.BinaryOp) and n.expr.op == "+" and \
                        T.is_pointer(T.typeof(n.expr.left)) and T.is_int(T.typeof(n.expr.right)):
                    out.append(("index", c_ast.ArrayRef(n.expr.left, n.expr.right), False))
                if n.op == "&" and isinstance(n.expr, c_ast.ArrayRef) and T.is_pointer(T.typeof(n.expr.name)):
                    out.append(("ptr-sum", c_ast.BinaryOp("+", n.expr.name, n.expr.subscript), False))
            if isinstance(n, c_ast.ArrayRef) and not site.addr and T.is_pointer(T.typeof(n.name)) and \
                    T.is_int(T.typeof(n.subscript)):
                out.append(("deref-sum", c_ast.UnaryOp("*", c_ast.BinaryOp("+", n.name, n.subscript)), False))
            if isinstance(n, c_ast.StructRef):
                if n.type == "." and isinstance(n.name, c_ast.UnaryOp) and n.name.op == "*":
                    out.append(("arrow", c_ast.StructRef(n.name.expr, "->", n.field), False))
                if n.type == "->":
                    out.append(("(*p).f", c_ast.StructRef(c_ast.UnaryOp("*", n.name), ".", n.field), False))
            if site.boolctx and not isinstance(n, c_ast.BinaryOp) or (
                    site.boolctx and isinstance(n, c_ast.BinaryOp) and n.op not in _COMPARE | _LOGICAL):
                if not (isinstance(n, c_ast.UnaryOp) and n.op == "!") and not isinstance(n, c_ast.Constant):
                    out.append(("!= 0", c_ast.BinaryOp("!=", n, c_ast.Constant("int", "0")), False))
            if isinstance(n, c_ast.Assignment) and not an.expr(n.lvalue).side:
                lv = expr_text(n.lvalue)
                r = n.rvalue
                if n.op == "=" and isinstance(r, c_ast.BinaryOp) and r.op in _ARITH:
                    if expr_text(r.left) == lv:
                        out.append(("op=", c_ast.Assignment(r.op + "=", n.lvalue, r.right), False))
                    elif r.op in _COMMUTATIVE and expr_text(r.right) == lv:
                        out.append(("op=", c_ast.Assignment(r.op + "=", n.lvalue, r.left), False))
                if n.op != "=" and n.op[:-1] in _ARITH:
                    rhs = r if not isinstance(r, c_ast.Assignment) else None
                    if rhs is not None:
                        out.append(("expand", c_ast.Assignment("=", n.lvalue, c_ast.BinaryOp(n.op[:-1], n.lvalue, rhs)), False))
                if _stmt_like(unit) and site.parent is None:
                    one = _int_value(r) == 1
                    if n.op in ("+=", "-=") and one:
                        out.append(("x" + n.op[0] * 2, c_ast.UnaryOp("p" + n.op[0] * 2, n.lvalue), False))
                    if n.op == "=" and isinstance(r, c_ast.BinaryOp) and r.op in ("+", "-") and \
                            expr_text(r.left) == lv and _int_value(r.right) == 1:
                        out.append(("x" + r.op * 2, c_ast.UnaryOp("p" + r.op * 2, n.lvalue), False))
            if isinstance(n, c_ast.UnaryOp) and n.op in ("++", "--", "p++", "p--") and _stmt_like(unit) \
                    and site.parent is None and not an.expr(n.expr).side:
                sym = n.op[-1]
                forms = {"++x": c_ast.UnaryOp(sym * 2, n.expr), "x++": c_ast.UnaryOp("p" + sym * 2, n.expr),
                         "x" + sym + "=1": c_ast.Assignment(sym + "=", n.expr, c_ast.Constant("int", "1")),
                         "x=x" + sym + "1": c_ast.Assignment("=", n.expr, c_ast.BinaryOp(sym, n.expr, c_ast.Constant("int", "1")))}
                for name, form in forms.items():
                    out.append((name, form, False))
            for action, new, review in out:
                text = unit.render(substitute(unit.root, {id(n): new}))
                if text == ctx.src[unit.start:unit.end]:
                    continue
                yield Cand(f"expr: {action} '{_snip(expr_text(n))}' L{line}", [(unit.start, unit.end, text)], review)


def _stmt_like(unit: Unit) -> bool:
    """Expression evaluated for its effect only: an expression statement or a for step/init."""
    return unit.kind == "stmt" or (unit.kind == "forpart" and unit.index in (0, 2))


def _const_like(old: c_ast.Constant, value: int) -> c_ast.Constant:
    text = old.value
    suffix = re.search(r"[uUlL]*$", text).group()
    body = hex(value) if text.lower().startswith("0x") and value >= 0 else str(value)
    if text.startswith("0X"):
        body = body.upper().replace("0X", "0X")
    return c_ast.Constant(old.type, body + suffix)


def fam_cast(ctx: Ctx):
    T = ctx.types
    names = [n if n in T.env.typedefs else " ".join(_C_NAMES[n]) for n in CAST_NAMES]

    def cast_to(name, e):
        return c_ast.Cast(c_ast.Typename(None, [], None, c_ast.TypeDecl(None, [], None, c_ast.IdentifierType(name.split()))), e)

    # declared types of locals and parameters
    for sn in ctx.nodes:
        if ctx.is_decl(sn) and ctx.prep.printable(sn) and T.is_int(sn.ast.type) and \
                isinstance(sn.ast.type, c_ast.TypeDecl) and isinstance(sn.ast.type.type, c_ast.IdentifierType):
            yield from _retype(ctx, sn.ast, sn.start, sn.end, names, "local", ";")
    for param, a, b, faithful in ctx.prep.params:
        if faithful and isinstance(param, c_ast.Decl) and T.is_int(param.type) and \
                isinstance(param.type, c_ast.TypeDecl) and isinstance(param.type.type, c_ast.IdentifierType) \
                and not ctx.prep.has_comment(a, b):
            yield from _retype(ctx, param, a, b, names, "param", "")
    for unit in ctx.units:
        if not unit.printable:
            continue
        line = ctx.line(unit.start)
        for site in sites(unit.root, False):
            n = site.node
            if site.sizeof:
                continue
            if isinstance(n, c_ast.Cast) and T.is_int(n.to_type.type):
                text = unit.render(substitute(unit.root, {id(n): n.expr}))
                yield Cand(f"cast: remove '{_snip(expr_text(n))}' L{line}", [(unit.start, unit.end, text)],
                           not _redundant_cast(T, site))
            if isinstance(n, c_ast.BinaryOp) and n.op == "&" and _int_value(n.right) in (0xFF, 0xFFFF) and \
                    T.is_int(T.typeof(n.left)):
                text = unit.render(substitute(unit.root, {id(n): n.left}))
                k = T.kind(T.typeof(n.left))
                proven = k[2] is False and (1 << (8 * k[1])) - 1 <= _int_value(n.right)
                yield Cand(f"cast: drop mask '{_snip(expr_text(n))}' L{line}", [(unit.start, unit.end, text)], not proven)
    for unit in ctx.units:
        if not unit.printable:
            continue
        line = ctx.line(unit.start)
        targets = []
        for site in sites(unit.root, False):
            n = site.node
            if site.lvalue or site.addr or site.sizeof or isinstance(site.parent, c_ast.Cast):
                continue
            if isinstance(site.parent, c_ast.Assignment) and site.parent.rvalue is n or \
                    isinstance(site.parent, c_ast.Decl) or isinstance(site.parent, c_ast.Return) or \
                    isinstance(n, (c_ast.ID, c_ast.StructRef, c_ast.ArrayRef)) or \
                    (isinstance(n, c_ast.UnaryOp) and n.op == "*"):
                if T.is_int(T.typeof(n)) and not isinstance(n, c_ast.Constant):
                    targets.append(n)
        for n in targets:
            k = T.kind(T.typeof(n))
            if isinstance(n, c_ast.ID) and k and k[1] <= 2 and not isinstance(site_parent(unit.root, n), c_ast.BinaryOp):
                mask = c_ast.Constant("int", "0xFF" if k[1] == 1 else "0xFFFF")
                text = unit.render(substitute(unit.root, {id(n): c_ast.BinaryOp("&", n, mask)}))
                yield Cand(f"cast: mask '{_snip(expr_text(n))}' & {mask.value} L{line}", [(unit.start, unit.end, text)], True)
            for name in names:
                text = unit.render(substitute(unit.root, {id(n): cast_to(name, n)}))
                yield Cand(f"cast: ({name}) '{_snip(expr_text(n))}' L{line}", [(unit.start, unit.end, text)], True)
def site_parent(root, node):
    for site in sites(root, False):
        if site.node is node:
            return site.parent
    return None


def _redundant_cast(T: Types, site: Site) -> bool:
    """``x = (T)e`` with ``T`` the type of ``x``: the assignment converts anyway."""
    parent, n = site.parent, site.node
    target = None
    if isinstance(parent, c_ast.Assignment) and parent.op == "=" and parent.rvalue is n:
        target = T.typeof(parent.lvalue)
    elif isinstance(parent, c_ast.Decl) and parent.init is n:
        target = parent.type
    return target is not None and T.sig(target) is not None and T.sig(target) == T.sig(n.to_type.type)


def _retype(ctx, decl, a, b, names, what, tail):
    current = " ".join(decl.type.type.names)
    for name in names:
        if name == current:
            continue
        new = copy.deepcopy(decl)
        new.type.type = c_ast.IdentifierType(name.split())
        yield Cand(f"cast: {what} {decl.name} {current} -> {name} L{ctx.line(a)}",
                   [(a, b, expr_text(new) + tail)], True)


# ---------------------------------------------------------------- temp / inline-temp
def _temp_ok(ctx: Ctx, site: Site) -> bool:
    n = site.node
    if site.lvalue or site.addr or site.sizeof or site.conditional:
        return False
    if isinstance(n, c_ast.ID):
        # a register local is already a temporary; a global/memory read is worth one
        k = ctx.types.kind(ctx.types.var_type(n.name))
        if ctx.an.reg(n.name) or n.name not in ctx.types.env.globals or not k or k[0] in ("array", "func", "struct"):
            return False
        if isinstance(site.parent, c_ast.FuncCall) and site.parent.name is n:
            return False
    if isinstance(n, (c_ast.Constant, c_ast.Assignment, c_ast.InitList, c_ast.ExprList,
                      c_ast.Decl, c_ast.Return, c_ast.FuncCall)):
        return False
    if isinstance(n, c_ast.UnaryOp) and n.op in ("++", "--", "p++", "p--", "sizeof"):
        return False
    if isinstance(n, c_ast.UnaryOp) and n.op == "&" and isinstance(n.expr, c_ast.ID):
        return False
    if isinstance(site.parent, c_ast.StructRef) and site.parent.type == ".":
        return False
    if not ids(n):
        return False
    eff = ctx.an.expr(n)
    if eff.side or eff.call:
        return False
    return True


def fam_temp(ctx: Ctx):
    body = ctx.prep.body
    T, an = ctx.types, ctx.an
    name = ctx.fresh("temp")
    for compound in ctx.nodes:
        if not ctx.editable_compound(compound):
            continue
        items = compound.children
        for i, sn in enumerate(items):
            if ctx.is_decl(sn):
                continue
            unit = ctx.unit_for(sn)
            if unit is None or not unit.printable or sn.kind not in ("simple", "if", "switch"):
                continue
            if sn.kind == "simple" and not isinstance(sn.ast, (c_ast.Assignment, c_ast.FuncCall, c_ast.Return,
                                                                  c_ast.UnaryOp, c_ast.BinaryOp)):
                continue
            seen = set()
            for site in sites(unit.root, unit.kind == "cond"):
                if not _temp_ok(ctx, site):
                    continue
                key = expr_text(site.node)
                if key in seen:
                    continue
                seen.add(key)
                decl = T.decl_text(T.typeof(site.node), name)
                if decl is None:
                    continue
                same = [s.node for s in sites(unit.root, unit.kind == "cond")
                        if expr_text(s.node) == key and _temp_ok(ctx, s)]
                new_unit = unit.render(substitute(unit.root, {id(x): c_ast.ID(name) for x in same}))
                assign = f"{name} = {key};"
                base = [ctx.decl_insert(body, decl), (unit.start, unit.end, new_unit)]
                eff = an.expr(site.node) | Effects(writes={name})
                line = ctx.line(sn.start)
                yield Cand(f"temp: '{_snip(key)}' L{line} before statement",
                           base + [ctx.stmt_insert(sn, assign)])
                k = i
                while k > 0 and not ctx.is_decl(items[k - 1]) and commute(an.node(items[k - 1]), eff):
                    k -= 1
                if k < i:
                    yield Cand(f"temp: '{_snip(key)}' L{line} hoisted to L{ctx.line(items[k].start)}",
                               base + [ctx.stmt_insert(items[k], assign)])
                reuse = []
                for j in range(i + 1, len(items)):
                    later = items[j]
                    lu = ctx.unit_for(later)
                    full = an.node(later)
                    if lu is not None and lu.printable and later.kind in ("simple", "if"):
                        hits = [s.node for s in sites(lu.root, lu.kind == "cond")
                                if expr_text(s.node) == key and _temp_ok(ctx, s)]
                        pre = _pre_store_effects(ctx, later)
                        if hits and pre is not None and commute(pre, eff):
                            reuse.append((lu, hits))
                    if not commute(full, eff):
                        break
                if reuse:
                    edits = base + [ctx.stmt_insert(sn, assign)]
                    for lu, hits in reuse:
                        edits.append((lu.start, lu.end, lu.render(substitute(lu.root, {id(x): c_ast.ID(name) for x in hits}))))
                    yield Cand(f"temp: '{_snip(key)}' L{line} reused x{len(reuse) + 1}", edits)


def _pre_store_effects(ctx: Ctx, sn: SNode) -> Effects | None:
    """Effects of a statement evaluated before its final top-level store (the store of
    ``x = rhs`` happens after ``rhs``), or of an if's condition."""
    an = ctx.an
    if sn.kind in ("if", "switch"):
        return an.expr(sn.ast.cond)
    if sn.kind != "simple" or sn.ast is None:
        return None
    s = sn.ast
    if isinstance(s, c_ast.Assignment) and s.op == "=":
        _reg, _loc, addr = an.lvalue(s.lvalue)
        return addr | an.expr(s.rvalue)
    if isinstance(s, c_ast.Return):
        return an.expr(s.expr)
    return an.stmt(s)


def fam_inline(ctx: Ctx):
    T, an = ctx.types, ctx.an
    occurrences: dict[str, list] = {}
    for unit in ctx.units:
        for i in ids(unit.root):
            occurrences.setdefault(i.name, []).append(i)
    decl_nodes = {}
    for sn in ctx.nodes:
        if ctx.is_decl(sn) and len(sn.group) == 1:
            decl_nodes[sn.ast.name] = sn
    for v, dsn in decl_nodes.items():
        if v not in an.locals or v in an.memlocals or v in an.duplicates or v in T.params or v in T.static_locals:
            continue
        compound = dsn.parent
        if compound is None or not ctx.editable_compound(compound):
            continue
        decl = dsn.ast
        occ = occurrences.get(v, [])
        # classify occurrences: definitions are the declaration init or `v = E;` statements
        defs, reads = [], []
        for node in occ:
            unit = ctx.unit_of_id[id(node)]
            root = unit.root
            if unit.kind == "stmt" and isinstance(root, c_ast.Assignment) and root.lvalue is node:
                defs.append(unit)
            elif _written(root, node):
                defs.append(None)
            else:
                reads.append((node, unit))
        if decl.init is not None:
            if defs or isinstance(decl.init, c_ast.InitList):
                continue
            def_sn, expr_e = dsn, decl.init
            def_container = compound
        else:
            if len(defs) != 1 or defs[0] is None or defs[0].root.op != "=":
                continue
            def_sn, expr_e = defs[0].node, defs[0].root.rvalue
            def_container = def_sn.parent
            if def_container is None or def_container.kind != "compound" or not ctx.editable_compound(def_container):
                continue
        if not reads or len(reads) > 4:
            continue
        eff = an.expr(expr_e)
        if eff.side or eff.call or v in eff.reads:
            continue
        items = def_container.children
        di = items.index(def_sn)
        # which item of the container holds each read
        positions = []
        ok = True
        for node, unit in reads:
            holder = unit.node
            while holder is not None and holder.parent is not def_container:
                holder = holder.parent
            if holder is None or not unit.printable:
                ok = False
                break
            j = items.index(holder)
            if j <= di:
                ok = False
                break
            positions.append((j, holder, unit))
        if not ok:
            continue
        last = max(j for j, _h, _u in positions)
        memory_conflict = False
        reg_only = Effects(reads=set(eff.reads))
        for j in range(di + 1, last + 1):
            item = items[j]
            using = [u for jj, _h, u in positions if jj == j]
            if not using:
                effect = an.node(item)
            elif item.kind in ("simple", "if", "switch") and all(u.node is item and u.kind != "forpart" for u in using):
                effect = _pre_store_effects(ctx, item)
                if effect is None:
                    ok = False
                    break
            else:
                effect = an.node(item)
            if effect.label or not commute(effect, reg_only, allow_jump=True):
                ok = False
                break
            if not commute(effect, eff, allow_jump=True):
                memory_conflict = True
        if not ok:
            continue
        vt, et = T.typeof(c_ast.ID(v)), T.typeof(expr_e)
        same = T.sig(vt) is not None and T.sig(vt) == T.sig(et)
        fits = _fits(T, et, vt)
        forms = []
        if same or fits:
            forms.append(("", expr_e, False))
        else:
            tname = T.type_name(vt)
            if tname and T.is_arith(vt):
                cast = c_ast.Cast(c_ast.Typename(None, [], None, c_ast.TypeDecl(None, [], None, c_ast.IdentifierType(tname.split()))), expr_e)
                forms.append((" with cast", cast, False))
            forms.append((" (drops conversion)", expr_e, True))
        by_unit: dict[int, tuple[Unit, list]] = {}
        for node, unit in reads:
            by_unit.setdefault(id(unit), (unit, []))[1].append(node)
        if memory_conflict:
            forms = [(s + " (memory may change)", r, True) for s, r, _rv in forms]
        for suffix, replacement, review in forms:
            edits = []
            for unit, nodes in by_unit.values():
                edits.append((unit.start, unit.end, unit.render(substitute(unit.root, {id(x): copy.deepcopy(replacement) for x in nodes}))))
            if def_sn is dsn:
                edits.append(ctx.remove(compound, compound.children.index(dsn)))
            else:
                edits.append(ctx.remove(def_container, di))
                edits.append(ctx.remove(compound, compound.children.index(dsn)))
            yield Cand(f"inline-temp: {v} = '{_snip(expr_text(expr_e))}' L{ctx.line(def_sn.start)}{suffix}", edits, review)


def _written(root, node) -> bool:
    for site in sites(root, False):
        if site.node is node and (site.lvalue or site.addr):
            return True
    return False


def _fits(T: Types, small, big) -> bool:
    ks, kb = T.kind(small), T.kind(big)
    if not ks or not kb or ks[0] != "int" or kb[0] != "int" or ks[2] is None or kb[2] is None:
        return False
    if ks[2] == kb[2]:
        return ks[1] <= kb[1]
    return ks[2] is False and kb[2] is True and ks[1] < kb[1]


# ---------------------------------------------------------------- statement order
def fam_stmt_order(ctx: Ctx):
    """Moves ordered by distance (all one-step moves first) so that undoing a move is cheap to reach."""
    found = list(_stmt_moves(ctx))
    found.sort(key=lambda item: item[0])
    for _distance, cand in found:
        yield cand


def _stmt_moves(ctx: Ctx):
    an = ctx.an
    for compound in ctx.nodes:
        if not ctx.editable_compound(compound):
            continue
        items = compound.children
        first = 0
        while first < len(items) and ctx.is_decl(items[first]):
            first += 1
        for i in range(first, len(items)):
            sn = items[i]
            eff = an.node(sn)
            if eff.jump or eff.label:
                continue
            what = f"'{_snip(ctx.src[sn.start:sn.end], 28)}' L{ctx.line(sn.start)}"
            a, b = ctx.chunk(compound, i)
            chunk = ctx.src[a:b]
            k = i
            while k > first and commute(an.node(items[k - 1]), eff):
                k -= 1
                yield i - k, Cand(f"stmt-order: move {what} up {i - k}", [ctx.insert_before(compound, k, (a, b)), (a, b, "")])
            k = i
            while k + 1 < len(items) and commute(an.node(items[k + 1]), eff):
                k += 1
                yield k - i, Cand(f"stmt-order: move {what} down {k - i}", [(a, b, ""), ctx.insert_after(compound, k, (a, b))])


# ---------------------------------------------------------------- declarations
def fam_decl_order(ctx: Ctx):
    an = ctx.an
    body = ctx.prep.body
    for compound in ctx.nodes:
        if not ctx.editable_compound(compound):
            continue
        items = compound.children
        decls = []
        for c in items:
            if not ctx.is_decl(c):
                break
            decls.append(c)

        def names(sn):
            return {d.name for d in sn.group}

        def init_eff(sn):
            return an.node(sn)
        for i, sn in enumerate(decls):
            a, b = ctx.chunk(compound, i)
            chunk = ctx.src[a:b]
            what = f"{','.join(d.name for d in sn.group)} L{ctx.line(sn.start)}"
            for k in range(i - 1, -1, -1):
                other = decls[k]
                if names(sn) & {x.name for x in ids(other.ast)} or names(other) & {x.name for d in sn.group for x in ids(d)} \
                        or not commute(init_eff(sn), init_eff(other)):
                    break
                yield Cand(f"decl-order: move {what} up {i - k}", [ctx.insert_before(compound, k, (a, b)), (a, b, "")])
            for k in range(i + 1, len(decls)):
                other = decls[k]
                if names(sn) & {x.name for d in other.group for x in ids(d)} or names(other) & {x.name for d in sn.group for x in ids(d)} \
                        or not commute(init_eff(sn), init_eff(other)):
                    break
                yield Cand(f"decl-order: move {what} down {k - i}", [(a, b, ""), ctx.insert_after(compound, k, (a, b))])
    # move into the innermost block holding all uses / out to the function block
    occurrences: dict[str, list] = {}
    for unit in ctx.units:
        for i in ids(unit.root):
            occurrences.setdefault(i.name, []).append(unit)
    for sn in ctx.nodes:
        if not ctx.is_decl(sn) or len(sn.group) != 1 or sn.ast.init is not None:
            continue
        v = sn.ast.name
        compound = sn.parent
        if v in an.duplicates or v in an.memlocals or v not in an.locals or compound is None:
            continue
        uses = [u for u in occurrences.get(v, []) if u.node is not sn]
        decl_text = ctx.src[sn.start:sn.end]
        removal = ctx.remove(compound, compound.children.index(sn))
        if compound is not body and v not in ctx.types.env.globals and ctx.editable_compound(body):
            yield Cand(f"decl-order: move {v} L{ctx.line(sn.start)} out to function block",
                       [removal, ctx.decl_insert(body, decl_text)])
        if not uses:
            continue
        target = _innermost_common(ctx, [u.node for u in uses])
        if target is None or target is compound or not ctx.editable_compound(target) or \
                not _inside(target, compound):
            continue
        first_use = min(uses, key=lambda u: u.start)
        holder = first_use.node
        while holder is not None and holder.parent is not target:
            holder = holder.parent
        if holder is None or first_use.node is not holder or first_use.kind != "stmt":
            continue
        root = first_use.root
        if not (isinstance(root, c_ast.Assignment) and root.op == "=" and isinstance(root.lvalue, c_ast.ID)
                and root.lvalue.name == v and v not in {x.name for x in ids(root.rvalue)}):
            continue
        if any(ctx.is_decl(c) and v in {d.name for d in c.group} for c in target.children):
            continue
        yield Cand(f"decl-order: move {v} L{ctx.line(sn.start)} into block L{ctx.line(target.start)}",
                   [removal, ctx.decl_insert(target, reindent(decl_text, "", ""))])


def _inside(inner: SNode, outer: SNode) -> bool:
    node = inner
    while node is not None:
        if node is outer:
            return True
        node = node.parent
    return False


def _innermost_common(ctx: Ctx, nodes: list[SNode]) -> SNode | None:
    def chain(n):
        out = []
        while n is not None:
            if n.kind == "compound":
                out.append(n)
            n = n.parent
        return out[::-1]
    chains = [chain(n) for n in nodes]
    common = None
    for level in zip(*chains):
        if all(x is level[0] for x in level):
            common = level[0]
        else:
            break
    return common


# ---------------------------------------------------------------- control flow
def negations(T: Types, e) -> list:
    """Logical negations of ``e`` for use as a condition: smart form(s) first, then ``!(e)``."""
    out = []
    if isinstance(e, c_ast.UnaryOp) and e.op == "!":
        out.append(e.expr)
    elif isinstance(e, c_ast.BinaryOp) and e.op in _LOGICAL:
        a, b = negations(T, e.left)[0], negations(T, e.right)[0]
        out.append(c_ast.BinaryOp("||" if e.op == "&&" else "&&", a, b))
    elif isinstance(e, c_ast.BinaryOp) and e.op in _NEGATE:
        floaty = e.op not in ("==", "!=") and (T.is_float(T.typeof(e.left)) or T.is_float(T.typeof(e.right))
                                             or T.typeof(e.left) is None or T.typeof(e.right) is None)
        if not floaty:
            out.append(c_ast.BinaryOp(_NEGATE[e.op], e.left, e.right))
    out.append(c_ast.UnaryOp("!", e))
    return out


def _ends_with_jump(sn: SNode) -> bool:
    last = sn
    while last.kind == "compound" and last.children:
        last = last.children[-1]
    return last.kind == "simple" and isinstance(last.ast, (c_ast.Return, c_ast.Goto, c_ast.Break, c_ast.Continue))


def fam_control(ctx: Ctx):
    T, an, src = ctx.types, ctx.an, ctx.src
    for sn in ctx.nodes:
        if sn.ast is None:
            continue
        ind = ctx.indent(sn)
        line = ctx.line(sn.start)
        parent = sn.parent
        in_block = parent is not None and parent.kind == "compound" and ctx.editable_compound(parent)
        if sn.kind == "if":
            cond_ok = ctx.prep.cond_printable(sn)
            ca, cb = ctx.prep.cond_span(sn)
            ctext = src[ca:cb]
            then, other = sn.children[0], (sn.children[1] if sn.has_else else None)
            negs = [expr_text(x) for x in negations(T, sn.ast.cond)] if cond_ok else []
            negs = list(dict.fromkeys(negs))
            # 1. if/else inversion
            if other is not None and negs:
                new_then = other if other.kind == "compound" else None
                then_txt = ctx.wrapped(other, ind) if other.kind != "compound" else ctx.stmt_text_at(other, ind)
                else_txt = ctx.stmt_text_at(then, ind) if then.kind == "compound" else ctx.wrapped(then, ind)
                for k, neg in enumerate(negs):
                    form = "" if k == 0 else " (plain !)"
                    yield Cand(f"control: invert if/else L{line}{form}",
                               [(sn.start, sn.end, f"if ({neg}) {then_txt} else {else_txt}")])
            # 2. early return <-> nested else
            if in_block:
                items = parent.children
                i = items.index(sn)
                if other is not None and _ends_with_jump(then) and _no_decls(other):
                    rest = ctx.body_items_text(other, ind) if other.kind == "compound" else ctx.stmt_text_at(other, ind)
                    if rest:
                        head = src[sn.start:then.end]
                        yield Cand(f"control: flatten else after jump L{line}", [(sn.start, sn.end, head + "\n" + ind + rest)])
                if other is not None and _ends_with_jump(other) and _no_decls(then) and negs:
                    rest = ctx.body_items_text(then, ind) if then.kind == "compound" else ctx.stmt_text_at(then, ind)
                    if rest:
                        jump_txt = ctx.stmt_text_at(other, ind) if other.kind == "compound" else ctx.wrapped(other, ind)
                        yield Cand(f"control: invert to early exit L{line}",
                                   [(sn.start, sn.end, f"if ({negs[0]}) {jump_txt}\n{ind}{rest}")])
                tail = items[i + 1:]
                if other is None and _ends_with_jump(then) and tail and not any(ctx.is_decl(t) for t in tail):
                    rest = reindent(src[tail[0].start:tail[-1].end], ctx.indent(tail[0]), ind + "    ")
                    nested = "{\n" + ind + "    " + rest + "\n" + ind + "}"
                    head = src[sn.start:then.end]
                    end = tail[-1].end
                    yield Cand(f"control: nest rest under else L{line}", [(sn.start, end, f"{head} else {nested}")])
                    if negs:
                        jump_txt = ctx.stmt_text_at(then, ind) if then.kind == "compound" else ctx.wrapped(then, ind)
                        yield Cand(f"control: nest rest under inverted if L{line}",
                                   [(sn.start, end, f"if ({negs[0]}) {nested} else {jump_txt}")])
            # 3. if (c) do B while (c);  ->  while (c) B
            if other is None:
                inner = then
                if inner.kind == "compound" and len(inner.children) == 1 and not ctx.is_decl(inner.children[0]):
                    inner = inner.children[0]
                if inner.kind == "do" and inner.ast is not None and \
                        expr_text(inner.ast.cond) == expr_text(sn.ast.cond):
                    body = inner.children[0]
                    yield Cand(f"control: if+do-while -> while L{line}",
                               [(sn.start, sn.end, f"while ({ctext}) " + ctx.stmt_text_at(body, ind))])
            # 4. a && b  <->  nested ifs
            if other is None and cond_ok and isinstance(sn.ast.cond, c_ast.BinaryOp) and sn.ast.cond.op == "&&":
                a_txt, b_txt = expr_text(sn.ast.cond.left), expr_text(sn.ast.cond.right)
                inner_txt = reindent(src[then.start:then.end], ind, ind + "    ")
                yield Cand(f"control: split && into nested ifs L{line}",
                           [(sn.start, sn.end, f"if ({a_txt}) {{\n{ind}    if ({b_txt}) {inner_txt}\n{ind}}}")])
            if other is None and cond_ok:
                inner = then
                if inner.kind == "compound" and len(inner.children) == 1:
                    inner = inner.children[0]
                if inner.kind == "if" and not inner.has_else and inner.ast is not None and ctx.prep.cond_printable(inner):
                    joined = expr_text(c_ast.BinaryOp("&&", sn.ast.cond, inner.ast.cond))
                    body = inner.children[0]
                    yield Cand(f"control: merge nested ifs with && L{line}",
                               [(sn.start, sn.end, f"if ({joined}) " + ctx.stmt_text_at(body, ind)
                                 if ctx.prep.starts_line(body.start) or body.kind == "compound" else
                                 f"if ({joined}) " + src[body.start:body.end])])
            # 5. if/else assignment -> ternary
            if other is not None and cond_ok:
                x, y = _single_assign(ctx, then), _single_assign(ctx, other)
                if x is not None and y is not None and expr_text(x.lvalue) == expr_text(y.lvalue) and \
                        not an.expr(x.lvalue).side:
                    review = T.sig(T.typeof(x.rvalue)) != T.sig(T.typeof(y.rvalue))
                    text = expr_text(c_ast.Assignment("=", x.lvalue, c_ast.TernaryOp(sn.ast.cond, x.rvalue, y.rvalue))) + ";"
                    yield Cand(f"control: if/else -> ternary L{line}", [(sn.start, sn.end, text)], review)
        if sn.kind == "while":
            ca, cb = ctx.prep.cond_span(sn)
            ctext = src[ca:cb]
            body = sn.children[0]
            if not an.expr(sn.ast.cond).side and "\n" not in ctext:
                yield Cand(f"control: while -> if+do-while L{line}",
                           [(sn.start, sn.end, f"if ({ctext}) do " + src[body.start:body.end] + f" while ({ctext});")])
            head_end = ctx.prep.code[sn.cond[1] + 1].end if sn.cond[1] >= sn.cond[0] else ctx.prep.code[sn.cond[0]].end
            yield Cand(f"control: while -> for(;;) L{line}", [(sn.start, head_end, f"for (; {ctext};)")])
            # init; while (c) { ...; step; }  ->  for (init; c; step) { ... }
            if body.kind == "compound" and body.children and ctx.editable_compound(body) and not has_escape(body.ast, ("continue",)):
                step = body.children[-1]
                if step.kind == "simple" and not ctx.is_decl(step) and isinstance(step.ast, (c_ast.Assignment, c_ast.UnaryOp)) \
                        and "\n" not in ctx.src[step.start:step.end] and not ctx.prep.has_comment(step.start, step.end):
                    a, b = ctx.chunk(body, len(body.children) - 1)
                    new_body = src[body.start:a] + src[b:body.end]
                    step_txt = src[step.start:step.end - 1].strip()
                    yield Cand(f"control: while -> for (no init) L{line}",
                               [(sn.start, sn.end, f"for (; {ctext}; {step_txt}) {new_body}")])
                    if in_block:
                        items = parent.children
                        i = items.index(sn)
                        if i > 0:
                            init = items[i - 1]
                            if init.kind == "simple" and not ctx.is_decl(init) and isinstance(init.ast, (c_ast.Assignment, c_ast.UnaryOp, c_ast.ExprList)) \
                                    and "\n" not in src[init.start:init.end] and not ctx.prep.has_comment(init.start, init.end):
                                init_txt = src[init.start:init.end - 1].strip()
                                yield Cand(f"control: init+while -> for L{line}",
                                           [(init.start, sn.end, f"for ({init_txt}; {ctext}; {step_txt}) {new_body}")])
        if sn.kind == "for":
            body = sn.children[0]
            parts = [ctx.prep.part_span(sn, k) for k in range(3)]
            texts = [src[p[0]:p[1]] if p else "" for p in parts]
            head_end = ctx.prep.code[sn.cond[1] + 1].end
            if not texts[0] and not texts[2]:
                yield Cand(f"control: for(;;) -> while L{line}", [(sn.start, head_end, f"while ({texts[1] or '1'})")])
            if not isinstance(sn.ast.init, c_ast.DeclList) and not has_escape(sn.ast.stmt, ("continue",)) and in_block \
                    and (texts[0] or texts[2]):
                cond = texts[1] or "1"
                if texts[2]:
                    if body.kind == "compound":
                        close = ctx.prep.code[body.t1].start
                        inner_ind = (ctx.indent(body.children[0]) if body.children else ind + "    ")
                        last_end = body.children[-1].end if body.children else ctx.prep.code[body.t0].end
                        new_body = src[body.start:last_end] + f"\n{inner_ind}{texts[2]};" + src[last_end:body.end]
                    else:
                        new_body = "{\n" + ind + "    " + ctx.stmt_text_at(body, ind + "    ") + f"\n{ind}    {texts[2]};\n{ind}}}"
                else:
                    new_body = src[body.start:body.end]
                prefix = f"{texts[0]};\n{ind}" if texts[0] else ""
                yield Cand(f"control: for -> init+while L{line}", [(sn.start, sn.end, f"{prefix}while ({cond}) {new_body}")])
        if sn.kind == "simple" and isinstance(sn.ast, c_ast.Assignment) and sn.ast.op == "=" and \
                isinstance(sn.ast.rvalue, c_ast.TernaryOp) and ctx.prep.printable(sn) and not an.expr(sn.ast.lvalue).side:
            t = sn.ast.rvalue
            lv = expr_text(sn.ast.lvalue)
            review = T.sig(T.typeof(t.iftrue)) != T.sig(T.typeof(t.iffalse))
            text = (f"if ({expr_text(t.cond)}) {{\n{ind}    {lv} = {expr_text(t.iftrue)};\n{ind}}} else {{\n"
                    f"{ind}    {lv} = {expr_text(t.iffalse)};\n{ind}}}")
            yield Cand(f"control: ternary -> if/else L{line}", [(sn.start, sn.end, text)], review)
    yield from _control_m2c(ctx)


def _entry_true(ctx: Ctx, init: SNode | None, cond) -> bool:
    """The loop condition is provably true on entry: ``v = K;`` immediately precedes the loop and
    the condition compares ``v`` (alone or with a constant) and evaluates true for ``v == K``."""
    if init is None or init.kind != "simple" or not isinstance(init.ast, c_ast.Assignment) or init.ast.op != "=":
        return False
    lv, value = init.ast.lvalue, _int_value(init.ast.rvalue)
    if not isinstance(lv, c_ast.ID) or value is None or not ctx.types.is_int(ctx.types.typeof(lv)):
        return False
    def ev(e):
        if isinstance(e, c_ast.ID) and e.name == lv.name:
            return value
        if isinstance(e, c_ast.Cast) and ctx.types.is_int(e.to_type.type):
            inner = ev(e.expr)
            k = ctx.types.kind(e.to_type.type)
            if inner is None or k is None:
                return None
            bits = 8 * k[1]
            inner &= (1 << bits) - 1
            if k[2] is not False and inner >= 1 << (bits - 1):
                inner -= 1 << bits
            return inner
        return _int_value(e)
    if isinstance(cond, c_ast.BinaryOp) and cond.op in _COMPARE:
        a, b = ev(cond.left), ev(cond.right)
        if a is None or b is None:
            return False
        return {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b, "==": a == b, "!=": a != b}[cond.op]
    v = ev(cond)
    return bool(v)


def _continues_to_end(ctx: Ctx, compound: SNode) -> bool:
    """Control leaving ``compound`` at its end reaches the end of the function directly."""
    node = compound
    for _ in range(64):
        if node is ctx.prep.body:
            return True
        parent = node.parent
        if parent is None:
            return False
        if parent.kind == "if":
            holder = parent
        elif parent.kind == "compound":
            if parent.children[-1] is not node:
                return False
            node = parent
            continue
        else:
            return False
        outer = holder.parent
        if outer is None or outer.kind != "compound" or outer.children[-1] is not holder:
            return False
        node = outer
    return False


def _void(ctx: Ctx) -> bool:
    t = ctx.prep.fn.decl.type.type
    return ctx.types.kind(t) == ("void",)


def _control_m2c(ctx: Ctx):
    """Loop rotation and void early-exit forms (m2c normal forms <-> written source)."""
    T, an, src = ctx.types, ctx.an, ctx.src
    for sn in ctx.nodes:
        parent = sn.parent
        if sn.ast is None or parent is None or parent.kind != "compound" or not ctx.editable_compound(parent):
            continue
        items = parent.children
        i = items.index(sn)
        ind, line = ctx.indent(sn), ctx.line(sn.start)
        prev = items[i - 1] if i > 0 and not ctx.is_decl(items[i - 1]) else None
        simple_prev = prev is not None and prev.kind == "simple" and \
            isinstance(prev.ast, (c_ast.Assignment, c_ast.UnaryOp, c_ast.ExprList)) and \
            "\n" not in src[prev.start:prev.end] and not ctx.prep.has_comment(prev.start, prev.end)
        if sn.kind == "do" and re.fullmatch(r"\(*\s*0[uUlL]*\s*\)*", src[slice(*ctx.prep.cond_span(sn))].strip()):
            # ``do { ... } while (0)`` is a block, not a rotated loop: as a ``while`` or ``for``
            # its body would never run, so no pre-tested form of it is ever offered
            pass
        elif sn.kind == "do":
            ca, cb = ctx.prep.cond_span(sn)
            ctext = src[ca:cb]
            body = sn.children[0]
            review = not _entry_true(ctx, prev, sn.ast.cond)
            yield Cand(f"control: do-while -> while L{line}", [(sn.start, sn.end, f"while ({ctext}) {src[body.start:body.end]}")], review)
            if body.kind == "compound" and body.children and ctx.editable_compound(body) and \
                    not has_escape(body.ast, ("continue",)) and simple_prev and "\n" not in ctext:
                step = body.children[-1]
                if step.kind == "simple" and isinstance(step.ast, (c_ast.Assignment, c_ast.UnaryOp)) and \
                        "\n" not in src[step.start:step.end] and not ctx.prep.has_comment(step.start, step.end):
                    a, b = ctx.chunk(body, len(body.children) - 1)
                    new_body = src[body.start:a] + src[b:body.end]
                    init_txt = src[prev.start:prev.end - 1].strip()
                    step_txt = src[step.start:step.end - 1].strip()
                    yield Cand(f"control: init+do-while -> for L{line}",
                               [(prev.start, sn.end, f"for ({init_txt}; {ctext}; {step_txt}) {new_body}")], review)
        if sn.kind in ("while", "for"):
            body = sn.children[0]
            if sn.kind == "for":
                parts = [ctx.prep.part_span(sn, k) for k in range(3)]
                texts = [src[p[0]:p[1]] if p else "" for p in parts]
                if isinstance(sn.ast.init, c_ast.DeclList) or not texts[1] or "\n" in "".join(texts) or \
                        has_escape(sn.ast.stmt, ("continue",)):
                    texts = None
                init_node = None
                if texts and sn.ast.init is not None:
                    init_node = SNode("simple", 0, 0)
                    init_node.ast = sn.ast.init
                    entry = _entry_true(ctx, init_node, sn.ast.cond)
                else:
                    entry = texts is not None and _entry_true(ctx, prev, sn.ast.cond)
                if texts:
                    if texts[2]:
                        if body.kind == "compound":
                            inner_ind = ctx.indent(body.children[0]) if body.children else ind + "    "
                            last_end = body.children[-1].end if body.children else ctx.prep.code[body.t0].end
                            new_body = src[body.start:last_end] + f"\n{inner_ind}{texts[2]};" + src[last_end:body.end]
                        else:
                            new_body = "{\n" + ind + "    " + ctx.stmt_text_at(body, ind + "    ") + f"\n{ind}    {texts[2]};\n{ind}}}"
                    else:
                        new_body = src[body.start:body.end]
                    prefix = f"{texts[0]};\n{ind}" if texts[0] else ""
                    yield Cand(f"control: for -> init+do-while L{line}",
                               [(sn.start, sn.end, f"{prefix}do {new_body} while ({texts[1]});")], not entry)
            else:
                ca, cb = ctx.prep.cond_span(sn)
                ctext = src[ca:cb]
                if "\n" not in ctext:
                    yield Cand(f"control: while -> do-while L{line}",
                               [(sn.start, sn.end, f"do {src[body.start:body.end]} while ({ctext});")],
                               not _entry_true(ctx, prev, sn.ast.cond))
        # void early exit at the end of the function
        if sn.kind == "if" and _void(ctx) and _continues_to_end(ctx, parent) and ctx.prep.cond_printable(sn):
            negs = list(dict.fromkeys(expr_text(x) for x in negations(T, sn.ast.cond)))
            then = sn.children[0]
            if not sn.has_else and i == len(items) - 1 and _no_decls(then) and \
                    not has_escape(then.ast):
                rest = ctx.body_items_text(then, ind) if then.kind == "compound" else ctx.stmt_text_at(then, ind)
                if rest:
                    for k, neg in enumerate(negs):
                        yield Cand(f"control: if-block -> early return L{line}" + ("" if k == 0 else " (plain !)"),
                                   [(sn.start, sn.end, f"if ({neg}) {{\n{ind}    return;\n{ind}}}\n{ind}{rest}")])
            is_return = then.kind == "simple" and isinstance(then.ast, c_ast.Return) and then.ast.expr is None or \
                (then.kind == "compound" and len(then.children) == 1 and isinstance(then.children[0].ast, c_ast.Return)
                 and then.children[0].ast.expr is None)
            tail = items[i + 1:]
            if not sn.has_else and is_return and tail and not any(ctx.is_decl(t) for t in tail) and \
                    not any(an.node(t).label for t in tail):
                rest = reindent(src[tail[0].start:tail[-1].end], ctx.indent(tail[0]), ind + "    ")
                for k, neg in enumerate(negs):
                    yield Cand(f"control: early return -> if-block L{line}" + ("" if k == 0 else " (plain !)"),
                               [(sn.start, tail[-1].end, f"if ({neg}) {{\n{ind}    {rest}\n{ind}}}")])


def _no_decls(sn: SNode) -> bool:
    return sn.kind != "compound" or not any(c.kind == "simple" and isinstance(c.ast, c_ast.Decl) for c in sn.children)


def _single_assign(ctx: Ctx, sn: SNode):
    if sn.kind == "compound" and len(sn.children) == 1:
        sn = sn.children[0]
    if sn.kind == "simple" and isinstance(sn.ast, c_ast.Assignment) and sn.ast.op == "=" and ctx.prep.printable(sn):
        return sn.ast
    return None


# ---------------------------------------------------------------- block and line structure
def fam_block(ctx: Ctx):
    """Unwrapping first (few, and the inverse of every wrap), then wrapping."""
    found = list(_block_forms(ctx))
    yield from (c for c in found if "unwrap" in c.label)
    yield from (c for c in found if "unwrap" not in c.label)


def _block_forms(ctx: Ctx):
    src = ctx.src
    for compound in ctx.nodes:
        if not ctx.editable_compound(compound):
            continue
        items = compound.children
        for i, sn in enumerate(items):
            if ctx.is_decl(sn):
                continue
            ind = ctx.indent(sn)
            line = ctx.line(sn.start)
            starts = ctx.prep.starts_line(sn.start)
            for j in (i, i + 1):
                if j >= len(items) or not starts:
                    continue
                text = reindent(src[sn.start:items[j].end], ind, ind + "    ")
                escape = any(has_escape(items[k].ast) for k in range(i, j + 1))
                span = f"L{line}" + (f"-L{ctx.line(items[j].start)}" if j > i else "")
                if not escape:
                    yield Cand(f"block: wrap {span} in do-while(0)",
                               [(sn.start, items[j].end, f"do {{\n{ind}    {text}\n{ind}}} while (0);")])
                yield Cand(f"block: wrap {span} in if (1)", [(sn.start, items[j].end, f"if (1) {{\n{ind}    {text}\n{ind}}}")])
            inner = None
            if sn.kind == "do" and _int_value(sn.ast.cond) == 0 and sn.children[0].kind == "compound" and \
                    not has_escape(sn.children[0].ast):
                inner, what = sn.children[0], "do-while(0)"
            elif sn.kind == "if" and not sn.has_else and _int_value(sn.ast.cond) not in (None, 0) and \
                    sn.children[0].kind == "compound":
                inner, what = sn.children[0], "if (1)"
            elif sn.kind == "compound":
                inner, what = sn, "block"
            if inner is not None and inner.children and _no_decls(inner) and ctx.editable_compound(inner):
                yield Cand(f"block: unwrap {what} L{line}", [(sn.start, sn.end, ctx.body_items_text(inner, ind))])


def fam_sameline(ctx: Ctx):
    src = ctx.src
    for compound in ctx.nodes:
        if compound.kind != "compound" or compound.ast is None:
            continue
        items = compound.children
        for i in range(len(items) - 1):
            a, b = items[i], items[i + 1]
            if a.ast is None or b.ast is None:
                continue
            gap = src[a.end:b.start]
            if gap.strip():
                continue
            if "\n" in gap:
                if "\n" in src[b.start:b.end] and b.kind == "simple":
                    continue
                yield Cand(f"sameline: join L{ctx.line(a.start)}+L{ctx.line(b.start)}", [(a.end, b.start, " ")])
            else:
                yield Cand(f"sameline: split L{ctx.line(a.start)} at '{_snip(src[b.start:b.end], 20)}'",
                           [(a.end, b.start, "\n" + ctx.prep.indent_at(a.start))])


FAMILY_FUNCS = {"temp": fam_temp, "inline-temp": fam_inline, "stmt-order": fam_stmt_order,
                "decl-order": fam_decl_order, "control": fam_control, "expr": fam_expr, "cast": fam_cast,
                "block": fam_block, "sameline": fam_sameline}


# ============================================================================== API
def context(source: str, name: str, includes=None) -> Ctx:
    return Ctx(astprep.prepare(source, name, includes))


def _labelled(ctx: Ctx, family: str):
    """Candidates of one family with unique, stable labels."""
    seen: dict[str, int] = {}
    try:
        for cand in FAMILY_FUNCS[family](ctx):
            count = seen.get(cand.label, 0) + 1
            seen[cand.label] = count
            if count > 1:
                cand.label = f"{cand.label} #{count}"
            yield cand
    except RecursionError:
        return


def _check(text: str, name: str, includes) -> bool:
    try:
        astprep.prepare(text, name, includes)
        return True
    except (PrepError, RecursionError):
        return False
    except Exception:              # pragma: no cover - parser bugs must not break the search
        return False


def variants(source: str, name: str, families: tuple[str, ...] = FAMILIES, limit: int = 64, *,
             includes=None, check: bool = True) -> list[Variant]:
    """Single-step variants of function ``name``.  Families are interleaved round-robin so
    every family gets a share of ``limit``; results are deduplicated by text and every one
    re-parses and re-maps.  ``[]`` when the function cannot be parsed or mapped."""
    try:
        ctx = context(source, name, includes)
    except (PrepError, RecursionError):
        return []
    except Exception:
        return []
    streams = [(f, _labelled(ctx, f)) for f in families if f in FAMILY_FUNCS]
    out: list[Variant] = []
    seen = {source}
    while streams and (limit is None or len(out) < limit):
        alive = []
        for family, stream in streams:
            if limit is not None and len(out) >= limit:
                break
            while True:
                try:
                    cand = next(stream)
                except StopIteration:
                    cand = None
                    break
                except Exception:
                    cand = None
                    break
                try:
                    text = apply_edits(source, cand.edits)
                except ValueError:
                    continue
                if text in seen:
                    continue
                seen.add(text)
                if check and not _check(text, name, includes):
                    continue
                out.append(Variant(cand.label, family, text, cand.review))
                break
            if cand is not None:
                alive.append((family, stream))
        streams = alive
    return out


def apply_path(source: str, name: str, labels: list[str], includes=None) -> str | None:
    """Replay a sequence of variant labels; ``None`` if a label does not apply."""
    text = source
    for label in labels:
        family = label.split(":", 1)[0]
        if family not in FAMILY_FUNCS:
            return None
        try:
            ctx = context(text, name, includes)
        except (PrepError, RecursionError):
            return None
        for cand in _labelled(ctx, family):
            if cand.label == label:
                text = apply_edits(text, cand.edits)
                break
        else:
            return None
    return text


def diagnose(source: str, name: str, includes=None) -> str:
    try:
        ctx = context(source, name, includes)
    except PrepError as error:
        return str(error)
    except RecursionError:
        return "recursion: function too deeply nested"
    statements = sum(1 for n in ctx.nodes if n.kind != "compound")
    frozen = sum(1 for u in ctx.units if not u.printable)
    missing = ctx.prep.missing_includes
    return (f"ok: {statements} statements, {len(ctx.units)} expression units ({frozen} not re-printable)"
            + (f"; missing includes: {', '.join(missing)}" if missing else ""))
