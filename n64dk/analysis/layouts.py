"""Structure layouts, global declarations and a decompiler context, recovered from machine code.

A first draft is only as good as the types it starts from: without them every field access
is a cast (`*(s16 *)((u8 *)p + 0x14)`), every global is an `s32`, every callee is
unprototyped, and the largest classes of residual (width, signedness, frame size, drafts that
do not build) are type guesses.  This module turns whole-image evidence into declarations.

``recover`` works on the facts of every function of an image (``values.track``):

* **identity** -- pointers that must have the same pointee type are joined (union-find with
  offsets): a function's parameter with the value each caller passes for it (``p + 0x40``
  joins with the embedded offset), a call's result with the callee's returned pointer, a
  global pointer variable with every load of it, and a pointer field with every pointer
  loaded from that field;
* **compatibility** -- two groups are joined only when their observed fields agree; a join that
  would put different widths at the same offset is refused and recorded, which keeps generic
  routines (`memcpy`, list helpers, allocators) from fusing unrelated structures.  A callee
  parameter that the callee never dereferences is not used as a bridge at all;
* **fields** -- per group and offset: width, signedness, integer/float, load/store counts, the
  functions that touch it, and the group a pointer field points to.

``context`` renders the result as C: provisional `struct` definitions (fields named
``unk_<hex offset>``, gaps as ``char unk_<hex>[n]`` so a decompiler may refine them), `extern`
declarations for globals with the width and signedness actually used, and prototypes from
``abi.solve`` with structure pointers substituted.  Everything is provisional evidence, named
as such, to seed drafts; it never replaces a project's real headers.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import abi as abimod
from . import values as valuemod

MAX_STRUCT_SIZE = 0x2000
MAX_FIELDS = 512


@dataclass
class Field:
    offset: int
    width: int
    signed: bool
    floating: bool
    loads: int = 0
    stores: int = 0
    functions: int = 0
    pointee: int | None = None          # group id this field points to
    conflicts: list[int] = field(default_factory=list)   # other widths seen at this offset

    @property
    def ctype(self) -> str:
        if self.floating:
            return "f32" if self.width == 4 else "f64"
        return {1: "s8" if self.signed else "u8", 2: "s16" if self.signed else "u16", 4: "s32",
                8: "s64"}[self.width]


@dataclass
class Group:
    gid: int
    name: str
    members: list[tuple]
    fields: dict[int, Field]
    size: int
    functions: int

    @property
    def is_struct(self) -> bool:
        if all(f.width == 1 and not f.floating for f in self.fields.values()):
            return False                               # only bytes: a buffer or string, not a record
        return len(self.fields) >= 2 or (len(self.fields) == 1 and next(iter(self.fields)) != 0)

    def view(self, offset: int) -> "Group":
        """The part of this record that starts ``offset`` bytes in (what a callee sees when it is
        handed ``&record->member``): same fields, re-based."""
        fields = {o - offset: Field(o - offset, f.width, f.signed, f.floating, f.loads, f.stores, f.functions,
                                    f.pointee, list(f.conflicts))
                  for o, f in self.fields.items() if o >= offset}
        size = max((o + f.width for o, f in fields.items()), default=0)
        return Group(self.gid, f"{self.name}_at_{offset:X}", self.members, fields, (size + 3) & ~3, self.functions)


@dataclass
class GlobalDecl:
    address: int
    name: str
    ctype: str
    array: bool
    accesses: int


@dataclass
class Layouts:
    groups: list[Group]
    param_group: dict[tuple[int, int], tuple[int, int]]     # (function, index) -> (group id, offset)
    return_group: dict[int, int]                            # function -> group id
    globals: list[GlobalDecl]
    refused: int                                            # joins refused for incompatibility

    def group(self, gid: int) -> Group | None:
        return next((g for g in self.groups if g.gid == gid), None)


class _Union:
    """Union-find where each node has a byte offset relative to its root."""

    def __init__(self):
        self.parent: dict = {}
        self.offset: dict = {}
        self.fields: dict = {}          # root -> {offset: Counter((width, signed, floating))}
        self.refused = 0

    def find(self, node):
        if node not in self.parent:
            self.parent[node], self.offset[node], self.fields[node] = node, 0, {}
            return node, 0
        chain, current = [], node
        while self.parent[current] != current:
            chain.append(current)
            current = self.parent[current]
        root, accumulated = current, 0
        for item in reversed(chain):                # nearest-to-root first: offsets become root-relative
            accumulated += self.offset[item]
            self.offset[item], self.parent[item] = accumulated, root
        return root, (self.offset[node] if chain else 0)

    def add_access(self, node, offset: int, width: int, signed, floating: bool) -> None:
        root, base = self.find(node)
        self.fields[root].setdefault(base + offset, Counter())[(width, bool(signed), floating)] += 1

    def union(self, a, b, delta: int = 0) -> bool:
        """Declare address(b) == address(a) + delta.  Refused when observed fields disagree."""
        root_a, off_a = self.find(a)
        root_b, off_b = self.find(b)
        if root_a == root_b:
            return off_b == off_a + delta
        shift = off_a + delta - off_b               # root_b's fields move by this much into root_a
        mine, theirs = self.fields[root_a], self.fields[root_b]
        overlap = conflicts = 0
        for offset, kinds in theirs.items():
            other = mine.get(offset + shift)
            if other:
                overlap += 1
                if {k[0] for k in kinds} != {k[0] for k in other}:
                    conflicts += 1
        if conflicts and conflicts * 4 > overlap:    # more than a quarter of shared offsets disagree
            self.refused += 1
            return False
        if max((o + shift for o in theirs), default=0) > MAX_STRUCT_SIZE or \
                min((o + shift for o in theirs), default=0) < -MAX_STRUCT_SIZE:
            self.refused += 1
            return False
        for offset, kinds in theirs.items():
            mine.setdefault(offset + shift, Counter()).update(kinds)
        self.parent[root_b], self.offset[root_b] = root_a, shift
        del self.fields[root_b]
        return True


def _node(key: tuple, function: int, uf: _Union):
    """Graph node for a tracked value key seen inside ``function`` (None: not a pointer identity)."""
    kind = key[0]
    if kind == "param":
        return ("param", function, key[1])
    if kind == "ret":
        return ("ret", key[1]) if key[1] is not None else None
    if kind == "gptr":
        return ("gptr", key[1])
    if kind == "field":
        base = _node(key[1], function, uf)
        if base is None:
            return None
        root, offset = uf.find(base)
        return ("fieldptr", root, offset + key[2])
    return None


def recover(functions: dict[int, valuemod.Facts], names: dict[int, str] | None = None) -> Layouts:
    names = names or {}
    uf = _Union()
    # 1. local evidence: every access through a tracked pointer
    for vram, facts in functions.items():
        for access in facts.accesses:
            node = _node(access.base, vram, uf)
            if node is not None and -0x100 <= access.offset < MAX_STRUCT_SIZE:
                uf.add_access(node, access.offset, access.width, access.signed if not access.store else False,
                              access.floating)
    dereferenced = {(vram, index) for vram, facts in functions.items()
                    for index, traits in facts.params.items() if "pointer" in traits}
    # 2. joins: arguments with parameters, results with returned pointers (two rounds: field
    #    pointers resolve against the groups formed in the first)
    for _round in range(2):
        for vram, facts in functions.items():
            for call in facts.calls:
                if call.target not in functions:
                    continue
                for reg, value in call.args.items():
                    index = reg - 4
                    if value is None or reg not in call.fresh or (call.target, index) not in dereferenced:
                        continue
                    node = _node(value[0], vram, uf)
                    if node is not None and abs(value[1]) < MAX_STRUCT_SIZE:
                        # address(parameter) == address(value) + delta
                        uf.union(node, ("param", call.target, index), value[1])
            for key in facts.returns:
                if key[0] in ("param", "gptr", "field", "ret"):
                    node = _node(key, vram, uf)
                    if node is not None and node != ("ret", vram):
                        uf.union(node, ("ret", vram), 0)
    # 3. groups
    members: dict = {}
    for node in list(uf.parent):
        root, _offset = uf.find(node)
        members.setdefault(root, []).append(node)
    touching: dict = {}
    for vram, facts in functions.items():
        for access in facts.accesses:
            node = _node(access.base, vram, uf)
            if node is not None:
                touching.setdefault(uf.find(node)[0], set()).add(vram)
    ids = {root: number for number, root in enumerate(sorted(members, key=repr))}
    groups: dict[int, Group] = {}
    for root, nodes in members.items():
        raw = uf.fields.get(root, {})
        if not raw or len(raw) > MAX_FIELDS:
            continue
        fields: dict[int, Field] = {}
        for offset in sorted(o for o in raw if o >= 0):
            kinds = raw[offset]
            widths = Counter()
            for (width, _signed, _floating), count in kinds.items():
                widths[width] += count
            width = widths.most_common(1)[0][0]
            if any(offset < o + f.width for o, f in fields.items() if o < offset):
                continue                             # inside a wider field already emitted
            same = {k: c for k, c in kinds.items() if k[0] == width}
            floating = sum(c for k, c in same.items() if k[2]) * 2 > sum(same.values())
            signed = any(k[1] for k in same) or width >= 4
            fields[offset] = Field(offset, width, signed, floating,
                                   conflicts=sorted(w for w in widths if w != width))
        if not fields:
            continue
        param_members = sorted(n for n in nodes if n[0] == "param")
        if param_members:
            owner = param_members[0]
            label = f"{names.get(owner[1]) or f'func_{owner[1]:08X}'}_arg{owner[2]}"
        else:
            first = sorted(nodes, key=repr)[0]
            label = (f"ret_{names.get(first[1]) or f'func_{first[1]:08X}'}" if first[0] == "ret"
                     else f"ptr_{first[1]:08X}" if first[0] == "gptr" else f"anon_{ids[root]}")
        size = max(o + f.width for o, f in fields.items())
        groups[ids[root]] = Group(ids[root], f"Struct_{label}", sorted(nodes, key=repr), fields,
                                  (size + 3) & ~3, len(touching.get(root, ())))
    # 4. pointer fields
    for root, nodes in members.items():
        for node in nodes:
            if node[0] == "fieldptr" and node[1] in ids and ids[root] in groups:
                owner = groups.get(ids[node[1]])
                if owner is not None and node[2] in owner.fields and owner.fields[node[2]].width == 4 \
                        and groups[ids[root]].is_struct:
                    owner.fields[node[2]].pointee = ids[root]
    param_group, return_group = {}, {}
    for node in uf.parent:
        root, offset = uf.find(node)
        gid = ids.get(root)
        if gid not in groups or not groups[gid].is_struct:
            continue
        if node[0] == "param":
            param_group[(node[1], node[2])] = (gid, offset)
        elif node[0] == "ret" and offset == 0:
            return_group[node[1]] = gid
    return Layouts(sorted((g for g in groups.values() if g.is_struct), key=lambda g: g.name), param_group,
                   return_group, _globals(functions, names), uf.refused)


def _globals(functions: dict[int, valuemod.Facts], names: dict[int, str]) -> list[GlobalDecl]:
    seen: dict[int, Counter] = {}
    indexed: Counter = Counter()
    for facts in functions.values():
        for access in facts.globals:
            kind = (access.width, bool(access.signed) if not access.store else None, access.floating)
            seen.setdefault(access.address, Counter())[kind] += 1
            indexed[access.address] += access.indexed
    out = []
    for address, kinds in sorted(seen.items()):
        if address in functions:
            continue
        widths = Counter()
        for (width, _signed, _floating), count in kinds.items():
            widths[width] += count
        if len(widths) > 1:
            continue                                  # mixed widths: an aggregate, leave it undeclared
        width = next(iter(widths))
        floating = sum(c for k, c in kinds.items() if k[2]) * 2 > sum(kinds.values())
        loads = [k for k in kinds if k[1] is not None]
        signed = any(k[1] for k in loads) if loads else True
        ctype = ("f32" if width == 4 else "f64") if floating else \
            {1: "s8" if signed else "u8", 2: "s16" if signed else "u16", 4: "s32", 8: "s64"}[width]
        if not loads and width < 4 and not floating:
            ctype = "u8" if width == 1 else "u16"     # store-only narrow global: signedness unknown
        out.append(GlobalDecl(address, names.get(address) or f"D_{address:08X}", ctype,
                              indexed[address] * 2 >= sum(kinds.values()), sum(kinds.values())))
    return out


TYPEDEFS = ("typedef signed char s8; typedef unsigned char u8; typedef signed short s16; "
            "typedef unsigned short u16;\ntypedef signed int s32; typedef unsigned int u32; "
            "typedef signed long long s64; typedef unsigned long long u64;\ntypedef float f32; typedef double f64;\n")


def struct_text(group: Group, layouts: Layouts) -> str:
    lines = [f"struct {group.name} {{   /* provisional: {len(group.fields)} field(s) from "
             f"{group.functions} function(s) */"]
    cursor = 0
    for offset in sorted(group.fields):
        item = group.fields[offset]
        if offset > cursor:
            lines.append(f"    /* 0x{cursor:02X} */ char unk_{cursor:X}[0x{offset - cursor:X}];")
        target = layouts.group(item.pointee) if item.pointee is not None else None
        ctype = f"struct {target.name} *" if target is not None and target.gid != group.gid else \
            (f"struct {group.name} *" if target is not None else item.ctype + " ")
        note = f"   /* also accessed as {', '.join(str(w * 8) + '-bit' for w in item.conflicts)} */" \
            if item.conflicts else ""
        lines.append(f"    /* 0x{offset:02X} */ {ctype}unk_{offset:X};{note}")
        cursor = offset + item.width
    lines.append("};")
    return "\n".join(lines)


class Declarations:
    """Renderable declarations for one image: whole (``full``) or cut down to what one function
    references (``focused``), which keeps the decompiler fast and lets a caller decide whether a
    function's own, less certain, prototype is imposed on its draft."""

    def __init__(self, layouts: Layouts, prototypes: dict[int, abimod.Prototype] | None = None,
                 min_confidence: float = 0.8, min_fields: int = 2, globals_min_accesses: int = 1):
        self.layouts = layouts
        kept = [g for g in layouts.groups if len(g.fields) >= min_fields]
        kept_ids = {g.gid for g in kept}
        # a parameter that points into the middle of a record gets a re-based view of it
        views: dict[tuple[int, int], Group] = {}
        for (_function, _index), (gid, offset) in sorted(layouts.param_group.items()):
            if gid in kept_ids and offset > 0 and (gid, offset) not in views:
                view = layouts.group(gid).view(offset)
                if len(view.fields) >= min_fields and view.is_struct:
                    views[(gid, offset)] = view
        self.structs: dict[str, str] = {g.name: struct_text(g, layouts) for g in [*kept, *views.values()]}
        self.globals: dict[int, str] = {
            item.address: f"extern {item.ctype} {item.name}{'[]' if item.array else ''};"
            for item in layouts.globals if item.accesses >= globals_min_accesses}
        self.prototypes: dict[int, str] = {}
        self.confident: set[int] = set()
        for vram, proto in sorted((prototypes or {}).items()):
            types = list(proto.arg_types)
            for index in range(len(types)):
                hit = layouts.param_group.get((vram, index))
                if hit and hit[0] in kept_ids and types[index] == "void *":
                    if hit[1] == 0:
                        types[index] = f"struct {layouts.group(hit[0]).name} *"
                    elif hit in views:
                        types[index] = f"struct {views[hit].name} *"
            returns = proto.returns
            if returns == "void *" and layouts.return_group.get(vram) in kept_ids:
                returns = f"struct {layouts.group(layouts.return_group[vram]).name} *"
            self.prototypes[vram] = f"{returns} {proto.name}({', '.join(types) or 'void'});"
            if proto.confidence >= min_confidence:
                self.confident.add(vram)

    def _render(self, protos: list[str], globals_: list[str], typedefs: bool, all_structs: bool) -> str:
        names = list(self.structs)
        if not all_structs:                          # only the records the chosen prototypes mention
            wanted, queue = set(), [n for n in names if any(f"struct {n} " in p for p in protos)]
            while queue:
                name = queue.pop()
                if name not in wanted:
                    wanted.add(name)
                    queue += [n for n in names if n not in wanted and f"struct {n} *" in self.structs[name]]
            names = [n for n in names if n in wanted]
        parts = ["/* Provisional declarations recovered from machine code by n64dk. Evidence, not truth. */"]
        if typedefs:
            parts.append(TYPEDEFS)
        parts += [f"struct {n};" for n in names] + [self.structs[n] for n in names] + globals_ + protos
        return "\n".join(parts) + "\n"

    def full(self, typedefs: bool = True) -> str:
        return self._render([self.prototypes[v] for v in sorted(self.confident)],
                            [self.globals[a] for a in sorted(self.globals)], typedefs, True)

    def focused(self, facts: valuemod.Facts, vram: int, include_self: bool = False,
                typedefs: bool = True) -> str:
        """Declarations for one function: prototypes of its (confidently solved) callees, the
        globals it touches and the records those mention; its own prototype only on request."""
        callees = sorted({c.target for c in facts.calls if c.target in self.confident and c.target != vram})
        protos = [self.prototypes[v] for v in callees]
        if include_self and vram in self.prototypes:
            protos.append(self.prototypes[vram])
        touched = sorted({g.address for g in facts.globals if g.address in self.globals})
        return self._render(protos, [self.globals[a] for a in touched], typedefs, False)


def context(layouts: Layouts, prototypes: dict[int, abimod.Prototype] | None = None,
            min_confidence: float = 0.8, typedefs: bool = True, min_fields: int = 2,
            globals_min_accesses: int = 1) -> str:
    """Whole-image declarations as C text (structs, globals, confident prototypes).
    ``typedefs=False`` omits the integer typedefs (for prepending to a source that has them)."""
    return Declarations(layouts, prototypes, min_confidence, min_fields, globals_min_accesses).full(typedefs)


def summary(layouts: Layouts) -> dict:
    structs = [g for g in layouts.groups if len(g.fields) >= 2]
    return {"structs": len(structs), "fields": sum(len(g.fields) for g in structs),
            "largest": sorted(((len(g.fields), g.name, g.size) for g in structs), reverse=True)[:5],
            "typed_parameters": len(layouts.param_group), "typed_returns": len(layouts.return_group),
            "globals": len(layouts.globals), "refused_joins": layouts.refused}
