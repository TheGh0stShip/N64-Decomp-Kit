"""One source file per function, cut from a preprocessed unit.

The donor stage accepts a unit only whole: every function of it must stand in the target, one
after the other.  A source tree's units are large, and one function that differs (another
release, an option, a routine the tree has not finished) then keeps all its neighbours out: on
the first tree measured, 2,700 functions were found in the target and 540 were accepted.

This module turns a unit into function-sized units the stage can take one at a time.  For each
function it writes a file with that function, and of everything else in the unit only what the
function needs:

* other functions become declarations (their bodies are not part of this function's code);
* objects the unit defines become ``extern`` declarations without their initialisers (their
  bytes belong to the unit's data, which a function-sized unit does not claim);
* declarations nothing in the file uses are left out;
* names that were local to the unit (``static``) are given a suffix of the unit, because two
  units may use the same local name for different things and the stage follows names;
* anything written through the assembler (``asm`` at file level) is dropped: such code is not C.

The cut is made on the text, by braces, parentheses and semicolons, not by a C parser: what a
preprocessor writes for these compilers is not always what a parser accepts.  Nothing here is
trusted either way.  A file that is cut wrongly does not compile, or compiles to other bytes,
and the stage's strict comparison with the target refuses it: a wrong cut loses a function, it
cannot credit one.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

KEYWORDS = frozenset("""auto break case char const continue default do double else enum extern float for goto if
inline int long register return short signed sizeof static struct switch typedef union unsigned void volatile while
__inline__ __inline __attribute__ __extension__ __asm__ __asm asm __volatile__ __const __signed__ __restrict
__typeof__ typeof __builtin_va_list""".split())
IDENT = re.compile(r"[A-Za-z_]\w*")
ATTRIBUTE = re.compile(r"\s*__attribute__\s*\(\(.*?\)\)\s*$", re.S)
ASM_START = re.compile(r"(?:__asm__|__asm|asm)\b")
TAG_ONLY = re.compile(r"(?:struct|union|enum)\b\s*\w*\s*;")
POINTER_NAME = re.compile(r"\(\s*\*+\s*(?:const\s+|volatile\s+)*([A-Za-z_]\w*)")


@dataclass
class Chunk:
    """One declaration or definition at file level."""
    text: str
    kind: str                     # function | object | other | asm | directive
    name: str | None = None       # function: its name
    head: str = ""                # function: everything before the body
    declares: frozenset = frozenset()
    uses: frozenset = frozenset()
    local: tuple = ()             # names this chunk makes local to the unit (``static``)
    inline: bool = False
    head_uses: frozenset = frozenset()   # function: the names its head alone uses


def literal_spans(text: str) -> list[tuple[int, int]]:
    """Spans of string and character literals."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            out.append((i, min(j + 1, n)))
            i = j + 1
        else:
            i += 1
    return out


def blank_literals(text: str) -> str:
    """``text`` with the inside of every literal replaced by spaces (same length)."""
    out = list(text)
    for start, end in literal_spans(text):
        for k in range(start + 1, end - 1):
            if out[k] != "\n":
                out[k] = " "
    return "".join(out)


def _match(blank: str, start: int, opener: str, closer: str) -> int:
    """Index of the bracket closing the one at ``start``; -1 when there is none."""
    depth = 0
    for i in range(start, len(blank)):
        if blank[i] == opener:
            depth += 1
        elif blank[i] == closer:
            depth -= 1
            if depth == 0:
                return i
    return -1


def _outside(blank: str) -> str:
    """``blank`` with whatever stands inside braces or parentheses replaced by spaces."""
    out, braces, parens = [], 0, 0
    for ch in blank:
        if ch == "{":
            braces += 1
        elif ch == "(":
            parens += 1
        out.append(ch if braces == 0 and parens == 0 or ch == "\n" else " ")
        if ch == "}":
            braces = max(0, braces - 1)
            out[-1] = " "
        elif ch == ")":
            parens = max(0, parens - 1)
            out[-1] = " "
    return "".join(out)


def _function_name(head_blank: str) -> str | None:
    head = head_blank.rstrip()
    while True:
        shorter = ATTRIBUTE.sub("", head)
        if shorter == head:
            break
        head = shorter.rstrip()
    if not head.endswith(")"):
        return None
    depth = 0
    for i in range(len(head) - 1, -1, -1):
        if head[i] == ")":
            depth += 1
        elif head[i] == "(":
            depth -= 1
            if depth == 0:
                found = re.search(r"([A-Za-z_]\w*)\s*$", head[:i])
                return found.group(1) if found and found.group(1) not in KEYWORDS else None
    return None


def _object_names(blank: str) -> list[str]:
    """Names an object declaration declares (one per comma-separated declarator)."""
    names = []
    flat = _outside(blank.rstrip().rstrip(";"))
    position = 0
    for part in flat.split(","):
        whole = blank[position:position + len(part)]
        position += len(part) + 1
        pointer = POINTER_NAME.search(whole)
        if pointer:
            names.append(pointer.group(1))
            continue
        plain = re.sub(r"\[[^\]]*\]", " ", part)
        found = [name for name in IDENT.findall(plain) if name not in KEYWORDS]
        if found:
            names.append(found[-1])
    return names


def _strip_initialisers(text: str) -> str:
    """``text`` (an object declaration) without ``= ...`` after its declarators."""
    blank = blank_literals(text)
    out, i, n, braces, parens = [], 0, len(text), 0, 0
    while i < n:
        ch = blank[i]
        if ch == "=" and braces == 0 and parens == 0:
            j, b, p = i, 0, 0
            while j < n:                                     # to the comma or semicolon that ends it
                cj = blank[j]
                if cj in "{":
                    b += 1
                elif cj == "}":
                    b -= 1
                elif cj == "(":
                    p += 1
                elif cj == ")":
                    p -= 1
                elif cj in ",;" and b == 0 and p == 0:
                    break
                j += 1
            i = j
            continue
        if ch == "{":
            braces += 1
        elif ch == "}":
            braces -= 1
        elif ch == "(":
            parens += 1
        elif ch == ")":
            parens -= 1
        out.append(text[i])
        i += 1
    return "".join(out)


def _without(word: str, text: str) -> str:
    return re.sub(rf"\b{word}\b\s*", "", text)


def chunks(text: str) -> list[Chunk]:
    """The file-level declarations and definitions of preprocessed C, in order."""
    blank = blank_literals(text)
    out: list[Chunk] = []
    i, n, start, braces, parens = 0, len(text), None, 0, 0

    def close(end: int, kind: str | None = None, **more) -> None:
        nonlocal start
        piece, piece_blank = text[start:end], blank[start:end]
        start = None
        if not piece.strip():
            return
        chunk = Chunk(piece.strip(), kind or "other", **more)
        chunk.uses = frozenset(name for name in IDENT.findall(piece_blank) if name not in KEYWORDS)
        if kind is None:
            chunk.kind, chunk.declares, chunk.local = _classify(piece.strip(), piece_blank.strip())
        elif kind == "function":
            chunk.declares = frozenset([chunk.name] if chunk.name else [])
            head = blank_literals(chunk.head)
            chunk.head_uses = frozenset(name for name in IDENT.findall(head) if name not in KEYWORDS)
            chunk.inline = bool(re.search(r"\b(?:inline|__inline__|__inline)\b", head))
            if re.search(r"\bstatic\b", head) and chunk.name and not chunk.inline:
                chunk.local = (chunk.name,)
        out.append(chunk)

    while i < n:
        ch = blank[i]
        if start is None:
            if ch.isspace():
                i += 1
                continue
            start = i
            if ch == "#":                                    # a directive the preprocessor left
                end = text.find("\n", i)
                end = n if end < 0 else end
                close(end, "directive")
                i = end
                continue
        if ch == "(":
            parens += 1
        elif ch == ")":
            parens -= 1
        elif ch == "{" and braces == 0 and parens == 0:
            before = blank[start:i].rstrip()
            trimmed = before
            while True:
                shorter = ATTRIBUTE.sub("", trimmed)
                if shorter == trimmed:
                    break
                trimmed = shorter.rstrip()
            end = _match(blank, i, "{", "}")
            if trimmed.endswith(")") and end >= 0:           # a function body
                close(end + 1, "function", name=_function_name(blank[start:i]), head=text[start:i].strip())
                i = end + 1
                continue
            braces += 1
        elif ch == "{":
            braces += 1
        elif ch == "}":
            braces -= 1
        elif ch == ";" and braces == 0 and parens == 0:
            close(i + 1)
            i += 1
            continue
        i += 1
    if start is not None:
        close(n)
    return out


TAG_BODY = re.compile(r"\b(struct|union|enum)\b\s*([A-Za-z_]\w*)?\s*\{")
TAG_NAME = re.compile(r"\b(?:struct|union|enum)\b\s*([A-Za-z_]\w*)")


def _tags_and_constants(blank: str) -> set[str]:
    """Tags a chunk gives a body to, and the constants of the enumerations it defines."""
    names: set[str] = set()
    for found in TAG_BODY.finditer(blank):
        if found.group(2):
            names.add(found.group(2))
        if found.group(1) == "enum":
            end = _match(blank, found.end() - 1, "{", "}")
            names.update(name for name in IDENT.findall(blank[found.end():end if end >= 0 else len(blank)])
                         if name not in KEYWORDS)
    return names


def _classify(text: str, blank: str) -> tuple[str, frozenset, tuple]:
    """Kind, declared names and unit-local names of a chunk that is not a function."""
    if ASM_START.match(blank):
        return "asm", frozenset(), ()
    if not blank.endswith(";"):
        return "other", frozenset(name for name in IDENT.findall(blank) if name not in KEYWORDS), ()
    flat = _outside(blank)
    names = _tags_and_constants(blank)
    without_bodies = re.sub(r"\s+", " ", _braces_removed(blank)).strip()
    if TAG_ONLY.fullmatch(without_bodies):                   # a tag alone: defined or announced
        names.update(TAG_NAME.findall(without_bodies))
        return "other", frozenset(names), ()
    has_initialiser = "=" in flat
    declarators = _strip_initialisers(text) if has_initialiser else text
    declarators_blank = blank_literals(declarators)
    prototype = ("(" in _braces_removed(declarators_blank).replace("__attribute__", "")
                 and not POINTER_NAME.search(_braces_removed(declarators_blank)))
    is_static = bool(re.search(r"\bstatic\b", flat))
    first = IDENT.match(blank)
    word = first.group() if first else ""
    if prototype and not has_initialiser:
        name = _function_name(declarators_blank.rstrip().rstrip(";"))
        if name:
            names.add(name)
        inline = bool(re.search(r"\b(?:inline|__inline__|__inline)\b", flat))
        return "other", frozenset(names), ((name,) if name and is_static and not inline else ())
    declared_here = _object_names(declarators_blank)
    names.update(declared_here)
    if word in ("typedef", "extern"):
        return "other", frozenset(names), ()
    return "object", frozenset(names), (tuple(declared_here) if is_static else ())


def _brace_spans(blank: str) -> list[tuple[int, int]]:
    out, i = [], 0
    while (i := blank.find("{", i)) >= 0:
        end = _match(blank, i, "{", "}")
        if end < 0:
            break
        out.append((i + 1, end))
        i = end + 1
    return out


def _braces_removed(blank: str) -> str:
    out, last = [], 0
    for start, end in _brace_spans(blank):
        out.append(blank[last:start - 1])
        last = end + 1
    out.append(blank[last:])
    return "".join(out)


def externalised(text: str) -> str:
    """An object definition as a declaration of something defined elsewhere."""
    text = _strip_initialisers(text)
    blank = blank_literals(text)
    flat = _outside(blank)
    found = re.search(r"\bstatic\b\s*", flat)
    if found:
        text = text[:found.start()] + text[found.end():]
    return text if re.match(r"\s*extern\b", text) else "extern " + text.lstrip()


def declared(head: str) -> str:
    """A function's head as a declaration: not local to the unit any more, not a definition."""
    blank = blank_literals(head)
    found = re.search(r"\bstatic\b\s*", _outside(blank))
    if found:
        head = head[:found.start()] + head[found.end():]
    return head.rstrip() + ";"


def rename(text: str, names: dict[str, str]) -> str:
    """``text`` with identifiers replaced as ``names`` says, outside literals."""
    if not names:
        return text
    out, last = [], 0
    for start, end in [*literal_spans(text), (len(text), len(text))]:
        out.append(IDENT.sub(lambda found: names.get(found.group(), found.group()), text[last:start]))
        out.append(text[start:end])
        last = end
    return "".join(out)


def unit_suffix(unit: str) -> str:
    return "__" + hashlib.sha1(unit.encode()).hexdigest()[:6]


def split(text: str, unit: str) -> dict[str, str]:
    """``{function label: source}`` for the functions ``text`` (a preprocessed unit) defines.

    A label is the function's name, with the unit's suffix when the function was local to the
    unit.  Functions written ``inline`` are helpers of the others, not units of their own."""
    parts = chunks(text)
    suffix = unit_suffix(unit)
    local = {name: name + suffix for part in parts for name in part.local}
    by_name: dict[str, list[int]] = {}
    for number, part in enumerate(parts):
        for name in part.declares:
            by_name.setdefault(name, []).append(number)
    out: dict[str, str] = {}
    for number, part in enumerate(parts):
        if part.kind != "function" or not part.name or part.inline:
            continue
        wanted, todo = {number}, list(part.uses)
        seen = set(todo)
        while todo:
            for other in by_name.get(todo.pop(), ()):
                if other not in wanted:
                    wanted.add(other)
                    # of another function only the declaration is kept: what its body uses is not needed
                    follows = parts[other]
                    for name in (follows.head_uses if follows.kind == "function" and not follows.inline
                                 else follows.uses):
                        if name not in seen:
                            seen.add(name)
                            todo.append(name)
        pieces = []
        for index in sorted(wanted | {k for k, p in enumerate(parts) if p.kind == "directive"}):
            piece = parts[index]
            if piece.kind == "asm":
                continue
            if piece.kind == "function" and index != number and not piece.inline:
                pieces.append(declared(piece.head))
            elif piece.kind == "function" and index == number:
                pieces.append(declared(piece.head)[:-1] + "\n" + piece.text[len(piece.head):].lstrip())
            elif piece.kind == "object":
                pieces.append(externalised(piece.text))
            elif piece.kind == "other" and piece.local:
                pieces.append(declared(piece.text.rstrip().rstrip(";")))
            else:
                pieces.append(piece.text)
        out[local.get(part.name, part.name)] = rename("\n".join(pieces) + "\n", local)
    return out
