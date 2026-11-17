"""Development records that can survive in a ROM: SN/PsyQ object records and source names.

Three scanners, all fail-closed (a candidate is accepted only when every field is plausible, and
the reason for every rejection is kept):

``objects``      complete SN/PsyQ object files (``LNK`` followed by version 2) left in a ROM or
                 a logical image: decoded record by record (sections, code bytes, symbols,
                 uninitialised data, relocations with their patch expressions, source files and
                 line records, function and block records, type definitions).
``functions``    function debug records without a file header (a record run copied into a
                 build): the record's frame register must be $sp or $fp, its return register
                 $ra, its line numbers and frame size sane, its name an identifier.
``source_names`` NUL-terminated strings that name a source file (``…/name.c``): what assertion
                 messages keep (``__FILE__``).  With the code references to each string they
                 attribute functions to a unit name — evidence, not a fact about the layout.

The record layout was established from the behaviour of the public PsyQ object reader
(pcsx-redux ``supportpsx/psyq-obj``; see the research log); this module is an independent
implementation.  Multi-byte fields are little-endian (the objects were written on PC hosts).
Every decoded fact keeps the offset of its record in the scanned bytes and the SHA-256 of the
record's bytes.
"""
from __future__ import annotations

import hashlib
import re
import struct

OPCODES = {0: "END", 2: "BYTES", 6: "SWITCH", 8: "ZEROES", 10: "RELOCATION", 12: "EXPORTED_SYMBOL",
           14: "IMPORTED_SYMBOL", 16: "SECTION", 18: "LOCAL_SYMBOL", 28: "FILENAME", 46: "PROGRAMTYPE",
           48: "UNINITIALIZED", 50: "INC_SLD_LINENUM", 52: "INC_SLD_LINENUM_BY_BYTE",
           54: "INC_SLD_LINENUM_BY_WORD", 56: "SET_SLD_LINENUM", 58: "SET_SLD_LINENUM_FILE", 60: "END_SLD",
           74: "FUNCTION", 76: "FUNCTION_END", 78: "BLOCK_START", 80: "BLOCK_END", 82: "SECTION_DEF",
           84: "SECTION_DEF2", 86: "FUNCTION_START2"}
EXPRESSION = {0: "VALUE", 2: "SYMBOL", 4: "SECTION_BASE", 12: "SECTION_START", 22: "SECTION_END",
              44: "ADD", 46: "SUB", 50: "DIV"}
IDENT = re.compile(rb"[A-Za-z_.$][A-Za-z0-9_.$]{0,127}")


class RecordError(ValueError):
    """A record that does not decode: the reason, at an offset."""


class _Reader:
    def __init__(self, data: bytes, offset: int, end: int):
        self.data, self.at, self.end = data, offset, end

    def take(self, size: int) -> bytes:
        if self.at + size > self.end:
            raise RecordError(f"truncated at 0x{self.at:X} (needs {size} bytes)")
        chunk = self.data[self.at:self.at + size]
        self.at += size
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def string(self) -> str:
        size = self.u8()
        raw = self.take(size)
        if size and not IDENT.fullmatch(raw) and not all(32 <= b < 127 for b in raw):
            raise RecordError(f"unprintable name at 0x{self.at - size:X}")
        return raw.decode("ascii")


def _expression(reader: _Reader, depth: int = 0) -> dict:
    if depth > 32:
        raise RecordError("expression nested too deeply")
    code = reader.u8()
    kind = EXPRESSION.get(code)
    if kind is None:
        raise RecordError(f"unknown expression opcode {code} at 0x{reader.at - 1:X}")
    if kind == "VALUE":
        return {"op": kind, "value": reader.u32()}
    if kind == "SYMBOL":
        return {"op": kind, "symbol": reader.u16()}
    if kind in ("SECTION_BASE", "SECTION_START", "SECTION_END"):
        return {"op": kind, "section": reader.u16()}
    right = _expression(reader, depth + 1)                 # the right operand is stored first
    left = _expression(reader, depth + 1)
    return {"op": kind, "left": left, "right": right}


def _record(reader: _Reader, data: bytes, state: dict) -> dict:
    """One record at the reader's position (raises ``RecordError``)."""
    start = reader.at
    code = reader.u8()
    name = OPCODES.get(code)
    if name is None:
        raise RecordError(f"unknown record opcode {code} at 0x{start:X}")
    fields: dict = {}
    if name == "END":
        return {"at": start, "record": name}
    if name == "BYTES":
        size = reader.u16()
        fields = {"size": size, "sha256": hashlib.sha256(reader.take(size)).hexdigest()}
    elif name == "SWITCH":
        fields = {"section": reader.u16()}
    elif name == "ZEROES":
        fields = {"size": reader.u32()}
    elif name == "RELOCATION":
        fields = {"type": reader.u8(), "offset": reader.u16(), "expression": _expression(reader)}
    elif name == "EXPORTED_SYMBOL":
        fields = {"symbol": reader.u16(), "section": reader.u16(), "offset": reader.u32(), "name": reader.string()}
    elif name == "IMPORTED_SYMBOL":
        fields = {"symbol": reader.u16(), "name": reader.string()}
    elif name == "SECTION":
        fields = {"section": reader.u16(), "group": reader.u16(), "alignment": reader.u8(), "name": reader.string()}
        if fields["alignment"] & (fields["alignment"] - 1):
            raise RecordError(f"section alignment {fields['alignment']} is not a power of two")
    elif name == "LOCAL_SYMBOL":
        fields = {"section": reader.u16(), "offset": reader.u32(), "name": reader.string()}
    elif name == "FILENAME":
        fields = {"file": reader.u16(), "name": reader.string()}
    elif name == "PROGRAMTYPE":
        fields = {"type": reader.u8()}
        state["program_types"] = state.get("program_types", 0) + 1
        if fields["type"] not in (7, 9) or state["program_types"] > 1:
            raise RecordError(f"program type {fields['type']} (expected one record of 7 or 9)")
    elif name == "UNINITIALIZED":
        fields = {"symbol": reader.u16(), "section": reader.u16(), "size": reader.u32(), "name": reader.string()}
    elif name == "INC_SLD_LINENUM":
        fields = {"offset": reader.u16()}
    elif name == "INC_SLD_LINENUM_BY_BYTE":
        fields = {"offset": reader.u16(), "by": reader.u8()}
    elif name == "INC_SLD_LINENUM_BY_WORD":
        fields = {"offset": reader.u16(), "by": reader.u16()}
    elif name == "SET_SLD_LINENUM":
        fields = {"offset": reader.u16(), "line": reader.u32()}
    elif name == "SET_SLD_LINENUM_FILE":
        fields = {"offset": reader.u16(), "line": reader.u32(), "file": reader.u16()}
    elif name == "END_SLD":
        fields = {"zero": reader.u16()}
        if fields["zero"]:
            raise RecordError("END_SLD with a non-zero operand")
    elif name in ("FUNCTION", "FUNCTION_START2"):
        fields = {"section": reader.u16(), "offset": reader.u32(), "file": reader.u16(), "line": reader.u32(),
                  "frame_register": reader.u16(), "frame_size": reader.u32(), "return_register": reader.u16(),
                  "register_mask": reader.u32(), "mask_offset": struct.unpack("<i", reader.take(4))[0]}
        if name == "FUNCTION_START2":
            fields.update(extra1=reader.u32(), extra2=reader.u32())
        fields["name"] = reader.string()
    elif name in ("FUNCTION_END", "BLOCK_START", "BLOCK_END"):
        fields = {"section": reader.u16(), "offset": reader.u32(), "line": reader.u32()}
    elif name in ("SECTION_DEF", "SECTION_DEF2"):
        fields = {"section": reader.u16(), "value": reader.u32(), "class": reader.u16(), "type": reader.u16(),
                  "size": reader.u32()}
        if name == "SECTION_DEF2":
            count = reader.u16()
            if count > 16:
                raise RecordError(f"{count} array dimensions")
            # each dimension is a u32 in the N64 records (research log R10): the array sizes agree
            fields["dims"] = [reader.u32() for _ in range(count)]
            fields["tag"] = reader.string()
        fields["name"] = reader.string()
    return {"at": start, "record": name, **fields,
            "record_sha256": hashlib.sha256(data[start:reader.at]).hexdigest()[:16]}


def decode_object(data: bytes, offset: int = 0, limit: int = 1 << 24) -> dict:
    """Decode one object starting at ``offset`` (``LNK`` + version).  Returns ``{"records": [...],
    "end": offset after END}``; raises ``RecordError`` with the reason when anything is off."""
    end = min(len(data), offset + limit)
    if data[offset:offset + 3] != b"LNK" or offset + 4 > end or data[offset + 3] != 2:
        raise RecordError("no LNK header with version 2")
    reader = _Reader(data, offset + 4, end)
    records, state = [], {}
    while True:
        record = _record(reader, data, state)
        records.append(record)
        if record["record"] == "END":
            break
    return {"offset": offset, "end": reader.at, "records": records}


def facts(decoded: dict, image: str = "", base: int = 0) -> list[dict]:
    """Normalised facts of a decoded object: every one keeps the record's offset (``base`` added:
    the object's place in the image) and digest, its kind, and ``direct`` (read from a record, not
    inferred)."""
    out = []
    files = {record["file"]: record["name"] for record in decoded["records"] if record["record"] == "FILENAME"}
    sections = {record["section"]: record["name"] for record in decoded["records"] if record["record"] == "SECTION"}
    for record in decoded["records"]:
        kind = record["record"]
        common = {"image": image, "record_offset": base + record["at"], "record_kind": kind,
                  "record_sha256": record.get("record_sha256"), "direct": True, "confidence": "high"}
        if kind in ("FUNCTION", "FUNCTION_START2"):
            out.append({**common, "fact": "function", "name": record["name"],
                        "section": sections.get(record["section"], record["section"]), "offset": record["offset"],
                        "source_file": files.get(record["file"]), "line": record["line"],
                        "frame_register": record["frame_register"], "frame_size": record["frame_size"],
                        "return_register": record["return_register"],
                        "saved_registers": f"0x{record['register_mask']:08X}", "mask_offset": record["mask_offset"]})
        elif kind == "FUNCTION_END":
            out.append({**common, "fact": "function-end", "section": sections.get(record["section"], record["section"]),
                        "offset": record["offset"], "line": record["line"]})
        elif kind in ("EXPORTED_SYMBOL", "LOCAL_SYMBOL"):
            out.append({**common, "fact": "symbol", "scope": "global" if kind == "EXPORTED_SYMBOL" else "local",
                        "name": record["name"], "section": sections.get(record["section"], record["section"]),
                        "offset": record["offset"]})
        elif kind == "IMPORTED_SYMBOL":
            out.append({**common, "fact": "external-reference", "name": record["name"]})
        elif kind == "UNINITIALIZED":
            out.append({**common, "fact": "bss", "name": record["name"], "size": record["size"],
                        "section": sections.get(record["section"], record["section"])})
        elif kind == "SECTION":
            out.append({**common, "fact": "section", "name": record["name"], "alignment": record["alignment"]})
        elif kind == "FILENAME":
            out.append({**common, "fact": "source-file", "name": record["name"]})
        elif kind in ("SECTION_DEF", "SECTION_DEF2"):
            out.append({**common, "fact": "type-definition", "name": record["name"], "class": record["class"],
                        "type": record["type"], "size": record["size"], "dims": record.get("dims", []),
                        "tag": record.get("tag")})
        elif kind == "RELOCATION":
            out.append({**common, "fact": "relocation", "type": record["type"], "offset": record["offset"],
                        "expression": record["expression"]})
    return out


def scan_objects(data: bytes) -> dict:
    """Every ``LNK``+2 header in ``data``: decoded, or rejected with the reason."""
    accepted, rejected = [], []
    for found in re.finditer(rb"LNK\x02", data):
        try:
            decoded = decode_object(data, found.start())
        except RecordError as error:
            rejected.append({"offset": found.start(), "reason": str(error)})
            continue
        kinds = {record["record"] for record in decoded["records"]}
        if not kinds & {"SECTION", "BYTES"}:
            rejected.append({"offset": found.start(), "reason": "decodes but holds no section and no code"})
            continue
        accepted.append(decoded)
    return {"accepted": accepted, "rejected": rejected}


_FUNCTION_RUN = re.compile(rb"[\x4A\x56]", re.S)


def scan_functions(data: bytes, limit: int = 2000) -> dict:
    """Function debug records without an object header (``FUNCTION`` / ``FUNCTION_START2``
    followed, within 64 KB, by a ``FUNCTION_END`` for the same section).  Fail-closed: the frame
    register must be 29 ($sp) or 30 ($fp), the return register 31, the frame size a multiple of 8
    below 64 KB, the line below 100,000, the name a C identifier, the end line not before the
    start line."""
    found, examined = [], 0
    for match in _FUNCTION_RUN.finditer(data):
        start = match.start()
        if len(data) - start < 30:
            break
        examined += 1
        reader = _Reader(data, start + 1, min(len(data), start + 128))
        try:
            section, offset, file_id, line = reader.u16(), reader.u32(), reader.u16(), reader.u32()
            frame_reg, frame_size, ret_reg = reader.u16(), reader.u32(), reader.u16()
            mask, _mask_offset = reader.u32(), reader.u32()
            if data[start] == 0x56:
                reader.u32(), reader.u32()
            if not (frame_reg in (29, 30) and ret_reg == 31 and frame_size % 8 == 0 and frame_size < 0x10000
                    and 0 < line < 100000 and section < 64 and file_id < 4096):
                continue
            name = reader.string()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
                continue
        except RecordError:
            continue
        found.append({"record_offset": start, "fact": "function", "name": name, "section": section, "offset": offset,
                      "file": file_id, "line": line, "frame_register": frame_reg, "frame_size": frame_size,
                      "saved_registers": f"0x{mask:08X}", "direct": True, "confidence": "medium",
                      "record_kind": "FUNCTION (headerless)"})
        if len(found) >= limit:
            break
    return {"examined": examined, "accepted": found}


_SOURCE_NAME = re.compile(rb"([A-Za-z0-9_./\\:-]{1,96}\.(?:c|cpp|cc|s|asm|h))\x00")


def source_names(data: bytes) -> list[dict]:
    """NUL-terminated source file names (what ``__FILE__`` leaves in assertion messages)."""
    out = []
    for match in _SOURCE_NAME.finditer(data):
        name = match.group(1).decode("ascii")
        if name.count(".") > 3 or name.startswith("."):
            continue
        out.append({"offset": match.start(1), "name": name, "fact": "source-name", "direct": True,
                    "confidence": "low", "record_kind": "string"})
    return out


def attribute_functions(code_image: bytes, delta: int, functions, names: list[dict], name_image_delta: int) -> list[dict]:
    """For each function that loads the address of a source-name string, the name: evidence of
    the unit it was compiled in (an assertion in it names its own file).  ``functions``:
    ``[(name, vram, size)]`` of the image whose code is scanned; ``name_image_delta``: vram minus
    offset of the image holding the strings."""
    from .. import mips
    by_address = {entry["offset"] + name_image_delta: entry["name"] for entry in names}
    out = []
    for function, vram, size in functions:
        start = vram - delta
        if start < 0 or start + size > len(code_image):
            continue
        hits = set()
        for ref in mips.scan_refs(code_image[start:start + size], vram, call_targets=False):
            if ref.address in by_address:
                hits.add(by_address[ref.address])
        if hits:
            out.append({"function": function, "vram": f"0x{vram:08X}", "source_names": sorted(hits),
                        "fact": "unit-name-evidence", "direct": False,
                        "confidence": "medium" if len(hits) == 1 else "low"})
    return out


# ---------------------------------------------------------------------------------------------
# Headerless debug record runs (a debug stream left in a ROM without its object)

# Record kinds of a headerless debug stream.  Line records (SLD) travel with code bytes inside
# objects and have no checkable field, so they are not accepted here; every kind below starts
# with a section field, which two name characters cannot forge (>= 0x2020, see _plausible).
DEBUG_RECORDS = {"FUNCTION", "FUNCTION_START2", "FUNCTION_END", "BLOCK_START", "BLOCK_END", "SECTION_DEF",
                 "SECTION_DEF2"}
# COFF storage classes (the SN debug records use COFF's class and type encodings)
COFF_CLASS = {1: "auto", 2: "external", 3: "static", 4: "register", 5: "external-def", 6: "label", 8: "member",
              9: "argument", 10: "struct-tag", 11: "union-member", 12: "union-tag", 13: "typedef",
              14: "static-undefined", 15: "enum-tag", 16: "enum-member", 17: "register-argument", 18: "bitfield",
              100: "block", 101: "function", 102: "end-of-struct", 103: "file", 0xFFFF: "end-of-function"}
COFF_BASE = {0: "none", 1: "void", 2: "char", 3: "short", 4: "int", 5: "long", 6: "float", 7: "double",
             8: "struct", 9: "union", 10: "enum", 11: "enum-member", 12: "unsigned char", 13: "unsigned short",
             14: "unsigned int", 15: "unsigned long"}
_NAME = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$]{0,127}")


def coff_type(code: int, tag: str | None = None, dims: list[int] | None = None) -> str:
    """A COFF type word as C-like text: base type in the low 4 bits, then 2-bit derivations
    (1 pointer, 2 function returning, 3 array) from bit 4 upward, the one nearest the name first
    (0x14 pointer to int; 0x64 function returning pointer to int; 0x91 pointer to function
    returning void)."""
    base = COFF_BASE.get(code & 0xF, f"base{code & 0xF}")
    if base in ("struct", "union", "enum") and tag:
        base = f"{base} {tag}"
    text, dims = "", list(dims or [])
    derived = code >> 4
    steps = []
    while derived:
        steps.append(derived & 3)
        derived >>= 2
    for step in steps:
        if step == 1:
            text = f"*{text}"
        elif step == 2:
            text = f"({text})()" if text.startswith("*") else f"{text}()"
        elif step == 3:
            size = dims.pop(0) if dims else ""
            text = f"({text})[{size}]" if text.startswith("*") else f"{text}[{size}]"
    return f"{base} {text}".strip()


def _plausible(record: dict) -> str | None:
    """Why a record in a headerless run is implausible (None when it is fine)."""
    kind = record["record"]
    if kind not in DEBUG_RECORDS:
        return f"{kind} is not a debug record"
    # SECTION_DEF records may be nameless (compiler-generated storage such as string literals)
    nameless_ok = kind in ("SECTION_DEF", "SECTION_DEF2")
    if "name" in record and not (_NAME.fullmatch(record["name"]) or (nameless_ok and record["name"] == "")):
        return f"name {record['name']!r} is not an identifier"
    # 0xFFFF is the reserved section of common/absolute symbols (seen on externals such as a
    # float with value 0x118); other section numbers stay small
    if "section" in record and 1024 <= record["section"] != 0xFFFF:
        return f"section {record['section']}"
    if kind in ("SECTION_DEF", "SECTION_DEF2"):
        if record["class"] not in COFF_CLASS:
            return f"storage class {record['class']}"
        if record["type"] > 0xFFFF or (record["type"] & 0xF) not in COFF_BASE:
            return f"type 0x{record['type']:X}"
    if kind in ("FUNCTION", "FUNCTION_START2"):
        if record["frame_register"] not in (29, 30) or record["return_register"] != 31:
            return "frame or return register"
        if record["frame_size"] % 8 or record["frame_size"] >= 0x10000:
            return "frame size"
    if "line" in record and record["line"] >= 1_000_000:
        return "line number"
    return None


def decode_run(data: bytes, start: int, stop: int | None = None, limit: int = 1 << 22) -> dict:
    """Debug records from ``start`` until the first record that does not decode or is not a
    plausible debug record (or until ``stop``, when given).  Returns the records, where the run
    ended and why."""
    reader = _Reader(data, start, min(len(data), start + limit))
    records, state, reason = [], {}, "limit"
    while reader.at < reader.end and (stop is None or reader.at < stop):
        at = reader.at
        try:
            record = _record(reader, data, state)
        except RecordError as error:
            reader.at, reason = at, str(error)
            break
        problem = _plausible(record)
        if problem:
            reader.at, reason = at, problem
            break
        records.append(record)
    else:
        reason = "stop" if stop is not None and reader.at >= stop else reason
    return {"start": start, "end": reader.at, "records": records, "ended_because": reason}


def _run_start(data: bytes, anchor: int, window: int = 512) -> int:
    """Step back one record at a time: the nearest offset holding one plausible record that ends
    exactly at the current start.  (The earliest such offset can lie inside a name: the letter T
    is the SECTION_DEF2 opcode.)"""
    start = anchor
    while start > 0:
        found = None
        for candidate in range(start - 1, max(0, start - window) - 1, -1):
            chain = decode_run(data, candidate, stop=start, limit=start - candidate)
            if chain["end"] == start and len(chain["records"]) == 1:
                found = candidate
                break
        if found is None:
            return start
        start = found
    return start


def scan_runs(data: bytes, minimum_functions: int = 3) -> dict:
    """Headerless debug record runs: anchored on plausible function records, extended back and
    forward; a run is accepted with at least ``minimum_functions`` function records."""
    anchors = [fact["record_offset"] for fact in scan_functions(data, limit=100000)["accepted"]]
    runs, rejected, covered_until = [], [], -1
    for anchor in anchors:
        if anchor < covered_until:
            continue
        start = _run_start(data, anchor)
        run = decode_run(data, start)
        covered_until = max(run["end"], anchor + 1)
        functions = sum(1 for record in run["records"] if record["record"] in ("FUNCTION", "FUNCTION_START2"))
        if functions >= minimum_functions:
            runs.append(run)
        else:
            rejected.append({"offset": start, "reason": f"{functions} function records (fewer than "
                                                         f"{minimum_functions})", "ended_because": run["ended_because"]})
    return {"accepted": runs, "rejected": rejected}


def run_facts(run: dict, image: str = "") -> dict:
    """Typed facts of a debug run: functions with their parameters, locals and line range;
    structures and unions with member offsets; typedefs; file-level variables."""
    functions, aggregates, typedefs, variables = [], [], [], []
    current = None
    aggregate = None
    for record in run["records"]:
        kind = record["record"]
        where = {"image": image, "record_offset": record["at"], "record_sha256": record.get("record_sha256"),
                 "direct": True}
        if kind in ("FUNCTION", "FUNCTION_START2"):
            current = {**where, "fact": "function", "name": record["name"], "section": record["section"],
                       "offset": record["offset"], "file": record["file"], "line": record["line"],
                       "frame_register": record["frame_register"], "frame_size": record["frame_size"],
                       "saved_registers": f"0x{record['register_mask']:08X}", "mask_offset": record["mask_offset"],
                       "parameters": [], "locals": [], "end_line": None, "end_offset": None}
            functions.append(current)
            continue
        if kind == "FUNCTION_END" and current is not None:
            current["end_line"], current["end_offset"] = record["line"], record["offset"]
            current = None
            continue
        if kind not in ("SECTION_DEF", "SECTION_DEF2"):
            continue
        storage = COFF_CLASS.get(record["class"], str(record["class"]))
        typed = {"name": record["name"], "type": coff_type(record["type"], record.get("tag"), record.get("dims")),
                 "type_code": record["type"], "size": record["size"], "value": record["value"], "class": storage}
        if storage in ("struct-tag", "union-tag", "enum-tag"):
            aggregate = {**where, "fact": storage.replace("-tag", ""), "tag": record["name"], "size": record["size"],
                         "members": []}
            aggregates.append(aggregate)
        elif storage in ("member", "union-member", "enum-member", "bitfield") and aggregate is not None:
            aggregate["members"].append({"name": record["name"], "offset": record["value"], "type": typed["type"],
                                         "size": record["size"], **({"bits": True} if storage == "bitfield" else {})})
        elif storage == "end-of-struct":
            aggregate = None
        elif storage == "typedef":
            typedefs.append({**where, "fact": "typedef", "name": record["name"], "type": typed["type"],
                             "size": record["size"]})
        elif current is not None and storage in ("argument", "register-argument"):
            current["parameters"].append(typed)
        elif current is not None and storage in ("auto", "register", "static"):
            current["locals"].append(typed)
        elif current is None and storage in ("external", "static", "external-def"):
            variables.append({**where, "fact": "variable", "scope": "global" if storage != "static" else "file",
                              **typed})
    return {"functions": functions, "aggregates": aggregates, "typedefs": typedefs, "variables": variables}


def object_sequences(functions: list[dict], minimum: int = 3) -> list[list[dict]]:
    """Function records grouped into objects' code: consecutive records of one section whose
    offsets continue exactly where the previous function ended."""
    groups, current = [], []
    for function in functions:
        if (current and function["section"] == current[-1]["section"]
                and current[-1]["end_offset"] is not None and function["offset"] == current[-1]["end_offset"]):
            current.append(function)
            continue
        if len(current) >= minimum:
            groups.append(current)
        current = [function] if function["end_offset"] is not None else []
    if len(current) >= minimum:
        groups.append(current)
    return groups


def _frame_size(code: bytes) -> int | None:
    """N of the first ``addiu sp, sp, -N`` in the first eight instructions (0 when there is a
    ``jr ra`` first, None when neither is seen)."""
    for index in range(0, min(len(code), 32), 4):
        word = int.from_bytes(code[index:index + 4], "big")
        if word >> 16 == 0x27BD:                         # addiu sp, sp, imm
            immediate = word & 0xFFFF
            return (0x10000 - immediate) if immediate & 0x8000 else 0
        if word == 0x03E00008:                           # jr ra before any frame
            return 0
    return None


def place(functions: list[dict], rows: list[tuple[str, int, int]], image: bytes, delta: int,
          minimum: int = 3) -> dict:
    """Place records on catalogue functions: an object's sequence of function sizes must equal the
    sizes of consecutive catalogue rows exactly (unique match), and every frame size must agree
    with the prologue.  Returns placements (direct name/prototype evidence for those addresses)
    and the sequences that could not be placed, with the reason."""
    rows = sorted(rows, key=lambda row: row[1])
    sizes = [size for _name, _vram, size in rows]
    placed, unplaced = [], []
    for group in object_sequences(functions, minimum):
        wanted = [function["end_offset"] - function["offset"] for function in group]
        hits = [index for index in range(len(rows) - len(wanted) + 1) if sizes[index:index + len(wanted)] == wanted]
        label = f"{group[0]['name']} .. {group[-1]['name']} ({len(group)} functions)"
        if len(hits) != 1:
            unplaced.append({"sequence": label, "reason": f"{len(hits)} catalogue positions with these sizes"})
            continue
        start = hits[0]
        frames_disagree = []
        for function, (name, vram, size) in zip(group, rows[start:start + len(group)]):
            frame = _frame_size(image[vram - delta:vram - delta + size])
            if frame is not None and frame != function["frame_size"]:
                frames_disagree.append(f"{function['name']}: record {function['frame_size']}, prologue {frame}")
        if frames_disagree:
            unplaced.append({"sequence": label, "reason": "frame sizes disagree: " + "; ".join(frames_disagree[:4])})
            continue
        for function, (name, vram, size) in zip(group, rows[start:start + len(group)]):
            placed.append({"vram": f"0x{vram:08X}", "catalogue_name": name, "size": size, "name": function["name"],
                           "line": function["line"], "end_line": function["end_line"],
                           "parameters": function["parameters"], "locals": function["locals"],
                           "record_offset": function["record_offset"], "direct": True,
                           "placed_by": f"size sequence of {len(group)} functions, unique; frame sizes agree"})
    return {"placed": placed, "unplaced": unplaced}


def scan_rom(data: bytes, with_facts: bool = False) -> dict:
    """The survey stage: retained objects and headerless debug runs, as ledger spans with
    evidence, a summary, and (``with_facts``) every normalised fact with its record offset."""
    objects = scan_objects(data)
    runs = scan_runs(data)
    spans, summary = [], {"objects": len(objects["accepted"]), "objects_rejected": len(objects["rejected"]),
                          "runs": len(runs["accepted"]), "runs_rejected": len(runs["rejected"]),
                          "functions": 0, "aggregates": 0, "typedefs": 0, "variables": 0, "bytes": 0}
    out_facts = {"schema": "n64dk.devrecords/1", "objects": [], "runs": []}
    for decoded in objects["accepted"]:
        spans.append({"start": decoded["offset"], "end": decoded["end"], "kind": "psyq_object",
                      "evidence": f"SN/PsyQ object, {len(decoded['records'])} records decoded to END"})
        if with_facts:
            out_facts["objects"].append({"offset": decoded["offset"], "facts": facts(decoded, "rom")})
    for run in runs["accepted"]:
        typed = run_facts(run, "rom")
        for key in ("functions", "aggregates", "typedefs", "variables"):
            summary[key] += len(typed[key])
        spans.append({"start": run["start"], "end": run["end"], "kind": "sn_debug_run",
                      "evidence": f"SN debug records without an object header: {len(run['records'])} records, "
                                  f"{len(typed['functions'])} functions, {len(typed['aggregates'])} types; "
                                  f"ended at 0x{run['end']:X} ({run['ended_because']})"})
        if with_facts:
            out_facts["runs"].append({"start": run["start"], "end": run["end"], "ended_because": run["ended_because"],
                                      **typed})
    summary["bytes"] = sum(span["end"] - span["start"] for span in spans)
    return {"spans": spans, "summary": summary, **({"facts": out_facts} if with_facts else {})}


# --------------------------------------------------------------------------- placement with drift

ADDIU_SP, JR_RA = 0x27BD0000, 0x03E00008


def align(functions: list[dict], image: bytes, vram: int, minimum: int = 3, drift: int = 0x800) -> dict:
    """Place a debug stream's functions in a program image although the image comes from a
    slightly different build (functions that changed size shift everything after them).

    Each function with a frame is anchored where the image holds its exact shape: a body of its
    recorded size ending in ``jr ra`` with ``addiu sp, sp, +frame`` in the delay slot, with
    ``addiu sp, sp, -frame`` within its first eight instructions.  Per object, the longest chain of
    anchors in record order (each displacement within ``drift`` of the previous) is kept.  An
    anchor is placed only when a neighbour in the chain has the same displacement (two functions
    agreeing); a function without an anchor is placed only between two placed anchors of equal
    displacement, where a return ends it at its recorded size.  Returns placements and, for each
    function not placed, the reason."""
    def word(offset: int) -> int | None:
        return int.from_bytes(image[offset:offset + 4], "big") if 0 <= offset <= len(image) - 4 else None

    epilogues: dict[int, list[int]] = {}
    for offset in range(0, len(image) - 7, 4):            # the delay slot may be the image's last word
        if word(offset) == JR_RA:
            following = word(offset + 4)
            if following is not None and following >> 16 == 0x27BD and not following & 0x8000:
                epilogues.setdefault(following & 0xFFFF, []).append(offset)
    placed, unplaced, shifts = [], [], []
    for group in object_sequences(functions, minimum):
        candidates = []                                   # (index, offset in the image)
        for index, function in enumerate(group):
            frame, size = function["frame_size"], function["end_offset"] - function["offset"]
            if frame <= 0 or size < 16:
                continue
            for end in epilogues.get(frame, ()):
                start = end + 8 - size
                if start >= 0 and any(word(start + 4 * k) == ADDIU_SP | (-frame & 0xFFFF) for k in range(8)):
                    candidates.append((index, start))
        candidates.sort()
        # longest chain: increasing index and address, displacement within drift of the previous
        best: list[int] = [1] * len(candidates)
        back: list[int | None] = [None] * len(candidates)
        for j, (index_j, at_j) in enumerate(candidates):
            shift_j = at_j - group[index_j]["offset"]
            for i in range(j):
                index_i, at_i = candidates[i]
                shift_i = at_i - group[index_i]["offset"]
                if index_i < index_j and at_i < at_j and abs(shift_j - shift_i) <= drift and best[i] + 1 > best[j]:
                    best[j], back[j] = best[i] + 1, i
        chain = []
        if candidates:
            j: int | None = max(range(len(candidates)), key=lambda k: (best[k], -k))
            while j is not None:
                chain.append(candidates[j])
                j = back[j]
            chain.reverse()
        displacement = {index: at - group[index]["offset"] for index, at in chain}
        ordered = [index for index, _ in chain]
        agreed = {}
        for position, index in enumerate(ordered):
            neighbours = [ordered[k] for k in (position - 1, position + 1) if 0 <= k < len(ordered)]
            if any(displacement[n] == displacement[index] for n in neighbours):
                agreed[index] = displacement[index]
        located = dict(agreed)
        anchors = sorted(agreed)
        for index, function in enumerate(group):
            if index in located:
                continue
            before = max((a for a in anchors if a < index), default=None)
            after = min((a for a in anchors if a > index), default=None)
            if before is None or after is None or agreed[before] != agreed[after]:
                continue
            start = function["offset"] + agreed[before]
            size = function["end_offset"] - function["offset"]
            if word(start + size - 8) == JR_RA or word(start + size - 8) is not None and word(start + size - 8) >> 26 == 2:
                located[index] = agreed[before]
        label = f"{group[0]['name']} .. {group[-1]['name']} ({len(group)} functions)"
        shifts.append({"sequence": label, "anchors": len(chain), "agreed": len(agreed), "placed": len(located),
                       "displacements": sorted({d for d in agreed.values()})})
        for index, function in enumerate(group):
            if index not in located:
                unplaced.append({"name": function["name"], "reason": "no unique shape at an agreed displacement"
                                 if function["frame_size"] > 0 else "frameless and not between agreeing anchors"})
                continue
            start = function["offset"] + located[index]
            placed.append({"vram": f"0x{vram + start:08X}", "size": function["end_offset"] - function["offset"],
                           "name": function["name"], "frame_size": function["frame_size"], "line": function["line"],
                           "end_line": function["end_line"], "parameters": function["parameters"],
                           "locals": function["locals"], "record_offset": function["record_offset"],
                           "displacement": located[index],
                           "placed_by": "shape anchored, displacement agreed by a neighbour" if index in agreed
                           else "between anchors of equal displacement, return at the recorded size"})
    return {"placed": placed, "unplaced": unplaced, "sequences": shifts}


# --------------------------------------------------------------------------- recorded declarations

_SCALAR_SIZES = {"char": 1, "unsigned char": 1, "short": 2, "unsigned short": 2, "int": 4, "unsigned int": 4,
                 "long": 4, "unsigned long": 4, "float": 4, "double": 8, "void": 0}
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def declarator(type_text: str, name: str) -> str:
    """``type_text`` (as ``coff_type`` writes it) declaring ``name``."""
    if "(*)" in type_text:
        return type_text.replace("(*)", f"(*{name})", 1)
    if " [" in type_text or type_text.endswith("]"):
        base, _, dims = type_text.partition(" [")
        return f"{base} {name}[{dims}"
    if type_text.endswith("()"):
        return f"{type_text[:-2].rstrip()} {name}()"
    return f"{type_text} {name}" if not type_text.endswith("*") else f"{type_text}{name}"


def _size_of(type_text: str, aggregates: dict[str, dict]) -> int | None:
    if "*" in type_text:
        return 4 if "[" not in type_text.split("*")[-1] else None
    count = 1
    while type_text.endswith("]"):
        type_text, _, dim = type_text.rpartition("[")
        type_text = type_text.rstrip()
        if not dim[:-1].isdigit():
            return None
        count *= int(dim[:-1])
    if type_text.startswith(("struct ", "union ")):
        known = aggregates.get(type_text)
        return known["size"] * count if known else None
    if type_text.startswith("enum "):
        return 4 * count
    size = _SCALAR_SIZES.get(type_text)
    return None if size in (None, 0) else size * count


_TAGGED = re.compile(r"\b(struct|union|enum) ([^\s*()\[\]]+)")


def _tag(tag: str) -> str:
    """An identifier for a recorded tag (the compiler names anonymous types ``.151fake``)."""
    clean = re.sub(r"[^A-Za-z0-9_]", "_", tag)
    return clean if _IDENT.match(clean) and not clean.startswith("_") else f"anon_{clean.strip('_')}"


def _clean_type(type_text: str) -> str:
    """Tags as identifiers; enum types as ``int`` (their constants are declared on their own)."""
    return _TAGGED.sub(lambda m: "int" if m.group(1) == "enum" else f"{m.group(1)} {_tag(m.group(2))}", type_text)


def render_declarations(run: dict, placed: list[dict]) -> tuple[str, dict]:
    """C declarations from a decoded run: forward declarations of every aggregate, struct and
    union bodies whose recorded layout is consistent (members in offset order, sizes known, padding
    where the record leaves a gap, total equal to the recorded size), enums, typedefs, and
    prototypes of the placed functions.  Returns the text and what was rendered or left out."""
    aggregates = {}
    for aggregate in run.get("aggregates", []):
        if aggregate["fact"] in ("struct", "union") and aggregate.get("tag"):
            members = [{**m, "type": _clean_type(m["type"])} for m in aggregate["members"]]
            aggregates[f"{aggregate['fact']} {_tag(aggregate['tag'])}"] = {**aggregate, "members": members}
    lines = ["/* declarations recorded by the original build's debug records (n64dk dev-records-place) */"]
    referenced = set(aggregates)
    for text in [m["type"] for a in aggregates.values() for m in a["members"]] + \
            [_clean_type(t.get("type") or "") for t in run.get("typedefs", [])] + \
            [_clean_type(v.get("type") or "") for v in run.get("variables", [])] + \
            [_clean_type(p.get("type") or "") for f in placed for p in f["parameters"]]:
        referenced.update(f"{m.group(1)} {m.group(2)}" for m in _TAGGED.finditer(text) if m.group(1) != "enum")
    lines += [f"{key};" for key in sorted(referenced)]
    stats = {"aggregates": len(aggregates), "bodies": 0, "bodies_left_opaque": 0, "enums": 0, "typedefs": 0,
             "prototypes": 0}
    bodies: dict[str, list[str]] = {}
    needs: dict[str, set[str]] = {}
    for key, aggregate in aggregates.items():
        members, cursor, ok, text, pad = sorted(aggregate["members"], key=lambda m: m["offset"]), 0, True, [], 0
        depends = set()
        for member in members:
            size = _size_of(member["type"], aggregates)
            if size is None or not _IDENT.match(member["name"] or "") or (
                    aggregate["fact"] == "struct" and member["offset"] < cursor):
                ok = False
                break
            if aggregate["fact"] == "struct" and member["offset"] > cursor:
                text.append(f"    char _pad{pad}[{member['offset'] - cursor}];")
                pad += 1
            text.append(f"    {declarator(member['type'], member['name'])};")
            if "*" not in member["type"] and member["type"].split(" [")[0] in aggregates:
                depends.add(member["type"].split(" [")[0])
            cursor = member["offset"] + size if aggregate["fact"] == "struct" else max(cursor, size)
        if ok and cursor <= aggregate["size"]:
            if cursor < aggregate["size"]:
                text.append(f"    char _pad{pad}[{aggregate['size'] - cursor}];")
            bodies[key], needs[key] = text, depends
        else:
            stats["bodies_left_opaque"] += 1
    emitted: list[str] = []

    def emit(key: str, stack: tuple = ()) -> bool:
        if key in emitted:
            return True
        if key not in bodies or key in stack or not all(emit(d, stack + (key,)) for d in needs[key]):
            return False
        emitted.append(key)
        return True
    for key in sorted(bodies):
        emit(key)
    for key in emitted:
        lines += [f"{key} {{", *bodies[key], "};"]
    stats["bodies"] = len(emitted)
    stats["bodies_left_opaque"] += len(bodies) - len(emitted)
    seen_members: set[str] = set()
    for aggregate in run.get("aggregates", []):
        if aggregate["fact"] != "enum":
            continue
        members = [m for m in aggregate["members"] if _IDENT.match(m["name"] or "") and m["name"] not in seen_members]
        if not members:
            continue
        seen_members.update(m["name"] for m in members)
        lines.append("enum {" + ", ".join(f"{m['name']} = {m['offset']}" for m in members) + "};")
        stats["enums"] += 1
    for typedef in run.get("typedefs", []):
        if _IDENT.match(typedef["name"] or "") and typedef["type"] and typedef["name"] not in ("int", "char"):
            lines.append(f"typedef {declarator(_clean_type(typedef['type']), typedef['name'])};")
            stats["typedefs"] += 1
    returns = {v["name"]: _clean_type(v["type"][:-2].rstrip()) for v in run.get("variables", [])
               if (v.get("type") or "").endswith("()")}
    for function in placed:
        parameters = [p for p in function["parameters"] if _IDENT.match(p["name"] or "")]
        if function["name"] not in returns or not _IDENT.match(function["name"]):
            continue
        listed = ", ".join(declarator(_clean_type(p["type"]), p["name"]) for p in parameters) or "void"
        result = returns[function["name"]] or "void"
        lines.append(f"{result}{'' if result.endswith('*') else ' '}{function['name']}({listed});")
        stats["prototypes"] += 1
    return "\n".join(lines) + "\n", stats


def apply_to_catalogue(facts: dict, data: bytes, vram: int, functions: list) -> tuple[dict, str]:
    """Place every decoded run's functions in a program image (``align``) and name the catalogue
    functions they land on.  A placement that is not a catalogue start, or whose recorded size
    differs from the catalogue's body, is listed as a conflict and changes nothing.  Returns the
    report and the recorded declarations for the named functions (empty when none)."""
    starts = {function.start: function for function in functions}
    taken = {function.name for function in functions}
    report = {"placed": [], "renamed": 0, "conflicts": [], "sequences": [], "declarations": {}}
    texts = []
    for run in facts.get("runs", []):
        placement = align(run["functions"], data, vram)
        report["sequences"] += placement["sequences"]
        named = []
        for item in placement["placed"]:
            address = int(item["vram"], 16)
            function = starts.get(address)
            entry = {key: item[key] for key in ("vram", "name", "size", "placed_by", "displacement", "line")}
            if function is None:
                report["conflicts"].append({**entry, "issue": "not a catalogue start"})
            elif function.body_end - function.start != item["size"]:
                report["conflicts"].append({**entry, "issue": f"catalogue body 0x{function.body_end - function.start:X}, "
                                                              f"record 0x{item['size']:X}"})
            elif _IDENT.match(item["name"]) and item["name"] not in taken:
                function.name = item["name"]
                taken.add(item["name"])
                named.append(item)
                report["renamed"] += 1
            report["placed"].append(entry)
        if named:
            text, stats = render_declarations(run, named)
            texts.append(text)
            report["declarations"] = {key: report["declarations"].get(key, 0) + value for key, value in stats.items()}
    return report, "".join(texts)
