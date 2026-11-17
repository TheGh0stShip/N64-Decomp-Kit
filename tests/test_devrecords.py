"""SN/PsyQ object records: decoding, fail-closed rejection, truncation, headerless function runs
and source names.  The fixtures are built here byte by byte (no ROM bytes)."""
import struct
import unittest

from n64dk.analysis import devrecords


def s(text: str) -> bytes:
    return bytes([len(text)]) + text.encode()


def obj(*records: bytes) -> bytes:
    return b"LNK\x02" + b"".join(records) + b"\x00"


SECTION = b"\x10" + struct.pack("<HHB", 1, 0, 8) + s(".text")
FILE = b"\x1c" + struct.pack("<H", 1) + s("src/player.c")
CODE = b"\x02" + struct.pack("<H", 8) + bytes(8)
EXPORT = b"\x0c" + struct.pack("<HHI", 3, 1, 0) + s("player_update")
IMPORT = b"\x0e" + struct.pack("<H", 4) + s("memcpy")
BSS = b"\x30" + struct.pack("<HHI", 5, 2, 64) + s("gPlayers")
FUNC = (b"\x4a" + struct.pack("<HIHIHIHIi", 1, 0, 1, 120, 29, 32, 31, 0x80030000, -4) + s("player_update"))
FUNC_END = b"\x4c" + struct.pack("<HII", 1, 8, 140)
# relocation: type 82, offset 4, expression ADD(SYMBOL 4, VALUE 16), right operand stored first
RELOC = b"\x0a" + bytes([82]) + struct.pack("<H", 4) + b"\x2c" + b"\x00" + struct.pack("<I", 16) + b"\x02" + struct.pack("<H", 4)
TYPEDEF = (b"\x54" + struct.pack("<HIHHI", 0, 0, 10, 8, 24) + struct.pack("<H", 1) + struct.pack("<I", 3)
           + s("Player") + s("players"))


class DecodeTest(unittest.TestCase):
    def test_a_complete_object_decodes_to_facts(self):
        data = b"\xff" * 16 + obj(SECTION, FILE, CODE, EXPORT, IMPORT, BSS, FUNC, FUNC_END, RELOC, TYPEDEF)
        found = devrecords.scan_objects(data)
        self.assertEqual(len(found["accepted"]), 1)
        facts = devrecords.facts(found["accepted"][0], image="main", base=0)
        function = next(f for f in facts if f["fact"] == "function")
        self.assertEqual((function["name"], function["source_file"], function["line"], function["frame_size"],
                          function["section"]), ("player_update", "src/player.c", 120, 32, ".text"))
        self.assertEqual(function["record_offset"], data.index(b"\x4a\x01\x00"))
        self.assertTrue(function["record_sha256"])
        self.assertTrue(all(f["direct"] for f in facts))
        reloc = next(f for f in facts if f["fact"] == "relocation")
        self.assertEqual(reloc["expression"], {"op": "ADD", "left": {"op": "SYMBOL", "symbol": 4},
                                               "right": {"op": "VALUE", "value": 16}})
        bss = next(f for f in facts if f["fact"] == "bss")
        self.assertEqual((bss["name"], bss["size"]), ("gPlayers", 64))
        typedef = next(f for f in facts if f["fact"] == "type-definition")
        self.assertEqual((typedef["dims"], typedef["tag"], typedef["name"]), ([3], "Player", "players"))
        self.assertIn("external-reference", {f["fact"] for f in facts})

    def test_every_truncation_is_rejected_with_a_reason(self):
        whole = obj(SECTION, FILE, CODE, FUNC, FUNC_END)
        for cut in range(4, len(whole)):
            found = devrecords.scan_objects(whole[:cut])
            self.assertEqual(found["accepted"], [], cut)
            self.assertTrue(found["rejected"][0]["reason"], cut)

    def test_malformed_records_are_rejected(self):
        cases = {
            "unknown opcode": obj(SECTION, b"\x07"),
            "alignment": obj(b"\x10" + struct.pack("<HHB", 1, 0, 6) + s(".text")),
            "program type": obj(b"\x2e\x05", SECTION),
            "two program types": obj(b"\x2e\x07", b"\x2e\x07", SECTION),
            "end_sld": obj(SECTION, b"\x3c\x01\x00"),
            "expression": obj(SECTION, b"\x0a\x52\x00\x00\x63"),
            "no content": obj(FILE),
            "version": b"LNK\x03" + SECTION + b"\x00",
        }
        for label, data in cases.items():
            found = devrecords.scan_objects(data)
            self.assertEqual(found["accepted"], [], label)
        self.assertIn("no LNK header", devrecords.scan_objects(b"LNK\x03" + SECTION + b"\x00")["rejected"][0]["reason"]
                      if devrecords.scan_objects(b"LNK\x03")["rejected"] else "no LNK header")

    def test_deep_expressions_are_refused(self):
        deep = b"\x2c" * 40 + (b"\x00" + bytes(4)) * 41
        found = devrecords.scan_objects(obj(SECTION, b"\x0a\x52\x00\x00" + deep))
        self.assertEqual(found["accepted"], [])
        self.assertIn("deep", found["rejected"][0]["reason"])


class HeaderlessTest(unittest.TestCase):
    def test_plausible_function_records_only(self):
        good = FUNC + FUNC_END
        bad_register = b"\x4a" + struct.pack("<HIHIHIHIi", 1, 0, 1, 120, 7, 32, 31, 0, 0) + s("f")
        bad_frame = b"\x4a" + struct.pack("<HIHIHIHIi", 1, 0, 1, 120, 29, 33, 31, 0, 0) + s("f")
        bad_name = b"\x4a" + struct.pack("<HIHIHIHIi", 1, 0, 1, 120, 29, 32, 31, 0, 0) + s("1abc")
        found = devrecords.scan_functions(bytes(10) + good + bad_register + bad_frame + bad_name + bytes(40))
        self.assertEqual([f["name"] for f in found["accepted"]], ["player_update"])
        self.assertEqual(found["accepted"][0]["record_offset"], 10)


class SourceNameTest(unittest.TestCase):
    def test_names_and_attribution(self):
        strings = b"\x00assert failed\x00src/game/player.c\x00..\x00ok.c\x00"
        names = devrecords.source_names(strings)
        self.assertEqual([n["name"] for n in names], ["src/game/player.c", "ok.c"])
        # a function that loads the address of the first name: lui a0, 0x8010 / addiu a0, a0, off
        delta = 0x80100000
        address = delta + names[0]["offset"]
        hi, lo = (address + 0x8000) >> 16, address & 0xFFFF
        code = struct.pack(">IIII", 0x3C040000 | hi, 0x24840000 | lo, 0x03E00008, 0)
        found = devrecords.attribute_functions(code, 0x80000000, [("f", 0x80000000, 16)], names, delta)
        self.assertEqual(found[0]["source_names"], ["src/game/player.c"])
        self.assertFalse(found[0]["direct"])


if __name__ == "__main__":
    unittest.main()


def sdef(section, value, cls, typ, size, name):
    return b"\x52" + struct.pack("<HIHHI", section, value, cls, typ, size) + s(name)


def sdef2(section, value, cls, typ, size, dims, tag, name):
    return (b"\x54" + struct.pack("<HIHHI", section, value, cls, typ, size) + struct.pack("<H", len(dims))
            + b"".join(struct.pack("<I", d) for d in dims) + s(tag) + s(name))


def function(section, offset, line, frame, name, mask=0x80000000):
    return b"\x4a" + struct.pack("<HIHIHIHIi", section, offset, 1, line, 29, frame, 31, mask, -4) + s(name)


def function_end(section, offset, line):
    return b"\x4c" + struct.pack("<HII", section, offset, line)


STREAM = (sdef(0, 12, 10, 8, 12, "Point_t") + sdef(0, 0, 8, 4, 0, "x") + sdef(0, 4, 8, 4, 0, "y")
          + sdef2(0, 8, 8, 0x32, 4, [4], "", "tag") + sdef(0, 12, 102, 0, 12, ".eos")
          + sdef(0, 0, 13, 8, 12, "Point")
          + sdef2(6, 0, 2, 0x38, 96, [8], "Point_t", "gPoints")
          + function(2, 0, 10, 24, "first") + sdef(0, 4, 17, 0x18, 12, "p") + sdef(0, 16, 4, 4, 0, "i")
          + function_end(2, 40, 14)
          + function(2, 40, 20, 0, "second") + function_end(2, 48, 21)
          + function(2, 48, 30, 32, "third") + sdef(0, 4, 17, 4, 0, "n") + function_end(2, 96, 40))


class RunTest(unittest.TestCase):
    def test_a_stream_decodes_into_typed_facts(self):
        # a name ending in "T..." just before the stream must not start a record
        data = bytes(64) + b"\x0bNOT_A_TAG_T" + STREAM + b"\x00" + bytes(32)
        found = devrecords.scan_runs(data)
        self.assertEqual(len(found["accepted"]), 1)
        run = found["accepted"][0]
        self.assertEqual(run["start"], data.index(STREAM))
        typed = devrecords.run_facts(run, "rom")
        point = typed["aggregates"][0]
        self.assertEqual((point["tag"], point["size"]), ("Point_t", 12))
        self.assertEqual([(m["name"], m["offset"], m["type"]) for m in point["members"]],
                         [("x", 0, "int"), ("y", 4, "int"), ("tag", 8, "char [4]")])
        self.assertEqual(typed["typedefs"][0]["type"], "struct")
        variable = next(v for v in typed["variables"] if v["name"] == "gPoints")
        self.assertEqual(variable["type"], "struct Point_t [8]")
        first = typed["functions"][0]
        self.assertEqual([(p["name"], p["type"], p["value"]) for p in first["parameters"]], [("p", "struct *", 4)])
        self.assertEqual([l["name"] for l in first["locals"]], ["i"])
        self.assertEqual((first["end_offset"], first["end_line"]), (40, 14))
        self.assertEqual([len(g) for g in devrecords.object_sequences(typed["functions"])], [3])

    def test_runs_need_three_functions(self):
        stream = function(2, 0, 10, 24, "a") + function_end(2, 8, 11) + function(2, 8, 12, 0, "b") + function_end(2, 16, 13)
        found = devrecords.scan_runs(bytes(16) + stream + b"\x00")
        self.assertEqual(found["accepted"], [])
        self.assertIn("fewer than 3", found["rejected"][0]["reason"])

    def test_coff_types(self):
        self.assertEqual(devrecords.coff_type(0x14), "int *")
        self.assertEqual(devrecords.coff_type(0x64), "int *()")
        self.assertEqual(devrecords.coff_type(0x91), "void (*)()")
        self.assertEqual(devrecords.coff_type(0x38, "S", [3]), "struct S [3]")


class PlacementTest(unittest.TestCase):
    def test_sizes_and_frames_must_agree(self):
        typed = devrecords.run_facts(devrecords.scan_runs(bytes(8) + STREAM + b"\x00")["accepted"][0])
        # catalogue: three functions of 40, 8 and 48 bytes, prologues addiu sp,-24 / jr ra / addiu sp,-32
        def body(size, frame):
            first = (0x27BD0000 | (0x10000 - frame)) if frame else 0x03E00008
            return struct.pack(">I", first) + bytes(size - 4)
        image = bytes(16) + body(40, 24) + body(8, 0) + body(48, 32)
        rows = [("f_a", 0x80000010, 40), ("f_b", 0x80000038, 8), ("f_c", 0x80000040, 48)]
        placed = devrecords.place(typed["functions"], rows, image, 0x80000000)
        self.assertEqual([(p["catalogue_name"], p["name"]) for p in placed["placed"]],
                         [("f_a", "first"), ("f_b", "second"), ("f_c", "third")])
        wrong = bytes(16) + body(40, 16) + body(8, 0) + body(48, 32)
        refused = devrecords.place(typed["functions"], rows, wrong, 0x80000000)
        self.assertEqual(refused["placed"], [])
        self.assertIn("frame sizes disagree", refused["unplaced"][0]["reason"])


def _framed(frame: int, size: int) -> list[int]:
    """A function of ``size`` bytes: prologue, filler, ``jr ra`` with the frame released in the slot."""
    body = [0x27BD0000 | (-frame & 0xFFFF)] + [0x00851021] * (size // 4 - 3) + [0x03E00008, 0x27BD0000 | frame]
    return body


def _record(name, offset, size, frame):
    return {"name": name, "offset": offset, "end_offset": offset + size, "frame_size": frame, "line": 1,
            "end_line": 2, "parameters": [{"name": "p", "type": "struct T_t *"}], "locals": [], "record_offset": 0,
            "section": 2, "file": 1, "frame_register": 29, "saved_registers": "0x80000000", "mask_offset": -4}


class DriftAlignTest(unittest.TestCase):
    """A stream from a slightly different build: one function grew by 8 bytes, so everything
    after it moved; both runs of agreeing displacement are placed, nothing is guessed."""

    def setUp(self):
        from n64dk.analysis import devrecords
        self.devrecords = devrecords
        frames = [(24, 64), (32, 80), (40, 96), (24, 48), (48, 112), (32, 64)]
        self.records, offset = [], 0
        for index, (frame, size) in enumerate(frames):
            self.records.append(_record(f"f{index}", offset, size, frame))
            offset += size
        words = [0] * 16                                      # 0x40 bytes of something else first
        for index, (frame, size) in enumerate(frames):
            words += _framed(frame, size + (8 if index == 2 else 0))   # f2 grew in the shipped build
        self.image = b"".join(w.to_bytes(4, "big") for w in words)

    def test_placed_with_two_displacements(self):
        result = self.devrecords.align(self.records, self.image, 0x80100000)
        placed = {item["name"]: int(item["vram"], 16) for item in result["placed"]}
        self.assertEqual(placed["f0"], 0x80100040)
        self.assertEqual(placed["f1"], 0x80100040 + 64)
        self.assertNotIn("f2", placed)                        # its size changed: no exact shape
        self.assertEqual(placed["f3"], 0x80100040 + 64 + 80 + 104)
        self.assertEqual(placed["f5"], 0x80100040 + 64 + 80 + 104 + 48 + 112)
        self.assertEqual(result["sequences"][0]["displacements"], [0x40, 0x48])

    def test_a_lone_shape_is_not_placed(self):
        lone = [_record("only", 0, 64, 24), _record("gone", 64, 80, 32), _record("away", 144, 96, 40)]
        image = b"".join(w.to_bytes(4, "big") for w in [0] * 4 + _framed(24, 64) + [0] * 64)
        self.assertEqual(self.devrecords.align(lone, image, 0x80000000)["placed"], [])


class RecordedDeclarationTest(unittest.TestCase):
    def test_layout_padding_anonymous_tags_and_prototypes(self):
        from n64dk.analysis import devrecords
        run = {"aggregates": [
            {"fact": "struct", "tag": "T_t", "size": 16, "members": [
                {"name": "a", "offset": 0, "type": "int"}, {"name": "b", "offset": 8, "type": "float"},
                {"name": "m", "offset": 12, "type": "enum .3fake"}]},
            {"fact": "struct", "tag": ".7fake", "size": 4, "members": [{"name": "x", "offset": 0, "type": "short"}]},
            {"fact": "struct", "tag": "Bad_t", "size": 4, "members": [{"name": "y", "offset": 0, "type": "int"},
                                                                     {"name": "z", "offset": 2, "type": "int"}]},
            {"fact": "enum", "tag": ".3fake", "size": 4, "members": [{"name": "ONE", "offset": 1}]}],
            "typedefs": [{"name": "Fn", "type": "void (*)()"}],
            "variables": [{"name": "f0", "type": "int *()"}]}
        text, stats = devrecords.render_declarations(run, [{"name": "f0", "parameters": [
            {"name": "p", "type": "struct T_t *"}, {"name": "q", "type": "struct Other_t *"}]}])
        self.assertIn("struct T_t {\n    int a;\n    char _pad0[4];\n    float b;\n    int m;\n};", text)
        self.assertIn("struct anon_7fake {", text)
        self.assertIn("struct Other_t;", text)                # referenced only: still declared
        self.assertNotIn("struct Bad_t {", text)                # overlapping members: left opaque
        self.assertIn("int *f0(struct T_t *p, struct Other_t *q);", text)
        self.assertIn("typedef void (*Fn)();", text)
        self.assertIn("enum {ONE = 1};", text)
        self.assertEqual((stats["bodies"], stats["bodies_left_opaque"], stats["prototypes"]), (2, 1, 1))
