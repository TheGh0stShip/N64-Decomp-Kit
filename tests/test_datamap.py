import glob
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk import boot, fixtures
from n64dk.analysis import datamap as dm


def truth_root(name):
    return fixtures.truth(name)


def encode(members):
    """Re-encode generated members to big-endian bytes (round-trip check)."""
    out = bytearray()
    for ctype, _name, init, size, _ext in members:
        if ctype == "f32":
            out += struct.pack(">f", float(init.rstrip("f")))
        elif ctype == "f64":
            out += struct.pack(">d", float(init))
        elif ctype == "u32":
            out += struct.pack(">I", int(init, 16))
        elif ctype == "u16":
            out += struct.pack(">H", int(init, 16))
        elif ctype == "char":
            body = init[1:-1].encode("latin-1").decode("unicode_escape").encode("latin-1")
            out += body.ljust(size, b"\0")[:size]
        elif ctype == "u8":
            vals = [int(x, 16) for x in init.strip("{} ").split(",")] if init.startswith("{") else [int(init, 16)]
            out += bytes(vals)
        else:
            raise AssertionError(ctype)
    return bytes(out)



class SyntheticTests(unittest.TestCase):
    def setUp(self):
        self.b = boot.BootInfo(entry=0x80000400, main_rom=0, main_vram=0x80000000, copy_size=0x1000)

    def test_xref_access_types(self):
        code = struct.pack(
            ">9I",
            0x3C018000,  # lui at, 0x8000
            0xC4200100,  # lwc1 f0, 0x100(at)
            0x3C028000,  # lui v0, 0x8000
            0x24420110,  # addiu v0, v0, 0x110
            0xD4420008,  # ldc1 f2, 8(v0)  -> 0x80000118 via register
            0x3C038000,  # lui v1, 0x8000
            0x00641821,  # addu v1, v1, a0
            0x8C630120,  # lw v1, 0x120(v1) (indexed table)
            0x03E00008,  # jr ra
        ) + bytes(4)
        xs = dm.scan_xrefs(code, self.b, [(0x80000000, 0x80000028)], [0x80000000], 0x80000000, 0x80001000)
        got = {(x.address, x.access, x.kind, x.via) for x in xs}
        self.assertIn((0x80000100, "f32", "load", "hilo"), got)
        self.assertIn((0x80000110, "addr", "addr", "hilo"), got)
        self.assertIn((0x80000118, "f64", "load", "reg"), got)
        self.assertIn((0x80000120, "word", "load", "hilo"), got)

    def test_strings(self):
        self.assertEqual(dm.string_at(b"Hello\0\0\0", 0, 8), (6, "string"))
        self.assertEqual(dm.string_at("テスト".encode("shift_jis") + b"\0", 0, 7), (7, "sjis"))
        self.assertIsNone(dm.string_at(b"Hi\0", 0, 3))

    def test_members_round_trip(self):
        blob = (struct.pack(">f", 1.5) + bytes(4) + struct.pack(">d", 0.1) + b"text\0\0\0\0"
                + struct.pack(">I", 0x80000000) + b"\x01\x02\x03")
        data = blob
        ev = {0x80000000: "f32", 0x80000008: "f64"}
        ms = dm.members(data, self.b, 0x80000000, 0x80000000 + len(blob), ev, {0x80000000: "sym"})
        self.assertEqual([m[0] for m in ms][:3], ["f32", "u32", "f64"])
        self.assertIn(("void *", "ptr18", "sym", 4, "sym"), ms)
        plain = [m if m[0] != "void *" else ("u32", m[1], "0x80000000", 4, None) for m in ms]
        self.assertEqual(encode(plain), blob)

    def test_read_matched_and_symbols(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "rows.tsv")
            p.write_text("# ROM_START\tSIZE\tSOURCE\tSECTION\n0x10\t0x8\ta.c\t.rodata\n0x20\t0x0\tb.c\t.data\n"
                         "0x40\t0x10\tc.c\t-O2\n0x60\t0x4\td.c\t.rdata\n")
            rows = dm.read_matched(p)
            self.assertEqual([(r.rom, r.section) for r in rows], [(0x10, ".rodata"), (0x40, ".text"), (0x60, ".rodata")])
            s = Path(d, "syms.txt")
            s.write_text("foo = 0x80001234; // type:u32\n80002000 T bar\n{ name = \"baz\", vram = 0x80003000, size = 0x4 },\n")
            self.assertEqual(dm.read_symbols(s), {0x80001234: "foo", 0x80002000: "bar", 0x80003000: "baz"})


class FixtureTests(unittest.TestCase):
    def test_battletanx(self):
        rom = fixtures.rom("battletanx")
        if rom is None:
            self.skipTest("battletanx not configured")
        m = dm.analyse(rom)
        self.assertEqual(m.text[-1], (0x80076000, 0x80125550))
        self.assertEqual(m.section_of(0x80071100), ".rodata")
        self.assertEqual(m.section_of(0x80130000), ".data")
        root = truth_root("battletanx")
        if root is None or not (root / "config/us/matching_data_units.tsv").is_file():
            return
        cfg = root / "config/us"
        code = [r for f in glob.glob(str(cfg / "matching_*units.tsv")) if "data" not in f for r in dm.read_matched(f)]
        data = dm.read_matched(cfg / "matching_data_units.tsv")
        b = m.boot
        rows = [(b.rom_to_vram(r.rom), b.rom_to_vram(r.rom + r.size), r.source) for r in data]
        res = dm.ownership_agreement(m, rows, dm.code_ranges(m, code))
        self.assertGreaterEqual(res["any"] / res["evaluable"], 0.95)
        self.assertGreaterEqual(res["exact"] / res["evaluable"], 0.9)
        self.assertEqual(sum(m.section_of(b.rom_to_vram(r.rom)) == r.section for r in data), len(data))
        ledger, rejected = dm.build_ledger(m, rom.data, code + data)
        self.assertFalse(rejected)
        self.assertEqual(ledger[0].start, 0x1000)
        self.assertEqual(ledger[-1].end, 0xD7040)

    def test_other_fixtures(self):
        for name, text_start in (("battletanx_ga", 0x80077C40), ("mk64", None)):
            rom = fixtures.rom(name)
            if rom is None:
                continue
            m = dm.analyse(rom)
            if text_start:
                self.assertEqual(m.text[-1][0], text_start)
            ledger, _ = dm.build_ledger(m, rom.data)
            self.assertEqual(sum(i.size for i in ledger), m.image_end - m.image_start)
            self.assertGreater(len(m.jump_tables), 50)

    def test_units_round_trip(self):
        rom = fixtures.rom("battletanx_ga")
        if rom is None:
            self.skipTest("battletanx_ga not configured")
        m = dm.analyse(rom)
        ev = dm.type_evidence(m)
        starts = set(m.xrefs)
        for a, z, sec in m.sections:
            if sec == ".text":
                continue
            ms = dm.members(rom.data, m.boot, a, z, ev, None, starts)
            self.assertEqual(encode(ms), rom.data[m.boot.vram_to_rom(a):m.boot.vram_to_rom(z)], hex(a))


if __name__ == "__main__":
    unittest.main()
