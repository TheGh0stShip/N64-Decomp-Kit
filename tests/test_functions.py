import struct
import tempfile
import unittest
from pathlib import Path

from n64dk import fixtures
from n64dk.analysis import functions as fn
from n64dk.rom import Rom

ZERO, AT, V0, V1, A0, T0, SP, RA = 0, 1, 2, 3, 4, 8, 29, 31
BASE = 0x80000400


def R(rs, rt, rd, sa, funct):
    return (rs << 21) | (rt << 16) | (rd << 11) | (sa << 6) | funct


def I(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def jal(target):
    return (3 << 26) | ((target >> 2) & 0x3FFFFFF)


def addiu(rt, rs, imm):
    return I(9, rs, rt, imm)


def lui(rt, imm):
    return I(0x0F, 0, rt, imm)


def lw(rt, off, base):
    return I(0x23, base, rt, off)


def sw(rt, off, base):
    return I(0x2B, base, rt, off)


def jr(rs):
    return R(rs, 0, 0, 0, 8)


NOP = 0


def program() -> dict[int, list[int]]:
    """Entry calls F1 (switch through a jump table) and F3 (hoisted load before its prologue);
    F2 is unreferenced and preceded by two garbage words."""
    return {
        0x400: [jal(0x80000420), NOP, jal(0x80000480), NOP, jr(RA), NOP],
        0x420: [I(0x0B, A0, AT, 3),           # sltiu at, a0, 3
                I(4, AT, ZERO, 10),           # beqz at, 0x450
                R(0, A0, T0, 2, 0),           # sll t0, a0, 2
                lui(V0, 0x8000),
                R(V0, T0, V0, 0, 0x21),       # addu v0, v0, t0
                lw(V0, 0x0500, V0),           # lw v0, %lo(table)(v0)
                jr(V0), NOP,
                jr(RA), addiu(V0, ZERO, 1),
                jr(RA), addiu(V0, ZERO, 2),
                jr(RA), R(ZERO, ZERO, V0, 0, 0x21)],
        0x458: [0x02530000, 0xAEA18B2F],      # stray words before an aligned function
        0x460: [addiu(SP, SP, -0x18), sw(RA, 0x14, SP), lw(RA, 0x14, SP), jr(RA), addiu(SP, SP, 0x18)],
        0x480: [lui(V1, 0x8000), lw(A0, 0x0600, V1),
                addiu(SP, SP, -0x18), sw(RA, 0x14, SP), jal(0x80000460), NOP,
                lw(RA, 0x14, SP), jr(RA), addiu(SP, SP, 0x18)],
        0x500: [0x80000440, 0x80000448, 0x80000450],
        0x600: [0x12345678],
    }


def synthetic_rom() -> Rom:
    data = bytearray(0x101000)
    struct.pack_into(">I", data, 0, 0x80371240)
    struct.pack_into(">I", data, 8, BASE)
    for off, words in program().items():
        for i, w in enumerate(words):
            struct.pack_into(">I", data, 0x1000 + off - 0x400 + 4 * i, w)
    return Rom(bytes(data))


class SyntheticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cat = fn.discover(synthetic_rom())

    def test_boundaries_and_text_end(self):
        got = [(f.start, f.body_end) for f in self.cat.functions]
        self.assertEqual(got, [(0x80000400, 0x80000418), (0x80000420, 0x80000458),
                               (0x80000460, 0x80000474), (0x80000480, 0x800004A4)])
        self.assertEqual(self.cat.text_end, 0x800004A4)
        self.assertEqual(self.cat.functions[0].size, 0x20)  # trailing zero padding included

    def test_jump_table(self):
        [t] = self.cat.jump_tables
        self.assertEqual((t.address, t.count, t.function, t.bounded), (0x80000500, 3, 0x80000420, True))

    def test_seeds_kinds_and_stray_words(self):
        by = {f.start: f for f in self.cat.functions}
        self.assertEqual(by[0x80000460].seed, "call")
        self.assertEqual(by[0x80000420].kind, "leaf")
        self.assertEqual(by[0x80000460].kind, "c")
        kinds = {(f.address, f.kind) for f in self.cat.findings}
        self.assertIn((0x80000458, "stray_words"), kinds)

    def test_audit_late_start_and_overlap(self):
        entries = [(0x80000420, 0x38), (0x80000430, 0x10), (0x80000480, 0x4), (0x80000484, 0x20)]
        found = {(f.function, f.kind) for f in fn.audit(self.cat.image, entries, self.cat)}
        self.assertIn((0x80000430, "overlap"), found)
        self.assertIn((0x80000484, "late_start"), found)

    def test_outputs(self):
        toml = fn.to_toml(self.cat)
        self.assertIn('{ name = "func_80000420", vram = 0x80000420, size = 0x38 }', toml)
        syms = fn.to_symbol_addrs(self.cat)
        self.assertIn("jtbl_80000500 = 0x80000500; // type:jtbl size:0xC", syms)
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as f:
            f.write(toml)
        try:
            loaded = fn.load_catalogue(f.name)
        finally:
            Path(f.name).unlink()
        self.assertEqual([(v, s) for _, v, s in loaded], [(x.start, x.size) for x in self.cat.functions])
        score = fn.compare(self.cat, loaded)
        self.assertEqual((score["precision"], score["recall"], score["exact_size_rate"]), (1.0, 1.0, 1.0))


class FixtureTests(unittest.TestCase):
    """Measured against project catalogues; thresholds sit a little under the documented results."""

    def _run(self, name, truth_rel, text, precision, recall, body):
        rom = fixtures.rom(name)
        root = fixtures.truth(name)
        if rom is None or root is None or not (root / truth_rel).is_file():
            self.skipTest(f"{name} fixture or ground truth not configured")
        cat = fn.discover(rom)
        self.assertEqual((cat.text_start, cat.text_end), text)
        truth = fn.load_catalogue(root / truth_rel)
        score = fn.compare(cat, truth)
        self.assertGreaterEqual(score["precision"], precision)
        self.assertGreaterEqual(score["recall"], recall)
        self.assertGreaterEqual(score["body_size_rate"], body)
        for t in cat.jump_tables:
            f = cat.function_at(t.site)
            self.assertTrue(all(f.start <= x < f.body_end for x in t.targets), hex(t.address))
        return cat, truth, score

    def test_battletanx(self):
        cat, truth, score = self._run("battletanx", "config/us/recomp_function_boundaries.toml",
                                      (0x80071000, 0x80125550), 0.97, 0.97, 0.99)
        # Every reference start we do not reproduce is flagged by the boundary audit.
        flagged = {f.function for f in fn.audit(cat.image, [(v, s) for _, v, s in truth], cat)}
        self.assertLessEqual(set(score["missed"]), flagged)

    def test_battletanx_ga(self):
        self._run("battletanx_ga", "config/us/symbol_addrs.txt", (0x80071000, 0x8011449C), 0.985, 0.99, 0.985)

    def test_mk64_counts(self):
        rom = fixtures.rom("mk64")
        if rom is None:
            self.skipTest("mk64 fixture not configured")
        cat = fn.discover(rom)
        self.assertEqual(cat.text_start, 0x80000400)
        self.assertGreater(cat.text_end, 0x800D0000)
        self.assertGreater(len(cat.functions), 2500)


if __name__ == "__main__":
    unittest.main()
