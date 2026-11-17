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


def rom_of(words_at: dict[int, list[int]], entry: int = BASE) -> Rom:
    data = bytearray(0x101000)
    struct.pack_into(">I", data, 0, 0x80371240)
    struct.pack_into(">I", data, 8, entry)
    for off, words in words_at.items():
        for i, w in enumerate(words):
            struct.pack_into(">I", data, 0x1000 + off - 0x400 + 4 * i, w)
    return Rom(bytes(data))


class HandOverTest(unittest.TestCase):
    """An entry routine that hands over through a register to code that does not start right
    behind it: data lies between, and the hand-over is the only way in."""

    def rom(self) -> Rom:
        return rom_of({
            0x400: [lui(T0, 0x8000), addiu(T0, T0, 0x0500), jr(T0), NOP],
            0x410: [0x47414D45, 0x20444154, 0x41000000, 0x00010203] * 4,          # data, not code
            0x500: [addiu(SP, SP, -0x18), sw(RA, 0x14, SP), jal(0x80000540), NOP,
                    lw(RA, 0x14, SP), jr(RA), addiu(SP, SP, 0x18)],
            0x540: [jr(RA), addiu(V0, ZERO, 7)],
        })

    def test_the_program_behind_the_data_is_found(self):
        from n64dk import boot
        rom = self.rom()
        info = boot.analyse(rom)
        self.assertEqual(info.main_call, 0x80000500)
        starts = {f.start for f in fn.discover(rom).functions}
        self.assertLessEqual({0x80000400, 0x80000500, 0x80000540}, starts)


class JumpIntoDataTest(unittest.TestCase):
    """A jump whose target follows a return and does not decode as code (a jump into a table).
    The target is proposed as a start, dropped when its walk fails, and must not be proposed
    again on the next pass: the discovery once never returned on such a title."""

    def test_growth_ends_and_the_target_is_not_a_function(self):
        import signal
        target = 0x80000410
        rom = rom_of({
            0x400: [jal(0x80000480), NOP, jr(RA), addiu(V0, ZERO, 1)],
            0x410: [I(0x20, ZERO, V1, 0xDEB0)] * 3 + [0x7C000000] * 2,            # reads as loads, then as nothing
            0x480: [(2 << 26) | ((target >> 2) & 0x3FFFFFF), NOP],                # a function that jumps back there
        })

        def late(*_args):
            raise AssertionError("function discovery did not end")
        previous = signal.signal(signal.SIGALRM, late)
        signal.alarm(20)
        try:
            found = fn.discover(rom)
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)
        starts = {f.start for f in found.functions}
        self.assertIn(0x80000480, starts)
        self.assertNotIn(target, starts)


class RelocatedEntryTest(unittest.TestCase):
    def test_the_image_is_placed_where_the_boot_code_puts_it(self):
        from n64dk import boot
        rom = rom_of({0x400: [jal(0x80000420), NOP, jr(RA), NOP], 0x420: [jr(RA), addiu(V0, ZERO, 1)]},
                     entry=0x80100400)
        rom.cic = "6103"                                             # this boot chip moves the entry down 1 MiB
        self.assertEqual(rom.entry_vram, 0x80000400)
        info = boot.analyse(rom)
        self.assertEqual((info.entry, info.main_vram), (0x80000400, 0x80000400))
        self.assertIn(0x80000420, {f.start for f in fn.discover(rom).functions})


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


class DeadReturnTest(unittest.TestCase):
    """A debug build's frameless functions are followed by returns nothing reaches."""

    VRAM = 0x80001000
    FRAMED = bytes.fromhex("27bdfff8" "afa40008" "10000001" "00000000" "03e00008" "27bd0008")   # with b +1; nop
    LEAF = bytes.fromhex("00851021" "03e00008" "00000000")                                     # addu; jr ra; nop
    STUB = bytes.fromhex("03e00008" "00000000")

    def _catalogue(self, parts, optimised=False):
        from n64dk.analysis import functions
        data, rows, at = b"", [], self.VRAM
        framed = self.FRAMED if not optimised else self.FRAMED[:8] + bytes(8) + self.FRAMED[16:]
        for index in range(24):                                # enough framed functions to judge the build
            parts = [("framed", framed, "call")] + parts if index else parts
        for name, code, seed in parts:
            rows.append(functions.Function(at, at + len(code), at + len(code), name=f"{name}_{at:X}", seed=seed,
                                           kind="c", frame=8 if name == "framed" else 0))
            data += code
            at += len(code)
        cat = functions.Catalogue.__new__(functions.Catalogue)
        cat.functions = rows
        return cat, data

    def test_unreferenced_return_only_ranges_join_the_frameless_function_before_them(self):
        from n64dk.analysis import functions
        cat, data = self._catalogue([("leaf", self.LEAF, "call"), ("stub", self.STUB, "unreferenced"),
                                     ("stub", self.STUB, "unreferenced"), ("leaf", self.LEAF, "call")])
        before = len(cat.functions)
        result = functions.merge_dead_returns(cat, data, self.VRAM)
        self.assertEqual((result["debug_build"], result["merged"]), (True, 2))
        self.assertEqual(len(cat.functions), before - 2)
        leaf = next(f for f in cat.functions if f.name.startswith("leaf"))
        self.assertEqual(leaf.size, len(self.LEAF) + 16)
        self.assertEqual(data[leaf.start - self.VRAM:leaf.end - self.VRAM][-16:], self.STUB * 2)

    def test_a_referenced_empty_function_and_one_behind_a_framed_function_stay(self):
        from n64dk.analysis import functions
        cat, data = self._catalogue([("leaf", self.LEAF, "call"), ("stub", self.STUB, "call"),
                                     ("framed", self.FRAMED, "call"), ("stub", self.STUB, "unreferenced")])
        self.assertEqual(functions.merge_dead_returns(cat, data, self.VRAM)["merged"], 0)

    def test_an_optimised_build_is_left_alone(self):
        from n64dk.analysis import functions
        cat, data = self._catalogue([("leaf", self.LEAF, "call"), ("stub", self.STUB, "unreferenced")], optimised=True)
        before = len(cat.functions)
        self.assertEqual(functions.merge_dead_returns(cat, data, self.VRAM), {"merged": 0, "debug_build": False})
        self.assertEqual(len(cat.functions), before)


class MappedImagePointerCodeTest(unittest.TestCase):
    """A program run through the TLB at 0x00200400 whose functions are reached only through a
    method table: calls inside it are valid, and every function after a function's end with a
    frame is catalogued."""

    def test_functions_reached_through_pointers_are_found(self):
        from n64dk.analysis import functions as F
        base = 0x00200400
        nop, jr_ra = 0, 0x03E00008
        entry = [jr_ra, nop]                                            # 0x200400
        method = [addiu(29, 29, -24), sw(31, 20, 29), jal(base + 0x48), nop,
                  lw(31, 20, 29), jr_ra, addiu(29, 29, 24), nop]       # 0x200408 (last word: padding)
        method2 = [addiu(29, 29, -32), sw(31, 28, 29), jal(base + 0x48), nop,
                   lw(31, 28, 29), jr_ra, addiu(29, 29, 32), nop]      # 0x200428
        leaf = [jr_ra, nop]                                             # 0x200448
        words = entry + method + method2 + leaf + [0] * 16
        data = b"".join(w.to_bytes(4, "big") for w in words)
        image = F.Image(data, base)
        analyser = F.Analyser(image, base, text_lo=base)
        analyser.add(base, "entry")
        analyser.grow()
        self.assertEqual(set(analyser.starts), {base})                 # no call reaches the methods
        self.assertTrue(analyser.walk(base + 8, image.end, strict=True).ok)   # mapped calls are valid
        self.assertEqual(analyser.prologue_seeds(base, image.end), 2)
        self.assertEqual({a for a, seed in analyser.starts.items() if seed == "prologue"}, {base + 0x8, base + 0x28})

    def test_a_prologue_inside_straight_code_is_not_a_start(self):
        from n64dk.analysis import functions as F
        base = 0x80000400
        words = [addiu(29, 29, -24), lui(2, 0x8000), addiu(29, 29, -8), 0x03E00008, addiu(29, 29, 32)] + [0] * 4
        image = F.Image(b"".join(w.to_bytes(4, "big") for w in words), base)
        self.assertFalse(F._after_function_end(image, base + 8))
        self.assertTrue(F._after_function_end(image, base + 20))       # after jr ra and its delay slot
