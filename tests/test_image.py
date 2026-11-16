import os
import struct
import unittest

from n64dk import fixtures, image, survey
from n64dk.rom import Rom
from tests.test_emu import SP, T0, T1, T2, addiu, bne, lui, ori, sw, synthetic_rom


def jal(target): return (3 << 26) | ((target >> 2) & 0x3FFFFFF)


def plain_rom() -> Rom:
    """A plain libultra-style entry: stack, BSS clear loop, call main (an idle loop)."""
    code = [lui(SP, 0x8030), addiu(SP, SP, -0x10),
            lui(T0, 0x8010), lui(T1, 0x8010), ori(T1, T1, 0x200),
            sw(0, 0, T0), addiu(T0, T0, 4), bne(T0, T1, -3), 0,
            jal(0x80000440), 0, 0, 0, 0, 0, 0,
            (4 << 26) | 0xFFFF, 0]   # 0x80000440: b . ; nop
    data = bytearray(0x101000)
    struct.pack_into(">III", data, 0, 0x80371240, 0, 0x80000400)
    struct.pack_into(f">{len(code)}I", data, 0x1000, *code)
    return Rom(bytes(data))


def stub_rom() -> Rom:
    """An ordinary entry routine (stack, call main) whose main writes two instructions into RAM
    and jumps to them: a stub that produces the program, with nothing staged in the entry."""
    def jr(reg): return (reg << 21) | 8
    code = [lui(SP, 0x8030), addiu(SP, SP, -0x10), jal(0x80000440), 0, (4 << 26) | 0xFFFF, 0] + [0] * 10 + [
        lui(T0, 0x8020), lui(T1, 0x1000), ori(T1, T1, 0xFFFF),          # 0x80000440: t1 = "b ."
        sw(T1, 0, T0), sw(0, 4, T0),
        # where to go is computed at run time (a sum kept in memory), as a real unpacker's is
        sw(T0, 0, SP), (35 << 26) | (SP << 21) | (T2 << 16), jr(T2), 0]
    data = bytearray(0x101000)
    struct.pack_into(">III", data, 0, 0x80371240, 0, 0x80000400)
    struct.pack_into(f">{len(code)}I", data, 0x1000, *code)
    return Rom(bytes(data))


class StubTests(unittest.TestCase):
    def counts(self, static: int, unpacked: int):
        seen = []

        def count(_rom, program):
            seen.append(program.method)
            return static if program.method == "static" else unpacked
        return count, seen

    def test_a_small_boot_image_that_unpacks_more_is_replaced(self):
        count, seen = self.counts(3, 300)
        img = image.build(stub_rom(), count=count)
        self.assertEqual((img.method, img.main().vram, img.main().kind), ("emulated", 0x80200000, "packed"))
        self.assertEqual(img.loader["stub"], {"functions": 3, "unpacked_functions": 300})
        self.assertEqual(seen, ["static", "emulated"])

    def test_what_it_unpacks_must_hold_several_times_more(self):
        count, _seen = self.counts(40, 70)
        self.assertEqual(image.build(stub_rom(), count=count).method, "static")

    def test_a_boot_image_of_ordinary_size_is_not_emulated(self):
        count, seen = self.counts(900, 5000)
        self.assertEqual(image.build(stub_rom(), count=count).method, "static")
        self.assertEqual(seen, ["static"])

    def test_a_small_program_that_unpacks_nothing_stays_as_it_is(self):
        count, _seen = self.counts(2, 0)
        self.assertEqual(image.build(plain_rom(), count=count).method, "static")


class ProgramImageTests(unittest.TestCase):
    def test_static(self):
        img = image.build(plain_rom())
        self.assertEqual(img.method, "static")
        self.assertEqual([(s.kind, s.vram, s.end) for s in img.segments],
                         [("rom", 0x80000400, 0x80100000), ("bss", 0x80100000, 0x80100200)])
        self.assertEqual(img.hand_over, 0x80000440)
        self.assertIs(img.boot_info(), img.boot)

    def test_emulated_dma(self):
        img = image.build(synthetic_rom())
        self.assertEqual(img.method, "emulated")
        main = img.main()
        self.assertEqual((main.kind, main.vram, main.rom), ("rom", 0x80180000, 0x2000))
        self.assertEqual(main.data[:4], bytes.fromhex("1000FFFF"))
        b = img.boot_info()
        self.assertEqual((b.main_rom, b.main_vram, b.entry), (0x2000, 0x80180000, 0x80180000))

    def test_survey_ledger_covers_rom(self):
        rom = plain_rom()
        res = survey.run(rom, lzari_brute=False)
        items = res["ledger"]
        self.assertEqual(items[0].start, 0)
        self.assertEqual(items[-1].end, rom.size)
        self.assertTrue(all(a.end == b.start for a, b in zip(items, items[1:])))
        rep = res["report"]
        self.assertEqual(rep["program"]["method"], "static")
        self.assertIn("unknown_bytes", rep)
        self.assertIn("referenced_only_bytes", rep)
        self.assertIsInstance(rep["next_steps"], list)
        md = survey.render_markdown(rep)
        self.assertIn("# Survey", md)
        self.assertIn("ROM understood", md)

    def test_describe_bytes(self):
        import os as _os
        self.assertIn("constant fill", survey.describe_bytes(bytes(0x8000)))
        self.assertIn("already compressed", survey.describe_bytes(_os.urandom(0x8000)))
        self.assertIn("structured", survey.describe_bytes(b"level 01 name: desert; units: 12\n" * 1000))

    def test_survey_places_graphics_pool(self):
        from tests.test_gbi import dl, vtx_f3dex
        blob = dl(vtx_f3dex(0x18, 1, 0), (0xB8000000, 0), (0xE7000000, 0)) + bytes(16)
        data = bytearray(plain_rom().data + bytes(0x2000))
        data[0x101000:0x101000 + 6 * len(blob)] = blob * 6
        data[0x101000 + 6 * len(blob):0x103000] = b"\x11" * (0x2000 - 6 * len(blob))
        res = survey.run(Rom(bytes(data)), lzari_brute=False)
        gfx = [it for it in res["ledger"] if it.category == "graphics"]
        self.assertEqual((gfx[0].start, gfx[-1].end, len(gfx)), (0x101000, 0x101000 + 6 * len(blob), 6))
        self.assertEqual(res["report"]["gfx"]["blobs"], 6)


class FixtureImageTests(unittest.TestCase):
    def test_madden_second_stage(self):
        rom = fixtures.rom("madden64")
        if rom is None:
            self.skipTest("madden64 not configured")
        img = image.build(rom)
        main, bss = img.main(), img.bss()
        self.assertEqual((main.kind, main.vram, main.end), ("packed", 0x80000400, 0x800776C0))
        self.assertEqual((bss.vram, bss.end), (0x800776C0, 0x8008B8E0))
        self.assertEqual(main.rom, 0x1318)   # exact: the source argument of the unpacking routine
        self.assertIn("0x802004DC", main.game_codec)
        self.assertEqual(img.hand_over, 0x80000440)
        # analyses see the second stage, with text starting at the segment, not the hand-over
        from n64dk.analysis import functions
        cat = functions.discover(rom, program=img)
        self.assertEqual(cat.text_start, 0x80000400)
        # CPU code continues after the RSP boot microcode linked into .text: recovered
        self.assertEqual(cat.text_end, 0x800649FC)
        self.assertTrue(any(f.kind == "text_extended" for f in cat.findings))
        self.assertGreater(len(cat.functions), 1300)
        # the game's own routine, called directly, reproduces the program (the loader copies
        # a 0x40-byte table over its start afterwards)
        from n64dk import gamecodec
        codec = gamecodec.find(img, img.call_args)
        self.assertEqual((codec.func, codec.source_rom), (0x802004DC, 0x1318))
        dec = gamecodec.decode(rom, codec, codec.source_rom, max_in=main.rom_end - main.rom + 0x100,
                               max_steps=40_000_000)
        self.assertEqual(dec.data[0x40:len(main.data)], main.data[0x40:])

    @unittest.skipUnless(os.environ.get("N64DK_SLOW"), "set N64DK_SLOW=1 (about 80 s)")
    def test_wwf_packed_program(self):
        rom = fixtures.rom("wwf_warzone")
        if rom is None:
            self.skipTest("wwf_warzone not configured")
        img = image.build(rom)
        main, bss = img.main(), img.bss()
        self.assertEqual((main.vram, main.end, main.rom, main.rom_end),
                         (0x8003C400, 0x8012A1C0, 0xB8E9E0, 0xBF5040))
        self.assertEqual((bss.vram, bss.end), (0x8012A1C0, 0x801A43E0))


if __name__ == "__main__":
    unittest.main()
