import struct
import unittest

from n64dk import boot, fixtures
from n64dk.assets import loaders as L

ROM_SIZE = 0x800000
VRAM = 0x80001000


def words(*ws: int) -> bytes:
    return struct.pack(f">{len(ws)}I", *ws)


def lui(rt, imm): return (0x0F << 26) | (rt << 16) | (imm & 0xFFFF)
def addiu(rt, rs, imm): return (0x09 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
def subu(rd, rs, rt): return (rs << 21) | (rt << 16) | (rd << 11) | 0x23
def jal(target): return (0x03 << 26) | ((target >> 2) & 0x3FFFFFF)
def sw(rt, off, base): return (0x2B << 26) | (base << 21) | (rt << 16) | (off & 0xFFFF)


A0, A1, A2, AT, V0, SP = 4, 5, 6, 1, 2, 29
NOP, JR_RA = 0, 0x03E00008


def hi_lo(reg, value):
    hi = (value + 0x8000) >> 16
    return [lui(reg, hi), addiu(reg, reg, value - (hi << 16))]


class CodeTraceTests(unittest.TestCase):
    def test_pi_pair_call_and_wrapper(self):
        dma = 0x80002000
        code = [addiu(SP, SP, -0x18)]
        for start, end in ((0x123450, 0x125000), (0x200000, 0x2008F0)):
            code += hi_lo(A0, 0xB0000000 + start) + hi_lo(A1, 0xB0000000 + end) + [jal(dma), NOP]
        code += [JR_RA, NOP]
        ranges, wrappers = L.code_ranges(words(*code), VRAM, ROM_SIZE)
        self.assertEqual([(r.start, r.end, r.source, r.loader) for r in ranges],
                         [(0x123450, 0x125000, "call", VRAM), (0x200000, 0x2008F0, "call", VRAM)])
        self.assertEqual(wrappers[dma]["kind"], "end")

    def test_linker_size_and_wrapper_reuse(self):
        dma = 0x80002000
        code = [addiu(SP, SP, -0x18)]
        # dma(start, dst, end - start) with raw linker offsets, twice
        for start, end in ((0x40000, 0x48000), (0x50000, 0x50400)):
            code += hi_lo(A0, start) + hi_lo(V0, end) + hi_lo(A1, 0x80300000) + [subu(A2, V0, A0), jal(dma), NOP]
        # a third site with a constant size only
        code += hi_lo(A0, 0x60000) + [addiu(A2, 0, 0x100), jal(dma), NOP, JR_RA, NOP]
        ranges, wrappers = L.code_ranges(words(*code), VRAM, ROM_SIZE)
        got = {(r.start, r.end, r.source) for r in ranges}
        self.assertIn((0x40000, 0x48000, "call"), got)
        self.assertIn((0x50000, 0x50400, "call"), got)
        self.assertIn((0x60000, 0x60100, "wrapper"), got)
        self.assertEqual(wrappers[dma], {"sites": 2, "start_slot": 0, "end_slot": 2, "kind": "size"})

    def test_stored_records(self):
        code = []
        table = 0x80125A68
        values = [0x738900, 0x73B2ED, 0x6F9C40, 0x6FEE7B, 0x73B2F0, 0x742D4E, 0x6FEE80, 0x7017CF]
        for k, v in enumerate(values):
            addr = table + 4 * k
            hi = (addr + 0x8000) >> 16
            code += hi_lo(V0, 0xB0000000 + v) + [lui(AT, hi), sw(V0, addr - (hi << 16), AT)]
        code += [JR_RA, NOP]
        _calls, sizes = L.trace_calls(words(*code), VRAM, ROM_SIZE)
        self.assertEqual(sorted((r.start, r.end) for r in sizes if r.source == "store"),
                         sorted(zip(values[::2], values[1::2])))


class TableTests(unittest.TestCase):
    def test_offset_table_and_parallel_arrays(self):
        starts = [0x300000, 0x301000, 0x302400]
        ends = [0x300FF0, 0x302400, 0x303000]
        data = words(0x12345678, *[0xB0000000 + v for v in starts + ends], 0)
        got = {(r.start, r.end, r.source) for r in L.table_ranges(data, 0x80100000, ROM_SIZE)}
        for s, e in zip(starts, ends):
            self.assertTrue(any(g[:2] == (s, e) for g in got), hex(s))

    def test_raw_records_need_structure(self):
        rows = []
        for k in range(4):  # {start, end, flags, pad} course-style records
            rows += [0x100000 + 0x10000 * k, 0x100000 + 0x10000 * k + 0x8000, 7, 0]
        got = L.dedupe(L.table_ranges(words(*rows), 0x80100000, ROM_SIZE))
        self.assertEqual([(r.start, r.end) for r in got if r.source == "records"],
                         [(0x100000 + 0x10000 * k, 0x108000 + 0x10000 * k) for k in range(4)])
        # The same pairs without a repeated stride are not trusted.
        lone = words(0x100000, 0x108000, 0x5555, 0x77777777)
        self.assertEqual(L.table_ranges(lone, 0x80100000, ROM_SIZE), [])

    def test_plausible(self):
        R = L.RomRange
        call = R(0x100000, 0x120000, "pi", "call", None, 0)
        member = R(0x104000, 0x108000, "pi", "records", None, 4)        # nested: kept
        crossing = R(0x118000, 0x130000, "pi", "records", None, 8)      # partial overlap: dropped
        huge = R(0x200000, 0x900000, "pi", "records", None, 12)         # 7 MiB on table evidence
        ladder = R(0x40000, 0x80000, "raw", "records", None, 16)        # size table
        anchored = R(0x300000, 0x500000, "raw", "records", None, 20)    # 2 MiB, but a stream starts there
        kept, why = L.plausible([call, member, crossing, huge, ladder, anchored], stream_starts={0x300000})
        self.assertEqual(kept, sorted([call, member, anchored], key=lambda r: (r.start, r.end)))
        self.assertEqual(why, {"partial overlap with stronger evidence": 1,
                               "over 1 MiB on table or raw-number evidence": 1,
                               "power-of-two bounds (a size table)": 1})


class RomTests(unittest.TestCase):
    def test_battletanx(self):
        rom = fixtures.rom("battletanx")
        if rom is None:
            self.skipTest("battletanx fixture not configured")
        b = boot.analyse(rom)
        ev = L.trace(rom.data, b.main_rom, b.main_vram, b.copy_size)
        got = {(r.start, r.end): r for r in ev.ranges}
        self.assertIn(0x80077930, ev.wrappers)  # rom_dma_read(pi_start, dst, size)
        # level world/nav streams are stored by func_800865E0
        for pair in ((0x738900, 0x73B2ED), (0x6F9C40, 0x6FEE7B), (0x7B4508, 0x7B69A0)):
            self.assertEqual(got[pair].source, "store")
            self.assertEqual(got[pair].loader, 0x800865E0)
        self.assertEqual(got[(0x4AC150, 0x4AD7E0)].loader, 0x800DADBC)


if __name__ == "__main__":
    unittest.main()


class AssetsScanCommandTests(unittest.TestCase):
    def test_battletanx_seeded_scan(self):
        rom = fixtures.rom("battletanx")
        if rom is None:
            self.skipTest("battletanx fixture not configured")
        from n64dk.commands.assets_scan import scan_rom
        res = scan_rom(rom, lzari_brute=False)
        starts = {int(s["rom"], 16) for s in res["streams"]}
        # Every level stream is reachable from loader evidence plus stream chaining.
        self.assertTrue({0x738900, 0x6F9C40, 0x7B4508, 0x4AC150} <= starts)
        items = res["ledger"]
        self.assertEqual(items[0].start, 0)
        self.assertEqual(items[-1].end, len(rom.data))
        self.assertTrue(all(a.end == b.start for a, b in zip(items, items[1:])))
