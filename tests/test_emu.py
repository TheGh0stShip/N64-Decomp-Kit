import struct
import unittest

from n64dk import boot, emu, fixtures
from n64dk.rom import Rom

SP, T0, T1, T2 = 29, 8, 9, 10


def lui(rt, imm): return (15 << 26) | (rt << 16) | imm
def ori(rt, rs, imm): return (13 << 26) | (rs << 21) | (rt << 16) | imm
def addiu(rt, rs, imm): return (9 << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)
def sw(rt, off, base): return (43 << 26) | (base << 21) | (rt << 16) | (off & 0xFFFF)
def bne(rs, rt, off): return (5 << 26) | (rs << 21) | (rt << 16) | (off & 0xFFFF)
def j(target): return (2 << 26) | ((target >> 2) & 0x3FFFFFF)


def synthetic_rom() -> Rom:
    """Entry sets the stack with lui/ori, DMAs ROM 0x2000 to 0x80180000, clears a
    BSS loop, writes one word, then jumps into the DMA'd code (an idle loop)."""
    code = [
        lui(SP, 0x803F), ori(SP, SP, 0xFFF0),
        lui(T0, 0xA460), lui(T1, 0x0018), sw(T1, 0, T0),
        lui(T1, 0x1000), ori(T1, T1, 0x2000), sw(T1, 4, T0),
        addiu(T1, 0, 0xFF), sw(T1, 0xC, T0),
        lui(T0, 0x8020), lui(T1, 0x8020), ori(T1, T1, 0x100),
        sw(0, 0, T0), addiu(T0, T0, 4), bne(T0, T1, -3), 0,
        lui(T2, 0x8030), lui(T1, 0x1234), sw(T1, 0, T2),
        j(0x80180000), 0,
    ]
    data = bytearray(0x102000 + 0x100)
    struct.pack_into(">III", data, 0, 0x80371240, 0, 0x80000400)
    struct.pack_into(f">{len(code)}I", data, 0x1000, *code)
    struct.pack_into(">II", data, 0x2000, (4 << 26) | 0xFFFF, 0)  # b . ; nop
    return Rom(bytes(data))


class SyntheticBootTests(unittest.TestCase):
    def test_static(self):
        info = boot.analyse(synthetic_rom())
        self.assertEqual(info.stack_top, 0x803FFFF0)
        self.assertEqual((info.bss_start, info.bss_end), (0x80200000, 0x80200100))
        self.assertEqual(info.main_call, 0x80180000)
        self.assertTrue(info.staged)

    def test_emulated(self):
        res = emu.run(synthetic_rom(), max_steps=5000, stop_after_handoff=20)
        self.assertEqual([(d.rom, d.ram, d.size) for d in res.dmas], [(0x2000, 0x80180000, 0x100)])
        self.assertEqual(res.handoffs[0][1], 0x80180000)
        self.assertEqual(res.stop_reason, "ran past the first handoff")
        kinds = {s["ram"]: (s["kind"], s.get("rom")) for s in res.segments()}
        self.assertEqual(kinds["0x80180000..0x80180100"], ("dma", "0x002000..0x002100"))
        self.assertEqual(kinds["0x80200000..0x80200100"], ("zero", None))
        self.assertEqual(kinds["0x80300000..0x80300100"], ("generated", None))

    def test_call_returns_and_records_arguments(self):
        # a routine at 0x80000500: v0 = a0 + a1; jr ra (delay slot sets a2, not seen by the caller)
        m = emu.Machine(synthetic_rom())
        struct.pack_into(">III", m.ram, 0x500, 0x00851021, 0x03E00008, addiu(6, 0, 7))
        self.assertEqual(m.call(0x80000500, (3, 4)), "returned")
        self.assertEqual(m.gpr[2], 7)
        # first-entry arguments are recorded for calls the program makes itself
        # jal 0x80000500 with a0 = 5 set in the delay slot, then jump to the return trap
        trap = emu.Machine.RETURN_TRAP
        struct.pack_into(">6I", m.ram, 0x600, (3 << 26) | (0x80000500 >> 2) & 0x3FFFFFF, addiu(4, 0, 5),
                         lui(8, trap >> 16), ori(8, 8, trap & 0xFFFF), 0x01000008, 0)   # jr $t0
        self.assertEqual(m.call(0x80000600, (0, 9)), "returned")
        self.assertEqual(m.first_args[0x80000500][:2], (5, 9))

    def test_unaligned_loads(self):
        m = emu.Machine(synthetic_rom())
        # lwl/lwr pair reading an unaligned word
        m.ram[0x1000:0x1008] = bytes(range(1, 9))
        self.assertEqual(m.lwlr(34, 0x80001001, 0) & 0xFFFFFFFF, 0x02030400)
        self.assertEqual(m.lwlr(38, 0x80001004, 0x02030400) & 0xFFFFFFFF, 0x02030405)


def single(value): return struct.unpack(">I", struct.pack(">f", value))[0]
def double(value): return struct.unpack(">Q", struct.pack(">d", value))[0]
def cop1(fmt, ft, fs, fd, fn): return (17 << 26) | (fmt << 21) | (ft << 16) | (fs << 11) | (fd << 6) | fn


class FloatingPointTests(unittest.TestCase):
    def setUp(self):
        self.m = emu.Machine(synthetic_rom())

    def test_single_arithmetic_and_compare(self):
        m = self.m
        m.fpr[2], m.fpr[4] = single(1.5), single(2.25)
        for fn, expected in ((0, 3.75), (1, -0.75), (2, 3.375), (3, 1.5 / 2.25)):
            m.fpu(16, fn, 2, 4, 6)
            self.assertEqual(m.fpr[6], single(expected), fn)
        m.fpu(16, 0x3C, 2, 4, 0)                             # c.lt.s
        self.assertTrue(m.fcc)
        m.fpu(16, 0x32, 2, 4, 0)                             # c.eq.s
        self.assertFalse(m.fcc)
        m.fpr[4] = single(float("nan"))
        m.fpu(16, 0x3C, 2, 4, 0)                             # ordered compare with a NaN
        self.assertFalse(m.fcc)
        m.fpu(16, 0x31, 2, 4, 0)                             # c.un.s
        self.assertTrue(m.fcc)

    def test_division_by_zero_and_what_does_not_fit(self):
        m = self.m
        m.fpr[2], m.fpr[4] = single(-3.0), single(0.0)
        m.fpu(16, 3, 2, 4, 6)
        self.assertEqual(m.fpr[6], single(float("-inf")))
        m.fpr[2] = single(3e10)
        m.fpu(16, 13, 2, 0, 6)                               # trunc.w.s of a value past 32 bits
        self.assertEqual(m.fpr[6], 0x7FFFFFFF)

    def test_conversions_round_as_the_processor_does(self):
        m = self.m
        m.fpr[2] = single(-2.7)
        for fn, expected in ((12, -3), (13, -2), (14, -2), (15, -3)):      # round, trunc, ceil, floor
            m.fpu(16, fn, 2, 0, 6)
            self.assertEqual(m.fpr[6], expected & 0xFFFFFFFF, fn)
        m.fpr[2] = single(2.5)
        m.fpu(16, 36, 2, 0, 6)                               # cvt.w.s: a tie goes to the even neighbour
        self.assertEqual(m.fpr[6], 2)
        m.fpr[2] = (-7) & 0xFFFFFFFF
        m.fpu(20, 32, 2, 0, 6)                               # cvt.s.w
        self.assertEqual(m.fpr[6], single(-7.0))

    def test_a_double_is_one_register_or_a_pair_as_the_status_register_says(self):
        m = self.m
        m.fpr[2] = 5
        m.fpu(20, 33, 2, 0, 4)                               # cvt.d.w with FR set: one 64-bit register
        self.assertEqual(m.fpr[4], double(5.0))
        m.cop0[12] &= ~emu.SR_FR
        m.fpu(20, 33, 2, 0, 4)                               # FR clear: low word in $f4, high in $f5
        self.assertEqual((m.fpr[5] << 32) | m.fpr[4], double(5.0))
        m.fpu(17, 0, 4, 4, 6)                                # add.d
        self.assertEqual(m.fget(6, True), double(10.0))
        m.fpu(17, 32, 6, 0, 8)                               # cvt.s.d
        self.assertEqual(m.fpr[8], single(10.0))

    def test_through_translated_code(self):
        # v0 = (int)((float)a0 * 0.5f) when a0 < a1 as floats, else -1; loads and stores go through memory
        m = self.m
        m.ram[0x700:0x704] = struct.pack(">f", 0.5)
        A0, A1, V0, AT = 4, 5, 2, 1
        code = [(17 << 26) | (4 << 21) | (A0 << 16) | (2 << 11),             # mtc1 a0, f2
                (17 << 26) | (4 << 21) | (A1 << 16) | (4 << 11),             # mtc1 a1, f4
                cop1(20, 0, 2, 2, 32), cop1(20, 0, 4, 4, 32),                # cvt.s.w f2, f2; cvt.s.w f4, f4
                lui(AT, 0x8000), (49 << 26) | (AT << 21) | (6 << 16) | 0x700,  # lwc1 f6, 0x700(at)
                cop1(16, 4, 2, 0, 0x3C),                                     # c.lt.s f2, f4
                (17 << 26) | (8 << 21) | (0 << 16) | 5, addiu(V0, 0, -1),    # bc1f to the return; (delay) v0 = -1
                cop1(16, 6, 2, 8, 2), cop1(16, 0, 8, 8, 13),                 # mul.s f8, f2, f6; trunc.w.s f8, f8
                (57 << 26) | (AT << 21) | (8 << 16) | 0x704,                 # swc1 f8, 0x704(at)
                (35 << 26) | (AT << 21) | (V0 << 16) | 0x704,                # lw v0, 0x704(at)
                0x03E00008, 0]                                               # jr ra
        struct.pack_into(f">{len(code)}I", m.ram, 0x500, *code)
        self.assertEqual(m.call(0x80000500, (9, 20)), "returned")
        self.assertEqual(m.gpr[2], 4)
        self.assertEqual(m.call(0x80000500, (30, 20)), "returned")
        self.assertEqual(m.gpr[2] & 0xFFFFFFFF, 0xFFFFFFFF)


class MappedAddressTests(unittest.TestCase):
    def map(self, m, index, virtual, physical, mask=0x001FE000):
        """One entry: a pair of pages (1 MiB each by default) at ``virtual``, onto ``physical``."""
        size = ((mask | 0x1FFF) + 1) >> 1
        m.cop0[0], m.cop0[5], m.cop0[10] = index, mask, virtual
        m.cop0[2] = ((physical >> 12) << 6) | 2              # even page, valid
        m.cop0[3] = (((physical + size) >> 12) << 6) | 2     # odd page
        m.tlb_op(2)

    def test_code_and_data_at_a_mapped_address(self):
        m = emu.Machine(synthetic_rom())
        self.map(m, 0, 0x00200000, 0x00100000)
        # at RAM 0x80100500, run as 0x00200500: v0 = *(0x00300010) + a0, a store back, return
        struct.pack_into(">I", m.ram, 0x200010, 40)          # the odd page: 0x00300000 -> RAM 0x200000
        code = [lui(8, 0x0030), (35 << 26) | (8 << 21) | (2 << 16) | 0x10, 0x00441021,      # lw v0,0x10(t0); addu v0,v0,a0
                sw(2, 0x14, 8), 0x03E00008, 0]
        struct.pack_into(f">{len(code)}I", m.ram, 0x100500, *code)
        self.assertEqual(m.call(0x00200500, (2,)), "returned")
        self.assertEqual(m.gpr[2], 42)
        self.assertEqual(struct.unpack_from(">I", m.ram, 0x200014)[0], 42)
        self.assertEqual(m.mappings(), [(0x00200000, 0x100000, 0x100000), (0x00300000, 0x100000, 0x200000)])

    def test_an_address_nothing_maps_stops_the_run(self):
        m = emu.Machine(synthetic_rom())
        self.assertIn("unmapped address 0x00200500", m.call(0x00200500))

    def test_probe_and_read_back(self):
        m = emu.Machine(synthetic_rom())
        self.map(m, 5, 0x00200000, 0x00100000)
        m.cop0[10] = 0x00200000
        m.tlb_op(8)
        self.assertEqual(m.cop0[0], 5)
        m.cop0[10] = 0x00800000
        m.tlb_op(8)
        self.assertEqual(m.cop0[0], 0x80000000)

    def test_the_straight_run_around_an_address(self):
        res = emu.EmuResult(0, "", 0)
        # two entries one after the other, then one that maps elsewhere
        res.mappings = [(0x00200000, 0x100000, 0x100000), (0x00300000, 0x100000, 0x200000),
                        (0x00400000, 0x100000, 0x700000)]
        self.assertEqual(res.physical(0x00300010), 0x200010)
        self.assertIsNone(res.physical(0x00900000))
        self.assertEqual(res.physical(0x80001234), 0x1234)
        # RAM 0x100400..0x380000 was written; mapped straight from 0x00200400 up to the end of the second entry
        self.assertEqual(res.linear(0x00200500, 0x100400, 0x380000), (0x00200400, 0x100400, 0x300000))
        self.assertEqual(res.linear(0x80100500, 0x100400, 0x380000), (0x80100400, 0x100400, 0x380000))


class IdleLoopTests(unittest.TestCase):
    def test_a_branch_to_itself_ends_the_run(self):
        m = emu.Machine(synthetic_rom())
        struct.pack_into(">II", m.ram, 0x500, (4 << 26) | 0xFFFF, 0)          # b . ; nop
        self.assertEqual(m.call(0x80000500), "idle loop")
        self.assertLess(m.steps, 10)

    def test_after_a_hand_over_it_is_still_reported_as_the_hand_over(self):
        res = emu.run(synthetic_rom(), max_steps=5000, stop_after_handoff=2000)
        self.assertEqual(res.stop_reason, "ran past the first handoff")
        self.assertLess(res.steps, 1000)                      # not the 2,000 steps allowed after the hand-over


class FixtureBootTests(unittest.TestCase):
    def test_nagano_reaches_threads(self):
        rom = fixtures.rom("nagano98")
        if rom is None:
            self.skipTest("nagano98 not configured")
        res = emu.run(rom, max_steps=3_000_000, stop_after_handoff=50_000)
        self.assertTrue(res.erets, res.summary())
        self.assertEqual(res.stop_reason, "ran past the first handoff")
        self.assertTrue(any(s["kind"] == "zero" and s["size"] > 0x100000 for s in res.segments()))


if __name__ == "__main__":
    unittest.main()
