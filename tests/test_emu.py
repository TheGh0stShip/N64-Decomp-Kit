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
