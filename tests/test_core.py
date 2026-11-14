import struct
import unittest

from n64dk import boot, fixtures, mips
from n64dk.ledger import Ledger, LedgerError
from n64dk.rom import Rom, to_big_endian


class ByteOrderTests(unittest.TestCase):
    def test_conversions(self):
        z64 = bytes.fromhex("80371240") + bytes(range(12))
        v64 = bytearray(z64)
        v64[0::2], v64[1::2] = z64[1::2], z64[0::2]
        n64 = b"".join(struct.pack("<I", w) for w in struct.unpack(">4I", z64))
        self.assertEqual(to_big_endian(bytes(v64)), (z64, "v64"))
        self.assertEqual(to_big_endian(n64), (z64, "n64"))


class LedgerTests(unittest.TestCase):
    def test_fill_and_overlap(self):
        data = bytes(4) + b"\xAA" * 4 + bytes(8)
        led = Ledger(0, 16)
        led.add(4, 8, "payload", name="a")
        items = led.complete(data)
        self.assertEqual([i.cls for i in items], ["padding", "payload", "padding"])
        led.add(6, 10, "payload", name="b")
        with self.assertRaises(LedgerError):
            led.complete(data)


class MipsTests(unittest.TestCase):
    def test_hi_lo_pair(self):
        code = struct.pack(">III", 0x3C028012, 0x8C425714, 0x03E00008)  # lui v0; lw v0,0x5714(v0); jr ra
        refs = mips.scan_refs(code + bytes(4), 0x80000000)
        self.assertEqual([(r.address, r.kind) for r in refs], [(0x80125714, "load")])


class RomFixtureTests(unittest.TestCase):
    def test_known_roms(self):
        found = 0
        for name in fixtures.KNOWN:
            rom = fixtures.rom(name)
            if rom is None:
                continue
            found += 1
            self.assertEqual(rom.cic, "6102")
            self.assertTrue(rom.checksum_ok())
            info = boot.analyse(rom)
            self.assertIsNotNone(info.stack_top, name)
            self.assertIsNotNone(info.main_call, name)
            if not info.staged:
                self.assertIsNotNone(info.bss_start, name)
        if not found:
            self.skipTest("no fixture ROMs configured")


if __name__ == "__main__":
    unittest.main()
