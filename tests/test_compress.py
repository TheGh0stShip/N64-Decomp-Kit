import os
import random
import struct
import unittest
import zlib

from n64dk import fixtures
from n64dk.assets import compress as c


def sample(seed: int = 1, n: int = 6000) -> bytes:
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < n:
        kind = rng.randrange(4)
        if kind == 0:
            out += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
        elif kind == 1:
            out += bytes(rng.randrange(1, 300))
        elif kind == 2 and len(out) > 8:
            a = rng.randrange(len(out) - 4)
            out += out[a:a + rng.randrange(3, 120)]
        else:
            out += b"texture_" * rng.randrange(1, 10)
    return bytes(out[:n])


class CodecRoundTrip(unittest.TestCase):
    def test_all_codecs(self):
        for data in (sample(1), sample(2, 300), b"x", bytes(5000), os.urandom(700)):
            for name in ("mio0", "yay0", "yaz0", "lzari", "zlib", "gzip", "deflate"):
                with self.subTest(codec=name, n=len(data)):
                    enc = c.encode(name, data)
                    dec = c.decode(name, enc + b"\x12\x34TRAILING-JUNK" * 3)
                    self.assertEqual(dec.data, data)
                    self.assertEqual(dec.consumed, len(enc), "consumed length must be exact")

    def test_registry_is_pluggable(self):
        codec = c.Codec("rev", lambda b, o=0, m=0: c.Decoded(bytes(b[o + 4:o + 4 + b[o]][::-1]), 4 + b[o]),
                        lambda d: bytes([len(d), 0, 0, 0]) + d[::-1])
        c.register(codec)
        try:
            self.assertEqual(c.decode("rev", c.encode("rev", b"abc")).data, b"abc")
        finally:
            del c.REGISTRY["rev"]

    def test_lzari_reference_vector(self):
        # Okumura LZARI of "aaaa": the size header is big-endian.
        enc = c.lzari_encode(b"aaaa")
        self.assertEqual(enc[:4], b"\0\0\0\4")
        self.assertEqual(c.lzari_decode(enc).data, b"aaaa")

    def test_truncation_is_an_error(self):
        enc = c.yaz0_encode(sample(3))
        with self.assertRaises(c.CodecError):
            c.yaz0_decode(enc[:len(enc) // 2])
        enc = c.mio0_encode(sample(3))
        with self.assertRaises(c.CodecError):
            c.mio0_decode(enc[:len(enc) // 2])

    def test_lzari_probe(self):
        enc = c.lzari_encode(sample(4, 3000))
        blob = os.urandom(64) + enc
        self.assertTrue(c.lzari_probe(blob, 64))
        rng = random.Random(5)
        noise = bytes(rng.randrange(256) for _ in range(4096))
        false = [p for p in range(0, 800, 4)
                 if c.lzari_probe(struct.pack(">I", 0x800) + noise[p + 4:], 0)]
        self.assertEqual(false, [])


class ScannerTests(unittest.TestCase):
    def test_finds_embedded_streams(self):
        parts = [("mio0", c.mio0_encode(sample(6))), ("yay0", c.yay0_encode(sample(7))),
                 ("yaz0", c.yaz0_encode(sample(8))), ("lzari", c.lzari_encode(sample(9))),
                 ("zlib", zlib.compress(sample(10)))]
        blob = bytearray(os.urandom(0x103))
        expect = []
        for name, enc in parts:
            blob += bytes(-len(blob) % 16 + 16)  # zero padding between streams
            expect.append((len(blob), name, len(enc)))
            blob += enc
        blob += bytes(32)
        found = [(s.rom, s.codec, s.consumed) for s in c.scan(bytes(blob), verify_reencode=True)]
        self.assertEqual(found, expect)

    def test_lzari_chain(self):
        a, b = c.lzari_encode(sample(11)), c.lzari_encode(sample(12))
        blob = bytes(16) + a + bytes(-len(a) % 4) + b + bytes(16)
        found = c.scan_lzari(blob, brute=False, seeds=[16])
        self.assertEqual([(s.rom, s.consumed, s.method) for s in found],
                         [(16, len(a), "seed"), (16 + len(a) + (-len(a) % 4), len(b), "chain")])


# Game facts (ROM offsets only) used to check the scanner on retail images.
BT_LEVEL_WORLD = [(0x738900, 0x73B2ED), (0x73B2F0, 0x742D4E), (0x79EB38, 0x7A6187), (0x7B4508, 0x7B69A0)]
BT_BUNDLES = [(0x49DCD0, 0x4AC150), (0x4AC150, 0x4AD7E0), (0x2D2790, 0x2E2CD0), (0x596EA0, 0x5A1110)]


class RomTests(unittest.TestCase):
    def test_battletanx_lzari(self):
        rom = fixtures.rom("battletanx")
        if rom is None:
            self.skipTest("battletanx fixture not configured")
        for start, end in BT_LEVEL_WORLD:
            d = c.lzari_decode(rom.data, start)
            self.assertEqual(d.consumed, end - start)
            self.assertTrue(c.lzari_probe(rom.data, start))
        for start, end in BT_BUNDLES:
            d = c.lzari_decode(rom.data, start)
            pad = rom.data[start + d.consumed:end]  # loader ranges include zero alignment padding
            self.assertTrue(len(pad) < 16 and not pad.strip(b"\0"))
            self.assertEqual(rom.data[start:start + d.consumed], c.lzari_encode(d.data))

    def test_mk64_mio0(self):
        rom = fixtures.rom("mk64")
        if rom is None:
            self.skipTest("mk64 fixture not configured")
        streams = c._magic_streams(rom.data, c.DEFAULT_MAX_OUTPUT)
        self.assertGreater(len(streams), 100)
        self.assertTrue(all(s.codec == "mio0" for s in streams))
        for s in streams[:: max(1, len(streams) // 12)]:
            self.assertEqual(c.mio0_encode(s.data), rom.data[s.rom:s.end], hex(s.rom))


if __name__ == "__main__":
    unittest.main()
