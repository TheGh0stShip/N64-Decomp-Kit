import struct
import unittest
import zlib

from n64dk.assets import texture as T


class CodecTests(unittest.TestCase):
    def test_rgba16(self):
        px = T.decode(struct.pack(">2H", 0xF801, 0x07C0), 0, 2, 2, 1)
        self.assertEqual(px, bytes((255, 0, 0, 255, 0, 255, 0, 0)))

    def test_ci4_with_palettes(self):
        pal = struct.pack(">16H", *([0] + [0xFFFF] * 15))
        px = T.decode(bytes([0x01]), 2, 0, 2, 1, pal)
        self.assertEqual(px, bytes((0, 0, 0, 0, 255, 255, 255, 255)))
        ia = struct.pack(">16H", *([0x80FF] * 16))
        self.assertEqual(T.decode(bytes([0x00]), 2, 0, 2, 1, ia, "ia16")[:4], bytes((0x80, 0x80, 0x80, 0xFF)))
        self.assertEqual(len(T.decode(bytes(4), 2, 1, 2, 2, bytes(512))), 16)

    def test_intensity_formats(self):
        self.assertEqual(T.decode(bytes([0xF0]), 4, 0, 2, 1), bytes((255,) * 4 + (0, 0, 0, 255)))
        self.assertEqual(T.decode(bytes([0x7F]), 4, 1, 1, 1), bytes((0x7F, 0x7F, 0x7F, 255)))
        self.assertEqual(T.decode(bytes([0xF0]), 3, 1, 1, 1), bytes((255, 255, 255, 0)))
        self.assertEqual(T.decode(bytes([0x40, 0x20]), 3, 2, 1, 1), bytes((0x40, 0x40, 0x40, 0x20)))
        self.assertEqual(T.decode(bytes([0xF1]), 3, 0, 2, 1), bytes((255, 255, 255, 255, 0, 0, 0, 255)))
        # Odd-width 4-bit rows start on byte boundaries.
        self.assertEqual(len(T.decode(bytes([0xF0, 0xF0]), 4, 0, 1, 2)), 8)

    def test_errors(self):
        with self.assertRaises(T.TextureError):
            T.decode(bytes(3), 0, 2, 2, 1)
        with self.assertRaises(T.TextureError):
            T.decode(bytes(8), 1, 2, 2, 1)

    def test_png(self):
        png = T.to_png(bytes(8), 0, 2, 2, 2)
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        idat = png.index(b"IDAT")
        size = struct.unpack(">I", png[idat - 4:idat])[0]
        self.assertEqual(len(zlib.decompress(png[idat + 4:idat + 4 + size])), 2 * (1 + 2 * 4))

    def test_names(self):
        self.assertEqual(T.parse_format("ci4"), (2, 0))
        self.assertEqual(T.format_name(3, 2), "IA16")


class DimensionTests(unittest.TestCase):
    def test_vertical_coherence(self):
        # 32x16 I8 image of vertical stripes: only the true width keeps columns aligned.
        row = bytes((x * 37) & 0xFF for x in range(32))
        guesses = T.guess_dimensions(row * 16, 1)
        self.assertEqual((guesses[0].width, guesses[0].height), (32, 16))

    def test_size_only(self):
        g = T.guess_dimensions(2048, 2)
        self.assertEqual((g[0].width, g[0].height), (32, 32))


if __name__ == "__main__":
    unittest.main()
