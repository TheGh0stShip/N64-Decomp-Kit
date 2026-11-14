import csv
import struct
import unittest

from n64dk import fixtures
from n64dk.assets import gbi


def dl(*cmds):
    return b"".join(struct.pack(">II", a, b) for a, b in cmds)


ENDDL1 = (0xB8000000, 0)
ENDDL2 = (0xDF000000, 0)


def vtx_f3dex(addr, n, v0):
    return (0x04000000 | (v0 * 2) << 16 | n << 10 | (n * 16 - 1), addr)


def vtx_f3d(addr, n, v0):
    return (0x04000000 | ((n - 1) << 4 | v0) << 16 | n * 16, addr)


def vtx_f3dex2(addr, n, v0):
    return (0x01000000 | n << 12 | (v0 + n) << 1, addr)


class DecodeTests(unittest.TestCase):
    def test_vertex_encodings(self):
        c = gbi.decode(*vtx_f3dex(0x06000100, 29, 0), "f3dex")
        self.assertEqual((c.name, c.fields["n"], c.fields["v0"], c.ref), ("G_VTX", 29, 0, ("vtx", 0x06000100, 464)))
        self.assertIsNone(c.error)
        c = gbi.decode(*vtx_f3d(0x06000100, 16, 0), "f3d")
        self.assertEqual((c.fields["n"], c.fields["v0"]), (16, 0))
        c = gbi.decode(*vtx_f3dex2(0x06000100, 8, 4), "f3dex2")
        self.assertEqual((c.fields["n"], c.fields["v0"], c.ref[2]), (8, 4, 128))
        self.assertIsNotNone(gbi.decode(0x04001234, 0x100, "f3dex").error)

    def test_triangles(self):
        self.assertEqual(gbi.decode(0xBF000000, 0x00000204, "f3dex").fields["v"], [0, 1, 2])
        self.assertEqual(gbi.decode(0xBF000000, 0x000A141E, "f3d").fields["v"], [1, 2, 3])
        self.assertEqual(gbi.decode(0x06000204, 0x00060402, "f3dex2").fields["v"], [0, 1, 2, 3, 2, 1])
        self.assertEqual(gbi.decode(0xB1000204, 0x00060402, "f3dex").name, "G_TRI2")
        self.assertEqual(gbi.decode(0xB1000204, 0x00060402, "f3d").name, "0xB1")

    def test_texture_commands(self):
        c = gbi.decode(0xFD500000, 0x00000100, "f3dex")
        self.assertEqual((c.fields["fmt"], c.fields["siz"], c.fields["width"]), (2, 2, 1))
        c = gbi.decode(0xF5400800, 0x00098060, "f3dex")
        self.assertEqual((c.fields["fmt"], c.fields["siz"], c.fields["line"], c.fields["tmem"]), (2, 0, 4, 0))
        c = gbi.decode(0xF3000000, 0x073FF200, "f3dex")
        self.assertEqual((c.fields["tile"], c.fields["texels"]), (7, 1024))
        c = gbi.decode(0xF0000000, 0x0703C000, "f3dex")
        self.assertEqual(c.fields["count"], 16)
        c = gbi.decode(0xE200001C, 0x00552078, "f3dex2")  # 2.x othermode encoding
        self.assertEqual((c.fields["shift"], c.fields["length"]), (3, 29))

    def test_s2dex_tables(self):
        self.assertEqual(gbi.opcode_name(0x02, "s2dex"), "G_BG_COPY")
        self.assertEqual(gbi.opcode_name(0x0A, "s2dex2"), "G_BG_COPY")
        self.assertEqual(gbi.opcode_name(0xDF, "s2dex2"), "G_ENDDL")


class WalkTests(unittest.TestCase):
    def test_sub_dl_segments_and_texture(self):
        # Root at 0 calls a sub-list through segment 6 (set by G_MOVEWORD), then draws.
        root = dl((0xBC001806, 0x00000100),           # segment 6 -> physical 0x100
                  (0x06000000, 0x06000000),           # G_DL push -> seg6+0
                  vtx_f3dex(0x00000200, 3, 0),
                  (0xBF000000, 0x00000204),
                  (0xFD100000, 0x00000300),           # RGBA16 image at 0x300
                  (0xF5100000, 0x07000000),
                  (0xE6000000, 0),
                  (0xF3000000, 0x0701F800),           # 32 texels... -> 64 bytes (16-bit)
                  (0xE7000000, 0),
                  (0xF5101000, 0x00000000),           # render tile 0, line 2 (8 texels)
                  (0xF2000000, 0x0001C00C),           # 8x4
                  (0xBF000000, 0x00000204),
                  ENDDL1)
        data = bytearray(0x400)
        data[:len(root)] = root
        sub = dl((0xE7000000, 0), ENDDL1)
        data[0x100:0x100 + len(sub)] = sub
        r = gbi.walk(gbi.Memory(bytes(data)), 0, "f3dex")
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(r.end, len(root))
        self.assertEqual(r.sub_dls, [(0x06000000, 0x100)])
        self.assertEqual(r.vertices, [(0x200, 0x200, 3)])
        self.assertEqual(r.triangles, 2)
        t = r.textures[0]
        self.assertEqual((t.offset, t.nbytes, t.format, t.width, t.height), (0x300, 64, "RGBA16", 8, 4))

    def test_errors(self):
        data = dl((0xBF000000, 0x00000204), ENDDL1)
        r = gbi.walk(data, 0, "f3dex")
        self.assertFalse(r.ok)
        self.assertIn("never loaded", r.errors[0])
        data = dl(vtx_f3dex(0x00001000, 2, 0), ENDDL1)
        self.assertFalse(gbi.walk(data, 0, "f3dex").ok)  # out of bounds

    def test_find_and_detect(self):
        junk = b"\x11" * 1024  # 0x11 is not an opcode in any family
        dlist = dl((0xE7000000, 0), vtx_f3dex2(0x06000000, 3, 0), (0x05000204, 0), ENDDL2)
        data = junk + dlist + junk
        found = gbi.find_display_lists(data, "f3dex2")
        self.assertEqual([(r.start, r.end) for r in found], [(len(junk), len(junk) + len(dlist))])
        self.assertEqual(gbi.detect_family(data), "f3dex2")

    def test_partition(self):
        blob = dl(vtx_f3dex(0x18, 1, 0), (0xB8000000, 0), (0xE7000000, 0)) + bytes(16)
        blobs, gaps = gbi.partition_blobs(blob * 3 + bytes(8), "f3dex")
        self.assertEqual([(b.start, b.end) for b in blobs], [(0, 40), (40, 80), (80, 120)])
        self.assertEqual(gaps, [(120, 128)])

    def test_find_pools_without_bounds(self):
        blob = dl(vtx_f3dex(0x18, 1, 0), (0xB8000000, 0), (0xE7000000, 0)) + bytes(16)
        junk = b"\x11" * 1024
        pools = gbi.find_blob_pools(junk + blob * 5 + junk, "f3dex")
        self.assertEqual([(p.start, p.end, len(p.blobs)) for p in pools], [(1024, 1024 + 200, 5)])
        self.assertEqual(gbi.find_blob_pools(junk + blob * 2 + junk, "f3dex"), [])  # below min_blobs


def _truth_dir():
    path = fixtures.truth("battletanx_models")
    return path if path and path.is_dir() else None


@unittest.skipUnless(fixtures.rom_paths().get("battletanx"), "BattleTanx ROM not configured")
class BattleTanxPools(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rom = fixtures.rom("battletanx").data

    def test_geometry_pool(self):
        blobs, gaps = gbi.partition_blobs(self.rom, "f3dex", 0x3EA970, 0x49C740)
        # 4756 indexed models plus 19 well-formed blobs no level index references.
        self.assertEqual(len(blobs), 4775)
        self.assertEqual(gaps, [])
        self.assertEqual((blobs[0].start, blobs[0].end), (0x3EA970, 0x3EAC08))
        w = blobs[0].walk
        self.assertEqual((len(w.commands), len(w.vertices), w.triangles), (19, 2, 16))

    def test_texture_pool(self):
        blobs, gaps = gbi.partition_blobs(self.rom, "f3dex", 0x5A1110, 0x6F9C40)
        self.assertEqual(len(blobs), 561)
        self.assertEqual(gaps, [(0x6F9C38, 0x6F9C40)])
        t = blobs[1].walk.textures[0]
        self.assertEqual((t.offset, t.format, t.width, t.height, t.palette_offset, t.palette_count),
                         (0x5A22B8, "CI4", 64, 64, 0x5A2290, 16))

    def test_pools_found_without_bounds(self):
        pools = {(p.start, p.end): len(p.blobs) for p in gbi.find_blob_pools(self.rom, "f3dex")}
        self.assertEqual(pools.get((0x3EA970, 0x49C740)), 4775)
        self.assertEqual(pools.get((0x5A1110, 0x6F9C38)), 561)

    def test_against_index(self):
        truth = _truth_dir()
        if truth is None:
            self.skipTest("roms.toml [truth] battletanx_models not configured")
        blobs = gbi.partition_blobs(self.rom, "f3dex", 0x3EA970, 0x49C740)[0]
        mine = {(b.start, b.end) for b in blobs}
        with open(truth / "models.tsv") as fh:
            rows = list(csv.DictReader(fh, delimiter="\t"))
        self.assertTrue(all((int(r["rom_start"], 16), int(r["rom_end"], 16)) in mine for r in rows))


if __name__ == "__main__":
    unittest.main()
