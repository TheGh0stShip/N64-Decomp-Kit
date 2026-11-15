import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from n64dk.match import images as im

CONFIG = """
[images.resident]
path = "main.bin"
vram_delta = 0x80000000
catalogue = "resident.txt"
manifests = ["resident.tsv"]
raw_segments = [[0x1000, 0x0, 0x100, "copy"]]
aliases = ["main"]

[images.ovA]
path = "ova.bin"
vram_delta = 0x80000000
catalogue = "ova.txt"
catalogue_shift = 0x100
manifests = ["ova.tsv"]
raw_segments = [[0x5000, 0x200, 0x200, "lzss"]]
aliases = ["overlay", "a"]

[images.ovB]
path = "ovb.bin"
vram_delta = 0x80000000
catalogue = "ovb.txt"
aliases = ["overlay"]
"""


class ImagesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        (root / "n64dk.toml").write_text(CONFIG)
        for name in ("main.bin", "ova.bin", "ovb.bin"):
            (root / name).write_bytes(bytes(0x400))
        (root / "resident.txt").write_text("r0 = 0x80000000; // type:func size:0x100\n")
        # overlay A's catalogue is 0x100 above its link addresses; B is in link space
        (root / "ova.txt").write_text("a0 = 0x80000300; // type:func size:0x40\n"
                                      "a1 = 0x80000340; // type:func size:0x40\n")
        (root / "ovb.txt").write_text("b0 = 0x80000200; // type:func size:0x80\n")
        (root / "resident.tsv").write_text("0x0\t0x100\tsrc/r0.c\t-O2\n")
        (root / "ova.tsv").write_text("0x200\t0x40\tsrc/a0.c\t-O2\n")
        self.root = root

    def tearDown(self):
        self.tmp.cleanup()

    def test_resolve_fail_closed(self):
        self.assertEqual(im.resolve(self.root, "main").name, "resident")
        self.assertEqual(im.resolve(self.root, "a").name, "ovA")
        with self.assertRaises(im.ImageError) as ctx:
            im.resolve(self.root, "main.bin")                       # never a file name
        self.assertIn("known images", str(ctx.exception))
        self.assertIn("ovB", str(ctx.exception))
        with self.assertRaises(im.ImageError) as ctx:
            im.resolve(self.root, "overlay")
        self.assertIn("ambiguous", str(ctx.exception))
        self.assertIn("ovA, ovB", str(ctx.exception))

    def test_explain_catalogue_shift(self):
        out = im.explain(self.root, "ovA", vram=0x80000300)
        self.assertEqual(out["link_vram"], "0x80000200")
        self.assertIn("catalogue row starts", out["why"])
        self.assertEqual(out["manifest_rows"][0]["source"], "src/a0.c")
        self.assertEqual(out["catalogue_rows"][0]["id"], "ovA:0x80000200:0x40")
        self.assertEqual(out["raw_rom"], "not representable: compressed segment (lzss) rom 0x00005000")
        self.assertEqual([o["image"] for o in out["other_images_mapping_this_vram"]], ["ovB"])
        link = im.explain(self.root, "ovA", vram=0x80000300, space="link")
        self.assertEqual(link["link_vram"], "0x80000300")

    def test_explain_coordinates(self):
        out = im.explain(self.root, "main", offset=0x10)
        self.assertEqual((out["link_vram"], out["raw_rom"]), ("0x80000010", "0x00001010"))
        out = im.explain(self.root, "resident", rom=0x1020)
        self.assertEqual(out["link_vram"], "0x80000020")
        with self.assertRaises(im.ImageError):
            im.explain(self.root, "ovA", rom=0x5004)                # compressed: no linear mapping

    def test_shared_vram_refuses_to_pick(self):
        out = im.explain(self.root, vram=0x80000220)
        self.assertIsNone(out["chosen"])
        self.assertIn("refusing to pick", out["why"])
        self.assertEqual(sorted(h["image"] for h in out["images"]), ["ovA", "ovB"])
        single = im.explain(self.root, vram=0x80000010)
        self.assertEqual(single["chosen"], "resident")

    def test_function_id(self):
        text = im.function_id("ovA", 0x80000200, 0x40)
        self.assertEqual(text, "ovA:0x80000200:0x40")
        self.assertEqual(im.parse_function_id(text), ("ovA", 0x80000200, 0x40))
        with self.assertRaises(ValueError):
            im.parse_function_id("ovA:80000200")

    def test_commands(self):
        from n64dk import cli
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(cli.main(["image-registry", "--project", str(self.root), "overlay"]), 2)
            self.assertEqual(cli.main(["image-address", "--project", str(self.root), "--vram", "0x80000220"]), 3)
            self.assertEqual(cli.main(["image-address", "--project", str(self.root), "--image", "a",
                                       "--vram", "0x80000300"]), 0)
        self.assertIn("ambiguous", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
