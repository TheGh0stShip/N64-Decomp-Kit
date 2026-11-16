"""Hardening regression for tranche accounting (review finding F16)."""
from __future__ import annotations

import argparse
import struct
import tempfile
import unittest
from pathlib import Path


class TrancheLimitTests(unittest.TestCase):
    def test_limit_counts_only_runnable_rows_and_reports_funnel(self):
        from n64dk.commands.autonomy import _sweep_args, quickwin_sweep
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "config").mkdir()
            small = struct.pack(">III", 0x27BDFFF0, 0x03E00008, 0x27BD0010)            # 12 bytes
            large = struct.pack(">IIIIII", 0x27BDFFE8, 0xAFB00010, 0x00008025,
                                0x8FB00010, 0x03E00008, 0x27BD0018)                     # 24 bytes
            image = bytearray(0x100)
            image[0x00:0x0C] = small; image[0x0C:0x18] = small
            image[0x18:0x30] = large; image[0x30:0x48] = large
            (root / "image.bin").write_bytes(bytes(image))
            (root / "config/functions_main.toml").write_text(
                '[[section]]\nvram = 0x80000000\nrom = 0\nsize = 0x100\nfunctions = [\n'
                ' { name = "func_80000000", vram = 0x80000000, size = 0xC },\n'
                ' { name = "func_8000000C", vram = 0x8000000C, size = 0xC },\n'
                ' { name = "func_80000018", vram = 0x80000018, size = 0x18 },\n'
                ' { name = "func_80000030", vram = 0x80000030, size = 0x18 },\n]\n')
            (root / ".tmp").mkdir()
            for vram in (0x80000018, 0x80000030):
                (root / f".tmp/func_{vram:08X}_candidate.c").write_text(
                    f"int func_{vram:08X}(void) {{ return 0; }}\n")
            parser = argparse.ArgumentParser()
            _sweep_args(parser)
            args = parser.parse_args(["--project", str(root), "--limit", "1", "--state-root",
                                      str(root / "sweeps"), "--image-file", f"main={root / 'image.bin'}",
                                      "--pipeline", "kmc+as", "--flags=-O2"])
            args.format = "json"
            result = quickwin_sweep(args)
            funnel = result["funnel"]
            # the two smallest (highest-ranked) rows have no source: they must not use up --limit
            self.assertEqual(funnel["ready"], 1, funnel)
            self.assertEqual(funnel["selected"], 1)
            self.assertEqual(funnel["source_missing"], 2)
            self.assertEqual(funnel["catalogue_rows"], 4)
            self.assertEqual(result["status"], {"ready_verified": 1})


if __name__ == "__main__":
    unittest.main()
