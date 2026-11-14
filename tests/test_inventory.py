from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk.match import context, inventory


class InventoryTests(unittest.TestCase):
    def test_interval_coverage_aggregate_units_and_exclusions(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = root / "config/us"
            config.mkdir(parents=True)
            (config / "functions_main.toml").write_text("""
[[section]]
name = ".main"
rom = 0x100
vram = 0x80001000
size = 0x100
functions = [
 { name = "first", vram = 0x80001000, size = 0x10 }, # c
 { name = "second", vram = 0x80001010, size = 0x10 }, # asm
 { name = "shared_tail", vram = 0x80001020, size = 0x8 }, # asm shared epilogue
 { name = "remaining", vram = 0x80001030, size = 0x20 }, # asm
]
""")
            (config / "matching_main_kmc_units.tsv").write_text(
                "# rows\n0x100\t0x20\tsrc/aggregate.c\t-O2\n")
            (config / "matching_main_asm_units.tsv").write_text(
                "# rows\n0x120\t0x8\tsrc/shared_tail.s\t-O2\n"
                "0x130\t0x20\tsrc/remaining.s\t-O2\n")
            candidate = root / ".tmp/remaining_candidate.c"
            candidate.parent.mkdir()
            candidate.write_text("int remaining(void) { return 0; }\n")
            result = inventory.build(root)
            rows = {row["name"]: row for row in result["functions"]}
            self.assertEqual(rows["first"]["state"], "covered")
            self.assertEqual(rows["second"]["state"], "covered")
            self.assertEqual(rows["shared_tail"]["state"], "excluded")
            self.assertEqual(rows["remaining"]["state"], "remaining")
            self.assertEqual(rows["remaining"]["candidate_source"], ".tmp/remaining_candidate.c")

    def test_splat_metadata_and_context_bundle(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "splat.yaml").write_text("""
options:
  target_path: build/game.z64
  symbol_addrs_path: config/symbol_addrs.txt
  compiler: KMC
segments:
  - [0x1000, c, code/main]
""")
            self.assertEqual(inventory.build(root)["splat"][0]["compiler"], "KMC")
            image = root / "image.bin"
            image.write_bytes(struct.pack(">III", 0x0C000408, 0, 0x03E00008))
            result = context.bundle(image, 0x80001000, 12)
            self.assertEqual(result["callees"], ["0x80001020"])
            self.assertEqual(len(result["disassembly"]), 3)


if __name__ == "__main__":
    unittest.main()
