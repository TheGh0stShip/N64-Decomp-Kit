import json
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk.match.results import ResultIndex


class ResultIndexTests(unittest.TestCase):
    def test_live_validity_detects_removed_source_mapping_and_manifest_state(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); audit = root / "build/us/audit"; audit.mkdir(parents=True)
            raw = bytearray(0x1100); code = struct.pack(">III", 0x24020000, 0x03E00008, 0)
            raw[0x1010:0x101C] = code; (audit / "overlay_4.z64").write_bytes(raw)
            composite = bytearray(0x4000); struct.pack_into(">I", composite, 8, 0x80000400)
            composite[0x2000:0x2100] = raw[0x1000:0x1100]
            image = audit / "overlay_4_composite.z64"; image.write_bytes(composite)
            source = root / "candidate.c"; source.write_text("int func_80002010(void){return 0;}\n")
            inventory = {"functions": [{"name": "func_80002010", "image": "overlay4",
                "vram": "0x80002010", "size": 12, "section_vram": "0x80002000",
                "section_rom": "0x1000", "section_size": 0x100,
                "coverage_authority": "manifest"}]}
            index = ResultIndex(root / "results.sqlite")
            try:
                index.record_direct({"exact": True, "sha256_text": "f" * 64},
                    {"addr": 0x80002010, "size": 12, "rom_sha256": hashlib.sha256(composite).hexdigest(),
                     "target_text_sha256": "e" * 64, "vram_delta": 0x80001000},
                    source, "func_80002010", "valid_current_target")
                source.unlink()
                current = index.query(function="func_80002010", project=root, inventory=inventory)
                rows = index.query(function="func_80002010", project=root, inventory=inventory,
                                   stale_mapping=True)
                absent = index.query(function="func_80002010", project=root, inventory=inventory,
                                     not_in_manifest=True)
            finally: index.close()
            self.assertEqual(current, [])
            self.assertEqual(rows[0]["observation_class"], "exact_stale_target")
            self.assertFalse(rows[0]["live_validity"]["source_digest_resolves"])
            self.assertFalse(rows[0]["live_validity"]["mapping_transform_current"])
            self.assertEqual(absent, [])

    def test_stale_mapping_excluded_and_residuals_cluster(self):
        inventory = {"functions": [
            {"name": "func_80001000", "vram": "0x80001000", "size": 16,
             "section_vram": "0x80001000", "section_rom": "0x100"},
            {"name": "func_80001010", "vram": "0x80001010", "size": 16,
             "section_vram": "0x80001000", "section_rom": "0x100"},
        ]}
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "results.json").write_text(json.dumps([
                {"function": "func_80001000", "score": 1, "size": 16,
                 "vram_delta": 0, "counts": {"branch": 1}},
                {"function": "func_80001000", "score": 8, "size": 16,
                 "vram_delta": 0x80000F00, "counts": {"branch": 1}},
                {"function": "func_80001010", "score": 8, "size": 16,
                 "vram_delta": 0x80000F00, "counts": {"branch": 1}},
            ]))
            index = ResultIndex(root / "index.sqlite")
            try:
                stats = index.index([str(root)], inventory)
                normal = index.query(function="func_80001000")
                stale = index.query(function="func_80001000", stale_mapping=True)
                clusters = index.clusters()
            finally:
                index.close()
            self.assertEqual(stats["invalid"], 1)
            self.assertEqual(normal[0]["score"], 8)
            self.assertEqual(normal[0]["validity"], "valid_current_target")
            self.assertEqual(stale[0]["score"], 1)
            self.assertEqual(len(clusters[0]["functions"]), 2)


if __name__ == "__main__":
    unittest.main()
