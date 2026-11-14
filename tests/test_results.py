import json
import tempfile
import unittest
from pathlib import Path

from n64dk.match.results import ResultIndex


class ResultIndexTests(unittest.TestCase):
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
