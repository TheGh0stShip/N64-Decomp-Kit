import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from n64dk.commands.autonomy import quickwin_sweep


class _Context:
    def __init__(self, project, mappings, refresh=False, inventory_snapshot=None):
        self.project = Path(project)
        base = {"image": "main", "state": "remaining", "vram": "0x80001000", "size": 12,
                "rank": 1.0, "reason": "fixture", "candidate_source": None,
                "section_rom": "0x0", "section_vram": "0x80001000",
                "section_size": 24, "catalogue_status": "", "rom": "0x0"}
        self.inventory = inventory_snapshot or {"project": str(self.project), "source_index": {},
            "functions": [{**base, "id": "missing", "name": "missing"},
                          {**base, "id": "ready", "name": "ready",
                           "vram": "0x8000100C", "rom": "0xC",
                           "candidate_source": "ready.c"}]}
        self.metrics = {"context_seconds": 0.0}

    def preflight(self, row, strict=True):
        return {"ok": True, "selected_image_offset": row["rom"],
                "mapping": {"linked_vram": row["vram"], "linked_base": "0x80001000",
                            "target_digest": "a" * 64}}

    def infer_recipe(self, row, pipeline=None, flags=None):
        return {"pipeline": "kmc+builtin", "flags": ["-O2"],
                "confidence": 0.9, "evidence": "fixture"}

    def validate_source(self, row):
        if row["id"] == "ready":
            return {"ok": True, "path": str(self.project / "ready.c"),
                    "digest": "b" * 64}
        return {"ok": False, "state": "source_missing", "reason": "no source"}

    def snapshot(self):
        return {"fixture": True}

    def close(self):
        pass


class AutonomyTest(unittest.TestCase):
    def test_tranche_limit_selects_only_runnable_targets(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root / "ready.c").write_text("void ready(void) {}\n")
            args = Namespace(project=name, all_images=True, image=[], limit=1, jobs=1,
                state_root=str(root / "state"), resume=None, report=None, run=False,
                image_file=[f"main={root / 'image.bin'}"], pipeline=None, flags=None,
                refresh_sources=False, run_ready_only=False, draft_missing=False,
                m2c_context=None, details=True, events=None)
            with mock.patch("n64dk.commands.autonomy.ProjectContext", _Context):
                result = quickwin_sweep(args)
            self.assertEqual(result["requested_ready"], 1)
            self.assertEqual(result["ready_selected"], 1)
            self.assertEqual(result["selected"], 1)
            self.assertEqual(result["items"][0]["name"], "ready")
            self.assertEqual(result["preflight_exclusions"]["counts"],
                             {"source_missing": 1})


if __name__ == "__main__":
    unittest.main()
