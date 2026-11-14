import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from n64dk.commands.workbench import _load_matrix, family_session_start, scheduler_plan
from n64dk.match.session import SessionStore
from n64dk.match.controlflow import classify_branches, variants
import struct
import subprocess

from n64dk.commands.workbench import _restore_worktree_snapshot, _worktree_snapshot


class WorkbenchTests(unittest.TestCase):
    def test_matrix_yaml_subset(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "matrix.yaml"
            path.write_text("hypothesis: ABI width\naxes:\n  helper_return: [\"s16\", \"u16\"]\n")
            value = _load_matrix(str(path))
            self.assertEqual(value["axes"]["helper_return"], ["s16", "u16"])

    def test_capabilities_are_option_granular(self):
        with tempfile.TemporaryDirectory() as name:
            store = SessionStore(name)
            try:
                store.record_flag("kmc+asn64", "-fno-example", False, "rejected")
                self.assertFalse(store.flag_supported("kmc+asn64", "-fno-example"))
                self.assertIsNone(store.flag_supported("kmc+asn64", "-O2"))
                self.assertEqual(store.invalidate_capabilities(option="-fno-example"), 1)
            finally:
                store.close()

    def test_family_and_scheduler_are_persistent(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); unit = root / "unit.c"; unit.write_text("int a(void){return 0;}\n")
            family = family_session_start(Namespace(project=str(root), unit="unit.c", functions="a,b"))
            self.assertTrue((root / ".n64dk/group-sessions.sqlite").is_file())
            plan = scheduler_plan(Namespace(project=str(root), jobs=2, gpu=False, limit=10))
            self.assertIn("plan_id", plan)
            self.assertTrue((root / ".n64dk/scheduler.sqlite").is_file())

    def test_branch_exit_classification_and_control_forms(self):
        with tempfile.TemporaryDirectory() as name:
            image = Path(name) / "image.bin"
            image.write_bytes(struct.pack(">IIII", 0x10000003, 0, 0, 0))
            context = {"rom": str(image), "addr": 0x80000000, "size": 16,
                       "vram_delta": 0x80000000}
            outcome = {"diff": {"entries": [{"kind": "instruction", "target_offset": 0,
                                               "compiled": "beql ...", "retail": "beq ..."}]}}
            classified = classify_branches(context, outcome)
            self.assertEqual(classified[0]["classification"], "loop-exit")
            generated = variants("void f(void) {\nlabel:\nif (x) { call(); }\n}\n")
            self.assertTrue(any(row["form"] == "goto-shared-exit" for row in generated))

    def test_integration_rollback_preserves_preexisting_worktree_edits(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            tracked = root / "tracked.txt"; tracked.write_text("base\n")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
                            "commit", "-qm", "base"], cwd=root, check=True)
            tracked.write_text("preexisting\n")
            loose = root / "notes.txt"; loose.write_text("keep\n")
            before, untracked = _worktree_snapshot(root)
            tracked.write_text("hook changed\n"); loose.write_text("hook changed\n")
            (root / "generated.txt").write_text("generated\n")
            _restore_worktree_snapshot(root, before, untracked)
            self.assertEqual(tracked.read_text(), "preexisting\n")
            self.assertEqual(loose.read_text(), "keep\n")
            self.assertFalse((root / "generated.txt").exists())


if __name__ == "__main__":
    unittest.main()
