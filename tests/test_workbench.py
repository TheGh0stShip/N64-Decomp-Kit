import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from n64dk.commands.workbench import (_load_matrix, code_query, compiler_explain,
                                      family_session_start, scheduler_plan)
from n64dk.match.session import SessionCandidate, SessionStore
from n64dk.match.controlflow import classify_branches, variants
from n64dk.match.typed_explore import (declaration_context, lifetime_graph,
                                        narrowing_variants, prototype_variants,
                                        source_shape)
from n64dk.match.typed_explore import call_chain_variants, call_result_ownership
from n64dk.match.project_context import ProjectContext
from n64dk.match.reconstruct import scaffold, shared_layout, prototype_constraints
from n64dk.match.corpus import CorpusIndex
import struct
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from n64dk.commands.workbench import _restore_worktree_snapshot, _worktree_snapshot


class WorkbenchTests(unittest.TestCase):
    def _compiler_session(self, root):
        store = SessionStore(root); session = store.create({"source_name": "fixture.c"})
        ids = []
        for index in range(2):
            source = f"int f(void){{return {index};}}\n".encode(); digest = store.cache.put(source)
            candidate = SessionCandidate(f"candidate-{index}", None, digest, f"candidate-{index}",
                "fixture", "kmc+asn64", (), "evaluated", False, index + 1,
                {"register": index + 1}, {"sha256_text": str(index), "diff": {"entries": []}},
                None, time.time_ns() + index)
            store.append(session, candidate); ids.append(candidate.candidate_id)
        store.close(); return session, ids

    def test_compiler_explain_single_pair_missing_and_stale(self):
        with tempfile.TemporaryDirectory() as name:
            session, ids = self._compiler_session(name)
            common = {"session_id": session, "project": name, "state_root": name,
                      "passes": "greg,lreg,sched", "artifact_dir": None}
            single = compiler_explain(Namespace(**common, candidate=[ids[0]],
                from_candidate=None, to_candidate=None))
            self.assertEqual(single["mode"], "single")
            pair = compiler_explain(Namespace(**common, candidate=None,
                from_candidate=ids[0], to_candidate=ids[1]))
            self.assertEqual(pair["mode"], "pairwise")
            with self.assertRaisesRegex(ValueError, "unknown or stale"):
                compiler_explain(Namespace(**common, candidate=["missing"],
                    from_candidate=None, to_candidate=None))
            store = SessionStore(name); stale = store.get(session, ids[0]); store.cache.path(stale.source_digest).unlink(); store.close()
            with self.assertRaisesRegex(ValueError, "stale candidate"):
                compiler_explain(Namespace(**common, candidate=[ids[0]],
                    from_candidate=None, to_candidate=None))

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

    def test_typed_exploration_covers_abi_call_use_narrowing_and_lifetime(self):
        source = ("extern s32 func_800E2480(void);\n"
                  "s32 func_800E1E74(void) {\n"
                  "    s32 result = func_800E2480();\n"
                  "    if ((s16)result != 0) return result;\n"
                  "    return 0;\n}\n")
        prototypes = prototype_variants(source, "func_800E2480", ["void", "s16", "s32"], 96)
        axes = [row["axes"] for row in prototypes]
        self.assertTrue(any(row.get("style") == "implicit" for row in axes))
        self.assertTrue(any(row.get("arguments") == "s16 arg0" for row in axes))
        self.assertTrue(any(row.get("call_use") == "narrowed" for row in axes))
        self.assertTrue(narrowing_variants(source))
        self.assertEqual(declaration_context(source, "func_800E2480")[0]["return"], "s32")
        self.assertEqual(source_shape(source), source_shape(source.replace("result", "value")))
        outcome = {"diff": {"entries": [{"retail": "jal func_800E2480"},
                    {"retail": "addu $s0, $v0, $zero"}, {"retail": "sll $s0, $s0, 16"},
                    {"retail": "sra $v0, $s0, 16"}, {"retail": "bnez $v0, 0x80000040"},
                    {"retail": "addu $v0, $zero, $zero"}]}}
        graph = lifetime_graph(outcome)
        self.assertIn("call result remains live across a later call", graph["constraints"])
        self.assertIn("narrowed value controls a branch", graph["constraints"])

    def test_corpus_prototype_distinguishes_declarations_from_calls(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "project"; source = root / "src" / "unit.c"
            source.parent.mkdir(parents=True)
            source.write_text("void helper(void); s16 func_80001000(s32);\n"
                              "s32 use(void) { return (s16)func_80001000(1); }\n")
            index = CorpusIndex(Path(name) / "corpus.sqlite")
            try:
                index.index([root]); inferred = index.infer_prototype("func_80001000")
            finally:
                index.close()
            self.assertEqual(inferred["ranked_prototypes"][0]["return_type"], "s16")
            self.assertEqual(inferred["call_sites"], 1)
            self.assertEqual(inferred["calls"][0]["call_arguments"], 1)

    def test_code_query_uses_standard_library_when_ripgrep_is_unavailable(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); source = root / "src" / "unit.c"
            source.parent.mkdir(); source.write_text("extern void func_80001000(void);\n")
            args = Namespace(project=name, symbol="func_80001000", address=None,
                             type_conflicts=False, all_projects=False, limit=10)
            with mock.patch("n64dk.commands.workbench.shutil.which", return_value=None):
                result = code_query(args)
            self.assertEqual(result["count"], 1)
            self.assertEqual(result["results"][0]["kind"], "declaration")

    def test_project_context_scans_once_and_hashes_each_image_once(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); image = root / "image.z64"; image.write_bytes(b"\0" * 64)
            snapshot = {"project": str(root), "functions": [], "images": [],
                        "source_index": {"elapsed_seconds": 0.0}}
            with mock.patch("n64dk.match.project_context.invmod.build", return_value=snapshot) as build:
                context = ProjectContext(root, {"resident": str(image)})
                first = context.image("resident"); second = context.image("resident")
                context.close()
            self.assertIs(first, second)
            self.assertEqual(build.call_count, 1)
            self.assertEqual(context.metrics["project_scans"], 1)
            self.assertEqual(context.metrics["image_hashes"], 1)

    def test_project_context_keeps_strict_preflights_separate_and_infers_tu_recipe(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); config = root / "config"; config.mkdir()
            manifest = config / "matching_resident_units.tsv"
            manifest.write_text("0x1000\t0x40\tsrc/libultra/unit.c\t-O2 -G0\n")
            image = root / "resident.bin"; image.write_bytes(b"\0" * 0x2000)
            row = {"id": "resident:func_80001010:80001010", "image": "resident",
                   "name": "func_80001010", "vram": "0x80001010", "size": 16,
                   "section_vram": "0x80001000", "section_rom": "0x1000",
                   "section_size": 0x100, "catalogue_status": "complete"}
            snapshot = {"project": str(root), "functions": [row],
                        "images": [{"name": "resident"}], "source_index": {}}
            context = ProjectContext(root, {"resident": str(image)}, inventory_snapshot=snapshot)
            try:
                with mock.patch("n64dk.match.project_context.preflight",
                                side_effect=lambda *_a, strict_entry=True, **_k: {"ok": strict_entry}):
                    self.assertFalse(context.preflight(row, False)["ok"])
                    self.assertTrue(context.preflight(row, True)["ok"])
                recipe = context.infer_recipe(row)
                self.assertEqual(recipe["evidence"], "same verified translation-unit interval")
                self.assertEqual(recipe["source"], "src/libultra/unit.c")
                self.assertEqual(recipe["pipeline"], "kmc+as")
                overridden = context.infer_recipe(row, override_flags="-O1 -G0")
                self.assertEqual(overridden["pipeline"], "kmc+as")
                candidate = root / "caller.c"
                candidate.write_text("void caller(void) { func_80001010(); }\n")
                source_row = {**row, "candidate_source": "caller.c"}
                self.assertEqual(context.validate_source(source_row)["state"], "source_wrong_function")
            finally:
                context.close()

    def test_project_context_history_snapshot_is_worker_safe(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); snapshot = {"project": str(root), "functions": [], "images": [],
                                            "source_index": {}}
            context = ProjectContext(root, inventory_snapshot=snapshot)
            target = {"rom_sha256": "0" * 64, "vram_delta": 0x80000000,
                      "addr": 0x80001000, "size": 16}
            try:
                with ThreadPoolExecutor(max_workers=4) as pool:
                    rows = list(pool.map(lambda _value: context.history(target), range(8)))
                self.assertTrue(all(row == [] for row in rows))
                self.assertEqual(context.metrics["history_scans"], 1)
            finally:
                context.close()

    def test_reconstruction_scaffold_layout_and_prototype_constraints(self):
        code = struct.pack(">III", 0x8C880014, 0x03E00008, 0)
        source, evidence = scaffold("func_80001000", code, 0x80001000)
        self.assertIn("func_80001000", source)
        layout = shared_layout([evidence])
        self.assertEqual(layout["fields"][0]["offset"], 0x14)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); (root / "src").mkdir(); (root / "include").mkdir()
            (root / "src" / "a.c").write_text("extern s16 func_80002000(s32 value);\n")
            (root / "include" / "a.h").write_text("extern s32 func_80002000(s32 value);\n")
            solved = prototype_constraints(root)
            self.assertEqual(len(solved["conflicts"]), 1)

    def test_call_result_ownership_drives_nested_call_decomposition(self):
        outcome = {"diff": {"entries": [
            {"retail": "jal func_800E25D0"}, {"retail": "nop"},
            {"retail": "jal func_800E2480"}, {"retail": "addu $s0, $v0, $zero"},
            {"retail": "sll $s0, $s0, 16"}, {"retail": "bnez $s0, 0x80000040"}]}}
        ownership = call_result_ownership(outcome)
        self.assertEqual(ownership["transfers"][0]["producer"], "func_800E25D0")
        source = "s32 f(void) {\n    status = func_800E2480(func_800E25D0(value));\n    return status;\n}\n"
        generated = call_chain_variants(source, ownership)
        self.assertIn("status = func_800E25D0(value);", generated[0]["source"])
        self.assertIn("func_800E2480();", generated[0]["source"])

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
