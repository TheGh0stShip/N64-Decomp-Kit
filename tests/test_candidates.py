import tempfile
import unittest
from pathlib import Path

from n64dk.commands import candidates

CATALOGUE = '''
[[section]]
vram = 0x80000400
rom = 0
size = 0x60
functions = [
  { name = "render_resource", vram = 0x80000400, size = 0x14 },
  { name = "member_two", vram = 0x80000414, size = 0x14 },
  { name = "alone", vram = 0x80000428, size = 0x10 },
  { name = "asm_owned", vram = 0x80000438, size = 0x10 },
  { name = "free", vram = 0x80000448, size = 0x18 },
]
'''


class ReconcileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = self.root = Path(self.tmp.name)
        (root / "config").mkdir()
        (root / "src").mkdir()
        (root / "config/functions_resident.toml").write_text(CATALOGUE)
        # the image holds the program at file offset 0x1000: manifest offsets are image-file offsets
        (root / "n64dk.toml").write_text('[images.resident]\npath = "image.bin"\nvram_delta = 0x7FFFF400\n')
        (root / "config/matching_kmc_units.tsv").write_text(
            "0x1000\t0x28\tsrc/render_resource.c\t-O2\n0x1028\t0x10\tsrc/alone.c\t-O2\n")
        (root / "config/matching_asm_units.tsv").write_text("0x1038\t0x10\tsrc/asm_owned.s\t\n")
        for name in ("render_resource", "alone"):
            (root / f"src/{name}.c").write_text(f"int {name}(void) {{ return 0; }}\n")
        (root / "src/asm_owned.s").write_text("nop\n")
        for name in ("member_two", "alone_copy", "asm_owned", "free", "stranger"):
            body = {"alone_copy": "alone"}.get(name, name)
            (root / f"src/cand_{name}.c").write_text(f"extern int g;\nint {body}(void) {{\n    return g;\n}}\n")

    def kinds(self, *sources):
        rows = candidates.reconcile(self.root, list(sources))
        return {row["source"]: row for row in rows}

    def test_every_kind_of_candidate(self):
        rows = self.kinds("src/cand_member_two.c", "src/cand_alone_copy.c", "src/cand_asm_owned.c",
                          "src/cand_free.c", "src/cand_stranger.c", "src/missing.c")
        member = rows["src/cand_member_two.c"]
        self.assertEqual(member["classification"], "existing_aggregate_member")
        self.assertEqual((member["owner"], member["owner_interval"]),
                         ("src/render_resource.c", "0x80000400-0x80000428"))
        self.assertEqual((member["new_function_credit"], member["new_c_byte_credit"]), (0, 0))
        self.assertEqual(rows["src/cand_alone_copy.c"]["classification"], "existing_standalone_duplicate")
        conversion = rows["src/cand_asm_owned.c"]
        self.assertEqual((conversion["classification"], conversion["new_c_byte_credit"]),
                         ("assembly_to_c_conversion", 0x10))
        fresh = rows["src/cand_free.c"]
        self.assertEqual((fresh["classification"], fresh["new_function_credit"], fresh["new_c_byte_credit"]),
                         ("new_function", 1, 0x18))
        self.assertEqual(rows["src/cand_stranger.c"]["classification"], "not_in_catalogue")
        self.assertEqual(rows["src/missing.c"]["classification"], "source_missing")

    def test_definitions_not_prototypes_name_the_function(self):
        text = "int helper(int);\nstatic int other(void);\nint real(int a) {\n    if (a) { return helper(a); }\n    return 0;\n}\n"
        self.assertEqual(candidates.defined_functions(text), ["real"])

    def test_summary_keeps_exact_count_and_new_coverage_apart(self):
        import argparse
        result = candidates.candidate_reconcile(argparse.Namespace(
            source=["src/cand_member_two.c", "src/cand_free.c"], project=str(self.root), sources_untracked=False,
            image_name=None, recompile=False, pipeline=None, flags=None, jobs=1, timeout=10))
        summary = result["summary"]
        self.assertIsNone(summary["compiled_exact"])                      # nothing was compiled, and it says so
        self.assertIn("not compiled", summary["null_reason"])
        self.assertEqual((summary["would_be_new_if_exact"], summary["aggregate_duplicates"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
