"""Every function of a title gets one cause after a source tree was offered to it."""
import json
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk.match import treeaccount


def words(*values):
    return struct.pack(f">{len(values)}I", *values)


class AccountTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="n64dk-test-account-"))
        folder = self.root / "tree_x"
        (folder / "split").mkdir(parents=True)
        # tree unit src/a.c: f1 f2 f3 f4 f5 in source order; f3 compiled, f4 has inline asm, f5 not compiled
        f1, f2, f3 = words(0x24020001, 0x03E00008, 0), words(0x24020002, 0x03E00008, 0), words(0x24020003, 0x03E00008, 0)
        donor_image = f1 + f2 + f3
        (folder / "image.bin").write_bytes(donor_image)
        (folder / "manifest.kmc_as.tsv").write_text(
            "# test\n0x0\t0xC\tsrc/a/f1.c\t-O2\n0xC\t0xC\tsrc/a/f2.c\t-O2\n0x18\t0xC\tsrc/a/f3.c\t-O2\n")
        (folder / "split" / "order.json").write_text(json.dumps({
            "order": {"src/a.c": ["f1", "f3", "f4", "f5", "f2"]},
            "excluded": {"src/a.c": {"f4": "inline assembly in its body"}}}))
        # the title: f1 at 0x100, then three functions, f2 at 0x130, then one more (no tree C)
        title = words(0x24020001, 0x03E00008, 0, 0x24020009, 0x03E00008, 0, 0x24020004, 0x03E00008, 0,
                      0x24020005, 0x03E00008, 0, 0x24020002, 0x03E00008, 0, 0x24020007, 0x03E00008, 0)
        self.functions = [("func_80000100", 0x80000100, 12), ("func_8000010C", 0x8000010C, 12),
                          ("func_80000118", 0x80000118, 12), ("func_80000124", 0x80000124, 12),
                          ("func_80000130", 0x80000130, 12), ("func_8000013C", 0x8000013C, 12)]
        self.images = [("main", title, 0x80000100, self.functions)]
        run = self.root / "run" / "main" / "donors"
        run.mkdir(parents=True)
        run.joinpath("report.json").write_text(json.dumps({"rows": [
            {"donor": "tree_x", "donor_unit": "src/a/f1.c", "functions": ["func_80000100"],
             "verdict": "exact-with-transferred-symbols"},
            {"donor": "tree_x", "donor_unit": "src/a/f2.c", "functions": ["func_80000130"],
             "verdict": "identical-awaiting-symbols"}], "needs_review": [], "near_hits": []}))

    def test_every_function_gets_one_cause(self):
        found = treeaccount.account_images(self.images, self.root / "run", self.root / "tree_x", "tree_x")
        causes = {row["function"]: row["cause"] for row in found["rows"]}
        self.assertEqual(causes, {"func_80000100": "strict", "func_8000010C": "tree-function-differs",
                                  "func_80000118": "tree-function-assembly", "func_80000124": "tree-function-not-compiled",
                                  "func_80000130": "awaiting-symbols", "func_8000013C": "no-tree-function"})
        detail = next(row for row in found["rows"] if row["function"] == "func_8000010C")
        self.assertEqual((detail["tree_function"], detail["detail"]), ("f3", "same length, 1 of 2 words differ"))
        self.assertEqual(found["functions"], 6)
        self.assertEqual(sum(found["causes"].values()), 6)

    def test_counts_that_do_not_agree_place_nothing(self):
        self.images[0][3].insert(2, ("func_extra", 0x80000112, 4))     # one more title function in the gap
        found = treeaccount.account_images(self.images, self.root / "run", self.root / "tree_x", "tree_x")
        causes = Counter(row["cause"] for row in found["rows"])
        self.assertEqual(causes["no-tree-function"], 5)


from collections import Counter  # noqa: E402

if __name__ == "__main__":
    unittest.main()


class WholeUnitDonorTest(AccountTest):
    def test_a_function_verified_through_the_whole_unit_donor_counts_for_the_tree(self):
        report = self.root / "run" / "main" / "donors" / "report.json"
        found = json.loads(report.read_text())
        found["rows"].append({"donor": "tree_x_units", "donor_unit": "src/a.c", "functions": ["func_8000013C"],
                              "verdict": "exact-with-transferred-symbols"})
        report.write_text(json.dumps(found))
        alone = treeaccount.account_images(self.images, self.root / "run", self.root / "tree_x", "tree_x")
        both = treeaccount.account_images(self.images, self.root / "run", self.root / "tree_x",
                                          {"tree_x", "tree_x_units"})
        cause = lambda result: next(r for r in result["rows"] if r["function"] == "func_8000013C")   # noqa: E731
        self.assertEqual(cause(alone)["cause"], "other-donor")
        self.assertEqual((cause(both)["cause"], cause(both)["via"]), ("strict", "tree_x_units"))
