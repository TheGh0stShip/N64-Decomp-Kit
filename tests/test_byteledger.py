import tempfile
import unittest
from pathlib import Path

from n64dk.match import byteledger as own
from tests.test_boundaries import BASE, CATALOGUE, LAYOUT, image
from n64dk.analysis import boundaries as b

IMG = image(LAYOUT)
INFO = own.ImageInfo.of("test", IMG.data, BASE, [(0x1000, 0, len(IMG.data), "copy")])
ROWS = [("f1", BASE, 0x20), ("f2", BASE + 0x20, 0x20), ("f3", BASE + 0x40, 0x20), ("f4", BASE + 0x60, 0x20)]


def m(vram, size, source, cls="c", digest=""):
    return own.ManifestRow(vram, size, source, cls, digest, f"test.tsv:{vram:x}")


class LedgerTest(unittest.TestCase):
    def assert_invariant(self, ledger):
        totals = ledger.totals()
        self.assertEqual(sum(totals["bytes"].values()), ledger.extent[1] - ledger.extent[0])
        self.assertTrue(totals["sum_equals_extent"])

    def test_aggregate_unit_not_double_counted(self):
        # one C unit owns f1 and f2; f3 is asm with provenance; f4 unmatched
        manifests = [m(BASE, 0x40, "src/a.c"), m(BASE + 0x40, 0x20, "src/b.s", "asm", "ab" * 32)]
        ledger = own.build(INFO, ROWS, manifests, extent=(BASE, BASE + 0x80), padding_from_nops=False)
        self.assert_invariant(ledger)
        t = ledger.totals()
        self.assertEqual(t["bytes"]["c-declared"], 0x40)
        self.assertEqual(t["bytes"]["asm-proven"], 0x20)
        self.assertEqual(t["bytes"]["function-unmatched"], 0x20)
        self.assertEqual(t["functions_by_status"], {"asm": 1, "c": 2, "unmatched": 1})
        self.assertEqual(ledger.check(), [])
        self.assertEqual(ledger.double_covered(), [])

    def test_verdicts_and_declared_asm(self):
        manifests = [m(BASE, 0x20, "src/a.c"), m(BASE + 0x20, 0x20, "src/b.c"), m(BASE + 0x40, 0x20, "src/c.s", "asm")]
        ledger = own.build(INFO, ROWS[:3], manifests, verdicts={"src/a.c": True, "src/b.c": False},
                           padding_from_nops=False)
        t = ledger.totals()["bytes"]
        self.assertEqual((t["c-verified"], t["c-declared"], t["asm-declared"]), (0x20, 0x20, 0x20))

    def test_only_strict_exact_verdicts_grant_verified_ownership(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "verdicts.tsv"
            path.write_text("a.c\tok\nb.c\tmatched\nc.c\texact\nd.c\texact_current_target\n")
            verdicts = own.read_verdicts(path)
        self.assertEqual(verdicts, {"a.c": False, "b.c": False, "c.c": True, "d.c": True})

    def test_overlap_gap_stale_outside_partial_missing(self):
        manifests = [m(BASE, 0x30, "src/a.c"), m(BASE + 0x20, 0x20, "src/b.c"),     # overlap; a.c is stale
                     m(BASE + 0x70, 0x08, "src/d.c"),                                 # f4 partly covered
                     m(BASE + 0x100000, 0x10, "src/far.c")]                           # outside the image
        rows = ROWS + [("f5", BASE + 0xA0, 0x10)]                                     # 0x80..0xA0 is a gap
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "src").mkdir()
            (Path(root) / "src" / "a.c").write_text("")
            ledger = own.build(INFO, rows, manifests, extent=(BASE, BASE + 0xB0), root=root,
                               padding_from_nops=False)
            kinds = sorted({v.kind for v in ledger.check()})
        self.assert_invariant(ledger)
        self.assertEqual(kinds, ["gap", "missing-source", "outside", "overlap", "partial", "stale"])
        self.assertEqual(ledger.double_covered(), ["f2"])
        # without image bytes nothing can prove the gap is padding: it stays unknown
        self.assertEqual(ledger.totals()["bytes"]["unknown"], 0x20)

    def test_zero_gap_is_padding(self):
        rows = [("g", BASE + 0x580, 0x8), ("h", BASE + 0x590, 0x8)]
        ledger = own.build(INFO, rows, [], IMG.data, extent=(BASE + 0x580, BASE + 0x598))
        self.assertEqual(ledger.totals()["bytes"]["padding"], 0x8)
        self.assertEqual(ledger.check(), [])

    def test_trailing_nop_padding_never_code(self):
        rows = [("func_P", BASE + 0x580, 0x10)]
        ledger = own.build(INFO, rows, [], IMG.data)
        t = ledger.totals()
        self.assertEqual((t["bytes"]["padding"], t["code_bytes"]), (8, 8))

    def test_tsv_round_trip(self):
        manifests = [m(BASE, 0x40, "src/a.c"), m(BASE + 0x20, 0x8, "src/x.c")]
        ledger = own.build(INFO, ROWS, manifests, padding_from_nops=False)
        with tempfile.TemporaryDirectory() as tmp:
            path = ledger.to_tsv(Path(tmp) / "l.tsv")
            again = own.Ledger.from_tsv(path)
            self.assertIn("0x00001000", path.read_text())          # raw ROM column
        self.assertEqual(again.totals(), ledger.totals())
        self.assertEqual([(v.kind, v.start) for v in again.check()], [(v.kind, v.start) for v in ledger.check()])
        self.assertEqual(again.image, ledger.image)

    def test_reconcile_with_boundary_operations(self):
        ops = b.solve(IMG, CATALOGUE)
        manifests = [m(BASE + 0x40, 0xC, "src/c.c")]
        before = own.build(INFO, CATALOGUE, manifests, IMG.data)
        after = own.build(INFO, CATALOGUE, manifests, IMG.data, operations=ops)
        self.assert_invariant(before)
        self.assert_invariant(after)
        self.assertEqual(after.totals()["bytes"]["fragment"], 0x20)
        report = own.reconcile(before, after)
        text = "\n".join(report["sentences"])
        self.assertIn("denominator 8 -> 8:", text)
        self.assertIn("func_B1 reclassified as fragment of func_A", text)
        self.assertIn("func_80001208 added at 0x80001208", text)
        self.assertIn("C bytes +0", text)
        self.assertEqual(own.reconcile(before, before)["sentences"],
                         ["no change in any numerator, denominator or class total"])

    def test_manifest_layouts(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "m.tsv"
            path.write_text("# IDO 5.3; header prose\n"
                            "0x1000\t0x20\tsrc/a.c\t-O2\t" + "ab" * 32 + "\n"
                            "0x1020\t0x10\tsrc/b.s\t-O2\n"
                            "func_X\t80001040\t8\tmatched\n"
                            "grp\tsrc/d.c\t.data\t0x80002000\t0x10\t" + "cd" * 32 + "\t16\n"
                            "0x2000\t0x0\tsrc/empty.c\t-O2\n")
            rows = own.read_manifest(path, 0x80000000, "c")
            self.assertEqual([(r.vram, r.size, r.cls) for r in rows],
                             [(0x80001000, 0x20, "c"), (0x80001020, 0x10, "asm"), (0x80001040, 8, "c"),
                              (0x80002000, 0x10, "c")])
            path.write_text("# ROM_START\tSIZE\tVRAM\tNAME\tSOURCE\tSHA256\n"
                            "0x1B90\t0x30\t0x80000F90\tf\tsrc/f.c\t" + "ef" * 32 + "\n")
            self.assertEqual([(r.vram, r.source) for r in own.read_manifest(path, 0x7FFFF400, "c")],
                             [(0x80000F90, "src/f.c")])


if __name__ == "__main__":
    unittest.main()
