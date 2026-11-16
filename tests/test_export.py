"""decompile-export: helpers that do not need a project."""
import types
import unittest

from n64dk.commands import export


class ScrubTest(unittest.TestCase):
    def test_machine_paths_are_removed(self):
        text = 'rom = "/mnt/c/Users/someone/Downloads/Game (USA).z64"\nroot = "/home/someone/.cache/lab/x"\nkeep /usr/bin/gcc\n'
        out = export._scrub(text, [("/home/someone/.cache/lab/x", "<run>")])
        self.assertNotIn("someone", out)
        self.assertIn('rom = "<home>/Downloads/Game (USA).z64"', out)
        self.assertIn('root = "<run>"', out)
        self.assertIn("keep /usr/bin/gcc", out)


class RomCoverageTest(unittest.TestCase):
    HEADER = "start\tend\tsize\tclass\tcategory\tkind\tname\tevidence\n"

    def ledger(self, tmp, rows):
        from pathlib import Path
        path = Path(tmp) / "ledger.tsv"
        path.write_text(self.HEADER + "".join("\t".join(row) + "\n" for row in rows))
        return path

    def test_a_ledger_that_covers_the_rom_from_first_byte_to_last(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            found = export.rom_coverage(self.ledger(tmp, [
                ("0x0", "0x40", "64", "rom_metadata", "", "header", "", ""),
                ("0x40", "0x1000", "4032", "rom_metadata", "", "ipl3", "", ""),
                ("0x1000", "0x3000", "8192", "code", "", ".text", "", ""),
                ("0x3000", "0x4000", "4096", "unknown", "", "raw", "", "7.6 bits/byte")]), 0x4000)
        self.assertEqual((found["gap_bytes"], found["overlap_bytes"], found["rows"]), (0, 0, 4))
        self.assertEqual(found["bytes_by_class"], {"code": 8192, "rom_metadata": 4096, "unknown": 4096})
        self.assertEqual(found["largest_unclassified"][0]["start"], "0x3000")

    def test_gaps_and_overlaps_are_counted(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            found = export.rom_coverage(self.ledger(tmp, [
                ("0x0", "0x100", "", "code", "", "", "", ""), ("0x80", "0x180", "", "data", "", "", "", ""),
                ("0x200", "0x300", "", "data", "", "", "", "")]), 0x400)
            self.assertEqual((found["gap_bytes"], found["overlap_bytes"]), (0x80 + 0x100, 0x80))
            from pathlib import Path
            self.assertIsNone(export.rom_coverage(Path(tmp) / "missing.tsv", 1))


class OriginTest(unittest.TestCase):
    def case(self, *stages):
        return types.SimpleNamespace(stages=list(stages))

    def test_how_a_case_was_matched_is_read_from_its_record(self):
        self.assertEqual(export._origin(self.case({"stage": "baseline"})), "draft")
        self.assertEqual(export._origin(self.case({"stage": "iterate", "start": 4, "final": 0})), "draft after variant search")
        self.assertEqual(export._origin(self.case({"stage": "iterate", "start": 4, "final": 2})), "draft")
        self.assertEqual(export._origin(self.case({"stage": "region-recipe", "kept": True})), "draft, recipe of its region")
        self.assertEqual(export._origin(self.case({"stage": "twin"})), "source of an identical function")
        self.assertIn("external author", export._origin(self.case({"stage": "refine"})))

    def test_matched_outcomes(self):
        self.assertEqual(export.MATCHED, ("donor", "donor-awaiting-symbols", "donor-assembly",
                                          "donor-assembly-awaiting-symbols", "exact", "awaiting-symbols",
                                          "assembly"))


if __name__ == "__main__":
    unittest.main()
