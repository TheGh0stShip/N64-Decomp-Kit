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


class WaitingDonorTest(unittest.TestCase):
    def test_a_strict_proof_is_credited_over_a_donor_unit_that_still_waits(self):
        case = lambda status: types.SimpleNamespace(status=status)
        proved = export.proved_beside_waiting_donor
        self.assertTrue(proved("donor-awaiting-symbols", case("exact"), True))
        self.assertTrue(proved("donor-assembly-awaiting-symbols", case("assembly"), True))
        self.assertFalse(proved("donor", case("exact"), True))                 # a verified unit keeps its functions
        self.assertFalse(proved("donor-awaiting-symbols", case("assumed"), True))
        self.assertFalse(proved("donor-awaiting-symbols", case("open"), True))
        self.assertFalse(proved("donor-awaiting-symbols", case("exact"), False))
        self.assertFalse(proved("donor-awaiting-symbols", None, False))


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


class ReproducedByTest(unittest.TestCase):
    def test_generated_assembly_is_never_c(self):
        from n64dk.commands.export import reproduced_by
        for outcome in ("open", "near", "does-not-build", "not attempted", "blocked-boundary", "matched-source-missing"):
            self.assertEqual(reproduced_by(outcome, True), "assembly (not decompiled)")
            self.assertEqual(reproduced_by(outcome, False), "nothing")
        self.assertEqual(reproduced_by("exact", False), "C")
        self.assertEqual(reproduced_by("donor-assembly-awaiting-symbols", False), "assembly (donor source)")
        self.assertEqual(reproduced_by("assembly", False), "assembly (hand-written)")


class DenominatorWarningTest(unittest.TestCase):
    def test_incomplete_and_doubtful_catalogues_warn(self):
        import json
        import tempfile
        from pathlib import Path
        from n64dk.commands.export import _denominator_warning
        run = Path(tempfile.mkdtemp(prefix="n64dk-test-warning-"))
        self.assertIsNone(_denominator_warning(run))                                   # no report
        for verdict, expected in (("complete", None), ("incomplete", "incomplete"), ("doubtful", "doubtful")):
            (run / "report.json").write_text(json.dumps({"discovery": {"verdict": verdict}}))
            found = _denominator_warning(run)
            if expected is None:
                self.assertIsNone(found)
            else:
                self.assertIn(expected, found)


class UnitClassRowTest(unittest.TestCase):
    def test_rows_carry_hexadecimal_sizes(self):
        from n64dk.commands.export import _unit_class
        evidence = {"entry": 0x80000400, "rsp": [(0x80001010, 0x80001100)], "kinds": {0x80002000: "asm"},
                    "sdk": {0x80003000}}

        def row(vram, size):                                 # as export() writes them
            return ["main", "f", f"0x{vram:08X}", "0x1000", f"0x{size:X}", f"0x{size:X}", "open", "", "", ""]
        self.assertEqual(_unit_class(row(0x80001000, 0x20), evidence), "rsp")     # reaches the range by its size
        self.assertEqual(_unit_class(row(0x80001000, 0x10), evidence), "game")
        self.assertEqual(_unit_class(row(0x80000400, 0x40), evidence), "boot")
        self.assertEqual(_unit_class(row(0x80002000, 0x40), evidence), "handwritten")
        self.assertEqual(_unit_class(row(0x80003000, 0x40), evidence), "sdk")


class GpProvenanceTest(unittest.TestCase):
    """A function built in a small-data lane against the run's recovered _gp says it needs that file."""

    def test_the_how_column_marks_functions_that_need_the_recovered_gp(self):
        from n64dk.commands.export import GP_DEPENDENT, _gp_note, _how

        def case(recipe):
            return types.SimpleNamespace(recipe=recipe, stages=[{"stage": "baseline"}])
        self.assertEqual(_how(case("kmc+asg -O2 -G8"), True), f"kmc+asg -O2 -G8 (draft; {GP_DEPENDENT})")
        self.assertEqual(_how(case("kmc+gas -O2 -G8"), True), f"kmc+gas -O2 -G8 (draft; {GP_DEPENDENT})")
        self.assertEqual(_how(case("kmc+asg -O2 -G8"), False), "kmc+asg -O2 -G8 (draft)")   # the project's _gp
        self.assertEqual(_how(case("kmc+as -O2"), True), "kmc+as -O2 (draft)")             # no small data
        self.assertEqual(_gp_note(0), [])
        self.assertIn("symbols/gp_symbols.txt", _gp_note(2)[0])

    def test_the_gp_counts_as_recovered_only_when_the_project_declares_none(self):
        import shutil
        import tempfile
        from pathlib import Path
        from n64dk.commands.export import _recovered_gp
        root = Path(tempfile.mkdtemp(prefix="n64dk-test-gp-"))
        self.addCleanup(shutil.rmtree, root, True)
        project, run = root / "project", root / "run"
        project.mkdir()
        run.mkdir()
        (project / "n64dk.toml").write_text('[run]\nsymbols = ["syms.txt"]\n')
        (project / "syms.txt").write_text("func_a = 0x80000400;\n")
        self.assertFalse(_recovered_gp(project, run, "main"))              # the run declared no _gp
        (run / "small_data").mkdir()
        (run / "small_data" / "gp_symbols.txt").write_text("_gp = 0x80100000;\n")
        self.assertTrue(_recovered_gp(project, run, "main"))
        (project / "syms.txt").write_text("_gp = 0x80100000;\nfunc_a = 0x80000400;\n")
        self.assertFalse(_recovered_gp(project, run, "main"))             # the project's own _gp was used
