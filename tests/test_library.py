import tempfile
import tomllib
import types
import unittest
from pathlib import Path

from n64dk.match import library


def _run(root: Path, rows: str) -> tuple[Path, Path, list]:
    """A finished run's ``queue`` and a project with one image."""
    project, out = root / "project", root / "out"
    (project / "survey").mkdir(parents=True)
    (out / "queue" / "main").mkdir(parents=True)
    (project / "rom.z64").write_bytes(b"\x80\x37\x12\x40" + bytes(60))
    (project / "survey" / "functions.toml").write_text("")
    (project / "survey" / "symbol_addrs.txt").write_text("func_80000400 = 0x80000400;\n")
    (out / "queue" / "queue.tsv").write_text(rows)
    spec = types.SimpleNamespace(name="main", path=project / "rom.z64", vram_delta=None, delta_source="boot segment",
                                 catalogue=project / "survey" / "functions.toml")
    return project, out, [spec]


ROWS = ("# image main; pipeline ido5.3; ROM_START SIZE SOURCE FLAGS  (# VRAM, strict verdict)\n"
        "0x1000\t0x20\tmain/func_80000400.c\t-O2 -mips2\t# 0x80000400 exact\n"
        "# image main; pipeline kmc+as; ROM_START SIZE SOURCE FLAGS  (# VRAM, strict verdict)\n"
        "0x1020\t0x10\tmain/func_80000420.c\t-O2 -G0\t# 0x80000420 exact\n"
        "0x1030\t0x10\tmain/func_80000430.c\t-O2 -G0\t# 0x80000430 exact\n")


class DonorDescriptionTest(unittest.TestCase):
    def test_one_donor_per_image_with_a_manifest_per_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, out, specs = _run(Path(tmp), ROWS)
            result = library.write_donor(out, project, specs, "abc", [project / "survey" / "symbol_addrs.txt",
                                                                      project / "missing.txt"])
            self.assertEqual((result["donors"], result["units"]), (1, 3))
            donor = tomllib.loads((out / "donor.toml").read_text())["donor"]["tabc_main"]
            self.assertEqual(sorted(m["pipeline"] for m in donor["manifests"]), ["ido5.3", "kmc+as"])
            self.assertEqual(len(donor["symbols"]), 1)                       # the missing file is left out
            self.assertNotIn("vram_delta", donor)                           # the ROM's own boot segment
            kmc = next(m["path"] for m in donor["manifests"] if m["pipeline"] == "kmc+as")
            self.assertEqual(len([line for line in (out / "queue" / kmc).read_text().splitlines()
                                  if not line.startswith("#")]), 2)

    def test_a_declared_load_address_and_declared_symbols_are_carried(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, out, specs = _run(Path(tmp), ROWS)
            specs[0].vram_delta, specs[0].delta_source = 0x80200000, "declared"
            (out / "main").mkdir()
            (out / "main" / "declared_symbols.txt").write_text("D_80000500 = 0x80000500;\n")
            library.write_donor(out, project, specs, "abc", [])
            donor = tomllib.loads((out / "donor.toml").read_text())["donor"]["tabc_main"]
            self.assertEqual(donor["vram_delta"], 0x80200000)
            self.assertTrue(donor["symbols"][0].endswith("declared_symbols.txt"))

    def test_every_image_of_a_run_is_described_when_the_queue_holds_every_image(self):
        """The queue tables are rewritten by each export; a run of several images exports all of
        them once more at its end (an export of the last image alone described only that one)."""
        from n64dk.match import resolve as resolvemod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project, out = root / "project", root / "out"
            project.mkdir()
            (project / "rom.z64").write_bytes(b"\x80\x37\x12\x40" + bytes(0x2000))
            (project / "seg_A.bin").write_bytes(bytes(0x100))
            store = resolvemod.CaseStore(out / "state")
            try:
                for image, name, vram, offset in (("main", "func_80000400", 0x80000400, 0x1000),
                                                  ("seg_A", "func_80378800", 0x80378800, 0x0)):
                    digest = store.save_source(f"void {name}(void) {{}}\n")
                    store.put(resolvemod.Case(resolvemod.case_id(image, vram, 0x20), image, name, vram, 0x20, "t",
                                              status="exact", best_digest=digest, best_score=0,
                                              recipe="ido5.3 -O2 -mips2", rom_offset=offset,
                                              strict={"verdict": "exact"}))
                specs = [types.SimpleNamespace(name="main", path=project / "rom.z64", vram_delta=None,
                                               delta_source="boot segment", catalogue=None),
                         types.SimpleNamespace(name="seg_A", path=project / "seg_A.bin", vram_delta=0x80378800,
                                               delta_source="declared", catalogue=None)]
                for spec in specs:
                    resolvemod.export_queue(store, out / "queue", spec.name, True)
                self.assertEqual(library.write_donor(out, project, specs, "abc", [])["donors"], 1)   # the hazard
                resolvemod.export_queue(store, out / "queue", None, True)
            finally:
                store.close()
            result = library.write_donor(out, project, specs, "abc", [])
            self.assertEqual((result["donors"], result["units"]), (2, 2))
            self.assertEqual(sorted(tomllib.loads((out / "donor.toml").read_text())["donor"]),
                             ["tabc_main", "tabc_seg_A"])

    def test_a_run_without_exact_functions_offers_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, out, specs = _run(Path(tmp), "")
            (out / "queue" / "queue.tsv").unlink()
            self.assertEqual(library.write_donor(out, project, specs, "abc", [])["donors"], 0)
            self.assertFalse((out / "donor.toml").exists())
            self.assertIsNone(library.register(Path(tmp) / "lib", out, "abc"))


class LibraryTest(unittest.TestCase):
    def test_a_title_is_never_its_own_donor_and_missing_images_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project, out, specs = _run(root / "a", ROWS)
            library.write_donor(out, project, specs, "aaa", [])
            lib = root / "lib"
            self.assertTrue(library.register(lib, out, "aaa").endswith("aaa.toml"))
            self.assertEqual([p.name for p in library.files(lib, "bbb")], ["aaa.toml"])
            self.assertEqual(library.files(lib, "aaa"), [])
            self.assertEqual([d.name for d in library.donors(lib, "bbb")], ["taaa_main"])
            (project / "rom.z64").unlink()                                   # the title's ROM is gone
            self.assertEqual(library.donors(lib, "bbb"), [])
            (lib / "broken.toml").write_text("not = [toml")
            self.assertEqual(library.donors(lib, "bbb"), [])

    def test_the_stage_identity_changes_when_an_entry_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp)
            self.assertEqual(library.identity(lib), [])
            (lib / "aaa.toml").write_text("x = 1\n")
            before = library.identity(lib)
            (lib / "aaa.toml").write_text("x = 12345\n")
            self.assertNotEqual(before, library.identity(lib))
            self.assertEqual(library.identity(None), [])

    def test_the_key_is_the_content_not_the_name(self):
        self.assertEqual(library.rom_key(b"abc"), library.rom_key(b"abc"))
        self.assertNotEqual(library.rom_key(b"abc"), library.rom_key(b"abd"))


if __name__ == "__main__":
    unittest.main()
