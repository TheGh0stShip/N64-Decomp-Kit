import argparse
import atexit
import json
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path

from n64dk.commands import blind, run
from n64dk.match import resolve

from tests.test_functions import synthetic_rom


def _scratch() -> Path:
    path = tempfile.mkdtemp(prefix="n64dk-blind-test-")
    atexit.register(shutil.rmtree, path, True)
    return Path(path)


class StartingRecipeTest(unittest.TestCase):
    def test_fingerprint_selects_the_family(self):
        pipeline, flags, why = blind.starting_recipe({"game_compiler": "kmc", "game_compiler_share": {"kmc": 0.97}})
        self.assertEqual(pipeline, "kmc+asn64")
        self.assertIn("-O2", flags)
        self.assertIn("97%", why)
        self.assertEqual(blind.starting_recipe({"game_compiler": "ido", "game_compiler_share": {"ido": 0.9}})[0], "ido5.3")

    def test_no_fingerprint_is_said_plainly(self):
        pipeline, _flags, why = blind.starting_recipe(None)
        self.assertEqual(pipeline, "ido5.3")
        self.assertIn("no compiler fingerprint", why)


class ProjectFromRomTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folder = _scratch()
        cls.rom = folder / "game.z64"
        cls.rom.write_bytes(synthetic_rom().data)
        cls.before = cls.rom.read_bytes()
        cls.out = folder / "project"
        cls.summary = blind.build_project(cls.rom, cls.out, calibrate=24, toolchain="/opt/toolchain", lzari_brute=False)

    def test_project_files(self):
        for name in ("n64dk.toml", "baserom.z64", "survey/functions.toml", "survey/symbol_addrs.txt",
                     "survey/sdk_symbols.txt", "survey/report.json", "survey/blind.json"):
            self.assertTrue((self.out / name).exists(), name)
        self.assertTrue((self.out / "baserom.z64").is_symlink())
        self.assertEqual((self.out / "baserom.z64").resolve(), self.rom.resolve())
        self.assertEqual(self.rom.read_bytes(), self.before)               # the ROM is only read

    def test_configuration_is_what_decompile_run_reads(self):
        config = tomllib.loads((self.out / "n64dk.toml").read_text())
        self.assertEqual(config["images"]["main"]["path"], "baserom.z64")
        self.assertEqual(config["images"]["main"]["catalogue"], "survey/functions.toml")
        self.assertEqual(config["run"]["calibrate"], 24)
        self.assertEqual(config["run"]["symbols"], ["survey/symbol_addrs.txt", "survey/sdk_symbols.txt"])
        self.assertEqual(config["toolchains"]["root"], "/opt/toolchain")
        self.assertIn(config["run"]["pipeline"], ("ido5.3", "kmc+asn64", "sn"))
        from n64dk.match import images
        spec = images.load_registry(self.out)["main"]
        self.assertEqual(len(spec.rows()), self.summary["functions"])

    def test_summary_states_the_coverage(self):
        self.assertEqual(self.summary["functions"], 4)
        self.assertEqual(self.summary["image"]["vram"], "0x80000400")
        self.assertFalse(self.summary["image"]["packed"])
        self.assertEqual(json.loads((self.out / "survey/blind.json").read_text())["functions"], 4)

    def test_existing_project_is_not_overwritten_without_force(self):
        args = argparse.Namespace(rom=str(self.rom), out=str(self.out), image="auto", calibrate=8, toolchain_dir=None,
                                  no_lzari_brute=True, force=False)
        with self.assertRaises(SystemExit):
            blind.decompile_init(args)


class LayoutTest(unittest.TestCase):
    REPORT = {"rom": {"size": 0x100000, "cic": "6102"},
              "program": {"method": "static", "entry": "0x80000400",
                          "main": {"vram": "0x80000400", "end": "0x80002400", "rom": "0x1000", "rom_end": "0x3000",
                                   "kind": "rom"}},
              "datamap": {"bss": "0x80002400..0x80003000",
                          "sections": [".text 0x80000400..0x80001400 (0x1000)", ".data 0x80001400..0x80002000 (0xC00)",
                                       ".rodata 0x80002000..0x80002400 (0x400)"]},
              "rsp_in_text": ["0x80001000..0x80001100"], "sdk": {"microcode": ["F3DEX 2.05 @0x2000"]},
              "unknown_bytes": 7}

    def test_sections_carry_rom_offsets_and_bss_has_none(self):
        layout = blind.rom_layout(self.REPORT, [], [], [])
        sections = {row["section"]: row for row in layout["main"]["sections"]}
        self.assertEqual((sections[".data"]["rom"], sections[".data"]["rom_end"]), ("0x2000", "0x2C00"))
        self.assertNotIn("rom", sections[".bss"])
        self.assertEqual(sections[".bss"]["size"], 0xC00)
        self.assertEqual(layout["main"]["rsp"][0]["kind"], "rsp")
        self.assertEqual(layout["unknown_bytes"], 7)

    def test_each_piece_with_bytes_is_written_once(self):
        layout = blind.rom_layout(self.REPORT, [], [], [])
        rom = bytes(range(256)) * 0x40
        with tempfile.TemporaryDirectory() as tmp:
            written = blind.extract_layout(layout, rom, rom[0x1000:0x3000], Path(tmp))
            self.assertEqual(sorted(written), ["header.bin", "ipl3.bin", "main.data.bin", "main.rodata.bin",
                                               "main.rsp_80001000.bin", "main.text.bin"])
            self.assertEqual((Path(tmp) / "main.data.bin").read_bytes(), rom[0x2000:0x2C00])
            self.assertEqual(len((Path(tmp) / "ipl3.bin").read_bytes()), 0xFC0)

    def test_a_refiner_is_recorded_only_when_asked_for(self):
        self.assertIn("refine_command", blind.build_project.__code__.co_varnames)


class CalibrationTest(unittest.TestCase):
    def setUp(self):
        self.state = _scratch()
        self.rows = [(f"f{i}", 0x80001000 + 0x100 * i, 0x40) for i in range(40)] + [("big", 0x80010000, 0x400)]

    def put(self, index, status, recipe, size=0x40):
        store = resolve.CaseStore(self.state)
        vram = 0x80001000 + 0x100 * index
        store.put(resolve.Case(resolve.case_id("main", vram, size), "main", f"f{index}", vram, size, "d" * 64,
                               status=status, recipe=recipe))
        store.close()

    def calibrate(self, sample=10, skip=()):
        seen = {}

        def fake_resolve_hard(options):
            seen.update(vars(options))
            return {"functions": sample, "seconds": 1.0}

        def options(**overrides):
            return argparse.Namespace(**overrides)
        return run.calibrate_recipe(fake_resolve_hard, options, self.state, "main", self.rows, set(skip), sample), seen

    def test_the_recipe_most_sample_functions_matched_under_is_chosen(self):
        for index in range(5):
            self.put(index, "exact" if index % 2 else "assumed", "ido5.3 -g -mips2")
        self.put(5, "exact", "ido7.1 -O2 -mips2")
        self.put(6, "near", "kmc+as -O2")                                   # not identical: no vote
        result, seen = self.calibrate()
        self.assertEqual(result["chosen"], {"label": "ido5.3 -g -mips2", "pipeline": "ido5.3", "flags": "-g -mips2",
                                            "matched": 5})
        self.assertEqual(result["identical"], 6)
        self.assertEqual(seen["cross_recipes"], 64)                         # every recipe is tried on the sample
        self.assertEqual((seen["min_size"], seen["max_size"]), run.CALIBRATION_SIZES)
        self.assertEqual(seen["every"], 4)                                  # 40 eligible functions, 10 wanted: spread
        self.assertIsNone(seen["refine"])

    def test_too_little_evidence_keeps_the_configured_recipe(self):
        self.put(0, "exact", "ido5.3 -O2")
        self.put(1, "exact", "ido5.3 -O2")
        result, _seen = self.calibrate()
        self.assertIsNone(result["chosen"])
        self.assertIn("fewer than three", result["reason"])

    def test_functions_recovered_by_donors_are_not_sampled(self):
        _result, seen = self.calibrate(sample=10, skip={row[1] for row in self.rows[:20]})
        self.assertEqual(seen["every"], 2)                                  # 20 eligible left

    def test_nothing_in_the_size_window(self):
        self.rows = [("big", 0x80010000, 0x400)]
        result, _seen = self.calibrate()
        self.assertEqual((result["sample"], result["chosen"]), (0, None))


if __name__ == "__main__":
    unittest.main()
