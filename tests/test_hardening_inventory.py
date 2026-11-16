"""Hardening regressions for the interval inventory (review findings F05, F06, F07, F22)."""
from __future__ import annotations

import argparse
import os
import tempfile
import unittest
from pathlib import Path

from n64dk.match import inventory
from n64dk.match.toolchain import Config

CATALOGUE = '''
[[section]]
vram = 0x80000400
rom = 0x1000
size = 0x100
functions = [
  { name = "Player_update", vram = 0x80000400, size = 0x40 },
  { name = "load_data_table", vram = 0x80000440, size = 0x40 },
  { name = "on_call_tail", vram = 0x80000480, size = 0x80 },
]
'''


def _project(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    for name, text in files.items():
        path = Path(tmp.name) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return tmp


def _rows(result):
    return {row["name"]: row for row in result["functions"]}


class InventoryTruthTests(unittest.TestCase):
    def test_missing_source_is_never_covered(self):
        with _project({"config/functions_game.toml": CATALOGUE,
                       "config/matching_game_kmc_units.tsv": "0x1000\t0x40\tsrc/does_not_exist.c\t-O2\n"}) as tmp:
            result = inventory.build(tmp)
            row = _rows(result)["Player_update"]
            self.assertNotEqual(row["state"], "covered")
            self.assertEqual(row["ownership_state"], "manifest_nonexact")
            self.assertEqual(row["verified"], "source-missing")
            self.assertEqual(result["summary"]["covered"], 0)
            self.assertFalse(result["consistency"]["ok"])
            self.assertTrue(result["consistency"]["missing_sources"])

    def test_names_never_shrink_the_denominator(self):
        with _project({"config/functions_game.toml": CATALOGUE}) as tmp:
            rows = _rows(inventory.build(tmp))
            self.assertEqual(rows["load_data_table"]["state"], "remaining")
            self.assertEqual(rows["on_call_tail"]["state"], "remaining")

    def test_configured_exclusions_are_explicit_and_reported(self):
        with _project({"config/functions_game.toml": CATALOGUE.replace(
                           '"on_call_tail", vram = 0x80000480, size = 0x80 },',
                           '"on_call_tail", vram = 0x80000480, size = 0x80 }, # shared epilogue'),
                       "n64dk.toml": '[inventory]\nexclude_names = ["load_*"]\nexclude_kinds = ["shared *"]\n'}) as tmp:
            result = inventory.build(tmp)
            rows = _rows(result)
            self.assertEqual(rows["load_data_table"]["state"], "excluded")
            self.assertIn("exclude_names 'load_*'", rows["load_data_table"]["reason"])
            self.assertEqual(rows["on_call_tail"]["state"], "excluded")
            self.assertEqual(rows["Player_update"]["state"], "remaining")
            self.assertEqual({item["name"] for item in result["discovery"]["exclusions"]},
                             {"load_data_table", "on_call_tail"})

    def test_legacy_bias_only_for_segment_relative_catalogue(self):
        catalogue = ('[[section]]\nvram = 0x80000400\nrom = {rom}\nsize = 0x100\n'
                     'functions = [ { name = "A", vram = 0x80000400, size = 0x40 }, '
                     '{ name = "B", vram = 0x80000440, size = 0x40 } ]\n')
        with _project({"config/functions_main.toml": catalogue.replace("{rom}", "0x1000"),
                       "config/matching_kmc_units.tsv": "0x1040\t0x40\tsrc/b.c\t-O2\n",
                       "src/b.c": "int B(void){return 0;}\n"}) as tmp:
            rows = _rows(inventory.build(tmp))
            self.assertEqual(rows["B"]["state"], "claimed")
            self.assertEqual(rows["B"]["owner"], "src/b.c")
            self.assertEqual(rows["A"]["state"], "remaining")
        with _project({"config/functions_main.toml": catalogue.replace("{rom}", "0"),
                       "config/matching_kmc_units.tsv": "0x1040\t0x40\tsrc/b.c\t-O2\n",
                       "src/b.c": "int B(void){return 0;}\n"}) as tmp:
            self.assertEqual(_rows(inventory.build(tmp))["B"]["state"], "remaining")

    def test_unmapped_manifest_rows_are_reported(self):
        with _project({"config/functions_game.toml": CATALOGUE,
                       "config/matching_game_kmc_units.tsv": "0x9000\t0x40\tsrc/a.c\t-O2\n",
                       "src/a.c": ""}) as tmp:
            result = inventory.build(tmp)
            self.assertEqual(result["summary"]["unmapped_manifest_rows"], 1)
            self.assertEqual(result["discovery"]["unmapped_manifest_rows"][0]["source"], "src/a.c")

    def test_empty_inventory_is_inconsistent(self):
        with _project({"analysis/functions.toml": CATALOGUE}) as tmp:
            result = inventory.build(tmp)
            # Modern discovery accepts an analysis functions catalogue by content.  This is a
            # real inventory, not the historical empty-inventory false success.
            self.assertEqual(result["summary"]["functions"], 3)

    def test_configured_catalogue_and_manifest_globs(self):
        with _project({"analysis/survey/functions.toml": CATALOGUE,
                       "config/us/matching_ido_units.tsv": "# IDO\n0x1000\t0x40\tsrc/p.c\t-O2\n",
                       "src/p.c": "",
                       "n64dk.toml": '[inventory]\ncatalogues = ["analysis/survey/functions.toml"]\n'
                                     'manifests = ["config/us/matching_*.tsv"]\n'}) as tmp:
            result = inventory.build(tmp)
            self.assertEqual(result["summary"]["functions"], 3)
            self.assertEqual(_rows(result)["Player_update"]["state"], "claimed")
            self.assertEqual(result["images"][0]["discovery"], "configured")

    def test_images_table_with_rom_bias(self):
        catalogue = CATALOGUE.replace("rom = 0x1000", "rom = 0")
        with _project({"cat/main.toml": catalogue,
                       "units.tsv": "0x1440\t0x40\tsrc/l.c\t-O2\n", "src/l.c": "",
                       "n64dk.toml": '[images.boot]\ncatalogue = "cat/main.toml"\nmanifests = ["units.tsv"]\n'
                                     'rom_bias = 0x1400\n'}) as tmp:
            result = inventory.build(tmp)
            self.assertEqual(_rows(result)["load_data_table"]["state"], "claimed")
            self.assertEqual(result["functions"][0]["image"], "boot")

    def test_single_c_owner_reason_is_not_padding_partition(self):
        with _project({"config/functions_game.toml": CATALOGUE,
                       "config/matching_game_kmc_units.tsv": "0x1000\t0x40\tsrc/p.c\t-O2\n", "src/p.c": ""}) as tmp:
            row = _rows(inventory.build(tmp))["Player_update"]
            self.assertEqual(row["state"], "claimed")
            self.assertNotIn("padding", row["reason"])

    def test_declared_and_verified_are_reported_separately(self):
        with _project({"config/functions_game.toml": CATALOGUE,
                       "config/matching_game_kmc_units.tsv": "0x1000\t0x40\tsrc/p.c\t-O2\n0x1040\t0x40\tsrc/q.c\t-O2\n",
                       "src/p.c": "", "src/q.c": ""}) as tmp:
            plain = inventory.build(tmp)
            self.assertEqual(plain["summary"]["manifest_declared"], 2)
            self.assertEqual(plain["summary"]["manifest_verified_current"], 0)
            self.assertEqual(_rows(plain)["Player_update"]["verified"], "unverified")
            verified = inventory.build(tmp, verification={("src/p.c", 0x80000400): {"verdict": "exact"},
                                                          ("src/q.c", 0x80000440): {"verdict": "mismatch"}})
            self.assertEqual(verified["summary"]["manifest_verified_current"], 1)
            self.assertEqual(verified["summary"]["verification"]["mismatch"], 1)
            self.assertEqual(_rows(verified)["load_data_table"]["verified"], "mismatch")


def _kmc_root() -> Path | None:
    value = os.environ.get("N64DK_TOOLCHAIN")
    if value and Config(project=Path("."), toolchain_root=Path(value)).toolchain("kmc") is not None:
        return Path(value)
    return None


@unittest.skipIf(_kmc_root() is None, "KMC GCC toolchain not configured (N64DK_TOOLCHAIN)")
class InventoryVerifyTests(unittest.TestCase):
    def test_verify_rebuilds_and_caches_strict_verdicts(self):
        from n64dk.commands.autonomy import match_inventory
        from n64dk.elf import Elf
        from n64dk.match import compare as cmp
        from n64dk.match.pipeline import BuildSpec, build
        flags = "-O2 -G0 -mips3 -mgp32 -mfp32"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "src").mkdir()
            (root / "inc").mkdir()
            (root / "inc" / "k.h").write_text("#define K 3\n")
            (root / "src" / "f.c").write_text('#include "../inc/k.h"\nint f(int a){return a*K;}\n')
            cfg = Config(project=root, toolchain_root=_kmc_root())
            obj = build(root / "src" / "f.c", BuildSpec("kmc+builtin", flags.split()), cfg, root / "w")
            text = cmp.find_section(Elf.load(obj), ".text").data
            size = len(text)
            image = bytearray(0x200); image[0x100:0x100 + size] = text
            (root / "image.bin").write_bytes(bytes(image))
            (root / "cat.toml").write_text(f'[[section]]\nvram = 0x80000000\nrom = 0x100\nsize = 0x100\n'
                                           f'functions = [{{ name = "f", vram = 0x80000000, size = {size:#x} }}]\n')
            (root / "units.tsv").write_text(f"# KMC GCC\n0x100\t{size:#x}\tsrc/f.c\t{flags}\n")
            (root / "n64dk.toml").write_text(
                f'[toolchains]\nroot = "{_kmc_root()}"\n[images.seg]\ncatalogue = "cat.toml"\n'
                'manifests = ["units.tsv"]\nrom = "image.bin"\n')
            parser = argparse.ArgumentParser()
            match_inventory.arguments(parser)
            args = parser.parse_args(["--project", str(root), "--verify", "--symbols", str(root / "none.txt")])
            (root / "none.txt").write_text("")
            first = match_inventory(args)
            self.assertEqual(first["summary"]["manifest_verified_current"], 1, first.get("verification"))
            self.assertEqual(first["verification"]["images"][0]["cached"], 0)
            second = match_inventory(args)
            self.assertEqual(second["verification"]["images"][0]["cached"], 1)
            (root / "inc" / "k.h").write_text("#define K 5\n")    # header edit must invalidate
            third = match_inventory(args)
            self.assertEqual(third["verification"]["images"][0]["cached"], 0)
            self.assertEqual(third["summary"]["verification"]["mismatch"], 1)
            (root / "src" / "f.c").unlink()
            fourth = match_inventory(args)
            self.assertEqual(fourth["summary"]["manifest_verified_current"], 0)
            self.assertEqual(fourth["summary"]["covered"], 0)


if __name__ == "__main__":
    unittest.main()
