"""Hardening regressions for command plumbing (review findings F01-F04 gating, F15, F19, F20)."""
from __future__ import annotations

import argparse
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from n64dk.match.engine import Outcome
from n64dk.match.pipeline import BuildSpec
from n64dk.match.session import MatchSession, SessionStore
from n64dk.match.toolchain import Config
from n64dk.outputs import file_output, is_stdout

KMC_FLAGS = ["-O2", "-G0", "-mips3", "-mgp32", "-mfp32"]


def _kmc_root() -> Path | None:
    value = os.environ.get("N64DK_TOOLCHAIN")
    if value and Config(project=Path("."), toolchain_root=Path(value)).toolchain("kmc") is not None:
        return Path(value)
    return None


class HistoryRetryTests(unittest.TestCase):
    def test_locked_database_is_retried(self):
        from n64dk.commands.match import _sqlite_retry
        calls = {"n": 0}

        def flaky():
            calls["n"] += 1
            if calls["n"] < 3:
                raise sqlite3.OperationalError("database is locked")
        self.assertIsNone(_sqlite_retry(flaky, delay=0.001))
        self.assertEqual(calls["n"], 3)

    def test_persistent_failure_is_reported_not_swallowed(self):
        from n64dk.commands.match import _sqlite_retry

        def locked():
            raise sqlite3.OperationalError("database is locked")
        warning = _sqlite_retry(locked, attempts=3, delay=0.001)
        self.assertIn("history not recorded", warning)
        self.assertIn("database is locked", warning)

        def schema():
            raise sqlite3.DatabaseError("file is not a database")
        self.assertIn("not a database", _sqlite_retry(schema, delay=0.001))


class StdoutOutputTests(unittest.TestCase):
    def test_helpers(self):
        self.assertTrue(is_stdout("-"))
        self.assertFalse(is_stdout("out.c"))
        with self.assertRaises(ValueError):
            file_output("-")
        self.assertEqual(file_output("x/y"), Path("x/y"))

    def test_session_export_dash_writes_no_file(self):
        from n64dk.commands.match import match_session_export
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            store = SessionStore(root / "state")
            session = MatchSession(store, lambda source, pipeline, flags, label:
                                   Outcome("f", 0x80000400, 16, BuildSpec(pipeline, list(flags))))
            sid, _ = session.create({"addr": 0x80000400}, b"int f(void){return 0;}\n", "kmc", ("-O2",))
            store.close()
            cwd = os.getcwd()
            os.chdir(root)
            try:
                result = match_session_export(argparse.Namespace(session_id=sid, output="-",
                                                                 state_root=str(root / "state"),
                                                                 project=str(root), candidate_id=None))
            finally:
                os.chdir(cwd)
            self.assertEqual(result["source"], "int f(void){return 0;}\n")
            self.assertFalse((root / "-").exists())
            self.assertFalse((root / "-.evidence.json").exists())

    def test_transform_apply_refuses_dash(self):
        from n64dk.commands.pipeline_core import transform_apply
        with self.assertRaises(ValueError):
            transform_apply(argparse.Namespace(source="a.c", output="-", proposal="p.json", inverse=None,
                                               max_edits=1, max_changed_characters=1))


class ImageSelectionTests(unittest.TestCase):
    """F14: same VRAM + size in two images must not be resolved by a ROM-filename regex."""

    def test_ambiguous_image_requires_image_name(self):
        import struct
        from n64dk.commands.match import _match_args, _setup
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            rom = bytearray(0x102000)
            struct.pack_into(">II", rom, 0, 0x80371240, 0)
            struct.pack_into(">I", rom, 8, 0x80000400)
            rom[0x1100:0x110C] = struct.pack(">III", 0x24020001, 0x03E00008, 0)
            (root / "overlay_2.z64").write_bytes(rom)      # the filename must not pick an image
            (root / "config").mkdir()
            for image in ("overlay1", "overlay2"):
                (root / f"config/functions_{image}.toml").write_text(
                    '[[section]]\nvram = 0x80000400\nrom = 0x1000\nsize = 0x1000\n'
                    f'functions = [{{ name = "f_{image}", vram = 0x80000500, size = 0xC }}]\n')
            parser = argparse.ArgumentParser()
            _match_args(parser)
            base = ["x.c", "--rom", str(root / "overlay_2.z64"), "--project", str(root),
                    "--addr", "80000500", "--size", "C"]
            with self.assertRaises(SystemExit) as caught:
                _setup(parser.parse_args(base))
            self.assertIn("overlay1:f_overlay1", str(caught.exception))
            self.assertIn("overlay2:f_overlay2", str(caught.exception))
            args = parser.parse_args(base + ["--image-name", "overlay1"])
            _setup(args)
            self.assertEqual(args._resolved_inventory_row["image"], "overlay1")
            with self.assertRaises(SystemExit):
                _setup(parser.parse_args(base + ["--image-name", "nope"]))


@unittest.skipIf(_kmc_root() is None, "KMC GCC toolchain not configured (N64DK_TOOLCHAIN)")
class ToolchainCommandTests(unittest.TestCase):
    def setUp(self):
        from n64dk.elf import Elf
        from n64dk.match import compare as cmp
        from n64dk.match.pipeline import build
        self.Elf, self.cmp, self.build = Elf, cmp, build
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg = Config(project=self.root, toolchain_root=_kmc_root())

    def tearDown(self):
        self.tmp.cleanup()

    def _object(self, name: str, text: str):
        source = self.root / name
        source.write_text(text)
        return source, self.Elf.load(self.build(source, BuildSpec("kmc+builtin", list(KMC_FLAGS)), self.cfg,
                                                self.root / "w"))

    def test_address_less_match_reports_ambiguity(self):
        from n64dk.match.engine import Target, match_source
        from n64dk.match.symbols import SymbolMap
        source, elf = self._object("f.c", "int f(int a){return a*3+7;}\n")
        text = self.cmp.find_section(elf, ".text").data
        rom = bytearray(0x400)
        rom[0x100:0x100 + len(text)] = text
        rom[0x200:0x200 + len(text)] = text
        target = Target(bytes(rom), 0x80000000, (0, len(rom)))
        spec = BuildSpec("kmc+builtin", list(KMC_FLAGS))
        out = match_source(source, spec, self.cfg, target, None, None, SymbolMap(), self.root / "m")
        self.assertFalse(out.exact)
        self.assertEqual(out.ambiguous_addresses[:2], [0x80000100, 0x80000200])
        self.assertIn("--addr", out.error)
        chosen = match_source(source, spec, self.cfg, target, 0x80000200, None, SymbolMap(), self.root / "m")
        self.assertTrue(chosen.exact)
        rom[0x100:0x100 + len(text)] = bytes(len(text))
        single = match_source(source, spec, self.cfg, Target(bytes(rom), 0x80000000, (0, len(rom))),
                              None, None, SymbolMap(), self.root / "m")
        self.assertTrue(single.exact)
        self.assertEqual(single.vram, 0x80000200)

    def test_match_batch_strict_verdicts(self):
        from types import SimpleNamespace
        from n64dk.commands.match import _strict_batch, _strict_summary
        from n64dk.match.manifest import Unit
        from n64dk.match.symbols import SymbolMap
        plain_src, plain = self._object("plain.c", "int plain(int a){return a+1;}\n")
        call_src, call = self._object("call.c", "extern int ext(int);\nint call(int a){return ext(a)+1;}\n")
        rom = bytearray(0x400)
        plain_text = plain.relocate(self.cmp.find_section(plain, ".text").name, {".text": 0x80000100}, SymbolMap())
        call_text = call.relocate(self.cmp.find_section(call, ".text").name, {".text": 0x80000200},
                                  SymbolMap({"ext": 0x80000300}))
        rom[0x100:0x100 + len(plain_text)] = plain_text
        rom[0x200:0x200 + len(call_text)] = call_text
        target = SimpleNamespace(rom=bytes(rom), vram_to_rom=lambda v: v - 0x80000000)
        spec = lambda: BuildSpec("kmc+builtin", list(KMC_FLAGS))
        units = [Unit("plain.c", plain_src, 0x80000100, len(plain_text), spec()),
                 Unit("call.c", call_src, 0x80000200, len(call_text), spec())]
        rows = _strict_batch(units, self.cfg, target, SymbolMap(), 2)
        self.assertEqual([row["verdict"] for row in rows], ["exact", "assumed"])
        summary = _strict_summary(rows)
        self.assertFalse(summary["all_exact_strict"])
        self.assertEqual(summary["assumed_symbols"], ["ext = 0x80000300;"])
        declared = _strict_batch(units, self.cfg, target, SymbolMap({"ext": 0x80000300}), 2)
        self.assertTrue(_strict_summary(declared)["all_exact_strict"])
        wrong = _strict_batch(units, self.cfg, target, SymbolMap({"ext": 0x80000300, "other": 0x80000300}), 2)
        self.assertEqual(wrong[1]["verdict"], "exact")   # declared ext resolves; alias is harmless

    def test_strict_source_rejects_retail_derived_callee(self):
        from n64dk.match.symbols import SymbolMap
        from n64dk.match.unit_verify import strict_source
        _src, call = self._object("c2.c", "extern int ext(int);\nint call(int a){return ext(a)+1;}\n")
        text = call.relocate(self.cmp.find_section(call, ".text").name, {".text": 0x80000200},
                             SymbolMap({"realCallee": 0x80000300, "ext": 0x80000300}))
        rom = bytearray(0x400); rom[0x200:0x200 + len(text)] = text
        spec = BuildSpec("kmc+builtin", list(KMC_FLAGS))
        source = b"extern int ext(int);\nint call(int a){return ext(a)+1;}\n"
        verdict = strict_source(source, ".c", spec, self.cfg, bytes(rom), lambda v: v - 0x80000000,
                                0x80000200, len(text), SymbolMap({"realCallee": 0x80000300}))
        self.assertEqual(verdict.verdict, "mismatch")     # ext would alias the declared realCallee
        verdict = strict_source(source, ".c", spec, self.cfg, bytes(rom), lambda v: v - 0x80000000,
                                0x80000200, len(text), SymbolMap())
        self.assertEqual(verdict.verdict, "assumed")


if __name__ == "__main__":
    unittest.main()
