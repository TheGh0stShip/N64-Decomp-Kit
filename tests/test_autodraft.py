import struct
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from n64dk.match import autodraft, m2c_bridge
from n64dk.commands.accelerate import _draft_mapping


def asm(*words):
    return b"".join(struct.pack(">I", w) for w in words)


class EmitTest(unittest.TestCase):
    def test_address_pair_is_symbolized_and_constant_pair_is_not(self):
        code = asm(0x3C028009, 0x8C4287D0,      # lui v0,0x8009 ; lw v0,-0x7830(v0)  -> address
                   0x3C03AAAA, 0x3463AAAB,      # lui v1,0xAAAA ; ori v1,v1,0xAAAB   -> constant
                   0x3C043F80, 0x24840000,      # lui a0,0x3F80 ; addiu a0,a0,0 -> constant
                   0x03E00008, 0x00000000)
        text = m2c_bridge.emit_asm("f", code, 0x80001000, macros=False)
        self.assertIn("%hi(D_800887D0)", text)
        self.assertIn("%lo(D_800887D0)($v0)", text)
        self.assertNotIn("AAAAAAAB", text)
        self.assertNotIn("D_3F800000", text)
        self.assertIn("0xAAAB", text)

    def test_indexed_pair_survives_addu(self):
        code = asm(0x3C018009, 0x00220821, 0x8C2287D0, 0x03E00008, 0x00000000)   # lui at; addu at,at,v0; lw
        self.assertIn("%lo(D_800887D0)($at)", m2c_bridge.emit_asm("f", code, 0x80001000, macros=False))

    def test_jump_table_is_found_and_named_for_m2c(self):
        base = 0x80001000
        code = asm(0x3C018009, 0x00220821, 0x8C2287D0, 0x00400008, 0x00000000,   # ... lw v0,tbl(at); jr v0
                   0x03E00008, 0x24020001, 0x03E00008, 0x24020002)
        table_off = 0x800887D0 - base
        image = code + bytes(table_off - len(code)) + asm(base + 0x14, base + 0x1C, 0)
        # The shared analyser recognizes the dispatch from the containing image.
        tables = m2c_bridge.find_jump_tables(image, base, base, len(code))
        self.assertEqual(tables, [(0x800887D0, [base + 0x14, base + 0x1C])])
        text = m2c_bridge.emit_asm("f", code, base, jump_tables=tables, macros=False)
        self.assertIn("%lo(jtbl_800887D0)($at)", text)
        self.assertIn("glabel jtbl_800887D0", text)
        self.assertIn(f".word .L{base + 0x1C:08X}", text)

    def test_external_branch_has_faithful_and_liftable_forms(self):
        base = 0x80001000
        code = asm(0x10000007, 0x00000000)  # b 0x80001020; nop
        faithful = m2c_bridge.emit_asm("f", code, base, macros=False)
        liftable = m2c_bridge.emit_asm("f", code, base, macros=False, external="stub")
        self.assertIn("L_80001020", faithful)
        self.assertIn(".L80001020:", liftable)
        self.assertIn("j L_80001020", liftable)

    def test_real_m2c_smoke_when_installed(self):
        if m2c_bridge.find_m2c() is None:
            self.skipTest("m2c is optional")
        result = m2c_bridge.draft("fixture", asm(0x03E00008, 0x24020001), 0x80001000)
        self.assertEqual(result["status"], "ok", result["error"])
        self.assertIn("return 1", result["source"])


class RepairTest(unittest.TestCase):
    SOURCE = "void g(); /* extern */\ns32 f(s32 arg0) {\n    s32 t;\n\n    *(arg0 | 4) = sp10;\n    return g(t);\n}\n"

    def test_prepare_unprototypes_callees(self):
        text = autodraft.prepare("s32 g(s32, ? *);                    /* extern */\nvoid f(void) {\n}\n")
        self.assertIn("s32 g();", text)
        self.assertNotIn("?", text.split("#endif")[-1])

    def test_repairs(self):
        fixed = autodraft.repair(self.SOURCE, "x.c:5: `sp10' undeclared (first use this function)")
        self.assertIn("{\n    s32 sp10;\n", fixed)
        fixed = autodraft.repair(self.SOURCE, "x.c:5: invalid type argument of `unary *'")
        self.assertIn("*(s32 *)(arg0 | 4) = sp10;", fixed)
        fixed = autodraft.repair(self.SOURCE, "x.c:6: void value not ignored as it ought to be")
        self.assertTrue(fixed.startswith("s32 g();"))
        self.assertIsNone(autodraft.repair(self.SOURCE, "x.c:9: parse error"))

    def test_sweep_rejects_interval_outside_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = autodraft.sweep([("outside", 0x80002000, 8)], bytes(16), 0x80001000,
                                     lambda *_args: None, Path(tmp), jobs=1)
        self.assertEqual(report["rows"][0]["status"], "skipped")
        self.assertIn("outside", report["rows"][0]["error"])

    def test_exact_draft_score_ignores_unowned_alignment(self):
        code = asm(0x03E00008, 0x00000000)
        outcome = SimpleNamespace(
            exact=True, error=None,
            result=SimpleNamespace(compiled_text=code + b"\x00\x00\x00\x00", diff=None))
        lifted = {"asm": "glabel f\n", "source": "void f(void) {}\n", "error": None}
        with tempfile.TemporaryDirectory() as tmp, \
             patch("n64dk.match.autodraft.m2c_bridge.draft", return_value=lifted):
            row = autodraft.draft_one("f", 0x80001000, len(code), code, lambda _a: None,
                                      lambda *_a: outcome, Path(tmp))
        self.assertEqual(row.status, "exact")
        self.assertEqual(row.asm_score["total"], 0)


class MappingTest(unittest.TestCase):
    def test_composite_delta_disagreement_fails_closed(self):
        args = Namespace(project=".", addr=0x800A2078, size=0xF8,
                         image="overlay_2_composite.z64", vram_delta=0x80000000)
        row = {"id": "target", "image": "overlay2", "vram": "0x800A2078", "size": 0xF8}
        with patch("n64dk.match.inventory.build", return_value={"functions": [row]}), \
             patch("n64dk.match.layout.from_inventory", return_value=object()), \
             patch("n64dk.match.layout.resolve_image_map",
                   return_value={"selected": {"offset": 0xA2C78,
                                                "authority": "anchored-composite-region"}}):
            with self.assertRaisesRegex(ValueError, "conflicts|project mapping"):
                _draft_mapping(args)

    def test_canonical_composite_delta_records_authority(self):
        args = Namespace(project=".", addr=0x800A2078, size=0xF8,
                         image="overlay_2_composite.z64", vram_delta=0x7FFFF400)
        row = {"id": "target", "image": "overlay2", "vram": "0x800A2078", "size": 0xF8}
        with patch("n64dk.match.inventory.build", return_value={"functions": [row]}), \
             patch("n64dk.match.layout.from_inventory", return_value=object()), \
             patch("n64dk.match.layout.resolve_image_map",
                   return_value={"selected": {"offset": 0xA2C78,
                                                "authority": "anchored-composite-region"}}):
            self.assertEqual(_draft_mapping(args)["authority"], "anchored-composite-region")


if __name__ == "__main__":
    unittest.main()
