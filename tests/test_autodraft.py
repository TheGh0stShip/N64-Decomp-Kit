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
                         image="overlay_2_composite.z64", image_name=None,
                         vram_delta=0x80000000)
        row = {"id": "target", "image": "overlay2", "vram": "0x800A2078", "size": 0xF8,
               "section_vram": "0x8008B8E0", "section_size": 0x32000}
        with patch("n64dk.match.inventory.build", return_value={"functions": [row]}), \
             patch("n64dk.match.layout.from_inventory", return_value=object()), \
             patch("n64dk.match.layout.resolve_image_map",
                   return_value={"selected": {"offset": 0xA2C78,
                                                "authority": "anchored-composite-region"},
                                 "linked_vram": "0x800A2078", "linked_base": "0x8008B8E0"}):
            with self.assertRaisesRegex(ValueError, "conflicts|project mapping"):
                _draft_mapping(args)

    def test_canonical_composite_delta_records_authority(self):
        args = Namespace(project=".", addr=0x800A2078, size=0xF8,
                         image="overlay_2_composite.z64", image_name=None,
                         vram_delta=0x7FFFF400)
        row = {"id": "target", "image": "overlay2", "vram": "0x800A2078", "size": 0xF8,
               "section_vram": "0x8008B8E0", "section_size": 0x32000}
        with patch("n64dk.match.inventory.build", return_value={"functions": [row]}), \
             patch("n64dk.match.layout.from_inventory", return_value=object()), \
             patch("n64dk.match.layout.resolve_image_map",
                   return_value={"selected": {"offset": 0xA2C78,
                                                "authority": "anchored-composite-region"},
                                 "linked_vram": "0x800A2078", "linked_base": "0x8008B8E0"}):
            self.assertEqual(_draft_mapping(args)["authority"], "anchored-composite-region")

    def test_shifted_catalogue_address_normalizes_to_linked_vram(self):
        args = Namespace(project=".", addr=0x800E0B58, size=0x20,
                         image="overlay_4_composite.z64", image_name="overlay4",
                         vram_delta=0x7FFE4C48)
        row = {"id": "target", "image": "overlay4", "vram": "0x800E0B58", "size": 0x20,
               "section_vram": "0x800C77E8", "section_size": 0x21000}
        resolved = {"selected": {"offset": 0xFA670, "authority": "anchored-composite-region"},
                    "linked_vram": "0x800DF2B8", "linked_base": "0x800C5F48"}
        with patch("n64dk.match.inventory.build", return_value={"functions": [row]}), \
             patch("n64dk.match.layout.from_inventory", return_value=object()), \
             patch("n64dk.match.layout.resolve_image_map", return_value=resolved):
            mapping = _draft_mapping(args)
        self.assertEqual(args.addr, 0x800DF2B8)
        self.assertEqual(mapping["catalogue_vram"], "0x800E0B58")
        self.assertEqual(mapping["linked_vram"], "0x800DF2B8")


class IdoRepairTest(unittest.TestCase):
    """The same repairs must fire on IDO front-end diagnostics, which are worded differently."""

    SOURCE = ("void g(s32, s32);  /* extern */\nvoid f(void *arg0, s32 arg1) {\n    void *var_a0;\n    s32 *var_a1;\n\n"
              "    var_a0 = arg0;\n    var_a0 += 0x28;\n    *(arg0 + sp4) = 0;\n    var_a1 = arg1;\n    g(arg1);\n"
              "    (*(M2C_UNK (**)(void *, void *))((s8 *)(arg0) + 8))(arg0);\n}\n")

    def fix(self, line, message):
        return autodraft.repair(self.SOURCE, f"cfe: Error: /tmp/x/f.c, line {line}: {message}\n  src\n ---^")

    def test_undefined_name(self):
        self.assertIn("{\n    s32 sp4;\n", self.fix(8, "'sp4' undefined; reoccurrences will not be reported."))

    def test_dereferenced_non_pointer(self):
        self.assertIn("*(s32 *)(arg0 + sp4) = 0;", self.fix(8, "Dereferenced a non-pointer."))

    def test_void_pointer_arithmetic_becomes_byte_pointer(self):
        fixed = self.fix(7, "Bad operand type for += or -=")
        self.assertIn("    s8 *var_a0;", fixed)
        self.assertIn("void *arg0", fixed)                       # only the variable on that line changes
        self.assertIn("f(s8 *arg0, s32 arg1)", self.fix(8, "Unacceptable operand of '+'."))

    def test_argument_count_disagreement(self):
        message = "Number of arguments doesn't agree with the number in the declaration."
        self.assertIn("(*(M2C_UNK (**)())((s8 *)(arg0) + 8))(arg0);", self.fix(11, message))
        self.assertTrue(self.fix(10, message).startswith("void g();  /* extern */"))

    def test_pointer_integer_assignment_gets_the_target_type(self):
        self.assertIn("    var_a1 = (s32 *) (arg1);", self.fix(9, "illegal combination of pointer and integer"))

    def test_redeclared_stack_slot_keeps_its_first_declaration(self):
        source = "void f(void) {\n    s32 sp1C;\n    f32 sp1C;\n    s32 a;\n\n    a = sp1C;\n}\n"
        ido = "cfe: Error: f.c, line 3: redeclaration of 'sp1C'; previous declaration at line 2 in file 'f.c'"
        gcc = "f.c:3: redeclaration of `sp1C'\nf.c:2: `sp1C' previously declared here"
        for message in (ido, gcc):
            self.assertEqual(autodraft.repair(source, message),
                             "void f(void) {\n    s32 sp1C;\n    s32 a;\n\n    a = sp1C;\n}\n")
        self.assertIsNone(autodraft.repair(source, "f.c:6: redeclaration of `sp1C'"))   # not a declaration line

    def test_dereferenced_void_pointer_becomes_a_word_pointer(self):
        source = "s32 f(void *arg0) {\n    void *var_v0;\n\n    var_v0 = arg0;\n    return *var_v0;\n}\n"
        for message in ("f.c:5: warning: dereferencing `void *' pointer\nf.c:5: void value not ignored as it ought to be",
                        "cfe: Error: f.c, line 5: Reference of an expression of void type or an incomplete type."):
            fixed = autodraft.repair(source, message)
            self.assertIn("    s32 *var_v0;", fixed)
            self.assertIn("void *arg0", fixed)

    def test_gcc_wording_still_works(self):
        fixed = autodraft.repair(self.SOURCE, "f.c:8: `sp4' undeclared (first use this function)")
        self.assertIn("    s32 sp4;", fixed)


if __name__ == "__main__":
    unittest.main()
