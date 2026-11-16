"""Hand-written code kept as assembly: the source assembles back to the target's bytes."""
from __future__ import annotations

import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk.match import handasm

VRAM = 0x80001000


def code(*words: int) -> bytes:
    return b"".join(struct.pack(">I", word) for word in words)


# mfc0 t0, Status; addiu at, zero, -2; and t1, t0, at; mtc0 t1, Status; andi v0, t0, 1; nop; jr ra; nop
DISABLE_INTERRUPTS = code(0x40086000, 0x2401FFFE, 0x01014824, 0x40896000, 0x31020001, 0x00000000,
                          0x03E00008, 0x00000000)
# lui k0, %hi(0x800A8B18); addiu k0, k0, %lo(..); sd at, 0x20(k0); cfc1 k1, FpcCsr; j 0x80002000; nop
SAVE_CONTEXT = code(0x3C1A800B, 0x275A8B18, 0xFF410020, 0x445BF800, 0x08000800, 0x00000000)
# beq zero, zero to a label 0x40 past the routine's end; nop; jr ra; nop
BRANCH_OUT = code(0x10000013, 0x00000000, 0x03E00008, 0x00000000)


def _config():
    try:
        from n64dk.match.toolchain import load_config
    except Exception:                                         # pragma: no cover
        return None
    project = Path(tempfile.mkdtemp(prefix="n64dk-handasm-test-"))
    cfg = load_config(project, None, None)
    shutil.rmtree(project, True)
    return cfg if cfg.gnu_as() is not None else None


class SourceTest(unittest.TestCase):
    def test_control_registers_are_numbered_and_named_in_a_comment(self):
        text = handasm.source("func_80001000", DISABLE_INTERRUPTS, VRAM)
        self.assertIn("mfc0 $t0, $12 /* Status */", text)
        self.assertIn("mtc0 $t1, $12 /* Status */", text)
        self.assertNotRegex(text, r"m[ft]c0 \$\w+, Status")

    def test_floating_point_control_register(self):
        self.assertIn("$31 /* FpcCsr */", handasm.source("func_80001000", SAVE_CONTEXT, VRAM))

    def test_a_name_that_states_its_address_resolves_and_another_does_not(self):
        symbols = handasm._Symbols({"osSetIntMask": 0x80002000})
        self.assertEqual((symbols["osSetIntMask"], symbols["func_80001234"], symbols["D_800A8B18"]),
                         (0x80002000, 0x80001234, 0x800A8B18))
        self.assertIn("jtbl_8009EF40", symbols)
        self.assertNotIn("gUnknown", symbols)
        self.assertIsNone(symbols.resolve("gUnknown"))

    def test_without_an_assembler_nothing_is_claimed(self):
        class NoAssembler:
            def gnu_as(self):
                return None
        self.assertEqual(handasm.prove("nop\n", b"\0\0\0\0", VRAM, NoAssembler())["verdict"], "unavailable")
        self.assertIsNone(handasm.attempt("f", DISABLE_INTERRUPTS, VRAM, NoAssembler()))


class WordsTest(unittest.TestCase):
    def test_each_listed_instruction_becomes_its_word_with_the_mnemonic_beside_it(self):
        text = "glabel f\n    /* 80001000 27BDFFE8 */ addiu $sp, $sp, -0x18\n.L80001004:\n    /* 80001004 03E00008 */ jr $ra\n"
        out = handasm.as_words(text)
        self.assertIn("    .word 0x27BDFFE8 /* 80001000: addiu $sp, $sp, -0x18 */", out)
        self.assertIn(".L80001004:", out)
        self.assertIn("glabel f", out)
        self.assertTrue(out.startswith("/* raw words"))


class ProveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = _config()

    def setUp(self):
        if self.cfg is None:
            self.skipTest("no MIPS GNU assembler configured (N64DK_TOOLCHAIN)")

    def check(self, target: bytes, names=None):
        kept = handasm.attempt("func_80001000", target, VRAM, self.cfg, names)
        self.assertIsNotNone(kept)
        self.assertEqual(kept[1]["verdict"], "exact")
        return kept[0]

    def test_coprocessor_moves(self):
        self.check(DISABLE_INTERRUPTS)

    def test_doubleword_store_address_pair_and_call(self):
        text = self.check(SAVE_CONTEXT, {0x80002000: "handler"})
        self.assertIn("handler", text)

    def test_branch_to_a_label_outside_the_routine(self):
        self.check(BRANCH_OUT)

    def test_two_jump_tables_that_are_not_adjacent(self):
        # lw v0,0(a0); jr v0; nop; lw v0,4(a0); jr v0; nop; jr ra; nop
        target = code(0x8C820000, 0x00400008, 0x00000000, 0x8C820004, 0x00400008, 0x00000000, 0x03E00008, 0x00000000)
        tables = [(0x80002000, [VRAM + 0x0C, VRAM + 0x18]), (0x80003000, [VRAM + 0x18, VRAM + 0x0C])]
        kept = handasm.attempt("func_80001000", target, VRAM, self.cfg, None, tables)
        self.assertIsNotNone(kept)
        self.assertIn('.section .rodata.jtbl_80002000, "a"', kept[0])
        self.assertIn('.section .rodata.jtbl_80003000, "a"', kept[0])

    def test_a_range_that_is_not_instructions_is_kept_as_words(self):
        # a reserved coprocessor encoding and plain data between a prologue and a return
        target = code(0x27BDFFE8, 0x4059F800, 0xDEADBEEF, 0x00000000, 0x03E00008, 0x27BD0018)
        kept = handasm.attempt("func_80001000", target, VRAM, self.cfg)
        self.assertIsNotNone(kept)
        self.assertEqual(kept[1]["verdict"], "exact")

    def test_source_that_assembles_to_other_bytes_is_not_kept(self):
        text = handasm.source("func_80001000", DISABLE_INTERRUPTS, VRAM)
        other = bytearray(DISABLE_INTERRUPTS)
        other[7] ^= 1
        self.assertEqual(handasm.prove(text, bytes(other), VRAM, self.cfg)["verdict"], "mismatch")


if __name__ == "__main__":
    unittest.main()
