"""Draft generators for optimised builds: a decompiler-style draft of a known source must come
back, through one of the generator's rewrites, to the bytes the source compiles to.

The compilers are needed for the round trips (skipped without ``N64DK_TOOLCHAIN``); the
declining cases need nothing."""
from __future__ import annotations

import struct
import unittest

from n64dk.match import autodraft, redraft, redraft_elements, redraft_gcc_opt, redraft_ido_opt
from tests.test_redraft_debug import VRAM, _compiler

GCC = ("kmc+as", ["-O2", "-G0", "-mips3", "-mgp32", "-mfp32"], "kmc")
IDO = ("ido5.3", ["-O2", "-mips2", "-non_shared", "-G", "0", "-Xcpluscomm", "-Wab,-r4300_mul"], "ido53")

# (what the programmer wrote, what a decompiler renders): the draft differs from the truth in
# exactly the way the rule under test repairs
CASES = {
    "bytes": ("extern s32 D_80100000[];\nvoid f(s32 i) {\n    D_80100000[i * 2] = 0;\n}\n",
              "extern M2C_UNK D_80100000;\nvoid f(s32 arg0) {\n    *(&D_80100000 + (arg0 * 8)) = 0;\n}\n"),
    "passed": ("void func_80002000(s32, s32);\nvoid f(s32 a) {\n    func_80002000(a, 0);\n}\n",
               "M2C_UNK func_80002000();\nvoid f(void) {\n    func_80002000(0);\n}\n"),
}


def words(*values: int) -> bytes:
    return b"".join(struct.pack(">I", value) for value in values)


class DecliningTest(unittest.TestCase):
    """Nothing here may raise, and code that is not the generator's situation gets no rewrite."""

    DRAFT = autodraft.PRELUDE + "\nvoid f(void) {\n}\n"
    # addiu sp,-24; sw ra; sw fp; addu fp,sp,zero ...: an unoptimised GCC frame
    DEBUG_GCC = words(0x27BDFFE8, 0xAFBF0014, 0xAFBE0010, 0x03A0F021, 0x03C0E821, 0x8FBF0014, 0x8FBE0010,
                      0x03E00008, 0x27BD0018)

    def test_empty_ragged_and_garbage_input(self):
        for module in (redraft_gcc_opt, redraft_ido_opt):
            for code in (b"", b"\x00\x01\x02", bytes(64), b"\xff" * 32):
                rows = module.variants(self.DRAFT, "f", code=code, vram=VRAM, pipeline="kmc+as", flags=("-O2",))
                self.assertEqual(rows, [], module.__name__)
            self.assertEqual(module.variants("not C at all {{{", "f", code=self.DEBUG_GCC, vram=VRAM,
                                             pipeline="kmc+as", flags=("-O2",)), [])

    def test_the_gcc_generator_leaves_ido_and_unoptimised_code_alone(self):
        rows = redraft_gcc_opt.variants(self.DRAFT, "f", code=self.DEBUG_GCC, vram=VRAM, pipeline="kmc+as",
                                        flags=("-O0",))
        self.assertEqual(rows, [])
        rows = redraft_gcc_opt.variants(self.DRAFT, "f", code=words(0x03E00008, 0x00000000), vram=VRAM,
                                        pipeline="ido5.3", flags=("-O2",), family="ido")
        self.assertEqual(rows, [])

    def test_a_rewrite_is_never_the_draft_itself_and_the_number_is_bounded(self):
        for module in (redraft_gcc_opt, redraft_ido_opt):
            rows = module.variants(self.DRAFT, "f", code=words(0x03E00008, 0x00000000), vram=VRAM,
                                   pipeline="kmc+as" if module is redraft_gcc_opt else "ido5.3", flags=("-O2",))
            self.assertLessEqual(len(rows), 6)
            self.assertNotIn(self.DRAFT, [text for _label, text in rows])


class ElementFormTest(unittest.TestCase):
    HEAD = "#ifndef N64DK_M2C_PRELUDE\n#endif\n"

    def body(self, text: str) -> str:
        return redraft_elements.rewrite(self.HEAD + text)[0][len(self.HEAD):]

    def test_multipliers_and_offsets_are_divided_by_the_element_size(self):
        out = self.body("extern M2C_UNK D_80100000;\nextern u16 D_80100100[];\nvoid f(s32 i, s32 *p) {\n"
                        "    *(&D_80100000 + (i * 8)) = 0;\n    x = *((i * 0xA) + D_80100100);\n    g(p + 0x10);\n"
                        "    y = *(&D_80100000 + (i * 4));\n}\n")
        self.assertIn("*(&D_80100000 + (i * 2)) = 0;", out)
        self.assertIn("x = *((i * 5) + D_80100100);", out)
        self.assertIn("g(p + 4);", out)
        self.assertIn("y = *(&D_80100000 + i);", out)

    def test_values_members_bytes_and_unknown_sizes_are_left_alone(self):
        text = ("extern u8 D_80100200[];\nvoid f(s32 *p, Thing *q, s32 i) {\n    i = *p + 4;\n    i = p[2] + 4;\n"
                "    g(D_80100200 + 4, q + 8, p->x + 4);\n}\n")
        self.assertEqual(redraft_elements.rewrite(self.HEAD + text), (self.HEAD + text, 0))

    def test_a_sum_that_does_not_divide_stops_the_whole_rewrite(self):
        text = "extern s32 D_80100000;\nvoid f(s32 i) {\n    *(&D_80100000 + (i * 8)) = *(&D_80100000 + (i * 6));\n}\n"
        self.assertEqual(redraft_elements.rewrite(self.HEAD + text)[1], 0)

    def test_offered_for_every_compiler(self):
        source = self.HEAD + "extern s32 D_80100000;\nvoid f(s32 i) {\n    *(&D_80100000 + (i * 8)) = 0;\n}\n"
        for pipeline in ("ido5.3", "kmc+as", "sn"):
            self.assertEqual([label for label, _t in redraft_elements.variants(source, "f", pipeline=pipeline)],
                             ["elements"])
        self.assertEqual(redraft_elements.variants(self.HEAD + "void f(void) {\n}\n", "f", pipeline="kmc+as"), [])


class RoundTripBase:
    module, recipe = None, ("", [], "")
    cases: tuple[str, ...] = ()

    @classmethod
    def setUpClass(cls):
        pipeline, flags, key = cls.recipe
        found, reason = _compiler(pipeline, flags, key)
        if found is None:
            raise unittest.SkipTest(reason)
        cls.compile = staticmethod(found)

    def round_trip(self, case: str) -> list[str]:
        truth, draft = CASES[case]
        target = self.compile(autodraft.PRELUDE + "\n" + truth)
        pipeline, flags, _key = self.recipe
        source = autodraft.PRELUDE + "\n" + draft
        self.assertNotEqual(self._built(source), target, "the draft must not already match")
        rows = self.module.variants(source, "f", code=target, vram=VRAM, pipeline=pipeline, flags=tuple(flags))
        return [label for label, text in rows if self._built(text) == target]

    def _built(self, text: str):
        try:
            return self.compile(text)
        except Exception:                                    # noqa: BLE001 - a rewrite that does not build is not a match
            return None


class GccOptRoundTrip(RoundTripBase, unittest.TestCase):
    module, recipe = redraft_gcc_opt, GCC

    def test_pointer_arithmetic_written_in_bytes(self):
        self.assertTrue(self.round_trip("bytes"))

    def test_an_argument_passed_through_untouched(self):
        self.assertTrue(self.round_trip("passed"))


class IdoOptRoundTrip(RoundTripBase, unittest.TestCase):
    module, recipe = redraft_ido_opt, IDO

    def test_pointer_arithmetic_written_in_bytes_needs_the_element_form(self):
        # The byte cast is right in meaning and changes the temporary IDO picks, so the
        # optimised-build generator alone does not bring this one back; the element form does.
        self.assertEqual(self.round_trip("bytes"), [])
        truth, draft = CASES["bytes"]
        target = self.compile(autodraft.PRELUDE + "\n" + truth)
        rows = redraft.variants(autodraft.PRELUDE + "\n" + draft, "f", code=target, vram=VRAM, pipeline=IDO[0],
                                flags=tuple(IDO[1]))
        self.assertIn("elements", [label for label, text in rows if self._built(text) == target])

    def test_an_argument_passed_through_untouched(self):
        self.assertTrue(self.round_trip("passed"))


if __name__ == "__main__":
    unittest.main()
