import unittest

from n64dk.match import draftforms

try:
    import pycparser  # noqa: F401
    HAVE_PARSER = True
except ImportError:
    HAVE_PARSER = False

PREAMBLE = "typedef int s32; typedef unsigned char u8; typedef unsigned short u16; typedef short s16;\n"


class NarrowTest(unittest.TestCase):
    def test_parameter_masked_at_every_use_takes_the_narrow_type(self):
        source = PREAMBLE + "M2C_UNK g();                         /* extern */\n\nvoid f(s32 arg0) {\n    g(((s16) arg0) & 0xFF);\n}\n"
        text, applied = draftforms.narrow(source, "f")
        self.assertIn("void f(u8 arg0) {\n    g(arg0);\n}", text)
        self.assertIn("M2C_UNK g(u8);                         /* extern */", text)      # the callee follows
        self.assertEqual(len(applied), 2)

    def test_parameter_with_an_unmasked_use_is_left_alone(self):
        source = PREAMBLE + "s32 f(s32 arg0) {\n    return (arg0 & 0xFF) + arg0;\n}\n"
        self.assertEqual(draftforms.narrow(source, "f"), (source, []))

    def test_parameter_uses_that_disagree_are_left_alone(self):
        source = PREAMBLE + "s32 f(s32 arg0) {\n    return (arg0 & 0xFF) + (arg0 & 0xFFFF);\n}\n"
        self.assertEqual(draftforms.narrow(source, "f")[1], [])

    def test_callee_prototype_from_a_mask_at_every_call(self):
        source = (PREAMBLE + "s32 g();                         /* extern */\n\nvoid f(void) {\n    s16 i;\n    s32 *p;\n\n"
                  "    g(i & 0xFFFF, &i, 3);\n    g((i + 1) & 0xFFFF, p, 0x10);\n}\n")
        text, applied = draftforms.narrow(source, "f")
        self.assertIn("s32 g(u16, void *, s32);                         /* extern */", text)
        self.assertIn("    g(i, &i, 3);\n    g((i + 1), p, 0x10);\n", text)
        self.assertEqual(applied, ["narrow: prototype g(u16, void *, s32)"])

    def test_callee_called_with_different_shapes_is_left_alone(self):
        source = PREAMBLE + "s32 g();\n\nvoid f(s32 a) {\n    g(a & 0xFF);\n    g(a, 1);\n    g(a + 2);\n}\n"
        self.assertEqual(draftforms.narrow(source, "f")[1], [])
        mixed = PREAMBLE + "s32 g();\n\nvoid f(s32 a, s32 b) {\n    g(a & 0xFF);\n    g(b);\n    a = b;\n}\n"
        self.assertEqual(draftforms.narrow(mixed, "f")[1], [])

    def test_branch_collector_is_merged_into_its_only_reader(self):
        source = (PREAMBLE + "s32 f(s32 a) {\n    s32 sp24;\n    s32 var_v0;\n\n    if (a == 1) {\n        var_v0 = g(1);\n"
                  "    } else {\n        var_v0 = h(2);\n    }\n    sp24 = var_v0;\n    k();\n    return sp24;\n}\n")
        text, applied = draftforms.narrow(source, "f")
        self.assertEqual(applied, ["narrow: merge var_v0 into sp24"])
        self.assertIn("        sp24 = g(1);\n    } else {\n        sp24 = h(2);\n    }\n    k();\n    return sp24;", text)
        self.assertNotIn("var_v0", text)

    def test_collector_that_is_read_elsewhere_is_kept(self):
        source = (PREAMBLE + "s32 f(s32 a) {\n    s32 sp24;\n    s32 var_v0;\n\n    if (a) {\n        var_v0 = 1;\n    } else {\n"
                  "        var_v0 = 2;\n    }\n    sp24 = var_v0;\n    return sp24 + var_v0;\n}\n")
        self.assertEqual(draftforms.narrow(source, "f")[1], [])

    def test_unknown_function_is_untouched(self):
        self.assertEqual(draftforms.narrow("int x;\n", "f"), ("int x;\n", []))


@unittest.skipUnless(HAVE_PARSER, "pycparser not installed")
class NormalFormTest(unittest.TestCase):
    ROTATED = (PREAMBLE + "s32 g();\n\nvoid f(void) {\n    s16 i;\n\n    i = 0;\n    do {\n        g(i & 0xFFFF);\n"
               "        i += 1;\n    } while (i < 5);\n}\n")

    def test_rotated_counting_loop_becomes_a_for_loop(self):
        text, applied, _review = draftforms.normalise(self.ROTATED, "f", draftforms.BOLD, allow_review=True)
        self.assertTrue(any("-> for" in label for label in applied), applied)
        self.assertIn("for (i = 0; i < 5;", text)
        self.assertNotIn("do {", text)

    def test_portfolio_contains_the_source_form(self):
        labels = {label: text for label, text, _review in draftforms.drafts(self.ROTATED, "f")}
        self.assertIn("narrow", labels)
        combined = labels.get("narrow+normal")
        self.assertIsNotNone(combined, sorted(labels))
        self.assertIn("s32 g(u16);", combined)
        self.assertRegex(combined, r"for \(i = 0; i < 5; i\+\+\) \{\s+g\(i\);")

    def test_unparseable_source_returns_itself(self):
        self.assertEqual(draftforms.normalise("void f( {", "f"), ("void f( {", [], False))


if __name__ == "__main__":
    unittest.main()
