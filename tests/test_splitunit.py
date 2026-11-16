"""One source file per function, cut from a preprocessed unit."""
import os
import tempfile
import unittest
from pathlib import Path

from n64dk.match import splitunit

UNIT = """
typedef int s32;
typedef float f32;
typedef f32 Vec3f[3];
typedef void (*Callback)(s32);
struct Unused { s32 nothing; };
struct Thing { s32 count; Vec3f at; };
enum Mode { MODE_OFF, MODE_ON = 4 };
#pragma weak something
extern s32 gCounter;
extern struct Thing gThings[];
static s32 sTimer = 3;
static const char *sName = "a; { name } with (braces)";
s32 gTable[] = { 1, 2, 3 }, gSpare;
void *unrelated(void);
static s32 helper(s32 value);
__asm__(".globl sneaked\\nsneaked:\\n jr $31\\n nop\\n");
static inline s32 twice(s32 value) { return value * 2; }
static s32 helper(s32 value) {
    return value + sTimer;
}
s32 first(struct Thing *thing, Callback done) {
    if (thing->count == MODE_ON) { done(helper(gCounter)); }
    return twice(gTable[1]) + (sName[0] == '{');
}
f32 second(Vec3f v)
{
    return v[0] + v[1];
}
"""


class ChunkTest(unittest.TestCase):
    def setUp(self):
        self.parts = splitunit.chunks(UNIT)

    def test_file_level_pieces_and_their_kinds(self):
        kinds = [(part.kind, part.name) for part in self.parts if part.kind in ("function", "asm", "directive")]
        self.assertEqual(kinds, [("directive", None), ("asm", None), ("function", "twice"), ("function", "helper"),
                                 ("function", "first"), ("function", "second")])
        objects = [part.text.split("=")[0].strip() for part in self.parts if part.kind == "object"]
        self.assertEqual(objects, ["static s32 sTimer", "static const char *sName", "s32 gTable[]"])

    def test_braces_and_semicolons_inside_a_literal_do_not_cut(self):
        self.assertTrue(any('"a; { name } with (braces)";' in part.text for part in self.parts))

    def test_what_each_piece_declares(self):
        by_start = {part.text.split("\n")[0][:28]: part for part in self.parts}
        self.assertEqual(by_start["typedef f32 Vec3f[3];"].declares, {"Vec3f"})
        self.assertEqual(by_start["typedef void (*Callback)(s32"].declares, {"Callback"})
        self.assertEqual(by_start["struct Thing { s32 count; Ve"].declares, {"Thing"})
        self.assertEqual(by_start["enum Mode { MODE_OFF, MODE_O"].declares, {"Mode", "MODE_OFF", "MODE_ON"})
        self.assertEqual(by_start["extern struct Thing gThings["].declares, {"gThings"})
        self.assertEqual(by_start["s32 gTable[] = { 1, 2, 3 }, "].declares, {"gTable", "gSpare"})
        self.assertEqual(by_start["void *unrelated(void);"].declares, {"unrelated"})

    def test_names_local_to_the_unit(self):
        local = sorted(name for part in self.parts for name in part.local)
        self.assertEqual(local, ["helper", "helper", "sName", "sTimer"])       # the prototype and the definition


class SplitTest(unittest.TestCase):
    def setUp(self):
        self.out = splitunit.split(UNIT, "src/a.c")
        self.suffix = splitunit.unit_suffix("src/a.c")

    def test_one_file_per_function_that_is_not_an_inline_helper(self):
        self.assertEqual(sorted(self.out), ["first", "helper" + self.suffix, "second"])

    def test_a_file_holds_its_function_and_only_what_that_needs(self):
        text = self.out["first"]
        self.assertIn("s32 first(struct Thing *thing, Callback done)\n{", text)
        self.assertIn("struct Thing { s32 count; Vec3f at; };", text)
        self.assertIn("enum Mode { MODE_OFF, MODE_ON = 4 };", text)
        self.assertIn("#pragma weak something", text)
        for absent in ("struct Unused", "unrelated", "second", "sneaked", "__asm__", "gThings"):
            self.assertNotIn(absent, text, absent)

    def test_other_functions_are_declared_and_objects_are_defined_elsewhere(self):
        text = self.out["first"]
        self.assertIn(f"s32 helper{self.suffix}(s32 value);", text)
        self.assertNotIn("return value + sTimer", text)                  # helper's body is not this function's code
        self.assertIn("extern s32 gTable[] , gSpare;", " ".join(text.split()).replace("[ ]", "[]"))
        self.assertIn(f"extern const char *sName{self.suffix} ;", " ".join(text.split()))
        self.assertNotIn("= { 1, 2, 3 }", text)
        self.assertNotIn("static s32", text.replace("static inline s32 twice", ""))

    def test_an_inline_helper_stays_whole(self):
        self.assertIn("static inline s32 twice(s32 value) { return value * 2; }", self.out["first"])

    def test_local_names_get_the_units_suffix_everywhere_but_in_literals(self):
        text = self.out["helper" + self.suffix]
        self.assertIn(f"s32 helper{self.suffix}(s32 value)\n{{", text)
        self.assertIn(f"return value + sTimer{self.suffix};", text)
        self.assertIn(f"extern s32 sTimer{self.suffix} ;", " ".join(text.split()))
        self.assertEqual(splitunit.rename('x = "sTimer"; sTimer = 1;', {"sTimer": "t"}), 'x = "sTimer"; t = 1;')

    def test_a_small_function_gets_a_small_file(self):
        self.assertNotIn("Thing", self.out["second"])
        self.assertIn("typedef f32 Vec3f[3];", self.out["second"])
        self.assertIn("typedef float f32;", self.out["second"])


class HelperTest(unittest.TestCase):
    def test_initialisers_are_removed_declarator_by_declarator(self):
        self.assertEqual(splitunit.externalised("static s32 a = 1, b[2] = { 3, 4 }, c;"), "extern s32 a , b[2] , c;")
        self.assertEqual(splitunit.externalised("struct P { int x; } gP = { 1 };"), "extern struct P { int x; } gP ;")
        self.assertEqual(splitunit.externalised("void (*gHook)(int) = 0;"), "extern void (*gHook)(int) ;")

    def test_a_function_returning_through_an_attribute_keeps_its_name(self):
        parts = splitunit.chunks("void stop(void) __attribute__((noreturn)) { for (;;) { } }\nint after;\n")
        self.assertEqual([(part.kind, part.name) for part in parts], [("function", "stop"), ("object", None)])


if __name__ == "__main__":
    unittest.main()
