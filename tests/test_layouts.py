import struct
import unittest

from n64dk.analysis import abi, flow, layouts, values


def code(words):
    return b"".join(struct.pack(">I", w) for w in words)


def facts(words, vram):
    return values.track(flow.analyse(code(words), vram))


INIT, USE, BYTES, CALLER = 0x80001000, 0x80001100, 0x80001200, 0x80002000
# init(p): p->0 = 0 (word); p->4 = 0 (half); p->6 = 0 (byte)
INIT_CODE = [0xAC800000, 0xA4800004, 0x03E00008, 0xA0800006]
# use(p): return p->0 + (s16)p->4
USE_CODE = [0x8C820000, 0x84830004, 0x03E00008, 0x00431021]
# bytes(p): return p[0] + p[1]   -- a generic byte routine
BYTES_CODE = [0x90820000, 0x90830001, 0x03E00008, 0x00431021]
# caller(q): init(&q->sub at 0x10); use(&q->sub); bytes(&q->sub); q->0x30; reads global s16 at 0x80100020
CALLER_CODE = [0x27BDFFE8, 0xAFBF0014, 0xAFB00010, 0x00808025, 0x0C000400, 0x26040010, 0x0C000440, 0x26040010,
               0x0C000480, 0x26040010, 0x8E020030, 0x3C038010, 0x84630020, 0x8FBF0014, 0x8FB00010, 0x03E00008,
               0x27BD0018]
# setf(p, f32 x): mtc1 a1,f4; p->8 = x          (float passed in an integer register)
FLOAT_ARG = [0x44852000, 0x03E00008, 0xE4840008]
# same through the argument home slot (IDO style): sw a1,4(sp); lwc1 f4,4(sp); swc1 f4,8(a0)
FLOAT_HOME = [0xAFA50004, 0xC7A40004, 0x03E00008, 0xE4840008]


def image():
    return {INIT: facts(INIT_CODE, INIT), USE: facts(USE_CODE, USE), BYTES: facts(BYTES_CODE, BYTES),
            CALLER: facts(CALLER_CODE, CALLER)}


NAMES = {INIT: "init", USE: "use", BYTES: "bytes", CALLER: "caller"}


class RecoverTest(unittest.TestCase):
    def setUp(self):
        self.facts = image()
        self.layouts = layouts.recover(self.facts, NAMES)

    def group_of(self, function, index):
        gid, offset = self.layouts.param_group[(function, index)]
        return self.layouts.group(gid), offset

    def test_callee_parameters_join_through_the_caller_with_the_embedded_offset(self):
        init_group, init_offset = self.group_of(INIT, 0)
        use_group, use_offset = self.group_of(USE, 0)
        caller_group, caller_offset = self.group_of(CALLER, 0)
        self.assertEqual(init_group.gid, use_group.gid)
        self.assertEqual(init_group.gid, caller_group.gid)
        self.assertEqual(init_offset - caller_offset, 0x10)        # the callee sees q + 0x10
        self.assertEqual(use_offset, init_offset)

    def test_fields_carry_width_and_signedness(self):
        group, base = self.group_of(INIT, 0)
        self.assertEqual(group.fields[base + 0].ctype, "s32")
        self.assertEqual(group.fields[base + 4].ctype, "s16")       # the load in `use` is signed
        self.assertEqual(group.fields[base + 6].ctype, "u8")        # store-only byte: unsigned by default
        self.assertEqual(group.fields[base - 0x10 + 0x30].width, 4)

    def test_generic_byte_routine_does_not_rewrite_the_word_field(self):
        group, base = self.group_of(INIT, 0)
        self.assertEqual(group.fields[base].width, 4)
        self.assertGreaterEqual(self.layouts.refused, 1)
        self.assertNotIn((BYTES, 0), {k for k, v in self.layouts.param_group.items() if v[0] == group.gid})

    def test_global_declaration(self):
        found = {g.address: g for g in self.layouts.globals}
        self.assertEqual((found[0x80100020].ctype, found[0x80100020].array), ("s16", False))

    def test_context_text(self):
        prototypes = abi.solve(self.facts, NAMES)
        text = layouts.context(self.layouts, prototypes, min_confidence=0.0)
        group, base = self.group_of(INIT, 0)
        self.assertIn(f"struct {group.name} {{", text)
        self.assertIn("extern s16 D_80100020;", text)
        # `init` receives a pointer into the middle of the record: it gets the re-based view
        view = f"struct {group.name}_at_{base:X}"
        self.assertIn(f"void init({view} *);", text)
        self.assertIn(f"{view} {{", text)
        self.assertIn("/* 0x04 */ s16 unk_4;", text.split(f"{view} {{")[1].split("};")[0])
        self.assertIn(f"caller(struct {group.name} *);", text)
        self.assertNotIn("Struct_bytes_arg0", text)                 # a byte buffer is not a record
        self.assertIn("char unk_", text)                            # gaps are refinable padding arrays
        self.assertNotIn("typedef", layouts.context(self.layouts, prototypes, typedefs=False))
        # every struct body is laid out in increasing offset order without overlap
        for body in text.split("struct ")[1:]:
            offsets = [int(line.split("/* 0x")[1].split(" ")[0], 16) for line in body.splitlines()
                       if line.strip().startswith("/* 0x")]
            self.assertEqual(offsets, sorted(offsets))


    def test_focused_context_lists_only_what_the_function_references(self):
        prototypes = abi.solve(self.facts, NAMES)
        declarations = layouts.Declarations(self.layouts, prototypes, min_confidence=0.0)
        text = declarations.focused(self.facts[CALLER], CALLER)
        self.assertIn("void init(", text)
        self.assertIn("extern s16 D_80100020;", text)
        self.assertNotIn("caller(", text)                           # own prototype only on request
        self.assertIn("caller(", declarations.focused(self.facts[CALLER], CALLER, include_self=True))
        leaf = declarations.focused(self.facts[USE], USE)
        self.assertNotIn("extern", leaf)
        self.assertNotIn("struct Struct", leaf)                     # no callee mentions a record here


class FloatArgumentTest(unittest.TestCase):
    def test_float_passed_in_an_integer_register(self):
        seen = facts(FLOAT_ARG, 0x80003000)
        self.assertIn("f32", seen.params.get(1, set()))
        proto = abi.solve({0x80003000: seen}, {0x80003000: "setf"})[0x80003000]
        self.assertEqual(proto.arg_types[:2], ["void *", "f32"])

    def test_float_reloaded_from_its_home_slot(self):
        seen = facts(FLOAT_HOME, 0x80003000)
        self.assertIn("f32", seen.params.get(1, set()))


if __name__ == "__main__":
    unittest.main()
