import struct
import unittest

from n64dk.analysis import abi, flow, values

BASE = 0x80001000


def code(words):
    return b"".join(struct.pack(">I", w) for w in words)


def facts(words, vram=BASE):
    return values.track(flow.analyse(code(words), vram))


# s32 get(Thing *p) { return p->field_8 (s16) + (u8)arg1; }   lh v0,8(a0); andi a1,a1,0xff; jr ra; addu v0,v0,a1
CALLEE = [0x84820008, 0x30A500FF, 0x03E00008, 0x00451021]
# caller: frame, save ra/s0; s0 = a0; a0 = s0->0x10 (lw); a1 = 3; jal CALLEE; nop; sh v0,4(s0); restore; return
CALLER = [0x27BDFFE8, 0xAFBF0014, 0xAFB00010, 0x00808025, 0x8E040010, 0x24050003, 0x0C000400, 0x00000000,
          0xA6020004, 0x8FBF0014, 0x8FB00010, 0x03E00008, 0x27BD0018]
# void leaf(void) { gCounter++; }   lui v0; lw v1,lo(v0); addiu v1,1; jr ra; sw v1,lo(v0)   -- scratch only
VOID = [0x3C028010, 0x8C430020, 0x24630001, 0x03E00008, 0xAC430020]
# reads 0x10(sp) with no frame: fifth argument
STACK = [0x8FA20010, 0x03E00008, 0x00441021]


class ValuesTest(unittest.TestCase):
    def test_parameter_traits_and_accesses(self):
        seen = facts(CALLEE)
        self.assertEqual(seen.params[0], {"pointer"})
        self.assertEqual(seen.params[1], {"u8"})
        access = seen.accesses[0]
        self.assertEqual((access.base, access.offset, access.width, access.signed), (("param", 0), 8, 2, True))

    def test_value_survives_a_copy_into_a_saved_register(self):
        seen = facts(CALLER, 0x80002000)
        offsets = sorted((a.offset, a.op) for a in seen.accesses if a.base == ("param", 0))
        self.assertEqual(offsets, [(4, "sh"), (16, "lw")])
        call = seen.calls[0]
        self.assertEqual(call.target, BASE)
        self.assertEqual(call.fresh, frozenset({4, 5}))
        self.assertTrue(call.result_used)
        self.assertEqual(call.args[4][0], ("field", ("param", 0), 16))

    def test_global_access_is_recorded_with_its_address(self):
        seen = facts(VOID)
        self.assertEqual({(g.address, g.op) for g in seen.globals}, {(0x80100020, "lw"), (0x80100020, "sw")})
        self.assertEqual(seen.returns, [("hi", 0x80100000)])      # half an address: scratch, not a result

    def test_stack_argument_read(self):
        self.assertEqual(facts(STACK).stack_args_read, [0x10])


class AbiTest(unittest.TestCase):
    def solve(self):
        functions = {BASE: facts(CALLEE), 0x80002000: facts(CALLER, 0x80002000), 0x80003000: facts(VOID, 0x80003000),
                     0x80004000: facts(STACK, 0x80004000)}
        return abi.solve(functions, {BASE: "get", 0x80002000: "use", 0x80003000: "bump", 0x80004000: "five"})

    def test_callee_and_caller_agree(self):
        proto = self.solve()[BASE]
        self.assertEqual(proto.declaration(), "s32 get(void *, u8);")
        self.assertGreaterEqual(proto.confidence, 0.9)
        self.assertEqual(proto.declaration(struct_names={0: "Thing"}), "s32 get(Thing *, u8);")

    def test_void_when_v0_is_never_written(self):
        proto = self.solve()[0x80003000]
        self.assertEqual(proto.declaration(), "void bump(void);")

    def test_stack_arguments_extend_the_count(self):
        self.assertEqual(self.solve()[0x80004000].args, 5)

    def test_caller_without_callers_is_low_confidence(self):
        proto = self.solve()[0x80002000]
        self.assertEqual(proto.args, 1)
        self.assertLessEqual(proto.confidence, 0.6)


if __name__ == "__main__":
    unittest.main()
