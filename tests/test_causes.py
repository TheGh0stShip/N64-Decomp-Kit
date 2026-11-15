import struct
import unittest

from n64dk.analysis import flow
from n64dk.match import causes

BASE = 0x80001000


def code(words):
    return b"".join(struct.pack(">I", w) for w in words)


# retail: value in $s0 set before the call; candidate: value in $a1 set after the call
LIFE_T = [0x27BDFFE0, 0xAFBF001C, 0xAFB00018, 0x24100005, 0x0C000800, 0x00000000, 0x00501021, 0x8FBF001C,
          0x8FB00018, 0x03E00008, 0x27BD0020]
LIFE_C = [0x27BDFFE8, 0xAFBF0014, 0x0C000800, 0x00000000, 0x24050005, 0x00451021, 0x8FBF0014, 0x03E00008,
          0x27BD0018]
VOL_T = [0xA0850000, 0xA0860001, 0x03E00008, 0x00000000]        # sb; sb; jr ra; nop
VOL_C = [0xA0850000, 0x03E00008, 0xA0860001]                    # sb; jr ra; sb (in the delay slot)
SIGN_T = [0x84820004, 0x03E00008, 0x00000000]                   # lh
SIGN_C = [0x94820004, 0x03E00008, 0x00000000]                   # lhu
PERM_T = [0x00854021, 0x00864821, 0xACE80000, 0x03E00008, 0xACE90004]
PERM_C = [0x00854821, 0x00864021, 0xACE90000, 0x03E00008, 0xACE80004]
AT_T = [0x3C018001, 0x00240821, 0x8C220100, 0x03E00008, 0x00000000]          # lui at; addu at,at,a0; lw
AT_C = [0x3C028001, 0x24420100, 0x00441021, 0x8C420000, 0x03E00008, 0x00000000]
FRAGMENT = [0x96020060, 0x00481821, 0xA6030024, 0x8FBF001C, 0x03E00008, 0x27BD0020]
SPLIT = [0x27BDFFE8, 0xAFBF0014, 0x1480000F, 0x00000000, 0x0C000800, 0x00000000]
TAIL_JUMP = [0x24840001, 0x08000900, 0x00000000]                # addiu a0,1 ; j 0x80002400 ; nop


def ids(target, candidate=None, **kw):
    return [c.id for c in causes.diagnose(code(target), None if candidate is None else code(candidate), BASE, **kw)]


class DiagnoseTest(unittest.TestCase):
    def test_equal_code_has_no_cause(self):
        self.assertEqual(ids(SIGN_T, SIGN_T + [0, 0]), [])

    def test_missing_source(self):
        self.assertEqual(ids(SIGN_T), ["source.missing"])

    def test_signedness(self):
        found = causes.diagnose(code(SIGN_T), code(SIGN_C), BASE)
        self.assertEqual(found[0].id, "type.signedness")
        self.assertEqual(found[0].families[0], "types")

    def test_volatile_from_a_store_kept_out_of_the_delay_slot(self):
        found = causes.diagnose(code(VOL_T), code(VOL_C), BASE)
        self.assertEqual(found[0].id, "type.volatile")
        self.assertEqual(causes.family_order(found, ("types", "lifetime", "volatile"))[0], "volatile")

    def test_call_crossing_lifetime(self):
        found = {c.id: c for c in causes.diagnose(code(LIFE_T), code(LIFE_C), BASE)}
        self.assertIn("register.lifetime", found)
        self.assertIn("$s0", found["register.lifetime"].evidence[0])
        self.assertIn("frame.size", found)

    def test_register_permutation(self):
        found = causes.diagnose(code(PERM_T), code(PERM_C), BASE)
        self.assertEqual(found[0].id, "register.permutation")
        self.assertIn("$t0", found[0].evidence[0])

    def test_at_sequences_are_attributed_to_the_assembler(self):
        self.assertIn("assembler.variant", ids(AT_T, AT_C, pipeline="kmc+builtin"))
        self.assertNotIn("assembler.variant", ids(AT_T, AT_C, pipeline="ido5.3"))

    def test_compiler_family_fingerprint(self):
        ido = [0x00802825, 0x10000001, 0x00000000, 0x00A01025, 0x03E00008, 0x00000000]   # or-moves and `b`
        gcc = [0x00802821, 0x08000403, 0x00000000, 0x00A01021, 0x03E00008, 0x00000000]   # addu-moves and `j`
        self.assertEqual(causes.compiler_family(flow.analyse(code(ido), BASE))["family"], "ido")
        self.assertEqual(causes.compiler_family(flow.analyse(code(gcc), BASE))["family"], "gcc")
        found = causes.diagnose(code(ido), code(gcc), BASE, pipeline="kmc+builtin")
        self.assertEqual(found[0].id, "compiler.family")
        self.assertNotIn("compiler.family", [c.id for c in causes.diagnose(code(ido), code(gcc), BASE,
                                                                           pipeline="ido5.3")])

    def test_boundary_causes_come_from_the_target_alone(self):
        self.assertEqual(ids(FRAGMENT)[0], "boundary.fragment")
        self.assertEqual(ids(SPLIT)[0], "boundary.false_split")
        found = causes.diagnose(code(TAIL_JUMP), None, BASE, neighbours={BASE, 0x80003000})
        self.assertIn("boundary.shared_tail", [c.id for c in found])

    def test_every_cause_is_in_the_taxonomy(self):
        for target, candidate in ((LIFE_T, LIFE_C), (VOL_T, VOL_C), (PERM_T, PERM_C), (AT_T, AT_C), (FRAGMENT, None)):
            for cause in causes.diagnose(code(target), None if candidate is None else code(candidate), BASE):
                self.assertIn(cause.id, causes.TAXONOMY)
                self.assertTrue(cause.as_dict()["meaning"])


if __name__ == "__main__":
    unittest.main()
