import struct
import unittest

from n64dk.match import score as sc


def asm(*words):
    return b"".join(struct.pack(">I", w) for w in words)


BASE = asm(0x27BDFFE8, 0xAFBF0014, 0x8C820000, 0x10400002, 0x00000000, 0x24420001,
           0x8FBF0014, 0x03E00008, 0x27BD0018)


class ScoreTest(unittest.TestCase):
    def test_identical_is_zero(self):
        result = sc.score(BASE, BASE, 0x80001000)
        self.assertEqual((result.total, result.percent), (0, 100.0))
        self.assertEqual(result.max_score, 900)

    def test_position_independent(self):
        self.assertEqual(sc.rows(BASE, 0x80001000)[3].text, sc.rows(BASE, 0x80200000)[3].text)

    def test_register_difference_is_five_per_field(self):
        other = bytearray(BASE); other[8:12] = struct.pack(">I", 0x8C830000)   # lw $v1 instead of $v0
        result = sc.score(BASE, bytes(other), 0x80001000)
        self.assertEqual((result.regalloc, result.total), (1, 5))

    def test_stack_offset_difference(self):
        other = bytearray(BASE); other[4:8] = struct.pack(">I", 0xAFBF0010)   # sw $ra, 0x10($sp)
        result = sc.score(BASE, bytes(other), 0x80001000)
        self.assertEqual((result.stack, result.regalloc, result.total), (4, 0, 4))
        self.assertEqual(sc.score(BASE, bytes(other), 0x80001000, stack_differences=False).total, 1)

    def test_branch_target_difference(self):
        other = bytearray(BASE); other[12:16] = struct.pack(">I", 0x10400003)
        result = sc.score(BASE, bytes(other), 0x80001000)
        self.assertEqual((result.branch, result.total), (1, 1))

    def test_reordering_and_insertion(self):
        swapped = BASE[:20] + BASE[24:28] + BASE[20:24] + BASE[28:]
        self.assertEqual(sc.score(BASE, swapped, 0x80001000).reordering, 1)
        longer = BASE[:20] + asm(0x00431021) + BASE[20:]
        result = sc.score(BASE, longer, 0x80001000)
        self.assertEqual((result.insertion, result.total), (1, 100))


if __name__ == "__main__":
    unittest.main()
