import struct
import unittest

from n64dk.analysis import fragments
from n64dk.match import similar


def asm(*words):
    return b"".join(struct.pack(">I", w) for w in words)


class SimilarTest(unittest.TestCase):
    def test_similarity_bounds(self):
        self.assertEqual(similar.similarity(("a", "b", "c"), ("a", "b", "c")), 1.0)
        self.assertAlmostEqual(similar.similarity(("a", "b", "c", "d"), ("a", "x", "c", "d")), 0.75)
        self.assertEqual(similar.similarity(("a",) * 10, ("b",) * 10, 0.8), 0.0)

    def test_queue_prefers_functions_with_matched_sibling(self):
        body = asm(0x27BDFFE8, 0xAFBF0014, 0x8C820000, 0x24420001, 0xAC820000, 0x8FBF0014, 0x03E00008, 0x27BD0018)
        other = asm(0x03E00008, 0x00000000)
        items = [similar.signature("matched", body, 0x80001000, matched=True, source="src/a.c"),
                 similar.signature("twin", body, 0x80002000), similar.signature("lonely", other, 0x80003000)]
        rows = similar.queue(items, threshold=0.8)
        self.assertEqual([r["name"] for r in rows], ["twin", "lonely"])
        self.assertEqual(rows[0]["references"][0]["source"], "src/a.c")


class FragmentTest(unittest.TestCase):
    def test_fall_through_fragment_is_merged_and_called_entry_kept(self):
        base = 0x80001000
        code = asm(
            0x27BDFFE8, 0x10800002, 0x00000000, 0x24020001,   # f0: frame, beqz a0 -> +0x10 (into "f1")
            0x00431021, 0x03E00008, 0x27BD0018, 0x00000000,   # "f1" at +0x10: addu v0,v0,v1 ; jr ra
            0x03E00008, 0x24020005,                           # f2 at +0x20: called below
            0x0C000408, 0x00000000, 0x03E00008, 0x00000000)   # f3 at +0x28: jal f2
        report = fragments.audit(code, base, [("f0", base, 0x10), ("f1", base + 0x10, 0x10),
                                              ("f2", base + 0x20, 8), ("f3", base + 0x28, 0x10)])
        flags = {s["name"]: s["fragment"] for s in report["starts"]}
        self.assertEqual(flags, {"f0": False, "f1": True, "f2": False, "f3": False})
        self.assertEqual(report["merges"][0]["absorbs"], ["f1"])
        self.assertEqual(report["merges"][0]["size"], 0x20)


if __name__ == "__main__":
    unittest.main()
