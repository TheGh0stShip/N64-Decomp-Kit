import struct
import unittest

from n64dk.analysis import units

BASE = 0x80001000
RET = [0x03E00008, 0x00000000]                         # jr ra; nop


def image(*chunks):
    return b"".join(struct.pack(">I", w) for chunk in chunks for w in chunk)


class UnitsTest(unittest.TestCase):
    def setUp(self):
        # f1: 8 bytes + 8 bytes padding -> object ends at 0x10; f2 at 0x10 (16 bytes, ends on 0x20);
        # f3 directly after f2 at 0x20 (aligned, no padding before it): undecided -> same unit;
        # f4 at 0x28 unaligned: same unit; then padding to 0x40 and f5 at 0x40: new unit.
        self.data = image(RET, [0, 0], [0x24020001, 0x24020002] + RET, RET, RET + [0, 0, 0, 0], RET)
        self.functions = [("f1", BASE, 0x10), ("f2", BASE + 0x10, 0x10), ("f3", BASE + 0x20, 8),
                          ("f4", BASE + 0x28, 0x18), ("f5", BASE + 0x40, 8)]

    def test_boundaries_follow_alignment_plus_padding(self):
        found = units.units(self.data, BASE, self.functions)
        self.assertEqual([[f[0] for f in u.functions] for u in found], [["f1"], ["f2", "f3", "f4"], ["f5"]])
        self.assertEqual([u.closed for u in found], [True, True, False])
        self.assertEqual(found[0].padding, 8)

    def test_padding_left_between_catalogue_rows_counts(self):
        functions = [("f1", BASE, 8), ("f2", BASE + 0x10, 0x10)]       # the catalogue excluded the padding
        found = units.units(self.data, BASE, functions)
        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].closed)

    def test_family_change_splits(self):
        families = iter(["ido", "ido", "gcc", "gcc", "gcc"] * 2)
        found = units.units(self.data, BASE, self.functions, family_of=lambda flow: next(families))
        self.assertEqual([[f[0] for f in u.functions] for u in found], [["f1"], ["f2"], ["f3", "f4"], ["f5"]])

    def test_recipe_candidates_prefer_the_same_unit_then_neighbours(self):
        found = units.units(self.data, BASE, self.functions)
        recipes = units.RecipeMap(found)
        recipes.add(BASE, 0x10, "ido5.3", ["-O1"])               # unit 0
        recipes.add(BASE + 0x20, 8, "ido5.3", ["-O2", "-g3"])    # unit 1 (same unit as f4)
        recipes.add(BASE + 0x40, 8, "kmc+as", ["-O2"])           # unit 2
        ranked = recipes.candidates(BASE + 0x28)
        self.assertEqual((ranked[0]["pipeline"], ranked[0]["flags"], ranked[0]["same_unit"]),
                         ("ido5.3", ["-O2", "-g3"], True))
        self.assertEqual({r["pipeline"] for r in ranked}, {"ido5.3", "kmc+as"})
        self.assertEqual(recipes.summary()["units_with_conflicting_recipes"], 0)
        recipes.add(BASE + 0x10, 0x10, "ido7.1", ["-O2"])        # a second recipe inside unit 1
        self.assertEqual(recipes.summary()["units_with_conflicting_recipes"], 1)


if __name__ == "__main__":
    unittest.main()
