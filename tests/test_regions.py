"""Recipe regions: the labelling of matched functions that explains most with fewest changes."""
import unittest

from n64dk.match import regions

O1, O2, IDO = "kmc+as -O1", "kmc+as -O2", "ido5.3 -O2"


def rows(pattern: str, base: int = 0x80001000) -> list[tuple[int, frozenset]]:
    """``1`` only -O1, ``2`` only -O2, ``b`` both, ``i`` IDO: one function every 0x40 bytes."""
    sets = {"1": {O1}, "2": {O2}, "b": {O1, O2}, "i": {IDO}}
    return [(base + 0x40 * n, frozenset(sets[c])) for n, c in enumerate(pattern)]


class SegmentTest(unittest.TestCase):
    def test_functions_both_levels_reproduce_belong_to_the_level_their_neighbours_need(self):
        runs = regions.segment(rows("1b1bb11b" + "2b22b2b2"), [O2, O1])
        self.assertEqual([recipe for _a, _b, recipe in runs], [O1, O2])
        self.assertIn(runs[1][0], (7, 8))                    # the function both reproduce may fall either side

    def test_one_function_only_the_other_level_reproduces_is_an_exception_not_a_region(self):
        runs = regions.segment(rows("111b1" + "2" + "1b111"), [O2, O1])
        self.assertEqual(runs, [(0, 10, O1)])

    def test_an_island_must_pay_for_two_changes(self):
        self.assertEqual(regions.segment(rows("1111" + "222" + "1111"), [O2, O1]), [(0, 10, O1)])
        runs = regions.segment(rows("1111" + "222222" + "1111"), [O2, O1])
        self.assertEqual([recipe for _a, _b, recipe in runs], [O1, O2, O1])

    def test_a_region_at_the_edge_pays_for_one(self):
        runs = regions.segment(rows("111111" + "222"), [O2, O1])
        self.assertEqual(runs, [(0, 5, O1), (6, 8, O2)])

    def test_nothing_contradicting_the_preferred_recipe_keeps_it(self):
        self.assertEqual(regions.segment(rows("bbbbbb"), [O2, O1]), [(0, 5, O2)])
        self.assertEqual(regions.segment(rows("bbbbbb"), [O1, O2]), [(0, 5, O1)])

    def test_a_second_compiler(self):
        runs = regions.segment(rows("1b11b1" + "iiii" + "2b2b22"), [O2, O1, IDO])
        self.assertEqual([recipe for _a, _b, recipe in runs], [O1, IDO, O2])

    def test_no_evidence(self):
        self.assertEqual(regions.segment([]), [])
        self.assertEqual(regions.Regions.build({}).regions, [])


class RegionsTest(unittest.TestCase):
    def build(self, pattern: str, unmatched_between: int = 0):
        evidence = dict(rows(pattern))
        starts = sorted(evidence)
        return regions.Regions.build({a: set(f) for a, f in evidence.items()}, starts, None, [O2, O1]), starts

    def test_unmatched_functions_take_the_recipe_of_the_region_they_lie_in(self):
        found, starts = self.build("1b1b11b1" + "22b22b22")
        self.assertEqual(found.recipe_at(starts[3] + 0x10), O1)          # inside a function of the first region
        self.assertEqual(found.recipe_at(starts[12]), O2)
        self.assertIsNone(found.recipe_at(starts[0] - 4))                # before the image's code
        self.assertEqual([(r.support, r.exceptions) for r in found.regions], [(8, 0), (8, 0)])

    def test_the_boundary_falls_halfway_between_the_regions_nearest_matched_members(self):
        evidence = {0x80001000: {O1}, 0x80001040: {O1}, 0x80001080: {O1},
                    0x80001200: {O2}, 0x80001240: {O2}, 0x80001280: {O2}}
        starts = list(range(0x80001000, 0x800012C0, 0x40))               # six unmatched functions between
        found = regions.Regions.build(evidence, starts, 0x800012C0, [O2, O1])
        self.assertEqual([(r.start, r.end, r.recipe) for r in found.regions],
                         [(0x80001000, 0x80001140, O1), (0x80001140, 0x800012C0, O2)])
        self.assertEqual(found.recipe_at(0x80001100), O1)
        self.assertEqual(found.recipe_at(0x80001180), O2)

    def test_a_region_with_too_few_functions_behind_it_is_not_offered(self):
        found = regions.Regions.build({0x80001000: {O1}, 0x80001040: {O1}}, None, None, [O2, O1])
        self.assertIsNone(found.recipe_at(0x80001000))
        self.assertEqual(found.recipe_at(0x80001000, min_support=2), O1)

    def test_recipes_that_explain_the_same_members_are_listed_as_alternatives(self):
        found, _starts = self.build("bbbb")
        self.assertEqual((found.regions[0].recipe, found.regions[0].alternatives), (O2, [O1]))

    def test_the_measured_shape_of_a_real_title(self):
        """Charlie Blast's Territory, GCC matches in address order (measured, round 9)."""
        pattern = ("11111211211112b1122211111b1bbb1bbb1bbbbbbbbbbbbbbbbbb11111bbbb1b11bb111121b21b12bb11111122b112211112"
                   "bb111b11bb22222222222b222b222222b22b22222b2222")
        found, starts = self.build(pattern)
        self.assertEqual([r.recipe for r in found.regions], [O1, O2])
        self.assertTrue(starts[105] <= found.regions[1].start <= starts[110])
        self.assertEqual(found.regions[0].exceptions, 14)                # -O2-only inside the -O1 game code


if __name__ == "__main__":
    unittest.main()
