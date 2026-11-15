import unittest

from n64dk.match.ownership import build, progress


class OwnershipTest(unittest.TestCase):
    def inventory(self):
        base = {"image": "main", "section_vram": "0x80000000", "section_size": 0x30,
                "section_rom": "0x1000", "state": "remaining", "reason": "fixture", "id": "x"}
        rows = [
            {**base, "name": "a", "vram": "0x80000000", "size": 0x10,
             "ownership_state": "manifest_exact_unit", "owner": "src/a.c"},
            {**base, "name": "b", "vram": "0x80000010", "size": 0x08,
             "ownership_state": "manifest_nonexact", "owner": "src/b.c"},
            {**base, "name": "c", "vram": "0x80000020", "size": 0x10,
             "ownership_state": "assembly_unit", "owner": "asm/c.s"},
        ]
        return {"summary": {"functions": 3, "declared_functions": 4, "denominator_delta": -1},
                "functions": rows}

    def test_partition_preserves_gaps_and_claims(self):
        result = build(self.inventory())
        self.assertTrue(result["complete_partition"])
        self.assertFalse(result["authoritative_complete"])
        self.assertEqual(result["totals"], {"verified_c": 16, "claimed_c": 8,
                                            "unknown": 8, "assembly": 16})
        self.assertEqual(result["unresolved_bytes"], 16)

    def test_progress_separates_denominator_and_claims(self):
        inventory = self.inventory(); result = progress(inventory, build(inventory))
        self.assertEqual(result["functions"]["verified_c"], 1)
        self.assertEqual(result["functions"]["claimed_c"], 1)
        self.assertEqual(result["functions"]["denominator_delta"], -1)
        self.assertTrue(result["invariants"]["one_class_per_byte"])


if __name__ == "__main__": unittest.main()
