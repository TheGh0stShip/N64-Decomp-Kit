import unittest

from n64dk.match.semantic_checks import check_unsigned_mask_identity


class SemanticChecksTests(unittest.TestCase):
    def test_catalog_r148_is_not_an_identity(self):
        result = check_unsigned_mask_identity(8, 0x377)
        self.assertFalse(result["equivalent"])
        self.assertEqual(result["counterexample_count"], 192)
        self.assertEqual(result["first_counterexample"]["input"], 8)

    def test_octal_0377_is_an_unsigned_byte_identity(self):
        self.assertTrue(check_unsigned_mask_identity(8, 0o377)["equivalent"])

    def test_domain_bounds_are_enforced(self):
        with self.assertRaises(ValueError):
            check_unsigned_mask_identity(32, 0xFFFFFFFF)
