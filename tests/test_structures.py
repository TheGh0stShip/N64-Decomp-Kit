from __future__ import annotations

import unittest
from types import SimpleNamespace

from n64dk.analysis.structures import context_header, infer
from n64dk.analysis.values import Access, CallSite


def fact(accesses=(), calls=()):
    return SimpleNamespace(accesses=list(accesses), calls=list(calls))


class StructureConstraintTest(unittest.TestCase):
    def test_cross_function_parameter_and_embedded_offset_unify(self):
        first, second = 0x80001000, 0x80002000
        facts = {
            first: fact(
                [Access(first + 4, ("param", 0), 4, "lw", 4, True, False, False)],
                [CallSite(first + 0x20, second, {4: (("param", 0), 0x20)}, frozenset({4}))]),
            second: fact(
                [Access(second + 4, ("param", 0), 8, "lhu", 2, False, False, False)]),
        }
        result = infer(facts, {first: "parent", second: "child"})
        self.assertEqual(result["layout_count"], 1)
        layout = result["layouts"][0]
        self.assertEqual([field["offset"] for field in layout["fields"]], [4, 0x28])
        self.assertEqual({member["function"] for member in layout["members"]}, {"parent", "child"})
        header = context_header(result)
        self.assertIn("field_0004", header)
        self.assertIn("field_0028", header)

    def test_conflicting_accesses_remain_explicit(self):
        address = 0x80001000
        facts = {address: fact([
            Access(address + 4, ("param", 0), 0, "lb", 1, True, False, False),
            Access(address + 8, ("param", 0), 0, "lw", 4, True, False, False),
        ])}
        result = infer(facts, {address: "conflict"})
        self.assertEqual(result["conflict_count"], 1)
        self.assertTrue(result["layouts"][0]["fields"][0]["conflict"])
        self.assertIn("conflict:", context_header(result))

    def test_loaded_pointer_field_is_a_separate_layout(self):
        address = 0x80001000
        nested = ("field", ("param", 0), 0x10)
        facts = {address: fact([
            Access(address + 4, ("param", 0), 0x10, "lw", 4, True, False, False),
            Access(address + 8, nested, 4, "sw", 4, None, True, False),
        ])}
        result = infer(facts, {address: "nested"})
        self.assertEqual(result["layout_count"], 2)


if __name__ == "__main__":
    unittest.main()
