import unittest
import tempfile
from pathlib import Path

from n64dk.match import iterate
from n64dk.match.pipeline import _INCLUDE_FILE_CACHE, _include_closure_digest

SOURCE = """#include "types.h"

extern s16 g(s16 index);

s32 f(u16 start) {
    s32 found;
    u16 offset;
    s16 index;

    index = g(start + 1);
    offset = 0;
    found = 0;
    while (found < 5) {
        if (*(s16 *)(index + offset) != -1) {
            found = (u16)found + 1;
        }
        offset++;
    }
    return found;
}
"""


class VariantTest(unittest.TestCase):
    def setUp(self):
        self.items = iterate.variants(SOURCE, "f")
        self.labels = [v.label for v in self.items]

    def test_type_variants_cover_locals_parameter_and_return(self):
        self.assertIn("type offset: u16 -> s16", self.labels)
        self.assertIn("param start: u16 -> s32", self.labels)
        self.assertIn("return type: s32 -> u16", self.labels)

    def test_pure_initialisation_moves_across_the_call(self):
        moved = next(v for v in self.items if v.label == "move `offset = 0;` up 1 across a call")
        self.assertLess(moved.source.index("offset = 0;"), moved.source.index("index = g("))

    def test_moves_never_cross_a_use_or_an_impure_statement(self):
        # ``found = 0`` cannot sink past the loop that reads it; the call result cannot move at all
        self.assertFalse([l for l in self.labels if l.startswith("move `found = 0;` down")])
        self.assertFalse([l for l in self.labels if "index = g(" in l])

    def test_field_and_cast_flips(self):
        self.assertTrue(any(l.startswith("field #1") and "u16 *" in l for l in self.labels))
        self.assertTrue(any("drop (u16)" in l for l in self.labels))

    def test_all_variants_are_distinct_and_only_touch_the_function(self):
        self.assertEqual(len({v.source for v in self.items}), len(self.items))
        self.assertTrue(all(v.source.startswith('#include "types.h"\n\nextern s16 g(s16 index);') for v in self.items))

    def test_expression_forms_and_review_markers(self):
        items = iterate.variants(SOURCE.replace("offset++;", "offset += 1;"), "f")
        self.assertTrue(any(v.label.startswith("add-to-postincrement") for v in items))
        self.assertTrue(any(v.semantic_review for v in items if v.family in {"types", "casts"}))

    def test_order_never_swaps_initialized_declarations(self):
        text = SOURCE.replace("    s32 found;\n    u16 offset;", "    s32 found = 1;\n    u16 offset = found;")
        self.assertFalse([v for v in iterate.variants(text, "f", ("order",))])


class DescendTest(unittest.TestCase):
    def test_descent_finds_two_step_answer_and_reports_sensitivity(self):
        def evaluate(text):
            score = 0
            score += 0 if "s16 offset;" in text else 10          # wrong type costs 10
            score += 0 if text.index("found = 0;") < text.index("index = g(") else 7   # must cross the call
            return iterate.Evaluation(score, score == 0, {"counts": {}, "entries": []})
        result = iterate.descend(SOURCE, "f", evaluate, jobs=1)
        self.assertTrue(result["exact"])
        self.assertEqual((result["start_score"], result["final_score"]), (17, 0))
        self.assertEqual([s["applied"] for s in result["steps"]],
                         ["type offset: u16 -> s16",
                          "type offset: u16 -> s16 ; move `found = 0;` up 2 across a call"])
        self.assertEqual(result["sensitivity"][0]["delta"], -10)

    def test_beam_reaches_an_answer_that_needs_two_edits_at_once(self):
        def evaluate(text):
            both = "s16 offset;" in text and text.index("found = 0;") < text.index("index = g(")
            return iterate.Evaluation(0 if both else 9, both, {"counts": {}, "entries": []})
        self.assertTrue(iterate.descend(SOURCE, "f", evaluate, jobs=1, beam=64, per_round=200)["exact"])

    def test_evidence_counts_saved_registers(self):
        report = {"entries": [{"compiled": "", "retail": "sw $s0, 0x10($sp)"},
                              {"compiled": "", "retail": "sw $s1, 0x14($sp)"},
                              {"compiled": "lhu $v0, 0x8($a0)", "retail": "lh $v0, 0x8($a0)"}]}
        seen = iterate.evidence(report)
        self.assertEqual((seen["saved_registers_missing"], seen["width_or_sign_sites"]), (2, 1))


class IncludeClosureTest(unittest.TestCase):
    def test_only_reachable_headers_affect_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); include = root / "include"; scratch = root / "scratch"
            include.mkdir(); scratch.mkdir()
            source = scratch / "candidate.c"
            source.write_text('#include "used.h"\nint f(void) { return VALUE; }\n')
            (include / "used.h").write_text('#include "nested.h"\n')
            nested = include / "nested.h"; nested.write_text('#define VALUE 1\n')
            for index in range(2000):
                (scratch / f"unrelated_{index}.c").write_text("int ignored;\n")
            _INCLUDE_FILE_CACHE.clear()
            first = _include_closure_digest(source, (include, scratch))
            (scratch / "unrelated_1999.c").write_text("int changed;\n")
            self.assertEqual(first, _include_closure_digest(source, (include, scratch)))
            nested.write_text('#define VALUE 2\n')
            self.assertNotEqual(first, _include_closure_digest(source, (include, scratch)))

    def test_forced_include_is_in_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "candidate.c"; forced = root / "forced.h"
            source.write_text("int f(void) { return VALUE; }\n"); forced.write_text("#define VALUE 1\n")
            first = _include_closure_digest(source, (root,), ("forced.h",))
            forced.write_text("#define VALUE 2\n")
            self.assertNotEqual(first, _include_closure_digest(source, (root,), ("forced.h",)))

    def test_command_line_computed_include_is_in_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / "candidate.c"; header = root / "selected.h"
            source.write_text("#include HEADER\nint f(void) { return VALUE; }\n")
            header.write_text("#define VALUE 1\n")
            macros = {"HEADER": (b'"', b"selected.h")}
            first = _include_closure_digest(source, (root,), command_macros=macros)
            header.write_text("#define VALUE 2\n")
            self.assertNotEqual(first, _include_closure_digest(source, (root,),
                                                               command_macros=macros))


if __name__ == "__main__":
    unittest.main()
