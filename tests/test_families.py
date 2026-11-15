import shutil
import atexit
import tempfile
import unittest
from pathlib import Path

from n64dk.match import families, iterate


def _scratch(prefix: str = "n64dk-test-") -> str:
    """A scratch directory removed when the test process exits."""
    path = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, path, True)
    return path


SOURCE = """#include "types.h"

extern s8 gBytes[];
extern s32 gCount;
extern s32 helper(s32 value);

void emit(u8 *destination, s32 index) {
    s32 first;
    s32 total;
    u8 *cursor;

    first = gBytes[0];
    total = gCount;
    helper(index);
    total = total - first + index;
    cursor = (u8 *)destination;
    if (index - first == 0) {
        *(cursor + 1) = first;
    }
    destination[0] = total;
}
"""


def labels(names):
    return [v.label for v in families.variants(SOURCE, "emit", names)]


class FamilyTest(unittest.TestCase):
    def test_volatile_sites(self):
        found = labels(("volatile",))
        self.assertIn("parameter destination: pointer to volatile", found)
        self.assertIn("local cursor: pointer to volatile", found)
        self.assertIn("global gBytes: volatile", found)
        self.assertTrue(any(l.startswith("cast #1") for l in found))
        variant = next(v for v in families.variants(SOURCE, "emit", ("volatile",))
                       if v.label == "parameter destination: pointer to volatile")
        self.assertIn("void emit(volatile u8 *destination, s32 index)", variant.source)
        self.assertTrue(variant.semantic_review)

    def test_volatile_can_be_removed_again(self):
        source = SOURCE.replace("void emit(u8 *destination", "void emit(volatile u8 *destination")
        found = [v for v in families.variants(source, "emit", ("volatile",)) if "drop volatile" in v.label]
        self.assertEqual(len(found), 1)
        self.assertIn("void emit(u8 *destination, s32 index)", found[0].source)

    def test_global_declaration_variants_only_touch_referenced_globals(self):
        found = labels(("globals",))
        self.assertIn("global gBytes: array -> pointer", found)
        self.assertIn("global gCount: s32 -> u16", found)
        self.assertIn("global gCount: scalar -> array", found)
        self.assertFalse([l for l in found if "helper" in l])

    def test_pointer_forms(self):
        found = labels(("pointer",))
        self.assertTrue(any(l.startswith("deref-sum to index") for l in found))
        self.assertTrue(any(l.startswith("index to deref-sum") for l in found))

    def test_pass_through_arguments(self):
        source = ("extern s32 next();\nvoid step(void *object, s32 mode) {\n    next();\n    other(object);\n"
                  "    last(mode);\n}\n")
        found = [v.label for v in families.variants(source, "step", ("callargs",))]
        self.assertEqual(found, ["line 2: next() -> next(object)", "line 2: next() -> next(object, mode)",
                                 "line 3: other(object) -> other(object, mode)"])     # last(mode) is not a prefix
        variant = families.variants(source, "step", ("callargs",))[0]
        self.assertIn("    next(object);\n", variant.source)
        self.assertTrue(variant.semantic_review)

    def test_evidence_selects_volatile_for_a_store_in_a_delay_slot(self):
        report = {"counts": {"scheduling": 2}, "entries": [
            {"compiled": "", "retail": "sb $a2, 0x1($a0)"},
            {"compiled": "sb $a2, 0x1($a0)", "retail": "nop"}]}
        self.assertEqual(families.evidence_families(report)[0], "volatile")
        self.assertEqual(iterate._family_order(report, iterate.FAMILIES)[0], "volatile")
        self.assertEqual(families.evidence_families({"counts": {"register": 2}, "entries": []}), [])


class SafetyTest(unittest.TestCase):
    """Moves and rewrites that are offered without review must preserve behaviour."""

    def setUp(self):
        self.items = iterate.variants(SOURCE, "emit", ("lifetime", "expression"))
        self.labels = [v.label for v in self.items]

    def test_a_global_read_never_moves_across_a_call(self):
        self.assertFalse([l for l in self.labels if "total = gCount" in l])
        self.assertFalse([l for l in self.labels if "first = gBytes" in l])

    def test_non_associative_rewrite_is_not_offered(self):
        self.assertFalse([v for v in self.items if "total -= first + index" in v.source])

    def test_zero_compare_of_a_difference_is_not_negated(self):
        self.assertFalse([v for v in self.items if "index - !first" in v.source])

    def test_extension_families_are_reachable_through_iterate(self):
        found = [v.label for v in iterate.variants(SOURCE, "emit", ("volatile",))]
        self.assertIn("parameter destination: pointer to volatile", found)


def _kmc():
    """(build function, None) or (None, reason) -- real compiler regressions need the KMC toolchain."""
    try:
        from n64dk.match import compare as cmp
        from n64dk.elf import Elf
        from n64dk.match.pipeline import build, split_flags
        from n64dk.match.toolchain import load_config
    except Exception as error:                                  # pragma: no cover
        return None, str(error)
    project = Path(_scratch("n64dk-families-"))
    cfg = load_config(project, None, None)
    if cfg.toolchain("kmc") is None:
        return None, "KMC GCC toolchain not configured (N64DK_TOOLCHAIN)"
    spec = split_flags(["-O2", "-G0", "-mips3", "-mgp32", "-mfp32"], "kmc+builtin")
    counter = [0]

    def compile_text(text: str) -> bytes:
        counter[0] += 1
        folder = project / f"c{counter[0]}"
        folder.mkdir()
        path = folder / "unit.c"
        path.write_text(text)
        elf = Elf.load(build(path, spec, cfg, folder))
        return cmp.find_section(elf, ".text").data.rstrip(b"\0")
    return compile_text, None


PRELUDE = "typedef unsigned char u8; typedef signed char s8; typedef int s32;\nextern s8 gBytes[];\n"
PLAIN = PRELUDE + "void put(u8 *destination, s32 a, s32 b) {\n    destination[0] = a;\n    destination[1] = b;\n}\n"
WIDE = PRELUDE + ("void copy(u8 *destination) {\n    s32 a;\n    s32 b;\n\n    a = gBytes[0];\n    b = gBytes[1];\n"
                  "    destination[0] = a;\n    destination[1] = b;\n}\n")


class CompilerRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compile_text, reason = _kmc()
        if compile_text is None:
            raise unittest.SkipTest(reason)
        cls.compile = staticmethod(compile_text)

    def test_volatile_pointer_keeps_the_store_out_of_the_jump_delay_slot(self):
        plain = self.compile(PLAIN)
        volatile = self.compile(PLAIN.replace("u8 *destination", "volatile u8 *destination"))
        # sb a1,0(a0); jr ra; sb a2,1(a0)      versus      sb; sb; jr ra; (nop)
        self.assertEqual(plain[-4:].hex(), "a0860001")
        self.assertEqual(plain[-8:-4].hex(), "03e00008")
        self.assertIn(bytes.fromhex("a0860001" "03e00008"), volatile + b"\0\0\0\0")

    def test_signed_byte_global_needs_a_wide_local_to_load_signed(self):
        wide = self.compile(WIDE)
        narrow = self.compile(WIDE.replace("s32 a;", "s8 a;").replace("s32 b;", "s8 b;"))
        opcodes = lambda code: {code[i] >> 2 for i in range(0, len(code), 4)}
        self.assertIn(0x20, opcodes(wide))          # lb
        self.assertNotIn(0x24, opcodes(wide))       # no lbu
        self.assertIn(0x24, opcodes(narrow))        # the narrow local loads unsigned

    def test_iterate_recovers_the_volatile_qualifier_by_itself(self):
        target = self.compile(PLAIN.replace("u8 *destination", "volatile u8 *destination"))

        def evaluate(text):
            try:
                built = self.compile(text)
            except Exception as error:
                return iterate.Evaluation(None, error=str(error))
            differences = sum(1 for i in range(0, max(len(built), len(target)), 4)
                              if built[i:i + 4] != target[i:i + 4])
            entries = [{"compiled": "sb $a2, 0x1($a0)", "retail": "nop"}] if differences else []
            return iterate.Evaluation(differences, differences == 0, {"counts": {}, "entries": entries})
        result = iterate.descend(PLAIN, "put", evaluate, jobs=1, budget=60)
        self.assertTrue(result["exact"], result.get("steps"))
        self.assertEqual(result["steps"][-1]["applied"], "parameter destination: pointer to volatile")

    def test_iterate_recovers_the_wide_local(self):
        target = self.compile(WIDE)
        start = WIDE.replace("s32 a;", "s8 a;")

        def evaluate(text):
            try:
                built = self.compile(text)
            except Exception as error:
                return iterate.Evaluation(None, error=str(error))
            differences = sum(1 for i in range(0, max(len(built), len(target)), 4)
                              if built[i:i + 4] != target[i:i + 4])
            return iterate.Evaluation(differences, differences == 0, {"counts": {}, "entries": []})
        result = iterate.descend(start, "copy", evaluate, jobs=1, budget=120)
        self.assertTrue(result["exact"], result.get("steps"))


if __name__ == "__main__":
    unittest.main()
