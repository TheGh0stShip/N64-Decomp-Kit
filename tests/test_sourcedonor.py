"""A source tree as a donor: what is found without a compiler, and (with one) the whole path."""
import os
import tempfile
import unittest
from pathlib import Path

from n64dk.match import sourcedonor


def tree_of(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="n64dk-test-tree-"))
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return root


class TreeTest(unittest.TestCase):
    def setUp(self):
        self.root = tree_of({
            "src/game/a.c": '#include "common.h"\n#include <PR/os.h>\n#include "local.h"\nint a(void) { return 1; }\n',
            "src/game/local.h": "#ifdef VERSION_B\n#define N 2\n#else\n#define N 1\n#endif\n",
            "src/game/table.c": "int table[] = { 1, 2, 3 };\n",
            "src/game/part.inc.c": "int part(void) { return 0; }\n",
            "src/b.c": '#include "common.h"\n#if defined(VERSION_A) && !defined(GUARD_H)\nint b(void) { return 2; }\n#endif\n'
                       "int c(void) { return 3; }\n",
            "include/common.h": "#ifndef GUARD_H\n#define GUARD_H\n#ifdef __sgi\n#endif\n#if DEBUG_LEVEL > 1\n#endif\n#endif\n",
            "include/PR/os.h": "typedef int OSTime;\n",
            "lib/include/PR/os.h": "typedef int Other;\n",
            "tools/host.c": "int main(void) { return 0; }\n",
            "build/us/src/gen.c": "int gen(void) { return 0; }\n",
            ".git/x.c": "int x(void) { return 0; }\n",
        })
        self.tree = sourcedonor.Tree(self.root)

    def test_units_are_c_files_with_a_function_body_outside_generated_directories(self):
        self.assertEqual(self.tree.units, ["src/b.c", "src/game/a.c"])

    def test_include_directories_come_from_the_include_lines(self):
        roots = [path.relative_to(self.root).as_posix() for path in self.tree.resolve_all()]
        self.assertEqual(roots, ["include"])                 # PR/os.h resolves under include/, already a root
        self.assertEqual(self.tree.includes("src/game/a.c"), ["include/common.h", "include/PR/os.h", "src/game/local.h"])

    def test_a_name_beside_the_including_file_needs_no_directory(self):
        self.assertEqual(self.tree.find("local.h", "src/game/a.c", True), "src/game/local.h")
        self.assertIsNone(self.tree.find("nowhere.h", "src/game/a.c", True))

    def test_configuration_macros_are_tested_and_never_defined(self):
        # DEBUG_LEVEL is compared with a number: offered at that number and one above
        self.assertEqual(self.tree.macros(), [("DEBUG_LEVEL=1", 1), ("DEBUG_LEVEL=2", 1), ("VERSION_A", 1), ("VERSION_B", 1)])

    def test_the_units_that_can_see_a_macro(self):
        self.assertEqual(self.tree.seeing("VERSION_B"), ["src/game/a.c"])       # through local.h
        self.assertEqual(self.tree.seeing("DEBUG_LEVEL=2"), ["src/b.c", "src/game/a.c"])


class DefinedTest(unittest.TestCase):
    def test_a_name_defined_under_a_condition_can_still_be_set_from_outside(self):
        text = ("#ifndef GUARD_H\n#define GUARD_H\n#define ALWAYS 1\n#ifdef DIALECT_B\n#define DIALECT_A\n#endif\n"
                "#ifndef FALLBACK\n#define FALLBACK 0\n#endif\n#endif\n#define AFTER\n")
        # FALLBACK is its own guard: the tree always ends up defining it
        self.assertEqual(sourcedonor.always_defined(text), {"GUARD_H", "ALWAYS", "FALLBACK", "AFTER"})

    def test_a_conditionally_defined_name_that_is_tested_is_a_candidate(self):
        root = tree_of({"a.c": '#include "d.h"\n#ifdef DIALECT_A\nint f(void) { return 1; }\n#endif\nint g(void) { return 2; }\n',
                        "d.h": "#ifdef DIALECT_B\n#define DIALECT_A\n#endif\n"})
        self.assertEqual([name for name, _count in sourcedonor.Tree(root).macros()], ["DIALECT_A", "DIALECT_B"])


class CandidateRecipeTest(unittest.TestCase):
    def test_the_first_recipe_is_also_offered_at_the_other_levels(self):
        from n64dk.commands.sourcedonor import with_levels
        self.assertEqual(with_levels(["ido5.3 -g -mips2", "ido7.1 -O2 -mips2"]),
                         ["ido5.3 -g -mips2", "ido7.1 -O2 -mips2", "ido5.3 -O2 -mips2", "ido5.3 -O1 -mips2"])
        self.assertEqual(with_levels(["kmc+as -O2 -G0"]), ["kmc+as -O2 -G0", "kmc+as -O0 -G0", "kmc+as -O1 -G0"])
        self.assertEqual(with_levels([]), [])

    def test_recipes_come_from_what_a_run_matched(self):
        import json
        import sqlite3
        from n64dk.commands.sourcedonor import recipes_of_run
        run = Path(tempfile.mkdtemp(prefix="n64dk-test-run-"))
        (run / "state").mkdir()
        db = sqlite3.connect(run / "state" / "cases.sqlite")
        db.execute("create table cases (case_id text, status text, payload text)")
        rows = [("exact", "a -O2")] * 5 + [("assumed", "b -O2")] * 3 + [("exact", "c -O2")] * 2 + [("open", "d -O2")] * 9
        db.executemany("insert into cases values (?, ?, ?)",
                       [(str(i), status, json.dumps({"recipe": recipe})) for i, (status, recipe) in enumerate(rows)])
        db.commit()
        db.close()
        self.assertEqual(recipes_of_run(run), ["a -O2", "b -O2", "a -O0", "a -O1"])
        self.assertEqual(recipes_of_run(run / "missing"), [])


class WrittenInCTest(unittest.TestCase):
    def setUp(self):
        self.tree = sourcedonor.Tree(tree_of({
            "a.c": '#include "part.inc.c"\n#include "protos.h"\n'
                   'INCLUDE_ASM("asm/nonmatchings/a", func_80001000);\n'
                   'GLOBAL_ASM("asm/b.s")\nstatic int helper(int (*call)(int), int n) {\n    return call(n);\n}\n'
                   "void\nspread_out (void)\n{\n}\n",
            "part.inc.c": "int included(void) { return 1; }\n",
            "protos.h": "void func_80001004(void);\n",
        }))

    def test_only_a_name_with_a_parameter_list_and_a_body_is_written_in_c(self):
        for label in ("helper", "spread_out", "included"):
            self.assertTrue(self.tree.defines("a.c", label), label)
        # pulled in through the assembler, or only declared: the title's own bytes, not a decompilation
        for label in ("func_80001000", "func_80001004", "call", "nowhere"):
            self.assertFalse(self.tree.defines("a.c", label), label)


class SelectionTest(unittest.TestCase):
    def test_each_unit_takes_the_recipe_that_finds_most_of_it(self):
        found = {"gcc -O2": {"a.c": 3, "b.c": 0, "c.c": 1}, "gcc -g": {"a.c": 1, "b.c": 4, "c.c": 1}}
        chosen, majority = sourcedonor.choose_recipes(found, ["gcc -O2", "gcc -g"])
        self.assertEqual(chosen, {"a.c": "gcc -O2", "b.c": "gcc -g", "c.c": "gcc -O2"})    # a tie: the first listed
        self.assertEqual(majority, "gcc -O2")

    def test_a_unit_found_under_no_recipe_is_left_to_the_majority(self):
        chosen, majority = sourcedonor.choose_recipes({"x": {"a.c": 0}, "y": {"a.c": 0, "b.c": 2}}, ["x", "y"])
        self.assertEqual((chosen, majority), ({"b.c": "y"}, "y"))

    def test_of_two_macros_that_exclude_each_other_the_better_one_is_kept(self):
        def measure(macros, _candidate):                     # two releases: B wins when both are set
            if "REL_B" in macros:
                return 4 + ("OPTION" in macros)
            return (9 if "REL_A" in macros else 2) + ("OPTION" in macros)
        kept, trials = sourcedonor.choose_macros(["REL_B", "REL_A", "OPTION", "NOTHING"], measure)
        self.assertEqual(kept, ["REL_A", "OPTION"])
        by_name = {row["macro"]: row for row in trials}
        self.assertFalse(by_name["REL_B"]["kept"])
        self.assertLess(by_name["REL_B"]["with"], by_name["REL_B"]["without"])     # measured on top of the release kept
        self.assertFalse(by_name["NOTHING"]["kept"])

    def test_a_macro_that_only_counts_once_another_is_set_is_found_in_a_later_round(self):
        def measure(macros, _candidate):                     # nothing compiles without PLATFORM
            return 0 if "PLATFORM" not in macros else 5 + 4 * ("RELEASE" in macros)
        kept, trials = sourcedonor.choose_macros(["RELEASE", "PLATFORM"], measure)
        self.assertEqual(kept, ["PLATFORM", "RELEASE"])
        self.assertEqual({row["macro"]: row["round"] for row in trials}, {"RELEASE": 2, "PLATFORM": 1})

    def test_one_value_of_a_compared_macro_is_kept(self):
        def measure(macros, _candidate):                     # found: more the closer the release
            return max([{"REL=REL_A": 3, "REL=REL_B": 8, "REL=REL_C": 5}.get(macro, 0) for macro in macros] or [1])
        kept, _trials = sourcedonor.choose_macros(["REL=REL_A", "REL=REL_B", "REL=REL_C"], measure)
        self.assertEqual(kept, ["REL=REL_B"])

    def test_a_macro_compared_with_names_the_tree_defines_is_offered_at_each(self):
        root = tree_of({"a.c": '#include "v.h"\n#if REL >= REL_B\nint f(void) { return 1; }\n#endif\n'
                               "#if REL == REL_A || OTHER < UNKNOWN_NAME\nint g(void) { return 2; }\n#endif\n",
                        "v.h": "#define REL_A 1\n#define REL_B 2\n"})
        tree = sourcedonor.Tree(root)
        # OTHER and UNKNOWN_NAME are compared only with each other: nothing to set them to
        self.assertEqual([name for name, _count in tree.macros()], ["OTHER", "REL=REL_A", "REL=REL_B", "UNKNOWN_NAME"])

    def test_spread_takes_evenly_spaced_items(self):
        self.assertEqual(sourcedonor.spread(list(range(10)), 5), [0, 2, 4, 6, 8])
        self.assertEqual(sourcedonor.spread([1, 2], 5), [1, 2])


class FunctionsTest(unittest.TestCase):
    def test_sizes_are_filled_from_the_next_symbol_and_the_unit_end(self):
        base = sourcedonor.BASE
        listing = f"{base:08x} T first\n{base + 0x10:08x} 00000008 T second\n{base + 0x40:08x} D data\n"
        functions, lines = sourcedonor.functions_of(listing, [(base, base + 0x10), (base + 0x10, base + 0x20)])
        self.assertEqual(functions, [["first", base, 0x10], ["second", base + 0x10, 8]])
        self.assertEqual(len(lines), 3)


@unittest.skipUnless(os.environ.get("N64DK_TOOLCHAIN"), "needs the compilers")
class WholePathTest(unittest.TestCase):
    """A small tree is built one way as "the title"; the importer, told nothing, must find that way."""

    FILES = {
        "code/one.c": '#include "shared.h"\n'
                      "int one(int *p, int n) { int s = 0; int i; for (i = 0; i < n; i++) { s += p[i] * SCALE; } return s; }\n"
                      "int two(int a, int b) { if (a > b) { return a * 3 + b; } return b * 5 - a; }\n",
        "code/three.c": '#include "shared.h"\n'
                        "#ifdef WITH_EXTRA\nint extra(int a, int b, int c) { return (a + b) * (c - a) + b * c; }\n#endif\n"
                        "int three(unsigned a, unsigned b) { return (a >> 3) + (b << 2) + (a ^ b) + SCALE; }\n",
        "headers/shared.h": "#ifdef RELEASE_TWO\n#define SCALE 7\n#else\n#define SCALE 3\n#endif\n",
        # a unit that also carries a routine that is not C (what a tree in progress does with
        # functions it has only disassembled)
        "code/mixed.c": '__asm__(".text\\n.globl sneaked\\n.ent sneaked\\nsneaked:\\n addiu $2,$4,1\\n addiu $2,$2,2\\n'
                        ' addiu $2,$2,3\\n addiu $2,$2,4\\n jr $31\\n nop\\n.end sneaked\\n.size sneaked,24\\n");\n'
                        "int real(int a, int b) { return (a * 9 + b) ^ (b >> 2) ^ (a << 5); }\n",
    }

    def test_units_that_come_out_empty_give_no_image_and_find_nothing(self):
        from n64dk.match.toolchain import load_config
        # under this configuration the whole unit is compiled away
        root = tree_of({"gone.c": "#ifdef PRESENT\nint gone(int a) { return a + 1; }\n#endif\n"})
        work = Path(tempfile.mkdtemp(prefix="n64dk-test-work-"))
        cfg = load_config(work, None, os.environ["N64DK_TOOLCHAIN"])
        tree = sourcedonor.Tree(root)
        built = sourcedonor.Builder(tree, [], cfg, work / "obj", 1).many(
            tree.units, lambda _u: "kmc+as -O2 -G0 -mips3 -mgp32 -mfp32", [])
        self.assertEqual(sorted(built), ["gone.c"])
        self.assertIn("error", sourcedonor.link(list(built.values()), work / "l", cfg))
        self.assertEqual(sourcedonor.found_in_target(built, work / "probe", cfg, {("x", 4): [("main", 1)]}), {})

    def test_what_the_tree_does_not_define_gets_a_place_of_its_own(self):
        import struct
        from n64dk.match.toolchain import load_config
        root = tree_of({"calls.c": "extern int outside(int);\nextern int elsewhere(int);\n"
                                   "int calls(int a) { return outside(a) + elsewhere(a + 1) + outside(a + 2); }\n"})
        work = Path(tempfile.mkdtemp(prefix="n64dk-test-work-"))
        cfg = load_config(work, None, os.environ["N64DK_TOOLCHAIN"])
        tree = sourcedonor.Tree(root)
        built = sourcedonor.Builder(tree, [], cfg, work / "obj", 1).many(
            tree.units, lambda _u: "kmc+as -O2 -G0 -mips3 -mgp32 -mfp32", [])

        def call_targets(linked):
            data = linked["image"].read_bytes()
            words = struct.unpack(f">{len(data) // 4}I", data[:len(data) // 4 * 4])
            return [0x80000000 | ((word & 0x3FFFFFF) << 2) for word in words if word >> 26 == 3]

        plain = sourcedonor.link(list(built.values()), work / "plain", cfg)
        self.assertEqual(set(call_targets(plain)), {0x80000000})          # three calls, one address: nothing to tell apart
        placed = sourcedonor.link(list(built.values()), work / "placed", cfg, place_undefined=True)
        self.assertEqual(sorted(placed["undefined"]), ["elsewhere", "outside"])
        targets = call_targets(placed)
        self.assertEqual(targets.count(placed["undefined"]["outside"]), 2)
        self.assertEqual(targets.count(placed["undefined"]["elsewhere"]), 1)
        self.assertTrue(all(address >= sourcedonor.UNDEFINED for address in placed["undefined"].values()))

    def test_recipe_and_macros_are_found_by_measurement(self):
        from n64dk.match.toolchain import load_config
        from n64dk.match.transplant import mask, signature, strip_padding
        root = tree_of(self.FILES)
        work = Path(tempfile.mkdtemp(prefix="n64dk-test-work-"))
        cfg = load_config(work, None, os.environ["N64DK_TOOLCHAIN"])
        tree = sourcedonor.Tree(root)
        retail = "kmc+as -O2 -G0 -mips3 -mgp32 -mfp32"
        other = "kmc+as -O0 -G0 -mips3 -mgp32 -mfp32"
        # the title: the same tree at -O2 with both macros set
        builder = sourcedonor.Builder(tree, tree.resolve_all(), cfg, work / "retail-obj", 2)
        built = builder.many(tree.units, lambda _u: retail, ["RELEASE_TWO", "WITH_EXTRA"])
        self.assertEqual(sorted(built), tree.units, builder.errors)
        linked = sourcedonor.link(list(built.values()), work / "retail", cfg)
        data = linked["image"].read_bytes()
        functions, _lines = sourcedonor.functions_of(linked["symbols"], [(s, s + n) for s, n in linked["placed"].values()])
        self.assertEqual(sorted(row[0] for row in functions), ["extra", "one", "real", "sneaked", "three", "two"])
        signatures = {}
        for label, address, size in functions:
            code = strip_padding(data[address - sourcedonor.BASE:address - sourcedonor.BASE + size])
            signatures.setdefault((signature(mask(code, 0x80400000 + address - sourcedonor.BASE)[0]), len(code)), []).append(("main", label))

        plan = sourcedonor.calibrate(tree, signatures, [other, retail], cfg, work / "cal", jobs=2)
        self.assertEqual(plan["macros"], ["RELEASE_TWO", "WITH_EXTRA"])
        self.assertEqual(plan["majority"], retail)
        self.assertEqual(plan["recipes"], {unit: retail for unit in tree.units})

        # the tree's own units as donor units
        result = sourcedonor.build(tree, plan, work / "out", "tree_test", cfg, signatures, by_function=False)
        self.assertEqual((result["units"], result["functions"]), (3, 5))
        self.assertEqual(result["symbols_not_written_in_c"], 1)
        catalogue = (work / "out" / "tree_test" / "functions.tsv").read_text()
        self.assertIn("\treal\n", catalogue)
        self.assertNotIn("sneaked", catalogue)
        manifest = (work / "out" / "tree_test" / "manifest.kmc_as.tsv").read_text()
        self.assertIn("code/one.c\t-O2 -G0 -mips3 -mgp32 -mfp32 -D_LANGUAGE_C -DRELEASE_TWO=1 -DWITH_EXTRA=1", manifest)
        # the routine is in the title and in the built unit, and is still not offered
        objects = plan["builder"].many(tree.units, lambda _u: retail, plan["macros"])
        unguarded = sourcedonor.found_in_target(objects, work / "check", cfg, signatures)
        guarded = sourcedonor.found_in_target(objects, work / "check", cfg, signatures, tree.defines)
        self.assertIn(("main", "sneaked"), unguarded["code/mixed.c"])
        self.assertNotIn(("main", "sneaked"), guarded["code/mixed.c"])
        whole = sum(len(places) for places in guarded.values())
        self.assertEqual(result["target_functions_found"], whole)

        # one unit per function (the default): the same functions, each a unit of its own
        result = sourcedonor.build(tree, plan, work / "out2", "tree_test", cfg, signatures)
        self.assertEqual((result["units"], result["functions"], result["functions_written"]), (5, 5, 5))
        self.assertEqual(result["functions_not_compiled"], 0)
        self.assertEqual(result["target_functions_found"], whole)
        manifest = (work / "out2" / "tree_test" / "manifest.kmc_as.tsv").read_text()
        for source in ("code/one/one.c", "code/one/two.c", "code/three/extra.c", "code/three/three.c", "code/mixed/real.c"):
            self.assertIn(f"\t{source}\t-O2 -G0 -mips3 -mgp32 -mfp32\n", manifest)
        self.assertNotIn("sneaked", (work / "out2" / "tree_test" / "functions.tsv").read_text())
        derived = (work / "out2" / "tree_test" / "split" / "code" / "one" / "one.c").read_text()
        self.assertIn("int one(int *p, int n)", derived)
        self.assertNotIn("int two(int a, int b) {", derived)             # declared at most, never defined
        self.assertNotIn("#include", derived)
        self.assertIn('root = "' + str(work / "out2" / "tree_test" / "split") + '"', result["toml"])

    def test_a_function_that_differs_does_not_keep_its_neighbours_out(self):
        """The title was built from the same tree with one function written differently.  Whole
        units find it only as a unit with a function missing; one unit per function finds the rest."""
        from n64dk.match.toolchain import load_config
        from n64dk.match.transplant import mask, signature, strip_padding
        retail = "kmc+as -O2 -G0 -mips3 -mgp32 -mfp32"
        changed = dict(self.FILES)
        changed["code/one.c"] = changed["code/one.c"].replace("return b * 5 - a;", "return b * 6 - a + 1;")
        self.assertNotEqual(changed, self.FILES)
        work = Path(tempfile.mkdtemp(prefix="n64dk-test-work-"))
        cfg = load_config(work, None, os.environ["N64DK_TOOLCHAIN"])
        title = sourcedonor.Tree(tree_of(changed))
        built = sourcedonor.Builder(title, title.resolve_all(), cfg, work / "title-obj", 2).many(
            title.units, lambda _u: retail, ["RELEASE_TWO", "WITH_EXTRA"])
        linked = sourcedonor.link(list(built.values()), work / "title", cfg)
        data = linked["image"].read_bytes()
        functions, _lines = sourcedonor.functions_of(linked["symbols"], [(s, s + n) for s, n in linked["placed"].values()])
        signatures = {}
        for label, address, size in functions:
            code = strip_padding(data[address - sourcedonor.BASE:address - sourcedonor.BASE + size])
            signatures.setdefault((signature(mask(code, address)[0]), len(code)), []).append(("main", label))

        tree = sourcedonor.Tree(tree_of(self.FILES))
        plan = sourcedonor.calibrate(tree, signatures, [retail], cfg, work / "cal", jobs=2,
                                     macros=["RELEASE_TWO", "WITH_EXTRA"], max_macros=0)
        result = sourcedonor.build(tree, plan, work / "out", "tree_test", cfg, signatures)
        objects = {f"{unit[:-2]}/{label}.c": None for unit, label in
                   (("code/one.c", "one"), ("code/one.c", "two"), ("code/three.c", "three"),
                    ("code/three.c", "extra"), ("code/mixed.c", "real"))}
        self.assertEqual(result["functions"], len(objects))
        found = {label for places in signatures.values() for _image, label in places}
        self.assertIn("two", found)                          # it is in the title, built from other source
        self.assertEqual(result["target_functions_found"],
                         sum(1 for (_sig, size), places in signatures.items()
                             for _image, label in places if label not in ("two", "sneaked") and size >= 20))
        self.assertGreaterEqual(result["target_functions_found"], 3)

if __name__ == "__main__":
    unittest.main()
