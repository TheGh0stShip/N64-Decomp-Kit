"""Marks a build leaves in machine code, and the table that ranks recipes by them."""
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk.match import idioms


def code(*words: int) -> bytes:
    return b"".join(struct.pack(">I", word) for word in words)


# addiu sp,-0x18; sw ra,0x14(sp); addu a1,a0,zero; jal; nop; lw ra,0x14(sp); jr ra; addiu sp,0x18
GNU = code(0x27BDFFE8, 0xAFBF0014, 0x00802821, 0x0C000400, 0x00000000, 0x8FBF0014, 0x03E00008, 0x27BD0018)
# addiu sp,-0x18; sw ra,0x14(sp); sw a0,0x18(sp); or a1,a0,zero; jal; nop; lw ra,0x14(sp); addiu sp,0x18; jr ra; nop
IDO = code(0x27BDFFE8, 0xAFBF0014, 0xAFA40018, 0x00802825, 0x0C000400, 0x00000000, 0x8FBF0014, 0x27BD0018,
           0x03E00008, 0x00000000)


class FeatureTest(unittest.TestCase):
    def test_the_assemblers_spell_a_move_differently(self):
        self.assertIn("move=addu", idioms.features(GNU))
        self.assertNotIn("move=or", idioms.features(GNU))
        self.assertIn("move=or", idioms.features(IDO))

    def test_frame_return_slot_and_homed_arguments(self):
        gnu, ido = idioms.features(GNU), idioms.features(IDO)
        self.assertLessEqual({"frame=first", "ra=32bit", "ra-slot=top", "return=slot-filled"}, gnu)
        self.assertLessEqual({"args=homed", "return=slot-empty"}, ido)
        self.assertNotIn("args=homed", gnu)

    def test_instruction_set_and_constants(self):
        marks = idioms.features(code(0x34020005, 0x24030007, 0x0002103C, 0x51000001, 0x03E00008, 0x00000000))
        self.assertLessEqual({"li=ori-small", "li=addiu", "isa=64bit", "branch=likely"}, marks)
        self.assertIn("frame=none", marks)

    def test_instruction_order_marks(self):
        marks = idioms.sequence_marks(GNU)
        self.assertIn("seq:spadj|st_sp", marks)
        self.assertNotIn("seq:st_sp|addu|jal", marks)
        self.assertIn("seq:st_sp|addu|jal", idioms.sequence_marks(GNU, triples=True))
        self.assertIn("seq:jr|spadj", marks)
        self.assertLessEqual(marks, idioms.features(GNU))
        self.assertFalse(any(mark.startswith("seq:") for mark in idioms.features(GNU, sequences=False)))

    def test_an_order_never_seen_does_not_exclude_a_class(self):
        table = idioms.Table()
        for _ in range(250):
            table.add("kmc+as -O2", idioms.features(GNU))
        odd = idioms.features(GNU, sequences=False) | {"seq:never|seen"}
        self.assertEqual(table.excluded(odd), set())

    def test_pruning_drops_rare_orders_only(self):
        table = idioms.Table()
        for _ in range(3):
            table.add("kmc+as -O2", idioms.features(GNU))
        table.prune(5)
        marks = table.classes["kmc+as -O2"]["marks"]
        self.assertIn("move=addu", marks)
        self.assertFalse(any(mark.startswith("seq:") for mark in marks))

    def test_padding_and_empty_code(self):
        self.assertEqual(idioms.features(b""), frozenset())
        self.assertEqual(idioms.sequence_marks(b""), frozenset())
        self.assertEqual(idioms.features(GNU + bytes(8)), idioms.features(GNU))

    def test_a_recipe_is_reduced_to_lane_and_level(self):
        self.assertEqual(idioms.recipe_class("kmc+as -O2 -G0 -mips3 -mgp32 -mfp32"), "kmc+as -O2")
        self.assertEqual(idioms.recipe_class("ido5.3 -g -mips2 -non_shared"), "ido5.3 -g")
        self.assertEqual(idioms.recipe_class("ido5.3 -O1 -g2 -mips2"), "ido5.3 -O1")
        self.assertEqual(idioms.recipe_class("sn -G0"), "sn -O2")


class TableTest(unittest.TestCase):
    def table(self) -> idioms.Table:
        table = idioms.Table()
        for _ in range(250):
            table.add("kmc+as -O2 -G0", idioms.features(GNU))
            table.add("ido5.3 -O2 -mips2", idioms.features(IDO))
        return table

    def test_ranking_follows_the_marks(self):
        table = self.table()
        self.assertEqual(table.rank([idioms.features(GNU)])[0][0], "kmc+as -O2")
        self.assertEqual(table.rank([idioms.features(IDO)] * 3)[0][0], "ido5.3 -O2")
        self.assertGreater(table.rank([idioms.features(IDO)] * 3)[0][1], 0.99)

    def test_a_class_that_never_showed_a_mark_is_excluded_only_when_seen_often(self):
        table = self.table()
        self.assertEqual(table.excluded(idioms.features(IDO)), {"kmc+as -O2"})
        self.assertEqual(table.excluded(idioms.features(IDO), min_functions=1000), set())
        self.assertEqual(table.excluded(frozenset()), set())

    def test_a_class_seen_a_handful_of_times_is_not_ranked(self):
        table = self.table()
        for _ in range(3):
            table.add("sn -O2", idioms.features(GNU))
        self.assertNotIn("sn -O2", dict(table.rank([idioms.features(GNU)])))

    def test_round_trip_and_learning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t" / "table.json"
            table = self.table()
            self.assertEqual(idioms.learn(table, [("kmc+as -O2", GNU, 0x80001000), ("", GNU, 0), ("x -O2", b"", 0)]), 1)
            table.save(path)
            again = idioms.Table.load(path)
            self.assertEqual(again.classes["kmc+as -O2"]["functions"], 251)
            self.assertEqual(idioms.Table.load(Path(tmp) / "missing.json").classes, {})

    def test_the_shipped_table_is_present_and_holds_counts_only(self):
        table = idioms.Table.load()
        self.assertGreaterEqual(len(table.classes), 4)
        for entry in table.classes.values():
            self.assertEqual(set(entry), {"functions", "marks"})
            self.assertTrue(all(isinstance(count, int) for count in entry["marks"].values()))

    def test_stretches_group_neighbours_with_the_same_lane(self):
        table = self.table()
        functions = [(0x80001000 + 0x40 * n, idioms.features(GNU)) for n in range(20)] \
            + [(0x80002000 + 0x40 * n, idioms.features(IDO)) for n in range(20)]
        found = idioms.stretches(functions, table, window=6)
        self.assertEqual([row["lane"] for row in found], ["kmc+as", "ido5.3"])
        self.assertEqual(sum(row["functions"] for row in found), 40)
        self.assertTrue(0x80001000 + 0x40 * 16 <= found[1]["start"] <= 0x80002000 + 0x40 * 3)   # within the window


class DoubtTest(unittest.TestCase):
    def table(self) -> idioms.Table:
        table = idioms.Table()
        for _ in range(250):
            table.add("kmc+as -O2 -G0", idioms.features(GNU))
            table.add("ido5.3 -O2 -mips2", idioms.features(IDO))
        return table

    def test_an_image_that_contradicts_its_configured_recipe(self):
        functions = [(0x80001000 + 0x40 * n, idioms.features(GNU)) for n in range(40)]
        wrong = idioms.doubt(functions, self.table(), "ido5.3 -O2 -mips2 -non_shared")
        self.assertEqual((wrong["against"], wrong["share"]), (40, 1.0))
        self.assertEqual(list(wrong["looks_like"]), ["kmc+as -O2"])
        right = idioms.doubt(functions, self.table(), "kmc+asn64 -O2 -G0 -mips3")
        self.assertEqual(right["share"], 0.0)                        # another assembler lane is not another family

    def test_a_short_stretch_or_an_unsure_one_does_not_count(self):
        functions = [(0x80001000 + 0x40 * n, idioms.features(GNU)) for n in range(6)]
        self.assertEqual(idioms.doubt(functions, self.table(), "ido5.3 -O2")["share"], 0.0)
        self.assertEqual(idioms.doubt([], self.table(), "ido5.3 -O2")["share"], 0.0)

    def test_another_level_of_the_same_compiler_counts(self):
        functions = [(0x80001000 + 0x40 * n, idioms.features(GNU)) for n in range(40)]
        self.assertEqual(idioms.doubt(functions, self.table(), "kmc+as -O0 -G0")["share"], 1.0)


# lui at,hi; lw v0,lo(at); jr ra; nop   -- a global read through the assembler's register
AT_LOAD = code(0x3C01801C, 0x8C2206C4, 0x03E00008, 0x00000000)


class UnknownToolchainTest(unittest.TestCase):
    def table(self) -> idioms.Table:
        table = idioms.Table()
        for _ in range(300):
            table.add("kmc+as -O2", idioms.features(GNU, 0x80001000))
            table.add("ido5.3 -O2", idioms.features(IDO, 0x80001000))
        return table

    def test_marks_of_an_assembler_no_class_uses(self):
        marks = idioms.features(AT_LOAD, 0x80001000)
        self.assertLessEqual({"at=load", "at=direct-load"}, marks)
        self.assertNotIn("at=direct-load", idioms.features(GNU, 0x80001000))
        jump_out = code(0x08000800, 0x00000000)                     # j 0x80002000 from 0x80001000
        self.assertIn("tail=jump", idioms.features(jump_out, 0x80001000))
        self.assertNotIn("tail=jump", idioms.features(code(0x08000401, 0x00000000, 0x03E00008, 0), 0x80001000))

    def test_a_stretch_that_keeps_doing_what_no_class_does_is_unexplained(self):
        table = self.table()
        odd = [idioms.features(AT_LOAD, 0x80001000)] * 6 + [idioms.features(GNU, 0x80001000)] * 18
        self.assertIn("at=direct-load", table.unexplained(odd))
        self.assertIsNone(table.unexplained([idioms.features(GNU, 0x80001000)] * 24))

    def test_a_seam_between_two_known_compilers_is_not_a_third(self):
        table = self.table()
        seam = [idioms.features(GNU, 0x80001000)] * 12 + [idioms.features(IDO, 0x80001000)] * 12
        self.assertTrue(table.misfit(seam))                         # each class is ruled out by the other's marks
        self.assertIsNone(table.unexplained(seam))                  # ... by different ones: not unexplained

    def test_a_jump_out_of_a_function_is_not_evidence(self):
        table = self.table()
        jump_out = idioms.features(code(0x08000800, 0x00000000), 0x80001000)
        self.assertIsNone(table.unexplained([jump_out] * 24))

    def test_unknown_stretches_cover_the_functions_and_nothing_else(self):
        table = self.table()
        functions = [(0x80001000 + 0x40 * n, idioms.features(GNU, 0x80001000)) for n in range(60)] \
            + [(0x80002000 + 0x40 * n, idioms.features(AT_LOAD, 0x80001000)) for n in range(60)]
        found = idioms.unknown_stretches(functions, table)
        self.assertEqual(len(found), 1)
        self.assertGreaterEqual(found[0]["start"], 0x80001000 + 0x40 * 36)
        self.assertEqual(found[0]["end"], 0x80002000 + 0x40 * 59)
        self.assertIn("at=direct-load", found[0]["marks"])
        self.assertEqual(idioms.unknown_stretches(functions[:60], table), [])
        self.assertEqual(idioms.unknown_stretches(functions[:5], table), [])


if __name__ == "__main__":
    unittest.main()
