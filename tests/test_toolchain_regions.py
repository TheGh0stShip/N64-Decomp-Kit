"""Regional toolchain reconstruction (n64dk.match.toolchain_regions) on a synthetic image."""
import struct
import unittest

from n64dk.match import idioms
from n64dk.match import toolchain_regions as tcmod

BASE = 0x80100000
GCC_LEAF = [0x00801021, 0x03E00008, 0x00000000, 0x00000000]          # addu v0,a0,zero; jr ra; nop
IDO_LEAF = [0x00801025, 0x03E00008, 0x00000000, 0x00000000]          # or v0,a0,zero
AT_LOAD = [0x3C018021, 0x8C240010, 0x00801021, 0x03E00008, 0x00000000, 0, 0, 0]   # lui at; lw a0,0x10(at)


def code(words):
    return struct.pack(f">{len(words)}I", *words)


def table():
    t = idioms.Table()
    for _ in range(200):
        t.add("kmc+as -O2 -G0", idioms.features(code(GCC_LEAF), BASE))
        t.add("ido5.3 -O2 -mips2", idioms.features(code(IDO_LEAF), BASE))
    return t


def image(*groups):
    words, rows = [], []
    for shape, count in groups:
        for _ in range(count):
            rows.append((f"func_{BASE + 4 * len(words):08X}", BASE + 4 * len(words), 4 * len(shape)))
            words += shape
    return code(words), rows


class ReconstructTest(unittest.TestCase):
    def test_known_and_unknown_regions(self):
        data, rows = image((GCC_LEAF, 40), (AT_LOAD, 40))
        found = tcmod.reconstruct(data, BASE, rows, table=table(), lane_marks={})
        verdicts = [(r["functions"], r["verdict"]) for r in found["regions"]]
        self.assertEqual(verdicts[0], (40, "known"))
        self.assertEqual(verdicts[-1][1], "unknown")
        unknown = found["regions"][-1]
        self.assertIn("at=direct-load", unknown["unknown_marks"])
        self.assertTrue(unknown["dossier"]["smallest_functions"])
        self.assertIn("assembler: global loads expanded through $at",
                      {m["component"] for m in unknown["component_mismatches"]})
        self.assertEqual(tcmod.unavailable(found), [(int(unknown["start"], 16), int(unknown["end"], 16))])

    def test_unreproduced_component_names_the_probe_evidence(self):
        lanes = {"kmc+as -O2": {"move=addu", "at=address"}, "ido5.3 -O2": {"move=or", "at=compare"}}
        found = tcmod.unreproduced({"at=direct-load": 0.9, "move=addu": 1.0}, lanes)
        self.assertEqual([u["mark"] for u in found], ["at=direct-load"])
        self.assertEqual(tcmod.unreproduced({"at=direct-load": 0.9}, {}), [])

    def test_short_stretches_join_a_neighbour(self):
        rows = [{"start": 0, "end": 10, "lane": "kmc+as", "functions": 30,
                 "likely": [{"recipe": "kmc+as -O2", "share": 1.0}]},
                {"start": 11, "end": 12, "lane": "ido5.3", "functions": 3,
                 "likely": [{"recipe": "ido5.3 -O2", "share": 1.0}]},
                {"start": 13, "end": 40, "lane": "kmc+as", "functions": 25,
                 "likely": [{"recipe": "kmc+as -O2", "share": 1.0}]}]
        merged = tcmod._merge(rows, least=16)
        self.assertEqual(len(merged), 2)
        self.assertEqual(sum(r["functions"] for r in merged), 58)

    def test_mismatch_names_the_component(self):
        found = tcmod._mismatches({"at=direct-load": 0.5, "move=addu": 1.0}, {"move=addu": 0.99})
        self.assertEqual([m["component"] for m in found], ["assembler: global loads expanded through $at"])


if __name__ == "__main__":
    unittest.main()


class AtLoadVariantTest(unittest.TestCase):
    def test_symbol_loads_go_through_at_and_nothing_else_changes(self):
        from n64dk.match import normalize
        text = ("\tlw\t$2,g\n\tlhu\t$4,table+4  # comment\n\tsw\t$4,g\n\tlw\t$3,8($sp)\n"
                "\tlw\t$5,%lo(x)($6)\n\tla\t$2,g\n")
        out = normalize.at_symbol_loads(text)
        self.assertIn("lui\t$1,%hi(g)\n\tlw\t$2,%lo(g)($1)", out)
        self.assertIn("lui\t$1,%hi(table+4)\n\tlhu\t$4,%lo(table+4)($1)", out)
        for kept in ("\tsw\t$4,g\n", "\tlw\t$3,8($sp)\n", "\tlw\t$5,%lo(x)($6)\n", "\tla\t$2,g\n"):
            self.assertIn(kept, out)
        self.assertEqual(out.count(".set\tnoat"), 2)

    def test_lane_is_a_known_pipeline_with_components(self):
        from n64dk.match import components, pipeline
        self.assertIn("kmc+atload", pipeline.PIPELINES)
        self.assertIn("kmc+atload", components.RECIPES)


class TailTest(unittest.TestCase):
    def test_binomial_tail_matches_the_exact_sum_and_survives_large_counts(self):
        import math
        exact = sum(math.comb(40, k) * 0.05 ** k * 0.95 ** (40 - k) for k in range(5, 41))
        self.assertAlmostEqual(idioms._tail(5, 40, 0.05), exact, places=12)
        self.assertEqual(idioms._tail(0, 10, 0.3), 1.0)
        self.assertEqual(idioms._tail(11, 10, 0.3), 0.0)
        value = idioms._tail(30, 1770, 0.01)               # overflowed before (Namco Museum 64)
        self.assertTrue(0.0 <= value <= 1.0)
