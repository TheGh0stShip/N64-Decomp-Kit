"""Training pairs and learned draft rules: records, statistics, the paired comparison, rule
kinds, learning and the leave-one-title-out evaluation, on synthetic data."""
import json
import tempfile
import unittest
from pathlib import Path

from n64dk.match import learnedrules, trainingcorpus


class FeatureTest(unittest.TestCase):
    def test_body_context_and_features(self):
        source = "typedef int s32;\ns32 g;\ns32 f(s32 *p) {\n    s32 i;\n    for (i = 0; i < 4; i++) { p[i] = g; }\n    return p->x;\n}\n"
        body = trainingcorpus.function_body(source, "f")
        self.assertTrue(body.startswith("s32 f(") and body.endswith("}"))
        self.assertNotIn("for (", trainingcorpus.context_of(source, "f"))
        features = trainingcorpus.source_features(body)
        self.assertEqual((features["for_loops"], features["array_index"], features["arrow"]), (1, 1, 1))
        self.assertEqual(trainingcorpus.normalised("a /* x */ +\n  b"), "a + b")

    def test_target_features_hold_no_bytes(self):
        code = bytes.fromhex("27BDFFE8AFBF00140C00000000000000" "8FBF001403E0000827BD0018")
        found = trainingcorpus.target_features(code, 0x80000000)
        self.assertEqual((found["words"], found["calls"], found["jump_register"]), (7, 1, 0))
        self.assertTrue(all(isinstance(value, int) for value in found.values()))


def record(title, family, plain, context, size=0x40):
    def draft(words):
        if words is None:
            return {"drafted": True, "compiles": False}
        return {"drafted": True, "compiles": True, "found": True, "differing_words": words, "text_equal": words == 0}
    return {"title_sha1": title, "compiler_family": family, "size": size, "flags": ["-O2"],
            "drafts": {"plain": draft(plain), "context": draft(context)}}


class StatsTest(unittest.TestCase):
    def test_paired_comparison(self):
        records = [record("a" * 40, "ido", 5, 2), record("a" * 40, "ido", 3, 3), record("a" * 40, "ido", None, 0),
                   record("b" * 40, "gcc", 0, 4)]
        found = trainingcorpus.compare_conditions(records)
        self.assertEqual(found["ido"]["context_closer"], 1)
        self.assertEqual(found["ido"]["equal"], 1)
        self.assertEqual(found["ido"]["context"]["exact text"], 1)
        self.assertEqual(found["gcc"]["context_further"], 1)
        self.assertEqual(found["all"]["pairs"], 4)
        stats = trainingcorpus.stats(records)
        self.assertEqual(stats["by_family"], {"ido": 3, "gcc": 1})
        self.assertEqual(stats["draft_plain"]["exact text"], 1)

    def test_export_withholds_sources(self):
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-corpus-"))
        (folder / "pairs.jsonl").write_text(json.dumps({**record("a" * 40, "ido", 1, 1), "local_only": True}) + "\n")
        out = Path(tempfile.mkdtemp(prefix="n64dk-test-export-"))
        trainingcorpus.export(folder, out)
        shared = json.loads((out / "pairs.jsonl").read_text())
        self.assertTrue(shared["sources_withheld"])
        self.assertNotIn("local_only", shared)
        self.assertFalse((out / "sources").exists())


class KindTest(unittest.TestCase):
    def test_place_and_operand_are_removed(self):
        self.assertEqual(learnedrules.kind("control: if+do-while -> while L12"), "control: if+do-while -> while")
        self.assertEqual(learnedrules.kind("cast: drop mask 'arg0 & 0xFF' L3 #2"), "cast: drop mask E")
        self.assertEqual(learnedrules.kind("stmt-order: move store to sp10 up 3"), "stmt-order: move up")
        self.assertEqual(learnedrules.kind("inline-temp: temp_v0 = 'x + 1' L5"), "inline-temp: inline")
        self.assertEqual(learnedrules.kind("cast: param arg0 s32 -> u8 L1"), "cast: param s32 -> u8")


def obs(title, pair, label, before, after, exact=False, family="ido"):
    return {"title": title, "pair": f"{title}:{pair}", "family": family, "label": label,
            "kind": learnedrules.kind(label), "before": before, "after": after, "compiles": after is not None,
            "exact": exact}


class LearnTest(unittest.TestCase):
    def test_rules_accepted_and_rejected_with_reasons(self):
        items = [obs("t", k, "control: init+do-while -> for L1", 5, 2) for k in range(10)]
        items += [obs("t", k, "block: wrap x in if (1)", 5, 9) for k in range(10)]
        items += [obs("t", k, "expr: x++ L2", 5, 5) for k in range(3)]
        rules = learnedrules.learn(items)
        self.assertTrue(rules[("ido", "control: init+do-while -> for")]["accepted"])
        self.assertFalse(rules[("ido", "block: wrap x in if (N)")]["accepted"])
        self.assertIn("only 3 tries", rules[("ido", "expr: x++")]["reason"])
        written = learnedrules.registry(rules, ["t"])
        self.assertEqual(written["accepted"][0]["kind"], "control: init+do-while -> for")

    def test_held_out_title_is_never_learned_from(self):
        train = []
        for k in range(12):          # on title A, the second step helps, the first never does
            train.append(obs("A", k, "block: wrap s in if (1)", 4, 6))
            train.append(obs("A", k, "control: while -> for (no init) L1", 4, 1))
        test = []
        for k in range(5):           # on title B the same: the generator's order wastes one build
            test.append(obs("B", k, "block: wrap s in if (1)", 4, 6))
            test.append(obs("B", k, "control: while -> for (no init) L1", 4, 0, exact=True))
        found = learnedrules.evaluate(train + test, "B", budgets=(1,))
        one = found["budgets"]["1"]
        self.assertEqual(one["generator"]["pairs_improved"], 0)
        self.assertEqual(one["learned"]["pairs_exact"], 5)
        self.assertEqual(found["train_observations"], 24)
        # learning on B alone would see B's observations; the held-out run must not
        self.assertEqual(found["trained_on"], ["A"])


if __name__ == "__main__":
    unittest.main()


class VariantFieldTest(unittest.TestCase):
    def test_explore_reads_the_variant_record_it_is_given(self):
        """The exploration builds ``variant.source``: the record of ``astforms.variants``."""
        from n64dk.match.iterate import Variant
        fields = Variant.__dataclass_fields__
        self.assertIn("source", fields)
        self.assertIn("semantic_review", fields)
        with open(learnedrules.__file__) as handle:
            text = handle.read()
        self.assertIn("variant.source", text)
        self.assertNotIn("variant.text", text)


class RelocationCompareTest(unittest.TestCase):
    def test_only_relocated_bits_are_ignored(self):
        """Regression: a pattern mask missed %lo used through an indexed base, so 9 of 120
        audited pairs that link exactly were reported as not reproducing."""
        import struct
        import tempfile
        from n64dk.match import trainingcorpus
        # an object with one function: lui at,0 / addu at,at,t6 / lh t8,0x20(at) / jr ra / nop,
        # an R_MIPS_HI16 on the lui and an R_MIPS_LO16 on the lh
        code = struct.pack(">5I", 0x3C010000, 0x002E0821, 0x87380020, 0x03E00008, 0)
        linked = struct.pack(">5I", 0x3C018034, 0x002E0821, 0x8738D5BC, 0x03E00008, 0)
        other = struct.pack(">5I", 0x3C018034, 0x002E0821, 0x8739D5BC, 0x03E00008, 0)   # different register
        path = Path(tempfile.mkdtemp(prefix="n64dk-test-reloc-")) / "f.o"
        path.write_bytes(_object(code, "f", [(0, 5), (8, 6)]))
        self.assertEqual(trainingcorpus.masked_difference(path, "f", linked, 0x80000000), (0, 4))   # trailing nop is padding
        self.assertEqual(trainingcorpus.masked_difference(path, "f", other, 0x80000000), (1, 4))
        self.assertEqual(trainingcorpus.defined_functions(path), ["f"])


class QuarantineTest(unittest.TestCase):
    def test_quarantined_pairs_never_load(self):
        import json
        import tempfile
        from n64dk.match import trainingcorpus
        corpus = Path(tempfile.mkdtemp(prefix="n64dk-test-quarantine-"))
        pairs = [{"image": "main", "vram": "0x80000000"}, {"image": "main", "vram": "0x80000010"}]
        (corpus / "pairs.jsonl").write_text("".join(json.dumps(p) + "\n" for p in pairs))
        (corpus / "quarantine.jsonl").write_text(json.dumps({"image": "main", "vram": "0x80000010",
                                                             "reason": "x"}) + "\n")
        self.assertEqual([p["vram"] for p in trainingcorpus.load(corpus)], ["0x80000000"])
        self.assertEqual(len(trainingcorpus.load(corpus, include_quarantined=True)), 2)

    def test_split_file_definitions(self):
        from n64dk.match import trainingcorpus
        text = ("typedef struct S { int a; } S;\nstatic void helper(S *s)\n{\n    s->a = 1;\n}\n"
                "void caller(S *s) {\n    helper(s);\n}\nextern int g(void);\n")
        self.assertEqual(set(trainingcorpus._DEFINITION.findall(text)), {"helper", "caller"})


def _object(code: bytes, name: str, relocations: list[tuple[int, int]]) -> bytes:
    """A minimal big-endian MIPS ELF relocatable: .text, .rel.text, .symtab, .strtab, .shstrtab."""
    import struct
    shstr = b"\0.text\0.rel.text\0.symtab\0.strtab\0.shstrtab\0"
    strtab = b"\0" + name.encode() + b"\0"
    symtab = bytes(16) + struct.pack(">IIIBBH", 1, 0, len(code), 0x12, 0, 1)   # global function in section 1
    rel = b"".join(struct.pack(">II", offset, (1 << 8) | kind) for offset, kind in relocations)
    body = [code, rel, symtab, strtab, shstr]
    offsets, position = [], 52
    for part in body:
        offsets.append(position)
        position += len(part)
    sections = [bytes(40),
                struct.pack(">10I", 1, 1, 6, 0, offsets[0], len(code), 0, 0, 4, 0),
                struct.pack(">10I", 7, 9, 0, 0, offsets[1], len(rel), 3, 1, 4, 8),
                struct.pack(">10I", 17, 2, 0, 0, offsets[2], len(symtab), 4, 1, 4, 16),
                struct.pack(">10I", 25, 3, 0, 0, offsets[3], len(strtab), 0, 0, 1, 0),
                struct.pack(">10I", 33, 3, 0, 0, offsets[4], len(shstr), 0, 0, 1, 0)]
    header = (b"\x7fELF\x01\x02\x01" + bytes(9) + struct.pack(">HHIIIIIHHHHHH", 1, 8, 1, 0, 0, position, 0,
                                                                52, 0, 0, 40, len(sections), 5))
    return header + b"".join(body) + b"".join(sections)
