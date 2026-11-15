import shutil
import atexit
import struct
import tempfile
import unittest

from n64dk.match import iterate, resolve


def _scratch(prefix: str = "n64dk-test-") -> str:
    """A scratch directory removed when the test process exits."""
    path = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, path, True)
    return path


BASE = 0x80001000


def code(words):
    return b"".join(struct.pack(">I", w) for w in words)


TARGET = code([0x84820004, 0x03E00008, 0x00000000])        # lh v0,4(a0); jr ra; nop
WRONG = code([0x94820004, 0x03E00008, 0x00000000])         # lhu
FRAGMENT = code([0x96020060, 0x00481821, 0xA6030024, 0x8FBF001C, 0x03E00008, 0x27BD0020])
SOURCE = "s32 read(Thing *thing) {\n    u16 value;\n\n    value = thing->field;\n    return value;\n}\n"


def fake_evaluate(calls, proof=True):
    """Pretend compiler: the function matches when ``value`` is declared s16."""
    def evaluate(text):
        calls.append(text)
        if "does not build" in text:
            return iterate.Evaluation(None, error="x.c:1: parse error"), None
        exact = "s16 value;" in text
        report = {"counts": {} if exact else {"instruction": 1},
                  "entries": [] if exact else [{"compiled": "lhu $v0, 0x4($a0)", "retail": "lh $v0, 0x4($a0)"}]}
        outcome = {"proof": {"verdict": "exact"}} if exact and proof else None
        return iterate.Evaluation(0 if exact else 3, exact, report, outcome=outcome), (TARGET if exact else WRONG)
    return evaluate


class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.root = _scratch("n64dk-resolve-test-")
        self.store = resolve.CaseStore(self.root)
        self.addCleanup(self.store.close)

    def test_ladder_reaches_exact_through_the_justified_family(self):
        calls, events = [], []
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate(calls), source=SOURCE,
                               jobs=1, emit=events.append)
        self.assertEqual(case.status, "exact")
        self.assertIn("s16 value;", self.store.source(case.best_digest))
        stages = [s["stage"] for s in case.stages]
        self.assertEqual(stages[:4], ["target", "source", "baseline", "diagnose"])
        self.assertEqual(case.stages[3]["causes"][0], "type.signedness")
        self.assertEqual(stages[4], "iterate")
        self.assertIn("exact-found", [e["event"] for e in events])

    def test_exact_case_is_not_recomputed(self):
        calls = []
        resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate(calls), source=SOURCE, jobs=1)
        before = len(calls)
        again = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate(calls), source=SOURCE, jobs=1)
        self.assertEqual((again.status, len(calls)), ("exact", before))

    def test_fragment_is_blocked_without_spending_a_build(self):
        calls = []
        case = resolve.resolve(self.store, "main", "piece", BASE, FRAGMENT, fake_evaluate(calls), source=SOURCE, jobs=1)
        self.assertEqual((case.status, case.top_cause, calls), ("blocked-boundary", "boundary.fragment", []))

    def test_changed_target_archives_the_old_case(self):
        calls, events = [], []
        resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate(calls), source=SOURCE, jobs=1)
        other = code([0x84820008, 0x03E00008, 0x00000000])          # same size, different bytes
        case = resolve.resolve(self.store, "main", "read", BASE, other, fake_evaluate(calls), source=SOURCE,
                               jobs=1, emit=events.append)
        self.assertEqual(events[0]["event"], "stale-case-archived")
        self.assertNotEqual(case.target_digest, events[0]["old_target"])
        stale = self.store.db.execute("SELECT COUNT(*) FROM stale").fetchone()[0]
        self.assertEqual(stale, 1)

    def test_missing_source_and_failed_draft(self):
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate([]), jobs=1,
                               draft=lambda family: (None, "m2c not found"))
        self.assertEqual((case.status, case.top_cause), ("needs-source", "source.missing"))
        self.assertIn("m2c not found", case.next)

    def test_build_failure_is_a_status_not_an_exception(self):
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate([]),
                               source="does not build", jobs=1)
        self.assertEqual(case.status, "does-not-build")

    def test_unhelpful_families_are_closed_for_that_source(self):
        def never(text):
            return iterate.Evaluation(5, False, {"counts": {"register": 2}, "entries": []}), WRONG
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, never, source=SOURCE, jobs=1, budget=60)
        self.assertIn(case.status, ("near", "open"))
        self.assertTrue(any(case.closed_families.values()))
        calls = []

        def counting(text):
            calls.append(text)
            return never(text)
        resolve.resolve(self.store, "main", "read", BASE, TARGET, counting, source=SOURCE, jobs=1, budget=60)
        self.assertLessEqual(len(calls), 3)          # baseline (+ final re-check): closed families are skipped

    def test_recipe_stage_switches_to_the_detected_compiler_family(self):
        # retail: move via `or` and an unconditional `b` (IDO); the candidate pipeline is KMC GCC
        target = code([0x00802825, 0x10000001, 0x00000000, 0x00A01025, 0x03E00008, 0x00000000])
        used = []

        def gcc(text):
            used.append("gcc")
            return iterate.Evaluation(9, False, {"counts": {"instruction": 3}, "entries": []}), WRONG

        def ido(text):
            used.append("ido")
            return iterate.Evaluation(0, True, {"counts": {}, "entries": []},
                                      outcome={"proof": {"verdict": "exact"}}), target
        case = resolve.resolve(self.store, "main", "copy", BASE, target, gcc, source=SOURCE, jobs=1,
                               pipeline="kmc+builtin", recipes=lambda family: [("ido5.3 -O2", "ido5.3", ido)])
        self.assertEqual(case.status, "exact")
        self.assertEqual(case.stages[0]["compiler_family"], "ido")
        self.assertEqual([s for s in case.stages if s["stage"] == "recipe"][0]["chosen"], "ido5.3 -O2")
        self.assertEqual(used, ["gcc", "ido"])

    def test_draft_portfolio_continues_from_the_closest_variant(self):
        good = SOURCE.replace("u16 value;", "s16 value;")
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate([]), jobs=1,
                               draft=lambda family: [("plain", SOURCE), ("context", good)])
        self.assertEqual(case.status, "exact")
        drafts = [s for s in case.stages if s["stage"] == "drafts"][0]["variants"]
        self.assertEqual([(d["label"], d["score"]) for d in drafts], [("context", 0), ("plain", 3)])
        self.assertEqual([s for s in case.stages if s["stage"] == "source"][0]["origin"], "draft:context")

    def test_a_draft_that_ranked_second_wins_under_a_sibling_recipe(self):
        """Under the default recipe `plain` is closest and nothing is exact; under the sibling
        recipe only `narrow` matches.  The case must end exact with that draft and that recipe."""
        narrow = SOURCE.replace("u16 value;", "u8 value;")

        def default(text):
            return iterate.Evaluation(6 if "u8 value;" in text else 3, False, {"counts": {"register": 1}}), WRONG

        def sibling(text):
            exact = "u8 value;" in text
            outcome = {"proof": {"verdict": "exact"}} if exact else None
            return iterate.Evaluation(0 if exact else 5, exact, {"counts": {}}, outcome=outcome), \
                (TARGET if exact else WRONG)

        events = []
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, default, jobs=1, emit=events.append,
                               pipeline="ido5.3", recipe_label="ido5.3 -O2",
                               draft=lambda family: [("plain", SOURCE), ("narrow", narrow)],
                               recipes=lambda family: [("ido7.1 -O2", "ido7.1", sibling)])
        self.assertEqual(case.status, "exact")
        self.assertEqual(case.recipe, "ido7.1 -O2")
        self.assertEqual([s for s in case.stages if s["stage"] == "source"][0]["origin"], "draft:narrow")
        cross = [s for s in case.stages if s["stage"] == "drafts-x-recipes"][0]
        self.assertEqual((cross["tried"], cross["chosen"]), (2, "ido7.1 -O2"))
        self.assertIn("recipe-selected", [e["event"] for e in events])

    def test_cross_check_is_skipped_when_a_draft_is_already_exact(self):
        good = SOURCE.replace("u16 value;", "s16 value;")
        calls = []
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate([]), jobs=1,
                               draft=lambda family: [("plain", SOURCE), ("context", good)],
                               recipes=lambda family: calls.append(family) or [])
        self.assertEqual(case.status, "exact")
        self.assertEqual(calls, [])
        self.assertFalse([s for s in case.stages if s["stage"] == "drafts-x-recipes"])

    def test_search_is_skipped_for_a_draft_too_far_from_the_target(self):
        calls = []

        def far(text):
            calls.append(text)
            return iterate.Evaluation(250, False, {"counts": {"instruction": 60}, "entries": []}), WRONG

        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, far, source=SOURCE, jobs=1, budget=50)
        self.assertEqual(case.status, "open")
        self.assertLessEqual(len(calls), 2)                              # baseline (and the final classification)
        self.assertEqual([s for s in case.stages if s["stage"] == "iterate-skipped"][0]["ceiling"],
                         resolve.SEARCH_CEILING)
        self.assertFalse([s for s in case.stages if s["stage"] == "iterate"])
        calls.clear()
        again = resolve.resolve(self.store, "main", "read", BASE, TARGET, far, source=SOURCE, jobs=1, budget=50,
                                search_ceiling=0, force=True)
        self.assertTrue([s for s in again.stages if s["stage"] == "iterate"])   # no ceiling: the search runs
        self.assertGreater(len(calls), 2)

    def test_worker_count(self):
        from n64dk.commands.resolve import worker_count
        self.assertEqual(worker_count(1, 500), 1)
        self.assertEqual(worker_count(6, 500), 6)
        self.assertEqual(worker_count(6, 5), 2)              # never more workers than half the functions
        self.assertEqual(worker_count(6, 1), 1)
        self.assertEqual(worker_count(None, 500), 1)
        self.assertGreaterEqual(worker_count(0, 500), 1)     # automatic: bounded by threads and free memory
        import os
        self.assertLessEqual(worker_count(0, 500), max(1, (os.cpu_count() or 4) // 2))

    def test_exact_case_records_the_strict_verdict_and_a_mismatch_demotes_it(self):
        seen = []

        def assumed(text, recipe):
            seen.append(recipe)
            return {"verdict": "assumed", "assumptions": [{"kind": "symbol", "name": "gThing"}]}
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate([], proof=False), source=SOURCE, jobs=1,
                               strict=assumed, recipe_label="ido5.3 -O2")
        self.assertEqual((case.status, case.strict["verdict"], seen), ("assumed", "assumed", ["ido5.3 -O2"]))
        self.assertIn("declare", case.next)
        other = resolve.resolve(self.store, "main", "read", BASE + 0x40, TARGET, fake_evaluate([], proof=False), source=SOURCE,
                                jobs=1, strict=lambda text, recipe: {"verdict": "mismatch",
                                                                     "conflicts": ["wrong callee"]})
        self.assertEqual(other.status, "open")
        self.assertIn("wrong callee", other.next)

    def test_exact_without_strict_proof_is_never_persisted(self):
        case = resolve.resolve(self.store, "main", "read", BASE, TARGET, fake_evaluate([], proof=False), source=SOURCE,
                               jobs=1, strict=lambda _text, _recipe: {"verdict": "error", "error": "boom"})
        self.assertEqual(case.status, "open")
        self.assertIn("strict verification", case.next)

    def test_twin_source_renames_symbols_site_by_site(self):
        from n64dk.commands.resolve import twin_source
        text = "extern s32 D_80100000;\ns32 func_80001000(void) {\n    helper();\n    return D_80100000 + func_80002000();\n}\n"
        old_sites = [(0, "jal", 0x80003000), (2, "hi", 0x80100000), (3, "lo", 0x80100000), (5, "jal", 0x80002000)]
        new_sites = [(0, "jal", 0x80003000), (2, "hi", 0x80100040), (3, "lo", 0x80100040), (5, "jal", 0x80002200)]
        names = {0x80003000: "helper", 0x80002200: "other_helper"}
        out = twin_source(text, "func_80001000", "func_80001100", old_sites, new_sites, names)
        self.assertEqual(out, "extern s32 D_80100040;\ns32 func_80001100(void) {\n    helper();\n"
                              "    return D_80100040 + func_80002200();\n}\n")
        self.assertIsNone(twin_source(text, "a", "b", old_sites, new_sites[:-1], names))       # different shape
        clash = [(0, "jal", 0x80003000), (2, "hi", 0x80100040), (3, "lo", 0x80100080), (5, "jal", 0x80002200)]
        self.assertIsNone(twin_source(text, "a", "b", old_sites, clash, names))               # one symbol, two addresses

    def test_hard_queue_groups_and_ranks(self):
        resolve.resolve(self.store, "main", "piece", BASE, FRAGMENT, fake_evaluate([]), source=SOURCE, jobs=1)
        resolve.resolve(self.store, "main", "read", BASE + 0x100, TARGET, fake_evaluate([]), jobs=1,
                        draft=lambda family: (None, "no m2c"))
        report = resolve.hard_queue(self.store.all())
        self.assertEqual({g["cause"] for g in report["queue"]}, {"boundary.fragment", "source.missing"})
        self.assertEqual(report["queue"][0]["cause"], "source.missing")      # boundary work has no compile payoff
        self.assertEqual(report["statuses"], {"blocked-boundary": 1, "needs-source": 1})


if __name__ == "__main__":
    unittest.main()
