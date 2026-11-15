import struct
import tempfile
import unittest

from n64dk.match import iterate, resolve

BASE = 0x80001000


def code(words):
    return b"".join(struct.pack(">I", w) for w in words)


TARGET = code([0x84820004, 0x03E00008, 0x00000000])        # lh v0,4(a0); jr ra; nop
WRONG = code([0x94820004, 0x03E00008, 0x00000000])         # lhu
FRAGMENT = code([0x96020060, 0x00481821, 0xA6030024, 0x8FBF001C, 0x03E00008, 0x27BD0020])
SOURCE = "s32 read(Thing *thing) {\n    u16 value;\n\n    value = thing->field;\n    return value;\n}\n"


def fake_evaluate(calls):
    """Pretend compiler: the function matches when ``value`` is declared s16."""
    def evaluate(text):
        calls.append(text)
        if "does not build" in text:
            return iterate.Evaluation(None, error="x.c:1: parse error"), None
        exact = "s16 value;" in text
        report = {"counts": {} if exact else {"instruction": 1},
                  "entries": [] if exact else [{"compiled": "lhu $v0, 0x4($a0)", "retail": "lh $v0, 0x4($a0)"}]}
        return iterate.Evaluation(0 if exact else 3, exact, report), (TARGET if exact else WRONG)
    return evaluate


class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="n64dk-resolve-test-")
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
        self.assertEqual(stages[4], "iterate:justified")
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
            return iterate.Evaluation(0, True, {"counts": {}, "entries": []}), target
        case = resolve.resolve(self.store, "main", "copy", BASE, target, gcc, source=SOURCE, jobs=1,
                               pipeline="kmc+builtin", recipes=lambda family: [("ido5.3 -O2", "ido5.3", ido)])
        self.assertEqual(case.status, "exact")
        self.assertEqual(case.stages[0]["compiler_family"], "ido")
        self.assertEqual([s for s in case.stages if s["stage"] == "recipe"][0]["chosen"], "ido5.3 -O2")
        self.assertEqual(used, ["gcc", "ido"])

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
