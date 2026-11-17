"""Search economics: a stratum that has cost builds and returned nothing stops being searched,
except for probes; a paying stratum never does; the state survives a second pass."""
import tempfile
import unittest
from pathlib import Path

from n64dk.match.economics import Governor


class GovernorTest(unittest.TestCase):
    def test_a_stratum_that_never_pays_plateaus_and_is_probed(self):
        governor = Governor(window=4, min_builds=100, probe=3)
        key = governor.stratum("kmc+as -O2", 80)
        for _ in range(4):
            self.assertEqual(governor.allow(key), (True, ""))
            governor.record(key, 80, 78, 30, False)
        decisions = [governor.allow(key)[0] for _ in range(6)]
        self.assertEqual(decisions, [False, False, True, False, False, True])
        self.assertIn("plateau", governor.allow(key)[1])
        row = next(row for row in governor.ranking() if row["stratum"] == key)
        self.assertTrue(row["plateaued"])
        self.assertGreater(row["builds_saved_estimate"], 0)

    def test_a_stratum_that_pays_is_never_stopped(self):
        governor = Governor(window=2, min_builds=10, probe=3)
        key = governor.stratum("ido5.3 -O2", 30)
        governor.record(key, 30, 8, 40, False)            # brought within ten: a yield
        for _ in range(10):
            governor.record(key, 30, 30, 40, False)
        self.assertTrue(all(governor.allow(key)[0] for _ in range(5)))

    def test_not_judged_before_the_window_and_the_spend(self):
        governor = Governor(window=5, min_builds=1000, probe=3)
        key = governor.stratum("x", 200)
        for _ in range(10):
            governor.record(key, 200, 200, 20, False)     # many searches, few builds
        self.assertTrue(governor.allow(key)[0])

    def test_state_is_kept_for_the_next_pass(self):
        path = Path(tempfile.mkdtemp(prefix="n64dk-test-econ-")) / "economics_main.json"
        first = Governor(path, window=1, min_builds=1, probe=50)
        key = first.stratum("x", 60)
        first.record(key, 60, 60, 5, False)
        first.save()
        second = Governor(path, window=1, min_builds=1, probe=50)
        self.assertFalse(second.allow(key)[0])

    def test_bands(self):
        self.assertEqual(Governor.stratum("r", 5), "r | first draft <=10")
        self.assertEqual(Governor.stratum("r", None), "r | first draft no-score")


if __name__ == "__main__":
    unittest.main()


class ObservingGovernorTest(unittest.TestCase):
    def test_observes_without_changing_the_search(self):
        import json
        import tempfile
        from pathlib import Path
        from n64dk.match.economics import Governor
        path = Path(tempfile.mkdtemp(prefix="n64dk-test-observe-")) / "economics_main.json"
        governor = Governor(path, window=2, min_builds=10, active=False)
        key = governor.stratum("kmc+as -O2", 50)
        for _ in range(3):                                 # a plateau: no exact, no near
            governor.record(key, 50, 48, 20, False)
        self.assertTrue(governor.plateaued(key))
        prediction = governor.predict(key)
        self.assertTrue(prediction["would_skip"])
        self.assertEqual(governor.allow(key), (True, ""))  # observing: never skips
        governor.observe(prediction, 50, 0, 12, True, 1.5)
        rows = [json.loads(line) for line in path.with_suffix(".observations.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["would_skip"], rows[0]["exact"], rows[0]["active"], rows[0]["builds"]),
                         (True, True, False, 12))
        active = Governor(path.with_name("active.json"), window=2, min_builds=10, probe=100)
        for _ in range(3):
            active.record(key, 50, 48, 20, False)
        self.assertFalse(active.allow(key)[0])
