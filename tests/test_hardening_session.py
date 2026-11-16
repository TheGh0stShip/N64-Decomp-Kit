"""Hardening regressions for session identity and failure memoisation (review finding F08)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from n64dk.match.engine import Outcome
from n64dk.match.pipeline import BuildSpec
from n64dk.match.session import MatchSession, SessionStore


class SessionPoisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = SessionStore(Path(self.tmp.name))

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_transient_failure_is_re_evaluated(self):
        calls = {"n": 0}

        def evaluator(source, pipeline, flags, label):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("database is locked")
            return Outcome("f", 0x80000400, 16, BuildSpec(pipeline, list(flags)))

        session = MatchSession(self.store, evaluator)
        sid, _ = session.create({"addr": 0x80000400}, b"int f(void){return 0;}\n", "kmc", ("-O2",))
        first = session.try_proposal(sid, {"hypothesis": "h", "source": "int f(void){return 1;}\n"}, jobs=1)
        second = session.try_proposal(sid, {"hypothesis": "retry", "source": "int f(void){return 1;}\n"}, jobs=1)
        self.assertEqual(calls["n"], 3)
        stored = [c for c in self.store.candidates(sid) if c.label != "baseline"]
        self.assertEqual([(c.status, c.error) for c in stored], [("evaluated", None)])
        attempts = self.store.db.execute("SELECT status FROM candidate_attempts WHERE session_id=? ORDER BY attempt_ns",
                                         (sid,)).fetchall()
        self.assertEqual([row[0] for row in attempts], ["evaluated", "failed", "evaluated"])
        del first, second

    def test_environment_change_re_evaluates_and_unchanged_reuses(self):
        calls = {"n": 0}
        header = {"value": "v1"}

        def evaluator(source, pipeline, flags, label):
            calls["n"] += 1
            return Outcome("f", 0x80000400, 16, BuildSpec(pipeline, list(flags)))
        evaluator.environment = lambda source, pipeline, flags: header["value"]

        session = MatchSession(self.store, evaluator)
        sid, _ = session.create({"addr": 0x80000400}, b"int f(void){return 0;}\n", "kmc", ("-O2",))
        proposal = {"hypothesis": "h", "source": "int f(void){return 1;}\n"}
        session.try_proposal(sid, proposal, jobs=1)
        session.try_proposal(sid, proposal, jobs=1)
        self.assertEqual(calls["n"], 2)          # baseline + one evaluation, second is a cache hit
        header["value"] = "v2"                    # e.g. an included header changed
        session.try_proposal(sid, proposal, jobs=1)
        self.assertEqual(calls["n"], 3)


if __name__ == "__main__":
    unittest.main()
