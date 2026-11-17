"""Stage profiles: tools and builds of this process and of forked workers are added up once."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from n64dk import profiling, safety
from n64dk.match import pipeline


class ProfileTest(unittest.TestCase):
    def test_stage_record_and_forked_worker_counters(self):
        out = Path(tempfile.mkdtemp(prefix="n64dk-test-profile-"))
        profiler = profiling.Profiler(out)
        with profiler.stage("resolve", "main") as record:
            safety.run_tool(["true"])
            pid = os.fork()
            if pid == 0:
                status = 1
                try:
                    safety.forked()                      # inherited counters are cleared
                    safety.run_tool(["true"])
                    safety.run_tool(["true"])
                    safety.flush_usage()
                    status = 0
                finally:
                    os._exit(status)
            _pid, status = os.waitpid(pid, 0)
            self.assertEqual(status, 0)
            record["gain"] = {"exact": 3}
        saved = [json.loads(line) for line in (out / "profile.jsonl").read_text().splitlines()]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["tools"]["true"]["count"], 3)       # 1 here + 2 in the worker, once each
        self.assertEqual(saved[0]["gain"], {"exact": 3})
        for key in ("wall_s", "python_cpu_s", "child_cpu_s", "peak_rss_mb", "builds", "read_bytes"):
            self.assertIn(key, saved[0])
        self.assertFalse((out / "usage" / "0000-resolve").exists())
        self.assertEqual(profiler.summary()["resolve"]["tool_invocations"], 3)

    def test_dedup_rate(self):
        out = Path(tempfile.mkdtemp(prefix="n64dk-test-profile-"))
        profiler = profiling.Profiler(out)
        with profiler.stage("resolve") as _record:
            with pipeline._CACHE_LOCK:
                pipeline._REQUESTED["builds"] += 4
                pipeline._OBJECT_KEYS.update({"k1", "k2"})
                pipeline._SOURCE_TEXTS.update({"s1"})
        builds = profiler.records[0]["builds"]
        self.assertEqual((builds["requested"], builds["distinct_objects"], builds["dedup_rate"]), (4, 2, 0.5))


if __name__ == "__main__":
    unittest.main()
