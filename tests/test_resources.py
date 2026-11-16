import os
import unittest
from unittest import mock

from n64dk.resources import MemorySnapshot, memory_snapshot, plan_jobs


class ResourceTests(unittest.TestCase):
    def test_meminfo_and_swap_used(self):
        with self.subTest("parsed"):
            import tempfile
            from pathlib import Path
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "meminfo"
                path.write_text("MemTotal: 8192000 kB\nMemAvailable: 6144000 kB\n"
                                "SwapTotal: 2097152 kB\nSwapFree: 1048576 kB\n")
                found = memory_snapshot(path)
                self.assertEqual((found.total_mb, found.available_mb, found.swap_used_mb),
                                 (8000, 6000, 1024))

    @mock.patch("os.cpu_count", return_value=32)
    def test_default_is_bounded_by_ceiling(self, _cpu):
        found = plan_jobs(0, snapshot=MemorySnapshot(8000, 7000, 0, 0), max_jobs=4)
        self.assertEqual(found.jobs, 4)
        self.assertIn("safety-ceiling", found.limited_by)

    @mock.patch("os.cpu_count", return_value=32)
    def test_low_memory_reduces_even_explicit_request(self, _cpu):
        found = plan_jobs(12, snapshot=MemorySnapshot(8000, 2800, 2048, 1024),
                          max_jobs=16, reserve_mb=2048, memory_per_job_mb=512)
        self.assertEqual(found.jobs, 1)
        self.assertIn("available-memory", found.limited_by)

    @mock.patch("os.cpu_count", return_value=32)
    def test_deliberate_override_disables_memory_and_ceiling_caps(self, _cpu):
        with mock.patch.dict(os.environ, {"N64DK_ALLOW_OVERSUBSCRIBE": "1"}):
            found = plan_jobs(12, snapshot=MemorySnapshot(8000, 1000, 2048, 0))
        self.assertEqual(found.jobs, 12)
        self.assertTrue(found.oversubscribe)


if __name__ == "__main__":
    unittest.main()
