"""Keeping the workstation usable: preflight, pause under pressure, one heavy job at a time,
leases, cancellation, per-child memory ceiling, bounded caches.  Every check runs on synthetic
values or small synthetic processes; nothing here exhausts memory."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from n64dk import resources, safety


class PreflightTest(unittest.TestCase):
    def check(self, available, pressure, free):
        return safety.preflight(Path("/"), min_available_mb=3072, max_pressure=10, min_free_mb=2048,
                                available=lambda: available, pressure=lambda: pressure, free=lambda _w: free)

    def test_a_job_starts_only_with_memory_calm_and_disk_space(self):
        self.assertTrue(self.check(6000, 0.5, 900000)["ok"])
        low = self.check(2000, 0.5, 900000)
        self.assertFalse(low["ok"])
        self.assertIn("only 2000 MB of memory available", low["reasons"][0])
        self.assertFalse(self.check(6000, 40.0, 900000)["ok"])
        self.assertIn("free on the output disk", self.check(6000, 0.5, 100)["reasons"][0])

    def test_unknown_measurements_do_not_block(self):
        self.assertTrue(self.check(None, None, None)["ok"])

    def test_switched_off(self):
        with mock.patch.dict(os.environ, {"N64DK_SAFETY": "off"}):
            self.assertTrue(self.check(10, 99.0, 1)["ok"])


class ThrottleTest(unittest.TestCase):
    def setUp(self):
        safety._last_check[:] = [0.0, False]

    def test_launches_wait_while_memory_is_short_and_go_on_when_it_recovers(self):
        readings = iter([60.0, 60.0, 40.0, 1.0])          # pressure, falling
        clock = [100.0]

        def sleep(seconds):
            clock[0] += seconds
        with mock.patch.dict(os.environ, {"N64DK_PAUSE_PRESSURE": "25", "N64DK_PAUSE_LIMIT_S": "600"}):
            waited = safety.throttle(pressure=lambda: next(readings), available=lambda: 5000, sleep=sleep,
                                     clock=lambda: clock[0])
        self.assertEqual(waited, 6.0)
        self.assertGreaterEqual(safety.pauses()["count"], 1)

    def test_a_calm_machine_is_not_delayed_and_not_read_twice_a_second(self):
        calls = []
        clock = [500.0]

        def pressure():
            calls.append(1)
            return 0.0
        for _ in range(5):
            self.assertEqual(safety.throttle(pressure=pressure, available=lambda: 5000, clock=lambda: clock[0]), 0.0)
        self.assertEqual(len(calls), 1)

    def test_the_wait_is_bounded(self):
        clock = [1000.0]

        def sleep(seconds):
            clock[0] += seconds
        with mock.patch.dict(os.environ, {"N64DK_PAUSE_LIMIT_S": "10"}):
            waited = safety.throttle(pressure=lambda: 90.0, available=lambda: 5000, sleep=sleep, clock=lambda: clock[0])
        self.assertGreaterEqual(waited, 10.0)
        self.assertLess(waited, 13.0)


class LockTest(unittest.TestCase):
    def test_a_second_heavy_job_refuses_and_a_nested_one_shares(self):
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-lock-"))
        with mock.patch.dict(os.environ, {"N64DK_STATE_DIR": str(folder)}):
            with safety.heavy_job("outer", folder, force=True):
                with safety.heavy_job("inner", folder) as inner:          # a batch running a title
                    self.assertTrue(inner["nested"])
                # another process trying to start while this one runs
                probe = subprocess.run([sys.executable, "-c",
                                        "from n64dk import safety\n"
                                        "try:\n"
                                        "    with safety.machine_lock():\n"
                                        "        print('got it')\n"
                                        "except safety.Busy as error:\n"
                                        "    print('busy', error)\n"],
                                       capture_output=True, text=True, env={**os.environ, "N64DK_STATE_DIR": str(folder),
                                                                            "PYTHONPATH": os.getcwd()})
                self.assertTrue(probe.stdout.startswith("busy"), probe.stdout + probe.stderr)
                self.assertEqual(len(safety.leases()), 1)
            self.assertEqual(safety.leases(), [])
            with safety.machine_lock():                                  # free again
                pass

    def test_a_job_that_may_not_start_says_why(self):
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-lock-"))
        with mock.patch.dict(os.environ, {"N64DK_STATE_DIR": str(folder), "N64DK_MIN_AVAILABLE_MB": "999999999"}):
            with self.assertRaises(safety.Busy) as caught:
                with safety.heavy_job("big", folder):
                    pass
            self.assertIn("not starting", str(caught.exception))
            with safety.heavy_job("big", folder, force=True):
                pass


class LeaseTest(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="n64dk-test-jobs-"))
        self.env = mock.patch.dict(os.environ, {"N64DK_STATE_DIR": str(self.folder)})
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_a_record_left_by_a_job_that_died_is_stale(self):
        jobs = self.folder / "jobs"
        jobs.mkdir()
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        (jobs / f"{dead.pid}-1.json").write_text(json.dumps({"pid": dead.pid, "start_time": "1", "heartbeat": time.time(),
                                                              "command": "decompile-run"}))
        self.assertEqual([record["state"] for record in safety.leases()], ["stale"])
        self.assertFalse(safety.cancel(dead.pid)["cancelled"])
        self.assertEqual(safety.leases(), [])

    def test_cancel_stops_the_job_and_everything_it_started(self):
        # a job that starts a child of its own, in its own process group, as a sweep would
        job = subprocess.Popen([sys.executable, "-c",
                                "import subprocess, sys, time\n"
                                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
                                "print(child.pid, flush=True)\n"
                                "time.sleep(120)\n"],
                               stdout=subprocess.PIPE, text=True, start_new_session=True)
        child = int(job.stdout.readline())
        jobs = self.folder / "jobs"
        jobs.mkdir(exist_ok=True)
        (jobs / f"{job.pid}.json").write_text(json.dumps({
            "pid": job.pid, "pgid": job.pid, "start_time": safety._start_time(job.pid), "heartbeat": time.time(),
            "command": "decompile-run"}))
        self.assertEqual([record["state"] for record in safety.leases()], ["running"])
        result = safety.cancel(job.pid, grace=5)
        job.wait(timeout=10)
        job.stdout.close()
        self.assertTrue(result["cancelled"])
        deadline = time.time() + 5
        while time.time() < deadline and safety._start_time(child) is not None:
            time.sleep(0.1)
        state = Path(f"/proc/{child}/stat").read_text().split()[2] if Path(f"/proc/{child}/stat").exists() else "gone"
        self.assertIn(state, ("gone", "Z"))                          # no child left running
        self.assertEqual(safety.leases(), [])

    def test_a_lease_beats_and_is_removed(self):
        with safety.JobLease("decompile-run", ["--x"], heartbeat=0.05) as lease:
            first = json.loads(lease.path.read_text())["heartbeat"]
            time.sleep(0.3)
            self.assertGreater(json.loads(lease.path.read_text())["heartbeat"], first)
            self.assertEqual([record["state"] for record in safety.leases()], ["running"])
        self.assertFalse(lease.path.exists())


class ChildLimitTest(unittest.TestCase):
    def test_a_child_that_outgrows_its_ceiling_fails_alone(self):
        with mock.patch.dict(os.environ, {"N64DK_CHILD_MEMORY_MB": "200"}):
            child = subprocess.Popen([sys.executable, "-c",
                                      "import sys, time\n"
                                      "time.sleep(0.3)\n"
                                      "try:\n"
                                      "    block = bytearray(400 * 1024 * 1024)\n"
                                      "    print('allocated')\n"
                                      "except MemoryError:\n"
                                      "    print('refused')\n"],
                                     stdout=subprocess.PIPE, text=True)
            self.assertTrue(safety.limit_child(child.pid))
            out, _ = child.communicate(timeout=30)
        self.assertEqual(out.strip(), "refused")

    def test_no_ceiling_when_switched_off(self):
        with mock.patch.dict(os.environ, {"N64DK_CHILD_MEMORY_MB": "0"}):
            self.assertFalse(safety.limit_child(os.getpid()))


class CompilerCleanupTest(unittest.TestCase):
    def test_a_timed_out_tool_leaves_no_descendant(self):
        from n64dk.match.pipeline import BuildError, _run
        marker = f"n64dk-test-{os.getpid()}-{time.time_ns()}"
        with self.assertRaises(BuildError):
            _run(["bash", "-c", f"exec -a {marker} sleep 60 & exec -a {marker}b sleep 60"], cwd=tempfile.gettempdir(),
                 timeout=1)
        time.sleep(0.5)
        survivors = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True).stdout.split()
        self.assertEqual(survivors, [])


class PruneTest(unittest.TestCase):
    def test_least_recently_used_first(self):
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-cache-"))
        for number in range(5):
            path = folder / "objects" / f"{number}.o"
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b"x" * 400_000)
            os.utime(path, (1000 + number, 1000 + number))
        result = safety.prune(folder, max_mb=1)
        self.assertEqual(result["removed"], 3)
        self.assertEqual(sorted(p.name for p in (folder / "objects").iterdir()), ["3.o", "4.o"])

    def test_a_pruned_object_reads_as_a_miss(self):
        from n64dk.match.cache import ContentCache
        cache = ContentCache(tempfile.mkdtemp(prefix="n64dk-test-cache-"))
        digest = cache.put(b"x" * 2_000_000)
        cache.put_ref("unit", digest)
        cache.prune(max_mb=1)
        self.assertIsNone(cache.get_ref("unit"))


class SmallMachineTest(unittest.TestCase):
    def test_two_jobs_below_twelve_gigabytes(self):
        small = resources.MemorySnapshot(7899, 6000, 2048, 2048)
        large = resources.MemorySnapshot(65536, 60000, 0, 0)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("N64DK_MAX_JOBS", None)
            with mock.patch("os.cpu_count", return_value=16):
                self.assertEqual(resources.plan_jobs(0, snapshot=small).jobs, 2)
                self.assertEqual(resources.plan_jobs(8, snapshot=small).jobs, 2)
                self.assertEqual(resources.plan_jobs(0, snapshot=large).jobs, 4)


class ReadOnlyStoreTest(unittest.TestCase):
    def test_inspecting_a_finished_run_leaves_no_file_behind(self):
        from n64dk.match import resolve as resolvemod
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-store-"))
        store = resolvemod.CaseStore(folder)
        store.close()
        for sidecar in folder.glob("cases.sqlite-*"):
            sidecar.unlink()
        (folder / "sources").rmdir()
        before = sorted(p.name for p in folder.iterdir())
        reader = resolvemod.CaseStore(folder, readonly=True)
        self.assertEqual(reader.all(), [])
        reader.close()
        self.assertEqual(sorted(p.name for p in folder.iterdir()), before)


if __name__ == "__main__":
    unittest.main()


class TerminateTest(unittest.TestCase):
    def test_sigterm_releases_the_lease_and_the_lock(self):
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-term-"))
        env = {**os.environ, "N64DK_STATE_DIR": str(folder), "PYTHONPATH": os.getcwd()}
        job = subprocess.Popen([sys.executable, "-c",
                                "import time\nfrom pathlib import Path\nfrom n64dk import safety\n"
                                "with safety.heavy_job('test', Path('.'), force=True):\n"
                                "    print('running', flush=True)\n    time.sleep(60)\n"],
                               stdout=subprocess.PIPE, text=True, env=env)
        self.assertEqual(job.stdout.readline().strip(), "running")
        self.assertEqual(len(list((folder / "jobs").glob("*.json"))), 1)
        job.terminate()
        job.wait(timeout=10)
        job.stdout.close()
        self.assertEqual(job.returncode, 143)
        self.assertEqual(list((folder / "jobs").glob("*.json")), [])
        with mock.patch.dict(os.environ, {"N64DK_STATE_DIR": str(folder)}):
            with safety.machine_lock():
                pass


class TokenTest(unittest.TestCase):
    def test_independent_processes_never_exceed_the_machine_capacity(self):
        """Six processes, each running three 'tools' through the shared tokens, capacity two:
        never more than two at once (start/end times are recorded and replayed)."""
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-tokens-"))
        env = {**os.environ, "N64DK_STATE_DIR": str(folder), "N64DK_TOKENS_COMPILE": "2", "PYTHONPATH": os.getcwd()}
        script = ("import json, os, time\nfrom n64dk import safety\n"
                  "for _ in range(3):\n"
                  "    with safety.token('compile'):\n"
                  "        start = time.time(); time.sleep(0.15); end = time.time()\n"
                  "    with open(os.environ['N64DK_STATE_DIR'] + '/spans.txt', 'a') as sink:\n"
                  "        sink.write(json.dumps([start, end]) + '\\n')\n")
        jobs = [subprocess.Popen([sys.executable, "-c", script], env=env) for _ in range(6)]
        for job in jobs:
            self.assertEqual(job.wait(timeout=60), 0)
        spans = [json.loads(line) for line in (folder / "spans.txt").read_text().splitlines()]
        self.assertEqual(len(spans), 18)
        points = sorted([(start, 1) for start, _ in spans] + [(end, -1) for _, end in spans], key=lambda p: (p[0], p[1]))
        running = peak = 0
        for _, step in points:
            running += step
            peak = max(peak, running)
        self.assertLessEqual(peak, 2)
        self.assertEqual(peak, 2)                       # and the capacity is used

    def test_a_dead_holder_frees_its_token(self):
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-tokens-"))
        env = {**os.environ, "N64DK_STATE_DIR": str(folder), "N64DK_TOKENS_MODEL": "1", "PYTHONPATH": os.getcwd()}
        holder = subprocess.Popen([sys.executable, "-c", "import time\nfrom n64dk import safety\n"
                                   "with safety.token('model'):\n    print('held', flush=True); time.sleep(60)\n"],
                                  stdout=subprocess.PIPE, text=True, env=env)
        self.assertEqual(holder.stdout.readline().strip(), "held")
        with mock.patch.dict(os.environ, {"N64DK_STATE_DIR": str(folder), "N64DK_TOKENS_MODEL": "1"}):
            with self.assertRaises(safety.Busy):
                with safety.token("model", deadline=0.3):
                    pass
            holder.kill()
            holder.wait()
            holder.stdout.close()
            with safety.token("model", deadline=5):
                pass
            self.assertIn("token-refused", (folder / "events.jsonl").read_text())


class LegacyCeilingTest(unittest.TestCase):
    def test_an_emulator_may_reserve_its_guest_address_space(self):
        """qemu-irix reserves 2 GB of address space up front; the ordinary 2 GB ceiling refused it
        (every IDO 5.2/6.0/MIPSpro build failed).  Emulators get the larger legacy ceiling."""
        import resource
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        try:
            with mock.patch.dict(os.environ, {"N64DK_CHILD_MEMORY_MB": "2048", "N64DK_CHILD_MEMORY_MB_LEGACY": "8192"}):
                self.assertTrue(safety.limit_child(child.pid, legacy=True))
                soft, _hard = resource.prlimit(child.pid, resource.RLIMIT_AS)
                self.assertEqual(soft, 8192 * 1024 * 1024)
        finally:
            child.kill()
            child.wait()


class CombinedCeilingTest(unittest.TestCase):
    def test_emulated_and_native_tools_share_one_ceiling(self):
        """Regression: compile and legacy tokens were separate pools, so two native and two
        emulated tools ran at once under a ceiling of two (measured: 4 compiler processes)."""
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-tokens-"))
        env = {**os.environ, "N64DK_STATE_DIR": str(folder), "N64DK_TOKENS_COMPILE": "2",
               "N64DK_TOKENS_LEGACY": "2", "PYTHONPATH": os.getcwd()}
        script = ("import json, os, sys, time\nfrom n64dk import safety\n"
                  "for _ in range(3):\n"
                  "    with safety.tool_tokens(legacy=sys.argv[1] == 'legacy'):\n"
                  "        start = time.time(); time.sleep(0.15); end = time.time()\n"
                  "    with open(os.environ['N64DK_STATE_DIR'] + '/spans.txt', 'a') as sink:\n"
                  "        sink.write(json.dumps([start, end]) + '\\n')\n")
        jobs = [subprocess.Popen([sys.executable, "-c", script, kind], env=env)
                for kind in ("legacy", "native", "legacy", "native", "legacy", "native")]
        for job in jobs:
            self.assertEqual(job.wait(timeout=60), 0)
        spans = [json.loads(line) for line in (folder / "spans.txt").read_text().splitlines()]
        points = sorted([(s, 1) for s, _ in spans] + [(e, -1) for _, e in spans], key=lambda p: (p[0], p[1]))
        running = peak = 0
        for _, step in points:
            running += step
            peak = max(peak, running)
        self.assertEqual(len(spans), 18)
        self.assertLessEqual(peak, 2)


class TerminateEverythingTest(unittest.TestCase):
    def test_sigterm_stops_thread_pools_forked_workers_and_tools(self):
        """Regression: SIGTERM raised SystemExit, and a thread pool's exit waited for every queued
        task, so a timed-out decompile-run kept running orphaned (measured).  Now the job, its
        forked worker and its tools' process groups all stop, and the lease is removed."""
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-term-"))
        env = {**os.environ, "N64DK_STATE_DIR": str(folder), "PYTHONPATH": os.getcwd()}
        script = (
            "import os, subprocess, sys, time\n"
            "from concurrent.futures import ThreadPoolExecutor\n"
            "from pathlib import Path\n"
            "from n64dk import safety\n"
            "with safety.heavy_job('test', Path('.'), force=True):\n"
            "    tool = subprocess.Popen(['sleep', '120'], start_new_session=True)\n"
            "    safety.register_tool(tool.pid)\n"
            "    pid = os.fork()\n"
            "    if pid == 0:\n"
            "        safety.forked()\n"
            "        time.sleep(120)\n"
            "        os._exit(0)\n"
            "    safety.register_child(pid)\n"
            "    print(tool.pid, pid, flush=True)\n"
            "    with ThreadPoolExecutor(2) as pool:\n"
            "        list(pool.map(lambda _: time.sleep(5), range(40)))\n")
        job = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True, env=env)
        tool, worker = (int(value) for value in job.stdout.readline().split())
        time.sleep(0.5)
        started = time.monotonic()
        job.terminate()
        job.wait(timeout=15)
        job.stdout.close()
        self.assertEqual(job.returncode, 143)
        self.assertLess(time.monotonic() - started, 10)

        def gone(pid):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    with open(f"/proc/{pid}/stat") as handle:
                        if handle.read().split(")")[-1].split()[0] == "Z":
                            return True
                except FileNotFoundError:
                    return True
                time.sleep(0.05)
            return False
        self.assertTrue(gone(tool), "the tool's process group survived")
        self.assertTrue(gone(worker), "the forked worker survived")
        self.assertEqual(list((folder / "jobs").glob("*.json")), [])


class WeightedSlotsTest(unittest.TestCase):
    def test_weights_in_flight_never_exceed_the_pool(self):
        """Eight processes with weights 1 and 2 over a pool of 4: the sum held at once stays <= 4."""
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-weights-"))
        env = {**os.environ, "N64DK_STATE_DIR": str(folder), "N64DK_TOKENS_COMPILE": "4", "PYTHONPATH": os.getcwd()}
        script = ("import json, os, sys, time\nfrom n64dk import safety\nweight = int(sys.argv[1])\n"
                  "for _ in range(3):\n"
                  "    with safety.token('compile', weight=weight):\n"
                  "        start = time.time(); time.sleep(0.12); end = time.time()\n"
                  "    with open(os.environ['N64DK_STATE_DIR'] + '/spans.txt', 'a') as sink:\n"
                  "        sink.write(json.dumps([start, end, weight]) + '\\n')\n")
        jobs = [subprocess.Popen([sys.executable, "-c", script, str(w)], env=env) for w in (1, 2, 1, 2, 1, 2, 1, 1)]
        for job in jobs:
            self.assertEqual(job.wait(timeout=90), 0)
        spans = [json.loads(line) for line in (folder / "spans.txt").read_text().splitlines()]
        self.assertEqual(len(spans), 24)
        points = sorted([(s, w) for s, _e, w in spans] + [(e, -w) for _s, e, w in spans], key=lambda p: (p[0], p[1]))
        running = peak = 0
        for _, step in points:
            running += step
            peak = max(peak, running)
        self.assertLessEqual(peak, 4)
        self.assertGreaterEqual(peak, 3)                   # and the pool is used

    def test_unprofiled_tools_keep_the_old_ceiling_and_measured_ones_follow_the_profile(self):
        folder = Path(tempfile.mkdtemp(prefix="n64dk-test-profile-"))
        with mock.patch.dict(os.environ, {"N64DK_STATE_DIR": str(folder), "N64DK_TOKENS_COMPILE": "4"}):
            safety._PROFILE["loaded"] = 0.0
            self.assertEqual(safety.tool_weight("cc1"), 2)                  # 4 slots / 2: two at once
            (folder / "tool_profile.json").write_text(json.dumps({"families": {
                "cc1": {"peak_rss_mb": 30.0, "samples": 9}, "big": {"peak_rss_mb": 900.0, "samples": 9},
                "mid": {"peak_rss_mb": 300.0, "samples": 9}, "few": {"peak_rss_mb": 10.0, "samples": 2}}}))
            safety._PROFILE["loaded"] = 0.0
            self.assertEqual([safety.tool_weight(f) for f in ("cc1", "mid", "big", "few")], [1, 2, 4, 2])

    def test_memory_admission_waits_for_the_floor(self):
        readings = iter([1000, 1200, 4000])
        with mock.patch.dict(os.environ, {"N64DK_TOOL_FLOOR_MB": "1536"}), \
                mock.patch.object(safety, "available_mb", lambda: next(readings)), \
                mock.patch.object(safety.time, "sleep", lambda _s: None):
            safety.admit_memory(256)
        with self.assertRaises(StopIteration):
            next(readings)                                 # it read until the third value

    def test_measured_peaks_are_the_tools_own(self):
        """A tool forked from this process inherits its RSS high-water mark; through the
        measurement wrapper a small tool reports a small peak."""
        if not os.path.exists("/usr/bin/time"):
            self.skipTest("/usr/bin/time not installed")
        ballast = bytearray(150 * 1024 * 1024)               # this process: >150 MB resident
        for index in range(0, len(ballast), 4096):
            ballast[index] = 1
        with mock.patch.dict(os.environ, {"N64DK_MEASURE_RSS": "1"}):
            safety.TOOL_USAGE.pop("true", None)
            safety.run_tool(["true"])
        self.assertLess(safety.TOOL_USAGE["true"]["peak_rss_mb"], 50)
        del ballast
