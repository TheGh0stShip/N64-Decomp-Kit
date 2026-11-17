"""Every external process goes through the shared runner (``safety.run_tool`` or the build
runners that take tokens themselves).  A direct launch anywhere else fails this test, so a new one
cannot bypass the machine's admission."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "n64dk"
LAUNCH = re.compile(r"\bsubprocess\.(run|Popen|check_output|check_call|call|getoutput|getstatusoutput)\(")

# file -> why its direct launches are allowed
ALLOWED = {
    "safety.py": "the shared runner itself",
    "match/pipeline.py": "built-in compiler pipeline: takes tool tokens, registers the process group",
    "match/custom_pipeline.py": "configured compiler lanes: takes tool tokens, registers the process group",
    "match/runner.py": "project build commands: takes a token, registers the process group",
    "match/refine.py": "the model call: takes the model token",
    "match/m2c_server.py": "m2c fork server: a light token per draft, registers its process group, the child "
                           "memory ceiling and the parent-death signal",
    "operations.py": "runs n64dk itself; the tools that process starts take their own tokens",
    "commands/results.py": "runs n64dk itself",
    "commands/candidates.py": "runs n64dk itself (match) and git ls-files for an interactive command",
    "commands/workbench.py": "interactive project gates and git queries a person starts, not part of decompile-run",
    "fixtures.py": "test fixture repositories (git)",
}


class LaunchTest(unittest.TestCase):
    def test_no_direct_launch_outside_the_runners(self):
        offenders = []
        for path in sorted(ROOT.rglob("*.py")):
            relative = path.relative_to(ROOT).as_posix()
            if relative in ALLOWED:
                continue
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if LAUNCH.search(line) and not line.lstrip().startswith("#"):
                    offenders.append(f"{relative}:{number}: {line.strip()}")
        self.assertEqual(offenders, [], "launch through n64dk.safety.run_tool")


class RunToolTest(unittest.TestCase):
    def test_result_timeout_and_group_kill(self):
        import os
        import subprocess
        import time
        from n64dk import safety
        done = safety.run_tool(["sh", "-c", "echo out; echo err >&2; exit 3"], text=True)
        self.assertEqual((done.returncode, done.stdout, done.stderr), (3, "out\n", "err\n"))
        with self.assertRaises(subprocess.CalledProcessError):
            safety.run_tool(["sh", "-c", "exit 1"], check=True)
        started = time.monotonic()
        marker = Path(os.environ.get("N64DK_STATE_DIR", "/tmp")) / f"grandchild-{os.getpid()}"
        with self.assertRaises(subprocess.TimeoutExpired):
            # a grandchild in the same session must die with the group
            safety.run_tool(["sh", "-c", f"(sleep 5; touch {marker}) & sleep 5"], timeout=0.5)
        self.assertLess(time.monotonic() - started, 3)
        time.sleep(5.5)
        self.assertFalse(marker.exists(), "the grandchild outlived the timeout")
        self.assertEqual(safety._TOOL_GROUPS, set())


class ParentDeathTest(unittest.TestCase):
    """A tool must not outlive an n64dk process killed outright (SIGKILL, the OOM killer)."""

    def _orphan_after_kill(self, mode: str, worker: bool = False) -> bool:
        import os
        import signal
        import subprocess
        import sys
        import tempfile
        import time
        folder = tempfile.mkdtemp(prefix="n64dk-pdeath-")
        self.addCleanup(__import__("shutil").rmtree, folder, True)
        pidfile = Path(folder) / "pid"
        script = (f"import os; os.environ['N64DK_PDEATHSIG'] = {mode!r}; os.environ['N64DK_PDEATHSIG_SCOPE'] = 'all'\n"
                  "from n64dk import safety\n"
                  f"safety.run_tool(['sh', '-c', 'echo $$ > {pidfile}.tmp; mv {pidfile}.tmp {pidfile}; exec sleep 30'],"
                  " timeout=60)\n") if not worker else (
                  f"import os, time; os.environ['N64DK_PDEATHSIG'] = {mode!r}\n"
                  "from n64dk import safety\n"
                  "pid = os.fork()\n"
                  "if pid == 0:\n"
                  "    safety.forked()\n"
                  f"    open('{pidfile}.tmp', 'w').write(str(os.getpid())); os.rename('{pidfile}.tmp', '{pidfile}')\n"
                  "    time.sleep(30); os._exit(0)\n"
                  "time.sleep(60)\n")
        environment = {**os.environ, "PYTHONPATH": str(ROOT.parent)}
        parent = subprocess.Popen([sys.executable, "-c", script], env=environment)
        deadline = time.monotonic() + 20
        while not pidfile.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(pidfile.exists(), "the tool never started")
        tool = int(pidfile.read_text())
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(tool, 0)
            except ProcessLookupError:
                return False
            time.sleep(0.05)
        os.kill(tool, signal.SIGKILL)                       # clean up what survived
        return True

    @unittest.skipUnless(__import__("sys").platform.startswith("linux"), "Linux parent-death signal")
    def test_tool_dies_with_its_killed_parent(self):
        from n64dk import safety
        modes = ["prctl"] + (["setpriv"] if __import__("os").access(safety.SETPRIV, __import__("os").X_OK) else [])
        for mode in modes:
            with self.subTest(mode=mode):
                self.assertFalse(self._orphan_after_kill(mode), f"{mode}: the tool outlived its parent")

    @unittest.skipUnless(__import__("sys").platform.startswith("linux"), "Linux parent-death signal")
    def test_forked_worker_stops_with_its_killed_parent(self):
        self.assertFalse(self._orphan_after_kill("setpriv", worker=True), "the worker outlived its parent")

    def test_only_long_lived_tools_are_guarded_by_default(self):
        import os
        from unittest import mock
        from n64dk import safety
        with mock.patch.dict(os.environ, {"N64DK_PDEATHSIG_SCOPE": "long"}):
            self.assertFalse(safety.guard_wanted(["/x/kmc/gcc", "-c"]))
            self.assertTrue(safety.guard_wanted(["/x/qemu-irix", "-L", "/r", "/r/cc"]))
            self.assertTrue(safety.guard_wanted(["/x/bin/m2c", "a.s"]))
            self.assertTrue(safety.guard_wanted(["cc"], legacy=True))
        with mock.patch.dict(os.environ, {"N64DK_PDEATHSIG_SCOPE": "all"}):
            self.assertTrue(safety.guard_wanted(["/x/kmc/gcc"]))

    @unittest.skipUnless(__import__("sys").platform.startswith("linux"), "Linux parent-death signal")
    def test_without_the_signal_the_tool_survives(self):
        """The control: proves the test above detects an orphan."""
        self.assertTrue(self._orphan_after_kill("off"))
