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
