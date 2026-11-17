"""The m2c fork server (n64dk.match.m2c_server): identical drafts, timeouts, bounded pool, no
process left behind.  Skipped when m2c is not importable."""
import importlib.util
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from n64dk.match import m2c_bridge, m2c_server

CODE = bytes.fromhex("00801021" "03E00008" "00000000")          # addu v0,a0,zero; jr ra; nop
HAVE_M2C = importlib.util.find_spec("m2c") is not None and m2c_bridge.locate_m2c().command is not None


def _alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().split(")")[-1].split()[0] != "Z"
    except OSError:
        return False


@unittest.skipUnless(HAVE_M2C and sys.platform.startswith("linux"), "m2c not importable, or not Linux")
class M2cServerTest(unittest.TestCase):
    def setUp(self):
        m2c_server.shutdown()             # servers left idle by earlier tests' drafts (the server is on by default)
        m2c_server._DISABLED["pid"] = None
        self.addCleanup(m2c_server.shutdown)
        self.addCleanup(m2c_server._DISABLED.update, {"pid": None})
        patcher = mock.patch.dict(os.environ, {m2c_server.ENV: "1"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _draft(self, server: bool):
        with mock.patch.dict(os.environ, {m2c_server.ENV: "1" if server else "0"}):
            return m2c_bridge.draft("f", CODE, 0x80000000, "kmc")

    def test_drafts_are_identical_to_the_command_line(self):
        if not m2c_server.wanted(m2c_bridge.locate_m2c().command):
            self.skipTest("the located m2c is not this interpreter's")
        served, plain = self._draft(True), self._draft(False)
        self.assertEqual((served["status"], served["source"], served["returncode"]),
                         (plain["status"], plain["source"], plain["returncode"]))
        self.assertEqual(served["status"], "ok")
        self.assertEqual(m2c_server.running(), 1)

    def test_timeout_kills_the_draft(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = os.path.join(tmp, "input.s")
            with open(source, "w") as handle:
                handle.write("glabel f\n/* 0 80000000 03E00008 */ jr $ra\n/* 4 80000004 00000000 */ nop\n")
            with self.assertRaises(subprocess.TimeoutExpired):
                m2c_server.run(["-t", "mips-gcc-c", source], tmp, 0.0)
            done = m2c_server.run(["-t", "mips-gcc-c", source], tmp, 30)      # the server is still usable
            self.assertEqual(done.returncode, 0)
            self.assertEqual(sorted(os.listdir(tmp)), ["input.s"])            # nothing left in the folder

    def test_pool_is_bounded(self):
        seen, errors = [], []

        def work():
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    path = os.path.join(tmp, "input.s")
                    with open(path, "w") as handle:
                        handle.write("glabel f\n/* 0 80000000 03E00008 */ jr $ra\n/* 4 80000004 00000000 */ nop\n")
                    for _ in range(3):
                        m2c_server.run(["-t", "mips-gcc-c", path], tmp, 30)
                        seen.append(m2c_server.running())
            except Exception as error:                                       # noqa: BLE001
                errors.append(error)
        with mock.patch.dict(os.environ, {"N64DK_M2C_SERVERS": "2"}):
            threads = [threading.Thread(target=work) for _ in range(5)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(len(seen), 15)
        self.assertLessEqual(max(seen), 2)

    def test_shutdown_leaves_nothing_running(self):
        self._draft(True)
        pids = [server.process.pid for server in m2c_server._POOL["idle"]]
        self.assertTrue(pids)
        m2c_server.shutdown()
        self.assertEqual(m2c_server.running(), 0)
        self.assertFalse(any(_alive(pid) for pid in pids))

    def test_server_dies_with_its_parent(self):
        script = ("import os, sys; os.environ['N64DK_M2C_SERVER'] = '1'\n"
                  "from n64dk.match import m2c_server\n"
                  "server = m2c_server._acquire(); print(server.process.pid, flush=True)\n"
                  "import time; time.sleep(60)\n")
        parent = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True,
                                  env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)})
        try:
            pid = int(parent.stdout.readline())
            self.assertTrue(_alive(pid))
            parent.send_signal(signal.SIGKILL)
            parent.wait(10)
            deadline = time.monotonic() + 10
            while _alive(pid) and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertFalse(_alive(pid))
        finally:
            if parent.poll() is None:
                parent.kill()
            parent.stdout.close()

    def test_a_broken_server_falls_back_to_the_command_line(self):
        with mock.patch.object(m2c_server, "_acquire", side_effect=RuntimeError("no")):
            served = self._draft(True)
        self.assertEqual(served["status"], "ok")
        self.assertEqual(m2c_server._DISABLED["pid"], os.getpid())


if __name__ == "__main__":
    unittest.main()
