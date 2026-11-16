import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from n64dk.match import pipeline
from n64dk.match.pipeline import BuildError, BuildSpec, absolute_flags, include_closure_digest
from n64dk.match.toolchain import Config


class PipelineHardeningTests(unittest.TestCase):
    def test_absolute_flags_preserve_i_dash(self):
        self.assertEqual(
            absolute_flags(["-Iinclude", "-I", "inc2", "-isystem", "sys", "-iquoteq",
                            "-idirafter", "/abs", "-I-", "-O2"], Path("/proj")),
            ["-I/proj/include", "-I", "/proj/inc2", "-isystem", "/proj/sys",
             "-iquote/proj/q", "-idirafter", "/abs", "-I-", "-O2"])

    def test_timeout_kills_the_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "pid"
            started = time.monotonic()
            with self.assertRaisesRegex(BuildError, "timed out"):
                pipeline._run(["sh", "-c", f"sleep 30 & echo $! > {marker}; wait"], tmp, timeout=0.2)
            self.assertLess(time.monotonic() - started, 5)
            child = int(marker.read_text())
            time.sleep(0.1)
            try:
                state = Path(f"/proc/{child}/stat").read_text().split()[2]
                alive = state != "Z"
            except (FileNotFoundError, ProcessLookupError):
                alive = False
            self.assertFalse(alive)

    def test_timeout_configuration_can_be_disabled(self):
        cfg = Config(project=Path("."))
        cfg.tool_timeout = 7
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("N64DK_TOOL_TIMEOUT", None)
            self.assertEqual(pipeline.tool_timeout(cfg), 7.0)
        with mock.patch.dict(os.environ, {"N64DK_TOOL_TIMEOUT": "0"}):
            self.assertIsNone(pipeline.tool_timeout(cfg))

    def test_dependency_identity_ignores_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "inc").mkdir()
            header = root / "inc" / "v.h"
            header.write_text("#define V 1\n")
            source = root / "a.c"
            source.write_text('#include "v.h"\nint f(void) { return V; }\n')
            cfg = Config(project=root, include=[root / "inc"])
            spec = BuildSpec("kmc+builtin", [])
            first = include_closure_digest(source, spec, cfg)
            (root / "inc" / "unrelated.h").write_text("#define X 1\n")
            self.assertEqual(first, include_closure_digest(source, spec, cfg))
            header.write_text("#define V 2\n")
            self.assertNotEqual(first, include_closure_digest(source, spec, cfg))


if __name__ == "__main__":
    unittest.main()
