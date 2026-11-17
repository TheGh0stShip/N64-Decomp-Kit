"""Object-cache identity is dependency-exact: it follows the headers a unit reaches and nothing
else in the include directories, and it follows the toolchain's bytes."""
import tempfile
import unittest
from pathlib import Path

from n64dk.match.pipeline import _compiler_digest, dependency_digest, split_flags
from n64dk.match.toolchain import load_config


class DependencyIdentityTest(unittest.TestCase):
    def setUp(self):
        self.project = Path(tempfile.mkdtemp(prefix="n64dk-test-cache-"))
        (self.project / "include").mkdir()
        (self.project / "include" / "used.h").write_text("#define A 1\n#include \"nested.h\"\n")
        (self.project / "include" / "nested.h").write_text("typedef int s32;\n")
        (self.project / "include" / "unused.h").write_text("#define B 2\n")
        (self.project / "include" / "macro_target.h").write_text("#define C 3\n")
        self.source = self.project / "unit.c"
        self.source.write_text('#include "used.h"\n#define HDR "macro_target.h"\n#include HDR\nint f(void) { return A; }\n')
        self.cfg = load_config(self.project, None, None)
        self.spec = split_flags(["-O2", "-Iinclude"], "kmc+as")

    def digest(self):
        return dependency_digest(self.source, self.spec, self.cfg, includes=[])

    def test_unrelated_files_do_not_invalidate(self):
        before = self.digest()
        (self.project / "include" / "unused.h").write_text("#define B 3\n")
        (self.project / "include" / "new_file.h").write_text("int x;\n")
        (self.project / "notes.txt").write_text("anything")
        self.assertEqual(before, self.digest())

    def test_reached_headers_invalidate(self):
        for name in ("used.h", "nested.h"):
            before = self.digest()
            path = self.project / "include" / name
            path.write_text(path.read_text() + "/* changed */\n")
            self.assertNotEqual(before, self.digest(), name)

    def test_macro_include_target_is_tracked(self):
        before = self.digest()
        (self.project / "include" / "macro_target.h").write_text("#define C 4\n")
        self.assertNotEqual(before, self.digest())


class ToolchainIdentityTest(unittest.TestCase):
    def test_compiler_bytes_change_the_identity(self):
        root = Path(tempfile.mkdtemp(prefix="n64dk-test-tools-"))
        tools = root / "kmc-gcc-2.7.2"
        tools.mkdir()
        from n64dk.match.toolchain import PROFILES
        for name in PROFILES["kmc"].required:
            (tools / name).parent.mkdir(parents=True, exist_ok=True)
            (tools / name).write_bytes(b"tool " + name.encode())
        project = Path(tempfile.mkdtemp(prefix="n64dk-test-cache-"))
        cfg = load_config(project, None, str(root))
        if cfg.toolchain("kmc") is None:
            self.skipTest("toolchain layout differs")
        before = _compiler_digest(cfg, "kmc+as")
        first = PROFILES["kmc"].required[0]
        (tools / first).write_bytes(b"other bytes")
        self.assertNotEqual(before, _compiler_digest(cfg, "kmc+as"))


if __name__ == "__main__":
    unittest.main()


class ToolDigestCacheTest(unittest.TestCase):
    def test_a_changed_tool_changes_its_digest(self):
        import os
        import tempfile
        from pathlib import Path
        from n64dk.match import pipeline
        tool = Path(tempfile.mkdtemp(prefix="n64dk-test-tool-")) / "cc1"
        tool.write_bytes(b"one")
        first = pipeline._file_digest(tool)
        self.assertEqual(pipeline._file_digest(tool), first)          # cached
        tool.write_bytes(b"two")
        os.utime(tool, ns=(1, 1))                                      # even with an old mtime
        self.assertNotEqual(pipeline._file_digest(tool), first)
