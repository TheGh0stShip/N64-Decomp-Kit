import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from n64dk import fixtures


def git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env).stdout


@unittest.skipUnless(subprocess.run(["git", "--version"], capture_output=True).returncode == 0, "git not available")
class PinnedTruthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.repo = base / "project"
        (self.repo / "config").mkdir(parents=True)
        git(self.repo, "init", "-q")
        (self.repo / "config/units.tsv").write_text("v1\n")
        (self.repo / ".gitignore").write_text(".toolchain/\n*.inc\n__pycache__/\n")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-q", "-m", "one")
        self.rev = git(self.repo, "rev-parse", "HEAD").decode().strip()
        # later: uncommitted edits, work in progress, and ignored environment files
        (self.repo / "config/units.tsv").write_text("v2 (being edited)\n")
        (self.repo / "config/new_unit.c").write_text("wip\n")
        (self.repo / ".toolchain").mkdir()
        (self.repo / ".toolchain/cc").write_text("compiler\n")
        (self.repo / "config/macro.inc").write_text("generated\n")
        (self.repo / "config/__pycache__").mkdir()
        patcher = mock.patch.object(fixtures, "SNAPSHOTS", base / "snapshots")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def env(self, **kw):
        return mock.patch.dict(os.environ, {f"N64DK_TRUTH_DEMO{k}": v for k, v in kw.items()})

    def test_unpinned_is_live(self):
        with self.env(**{"": str(self.repo)}):
            root = fixtures.truth("demo")
        self.assertEqual(root, self.repo)
        self.assertEqual((root / "config/units.tsv").read_text(), "v2 (being edited)\n")

    def test_pinned_snapshot(self):
        with self.env(**{"": str(self.repo), "_REV": self.rev[:7]}):
            root = fixtures.truth("demo")
            again = fixtures.truth("demo")
        self.assertEqual(root, again)
        self.assertNotEqual(root, self.repo)
        self.assertEqual((root / "config/units.tsv").read_text(), "v1\n")
        # ignored files are linked live, at any depth; work in progress and caches are not
        self.assertTrue((root / ".toolchain").is_symlink())
        self.assertEqual((root / ".toolchain/cc").read_text(), "compiler\n")
        self.assertEqual((root / "config/macro.inc").read_text(), "generated\n")
        self.assertFalse((root / "config/new_unit.c").exists())
        self.assertFalse((root / "config/__pycache__").exists())
        self.assertFalse((root / ".git").exists())
        # the project itself is untouched
        self.assertEqual((self.repo / "config/units.tsv").read_text(), "v2 (being edited)\n")

    def test_pinned_subpath_and_untracked(self):
        with self.env(**{"": str(self.repo / "config/units.tsv"), "_REV": self.rev}):
            self.assertEqual(fixtures.truth("demo").read_text(), "v1\n")
        with self.env(**{"": str(self.repo / ".toolchain"), "_REV": self.rev}):
            with self.assertRaises(ValueError):
                fixtures.truth("demo")


if __name__ == "__main__":
    unittest.main()
