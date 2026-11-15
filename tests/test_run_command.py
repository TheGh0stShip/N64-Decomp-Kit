import shutil
import atexit
import argparse
import tempfile
import unittest
from pathlib import Path

from n64dk.commands import run


def _scratch(prefix: str = "n64dk-test-") -> str:
    """A scratch directory removed when the test process exits."""
    path = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, path, True)
    return path



class RunCommandTest(unittest.TestCase):
    def test_project_without_images_is_rejected_with_guidance(self):
        project = Path(_scratch())
        (project / "n64dk.toml").write_text("[toolchains]\nroot = \"/nonexistent\"\n")
        args = argparse.Namespace(project=str(project), out=_scratch(), image=[], all_images=True)
        with self.assertRaisesRegex(SystemExit, r"\[images\.<name>\]"):
            run.decompile_run(args)

    def test_settings_merge_defaults_and_per_image_overrides(self):
        project = Path(_scratch())
        (project / "n64dk.toml").write_text(
            '[run]\npipeline = "ido5.3"\nflags = "-O2"\n[run.images.overlay]\nflags = "-O1"\n'
            'recipes = { "m.tsv" = "ido7.1" }\n')
        self.assertEqual(run._settings(project, "main"), {"pipeline": "ido5.3", "flags": "-O2"})
        self.assertEqual(run._settings(project, "overlay"),
                         {"pipeline": "ido5.3", "flags": "-O1", "recipes": {"m.tsv": "ido7.1"}})

    def test_stage_results_are_checkpointed(self):
        folder = Path(_scratch())
        calls = []
        first, cached = run._stage(folder, "x", lambda: calls.append(1) or {"n": 1}, False)
        again, cached_again = run._stage(folder, "x", lambda: calls.append(1) or {"n": 2}, False)
        redo, _ = run._stage(folder, "x", lambda: calls.append(1) or {"n": 3}, True)
        self.assertEqual((first, cached, again, cached_again, redo, len(calls)),
                         ({"n": 1}, False, {"n": 1}, True, {"n": 3}, 2))

    def test_stage_checkpoint_is_invalidated_by_input_identity(self):
        folder = Path(_scratch())
        calls = []
        first, _ = run._stage(folder, "x", lambda: calls.append(1) or {"n": 1}, False, "image-a")
        cached, was_cached = run._stage(folder, "x", lambda: calls.append(2) or {"n": 2}, False, "image-a")
        changed, changed_cached = run._stage(folder, "x", lambda: calls.append(3) or {"n": 3}, False, "image-b")
        self.assertEqual((first, cached, was_cached, changed, changed_cached, calls),
                         ({"n": 1}, {"n": 1}, True, {"n": 3}, False, [1, 3]))

    def test_generated_state_inside_source_tree_is_rejected(self):
        project = Path(_scratch())
        (project / "n64dk.toml").write_text("[toolchains]\nroot='/none'\n")
        args = argparse.Namespace(project=str(project), out=str(project / "generated"), image=[], all_images=True,
                                  allow_project_output=False)
        with self.assertRaisesRegex(SystemExit, "source tree"):
            run.decompile_run(args)

    def test_report_markdown_lists_every_image_and_remaining_causes(self):
        report = {"project": "/p", "seconds": 1.5, "images": {"main": {
            "functions": 10, "donors": {"verified": [{"functions": ["a", "b"]}]},
            "resolve": {"statuses": {"exact": 3}, "exact_bytes": 64},
            "queue": {"exported": 3, "strict_exact": 3},
            "hard_queue": [{"cause": "type.width", "functions": 2, "bytes": 80}],
            "ledger": {"error": "boom"}}}}
        text = run._markdown(report)
        self.assertIn("## main", text)
        self.assertIn("recovered from donors (verified): 2", text)
        self.assertIn("| type.width | 2 | 80 |", text)
        self.assertIn("stages with errors: ['ledger']", text)


class RegistrationTest(unittest.TestCase):
    """The command line must reach ``decompile_run`` with every option it documents."""

    def test_command_is_registered_with_its_options(self):
        import contextlib
        import io
        from n64dk import cli
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit) as stop:
            cli.main(["decompile-run", "--help"])
        self.assertEqual(stop.exception.code, 0)
        text = buffer.getvalue()
        for option in ("--project", "--out", "--donors", "--workers", "--search-ceiling", "--refine-command",
                       "--refine-rounds", "--max-size", "--budget"):
            self.assertIn(option, text)

    def test_resolve_hard_documents_the_refine_and_padding_options(self):
        import contextlib
        import io
        from n64dk import cli
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), self.assertRaises(SystemExit):
            cli.main(["resolve-hard", "--help"])
        for option in ("--refine-command", "--refine-names", "--keep-padding", "--workers", "--search-ceiling"):
            self.assertIn(option, buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
