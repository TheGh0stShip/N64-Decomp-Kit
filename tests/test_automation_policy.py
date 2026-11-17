import argparse
import unittest

from n64dk.commands.resolve import resolve_hard
from n64dk.commands.run import decompile_run


class AutomationPolicyTests(unittest.TestCase):
    def test_rejected_recipe_guesses_are_opt_in(self):
        parser = argparse.ArgumentParser()
        resolve_hard.arguments(parser)
        args = parser.parse_args(["--rom", "image.bin", "--catalogue", "functions.toml"])
        self.assertFalse(args.region_recipes)
        self.assertFalse(args.unit_recipes)
        self.assertFalse(args.skip_unknown_search)
        self.assertFalse(args.search_economics)

    def test_decompile_run_experiments_are_opt_in(self):
        parser = argparse.ArgumentParser()
        decompile_run.arguments(parser)
        args = parser.parse_args(["--project", "project", "--out", "run", "--all-images"])
        self.assertFalse(args.region_recipes)
        self.assertFalse(args.unit_recipes)
        self.assertFalse(args.skip_unknown_search)
        self.assertFalse(args.search_economics)
        self.assertEqual(args.refine_known_source, [])

    def test_experiments_can_be_enabled_explicitly(self):
        parser = argparse.ArgumentParser()
        decompile_run.arguments(parser)
        args = parser.parse_args(["--project", "project", "--out", "run", "--all-images",
                                  "--region-recipes", "--unit-recipes", "--skip-unknown-search"])
        self.assertTrue(args.region_recipes)
        self.assertTrue(args.unit_recipes)
        self.assertTrue(args.skip_unknown_search)


if __name__ == "__main__":
    unittest.main()
