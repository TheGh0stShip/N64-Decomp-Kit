"""The toolchain component graph: every recipe stage names a known component, identities are
stable and change with a component's bytes, and two lanes' shared stages are reported."""
import tempfile
import unittest
from pathlib import Path

from n64dk.match import components


class CatalogueTest(unittest.TestCase):
    def test_every_entry_is_classified(self):
        for component in components.COMPONENTS:
            self.assertIn(component.role, components.ROLES, component.ident)
            self.assertIn(component.provenance, components.PROVENANCE, component.ident)
            self.assertIn(component.disposition, components.DISPOSITIONS, component.ident)
        self.assertEqual(len({c.ident for c in components.COMPONENTS}), len(components.COMPONENTS))

    def test_cross_platform_relatives_are_never_n64_lanes(self):
        lanes_components = {stage.component for recipe in components.RECIPES.values() for stage in recipe.stages}
        for component in components.COMPONENTS:
            if component.provenance in ("comparative", "speculation"):
                self.assertNotIn(component.ident, lanes_components)
                self.assertIn(component.disposition, ("comparative-only", "undistributable-local", "speculation"))

    def test_every_recipe_stage_names_a_component(self):
        for lane, recipe in components.RECIPES.items():
            for stage in recipe.stages:
                self.assertTrue(stage.component in components.BY_ID or stage.component in components.HOST_COMPONENTS,
                                f"{lane}: {stage.component}")


class IdentityTest(unittest.TestCase):
    def test_identity_follows_the_component_bytes(self):
        root = Path(tempfile.mkdtemp(prefix="n64dk-test-components-"))
        (root / "kmc-gcc-2.7.2").mkdir()
        for name in ("gcc", "cpp", "cccp", "cc1", "as"):
            (root / "kmc-gcc-2.7.2" / name).write_bytes(b"\x7fELF" + name.encode())
        first = components.recipe_identity(components.RECIPES["kmc+as"], root)
        again = components.recipe_identity(components.RECIPES["kmc+as"], root)
        self.assertEqual(first["identity"], again["identity"])
        self.assertTrue(first["runnable"])
        (root / "kmc-gcc-2.7.2" / "as").write_bytes(b"\x7fELF other assembler")
        changed = components.recipe_identity(components.RECIPES["kmc+as"], root)
        self.assertNotEqual(first["identity"], changed["identity"])
        self.assertNotEqual(first["identity"],
                            components.recipe_identity(components.RECIPES["kmc+as"], root, ["-O1"])["identity"])

    def test_lanes_that_share_a_compiler_differ_only_in_the_assembler(self):
        found = components.shared_stages("kmc+as", "kmc+asn64")
        self.assertIn("compile", found["same"])
        self.assertEqual({row["stage"] for row in found["different"]}, {"assemble", "convert"})


if __name__ == "__main__":
    unittest.main()


class ProbeAnalysisTest(unittest.TestCase):
    def test_classes_attribution_and_line_layout(self):
        from n64dk.match import probes
        table = {
            "kmc+as -O2": {"a": "x:8", "b": "y:8", "lines_one": "l:8", "lines_many": "l:8"},
            "kmc+asn64 -O2": {"a": "x:8", "b": "z:8", "lines_one": "l:8", "lines_many": "l:8"},
            "ido5.3 -g": {"a": "q:8", "b": "r:8", "lines_one": "m:8", "lines_many": "n:8"},
            "ido7.1 -g": {"a": "q:8", "b": "r:8", "lines_one": "m:8", "lines_many": "n:8"},
        }
        found = probes.analyse(table)
        self.assertEqual(found["distinct_recipes"], 3)
        self.assertIn(["ido5.3 -g", "ido7.1 -g"], found["equivalence_classes"])
        attribution = next(row for row in found["stage_attribution"] if row["recipes"] == ["kmc+as -O2", "kmc+asn64 -O2"])
        self.assertEqual(attribution["probes"], ["b"])
        self.assertIn("assemble", attribution["differing_stages"])
        self.assertTrue(found["line_layout_changes_code"]["ido5.3 -g"])
        self.assertFalse(found["line_layout_changes_code"]["kmc+as -O2"])

    def test_every_probe_defines_the_function(self):
        from n64dk.match import probes
        for name in probes.PROBES:
            self.assertIn("probe(", probes.probe_source(name), name)
        import re
        tokens = lambda text: re.findall(r"\w+|[^\s\w]", text)      # noqa: E731
        self.assertEqual(tokens(probes.PROBES["lines_one"][1]), tokens(probes.PROBES["lines_many"][1]))


class ProbeFlagTest(unittest.TestCase):
    def test_ido_probes_use_the_retail_fixed_flags(self):
        """Regression: the first probe run built IDO without -non_shared (PIC code), so no SM64
        function could be reproduced by any IDO candidate."""
        from n64dk.match import engine, probes
        for lane in ("ido5.3", "ido7.1"):
            for flags in probes.FLAG_SETS[lane]:
                for fixed in engine.IDO_FIXED:
                    self.assertIn(fixed, flags, (lane, flags))
