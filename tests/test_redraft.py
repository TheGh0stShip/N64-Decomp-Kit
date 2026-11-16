import types
import unittest

from n64dk.match import redraft


def _module(rows=None, error=None):
    def variants(source, name, **context):
        if error:
            raise error
        return rows(source, name, context) if callable(rows) else list(rows or [])
    return types.SimpleNamespace(variants=variants)


class RegistryTest(unittest.TestCase):
    CONTEXT = dict(code=b"\x03\xe0\x00\x08\x00\x00\x00\x00", vram=0x80001000, pipeline="ido5.3", flags=("-g",))

    def test_rewrites_are_labelled_and_the_unchanged_draft_is_not_repeated(self):
        found = redraft.variants("int f(void) { return 0; }", "f", generators=[
            _module([("same", "int f(void) { return 0; }"), ("one", "int f(void) { return 1; }"),
                     ("again", "int f(void) { return 1; }")])], **self.CONTEXT)
        self.assertEqual(found, [("one", "int f(void) { return 1; }")])

    def test_a_generator_sees_the_machine_code_and_the_recipe(self):
        seen = {}
        redraft.variants("x", "f", generators=[_module(lambda s, n, c: seen.update(c) or [])], **self.CONTEXT)
        self.assertEqual((seen["code"], seen["vram"], seen["pipeline"], seen["flags"]),
                         (self.CONTEXT["code"], 0x80001000, "ido5.3", ("-g",)))

    def test_a_failing_or_missing_generator_costs_nothing(self):
        found = redraft.variants("x", "f", generators=[_module(error=ValueError("no")), "no_such_module",
                                                       _module([("ok", "y")])], **self.CONTEXT)
        self.assertEqual(found, [("ok", "y")])

    def test_the_number_of_rewrites_per_generator_is_bounded(self):
        many = [(f"v{i}", f"text {i}") for i in range(40)]
        self.assertEqual(len(redraft.variants("x", "f", generators=[_module(many)], **self.CONTEXT)),
                         redraft.MAX_VARIANTS)

    def test_registered_modules_that_exist_can_be_imported(self):
        for module in redraft.GENERATORS:
            found = redraft._load(module)
            if found is not None:
                self.assertTrue(callable(found.variants), module)


if __name__ == "__main__":
    unittest.main()
