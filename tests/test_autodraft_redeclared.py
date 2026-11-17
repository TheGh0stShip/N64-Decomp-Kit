"""A draft's own guesses for declared names are dropped; its statements never are."""
import unittest

from n64dk.match import autodraft


class DropRedeclaredTest(unittest.TestCase):
    def test_call_statements_survive_and_guesses_go(self):
        draft = ("extern s32 D_8032D584;\nvoid func_8032171C(void);\ns32 helper(s32 *, s32);\n\n"
                 "void handle(void) {\n    D_8032D584 = 1;\n    func_8032171C();\n    helper(&x, 2);\n}\n")
        declarations = "extern s32 D_8032D584;\nvoid func_8032171C(void);\ns32 helper(s32 *p, s32 n);\n"
        kept = autodraft.drop_redeclared(draft, declarations)
        self.assertNotIn("extern s32 D_8032D584;", kept)
        self.assertNotIn("void func_8032171C(void);", kept)
        self.assertNotIn("s32 helper(s32 *, s32);", kept)
        self.assertIn("    func_8032171C();", kept)       # dropped before the fix
        self.assertIn("    helper(&x, 2);", kept)
        self.assertIn("    D_8032D584 = 1;", kept)

    def test_pointer_and_array_declarations(self):
        kept = autodraft.drop_redeclared("extern u8 *gPtr;\nextern s16 gTable[4];\nstatic int keep;\n",
                                         "extern u8 *gPtr;\nextern s16 gTable[];\n")
        self.assertEqual(kept.strip(), "static int keep;")


if __name__ == "__main__":
    unittest.main()
