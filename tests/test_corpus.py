from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from n64dk.match.corpus import CorpusIndex, assembly_signature, assembly_units


class CorpusTests(unittest.TestCase):
    def test_multi_function_assembly_units(self):
        text = ".ent first\nfirst:\n jr $ra\n nop\n.end first\n.ent second\nsecond:\n jr $ra\n nop\n.end second\n"
        units = assembly_units(text, "file")
        self.assertEqual([name for name, _body in units], ["first", "second"])

    def test_signatures_distinguish_registers_from_opcode_shape(self):
        first = assembly_signature("""
.ent one
one:
  addiu $sp, $sp, -0x10
  addu $v0, $a0, $a1
  jr $ra
  nop
.end one
""")
        renamed = assembly_signature("""
  addiu $sp, $sp, -0x20
  addu $v1, $a1, $a2
  jr $ra
  nop
""")
        self.assertNotEqual(first["text_hash"], renamed["text_hash"])
        self.assertEqual(first["register_neutral_hash"], renamed["register_neutral_hash"])
        self.assertEqual(first["opcode_hash"], renamed["opcode_hash"])

    def test_incremental_index_and_query(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "game"
            source = root / "asm/func_80001000.s"
            source.parent.mkdir(parents=True)
            source.write_text(""".ent func_80001000
func_80001000:
  addu $v0, $a0, $a1
  jr $ra
  nop
.end func_80001000
""")
            index = CorpusIndex(Path(name) / "corpus.sqlite")
            try:
                first = index.index([root])
                second = index.index([root])
                matches = index.query(assembly_signature(source.read_text()))
            finally:
                index.close()
            self.assertEqual(first["indexed"], 1)
            self.assertEqual(second["changed"], 0)
            self.assertEqual(matches[0]["match"], "textual-exact")
            self.assertEqual(matches[0]["name"], "func_80001000")


if __name__ == "__main__":
    unittest.main()
