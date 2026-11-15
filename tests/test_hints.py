import unittest

from n64dk.match.hints import hints


def entry(kind, compiled, retail, off=0):
    return {"kind": kind, "offset": off, "target_offset": off, "compiled": compiled, "retail": retail}


class HintsTest(unittest.TestCase):
    def test_signedness_and_frame(self):
        rows = hints({"counts": {"instruction": 2}, "entries": [
            entry("instruction", "lh $v0, 0x4($a0)", "lhu $v0, 0x4($a0)", 8),
            entry("immediate", "addiu $sp, $sp, -0x18", "addiu $sp, $sp, -0x20", 0)]})
        self.assertEqual({r["hint"] for r in rows}, {"u16-load", "frame-too-small"})

    def test_missing_s16_cast(self):
        rows = hints({"counts": {"instruction": 2}, "entries": [
            entry("instruction", "", "sll $v0, $v0, 16", 4), entry("instruction", "", "sra $v0, $v0, 16", 8)]})
        self.assertEqual(rows[0]["hint"], "add-s16-cast")

    def test_register_only_is_family_specific(self):
        report = {"counts": {"register": 4}, "register_swap": {"$s0": "$s1", "$s1": "$s0"}, "entries": [
            entry("register", "addu $s0, $a0, $zero", "addu $s1, $a0, $zero")]}
        self.assertEqual([r["hint"] for r in hints(report, "gcc")], ["regalloc-saved-gcc"])
        self.assertEqual([r["hint"] for r in hints(report, "ido")], ["regalloc-saved-ido"])


if __name__ == "__main__":
    unittest.main()
