import struct
import unittest

from n64dk.commands import flowcmd

BASE = 0x80001000
# first: falls through (no return); second: a framed leaf; third: starts after a returning function
WORDS = [0x24020001, 0x24030002,                                     # first: li v0,1 ; li v1,2   (no terminator)
         0x27BDFFE8, 0xAFBF0014, 0x8FBF0014, 0x03E00008, 0x27BD0018,   # second
         0x03E00008, 0x24020003]                                      # third: jr ra ; li v0,3
DATA = struct.pack(f">{len(WORDS)}I", *WORDS)
FUNCTIONS = [("first", BASE, 8), ("second", BASE + 8, 20), ("third", BASE + 28, 8)]
STARTS = {vram for _n, vram, _s in FUNCTIONS}


class OneEntryTest(unittest.TestCase):
    def one(self, wanted):
        return flowcmd._one_entry(wanted, FUNCTIONS, STARTS, DATA, BASE)

    def test_name_hex_and_decimal_select_the_same_function(self):
        for wanted in ("third", hex(BASE + 28), str(BASE + 28)):
            found = self.one(wanted)
            self.assertEqual((found["name"], found["vram"], found["size"]), ("third", f"0x{BASE + 28:08X}", "0x8"))
            self.assertFalse(found["predecessor_fallthrough"])
            self.assertEqual(found["predecessor"], "second")

    def test_predecessor_that_does_not_return_is_reported(self):
        found = self.one("second")
        self.assertTrue(found["predecessor_fallthrough"])
        self.assertFalse(found["strict_entry"])
        self.assertEqual(found["frame_size"], 0x18)

    def test_unknown_function_is_an_error_not_a_summary(self):
        with self.assertRaises(SystemExit):
            self.one("nosuch")


if __name__ == "__main__":
    unittest.main()
