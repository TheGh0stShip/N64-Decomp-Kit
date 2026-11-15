import shutil
import atexit
import tempfile
import unittest
from pathlib import Path

from n64dk.analysis import catalogue


def _scratch(prefix: str = "n64dk-test-") -> str:
    """A scratch directory removed when the test process exits."""
    path = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, path, True)
    return path



def write(name: str, text: str) -> Path:
    path = Path(_scratch()) / name
    path.write_text(text)
    return path


class CatalogueTest(unittest.TestCase):
    def test_commented_header_table(self):
        path = write("functions.tsv", "# Audited bodies\n# ROM_START\tSIZE\tVRAM\tNAME\tEVIDENCE\n"
                                      "0x1000\t0x40\t0x80000400\tfunc_80000400\tretail\n"
                                      "0x1060\t0x3F8\t0x80000460\tboot_main\tretail\n")
        self.assertEqual(catalogue.load(path), [("func_80000400", 0x80000400, 0x40), ("boot_main", 0x80000460, 0x3F8)])

    def test_rom_only_table_needs_a_delta_and_types_filter(self):
        path = write("f.csv", "offset,length,symbol,type\n0x1000,16,alpha,func\n0x1010,8,table,data\n0x1018,8,,\n")
        self.assertEqual(catalogue.load(path), [])
        self.assertEqual(catalogue.load(path, vram_delta=0x7FFFF400),
                         [("alpha", 0x80000400, 16), ("func_80000418", 0x80000418, 8)])

    def test_symbol_addrs_still_load(self):
        path = write("symbol_addrs.txt", "alpha = 0x80000400; // type:func size:0x10\n")
        self.assertEqual(catalogue.load(path), [("alpha", 0x80000400, 0x10)])


if __name__ == "__main__":
    unittest.main()
