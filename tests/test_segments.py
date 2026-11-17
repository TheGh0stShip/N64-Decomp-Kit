import struct
import unittest

from n64dk.analysis import segments

BASE = 0x80300000


def function(index: int, callee_address: int | None) -> list[int]:
    """A small framed function that optionally calls ``callee_address``."""
    words = [0x27BDFFE8, 0xAFBF0014]                                   # addiu sp,-0x18 ; sw ra,0x14(sp)
    if callee_address is not None:
        words += [0x0C000000 | ((callee_address & 0x0FFFFFFF) >> 2), 0x00000000]   # jal ; nop
    words += [0x24020000 | index, 0x8FBF0014, 0x03E00008, 0x27BD0018]   # li v0 ; lw ra ; jr ra ; addiu sp
    return words


def segment(base: int, count: int = 24, external: int | None = None, salt: int = 0) -> bytes:
    """``count`` functions of irregular sizes (real code is not a lattice); every one calls another
    function of the segment, or ``external``."""
    sizes = [8 + (((index + 1 + 977 * salt) * 2654435761) >> 11) % 53 for index in range(count)]   # no period          # in words
    starts = [4 * sum(sizes[:index]) for index in range(count)]
    words = []
    for index in range(count):
        callee = base + starts[(index * 7 + 3) % count] if external is None else external
        body = function(index, callee)
        words += body + [0x00000000] * (sizes[index] - len(body))
    return struct.pack(f">{len(words)}I", *words) + bytes(0x400)        # data after the text


class SolveTest(unittest.TestCase):
    def test_load_address_is_where_the_internal_calls_land(self):
        found = segments.solve(segment(BASE), [(0x80000400, 0x80100000)])
        self.assertEqual(found.vram, BASE)
        self.assertGreaterEqual(found.votes, 20)
        self.assertGreater(found.votes, 2 * found.runner_up)
        self.assertEqual(found.prologues, 24)

    def test_address_does_not_depend_on_where_the_range_sits_in_the_rom(self):
        self.assertEqual(segments.solve(segment(0x80412340), []).vram, 0x80412340)

    def test_data_is_not_code(self):
        self.assertIn("not code", segments.solve(bytes(range(256)) * 32, []).reason)
        self.assertIsNone(segments.solve(bytes(0x4000), []).vram)

    def test_small_ranges_are_left_alone(self):
        self.assertIn("too small", segments.solve(segment(BASE, 4)[:0x100], []).reason)

    def test_calls_into_known_segments_do_not_place_it(self):
        found = segments.solve(segment(BASE, external=0x80001000), [(0x80000400, 0x80100000)])
        self.assertIsNone(found.vram)
        self.assertIn("too few calls outside the known segments", found.reason)

    def test_overlay_sharing_addresses_is_flagged(self):
        found = segments.solve(segment(BASE), [(BASE - 0x1000, BASE + 0x100)])
        self.assertEqual(found.vram, BASE)                               # the calls outside the shared part still agree
        self.assertTrue(any("overlay sharing addresses" in line for line in found.evidence))

    def test_range_whose_calls_all_fall_in_a_known_segment_is_not_placed(self):
        found = segments.solve(segment(BASE), [(BASE - 0x1000, BASE + 0x10000)])
        self.assertIsNone(found.vram)


class DiscoverTest(unittest.TestCase):
    class Item:
        def __init__(self, start, end, category="loader_range", kind="raw"):
            self.start, self.end, self.category, self.kind = start, end, category, kind

    def test_adjacent_raw_ranges_are_joined_and_placed(self):
        code = segment(BASE)
        rom = bytes(0x2000) + code + bytes(0x1000)
        half = 0x2000 + len(code) // 2
        ledger = [self.Item(0x2000, half), self.Item(half, 0x2000 + len(code)),
                  self.Item(0x100, 0x180), self.Item(0x400, 0x1400, kind="mio0")]
        self.assertEqual(segments.raw_ranges(ledger), [(0x2000, 0x2000 + len(code))])
        [found] = segments.discover(rom, ledger, [(0x80000400, 0x80100000)])
        self.assertEqual((found.rom_start, found.vram), (0x2000, BASE))
        self.assertEqual(found.as_dict()["vram"], "0x80300000")


if __name__ == "__main__":
    unittest.main()


def rom_with(pieces: dict[int, bytes], size: int = 0x40000) -> bytes:
    """A ROM of non-code filler with ``pieces`` at their offsets."""
    rom = bytearray((bytes(range(1, 256)) * (size // 255 + 1))[:size])
    for offset, data in pieces.items():
        rom[offset:offset + len(data)] = data
    return bytes(rom)


class CompressedTest(unittest.TestCase):
    def test_code_inside_a_zlib_stream_is_unpacked_and_placed(self):
        import zlib
        plain = segment(BASE, 60)
        rom = rom_with({0x3000: zlib.compress(plain, 9)})
        found = [c for c in segments.discover_compressed(rom, [(0x80000400, 0x80100000)]) if c.vram is not None]
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].vram, found[0].rom_start, found[0].codec, found[0].data), (BASE, 0x3000, "zlib", plain))
        self.assertEqual(found[0].size, len(plain))

    def test_a_compressed_asset_is_not_a_segment(self):
        import zlib
        rom = rom_with({0x3000: zlib.compress(bytes(range(256)) * 64, 9)})
        self.assertEqual(segments.discover_compressed(rom, []), [])


class RegionTest(unittest.TestCase):
    def text(self, base, count=90):
        return segment(base, count)[:-0x400]

    def test_code_nothing_points_at_is_found_and_placed(self):
        code = self.text(0x80234560)
        found = segments.discover_regions(rom_with({0x8040: code}), [(0x80000400, 0x80100000)])
        self.assertEqual(len(found), 1)
        self.assertEqual((found[0].rom_start, found[0].vram, found[0].by_density), (0x8040, 0x80234560, True))
        self.assertGreater(found[0].rom_end, 0x8040 + len(code) - 0x100)

    def test_two_overlays_sharing_addresses_get_their_own_distances(self):
        first, second = self.text(0x80300000), segment(0x80300000, 96, salt=5)[:-0x400]
        found = segments.discover_regions(rom_with({0x8000: first, 0x20000: second}), [])
        self.assertEqual([(c.rom_start, c.vram) for c in found], [(0x8000, 0x80300000), (0x20000, 0x80300000)])

    def test_ranges_already_placed_are_not_scanned(self):
        rom = rom_with({0x8040: self.text(0x80234560)})
        self.assertEqual(segments.discover_regions(rom, [], [(0x8000, 0x10000)]), [])

    def test_code_whose_calls_all_leave_is_reported_unplaced(self):
        code = segment(BASE, 90, external=0x80001000)[:-0x400]
        found = segments.discover_regions(rom_with({0x8040: code}), [(0x80000400, 0x80100000)])
        self.assertEqual([c.vram for c in found], [None])
        self.assertIn("no load address", found[0].reason)


class NeighbouringProgramsTest(unittest.TestCase):
    def test_two_programs_back_to_back_are_cut_where_the_called_functions_switch(self):
        first, second = segment(0x80300000, 90)[:-0x400], segment(0x80300000, 96, salt=5)[:-0x400]
        rom = rom_with({0x8000: first + second})
        found = sorted(segments.discover_regions(rom, []), key=lambda c: c.rom_start)
        self.assertEqual([(c.rom_start, c.vram) for c in found],
                         [(0x8000, 0x80300000), (0x8000 + len(first), 0x80300000)])

    def test_a_small_foreign_program_in_front_is_not_given_the_large_ones_address(self):
        # eight functions of another program whose calls, read at the large program's distance, fall
        # inside it but not on a function start
        small, large = segment(0x80300000, 8, external=0x80300010)[:-0x400], segment(0x80300000, 90)[:-0x400]
        rom = rom_with({0x8000: small + large})
        placed = [c for c in segments.discover_regions(rom, []) if c.vram is not None]
        self.assertEqual([(c.rom_start, c.vram) for c in placed], [(0x8000 + len(small), 0x80300000)])

    def test_one_program_is_never_cut(self):
        code = segment(0x80234560, 200)[:-0x400]
        found = segments.discover_regions(rom_with({0x8040: code}), [])
        self.assertEqual([(c.rom_start, c.vram) for c in found], [(0x8040, 0x80234560)])


class DataExtentTest(unittest.TestCase):
    """A range found by code density is extended over the data its own code reads past its end."""

    def test_the_end_moves_to_the_furthest_read_past_the_code(self):
        import struct as _struct
        from n64dk.analysis import segments as seg
        delta = 0x80100000 - 0x1000                         # the range at ROM 0x1000 runs at 0x80100000
        code = [0x3C028010, 0x8C420040,                       # lui v0, 0x8010; lw v0, 0x40(v0)  -> 0x80100040
                0x3C038010, 0xC4640120,                       # lui v1, 0x8010; lwc1 f4, 0x120(v1) -> 0x80100120 (past the code)
                0x03E00008, 0]
        rom = bytearray(0x4000)
        _struct.pack_into(f">{len(code)}I", rom, 0x1000, *code)
        end = 0x1000 + 4 * len(code)
        new_end, references = seg.data_extent(bytes(rom), 0x1000, end, delta, len(rom))
        self.assertEqual((new_end, references), (0x1130, 2))       # both reads land past the 24 bytes of code
        # never past what belongs to something else
        self.assertEqual(seg.data_extent(bytes(rom), 0x1000, end, delta, 0x1100), (0x1050, 1))   # the read past the limit is not counted
        # code that reads nothing past itself keeps its end
        self.assertEqual(seg.data_extent(bytes(rom), 0x1010, end, delta, len(rom)), (end, 0))       # jr ra; nop
