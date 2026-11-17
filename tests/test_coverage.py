"""Discovery completeness audit (n64dk.analysis.coverage) on synthetic images."""
import struct
import unittest

from n64dk.analysis import coverage

BASE = 0x80000400
NOP = 0
JR_RA = 0x03E00008


def jal(target):
    return 0x0C000000 | ((target >> 2) & 0x3FFFFFF)


def framed(*body):
    """addiu sp,-24; sw ra,20(sp); body...; lw ra,20(sp); jr ra; addiu sp,24; padded to 16 bytes."""
    words = [0x27BDFFE8, 0xAFBF0014, *body, 0x8FBF0014, JR_RA, 0x27BD0018]
    return words + [NOP] * (-len(words) % 4)


def image(*functions, tail=()):
    words, starts = [], []
    for f in functions:
        starts.append(BASE + 4 * len(words))
        words += f
    words += list(tail)
    return struct.pack(f">{len(words)}I", *words), starts


class AuditTest(unittest.TestCase):
    def layout(self):
        # A calls B; C is framed and unreferenced; D is a leaf only a data word points at
        a_calls = BASE + 0x20
        data, starts = image(framed(jal(a_calls), NOP), framed(NOP), framed(NOP, NOP),
                             [0x24020001, JR_RA, NOP, NOP])
        d = starts[3]
        data += struct.pack(">4I", d, 0, 0, 0)
        return data, starts

    def test_complete_catalogue(self):
        data, starts = self.layout()
        rows = [(f"f{i}", s, (starts[i + 1] if i + 1 < len(starts) else BASE + len(data) - 16) - s)
                for i, s in enumerate(starts)]
        report = coverage.audit_image("main", data, BASE, rows)
        self.assertEqual(report["verdict"], "complete", report["reasons"] + report["doubts"])
        self.assertEqual(report["coverage"], 1.0)
        self.assertEqual(report["direct_calls"]["missing"], 0)

    def test_missing_functions_found_with_evidence(self):
        data, starts = self.layout()
        report = coverage.audit_image("main", data, BASE, [("f0", starts[0], 0x20)])
        self.assertEqual(report["direct_calls"]["missing"], 1)
        self.assertEqual(report["prologues_outside"]["walk_as_functions"], 2)
        self.assertEqual(report["verdict"], "incomplete")
        found = {i.start: i for i in report["_islands"]}
        self.assertEqual(found[starts[1]].confidence, "high")          # call target with a frame
        self.assertIn("pointer target", found[starts[3]].evidence)
        self.assertLess(report["coverage"], coverage.INCOMPLETE_COVERAGE)

    def test_repair_reaches_complete_and_keeps_rows(self):
        data, starts = self.layout()
        rows, added, audits = coverage.repair("main", data, BASE, [("f0", starts[0], 0x20)])
        self.assertEqual([r[1] for r in rows], starts)
        self.assertEqual(rows[0], ("f0", starts[0], 0x20))
        self.assertEqual(len(added), 3)
        self.assertEqual(audits[0]["verdict"], "incomplete")
        self.assertEqual(audits[-1]["verdict"], "complete")

    def test_interior_and_unmapped_calls_are_reported_not_repaired(self):
        inner = BASE + 8
        data, starts = image(framed(NOP, jal(inner), NOP, jal(0x80700000), NOP))
        report = coverage.audit_image("main", data, BASE, [("f0", BASE, len(data))])
        self.assertEqual(report["direct_calls"]["interior"], 1)
        self.assertEqual(report["direct_calls"]["unmapped"], 1)
        rows, added, _ = coverage.repair("main", data, BASE, [("f0", BASE, len(data))])
        self.assertEqual(added, [])

    def test_call_into_other_image(self):
        other = {"seg": (0x80400000, 0x80401000, {0x80400000})}
        data, _ = image(framed(jal(0x80400000), NOP, jal(0x80400010), NOP))
        report = coverage.audit_image("main", data, BASE, [("f0", BASE, len(data))], others=other)
        self.assertEqual(report["direct_calls"]["cross_image"], 1)
        self.assertEqual(report["direct_calls"]["missing_in_other_image"], 1)
        self.assertEqual(report["direct_calls"]["unmapped"], 0)

    def test_kseg1_alias_pointer(self):
        data, starts = image(framed(NOP), framed(NOP))
        data += struct.pack(">4I", starts[1] | 0x20000000, 0, 0, 0)
        report = coverage.audit_image("main", data, BASE, [("f0", starts[0], 0x20), ("f1", starts[1], 0x20)])
        self.assertEqual(report["pointers"]["translated_to_starts"], 1)

    def test_data_is_not_an_island(self):
        data, starts = image(framed(NOP), tail=[0x3F800000, 0x40000000, 0x12345678, 0xDEADBEEF] * 8)
        report = coverage.audit_image("main", data, BASE, [("f0", starts[0], 0x20)])
        self.assertEqual(report["islands"]["count"], 0)
        self.assertEqual(report["verdict"], "complete")

    def test_text_section_share(self):
        data, starts = self.layout()
        report = coverage.audit_image("main", data, BASE, [("f0", starts[0], 0x20)],
                                      text_ranges=[(BASE, BASE + 0x70)])
        self.assertTrue(any(".text" in r for r in report["reasons"]))


if __name__ == "__main__":
    unittest.main()


class PlacementTest(unittest.TestCase):
    """Code the title calls but no image holds, placed from the ROM by those calls."""

    def rom_with(self, code: bytes, at: int = 0x20000, size: int = 0x40000) -> bytes:
        rom = bytearray(size)
        rom[at:at + len(code)] = code
        return bytes(rom)

    def segment(self, count=12):
        """``count`` framed functions of differing lengths (real code is not periodic)."""
        lengths = [1, 6, 2, 13, 4, 3, 9, 5, 8, 2, 11, 1]
        data, starts = image(*[framed(*[NOP] * lengths[k % len(lengths)]) for k in range(count)])
        return data, [s - BASE for s in starts]

    def test_owner_placement_by_call_targets(self):
        data, offsets = self.segment()
        rom = self.rom_with(data)
        base = 0x80300000
        targets = [base + o for o in offsets[:6]]
        placed = coverage.place_unmapped(rom, targets, taken=[], candidates=[(0x20000, 0x20000 + len(data))])
        self.assertEqual(len(placed), 1)
        self.assertEqual((placed[0]["rom"], placed[0]["vram"], placed[0]["kind"]), (0x20000, base, "owner"))

    def test_overlay_placement_keeps_targets_for_the_next(self):
        data, offsets = self.segment(6)                    # 6 prologues, 3 of them called
        rom = self.rom_with(data)
        base = 0x80300000
        # other overlays at the same address answer most calls: only 3 land here, all its prologues
        targets = [base + o for o in offsets[:3]] + [base + 0x2000 + 0x40 * k for k in range(9)]
        placed = coverage.place_unmapped(rom, targets, taken=[], candidates=[(0x20000, 0x20000 + len(data))])
        self.assertEqual([(p["vram"], p["kind"]) for p in placed], [(base, "overlay")])

    def test_scattered_targets_place_nothing(self):
        data, offsets = self.segment()
        rom = self.rom_with(data)
        targets = [0x80300000 + 0x44 * k for k in range(10)]       # no consistent load address
        self.assertEqual(coverage.place_unmapped(rom, targets, taken=[], candidates=[(0x20000, 0x20000 + len(data))]),
                         [])

    def test_taken_ranges_are_not_candidates(self):
        data, offsets = self.segment()
        rom = self.rom_with(data)
        targets = [0x80300000 + o for o in offsets[:6]]
        self.assertEqual(coverage.place_unmapped(rom, targets, taken=[(0x20000, 0x20000 + len(data))],
                                                 candidates=[(0x20000, 0x20000 + len(data))]), [])

    def test_unmapped_calls_fail_the_gate(self):
        calls = [jal(0x80600000 + 0x40 * k) for k in range(5)]
        body = []
        for c in calls:
            body += [c, NOP]
        data, _ = image(framed(*body))
        report = coverage.audit_image("main", data, BASE, [("f0", BASE, len(data))])
        self.assertEqual(report["direct_calls"]["unmapped"], 5)
        self.assertEqual(report["verdict"], "incomplete")


class LeadInTest(unittest.TestCase):
    def test_call_target_before_a_prologue_moves_the_start(self):
        # f0 calls 0x...0420, where two loads come before the prologue of the next function
        lead = [0x3C028019, 0x8C4318BC]                  # lui v0; lw v1 (scheduled before the frame)
        data, starts = image(framed(jal(BASE + 0x20), NOP), lead + framed(NOP)[:-2], [NOP, NOP])
        # the catalogue (as a prologue scan finds it) starts the second function at its prologue
        rows = [("f0", starts[0], 0x20), ("f1", starts[1] + 8, len(data) - 0x28)]
        report = coverage.audit_image("main", data, BASE, rows)
        self.assertEqual(report["direct_calls"]["lead_ins"], 1)
        fixed, added, audits = coverage.repair("main", data, BASE, rows)
        self.assertEqual([r[1] for r in fixed], [starts[0], starts[1]])
        self.assertEqual(added[0]["moved_from"], f"0x{starts[1] + 8:08X}")
        self.assertEqual(audits[-1]["direct_calls"]["missing"], 0)


class SummaryTest(unittest.TestCase):
    def test_summary_reports_what_remains_after_repair(self):
        from n64dk.commands.run import discovery_summary
        found = {"verdict": "incomplete", "verdict_before": "incomplete", "images": {"seg": {
            "verdict": "incomplete", "coverage": 0.01, "functions": 5,
            "reasons": ["682 complete functions with a stack frame lie outside the catalogue"],
            "repair": {"added": 1439, "bytes": 358764, "verdict_after": "incomplete", "coverage_after": 1.0,
                       "functions_after": 1444, "reasons_after": ["182 direct call targets start no function"]}}}}
        image = discovery_summary(found)["images"]["seg"]
        self.assertEqual(image["reasons_after"], ["182 direct call targets start no function"])
        self.assertEqual(image["functions_after"], 1444)
        self.assertIn("682", image["reasons"][0])                  # the pre-repair reasons stay, labelled as such
