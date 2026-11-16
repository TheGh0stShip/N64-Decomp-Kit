"""Donor transplant: masking, scan, symbol transfer, unit planning (synthetic) and a real
end-to-end transplant that skips without the toolchain or the game images."""
from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk.match import transplant as tp

NOP, JR_RA = 0x00000000, 0x03E00008


def jal(target: int) -> int:
    return 0x0C000000 | ((target >> 2) & 0x3FFFFFF)


def code(*words: int) -> bytes:
    return struct.pack(f">{len(words)}I", *words)


def donor_fn(lui: int, lo: int, callee: int, field: int = 0x10, extra: tuple[int, ...] = ()) -> bytes:
    return code(0x27BDFFE8,              # addiu sp, sp, -0x18      (kept)
                0xAFBF0014,              # sw ra, 0x14(sp)          (kept)
                0x3C010000 | lui,        # lui at, %hi(sym)         (masked)
                0x8C220000 | lo,         # lw v0, %lo(sym)(at)      (masked)
                jal(callee),             # jal callee               (masked)
                0x8C880000 | field,      # lw t0, field(a0)         (kept)
                *extra,
                0x8FBF0014,              # lw ra, 0x14(sp)
                JR_RA,
                0x27BD0018)              # addiu sp, sp, 0x18


DONOR_NAMES = {0x80123456: "gValue", 0x80101000: "callee", 0x80101100: "other"}


def name_at(address):
    return (DONOR_NAMES[address], 0) if address in DONOR_NAMES else (None, 0)


def make_unit(functions: list[tuple[str, bytes]], vram: int, donor: str = "D", source: str = "src/a.c") -> dict:
    records, offset = [], 0
    blob = b"".join(c for _n, c in functions)
    for k, (name, c) in enumerate(functions):
        records.append(tp.function_record(c, vram + offset, name, offset, len(c), k, name_at, (vram, vram + len(blob))))
        offset += len(c)
    masked, _ = tp.mask(blob, vram)
    return {"donor": donor, "source": source, "manifest": "m.tsv", "line": 1, "pipeline": "ido5.3",
            "flags_text": "", "flags": ["-O2"], "normalizer_args": [], "section_bases": {}, "symbols": {},
            "vram": vram, "size": len(blob), "core_size": len(blob), "unit_masked": tp.signature(masked),
            "functions": records}


def image_with(vram_delta: int, placed: dict[int, bytes], size: int = 0x4000, base: int = 0x80200000) -> bytes:
    data = bytearray(size)
    for vram, c in placed.items():
        off = vram - vram_delta
        data[off:off + len(c)] = c
    return bytes(data)


class MaskTest(unittest.TestCase):
    def test_masks_relocations_keeps_ordinary_immediates(self):
        c = donor_fn(0x8012, 0x3456, 0x80101000)
        masked, sites = tp.mask(c, 0x80100000)
        raw = tp.words_of(c)
        self.assertEqual(masked[0], raw[0])                 # stack adjust kept
        self.assertEqual(masked[1], raw[1])                 # stack offset kept
        self.assertEqual(masked[2], 0x3C010000)             # lui immediate masked
        self.assertEqual(masked[3], 0x8C220000)             # %lo masked
        self.assertEqual(masked[4], 0x0C000000)             # jal target masked
        self.assertEqual(masked[5], raw[5])                 # struct field offset kept
        kinds = {i: (k, a) for i, k, a in sites}
        self.assertEqual(kinds[2], ("hi", 0x80123456))
        self.assertEqual(kinds[3], ("lo", 0x80123456))
        self.assertEqual(kinds[4], ("jal", 0x80101000))

    def test_lui_ori_constant_keeps_ori(self):
        c = code(0x3C043F80, 0x34840001, JR_RA, NOP)        # lui a0,0x3f80; ori a0,a0,1
        masked, sites = tp.mask(c, 0x80100000)
        self.assertEqual(masked[0], 0x3C040000)
        self.assertEqual(masked[1], 0x34840001)
        self.assertEqual(sites[0][1], "lui")                # unpaired: masked, never transferred

    def test_trailing_padding_is_not_part_of_the_signature(self):
        c = donor_fn(0x8012, 0x3456, 0x80101000)
        self.assertEqual(tp.strip_padding(c + bytes(8)), c)


class ScanTransferTest(unittest.TestCase):
    delta = 0x80200000 - 0x1000

    def index(self, *units):
        return tp.Index({str(k): u for k, u in enumerate(units)}, {"D": {"root": "/x", "image": "/x", "delta": 0, "include": []}})

    def test_exact_hit_and_symbol_transfer(self):
        unit = make_unit([("donor_f", donor_fn(0x8012, 0x3456, 0x80101000))], 0x80100000)
        target = donor_fn(0x8022, 0x3466, 0x80205000)
        image = image_with(self.delta, {0x80200100: target})
        hits = tp.scan(image, self.delta, [("t_f", 0x80200100, len(target))], self.index(unit))
        self.assertEqual([h.kind for h in hits], ["exact"])
        result = tp.transfer(hits)
        by_name = {v["donor_symbol"]: v["target_address"] for v in result["symbols"].values()}
        self.assertEqual(by_name, {"gValue": 0x80223466, "callee": 0x80205000})
        self.assertIn("gValue = 0x80223466;", tp.symbol_file(result))
        self.assertIn("callee = 0x80205000; // type:func", tp.symbol_file(result))

    def test_near_hit_is_reported_not_exact(self):
        unit = make_unit([("donor_f", donor_fn(0x8012, 0x3456, 0x80101000))], 0x80100000)
        target = donor_fn(0x8022, 0x3466, 0x80205000, field=0x14)    # one ordinary immediate differs
        image = image_with(self.delta, {0x80200100: target})
        hits = tp.scan(image, self.delta, [("t_f", 0x80200100, len(target))], self.index(unit))
        self.assertEqual([(h.kind, h.diffs) for h in hits], [("near", [5])])
        jobs, _partial = tp.plan(hits, image, self.delta)
        self.assertEqual(jobs, [])                                      # never transplanted

    def test_contradiction_marks_hits_for_review(self):
        a = make_unit([("fa", donor_fn(0x8012, 0x3456, 0x80101000))], 0x80100000, source="a.c")
        b = make_unit([("fb", donor_fn(0x8012, 0x3456, 0x80101100, extra=(0x00851021,)))], 0x80100800, source="b.c")
        ta = donor_fn(0x8022, 0x3466, 0x80205000)
        tb = donor_fn(0x8022, 0x3470, 0x80205100, extra=(0x00851021,))  # gValue elsewhere
        image = image_with(self.delta, {0x80200100: ta, 0x80200200: tb})
        hits = tp.scan(image, self.delta, [("ta", 0x80200100, len(ta)), ("tb", 0x80200200, len(tb))],
                       self.index(a, b))
        result = tp.transfer(hits)
        self.assertEqual(len(result["contradictions"]), 1)
        self.assertEqual({h.status for h in hits}, {"needs-review"})
        self.assertNotIn(("D", 0x80123456), result["symbols"])

    def test_generic_shape_does_not_vote(self):
        unit = make_unit([("getter", code(0x3C028012, 0x8C423456, JR_RA, NOP))], 0x80100000)
        t1, t2 = code(0x3C028022, 0x8C420010, JR_RA, NOP), code(0x3C028022, 0x8C420020, JR_RA, NOP)
        image = image_with(self.delta, {0x80200100: t1, 0x80200200: t2})
        hits = tp.scan(image, self.delta, [("g1", 0x80200100, 16), ("g2", 0x80200200, 16)], self.index(unit))
        result = tp.transfer(hits)
        self.assertTrue(all(h.template for h in hits))
        self.assertEqual(result["contradictions"], [])
        self.assertEqual(result["symbols"], {})

    def test_two_donor_symbols_on_one_address_are_suspicious(self):
        a = make_unit([("fa", donor_fn(0x8012, 0x3456, 0x80101000))], 0x80100000, source="a.c")
        b = make_unit([("fb", donor_fn(0x8012, 0x3456, 0x80101100, extra=(0x00851021,)))], 0x80100800, source="b.c")
        ta = donor_fn(0x8022, 0x3466, 0x80205000)
        tb = donor_fn(0x8022, 0x3466, 0x80205000, extra=(0x00851021,))  # callee and other -> one address
        image = image_with(self.delta, {0x80200100: ta, 0x80200200: tb})
        hits = tp.scan(image, self.delta, [("ta", 0x80200100, len(ta)), ("tb", 0x80200200, len(tb))],
                       self.index(a, b))
        result = tp.transfer(hits)
        self.assertEqual(len(result["suspicious"]), 1)
        self.assertEqual(result["suspicious"][0]["target_address"], "0x80205000")


class UnitPlanTest(unittest.TestCase):
    delta = 0x80200000 - 0x1000

    def setUp(self):
        self.f1 = donor_fn(0x8012, 0x3456, 0x80101000)
        self.f2 = donor_fn(0x8012, 0x3456, 0x80101100, extra=(0x00851021,))
        self.unit = make_unit([("f1", self.f1), ("f2", self.f2)], 0x80100000)
        self.index = tp.Index({"u": self.unit}, {})

    def test_whole_unit_when_all_functions_are_contiguous(self):
        t1 = donor_fn(0x8022, 0x3466, 0x80205000)
        t2 = donor_fn(0x8022, 0x3466, 0x80205100, extra=(0x00851021,))
        image = image_with(self.delta, {0x80200100: t1 + t2})
        funcs = [("t1", 0x80200100, len(t1)), ("t2", 0x80200100 + len(t1), len(t2))]
        hits = tp.scan(image, self.delta, funcs, self.index)
        jobs, partial = tp.plan(hits, image, self.delta, {f[1] for f in funcs})
        self.assertEqual(len(jobs), 1)
        self.assertEqual((jobs[0].vram, jobs[0].size), (0x80200100, len(t1) + len(t2)))
        self.assertEqual(sorted(h.name for h in jobs[0].hits), ["t1", "t2"])
        self.assertEqual(partial, [])

    def test_partial_unit_lists_missing_neighbours(self):
        t1 = donor_fn(0x8022, 0x3466, 0x80205000)
        image = image_with(self.delta, {0x80200100: t1 + code(*([0x24020001] * 12))})
        funcs = [("t1", 0x80200100, len(t1))]
        hits = tp.scan(image, self.delta, funcs, self.index)
        jobs, partial = tp.plan(hits, image, self.delta, {0x80200100})
        self.assertEqual(jobs, [])
        self.assertEqual(hits[0].status, "partial-unit")
        self.assertEqual([m["donor_function"] for m in partial[0]["missing_neighbours"]], ["f2"])

    def test_unit_must_start_at_a_target_function_start(self):
        t2 = donor_fn(0x8022, 0x3466, 0x80205100, extra=(0x00851021,))
        image = image_with(self.delta, {0x80200100: t2})
        hits = tp.scan(image, self.delta, [("t2", 0x80200100, len(t2))], self.index)
        jobs, _ = tp.plan(hits, image, self.delta, {0x80200100})
        self.assertEqual(jobs, [])


class IndexPersistenceTest(unittest.TestCase):
    def test_round_trip(self):
        unit = make_unit([("f", donor_fn(0x8012, 0x3456, 0x80101000))], 0x80100000)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "index.json"
            tp.Index({"k": unit}, {"D": {}}).save(path)
            again = tp.Index.load(path)
        self.assertEqual(list(again.by_sig), list(tp.Index({"k": unit}).by_sig))

    def test_donor_toml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "donors.toml"
            path.write_text('[donor.a]\nroot = "/r"\nimage = "rom.z64"\nvram_delta = "0x7FFFF400"\n'
                            'manifests = ["m.tsv=ido5.3", { path = "k.tsv", pipeline = "kmc+as" }]\n')
            (donor,) = tp.load_donors(path)
        self.assertEqual(donor.image, Path("/r/rom.z64"))
        self.assertEqual(donor.vram_delta, 0x7FFFF400)
        self.assertEqual([(m.path, m.pipeline) for m in donor.manifests], [("m.tsv", "ido5.3"), ("k.tsv", "kmc+as")])


GAMES = Path(os.environ.get("N64DK_FIXTURE_ROOT", "/nonexistent"))
TOOLCHAIN = Path(os.environ.get("N64DK_TOOLCHAIN", "/nonexistent"))
BTX, NAGANO = GAMES / "BattleTanx", GAMES / "nagano"


@unittest.skipUnless((TOOLCHAIN / "ido5.3").is_dir(), "IDO toolchain not configured (N64DK_TOOLCHAIN)")
@unittest.skipUnless((BTX / "baseroms/us/baserom.z64").is_file() and (NAGANO / "baseroms/us/baserom.z64").is_file(),
                     "BattleTanx / nagano images not present")
class RealTransplantTest(unittest.TestCase):
    def test_battletanx_libultra_into_nagano(self):
        from n64dk.match.engine import Target
        from n64dk.rom import Rom
        donor = tp.DonorSpec("BattleTanx", BTX, BTX / "baseroms/us/baserom.z64",
                             [tp.Manifest("config/us/matching_units.tsv", "ido5.3")],
                             catalogue=[BTX / "config/us/recomp_function_boundaries.toml"],
                             include=[BTX / "include"])
        with tempfile.TemporaryDirectory() as tmp:
            index, info = tp.build_index([donor], Path(tmp) / "index.json")
            self.assertGreater(info["indexed"], 100)
            _again, info2 = tp.build_index([donor], Path(tmp) / "index.json")
            self.assertEqual(info2["indexed"], 0)                      # incremental
            target = Target.from_rom(Rom.load(NAGANO / "baseroms/us/baserom.z64"))
            functions = tp.load_functions([NAGANO / "analysis/survey/functions.toml"], target.delta)
            near = [f for f in functions if 0x8004E000 <= f[1] < 0x80050000]
            report = tp.run(None, target, near, index, out_dir=Path(tmp) / "out", jobs=2,
                            toolchain_root=TOOLCHAIN)
            self.assertGreaterEqual(report["verdicts"].get(tp.EXACT_VERDICT, 0), 3, report["verdicts"])
            self.assertTrue(any(p.name.startswith("proposed_BattleTanx") for p in (Path(tmp) / "out").iterdir()))


if __name__ == "__main__":
    unittest.main()


class CommonShapeTest(unittest.TestCase):
    def test_a_unit_is_a_common_shape_only_when_every_function_of_it_is(self):
        from types import SimpleNamespace as Hit
        self.assertTrue(tp.common_shape([Hit(template=True)]))
        self.assertTrue(tp.common_shape([Hit(template=True), Hit(template=True)]))
        # one getter among functions that stand nowhere else: the unit's place is not in doubt
        self.assertFalse(tp.common_shape([Hit(template=True), Hit(template=False), Hit(template=False)]))
        self.assertFalse(tp.common_shape([Hit(template=False)]))
        self.assertFalse(tp.common_shape([]))


class AlternativesTest(unittest.TestCase):
    def job(self, donor, source, functions=1, masked="m", flags=("-O2",), pipeline="kmc+as"):
        unit = {"donor": donor, "source": source, "functions": [{}] * functions, "unit_masked": masked,
                "flags": list(flags), "pipeline": pipeline}
        return tp.Job([], unit, 0x80001000, 0x40)

    def test_library_units_never_come_before_project_and_sdk_units(self):
        jobs = [self.job("t0123456789abcdef_main", "main/func_80001000.c"),
                self.job("sdk_2_0J_libgultra_rom", "src/os/createthread.c", functions=3),
                self.job("Rugrats64", "src/runtime/create_thread.c")]
        ordered = sorted(jobs, key=tp.alternative_order)
        self.assertEqual([job.unit["donor"] for job in ordered],
                         ["Rugrats64", "sdk_2_0J_libgultra_rom", "t0123456789abcdef_main"])

    def test_the_same_build_from_several_library_versions_is_tried_once(self):
        jobs = [self.job(f"sdk_2_0{v}_libgultra_rom", "/x/ultralib/src/os/createthread.c",
                         flags=("-O3", f"-DBUILD_VERSION=VERSION_{v}")) for v in "FHIJKL"]
        jobs.append(self.job("sdk_2_0J_libgultra_rom", "/x/ultralib/src/os/createthread.c", masked="other",
                             flags=("-O3", "-DBUILD_VERSION=VERSION_J")))
        jobs.append(self.job("sdk_2_0J_libultra_rom", "/x/ultralib/src/os/createthread.c", pipeline="ido5.3",
                             flags=("-O1",)))
        kept = tp.distinct_alternatives(jobs)
        self.assertEqual(len(kept), 3)                               # one per distinct code, compiler and flags
        self.assertGreaterEqual(tp.MAX_ALTERNATIVES, 8)

    def test_different_sources_with_the_same_code_are_both_kept(self):
        jobs = [self.job("Rugrats64", "src/runtime/create_thread.c"), self.job("sdk_2_0J_libgultra_rom", "src/os/createthread.c")]
        self.assertEqual(len(tp.distinct_alternatives(jobs)), 2)


class AssumedRowsTest(unittest.TestCase):
    def test_exact_rows_are_chosen_before_rows_awaiting_symbols(self):
        rows = [{"verdict": tp.ASSUMED_VERDICT, "target_vram": 0x80001000, "size": 0x40, "notes": []},
                {"verdict": tp.EXACT_VERDICT, "target_vram": 0x80001020, "size": 0x20, "notes": []},
                {"verdict": tp.ASSUMED_VERDICT, "target_vram": 0x80002000, "size": 0x20, "notes": []}]
        chosen = tp.select_rows(rows)
        self.assertEqual([row["verdict"] for row in chosen], ["superseded", tp.EXACT_VERDICT, tp.ASSUMED_VERDICT])

    def test_transfer_reports_where_donor_functions_were_found(self):
        callee = code(0x03E00008, 0x24020007)
        caller = donor_fn(0x8030, 0x1234, 0x80200100)
        unit = make_unit([("callee", callee)], 0x80200100, source="src/b.c")
        index = tp.Index({"u": unit}, {"D": {"root": ".", "include": [], "delta": 0, "image": ""}})
        image = image_with(0x80000000, {0x80001000: callee})
        hits = tp.scan(image, 0x80000000, [("func_80001000", 0x80001000, len(callee))], index)
        found = tp.transfer(hits)["definitions"]
        self.assertEqual(found.get(("D", 0x80200100)), {0x80001000})
        del caller
