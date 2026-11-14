from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from n64dk.match import context, inventory
from n64dk.match.layout import Layout, physical_collisions, preflight, resolve_image_map
from n64dk.match.registry import SessionRegistry, resolve_store
from n64dk.match.session import MatchSession, SessionStore


class InventoryTests(unittest.TestCase):
    def test_interval_coverage_aggregate_units_and_exclusions(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = root / "config/us"
            config.mkdir(parents=True)
            (config / "functions_main.toml").write_text("""
[[section]]
name = ".main"
rom = 0x100
vram = 0x80001000
size = 0x100
functions = [
 { name = "first", vram = 0x80001000, size = 0x10 }, # c
 { name = "second", vram = 0x80001010, size = 0x10 }, # asm
 { name = "shared_tail", vram = 0x80001020, size = 0x8 }, # asm shared epilogue
 { name = "remaining", vram = 0x80001030, size = 0x20 }, # asm
]
""")
            (config / "matching_main_kmc_units.tsv").write_text(
                "# rows\n0x100\t0x20\tsrc/aggregate.c\t-O2\n")
            (config / "matching_main_asm_units.tsv").write_text(
                "# rows\n0x120\t0x8\tsrc/shared_tail.s\t-O2\n"
                "0x130\t0x20\tsrc/remaining.s\t-O2\n")
            candidate = root / ".tmp/remaining_candidate.c"
            candidate.parent.mkdir()
            candidate.write_text("int remaining(void) { return 0; }\n")
            result = inventory.build(root)
            self.assertTrue(any(row["source"] == "aggregate_owned_c" for row in result["reconciliation"]))
            rows = {row["name"]: row for row in result["functions"]}
            self.assertEqual(rows["first"]["state"], "covered")
            self.assertEqual(rows["second"]["state"], "covered")
            self.assertEqual(rows["shared_tail"]["state"], "excluded")
            self.assertEqual(rows["remaining"]["state"], "assembly")
            self.assertEqual(rows["remaining"]["candidate_source"], ".tmp/remaining_candidate.c")
            self.assertEqual(rows["remaining"]["ownership_state"], "assembly_unit")
            self.assertEqual(rows["first"]["ownership_state"], "manifest_exact_member")

    def test_progress_denominator_mismatch_is_explicit(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); config = root / "config/us"; config.mkdir(parents=True)
            (config / "functions_main.toml").write_text('''
[[section]]
rom = 0
vram = 0x80000000
size = 0x20
functions = [{ name = "one", vram = 0x80000000, size = 0x10 }]
''')
            (config / "progress.toml").write_text("[image]\ntotal_functions = 2\n")
            result = inventory.build(root)
            self.assertEqual(result["summary"]["denominator_delta"], -1)
            self.assertEqual(result["consistency"]["denominator_mismatch"]["declared_functions"], 2)

    def test_scratch_candidate_never_claims_coverage(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = root / "config/us"
            config.mkdir(parents=True)
            (config / "functions_main.toml").write_text('''
[[section]]
rom = 0
vram = 0x80000000
size = 0x20
functions = [{ name = "func_80000000", vram = 0x80000000, size = 0x10 }] # c candidate
''')
            scratch = root / ".tmp/func_80000000_candidate.c"
            scratch.parent.mkdir()
            scratch.write_text("int func_80000000(void) { return 0; }\n")
            row = inventory.build(root)["functions"][0]
            self.assertEqual(row["state"], "remaining")
            self.assertEqual(row["ownership_state"], "scratch_candidate")
            self.assertIsNone(row["coverage_authority"])

    def test_generic_resident_manifest_expands_aggregate_unit(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); config = root / "config/us"; config.mkdir(parents=True)
            (config / "functions_resident.toml").write_text('''
[[section]]
rom = 0
vram = 0x80000400
size = 0x100
functions = [
 { name = "member_a", vram = 0x80000440, size = 0x10 },
 { name = "member_b", vram = 0x80000450, size = 0x10 },
]
''')
            (config / "matching_kmc_units.tsv").write_text(
                "0x1040\t0x20\tsrc/aggregate.c\t-O2\t" + "a" * 64 + "\n")
            rows = inventory.build(root)["functions"]
            self.assertTrue(all(row["state"] == "covered" for row in rows))
            self.assertTrue(all(row["ownership_state"] == "manifest_exact_member" for row in rows))

    def test_callee_save_store_is_not_semantic_live_in(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "function.bin"
            path.write_bytes(struct.pack(">IIIIII", 0x27BDFFE8, 0xAFB00010, 0x00008025,
                                         0x8FB00010, 0x03E00008, 0x27BD0018))
            layout = Layout("main", 0, 0x80000000, 24, 0x80000000, 24)
            report = preflight(path, layout, strict_entry=True)
            self.assertEqual(report["entry_preflight"]["entry_status"], "accept")

    def test_raw_offset_is_canonical_and_unanchored_composite_fails_closed(self):
        with tempfile.TemporaryDirectory() as name:
            layout = Layout("overlay2", 0x1000, 0x8008B8E0, 0x40000, 0x800AEF84, 12)
            code = struct.pack(">III", 0x24020001, 0x03E00008, 0)
            raw = bytearray(0x40000); raw[layout.rom:layout.rom + 12] = code
            raw_path = Path(name) / "raw.bin"; raw_path.write_bytes(raw)
            composite = bytearray(0xC0000); composite_offset = 0xAFB84
            composite[composite_offset:composite_offset + 12] = code
            composite_path = Path(name) / "composite.bin"; composite_path.write_bytes(composite)
            self.assertEqual(preflight(raw_path, layout)["selected_image_mapping"], "raw-overlay")
            with self.assertRaisesRegex(ValueError, "ambiguous composite image mapping"):
                preflight(composite_path, layout)

    def test_composite_payload_anchor_overrides_catalogue_vram_guess(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); raw_path = root / "overlay_4.z64"
            composite_path = root / "overlay_4_composite.z64"
            layout = Layout("overlay4", 0x1000, 0x800C77E8, 0x100,
                            0x800C77F8, 12)
            code = struct.pack(">III", 0x24020001, 0x03E00008, 0)
            raw = bytearray(0x1100); raw[0x1010:0x101C] = code; raw_path.write_bytes(raw)
            composite = bytearray(0x4000); struct.pack_into(">I", composite, 8, 0x80000400)
            composite[0x2000:0x2100] = raw[0x1000:0x1100]
            naive = layout.function_vram - 0x80000400 + 0x1000
            if naive + 12 <= len(composite): composite[naive:naive + 12] = struct.pack(">III", 0, 0x03E00008, 0)
            composite_path.write_bytes(composite)
            report = preflight(composite_path, layout)
            self.assertEqual(report["selected_image_mapping"], "anchored-composite-region")
            self.assertEqual(report["selected_image_offset"], "0x2010")
            self.assertEqual(report["mapping"]["linked_base"], "0x80001400")
            mapping = resolve_image_map(composite_path, layout)
            rows = [{"name": "linked_duplicate", "image": "overlay4", "vram": "0x80003010",
                     "section_vram": "0x80003000", "size": 12, "owner": "src/duplicate.c",
                     "ownership_state": "manifest_exact_unit"}]
            # Point a competing mapping at the duplicate's canonical physical interval.
            mapping["candidates"].append({**mapping["selected"], "authority": "wrong-map",
                                           "offset": 0x2010})
            collisions = physical_collisions(composite_path, layout, mapping, rows)
            self.assertEqual(collisions[0]["owner"], "linked_duplicate")

    def test_splat_metadata_and_context_bundle(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "splat.yaml").write_text("""
options:
  target_path: build/game.z64
  symbol_addrs_path: config/symbol_addrs.txt
  compiler: KMC
segments:
  - [0x1000, c, code/main]
""")
            self.assertEqual(inventory.build(root)["splat"][0]["compiler"], "KMC")
            image = root / "image.bin"
            image.write_bytes(struct.pack(">III", 0x0C000408, 0, 0x03E00008))
            result = context.bundle(image, 0x80001000, 12)
            self.assertEqual(result["callees"], ["0x80001020"])
            self.assertEqual(len(result["disassembly"]), 3)

    def test_layout_is_derived_from_section_and_rejects_data(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            image = root / "image.bin"
            image.write_bytes(b"\0" * 0x100 + struct.pack(">III", 0x27BDFFF0, 0x03E00008, 0))
            layout = Layout("overlay5", 0x100, 0x800C5F48, 0x100,
                            0x800C5F48, 12)
            result = preflight(image, layout)
            self.assertEqual(layout.delta, 0x800C5E48)
            self.assertEqual(result["mapping_authority"], "catalogue-section")
            bad = root / "bad.bin"
            bad.write_bytes(b"\0" * 0x100 + struct.pack(">III", 0x70000000, 0x70000000, 0x70000000))
            with self.assertRaisesRegex(ValueError, "data-like"):
                preflight(bad, layout)

    def test_delay_slot_and_entry_fragment_are_explicit(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            missing_slot = root / "missing.bin"
            missing_slot.write_bytes(struct.pack(">II", 0x27BDFFF0, 0x03E00008))
            layout = Layout("main", 0, 0x80000000, 8, 0x80000000, 8)
            with self.assertRaisesRegex(ValueError, "delay slot"):
                preflight(missing_slot, layout)
            # lw s0, 0x10(sp) before any definition is characteristic of an
            # epilogue/internal fragment, even when it owns its return slot.
            fragment = root / "fragment.bin"
            fragment.write_bytes(struct.pack(">III", 0x8FB00010, 0x03E00008, 0x27BD0018))
            layout = Layout("main", 0, 0x80000000, 12, 0x80000000, 12)
            report = preflight(fragment, layout)
            self.assertEqual(report["entry_preflight"]["entry_status"], "reject")
            self.assertIn("saved_register_restore_without_save",
                          report["entry_preflight"]["reason_codes"])
            with self.assertRaisesRegex(ValueError, "entry preflight"):
                preflight(fragment, layout, strict_entry=True)

    def test_registry_resolves_legacy_tranche_store(self):
        class Outcome:
            exact = True
            error = None
            result = None
            def as_dict(self):
                return {"exact": True}

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            store_root = root / ".n64dk/quickwin-sweeps/sessions"
            store = SessionStore(store_root)
            try:
                session_id, _ = MatchSession(store, lambda *_: Outcome()).create(
                    {"rom_sha256": "a", "addr": 1, "size": 4}, b"x", "kmc+as", ())
            finally:
                store.close()
            self.assertEqual(resolve_store(session_id, root), store_root)
            registry = SessionRegistry(root)
            try:
                self.assertEqual(len(registry.same_target(
                    {"rom_sha256": "a", "addr": 1, "size": 4})), 1)
            finally:
                registry.close()


if __name__ == "__main__":
    unittest.main()
