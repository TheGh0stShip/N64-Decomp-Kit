from __future__ import annotations

import tempfile
import unittest
import shutil
from pathlib import Path

from n64dk.match.cache import CacheError, ContentCache
from n64dk.match.campaign import Campaign, OracleObservation
from n64dk.match.diff import Report
from n64dk.match.diff import diff as instruction_diff
from n64dk.match.experiments import Experiment, ExperimentLedger
from n64dk.match.fingerprint import BuildClosure, ToolchainFingerprint, sha256_file
from n64dk.match.gcc27dump import explain as explain_gcc27
from n64dk.match.provenance import (Verdict, classify_source, credit_bytes, scan_c)
from n64dk.match.proof import ToolchainEmulation, evaluate as evaluate_proof
from n64dk.match.pipeline import BuildSpec
from n64dk.match.residual import Mechanism, ResidualSignature, classify
from n64dk.match.workbench import Workbench, WorkbenchError
from n64dk.match.transforms import Edit, Proposal, TransformationError, default_registry
from n64dk.match.runner import ExecutionLimits, RunnerError, UnitRunner
from n64dk.match.jobs import JobConfig, JobStore, MatchJob, generate_candidates
from n64dk.match.profiles import ProfileRegistry
from n64dk.project import OwnedSpan, WorkUnit
from n64dk.research import audit as audit_research


class ProjectContractTests(unittest.TestCase):
    def test_cross_section_overlap_in_same_image_is_rejected(self):
        with self.assertRaises(ValueError):
            WorkUnit("u", Path("u.c"), (
                OwnedSpan("resident", ".text", 0x100, 0x20),
                OwnedSpan("resident", ".rodata", 0x110, 0x20, "data"),
            ), "kmc")

    def test_section_names_do_not_determine_address_order(self):
        WorkUnit("u", Path("u.c"), (
            OwnedSpan("resident", ".text", 0x100, 0x20),
            OwnedSpan("resident", ".rodata", 0x200, 0x20, "data"),
        ), "kmc")
    def test_work_unit_rejects_overlapping_spans(self):
        with self.assertRaises(ValueError):
            WorkUnit("u", Path("u.c"), (
                OwnedSpan("resident", ".text", 0x100, 0x20),
                OwnedSpan("resident", ".text", 0x110, 0x20),
            ), "kmc")

    def test_same_vram_in_different_images_is_not_an_overlap(self):
        WorkUnit("u", Path("u.c"), (
            OwnedSpan("overlay-a", ".text", 0x80000000, 0x20),
            OwnedSpan("overlay-b", ".text", 0x80000000, 0x20),
        ), "ido")


class FingerprintTests(unittest.TestCase):
    def test_toolchain_and_closure_are_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cc = root / "cc1"
            source = root / "unit.c"
            cc.write_bytes(b"compiler")
            source.write_text("int f(void) { return 1; }\n")
            a = ToolchainFingerprint.create("test", {"compiler": cc}, "mips-n64",
                                            ["-O2"], {"TZ": "UTC"}, ["TZ"])
            b = ToolchainFingerprint.create("test", {"compiler": cc}, "mips-n64",
                                            ["-O2"], {"TZ": "UTC"}, ["TZ"])
            self.assertEqual(a.digest, b.digest)
            closure = BuildClosure.create("adapter", "1", "f", a.digest,
                                          {"source": source}, ["cc1", "-O2"],
                                          {"TZ": "UTC", "SECRET": "no"}, "strict", ["TZ"])
            self.assertEqual(closure.environment, (("TZ", "UTC"),))
            self.assertEqual(dict(closure.inputs)["source"], sha256_file(source))


class CacheTests(unittest.TestCase):
    def test_round_trip_and_corruption_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = ContentCache(tmp)
            digest = cache.put(b"artifact")
            self.assertEqual(cache.get(digest), b"artifact")
            cache.path(digest).write_bytes(b"corrupt")
            with self.assertRaises(CacheError):
                cache.get(digest)

    def test_campaign_compiles_identical_closure_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "f.c"
            source.write_text("int f(void) { return 1; }\n")
            closure = BuildClosure.create("test", "1", "f", "toolchain",
                                          {"source": source}, ["cc", "f.c"], {}, "strict")
            cache = ContentCache(root / "cache")
            ledger = ExperimentLedger(root / "ledger.sqlite")
            campaign = Campaign(cache, ledger)
            calls = []

            def produce():
                calls.append(1)
                return b"compiled-object"

            def observe(artifact):
                return OracleObservation(artifact == b"compiled-object", 0, {"counts": {}}, b"proof")

            first = campaign.evaluate(closure, source.read_bytes(), produce, observe,
                                      "baseline", "establish baseline")
            second = campaign.evaluate(closure, source.read_bytes(), produce, observe,
                                       "baseline", "establish baseline")
            self.assertFalse(first.cache_hit)
            self.assertTrue(second.cache_hit)
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(ledger.for_unit("f")), 1)
            ledger.close()


class ResidualTests(unittest.TestCase):
    def test_immediate_change_is_not_mislabeled_as_register_only(self):
        # Regression for the old Madden mask 0xFC00003F, which treats these as equal.
        a = bytes.fromhex("25080000")  # addiu t0,t0,0
        b = bytes.fromhex("25080040")  # addiu t0,t0,64
        report = instruction_diff(a, b, 0x80000000)
        self.assertEqual(report.counts["immediate"], 1)
        self.assertEqual(report.counts["register"], 0)
    def test_register_swap_is_high_confidence_regalloc(self):
        rep = Report(compiled_size=8, target_size=8, register_swap={"$s0": "$s1"})
        rep.entries = []
        sig = ResidualSignature.from_report(rep)
        diagnoses = classify(sig)
        # No entries means exact despite a nonsensical swap; real reports cannot have this.
        self.assertEqual(diagnoses[0].mechanism, Mechanism.EXACT)

    def test_type_and_schedule_can_be_reported_together(self):
        sig = ResidualSignature(16, 16, (("scheduling", 2),),
                                load_width_mismatches=1)
        mechanisms = {d.mechanism for d in classify(sig)}
        self.assertIn(Mechanism.TYPES, mechanisms)
        self.assertIn(Mechanism.SCHEDULING, mechanisms)

    def test_ownership_conflict_precedes_source_search(self):
        sig = ResidualSignature(16, 20, (("size", 1),), ownership_conflict=True)
        self.assertEqual(classify(sig)[0].mechanism, Mechanism.BOUNDARY)


class ExperimentTests(unittest.TestCase):
    def test_ledger_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger = ExperimentLedger(Path(tmp) / "experiments.sqlite")
            experiment = Experiment.create("f", "closure", "candidate", "baseline",
                                           "establish baseline", "result", False, 12,
                                           {"counts": {"register": 2}}, 31)
            self.assertTrue(ledger.append(experiment))
            self.assertFalse(ledger.append(experiment))
            self.assertEqual(ledger.get(experiment.experiment_id), experiment)
            self.assertEqual(ledger.for_unit("f"), [experiment])
            ledger.close()


class ProvenanceTests(unittest.TestCase):
    def test_plain_c_is_creditable(self):
        result = scan_c("int f(int x) { return x + 1; }\n")
        self.assertEqual(result.verdict, Verdict.GENUINE_C)
        self.assertEqual(credit_bytes(16, result, True, True), 16)

    def test_inline_asm_and_register_binding_are_forbidden(self):
        self.assertEqual(scan_c('asm volatile ("nop");').verdict, Verdict.FORBIDDEN)
        self.assertEqual(scan_c('register int x asm("$2");').verdict, Verdict.FORBIDDEN)

    def test_assembly_needs_positive_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "f.s"
            source.write_text("jr $ra\n")
            self.assertEqual(classify_source(source).verdict, Verdict.INSUFFICIENT)
            proven = classify_source(source, ("original-source-manifest:unit42",))
            self.assertEqual(proven.verdict, Verdict.HANDWRITTEN_ASM)
            self.assertEqual(credit_bytes(8, proven, True, True), 8)
            self.assertEqual(credit_bytes(8, proven, True, True, normalizer_specific=True), 0)

    def test_function_specific_normalizer_cannot_be_proof_grade(self):
        source = scan_c("int f(void) { return 0; }")
        spec = BuildSpec("kmc+asn64", ["-O2"], normalizer_args=["--enable-MY-FUNCTION"])
        verdict = evaluate_proof(spec, source, True, True)
        self.assertFalse(verdict.proof_grade)
        self.assertIn("lacks cross-project validation", verdict.reasons[0])

    def test_generic_emulation_needs_cross_project_fixtures(self):
        source = scan_c("int f(void) { return 0; }")
        spec = BuildSpec("kmc+asn64", ["-O2"], normalizer_args=["--enable-FP-PAIR"])
        weak = ToolchainEmulation("FP-PAIR", "0" * 64, 1, ("compiler-output",))
        strong = ToolchainEmulation("FP-PAIR", "0" * 64, 2, ("compiler-output",))
        self.assertFalse(evaluate_proof(spec, source, True, True,
                                       {"FP-PAIR": weak}).proof_grade)
        self.assertTrue(evaluate_proof(spec, source, True, True,
                                      {"FP-PAIR": strong}).proof_grade)


class GccDumpTests(unittest.TestCase):
    def test_allocator_dump_explains_priorities_and_ties(self):
        local = """
Register 72 used 4 times across 8 insns in block 0; GR_REGS or none; pointer.
Register 73 used 2 times across 2 insns in block 0; GR_REGS or none.
Register 74 used 2 times across 2 insns in block 0; GR_REGS or none.
;; Register 72 in 16.
;; Register 73 in 17.
;; Register 74 in 18.
"""
        result = explain_gcc27(local)
        self.assertEqual(result["pseudos"][0]["number"], 72)
        self.assertEqual(result["pseudos"][0]["priority"], 10000)
        self.assertEqual(result["priority_ties"]["10000"], [72, 73, 74])


class ResearchTests(unittest.TestCase):
    def test_audit_rejects_search_only_primary_claims(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sources = root / "sources.tsv"
            findings = root / "findings.tsv"
            sources.write_text(
                "url\ttitle\tsource_type\tevidence_quality\tfetched_or_search_only\tnotes\n"
                "https://example.invalid/source\tCompiler source\tcode\tprimary\tsearch_only\t-\n"
            )
            findings.write_text(
                "round_id\tquery_or_question\tsources\tkey_evidence\tevidence_type\tconfidence\tactionable_experiment\n"
                "R1\tWhat?\thttps://example.invalid/source\tClaim\tsourced\thigh\tCompile a probe\n"
            )
            result = audit_research(sources, findings)
            self.assertFalse(result["gates"]["search_only_is_not_primary_evidence"])
            self.assertEqual(result["actionable_findings"], 1)
            review = result["finding_reviews"][0]
            self.assertEqual(review["status"], "needs-evidence")
            self.assertFalse(review["implementation_approved"])
            self.assertIn("no fetched primary source", review["reasons"])


class WorkbenchBridgeTests(unittest.TestCase):
    def test_missing_executable_is_an_explicit_capability_failure(self):
        with self.assertRaises(WorkbenchError):
            Workbench.discover("definitely-not-an-installed-workbench")


class TransformationTests(unittest.TestCase):
    def test_bounded_edit_is_reversible(self):
        import hashlib
        source = "int f(void) { int x = 1; return x; }\n"
        start = source.index("int x = 1;")
        proposal = Proposal(
            "declaration-lifetime", hashlib.sha256(source.encode()).hexdigest(),
            "kmc-gcc-2.7.2", (Edit(start, start + len("int x = 1;"), "int x; x = 1;"),),
            ("initializer is side-effect free",), "alter pseudo birth without changing value",
        )
        registry = default_registry()
        applied = registry.apply(source, proposal)
        reverted = registry.apply(applied.source, applied.inverse)
        self.assertEqual(reverted.source, source)

    def test_stale_or_unproven_proposal_is_rejected(self):
        source = "int f(void) { return 1; }\n"
        proposal = Proposal("statement-order", "0" * 64, "gcc-2.7.x",
                            (Edit(0, 0, " "),), (), "")
        with self.assertRaises(TransformationError):
            default_registry().apply(source, proposal)

    def test_forbidden_assembly_escape_is_rejected(self):
        import hashlib
        source = "int f(void) { return 1; }\n"
        start = source.index("return 1;")
        proposal = Proposal(
            "statement-order", hashlib.sha256(source.encode()).hexdigest(),
            "gcc-2.7.x", (Edit(start, start + len("return 1;"),
                               'asm("nop"); return 1;'),),
            ("diagnostic experiment",), "test provenance rejection",
        )
        with self.assertRaises(TransformationError):
            default_registry().apply(source, proposal)


class RunnerTests(unittest.TestCase):
    def test_source_or_tool_drift_does_not_publish_cache_reference(self):
        from n64dk.match.runner import RunnerError
        for changed in ("source", "tool"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                adapter = self.Adapter(root)
                original = adapter.prepare_workspace
                def prepare(unit, workspace):
                    original(unit, workspace)
                    getattr(adapter, changed).write_text("changed during preparation")
                adapter.prepare_workspace = prepare
                runner = UnitRunner(adapter, root / "state")
                try:
                    with self.assertRaisesRegex(RunnerError, "changed during evaluation"):
                        runner.evaluate("f")
                    self.assertEqual(list(runner.cache.refs.iterdir()), [])
                    self.assertEqual(runner.ledger.for_unit("f"), [])
                finally:
                    runner.close()

    def test_truncated_target_extraction_is_rejected(self):
        from n64dk.match.runner import RunnerError
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            adapter.target_span_bytes = lambda unit, span: b""
            runner = UnitRunner(adapter, root / "state")
            try:
                with self.assertRaisesRegex(RunnerError, "extraction length"):
                    runner.evaluate("f")
            finally:
                runner.close()

    def test_unhashed_environment_is_rejected_before_build(self):
        from n64dk.match.runner import RunnerError
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            adapter.build_environment = lambda unit: {"CFLAGS": "-O0"}
            runner = UnitRunner(adapter, root / "state")
            try:
                with self.assertRaisesRegex(RunnerError, "unhashed keys"):
                    runner.evaluate("f")
            finally:
                runner.close()

    class Adapter:
        adapter_id = "fixture"
        adapter_version = "1"

        def __init__(self, root, wrong_rodata=False):
            self.root = root
            self.wrong_rodata = wrong_rodata
            self.source = root / "f.c"
            self.source.write_text("int f(void) { return 1; }\n")
            self.tool = root / "fake-tool"
            self.tool.write_text("fixture tool\n")
            self.code = OwnedSpan("resident", ".text", 0x80000100, 4, "code")
            self.rodata = OwnedSpan("resident", ".rodata", 0x80000200, 4, "data")
            self.unit = WorkUnit("f", self.source, (self.code, self.rodata), "fixture", ("-O2",))

        def project_root(self): return self.root
        def discover_units(self): return [self.unit]
        def image_bytes(self, image): return b""
        def target_span_bytes(self, unit, span):
            return b"\x00\x00\x00\x00" if span == self.code else b"DATA"
        def input_files(self, unit): return {"source": self.source}
        def toolchain_files(self, unit): return {"compiler": self.tool}
        def allowed_environment(self, unit): return ()
        def oracle_policy(self, unit): return "all-owned-spans-v1"
        def prepare_workspace(self, unit, workspace):
            shutil.copy2(self.source, workspace / "f.c")
        def build_command(self, unit, workspace):
            return ["/bin/sh", "-c", "printf built > build.marker"]
        def build_environment(self, unit): return {}
        def built_span_bytes(self, unit, workspace):
            self.assert_build(workspace)
            rodata = b"FAIL" if self.wrong_rodata else b"DATA"
            return {self.code: b"\x00\x00\x00\x00", self.rodata: rodata}
        @staticmethod
        def assert_build(workspace):
            if not (workspace / "build.marker").is_file():
                raise AssertionError("build command did not run")

    def test_all_owned_sections_are_required_and_build_is_cached(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root, wrong_rodata=True)
            runner = UnitRunner(adapter, root / "state")
            first = runner.evaluate("f")
            second = runner.evaluate("f")
            self.assertFalse(first.result.experiment.exact)
            self.assertEqual(first.result.experiment.score, 3)
            self.assertFalse(first.result.cache_hit)
            self.assertTrue(second.result.cache_hit)
            self.assertEqual(len(runner.ledger.for_unit("f")), 1)
            runner.close()

    def test_target_or_ownership_change_invalidates_build_closure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root, wrong_rodata=False)
            runner = UnitRunner(adapter, root / "state")
            first = runner.evaluate("f")
            adapter.rodata = OwnedSpan("resident", ".rodata", 0x80000204, 4, "data")
            adapter.unit = WorkUnit("f", adapter.source, (adapter.code, adapter.rodata),
                                    "fixture", ("-O2",))
            second = runner.evaluate("f")
            self.assertNotEqual(first.closure.digest, second.closure.digest)
            self.assertFalse(second.result.cache_hit)
            runner.close()

    def test_independent_verification_is_recorded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root, wrong_rodata=False)
            runner = UnitRunner(adapter, root / "state")
            summary = runner.evaluate("f", independent_verify=True)
            self.assertTrue(summary.verification["accepted"])
            self.assertFalse(summary.verification["production_approved"])
            rows = runner.ledger.verifications(summary.result.experiment.experiment_id)
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["same_artifact"])
            runner.close()

    def test_candidate_source_is_staged_without_mutating_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            original = adapter.source.read_bytes()
            observed = []
            old_built = adapter.built_span_bytes

            def built(unit, workspace):
                observed.append((workspace / "f.c").read_bytes())
                return old_built(unit, workspace)

            adapter.built_span_bytes = built
            runner = UnitRunner(adapter, root / "state")
            try:
                runner.evaluate("f", candidate_source=b"int f(void) { return 2; }\n")
            finally:
                runner.close()
            self.assertEqual(observed, [b"int f(void) { return 2; }\n"])
            self.assertEqual(adapter.source.read_bytes(), original)

    def test_build_timeout_kills_and_reports_the_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            adapter.build_command = lambda unit, workspace: ["/bin/sh", "-c", "sleep 10"]
            runner = UnitRunner(adapter, root / "state", ExecutionLimits(0.1, 4096))
            try:
                with self.assertRaisesRegex(RunnerError, "timed out"):
                    runner.evaluate("f")
            finally:
                runner.close()

    def test_build_output_limit_kills_and_reports_the_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            adapter.build_command = lambda unit, workspace: [
                "/bin/sh", "-c", "while :; do printf 0123456789; done"]
            runner = UnitRunner(adapter, root / "state", ExecutionLimits(5, 128))
            try:
                with self.assertRaisesRegex(RunnerError, "output exceeded"):
                    runner.evaluate("f")
            finally:
                runner.close()


class MatchJobTests(unittest.TestCase):
    class Adapter(RunnerTests.Adapter):
        def __init__(self, root):
            super().__init__(root)
            self.source.write_text("int f(void) {\n    int x = 1;\n    return x;\n}\n")

        def built_span_bytes(self, unit, workspace):
            self.assert_build(workspace)
            source = (workspace / "f.c").read_text()
            code = b"\x00\x00\x00\x00" if "int x;\n    x = 1;" in source else b"\x01\x00\x00\x00"
            return {self.code: code, self.rodata: b"DATA"}

    def test_generator_is_deterministic_and_local(self):
        source = b"int f(void) {\n    int x = 1;\n    x += 2;\n    return x;\n}\n"
        rows = generate_candidates(source)
        self.assertEqual([row.transform_id for row in rows],
                         ["split-fuse-expression", "compound-assignment"])
        self.assertTrue(all(row.source != source for row in rows))

    def test_job_persists_lineage_and_finds_exact_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            original = adapter.source.read_text()
            runner = UnitRunner(adapter, root / "state")
            store = JobStore(root / "state" / "jobs.sqlite")
            try:
                job = MatchJob(runner, store)
                job_id = job.create(JobConfig("f", budget=8, beam_width=2,
                                              max_candidates_per_parent=4))
                result = job.run(job_id)
                self.assertEqual(result["status"], "exact")
                self.assertEqual(result["attempts"], 2)
                rows = store.candidates(job_id)
                self.assertIsNone(rows[0].parent_id)
                self.assertEqual(rows[1].parent_id, rows[0].candidate_id)
                self.assertTrue(rows[1].exact)
                self.assertEqual(store.summary(job_id)["best"]["candidate_id"],
                                 rows[1].candidate_id)
            finally:
                store.close()
                runner.close()
            self.assertEqual(adapter.source.read_text(), original)

    def test_failed_build_is_persisted_and_resume_does_not_duplicate_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            adapter.build_command = lambda unit, workspace: ["/bin/sh", "-c", "exit 7"]
            runner = UnitRunner(adapter, root / "state")
            store = JobStore(root / "state" / "jobs.sqlite")
            try:
                job = MatchJob(runner, store)
                job_id = job.create(JobConfig("f", budget=4))
                first = job.run(job_id)
                second = job.run(job_id)
                self.assertEqual(first["attempts"], 1)
                self.assertEqual(second["attempts"], 1)
                self.assertEqual(second["failed"], 1)
                self.assertIn("status 7", store.candidates(job_id)[0].error)
            finally:
                store.close()
                runner.close()

    def test_resume_rejects_changed_build_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter = self.Adapter(root)
            runner = UnitRunner(adapter, root / "state")
            store = JobStore(root / "state" / "jobs.sqlite")
            try:
                job = MatchJob(runner, store)
                job_id = job.create(JobConfig("f", budget=1))
                job.run(job_id)
                adapter.tool.write_text("different compiler\n")
                with self.assertRaisesRegex(RunnerError, "context changed"):
                    job.run(job_id)
            finally:
                store.close()
                runner.close()


class ProfileTests(unittest.TestCase):
    def test_open_set_abstains_on_weak_or_tied_evidence(self):
        registry = ProfileRegistry.from_mapping({"profiles": {
            "a": {"component": "compiler", "family": "gcc", "version": "a",
                  "observations": {"move": "x", "switch": "y", "loop-call": "z"}},
            "b": {"component": "compiler", "family": "gcc", "version": "b",
                  "observations": {"move": "x", "switch": "y", "loop-call": "q"}},
        }})
        tied = registry.classify("compiler", {"move": "x", "switch": "y"})
        self.assertTrue(tied.abstained)
        self.assertIsNone(tied.profile_id)

    def test_open_set_accepts_reproduced_probe_profile(self):
        registry = ProfileRegistry.from_mapping({"profiles": {
            "kmc-fixture": {"component": "compiler", "family": "gcc", "version": "2.7.2",
                            "observations": {"move": "aa", "switch": "bb",
                                             "loop-call": "cc", "double-literal": "dd"}},
            "ido-fixture": {"component": "compiler", "family": "ido", "version": "7.1",
                            "observations": {"move": "11", "switch": "22",
                                             "loop-call": "33", "double-literal": "44"}},
        }})
        result = registry.classify("compiler", {"move": "aa", "switch": "bb",
                                                 "loop-call": "cc", "double-literal": "dd"})
        self.assertFalse(result.abstained)
        self.assertEqual(result.profile_id, "kmc-fixture")

if __name__ == "__main__":
    unittest.main()
