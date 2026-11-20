"""Code rules: what blocks a match, what is only open work, and what genuine code must pass."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from n64dk.match import coderules
from n64dk.match.coderules import ADVISORY, EXCEPTION, MATCH, MATCH_PENDING, MATCHED, NOT_MATCHED, ORIGINAL_ASM, Profile
from n64dk.match.provenance import Verdict, credit_bytes, judge_c, scan_c


def rules(source, path="unit.c", tier=MATCH, profile=None):
    return [finding.rule for finding in coderules.check_source(source, path, profile).of(tier)]


def messages(source, path="unit.c", tier=MATCH, profile=None):
    return [finding.message for finding in coderules.check_source(source, path, profile).of(tier)]


def body(statements, declarations=""):
    return f"/* f */\nint f(Thing *thing, int count) {{\n{declarations}{statements}\n    return count;\n}}\n"


class FakeCodeTest(unittest.TestCase):
    """R17: each shape that steers a compiler without being source."""

    def test_a_volatile_local_blocks_and_no_note_excuses_it(self):
        source = body("    keep = count;\n    count = keep;", "    volatile int keep; /* volatile: forces the store */\n")
        self.assertEqual(rules(source), ["R17"])
        self.assertIn("`volatile` on a local", messages(source)[0])
        self.assertEqual(rules(body("    keep = count;\n    count = keep;", "    vs32 keep;\n")), ["R17"])

    def test_volatile_elsewhere_needs_its_evidence(self):
        bare = "extern volatile u32 gRetrace;\n"
        noted = "/* volatile: written by the VI interrupt handler */\nextern volatile u32 gRetrace;\n"
        self.assertEqual(rules(bare, "video.h"), ["R17"])
        self.assertEqual(rules(noted, "video.h"), [])
        member = "typedef struct {\n    volatile u32 status;\n} Port;\n"
        self.assertEqual(rules(member, "port.h"), ["R17"])
        self.assertEqual(rules(member.replace("status;", "status; // volatile: hardware register"), "port.h"), [])

    def test_hardware_registers_pass_without_a_note(self):
        source = body("    *(volatile u32 *)0xA4400010 = 0;\n    count = *(vu32 *)PHYS_TO_K1(0x04600010);\n"
                      "    count = IO_READ(PI_STATUS_REG);")
        self.assertEqual(rules(source), [])
        self.assertEqual(rules("typedef volatile unsigned int vu32;\n", "ultratypes.h"), [])
        self.assertEqual(rules("#define IO_READ(a) (*(vu32 *)PHYS_TO_K1(a))\n", "rcp.h"), [])

    def test_a_volatile_pointer_to_ordinary_data_needs_evidence(self):
        self.assertEqual(rules(body("    count = *(volatile int *)thing;")), ["R17"])
        self.assertEqual(rules(body("    count = *(vu32 *)D_80012345;")), ["R17"])       # an address is not a register name
        self.assertEqual(rules("/* f */\nint f(volatile int *value) {\n    return *value;\n}\n"), ["R17"])

    def test_unused_locals(self):
        self.assertEqual(messages(body("", "    int spare;\n")), ["local `spare` is never used"])
        self.assertEqual(rules(body("", "    int a, *b, c[4];\n")), ["R17", "R17", "R17"])
        self.assertEqual(rules(body("    spare = count;", "    int spare;\n")), [])
        # the original's own unused local stays, labelled as a quirk
        self.assertEqual(rules(body("", "    int spare; /* NOTE: unused in the original, sizes its frame */\n")), [])

    def test_the_kits_own_frame_padding_is_scaffolding(self):
        from n64dk.match import draftforms
        from n64dk.match.transform_classes import SCAFFOLD_MARK
        padded = draftforms.pad("/* f */\nint f(int count) {\n    int i;\n    i = count;\n    return i;\n}\n", "f", 8)
        self.assertIn(SCAFFOLD_MARK, padded)
        found = coderules.check_source(padded, "f.c").blocking
        self.assertEqual([(f.rule, f.function) for f in found], [("R17", "f")])
        self.assertIn("scaffolding", found[0].message)

    def test_empty_blocks_and_bare_statements(self):
        self.assertEqual(messages(body("    if (count) {\n    }")), ["an empty `if` block"])
        self.assertEqual(messages(body("    if (count) {\n        count = 1;\n    } else {\n    }")), ["an empty `else` block"])
        self.assertEqual(messages(body("    if (count);")), ["an empty `if` block"])
        self.assertEqual(messages(body("    count = 1;;")), ["a bare `;` statement"])
        self.assertEqual(messages(body("    {\n        ;\n    }")), ["a bare `;` statement"])

    def test_loop_bodies_cases_and_labels_may_be_empty(self):
        source = body("    while (*text++) ;\n    for (;;) ;\n    while (--count) {\n        ;\n    }\n"
                      "    for (i = 0; i < count; i++) {\n    }\n"
                      "    switch (count) {\n    case 1: ;\n    default:\n        break;\n    }\n"
                      "done: ;", "    char *text;\n    int i;\n")
        self.assertEqual(rules(source), [])

    def test_do_while_zero_outside_a_macro(self):
        self.assertEqual(rules(body("    do {\n        count = 2;\n    } while (0);")), ["R17"])
        self.assertEqual(rules("#define SWAP(a, b) do { int t = a; a = b; b = t; } while (0)\n" + body("    SWAP(count, count);")), [])
        self.assertEqual(rules(body("    do {\n        count--;\n    } while (count);")), [])

    def test_self_assignment_and_identity_arithmetic(self):
        self.assertEqual(messages(body("    count = count;")), ["self-assignment"])
        self.assertEqual(messages(body("    thing->size = thing->size;")), ["self-assignment"])
        self.assertEqual(messages(body("    count = count + 0;")), ["`+ 0`"])
        self.assertEqual(messages(body("    count = count * 1;")), ["`* 1`"])
        genuine = body("    count = thing->count;\n    *thing = thing;\n    count = count + 0x10 + 0.5f;\n"
                       "    count = count * 10 * 1.5f;\n    count += 0;\n    count = 1e+0;")
        self.assertEqual(rules(genuine), [])

    def test_padding_members(self):
        source = "typedef struct Thing {\n    int count;\n    char pad[3];\n    int _pad2;\n} Thing;\n"
        self.assertEqual(rules(source, "thing.h"), ["R17", "R17"])
        self.assertEqual(rules(source.replace("pad[3]", "unk_04[3]").replace("_pad2", "unk_08"), "thing.h"), [])
        named = Profile(sdk_padding=("pad", "_pad2"))
        self.assertEqual(rules(source, "thing.h", profile=named), [])

    def test_a_probe_marker_blocks(self):
        self.assertEqual(rules(body("    count ^= 1; /* probe: forces t0 */")), ["R17"])
        self.assertEqual(rules(body("    count ^= 1; /* FAKEMATCH */")), ["R17"])
        self.assertEqual(rules(body("    count ^= 1; /* probe the controller port first */")), [])
        self.assertEqual(rules(body("    count ^= 1; /* the probe timed out */")), [])


class StructureTest(unittest.TestCase):
    """R1, R2, R4, R13, R18."""

    def test_offset_casts(self):
        self.assertEqual(rules(body("    count = *(int *)((char *)thing + 0x10);")), ["R4"])
        self.assertEqual(rules(body("    *(s16 *)((u8 *)thing + 6) |= 1;")), ["R4"])
        self.assertEqual(rules(body("    count = ((Other *)((u8 *)thing->next + 8))->size;")), ["R4"])
        self.assertEqual(rules("#define FLAGS(p) (*(u32 *)((u8 *)(p) + 0x10))\n", "thing.h"), ["R4"])
        # a parser walking bytes has no struct to name; an integer cast is only a suspicion
        self.assertEqual(rules(body("    cursor = (u8 *)thing + 4;\n    count = cursor[0] | (cursor[1] << 8);",
                                    "    u8 *cursor;\n")), [])
        self.assertEqual(rules(body("    count = *(int *)((u32)thing + 0x10);")), [])
        self.assertEqual(rules(body("    count = *(int *)((u32)thing + 0x10);"), tier=ADVISORY).count("R4"), 1)

    def test_a_rule_exception_records_a_style_rule_but_never_fake_code(self):
        excepted = body("    /* RULE-EXCEPTION: R4, the save block has no fixed layout */\n"
                        "    count = *(int *)((char *)thing + 0x10);")
        report = coderules.check_source(excepted, "unit.c")
        self.assertEqual(report.blocking, [])
        self.assertEqual([f.rule for f in report.of(EXCEPTION)], ["R4"])
        fake = body("    count = count; /* RULE-EXCEPTION: R17, the bytes need it */")
        self.assertEqual(rules(fake), ["R17"])
        wrong = body("    count = *(int *)((char *)thing + 0x10); /* RULE-EXCEPTION: R2, not this rule */")
        self.assertEqual(rules(wrong), ["R4"])

    def test_externs_belong_in_a_header(self):
        self.assertEqual(rules("extern int gFrame;\n", "game.c"), ["R2"])
        self.assertEqual(rules("extern int gFrame;\nextern Thing *gThings[8], gCount;\n", "game.h"), [])
        self.assertEqual(rules(body("    extern int gFrame;\n    count = gFrame;")), ["R2"])
        # a prototype outside a header is a reader's dead end, not a blocked match
        self.assertEqual(rules("extern void Update(int);\nvoid Draw(Thing *);\n", "game.c"), [])
        self.assertEqual(rules("extern void Update(int);\n", "game.c", tier=ADVISORY), ["R7"] * 0 + ["R25"])
        relaxed = Profile(relax={"R2": "the surviving SDK source declares its externs in each .c file"})
        self.assertEqual(rules("extern int gFrame;\n", "game.c", profile=relaxed), [])

    def test_one_global_one_type(self):
        report = coderules.check({"a.h": "extern int gFrame;\n", "b.h": "extern long gFrame;\nextern int gOther[];\n",
                                  "c.h": "extern int gOther[4];\n"})
        self.assertEqual([(f.path, f.rule) for f in report.blocking], [("a.h", "R2"), ("b.h", "R2")])
        self.assertIn("`int` / `long`", report.blocking[0].message)
        table = {row["name"]: row for row in coderules.declarations({"a.c": "extern int gFrame;\n",
                                                                     "b.c": "extern long gFrame;\nint Tick(void);\n"})}
        self.assertTrue(table["gFrame"]["conflict"])
        self.assertEqual(table["gFrame"]["files"], 2)

    def test_one_type_one_definition(self):
        whole = "typedef struct Thing {\n    int count;\n    float scale;\n} Thing;\n"
        report = coderules.check({"a.c": whole, "b.c": whole.replace("float scale", "int scale")})
        self.assertEqual(sorted({f.rule for f in report.blocking}), ["R1"])
        self.assertEqual(coderules.check({"a.c": whole, "b.c": whole}).blocking, [])       # identical copies: review, not a block
        self.assertEqual(coderules.check({"a.h": whole, "a.c": '#include "a.h"\n'}).blocking, [])

    def test_a_layout_view_is_not_a_type(self):
        whole = "typedef struct Thing {\n    int count;\n    float scale;\n    int flags;\n} Thing;\n"
        view = "typedef struct {\n    int count;\n    float scale;\n} ThingHead;\n"
        use = "/* g */\nint g(Thing *thing) {\n    return ((ThingHead *)thing)->count;\n}\n"
        report = coderules.check({"thing.h": whole, "b.c": view + use})
        self.assertEqual([(f.path, f.rule) for f in report.blocking], [("b.c", "R1")])
        self.assertIn("layout view", report.blocking[0].message)
        # C's inheritance idiom and an unrelated struct with the same first fields are not views
        derived = "typedef struct {\n    Thing base;\n    int extra;\n} Derived;\n/* g */\nint g(Thing *thing) {\n    return ((Derived *)thing)->extra;\n}\n"
        self.assertEqual(coderules.check({"thing.h": whole, "b.c": derived}).blocking, [])
        self.assertEqual(coderules.check({"thing.h": whole, "b.h": view}).blocking, [])

    def test_class_and_struct_keywords_must_agree(self):
        report = coderules.check({"a.h": "class Actor;\n", "actor.h": "struct Actor {\n    int id;\n};\n"})
        self.assertEqual(sorted({f.rule for f in report.blocking}), ["R1"])
        self.assertEqual(rules("class Actor {\npublic:\n    virtual void pad1();\n    virtual void Think();\n};\n", "actor.h"), ["R13"])

    def test_assembly_is_not_source(self):
        self.assertEqual(rules(body('    __asm__("nop");')), ["R18"])
        self.assertEqual(rules(body('    register int value asm("$4");\n    count = value;')), ["R18"])
        self.assertEqual(rules('INCLUDE_ASM("asm/nonmatchings/unit", func_80012345);\n'), ["R18"])
        self.assertEqual(rules('#pragma GLOBAL_ASM("asm/nonmatchings/unit/func_80012345.s")\n'), ["R18"])
        self.assertEqual(rules('extern int gFrame __asm__("D_80012345");\n', "game.h"), [])        # a symbol alias

    def test_original_assembly_is_listed_apart(self):
        source = '/* ORIGINAL-ASM: hand-scheduled, see asm/boot.s */\nvoid Boot(void) {\n    __asm__("nop");\n}\n'
        report = coderules.check_source(source, "boot.c")
        self.assertEqual(report.blocking, [])
        self.assertEqual([f.rule for f in report.of(ORIGINAL_ASM)], ["R18"])
        self.assertEqual(report.summary()["original_asm"], 1)
        self.assertEqual(report.summary()["pass"], 0)                 # counted neither way
        listed = coderules.check_source(body('    __asm__("mult $4, $5");'), "unit.c", Profile(asm_helpers=("f",)))
        self.assertEqual(listed.blocking, [])
        self.assertEqual([f.rule for f in listed.of(EXCEPTION)], ["R18"])


class AdvisoryTest(unittest.TestCase):
    """Open work is reported and never blocks a match."""

    def test_placeholder_names_are_open_naming_work(self):
        source = "/* f */\ns32 func_80012345(s32 arg0) {\n    s32 temp_v0;\n    s32 sp1C;\n    temp_v0 = arg0 + D_80123456;\n    sp1C = temp_v0;\n    return sp1C + 0x80123456;\n}\n"
        report = coderules.check_source(source, "unit.h")
        self.assertEqual(report.blocking, [])
        named = {f.message.split("`")[1] for f in report.of(ADVISORY) if f.rule == "R7"}
        self.assertEqual(named, {"func_80012345", "arg0", "temp_v0", "sp1C", "D_80123456"})
        self.assertEqual(report.status("unit.h", "func_80012345"), MATCHED)
        kept = Profile(naming_whitelist=("arg\\d+",))
        self.assertNotIn("placeholder name `arg0`", messages(source, "unit.h", ADVISORY, kept))
        self.assertEqual(rules("/* f */\nint Facade(int decade) {\n    return decade + 1000000;\n}\n", tier=ADVISORY), [])

    def test_readability_findings(self):
        source = ("int f(int count) {\n    if (count)\n        count = 1;\n    if (count = Next())\n    {\n        count = !!count;\n    }\n"
                  "    if ((count = Find(count)) != 0) {\n        count = 3;\n    }\n    if (count) {\n        (void)count;\n    }\n"
                  "    return count & 2048;\n}\n#if 0\nint old;\n#endif\n")
        report = coderules.check_source(source, "unit.c")
        found = sorted({(f.rule, f.message.split(":")[0]) for f in report.of(ADVISORY)})
        self.assertIn(("R33", "no header comment"), found)
        self.assertIn(("R35", "`if` body without braces"), found)
        self.assertIn(("R37", "`#if 0` block"), found)
        self.assertIn(("R9", "a mask written in decimal"), found)
        self.assertEqual(rules(body("    if (count && 100 < count) {\n        count = 0;\n    }"), tier=ADVISORY), [])
        self.assertEqual([f.message for f in report.of(MATCH)], [])
        self.assertIn(("F", "`(void)x;` only keeps a name alive"), found)
        self.assertEqual(sum(f.rule == "R35" and "assignment" in f.message for f in report.of(ADVISORY)), 0)

    def test_an_assignment_in_a_condition_outside_the_search_idiom(self):
        self.assertIn("an assignment inside a condition", messages(body("    if (count = thing->count) {\n        count = 2;\n    }"),
                                                                    tier=ADVISORY))

    def test_a_project_may_tighten_a_mechanical_rule_and_record_braceless_style(self):
        source = "int f(int count) {\n    if (count)\n        count = 1;\n    return count;\n}\n"
        self.assertEqual(rules(source, profile=Profile(tighten=("R33",))), ["R33"])
        self.assertNotIn("R35", rules(source, tier=ADVISORY, profile=Profile(braceless=True)))
        self.assertNotIn("R33", rules(source, tier=ADVISORY, profile=Profile(banners=False)))


class GenuineCodeTest(unittest.TestCase):
    def test_the_eras_idioms_pass(self):
        source = '''// g_combat.c -- damage, death and scoring

#include "g_local.h"

/*
================
CopyName

Copies a name, stopping at the first control character
================
*/
static int CopyName( char *dst, const char *src, int count ) {
    gentity_t *ent;
    int       i, total;

    total = 0;
    for ( i = 0; i < count && *src; i++ ) {
        *dst++ = *src++;
    }
    while ( --count ) {
        total += count;
    }
    if ( !( ent = G_Find( NULL, FOFS( classname ), "info_player" ) ) ) {
        goto fail;
    }
    while ( ( ent = G_Find( ent, FOFS( classname ), "item" ) ) != NULL ) {
        total += ent->count * 16 + 1;
    }
    VectorCopy( ent->s.origin, ent->pos1 );
    a = b = 0;
    return ( total & FL_GODMODE ) ? total : 0;

fail:
    Com_Error( ERR_DROP, "CopyName: no player start" );
    return -1;
}
'''
        report = coderules.check_source(source, "g_combat.c")
        self.assertEqual([f.text() for f in report.findings], [])
        self.assertEqual(report.functions, {"g_combat.c": ["CopyName"]})

    def test_comments_strings_and_macros_are_not_code(self):
        source = ('/* volatile int x; x = x; do { } while (0); */\n#define NOP() do { } while (0)\n'
                  '/* f */\nint f(int count) {\n    Print("x = x; + 0; volatile");   // if (x) { }\n    return count;\n}\n')
        self.assertEqual(coderules.check_source(source, "unit.c").blocking, [])


class StatusTest(unittest.TestCase):
    SOURCE = "extern int gFrame;\n/* a */\nint A(int x) {\n    return x;\n}\n/* b */\nint B(int x) {\n    int spare;\n    return x;\n}\n"

    def test_identical_bytes_alone_are_not_a_match(self):
        report = coderules.check_source(self.SOURCE.replace("extern int gFrame;\n", ""), "unit.c")
        self.assertEqual(report.status("unit.c", "A"), MATCHED)
        self.assertEqual(report.status("unit.c", "B"), MATCH_PENDING)
        self.assertEqual(report.status("unit.c", "A", exact=False), NOT_MATCHED)
        self.assertEqual(coderules.verdict(True, report), MATCH_PENDING)
        self.assertEqual(coderules.verdict(True, report, "unit.c", "A"), MATCHED)
        self.assertEqual(report.summary()["pass"], 1)
        self.assertEqual(report.summary()["match_pending"], 1)

    def test_a_file_scope_finding_blocks_every_function_of_the_unit(self):
        report = coderules.check_source(self.SOURCE, "unit.c")
        self.assertEqual(report.blocked_rules("unit.c", "A"), ["R2"])
        self.assertEqual(report.blocked_rules("unit.c", "B"), ["R2", "R17"])
        self.assertEqual(report.summary()["match_findings"], {"R2": 1, "R17": 1})

    def test_credit_needs_the_rules(self):
        fake = "int f(int x) {\n    int pad;\n    return x;\n}\n"
        self.assertEqual(scan_c(fake).verdict, Verdict.GENUINE_C)          # a search may still compile it
        judged = judge_c(fake)
        self.assertEqual(judged.verdict, Verdict.MATCH_PENDING)
        self.assertEqual(judged.reasons, ("code rule R17",))
        self.assertIn("local `pad` is never used", judged.evidence[0])
        self.assertEqual(credit_bytes(16, judged, True, True), 0)
        clean = judge_c("int f(int x) {\n    return x + 1;\n}\n")
        self.assertEqual(clean.verdict, Verdict.GENUINE_C)
        self.assertEqual(credit_bytes(16, clean, True, True), 16)
        self.assertEqual(judge_c('int f(void) {\n    __asm__("nop");\n    return 0;\n}\n').verdict, Verdict.FORBIDDEN)

    def test_proof_is_refused_for_match_pending_source(self):
        from n64dk.match.pipeline import BuildSpec
        from n64dk.match.proof import evaluate
        verdict = evaluate(BuildSpec("kmc", ["-O2"]), judge_c("int f(int x) {\n    x = x;\n    return x;\n}\n"), True, True)
        self.assertFalse(verdict.proof_grade)
        self.assertEqual(verdict.reasons, ("source provenance is match-pending",))


class ProfileTest(unittest.TestCase):
    def test_fake_code_and_assembly_cannot_be_relaxed(self):
        for rule in ("R17", "R18"):
            with self.assertRaises(ValueError):
                Profile(relax={rule: "the bytes need it"})
        with self.assertRaises(ValueError):
            Profile(relax={"R2": " "})
        with self.assertRaises(ValueError):
            Profile.from_mapping({"relaxed": {}})

    def test_the_profile_is_read_from_the_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(Profile.load(tmp), Profile())
            Path(tmp, "n64dk.toml").write_text(
                '[code_rules]\ntighten = ["R33"]\nsdk_padding = ["pad"]\nplaceholders = ["gUnk\\\\w+"]\nbraceless = true\n'
                '[code_rules.relax]\nR2 = "the SDK source declares externs per unit"\n')
            profile = Profile.load(tmp)
            self.assertEqual(profile.relax, {"R2": "the SDK source declares externs per unit"})
            self.assertEqual(profile.tighten, ("R33",))
            self.assertTrue(profile.braceless)
            self.assertIn("gUnk\\w+", profile.placeholders)
            self.assertIn("func_[0-9A-Fa-f]{6,8}", profile.placeholders)


class SearchProvenanceTest(unittest.TestCase):
    def test_steering_families_are_named(self):
        from n64dk.match.transform_classes import STEERING, provenance
        found = provenance([{"stage": "iterate", "helpful_families": ["ast-block", "lifetime", "volatile"]},
                            {"stage": "frame-fit", "chosen": "pad 4 top"}])
        self.assertEqual(found["steering"], ["ast-block", "volatile", "frame-pad"])
        self.assertEqual(provenance([{"stage": "iterate", "helpful_families": ["lifetime", "order"]}])["steering"], [])
        self.assertTrue(all(rule.startswith("R") and hides for rule, hides in STEERING.values()))

    def test_what_the_block_family_writes_is_never_credited(self):
        # the two wrappers of astforms' ``block`` family, as it writes them
        for wrapper in ("do {\n        b = a + 1;\n    } while (0);", "if (1) {\n        b = a + 1;\n    }"):
            source = f"int f(int a) {{\n    int b;\n    {wrapper}\n    return b;\n}}\n"
            judged = judge_c(source)
            self.assertEqual((judged.verdict, judged.reasons), (Verdict.MATCH_PENDING, ("code rule R17",)), wrapper)

    def test_the_block_family_itself(self):
        try:
            from n64dk.match import astforms
        except ImportError:
            self.skipTest("pycparser is not installed")
        source = "int f(int a) {\n    int b;\n    b = a + 1;\n    return b;\n}\n"
        wrapped = [v.source for v in astforms.variants(source, "f", families=("block",))]
        if not wrapped:
            self.skipTest("no host C preprocessor: the block family produced nothing")
        self.assertTrue(all(judge_c(text).verdict == Verdict.MATCH_PENDING for text in wrapped), wrapped)

    def test_the_refiner_is_told_what_does_not_count(self):
        from n64dk.match import refine
        self.assertIn("are not a match", refine.INSTRUCTIONS)
        self.assertIsNone(refine.candidate_problem('#include "types.h"\nint f(int x) {\n    return x;\n}\n'))


class CommandTest(unittest.TestCase):
    def run_command(self, *argv):
        from n64dk.cli import main
        out = io.StringIO()
        with redirect_stdout(out):
            code = main(list(argv))
        return code, out.getvalue()

    def test_one_line_per_finding_and_a_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "a.c").write_text("extern int gFrame;\n/* a */\nint A(void) {\n    return gFrame;\n}\n")
            (root / "src" / "b.c").write_text("extern long gFrame;\n/* b */\nint B(int x) {\n    return x;\n}\n")
            code, text = self.run_command("code-rules", str(root / "src"), "--project", tmp, "--declarations")
            self.assertEqual(code, 0)
            self.assertIn("src/a.c:1: R2 [match]: `extern` of `gFrame` outside its header", text)
            self.assertIn("declaration: object `gFrame` in 2 files: int / long", text)
            self.assertIn("2 files, 2 functions: 0 pass, 2 MATCH-PENDING, 0 ORIGINAL-ASM", text)
            code, text = self.run_command("--format", "json", "code-rules", str(root / "src"), "--project", tmp, "--strict",
                                          "--no-advisory")
            self.assertEqual(code, 1)
            result = json.loads(text)
            self.assertEqual(result["status"], "MATCH-PENDING")
            self.assertEqual(result["match_findings"], {"R2": 4})
            self.assertEqual({row["function"] for row in result["pending_functions"]}, {"A", "B"})
            self.assertTrue(all(row["tier"] != "advisory" for row in result["findings"]))
            (root / "n64dk.toml").write_text('[code_rules.relax]\nR2 = "externs per unit, as in the surviving source"\n')
            code, text = self.run_command("code-rules", str(root / "src" / "b.c"), "--project", tmp, "--strict")
            self.assertEqual(code, 0)
            self.assertIn("1 pass, 0 MATCH-PENDING", text)

    def test_provenance_audit_refuses_fake_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake, clean = Path(tmp, "fake.c"), Path(tmp, "clean.c")
            fake.write_text("int f(int x) {\n    do {\n        x++;\n    } while (0);\n    return x;\n}\n")
            clean.write_text("int g(int x) {\n    return x + 1;\n}\n")
            code, text = self.run_command("--format", "json", "provenance-audit", str(fake), str(clean), "--size", "16",
                                          "--exact", "--ownership-verified")
            rows = {Path(row["source"]).name: row for row in json.loads(text)["results"]}
            self.assertEqual(rows["fake.c"]["verdict"], "match-pending")
            self.assertEqual(rows["fake.c"]["credited_bytes"], 0)
            self.assertEqual(rows["clean.c"]["credited_bytes"], 16)
            self.assertFalse(json.loads(text)["all_creditable"])


class TrackerTest(unittest.TestCase):
    def test_the_rules_track_counts_only_what_passes(self):
        import importlib.util
        path = Path(__file__).resolve().parents[1] / "tools" / "generate_tracker_progress.py"
        spec = importlib.util.spec_from_file_location("generate_tracker_progress", path)
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        rows = [{"image": "main", "vram": f"0x{0x80000000 + 16 * index:08X}", "code_size": "0x10", "rules": status}
                for index, status in enumerate(("pass", "MATCH-PENDING: R2,R17", "ORIGINAL-ASM", "", "pass"))]
        verified = {tool.function_key(row) for row in rows[:2]}           # the last row has no replayed C
        self.assertEqual(tool.rules_measure(rows, verified), (16, 64))
        rows[1]["rules"] = "looks fine"
        with self.assertRaises(ValueError):
            tool.rules_measure(rows, verified)


if __name__ == "__main__":
    unittest.main()
