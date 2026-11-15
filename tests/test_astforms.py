import shutil
import atexit
"""astforms: span-faithful AST transformations (toolchain-free tests, plus real-compiler
recoveries skipped when the compilers are not configured)."""
import os
import re
import tempfile
import unittest
from pathlib import Path


def _scratch(prefix: str = "n64dk-test-") -> str:
    """A scratch directory removed when the test process exits."""
    path = tempfile.mkdtemp(prefix=prefix)
    atexit.register(shutil.rmtree, path, True)
    return path


try:
    import pycparser  # noqa: F401
    HAVE_PYCPARSER = True
except ImportError:                                            # pragma: no cover
    HAVE_PYCPARSER = False

if HAVE_PYCPARSER:
    from n64dk.match import astforms, astprep, iterate

PRELUDE = """typedef signed char s8; typedef unsigned char u8; typedef short s16;
typedef unsigned short u16; typedef int s32; typedef unsigned int u32;
"""

SOURCE = PRELUDE + """#include "missing_header.h"
/* a comment outside the function */
extern s32 gCount;
extern s32 gOther;
extern s32 helper(s32 value);
#define TWICE(x) ((x) * 2)

s32 work(s32 *p, s32 *q, s32 n) {
    s32 a;
    s32 b;
    s32 c;

    a = gCount + n;   // trailing comment
    helper(a);
    b = gCount + n;
    *p = a;
    c = *q;
    if (!(a && b)) {
        c++;
    } else {
        c += TWICE(n);
    }
    return a + b + c;
}

void tail(void) {
    gOther = 1;
}
"""


def L(source, snippet):
    """1-based line of ``snippet`` in ``source``."""
    return "L%d" % (source[:source.index(snippet)].count("\n") + 1)


def run(source, name, families, limit=None):
    return astforms.variants(source, name, families, limit=limit)


def by_label(variants, prefix):
    return [v for v in variants if v.label.startswith(prefix)]


@unittest.skipUnless(HAVE_PYCPARSER, "pycparser not installed")
class FidelityTest(unittest.TestCase):
    def test_text_outside_the_function_is_byte_identical(self):
        start = SOURCE.index("s32 work(")
        end = SOURCE.index("void tail")
        found = run(SOURCE, "work", astforms.FAMILIES)
        self.assertGreater(len(found), 50)
        for v in found:
            self.assertTrue(v.source.startswith(SOURCE[:start]), v.label)
            self.assertTrue(v.source.endswith(SOURCE[end:]), v.label)
            self.assertIn('#include "missing_header.h"', v.source)
            self.assertIn("/* a comment outside the function */", v.source)

    def test_comments_inside_the_function_survive_unrelated_edits(self):
        for v in run(SOURCE, "work", ("expr", "control", "stmt-order")):
            if L(SOURCE, "a = gCount") not in v.label:
                self.assertIn("// trailing comment", v.source, v.label)

    def test_a_statement_with_a_comment_is_never_reprinted(self):
        source = PRELUDE + "void f(s32 *p, s32 n) {\n    p[0] = n /* keep */ + 1;\n    p[1] = n + 2;\n}\n"
        found = run(source, "f", ("expr", "cast", "temp"))
        self.assertTrue(found)
        self.assertFalse([v for v in found if re.search(r"' L4\b", v.label)])
        for v in found:
            self.assertIn("p[0] = n /* keep */ + 1;", v.source)

    def test_macro_statements_are_not_reprinted(self):
        for v in run(SOURCE, "work", ("expr", "cast", "temp")):
            self.assertIn("c += TWICE(n);", v.source, v.label)

    def test_every_variant_reparses_labels_unique_and_stable(self):
        first = run(SOURCE, "work", astforms.FAMILIES)
        second = run(SOURCE, "work", astforms.FAMILIES)
        self.assertEqual([v.label for v in first], [v.label for v in second])
        self.assertEqual(len({v.label for v in first}), len(first))
        self.assertEqual(len({v.source for v in first}), len(first))
        for v in first:
            astprep.prepare(v.source, "work")

    def test_limit_round_robins_families(self):
        limited = run(SOURCE, "work", astforms.FAMILIES, limit=18)
        self.assertEqual(len(limited), 18)
        self.assertGreaterEqual(len({v.family for v in limited}), 8)

    def test_unparseable_function_returns_empty_and_diagnoses(self):
        bad = PRELUDE + "void f(void) { s32 x = ; }\n"
        self.assertEqual(astforms.variants(bad, "f", astforms.FAMILIES), [])
        self.assertIn("parse", astforms.diagnose(bad, "f"))
        self.assertIn("function-not-found", astforms.diagnose(SOURCE, "nothere"))

    def test_statement_macro_is_opaque_but_the_rest_is_mapped(self):
        source = PRELUDE + ("#define PAIR(a, b) a = 1; b = 2\nextern s32 g;\n"
                            "void f(s32 x) {\n    s32 a;\n    s32 b;\n\n    PAIR(a, b);\n    g = x + 1;\n}\n")
        self.assertTrue(astforms.diagnose(source, "f").startswith("ok"))
        found = run(source, "f", astforms.FAMILIES)
        self.assertTrue(by_label(found, "expr: commute 'x + 1'"))
        for v in found:
            self.assertIn("PAIR(a, b);", v.source)

    def test_apply_path_replays_labels(self):
        one = run(SOURCE, "work", ("expr",))[0]
        two = run(one.source, "work", ("control",))[0]
        self.assertEqual(astforms.apply_path(SOURCE, "work", [one.label, two.label]), two.source)
        self.assertIsNone(astforms.apply_path(SOURCE, "work", ["expr: no such edit"]))

    def test_c89_declaration_at_block_start(self):
        temp = by_label(run(SOURCE, "work", ("temp",)), f"temp: 'gCount + n' {L(SOURCE, 'a = gCount')}")[0]
        body = temp.source[temp.source.index("s32 work("):]
        self.assertRegex(body, r"s32 c;\n    s32 temp;\n\n")
        self.assertIn("temp = gCount + n;\n    a = temp;", body)


@unittest.skipUnless(HAVE_PYCPARSER, "pycparser not installed")
class AnalysisTest(unittest.TestCase):
    def setUp(self):
        self.ctx = astforms.context(SOURCE, "work")
        self.stmts = {self.ctx.src[n.start:n.end]: n for n in self.ctx.nodes}

    def eff(self, text):
        return self.ctx.an.node(self.stmts[text])

    def test_locals_globals_reads_writes(self):
        e = self.eff("a = gCount + n;")
        self.assertEqual(e.writes, {"a"})
        self.assertEqual(e.reads, {"n"})
        self.assertEqual(e.memr, {"g:gCount"})
        self.assertFalse(e.call)
        self.assertTrue(self.eff("helper(a);").call)
        self.assertEqual(self.eff("*p = a;").memw, {"*"})

    def test_commutation_rules(self):
        commute = astforms.commute
        self.assertFalse(commute(self.eff("helper(a);"), self.eff("b = gCount + n;")))   # call vs global read
        self.assertFalse(commute(self.eff("*p = a;"), self.eff("c = *q;")))              # pointer store vs load
        self.assertTrue(commute(self.eff("*p = a;"), self.eff("b = gCount + n;")) is False)  # store may alias global
        self.assertFalse(commute(self.eff("return a + b + c;"), self.eff("c = *q;")))     # jumps never move

    def test_distinct_locals_and_globals_commute(self):
        source = PRELUDE + ("extern s32 g1; extern s32 g2;\nvoid f(void) {\n    s32 x[2];\n    s32 y[2];\n"
                            "    x[0] = g1;\n    y[0] = g2;\n    g1 = 1;\n    g2 = 2;\n}\n")
        ctx = astforms.context(source, "f")
        items = ctx.prep.body.children
        e = [ctx.an.node(n) for n in items[2:]]
        self.assertTrue(astforms.commute(e[0], e[1]))       # distinct local arrays
        self.assertTrue(astforms.commute(e[2], e[3]))       # distinct globals
        self.assertFalse(astforms.commute(e[0], e[2]))      # read g1 / write g1

    def test_address_taken_local_is_memory(self):
        source = PRELUDE + "extern void use(s32 *);\nvoid f(void) {\n    s32 x;\n    s32 y;\n    use(&x);\n    y = x;\n}\n"
        ctx = astforms.context(source, "f")
        self.assertIn("x", ctx.an.memlocals)
        self.assertNotIn("y", ctx.an.memlocals)
        items = ctx.prep.body.children
        self.assertFalse(astforms.commute(ctx.an.node(items[2]), ctx.an.node(items[3])))

    def test_volatile_access_is_ordered(self):
        source = PRELUDE + "extern volatile s32 gReg;\nextern s32 g;\nvoid f(void) {\n    s32 x;\n    x = gReg;\n    g = 1;\n}\n"
        ctx = astforms.context(source, "f")
        items = ctx.prep.body.children
        self.assertTrue(ctx.an.node(items[1]).volatile)
        self.assertFalse(astforms.commute(ctx.an.node(items[1]), ctx.an.node(items[2])))

    def test_types(self):
        T = self.ctx.types
        e = self.stmts["a = gCount + n;"].ast.rvalue
        self.assertEqual(T.kind(T.typeof(e)), ("int", 4, True))
        self.assertEqual(T.decl_text(T.typeof(e), "t"), "s32 t;")


@unittest.skipUnless(HAVE_PYCPARSER, "pycparser not installed")
class FamilyTest(unittest.TestCase):
    def test_temp_not_hoisted_across_a_call_when_reading_a_global(self):
        found = by_label(run(SOURCE, "work", ("temp",)), f"temp: 'gCount + n' {L(SOURCE, 'b = gCount')}")
        self.assertTrue(found)
        self.assertFalse([v for v in found if "hoisted" in v.label])

    def test_temp_hoists_across_independent_statements(self):
        source = PRELUDE + "void f(s32 *p, s32 a, s32 b) {\n    s32 x;\n    s32 y;\n\n    x = a;\n    y = b;\n    p[0] = (a + b) * 2;\n}\n"
        labels = [v.label for v in run(source, "f", ("temp",))]
        self.assertIn(f"temp: 'a + b' {L(source, 'p[0]')} hoisted to {L(source, 'x = a')}", labels)

    def test_temp_for_global_read_and_address(self):
        source = PRELUDE + "extern s32 gCmd;\nextern s32 gTab[];\nvoid f(s32 *p, s32 i) {\n    p[0] = gCmd;\n    p[1] = *&gTab[i];\n}\n"
        labels = [v.label for v in run(source, "f", ("temp",))]
        self.assertIn("temp: 'gCmd' L6 before statement", labels)
        self.assertIn("temp: '&gTab[i]' L7 before statement", labels)
        self.assertFalse([l for l in labels if "'p'" in l or "'i'" in l])       # register locals: no

    def test_temp_reuse_stops_at_a_conflicting_write(self):
        source = PRELUDE + ("void f(s32 *p, s32 a, s32 b) {\n    p[0] = a + b;\n    p[1] = a + b;\n"
                            "    a = 3;\n    p[2] = a + b;\n}\n")
        reuse = by_label(run(source, "f", ("temp",)), f"temp: 'a + b' {L(source, 'p[0]')} reused")
        self.assertEqual(len(reuse), 1)
        self.assertIn("reused x2", reuse[0].label)
        self.assertIn("p[2] = a + b;", reuse[0].source)

    def test_inline_temp_once_used_local(self):
        source = PRELUDE + "extern s32 g;\nvoid f(s32 *p, s32 n) {\n    s32 t;\n\n    t = n * 3;\n    *p = t + 1;\n}\n"
        found = run(source, "f", ("inline-temp",))
        self.assertEqual(len(found), 1)
        self.assertFalse(found[0].semantic_review)
        self.assertIn("*p = (n * 3) + 1;", found[0].source.replace("n * 3 + 1", "(n * 3) + 1"))
        self.assertNotIn("s32 t;", found[0].source)

    def test_inline_temp_into_switch_condition(self):
        source = PRELUDE + "extern s32 gMode;\nextern void g(void);\nvoid f(void) {\n    s32 t;\n\n    t = gMode;\n    switch (t) {\n    case 1:\n        g();\n        break;\n    }\n}\n"
        found = run(source, "f", ("inline-temp",))
        self.assertEqual(len(found), 1)
        self.assertIn("switch (gMode)", found[0].source)

    def test_inline_temp_refused_when_an_operand_is_rewritten(self):
        source = PRELUDE + "void f(s32 *p, s32 n) {\n    s32 t;\n\n    t = n * 3;\n    n = 0;\n    *p = t + n;\n}\n"
        self.assertEqual(run(source, "f", ("inline-temp",)), [])

    def test_inline_memory_read_across_a_store_needs_review(self):
        source = PRELUDE + ("extern s32 *gp;\nextern void use(s32);\nvoid f(s32 *q) {\n    s32 t;\n\n    t = *gp;\n"
                            "    if (t != 0) {\n        *q = 1;\n        use(t);\n    }\n}\n")
        found = run(source, "f", ("inline-temp",))
        self.assertEqual(len(found), 1)
        self.assertTrue(found[0].semantic_review)
        self.assertIn("if (*gp != 0)", found[0].source)

    def test_inline_narrowing_adds_cast(self):
        source = PRELUDE + "void f(u8 *p, s32 n) {\n    s16 t;\n\n    t = n + 1;\n    *p = t;\n}\n"
        found = run(source, "f", ("inline-temp",))
        self.assertTrue(any("with cast" in v.label and not v.semantic_review and "(s16) (n + 1)" in v.source.replace("(s16)(", "(s16) (")
                            for v in found))
        self.assertTrue(any(v.semantic_review for v in found))

    def test_stmt_order_refuses_pointer_store_and_load(self):
        labels = [v.label for v in run(SOURCE, "work", ("stmt-order",))]
        self.assertFalse([l for l in labels if "'*p = a;'" in l and "down" in l])
        self.assertFalse([l for l in labels if "'c = *q;'" in l and "up" in l])

    def test_stmt_order_moves_independent_statement(self):
        source = PRELUDE + "extern s32 g;\nvoid f(s32 a, s32 b) {\n    s32 x;\n    s32 y;\n\n    x = a + 1;\n    y = b + 2;\n    g = x + y;\n}\n"
        found = run(source, "f", ("stmt-order",))
        # moving x down and y up give the same text: deduplicated
        self.assertEqual([v.label for v in found], ["stmt-order: move 'x = a + 1;' L8 down 1"])
        self.assertIn("    s32 y;\n\n    y = b + 2;\n    x = a + 1;\n    g = x + y;", found[0].source)
        self.assertFalse(any("g = x + y" in v.label for v in found))

    def test_control_negation_de_morgan(self):
        found = by_label(run(SOURCE, "work", ("control",)), "control: invert if/else")
        texts = [v.source for v in found]
        self.assertTrue(any("if (a && b) {" in t for t in texts))           # !!(...) removed
        source = PRELUDE + "extern void g(void);\nvoid f(s32 a, s32 b) {\n    if (a < 0 && b == 1) g(); else a = 2;\n}\n"
        inv = by_label(run(source, "f", ("control",)), "control: invert if/else")
        self.assertIn("if (a >= 0 || b != 1)", inv[0].source)
        self.assertIn("if (!(a < 0 && b == 1))", inv[1].source)

    def test_float_comparisons_are_not_flipped(self):
        source = "typedef float f32;\nextern void g(void);\nvoid f(f32 a) {\n    if (a < 1.0f) g(); else a = 2;\n}\n"
        inv = by_label(run(source, "f", ("control",)), "control: invert if/else")
        self.assertEqual(len(inv), 1)
        self.assertIn("if (!(a < 1.0f))", inv[0].source)

    def test_for_to_while_refused_with_continue(self):
        ok = PRELUDE + "extern void g(s32);\nvoid f(s32 n) {\n    s32 i;\n\n    for (i = 0; i < n; i++) {\n        g(i);\n    }\n}\n"
        bad = ok.replace("g(i);", "if (i == 3) continue;\n        g(i);")
        self.assertTrue(by_label(run(ok, "f", ("control",)), "control: for -> init+while"))
        self.assertFalse(by_label(run(bad, "f", ("control",)), "control: for -> init+while"))
        out = by_label(run(ok, "f", ("control",)), "control: for -> init+while")[0].source
        self.assertIn("i = 0;\n    while (i < n) {\n        g(i);\n        i++;\n    }", out)

    def test_while_if_do_and_back(self):
        source = PRELUDE + "extern s32 h(void);\nextern void g(void);\nvoid f(s32 n) {\n    while (n) {\n        n--;\n    }\n    while (h() != 0) {\n        g();\n    }\n}\n"
        found = run(source, "f", ("control",))
        rotated = by_label(found, f"control: while -> if+do-while {L(source, 'while (n)')}")
        self.assertTrue(rotated)
        self.assertFalse(by_label(found, f"control: while -> if+do-while {L(source, 'while (h')}"))     # side-effecting condition
        guarded = PRELUDE + "extern s32 h(void);\nextern void g(void);\nvoid f(void) {\n    if (h() != 0) {\n        do {\n            g();\n        } while (h() != 0);\n    }\n}\n"
        back = by_label(run(guarded, "f", ("control",)), "control: if+do-while -> while")
        self.assertTrue(back)                                           # allowed: same evaluation count
        self.assertIn("while (h() != 0) {\n        g();\n    }", back[0].source)

    def test_loop_rotation_m2c_form(self):
        draft = PRELUDE + "extern void f2(s32);\nvoid f(void) {\n    s32 i;\n\n    i = 0;\n    do {\n        f2(i);\n        i += 1;\n    } while (i < 5);\n}\n"
        found = run(draft, "f", ("control",))
        rot = by_label(found, "control: init+do-while -> for")
        self.assertEqual(len(rot), 1)
        self.assertFalse(rot[0].semantic_review)                       # 0 < 5 on entry
        self.assertIn("for (i = 0; i < 5; i += 1) {\n        f2(i);\n    }", rot[0].source)
        unknown = draft.replace("i = 0;", "i = g0();").replace("extern void f2", "extern s32 g0(void);\nextern void f2")
        self.assertTrue(by_label(run(unknown, "f", ("control",)), "control: do-while -> while")[0].semantic_review)

    def test_void_early_return(self):
        nested = PRELUDE + "extern void X(void);\nextern void g(void);\nvoid f(s32 a, s32 b) {\n    if (a == 0) {\n        if (b == 0) {\n            X();\n        }\n    } else {\n        g();\n    }\n}\n"
        found = by_label(run(nested, "f", ("control",)), f"control: if-block -> early return {L(nested, 'if (b')}")
        self.assertTrue(found)
        self.assertIn("if (b != 0) {\n            return;\n        }\n        X();", found[0].source)
        back = by_label(run(found[0].source, "f", ("control",)), "control: early return -> if-block")
        self.assertIn(nested, [v.source for v in back])
        nonvoid = nested.replace("void f(", "s32 f(")
        self.assertFalse(by_label(run(nonvoid, "f", ("control",)), "control: if-block -> early return"))

    def test_and_split_and_ternary(self):
        source = PRELUDE + "extern void g(void);\nvoid f(s32 a, s32 b, s32 *p) {\n    if (a && b) {\n        g();\n    }\n    *p = a ? b : 3;\n}\n"
        found = run(source, "f", ("control",))
        split = by_label(found, "control: split &&")[0]
        self.assertIn("if (a) {\n        if (b) {\n            g();\n        }\n    }", split.source)
        merged = by_label(run(split.source, "f", ("control",)), "control: merge nested ifs")
        self.assertIn(source, [v.source for v in merged])
        tern = by_label(found, "control: ternary -> if/else")[0]
        back = by_label(run(tern.source, "f", ("control",)), "control: if/else -> ternary")
        self.assertIn(source.replace("*p = a ? b : 3;", "*p = (a) ? (b) : (3);"),
                      [v.source.replace("a ? b : 3", "(a) ? (b) : (3)") for v in back])

    def test_expr_forms(self):
        source = PRELUDE + ("typedef struct { s32 f; } S;\nvoid f(s32 *p, S *s, s32 i, s32 x) {\n    p[i] = x + 1;\n"
                            "    s->f = x;\n    x += 2;\n    i++;\n    if (x <= 5) p = &p[i];\n    if (!x) p[0] = 0;\n}\n")
        labels = [v.label for v in run(source, "f", ("expr",))]
        for expected in ("expr: deref-sum 'p[i]' L5", "expr: commute 'x + 1' L5", "expr: (*p).f 's->f' L6",
                         "expr: expand 'x += 2' L7", "expr: x+=1 'i++' L8", "expr: ++x 'i++' L8",
                         "expr: bound 'x <= 5' L9", "expr: ptr-sum '&p[i]' L9", "expr: ==0 '!x' L10",
                         "expr: != 0 'x' L10"):
            self.assertIn(expected, labels)
        self.assertFalse([l for l in labels if "a - b" in l])

    def test_commute_refused_with_side_effects(self):
        source = PRELUDE + "extern s32 h(void);\nvoid f(s32 *p, s32 x) {\n    *p = h() + x;\n    *p = x * 2;\n}\n"
        labels = [v.label for v in run(source, "f", ("expr",))]
        self.assertNotIn("expr: commute 'h() + x' L5", labels)
        self.assertIn("expr: commute 'x * 2' L6", labels)

    def test_cast_family_is_always_reviewed(self):
        source = PRELUDE + "void f(u8 *p, s32 x) {\n    s32 y;\n\n    y = (s32)(x + 1);\n    *p = y & 0xFF;\n}\n"
        found = run(source, "f", ("cast",))
        self.assertTrue(by_label(found, "cast: local y s32 -> u16"))
        self.assertTrue(by_label(found, "cast: param x s32 -> s16"))
        redundant = by_label(found, "cast: remove '(s32) (x + 1)'")[0]
        self.assertFalse(redundant.semantic_review)                   # assignment converts anyway
        mask = by_label(found, "cast: drop mask 'y & 0xFF'")[0]
        self.assertTrue(mask.semantic_review)                         # y is s32: not provably redundant
        self.assertTrue(all(v.semantic_review for v in found if v.label.startswith("cast: (")))

    def test_decl_order_and_scope(self):
        source = PRELUDE + "extern void g(s32);\nvoid f(s32 n) {\n    s32 a;\n    s32 b;\n\n    if (n) {\n        b = n;\n        g(b);\n    }\n    a = 1;\n    g(a);\n}\n"
        found = run(source, "f", ("decl-order",))
        labels = [v.label for v in found]
        self.assertIn("decl-order: move a L5 down 1", labels)
        inner = by_label(found, "decl-order: move b L6 into block")[0]
        self.assertIn("if (n) {\n        s32 b;\n        b = n;", inner.source)
        out = by_label(run(inner.source, "f", ("decl-order",)), "decl-order: move b")
        self.assertIn(source, [v.source for v in out])
        self.assertFalse([l for l in labels if "move a" in l and "into" in l])   # a used in the function block

    def test_block_and_sameline(self):
        source = PRELUDE + "extern void g(s32);\nvoid f(s32 n) {\n    while (n) {\n        g(n);\n        break;\n    }\n    g(1);\n    g(2);\n}\n"
        found = run(source, "f", ("block", "sameline"))
        labels = [v.label for v in found]
        self.assertIn("block: wrap L9 in do-while(0)", labels)
        self.assertIn("block: wrap L5 in do-while(0)", labels)       # the break is inside the loop
        joined = by_label(found, "sameline: join L9+L10")[0]
        self.assertIn("    g(1); g(2);\n", joined.source)
        split = by_label(run(joined.source, "f", ("sameline",)), "sameline: split L9")
        self.assertEqual(split[0].source, source)
        wrapped = by_label(found, "block: wrap L9 in do-while(0)")[0]
        unwrapped = by_label(run(wrapped.source, "f", ("block",)), "block: unwrap do-while(0)")
        self.assertEqual(unwrapped[0].source, source)

    def test_do_wrap_refused_around_break(self):
        source = PRELUDE + "extern void g(s32);\nvoid f(s32 n) {\n    while (n) {\n        g(n);\n        break;\n    }\n}\n"
        labels = [v.label for v in run(source, "f", ("block",))]
        self.assertNotIn("block: wrap L7 in do-while(0)", labels)
        self.assertIn("block: wrap L7 in if (1)", labels)

    def test_interfaces(self):
        self.assertEqual(astforms.FAMILIES[0], "temp")
        v = run(SOURCE, "work", ("expr",), limit=1)[0]
        self.assertIsInstance(v, iterate.Variant)


# ------------------------------------------------------------------------------ real compilers
def _compiler(pipeline, flags):
    try:
        from n64dk.elf import Elf
        from n64dk.match import compare as cmp
        from n64dk.match.pipeline import build, split_flags
        from n64dk.match.toolchain import load_config
    except Exception as error:                                   # pragma: no cover
        return None, str(error)
    project = Path(_scratch("n64dk-astforms-"))
    cfg = load_config(project, None, None)
    key = "kmc" if pipeline.startswith("kmc") else pipeline.replace(".", "")
    from n64dk.match.pipeline import TOOLCHAIN_OF
    if cfg.toolchain(TOOLCHAIN_OF.get(pipeline, "kmc")) is None:
        return None, f"{pipeline} toolchain not configured (N64DK_TOOLCHAIN)"
    spec = split_flags(flags, pipeline)
    counter = [0]

    def compile_text(text):
        counter[0] += 1
        folder = project / f"c{counter[0]}"
        folder.mkdir()
        path = folder / "unit.c"
        path.write_text(text)
        return cmp.find_section(Elf.load(build(path, spec, cfg, folder, includes=[])), ".text").data
    return compile_text, None


TRUTHS = {
    "loop": PRELUDE + "extern void f2(s32);\nvoid f(s32 n) {\n    s32 i;\n\n    for (i = 0; i < n; i++) {\n        f2(i);\n    }\n}\n",
    "temp": PRELUDE + "extern s32 gA[];\nvoid f(s32 *p, s32 i) {\n    p[0] = gA[i] + 3;\n    p[1] = gA[i] * 5;\n}\n",
    "order": PRELUDE + "void f(s32 *p, s32 *q, s32 a, s32 b) {\n    s32 x;\n    s32 y;\n\n    x = a * 3;\n    y = b * 5;\n    p[0] = x;\n    q[0] = y;\n}\n",
    "early": PRELUDE + "extern void g(s32);\nvoid f(s32 a, s32 b) {\n    if (a == 0) {\n        if (b != 0) {\n            return;\n        }\n        g(1);\n    } else {\n        g(2);\n    }\n}\n",
}


def _perturb_and_recover(test, compile_text, truth, family, name="f", budget=200):
    ref = compile_text(truth)
    perturbed = None
    for v in astforms.variants(truth, name, (family,), limit=None):
        if compile_text(v.source) != ref:
            perturbed = v
            break
    if perturbed is None:
        test.skipTest(f"no {family} variant changes the object")

    def evaluate(text):
        try:
            data = compile_text(text)
        except Exception:
            return iterate.Evaluation(None, error="build")
        diff = sum(1 for k in range(0, max(len(data), len(ref)), 4) if data[k:k + 4] != ref[k:k + 4])
        return iterate.Evaluation(diff, exact=data == ref)
    saved = iterate.variants
    iterate.variants = lambda s, n, families=(), reach=6: astforms.variants(s, n, astforms.FAMILIES, limit=160)
    try:
        result = iterate.descend(perturbed.source, name, evaluate, families=astforms.FAMILIES, budget=budget, jobs=2)
    finally:
        iterate.variants = saved
    test.assertTrue(result["exact"], f"{perturbed.label}: {result.get('final_score')}")


IDO_FLAGS = ["-O2", "-mips2", "-non_shared", "-G", "0", "-Xcpluscomm", "-Wab,-r4300_mul"]
KMC_FLAGS = ["-O2", "-G0", "-mips3", "-mgp32", "-mfp32"]


@unittest.skipUnless(HAVE_PYCPARSER, "pycparser not installed")
class IdoRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compile_text, reason = _compiler("ido5.3", IDO_FLAGS)
        if compile_text is None:
            raise unittest.SkipTest(reason)
        cls.compile = staticmethod(compile_text)

    def test_loop_rotation(self):
        _perturb_and_recover(self, self.compile, TRUTHS["loop"], "control")

    def test_temp(self):
        _perturb_and_recover(self, self.compile, TRUTHS["temp"], "temp")

    def test_early_return(self):
        _perturb_and_recover(self, self.compile, TRUTHS["early"], "control")

    def test_same_line_statements(self):
        # IDO's output depends on which statements share a source line
        _perturb_and_recover(self, self.compile, TRUTHS["order"], "sameline")


@unittest.skipUnless(HAVE_PYCPARSER, "pycparser not installed")
class KmcRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compile_text, reason = _compiler("kmc+builtin", KMC_FLAGS)
        if compile_text is None:
            raise unittest.SkipTest(reason)
        cls.compile = staticmethod(compile_text)

    def test_block_wrapping(self):
        _perturb_and_recover(self, self.compile, TRUTHS["order"], "block")

    def test_temp(self):
        _perturb_and_recover(self, self.compile, TRUTHS["temp"], "temp")

    def test_loop(self):
        _perturb_and_recover(self, self.compile, TRUTHS["loop"], "control")


class ConstantFalseLoopTest(unittest.TestCase):
    """``do { ... } while (0)`` must never become a pre-tested loop: the body would stop running."""

    def test_no_pretested_form_of_a_do_while_zero(self):
        source = ("typedef int s32;\nextern s32 g;\n\nvoid f(void) {\n    s32 i;\n\n    i = 1;\n    do {\n        g = i;\n"
                  "        i += 1;\n    } while (0);\n    g = 2;\n}\n")
        offered = astforms.variants(source, "f", ("control",), limit=64, check=False)
        self.assertFalse([v.label for v in offered if "while (0) {" in v.source or "; 0; " in v.source])
        self.assertFalse([v.label for v in offered if "do-while -> while" in v.label or "do-while -> for" in v.label])

    def test_a_real_rotated_loop_is_still_offered(self):
        source = ("typedef int s32;\nextern s32 g;\n\nvoid f(void) {\n    s32 i;\n\n    i = 0;\n    do {\n        g = i;\n"
                  "        i += 1;\n    } while (i < 5);\n}\n")
        labels = [v.label for v in astforms.variants(source, "f", ("control",), limit=64, check=False)]
        self.assertTrue(any("do-while -> while" in label for label in labels), labels)


if __name__ == "__main__":
    unittest.main()
