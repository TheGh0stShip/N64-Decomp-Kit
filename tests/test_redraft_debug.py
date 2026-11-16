"""Round trips for the two unoptimised-code translators: compile a small function without
optimisation, hand its machine code to the translator, compile what it writes, compare bytes."""
import atexit
import shutil
import tempfile
import unittest
from pathlib import Path

from n64dk.match import redraft, redraft_gcc_debug, redraft_ido_debug

TYPES = "typedef signed char s8; typedef unsigned char u8; typedef short s16; typedef unsigned short u16;\n" \
        "typedef int s32; typedef unsigned int u32; typedef float f32; typedef double f64;\n"
EXTERNALS = "extern s32 D_80100000; extern s32 D_80100010[]; extern u8 D_80100100[]; extern s16 D_80100200;\n" \
            "s32 func_80002000(s32, s32); void func_80002100(void);\n" \
            "struct S { s32 a; s16 b; u8 c; s8 d; s32 e[4]; struct S *next; };\n"
PROGRAMS = {
    "arith": "s32 f(s32 a, s32 b) {\n    s32 x;\n    s32 y;\n\n    x = a + b;\n    y = x * 2;\n    if (y > 10) {\n"
             "        y = y - a;\n    }\n    return y;\n}\n",
    "loop": "s32 f(s32 n) {\n    s32 i;\n    s32 t;\n\n    t = 0;\n    for (i = 0; i < n; i++) {\n        t += i;\n    }\n"
            "    return t;\n}\n",
    "bytes": "void f(u8 *p, s32 n) {\n    s32 i;\n\n    for (i = 0; i < n; i++) {\n        p[i] = 0;\n    }\n}\n",
    "dead": "void f(s32 a) {\n    s32 unused;\n\n    unused = a + 3;\n}\n",
    "call": "s32 f(s32 a) {\n    s32 r;\n\n    r = func_80002000(a, 3);\n    func_80002100();\n    return r + 1;\n}\n",
    "global": "void f(s32 a) {\n    D_80100000 = a;\n    D_80100010[2] = D_80100000 + 1;\n    D_80100200 = 5;\n}\n",
    "index": "s32 f(s32 i) {\n    return D_80100010[i] + D_80100100[i];\n}\n",
    "field": "s32 f(struct S *p) {\n    p->a = 1;\n    p->b = 2;\n    p->c = 3;\n    return p->e[1] + p->d;\n}\n",
    "while": "s32 f(struct S *p) {\n    s32 n;\n\n    n = 0;\n    while (p != 0) {\n        n++;\n        p = p->next;\n    }\n"
             "    return n;\n}\n",
    "dowhile": "s32 f(s32 n) {\n    s32 t;\n\n    t = 0;\n    do {\n        t += n;\n        n--;\n    } while (n > 0);\n"
               "    return t;\n}\n",
    "ifelse": "s32 f(s32 a, s32 b) {\n    s32 r;\n\n    if (a < b) {\n        r = a;\n    } else if (a == b) {\n        r = 0;\n"
              "    } else {\n        r = b;\n    }\n    return r;\n}\n",
    "logic": "s32 f(s32 a, s32 b) {\n    if (a > 0 && b > 0) {\n        return 1;\n    }\n    if (a < 0 || b < 0) {\n"
             "        return 2;\n    }\n    return 0;\n}\n",
    "narrow": "s32 f(u8 a, s16 b) {\n    u8 x;\n    s16 y;\n\n    x = a + 1;\n    y = b - x;\n    return y;\n}\n",
    "float": "f32 f(f32 a, f32 b) {\n    f32 r;\n\n    r = a * b + 1.5f;\n    if (r < a) {\n        r = a;\n    }\n    return r;\n}\n",
    "fcall": "f32 func_80002200(f32, s32);\nf32 f(f32 a, s32 n) {\n    return func_80002200(a * 2.0f, n) - 0.25f;\n}\n",
    "fconv": "f32 f(s32 n, f32 x) {\n    s32 k;\n\n    k = x;\n    return n + k * 0.5f;\n}\n",
    "fcmp": "s32 f(f32 a, f32 b) {\n    if (a > b) {\n        return 1;\n    }\n    if (a <= b) {\n        return 2;\n    }\n"
            "    if (a == b) {\n        return 3;\n    }\n    return 0;\n}\n",
    "fglobal": "extern f32 D_80100300; extern f32 D_80100310[];\nvoid f(s32 i) {\n    D_80100300 = D_80100310[i] / 3.0f;\n}\n",
    "switch3": "s32 f(s32 a) {\n    s32 r;\n\n    r = 0;\n    switch (a) {\n    case 1:\n        r = 10;\n        break;\n"
               "    case 2:\n        r = 20;\n    case 5:\n        r += 3;\n        break;\n    default:\n        r = -1;\n    }\n"
               "    return r;\n}\n",
    "gfx": "typedef struct { s32 w0; s32 w1; } G;\nextern G *D_80100400;\nvoid f(void) {\n    G *g;\n\n"
           "    g = D_80100400++;\n    g->w0 = 0x06000000;\n    g->w1 = 5;\n    g = D_80100400++;\n    g->w0 = 7;\n}\n",
    "manyargs": "void f(s16 a, s16 b, s16 c, s16 d, s16 e, u8 g) {\n    D_80100200 = a + e + g;\n}\n",
    "midinc": "struct R { s32 a; s32 n; u8 *q; };\nvoid f(u8 *out, s32 count, struct R *r) {\n    s32 i;\n\n"
              "    for (i = 0; i < count; i++) {\n        out[i] = r->q[r->n++];\n    }\n}\n",
    "logicval": "s32 f(s32 a, s32 b) {\n    s32 r;\n\n    r = a < -5 || a > 5;\n    return r && b != 3;\n}\n",
    "ternary": "s32 f(s32 a, s32 b) {\n    return func_80002000(a, (a & 4) ? 0x1234 : b) + 1;\n}\n",
    "array": "s32 f(void) {\n    s32 buf[4];\n    s32 i;\n\n    for (i = 0; i < 4; i++) {\n        buf[i] = i;\n    }\n"
             "    return buf[2];\n}\n",
    "switch": "s32 f(s32 a) {\n    switch (a) {\n    case 1:\n        return 10;\n    case 2:\n        return 20;\n    }\n"
              "    return 0;\n}\n",
    "address": "s32 f(void) {\n    s32 v;\n\n    v = 4;\n    return func_80002000((s32) &v, v);\n}\n",
    "unsigned": "u32 f(u32 a, u32 b) {\n    if (a < b) {\n        return b / a;\n    }\n    return a >> 3;\n}\n",
}
VRAM = 0x80001000


def _compiler(pipeline: str, flags: list[str], key: str):
    try:
        from n64dk.elf import Elf
        from n64dk.match import compare as cmp
        from n64dk.match.pipeline import build, split_flags
        from n64dk.match.symbols import SymbolMap
        from n64dk.match.toolchain import load_config
    except Exception as error:                                # pragma: no cover
        return None, str(error)
    project = Path(tempfile.mkdtemp(prefix="n64dk-debug-test-"))
    atexit.register(shutil.rmtree, project, True)
    cfg = load_config(project, None, None)
    if cfg.toolchain(key) is None:
        return None, f"{key} toolchain not configured (N64DK_TOOLCHAIN)"
    spec, counter = split_flags(flags, pipeline), [0]

    def compile_text(text: str) -> bytes:
        counter[0] += 1
        folder = project / f"c{counter[0]}"
        folder.mkdir()
        (folder / "f.c").write_text(text)
        elf = Elf.load(build(folder / "f.c", spec, cfg, folder))
        # placed at VRAM as a linker would; external names carry their own addresses
        code = cmp.relocate(elf, ".text", {".text": VRAM}, SymbolMap())
        last = max(at for at in range(0, len(code), 4) if code[at:at + 4] == b"\x03\xe0\x00\x08")
        return code[:last + 8]         # up to the last return and its delay slot (a debug build's unreachable ones included): no padding
    return compile_text, None


class RoundTrip:
    module = None
    pipeline, flags, key = "", [], ""
    expected = ()

    @classmethod
    def setUpClass(cls):
        found, reason = _compiler(cls.pipeline, cls.flags, cls.key)
        if found is None:
            raise unittest.SkipTest(reason)
        cls.compile = staticmethod(found)

    def round_trip(self, program: str) -> bool:
        target = self.compile(TYPES + EXTERNALS + PROGRAMS[program])
        found = self.module.variants(TYPES, "f", code=target, vram=VRAM, pipeline=self.pipeline,
                                     flags=tuple(self.flags), family=None)
        for _label, text in found:
            try:
                if self.compile(text) == target:
                    return True
            except Exception:
                continue
        return False

    def test_small_functions_come_back_byte_identical(self):
        results = {program: self.round_trip(program) for program in PROGRAMS}
        self.assertTrue({p for p, ok in results.items() if ok} >= set(self.expected), results)

    def test_optimised_code_is_not_this_generators_business(self):
        optimised, reason = _compiler(self.pipeline, ["-O2" if f in ("-O0", "-g") else f for f in self.flags], self.key)
        code = optimised(TYPES + EXTERNALS + PROGRAMS["arith"])
        self.assertEqual(self.module.variants(TYPES, "f", code=code, vram=VRAM, pipeline=self.pipeline,
                                              flags=("-O2",), family=None), [])


class GccDebugTest(RoundTrip, unittest.TestCase):
    module = redraft_gcc_debug
    pipeline, flags, key = "kmc+as", ["-O0", "-G0", "-mips3", "-mgp32", "-mfp32"], "kmc"
    expected = tuple(name for name in PROGRAMS if name not in ("logicval", "ternary"))   # known gaps: || and ?: as values


class IdoDebugTest(RoundTrip, unittest.TestCase):
    module = redraft_ido_debug
    pipeline, flags, key = "ido5.3", ["-g", "-mips2", "-non_shared", "-G", "0", "-Xcpluscomm", "-Wab,-r4300_mul"], "ido53"
    expected = tuple(name for name in PROGRAMS if name not in ("index",))         # known gap: operand order of two array loads


class RegistrationTest(unittest.TestCase):
    def test_both_translators_are_registered_and_decline_what_they_do_not_know(self):
        self.assertIn("redraft_gcc_debug", redraft.GENERATORS)
        self.assertIn("redraft_ido_debug", redraft.GENERATORS)
        junk = bytes(range(64))
        for module in (redraft_gcc_debug, redraft_ido_debug):
            self.assertEqual(module.variants("", "f", code=junk, vram=VRAM, pipeline="x", flags=()), [])
            self.assertEqual(module.variants("", "f", code=b"", vram=VRAM, pipeline="x", flags=()), [])


if __name__ == "__main__":
    unittest.main()
