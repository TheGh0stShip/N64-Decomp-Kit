import struct
import unittest

from n64dk import fixtures
from n64dk.sdk import analyse, fingerprint
from n64dk.sdk.db import DEFAULT_PATH, Database
from n64dk.sdk.matcher import scan
from n64dk.sdk.signature import KEY_WORDS, KEEP_16, KEEP_26, canon_keep, digest, read_archive


def truth_root(name):
    return fixtures.truth(name)


def entry(name, words, masks, calls=()):
    keep = dict(masks)
    rm = [w & keep.get(i, 0xFFFFFFFF) for i, w in enumerate(words)]
    cm = [w & keep.get(i, 0xFFFFFFFF) & canon_keep(w) for i, w in enumerate(words)]
    n = len(words) * 4
    return {"name": name, "size": n, "exact": digest(rm, n), "canon": digest(cm, n), "key": digest(cm[:KEY_WORDS]),
            "prefix": digest(words[:KEY_WORDS]), "masks": list(masks), "calls": list(calls), "local": False,
            "obj": "x.c", "sources": ["ultralib:2.0X:libultra_rom"], "compilers": ["ido"]}


# addiu sp,-0x18; sw ra,0x14(sp); lui a0,%hi; addiu a0,%lo; jal f; nop; lw ra; addiu sp; jr ra; nop ...
BODY = [0x27BDFFE8, 0xAFBF0014, 0x3C040000, 0x24840000, 0x0C000000, 0x00000000, 0x8C820004, 0x24420001,
        0xAC820004, 0x8FBF0014, 0x27BD0018, 0x03E00008, 0x00000000]
MASKS = [(2, KEEP_16), (3, KEEP_16), (4, KEEP_26)]


def relocated(words, hi, lo, target):
    w = list(words)
    w[2] |= hi
    w[3] |= lo
    w[4] |= (target >> 2) & 0x3FFFFFF
    return w


class SignatureTests(unittest.TestCase):
    def test_canonical_mask(self):
        self.assertEqual(canon_keep(0x0C001234), KEEP_26)          # jal
        self.assertEqual(canon_keep(0x3C048012), KEEP_16)          # lui
        self.assertEqual(canon_keep(0x8FBF0014), 0xFFFFFFFF)       # lw ra,0x14(sp): kept
        self.assertEqual(canon_keep(0x8C820004), KEEP_16)          # lw v0,4(a0)
        self.assertEqual(canon_keep(0x00851021), 0xFFFFFFFF)       # addu

    def test_archive(self):
        def member(name, body):
            hdr = f"{name:<16}{0:<12}{0:<6}{0:<6}{644:<8}{len(body):<10}`\n".encode()
            return hdr + body + (b"\n" if len(body) & 1 else b"")
        data = b"!<arch>\n" + member("/", b"\0\0\0\0") + member("a.o/", b"abc") + member("b.o/", b"defg")
        self.assertEqual(read_archive(data), [("a.o", b"abc"), ("b.o", b"defg")])


class MatcherTests(unittest.TestCase):
    def setUp(self):
        self.db = Database()
        e = entry("osThing", BODY, MASKS)
        self.db.entries[(e["name"], e["exact"])] = e

    def image(self, words_list):
        data = b"".join(struct.pack(f">{len(w)}I", *w) for w in words_list)
        return data

    def test_exact_with_relocations(self):
        code = relocated(BODY, 0x8012, 0x5714, 0x80123450)
        data = self.image([[0] * 4, code, [0] * 4])
        found = scan(data, 0, len(data), 0x80000400, self.db)
        self.assertEqual([(m.vram, m.name, m.kind) for m in found], [(0x80000410, "osThing", "exact")])
        self.assertGreaterEqual(found[0].confidence, 0.95)

    def test_variant_and_mismatch(self):
        variant = relocated(BODY, 1, 2, 0x80000000)
        variant[6] = 0x8C820008  # different struct offset: canonical match only
        other = list(BODY)
        other[1] = 0xAFBF0010   # different $sp-relative save slot: no match
        data = self.image([variant, [0] * 4, other])
        found = scan(data, 0, len(data), 0x80000000, self.db)
        self.assertEqual([(m.vram, m.kind) for m in found], [(0x80000000, "variant")])

    def test_ambiguity_resolved_by_callers(self):
        twin = entry("osTwin", BODY, MASKS)
        self.db.entries[(twin["name"], twin["exact"])] = twin
        # A caller calls the function at 0x80000040 as "osTwin".
        caller_words = [0x27BDFFE8, 0xAFBF0014, 0x0C000000 | (0x80000040 >> 2) & 0x3FFFFFF, 0, 0x24050001,
                        0x24060002, 0x24070003, 0x8FBF0014, 0x27BD0018, 0x03E00008, 0, 0, 0, 0, 0, 0]
        caller = entry("osCaller", caller_words[:11], [(2, KEEP_26)], calls=[(2, "osTwin")])
        self.db.entries[(caller["name"], caller["exact"])] = caller
        data = self.image([caller_words, BODY])
        names = {m.vram: m.name for m in scan(data, 0, len(data), 0x80000000, self.db)}
        self.assertEqual(names[0x80000040], "osTwin")


class FingerprintTests(unittest.TestCase):
    def test_microcode_and_libmus(self):
        blob = bytes(64) + b"RSP Gfx ucode F3DEX       fifo 2.07  Yoshitaka Yasumoto 1998 Nintendo.\0" + bytes(32)
        blob += b"N64 PtrTablesV2\0"
        u = fingerprint.find_microcode(blob)[0]
        self.assertEqual((u.family, u.version, u.variant), ("F3DEX", "2.07", "fifo"))
        self.assertEqual(fingerprint.find_libmus(blob), [(len(blob) - 16, "N64 PtrTablesV2")])

    def test_seqfile(self):
        blob = b"S1" + struct.pack(">H", 2) + struct.pack(">4I", 0x14, 0x10, 0x24, 0x20) + bytes(0x40)
        self.assertEqual([(a.kind, a.count) for a in fingerprint.find_audio(blob)], [("ALSeqFile", 2)])

    def test_compiler_features(self):
        ido = [0x27BDFFE8, 0xAFBF0014, 0x00808025, 0x0C000000, 0, 0x8FBF0014, 0x27BD0018, 0x03E00008, 0]
        gcc = [0x27BDFFE8, 0xAFBF0010, 0x00808021, 0x0C000000, 0, 0x8FBF0010, 0x03E00008, 0x27BD0018]
        fi, fg = fingerprint.function_features(ido), fingerprint.function_features(gcc)
        self.assertTrue(fi["move_or"] and fi["ra_top"] and fi["jr_nop"])
        self.assertTrue(fg["move_addu"] and fg["ra_mid"] and fg["sp_delay"])


@unittest.skipUnless(DEFAULT_PATH.is_file(), "bundled signature database missing")
class DatabaseTests(unittest.TestCase):
    def test_bundled(self):
        db = Database.load()
        names = db.names()
        for name in ("osSendMesg", "osRecvMesg", "osPiStartDma", "alSynNew", "guPerspectiveF", "__ll_div"):
            self.assertIn(name, names)
        self.assertTrue(any(t.startswith("ultralib:2.0L") for t in db.versions()))
        self.assertGreater(db.model.totals.get("ido", 0), 100)
        self.assertGreater(db.model.totals.get("kmc", 0), 100)


def _truth(name):
    root = truth_root(name)
    path = root and root / "config/us/recomp_function_boundaries.toml"
    return path if path and path.is_file() else None


@unittest.skipUnless(DEFAULT_PATH.is_file(), "bundled signature database missing")
class RomTests(unittest.TestCase):
    def run_rom(self, name, exclude=True):
        rom = fixtures.rom(name)
        if rom is None:
            self.skipTest(f"{name} fixture not configured")
        db = Database.load()
        return analyse(rom, db.without_sources([name]) if exclude else db), db

    def check_truth(self, name, rep, db, min_recall):
        path = _truth(name)
        if path is None:
            self.skipTest(f"{name} truth not configured")
        from n64dk.sdk.validate import evaluate, load_truth
        ev = evaluate(rep.matches, load_truth(path), db.without_sources([name]).names())
        self.assertEqual(ev["wrong"], 0, ev["errors"][:10])
        self.assertGreaterEqual(ev["recall"], min_recall)

    def test_battletanx(self):
        rep, db = self.run_rom("battletanx")
        s = rep.summary()
        self.assertEqual(s["game_compiler"], "kmc")
        self.assertIn("2.0I:libultra_rom", s["sdk_version"])
        self.assertTrue(any(v.startswith("F3DEX 1.21") for v in s["microcode"]))
        self.assertEqual(rep.library_compiler and max(rep.library_compiler, key=rep.library_compiler.get), "ido")
        self.check_truth("battletanx", rep, db, 0.75)

    def test_global_assault(self):
        rep, db = self.run_rom("battletanx_ga")
        s = rep.summary()
        self.assertEqual(s["game_compiler"], "kmc")
        self.assertIn("N64 PtrTablesV2", s["libmus"])
        self.assertTrue(any(v.startswith("F3DEX 2.07 fifo") for v in s["microcode"]))
        self.check_truth("battletanx_ga", rep, db, 0.75)

    def test_mk64(self):
        rep, _db = self.run_rom("mk64")
        s = rep.summary()
        self.assertEqual(s["game_compiler"], "ido")
        self.assertGreaterEqual(s["high_confidence"], 100)
        names = {m.name for m in rep.matches}
        self.assertTrue({"osSendMesg", "osRecvMesg", "osCreateThread"} <= names)
        self.assertFalse(any(v.startswith(("2.0J", "2.0K", "2.0L")) for v in s["sdk_version"]))


if __name__ == "__main__":
    unittest.main()
