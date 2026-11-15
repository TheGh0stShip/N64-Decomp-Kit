import hashlib
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from n64dk.match import reconcile as rec
from n64dk.match.session import SessionCandidate, SessionStore

GIT = shutil.which("git")
IMAGE = bytes(range(256)) * 16          # 4 KiB synthetic image, offsets 0..0xFFF


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Fixture:
    def __init__(self, root: Path):
        self.project = root / "proj"
        (self.project / "src").mkdir(parents=True)
        self.image = self.project / "ovl_a.z64"
        self.image.write_bytes(IMAGE)
        self.store = SessionStore(self.project / ".n64dk" / "match-sessions")
        self.n = 0

    def exact(self, name, offset, size, source=b"int f(void){return 0;}\n", exact=True,
              target=None, delta=0x80000000):
        sid = self.store.create({"addr": offset + delta, "vram_delta": delta, "size": size,
                                 "rom": str(self.image), "source_name": f"{name}.c",
                                 "target_text_sha256": target or sha(IMAGE[offset:offset + size])})
        digest = self.store.cache.put(source)
        self.n += 1
        cid = sha(f"{sid}{self.n}".encode())
        self.store.append(sid, SessionCandidate(cid, None, digest, "l", "h", "kmc", ("-O2",),
                                                "evaluated", exact, 0 if exact else 4, {},
                                                {"proof": {"verdict": "exact"}} if exact else {},
                                                None, time.time_ns()))
        return sid, cid

    def manifest(self, rows, name="matching_ovl_a_units.tsv"):
        path = self.project / name
        path.write_text("# ROM_START SIZE SOURCE FLAGS\n" + "".join(
            f"0x{s:X}\t0x{z:X}\t{src}\t-O2\n" for s, z, src in rows))
        return path


class ReconcileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self.tmp.name))

    def tearDown(self):
        self.fx.store.close()
        self.tmp.cleanup()

    def run_rec(self, manifests, **kw):
        if "bindings" not in kw:
            kw["bindings"] = {str(path): "ovla" for path in manifests}
        return rec.stranded_exacts(self.fx.project, manifests, **kw)

    def test_six_classes(self):
        fx = self.fx
        src = b"int a(void){return 1;}\n"
        (fx.project / "src/a.c").write_bytes(src)
        (fx.project / "src/b.c").write_bytes(b"different\n")
        fx.exact("a", 0x100, 0x20, src)                     # integrated
        fx.exact("b", 0x200, 0x20)                          # covered-different-source
        fx.exact("c", 0x310, 0x10)                          # covered-by-aggregate
        fx.exact("d", 0x400, 0x10)                          # stale (manifest size differs)
        fx.exact("e", 0x500, 0x40)                          # stranded
        fx.exact("e", 0x500, 0x40)                          # duplicate
        fx.exact("f", 0x600, 0x8, exact=False)              # ignored
        m = fx.manifest([(0x100, 0x20, "src/a.c"), (0x200, 0x20, "src/b.c"),
                         (0x300, 0x40, "src/agg.c"), (0x400, 0x20, "src/d.c")])
        out = self.run_rec([m])
        self.assertEqual(out["exact_candidates"], 6)
        expected = {c: 1 for c in rec.CLASSES}; expected["unverified-proof"] = 0
        self.assertEqual(out["summary"], expected)
        self.assertEqual([q["name"] for q in out["queue"]], ["e"])
        self.assertEqual(len(out["queue"][0]["duplicates"]), 1)
        self.assertEqual(out["queue"][0]["rom_offset"], 0x500)

    def test_stale_target_from_image_bytes(self):
        self.fx.exact("g", 0x700, 0x10, target="0" * 64)
        self.fx.exact("h", 0x800, 0x10)
        out = self.run_rec([], image_bytes=rec.file_image_bytes)
        by = {i["name"]: i for i in out["items"]}
        self.assertEqual(by["g"]["class"], "stale-target")
        self.assertTrue(by["h"]["target_checked"])
        self.assertEqual(by["h"]["class"], "stranded")
        self.assertFalse(self.run_rec([])["items"][0]["target_checked"])

    def test_manifest_binding_is_explicit_and_fails_closed(self):
        self.fx.exact("e", 0x500, 0x40)
        self.fx.image = self.fx.project / "ovl_b.z64"
        self.fx.exact("eb", 0x600, 0x40)                    # makes token "ovlb" known
        other = self.fx.manifest([(0x500, 0x40, "src/e.c")], "matching_ovl_b_units.tsv")
        self.assertEqual(self.run_rec([other], bindings={str(other): "ovlb"})["summary"]["stranded"], 2)
        self.fx.image = self.fx.project / "ovl_a.z64"
        unbound = self.fx.manifest([(0x500, 0x40, "src/e.c")], "units.tsv")
        report = self.run_rec([unbound], bindings={})
        self.assertEqual(report["summary"]["stranded"], 2)
        self.assertEqual(report["unbound_manifests"], [str(unbound)])
        self.assertEqual(self.run_rec([unbound], bindings={str(unbound): "ovla"})
                         ["summary"]["covered-different-source"], 1)
        self.assertEqual(self.run_rec([unbound], bindings={str(unbound): "ovlb"})
                         ["summary"]["stranded"], 2)

    def test_exact_value_variants(self):
        db = self.fx.store.db
        for i, value in enumerate((1, True, "1", 0, False, "0")):
            s, c = self.fx.exact(f"v{i}", 0xA00 + 0x10 * i, 0x10, exact=False)
            db.execute("UPDATE session_candidates SET exact=? WHERE candidate_id=?", (value, c))
        db.commit()
        names = sorted(i["name"] for i in self.run_rec([])["items"])
        self.assertEqual(names, ["v0", "v1", "v2"])

    def test_export_source(self):
        sid, cid = self.fx.exact("e", 0x500, 0x40, b"void e(void){}\n")
        store = self.fx.project / ".n64dk/match-sessions/sessions.sqlite"
        self.assertEqual(rec.export_source(store, sid, cid), "void e(void){}\n")
        self.assertIsNone(rec.export_source(store, sid, "nope"))

    def test_corrupt_and_locked_stores_skipped(self):
        self.fx.exact("e", 0x500, 0x40)
        state = self.fx.project / ".n64dk"
        (state / "bad.sqlite").write_bytes(b"SQLite format 3\x00" + b"\xff" * 200)
        locked = state / "locked.sqlite"
        con = sqlite3.connect(locked)
        con.execute("CREATE TABLE session_candidates(x)")
        con.commit()
        con.execute("BEGIN EXCLUSIVE")
        try:
            scan = rec.find_stores(self.fx.project, [Path(self.tmp.name) / "missing.sqlite"])
        finally:
            con.rollback()
            con.close()
        skipped = {Path(s["path"]).name for s in scan.skipped}
        self.assertIn("bad.sqlite", skipped)
        self.assertIn("locked.sqlite", skipped)
        self.assertIn("missing.sqlite", skipped)
        self.assertEqual([p.name for p in scan.stores], ["sessions.sqlite"])
        self.assertEqual(self.run_rec([], stores=scan)["summary"]["stranded"], 1)

    def test_reading_creates_no_sidecars(self):
        self.fx.exact("e", 0x500, 0x40)
        self.fx.store.close()
        db = self.fx.project / ".n64dk/match-sessions/sessions.sqlite"
        self.assertFalse(Path(f"{db}-wal").exists())
        self.assertEqual(self.run_rec([])["summary"]["stranded"], 1)
        self.assertFalse(Path(f"{db}-wal").exists() or Path(f"{db}-shm").exists())

    def test_target_of_tolerant(self):
        self.assertEqual(rec._target_of({})["rom_offset"], None)
        t = rec._target_of({"addr": 0x80001010, "vram_delta": 0x80000000, "size": 8,
                            "inventory_image": "overlay5", "inventory_name": "fn"})
        self.assertEqual((t["rom_offset"], t["name"], t["image_token"]), (0x1010, "fn", "overlay5"))


@unittest.skipUnless(GIT, "git unavailable")
class WorkspaceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        (self.root / "src").mkdir(parents=True)
        subprocess.run([GIT, "init", "-q", str(self.root)], check=True)
        for rel in ("src/t.c.greg", "src/x.c.greg", "src/y.raw.s", "a.out", "src/keep.c",
                    "src/z.h.greg", ".n64dk/w.c.rtl", "build/q.c.rtl"):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.root / rel).write_text("x")
        subprocess.run([GIT, "-C", str(self.root), "add", "src/t.c.greg"], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_audit_tracked_vs_untracked(self):
        audit = rec.workspace_audit(self.root)
        got = {g["path"]: g["tracked"] for g in audit["generated"]}
        self.assertEqual(got, {"a.out": False, "src/t.c.greg": True, "src/x.c.greg": False,
                               "src/y.raw.s": False})
        self.assertEqual(sorted(audit["plan"]), ["a.out", "src/x.c.greg", "src/y.raw.s"])

    def test_clean_dry_run_and_apply(self):
        dry = rec.workspace_clean(self.root, ["src/x.c.greg"])
        self.assertTrue((self.root / "src/x.c.greg").exists())
        self.assertEqual(dry["removed"], [])
        outside = Path(self.tmp.name) / "o.c.greg"
        outside.write_text("x")
        (self.root / "src/l.c.greg").symlink_to(self.root / "src/keep.c")
        out = rec.workspace_clean(self.root, ["src/x.c.greg", "src/t.c.greg", "src/l.c.greg",
                                              str(outside), "../o.c.greg", "src/keep.c"],
                                  apply=True)
        self.assertEqual(out["removed"], ["src/x.c.greg"])
        reasons = {r["path"]: r["reason"] for r in out["refused"]}
        self.assertEqual(reasons["src/t.c.greg"], "tracked by git")
        self.assertEqual(reasons["src/l.c.greg"], "symlink")
        self.assertEqual(reasons[str(outside)], "outside project")
        self.assertEqual(reasons["../o.c.greg"], "outside project")
        self.assertEqual(reasons["src/keep.c"], "not a generated pattern")
        self.assertFalse((self.root / "src/x.c.greg").exists())
        self.assertTrue(outside.exists() and (self.root / "src/t.c.greg").exists())


if __name__ == "__main__":
    unittest.main()
