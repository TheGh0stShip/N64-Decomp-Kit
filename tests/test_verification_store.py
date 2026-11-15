from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from n64dk.match.pipeline import BuildSpec
from n64dk.match.toolchain import Config
from n64dk.match.verification_store import current, record


class _Proof:
    exact = True

    def as_dict(self):
        return {"verdict": "exact"}


class VerificationReceiptTest(unittest.TestCase):
    def test_target_and_dependency_drift_invalidate_receipt(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); include = root / "include"; include.mkdir()
            header = include / "value.h"; header.write_text("#define VALUE 1\n")
            source = root / "unit.c"; source.write_text('#include "value.h"\nint f(void){return VALUE;}\n')
            image = root / "image.bin"; image.write_bytes(b"ABCD" + b"truth" + b"tail")
            cfg = Config(project=root, include=[include], rom=image)
            spec = BuildSpec("kmc+builtin", ())
            unit = SimpleNamespace(source=source, spec=spec, vram=0x80000004, size=5)
            target = SimpleNamespace(rom=image.read_bytes(), delta=0x80000000)
            outcome = SimpleNamespace(exact=True, proof=_Proof())
            catalogue_vram = 0x80001004
            self.assertEqual(record(root, cfg, target, [unit], [outcome], "main",
                                    {(unit.vram, unit.size): catalogue_vram}), 1)
            self.assertIn(("unit.c", catalogue_vram, unit.size), current(root, cfg))
            self.assertFalse(Path(str(root / ".n64dk" / "verification.sqlite") + "-shm").exists())
            self.assertFalse(Path(str(root / ".n64dk" / "verification.sqlite") + "-wal").exists())

            image.write_bytes(b"ABCD" + b"truth" + b"TAIL")
            self.assertNotIn(("unit.c", catalogue_vram, unit.size), current(root, cfg))

            image.write_bytes(target.rom)
            self.assertIn(("unit.c", catalogue_vram, unit.size), current(root, cfg))
            header.write_text("#define VALUE 2\n")
            self.assertNotIn(("unit.c", catalogue_vram, unit.size), current(root, cfg))


if __name__ == "__main__":
    unittest.main()
