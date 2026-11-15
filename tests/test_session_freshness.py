from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from n64dk.commands.match import _session_context, _session_runtime
from n64dk.match.engine import Target
from n64dk.match.pipeline import BuildSpec
from n64dk.match.toolchain import Config


class SessionFreshnessTest(unittest.TestCase):
    def test_header_change_invalidates_immutable_session(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            include = root / "include"
            include.mkdir()
            header = include / "value.h"
            header.write_text("#define VALUE 1\n")
            source = root / "candidate.c"
            source.write_text('#include "value.h"\nint f(void) { return VALUE; }\n')
            rom = root / "image.z64"
            image = bytearray(0x101000)
            image[:4] = b"\x80\x37\x12\x40"
            rom.write_bytes(image)
            cfg = Config(project=root, include=[include], rom=rom, vram_delta=0x80000000)
            args = SimpleNamespace(rom=str(rom), no_infer=False, addr=None, size=None,
                                   strict_entry=False)
            context = _session_context(args, cfg, Target(bytes(image), 0x80000000,
                                                         (0, len(image))), [],
                                       source, BuildSpec("kmc+builtin", ()), source.read_bytes())
            _session_runtime(context)
            header.write_text("#define VALUE 2\n")
            with self.assertRaisesRegex(RuntimeError, "include closure changed"):
                _session_runtime(context)


if __name__ == "__main__":
    unittest.main()
