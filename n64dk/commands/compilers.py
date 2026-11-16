"""``compilers``: which of the compilers known to have built N64 code this machine can use."""
from __future__ import annotations

import os
from pathlib import Path

from ..cli import command


@command("compilers", "List every compiler known to have built N64 retail code and which are installed and usable; "
                      "--fetch downloads missing ones")
def compilers(args):
    from ..match import compilers as catalogue
    root = args.toolchain_dir or os.environ.get("N64DK_TOOLCHAIN")
    root = Path(root).expanduser() if root else None
    fetched = []
    if args.fetch is not None:
        if root is None:
            raise SystemExit("--fetch needs a toolchain root: --toolchain-dir DIR or N64DK_TOOLCHAIN")
        wanted = args.fetch or [row["id"] for row in catalogue.status(root)["compilers"] if not row["installed"]]
        for ident in wanted:
            try:
                fetched.append(catalogue.fetch(ident, root, force=args.force))
            except catalogue.FetchError as error:
                fetched.append({"id": ident, "status": "failed", "error": str(error)[-300:]})
            except Exception as error:                       # network trouble is a result, not a crash
                fetched.append({"id": ident, "status": "failed", "error": f"{type(error).__name__}: {error}"[-300:]})
    report = catalogue.status(root)
    if fetched:
        report["fetched"] = fetched
    return report


def _args(p):
    p.add_argument("--toolchain-dir", help="toolchain root to check or fetch into (default: N64DK_TOOLCHAIN)")
    p.add_argument("--fetch", nargs="*", metavar="ID",
                   help="download these compilers (no ID: every missing one) from the public decomp.me compiler "
                        "archive into the toolchain root; each layer is checked against its SHA-256 before unpacking")
    p.add_argument("--force", action="store_true", help="with --fetch: replace a compiler that is already installed")


compilers.arguments = _args
