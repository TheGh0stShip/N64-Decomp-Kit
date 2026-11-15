"""``boundary-solve``, ``ledger-build``, ``ledger-check``, ``ledger-diff``,
``image-registry`` and ``image-address``."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from ..analysis import boundaries as bmod
from ..cli import command
from ..match import images as imgmod
from ..match import byteledger as own


def _int(text: str) -> int:
    return int(text, 0)


def _load_image(path: str, delta: int | None) -> tuple[bytes, int]:
    if delta is not None:
        return Path(path).read_bytes(), delta
    from ..match.engine import Target
    from ..rom import Rom
    target = Target.from_rom(Rom.load(path))
    return target.rom, target.delta


def _also(specs: list[str]) -> list[bmod.Image]:
    out = []
    for spec in specs or []:
        path, _sep, delta = spec.rpartition(":")
        out.append(bmod.Image(*_load_image(path, _int(delta))))
    return out


def _manifest_rows(paths, delta, cls) -> list[own.ManifestRow]:
    rows = []
    for path in paths or []:
        rows += own.read_manifest(path, delta, cls)
    return rows


# ---------------------------------------------------------------------------------------------

def _solve_args(p):
    p.add_argument("image", help="linear image or ROM")
    p.add_argument("--vram-delta", type=_int, help="VRAM minus file offset (omit for a ROM with a boot segment)")
    p.add_argument("--catalogue", required=True)
    p.add_argument("--catalogue-shift", type=_int, default=0, help="catalogue address minus link address")
    p.add_argument("--also", action="append", default=[], metavar="IMAGE:DELTA",
                   help="another image whose calls may target this one")
    p.add_argument("--manifest", action="append", default=[], help="manifest claims (protected only with --verdicts)")
    p.add_argument("--verdicts", help="strict KEY VERDICT receipt file; only exact rows are protected")
    p.add_argument("--manifest-delta", type=_int, help="file-offset base of the manifests (default: --vram-delta)")
    p.add_argument("--min-confidence", type=float, default=0.8)
    p.add_argument("--keep-padding", action="store_true", help="the project keeps trailing padding in functions")
    p.add_argument("--name-format", default="func_{vram:08X}")
    p.add_argument("--out", help="directory for operations.json, the corrected catalogue and inverse.json")
    p.add_argument("--force", action="store_true", help="allow --out inside the catalogue's directory")
    p.add_argument("--show", type=int, default=0, help="list this many operations at or above the threshold")


@command("boundary-solve", "Turn boundary evidence into reversible catalogue operations (merge, split, extend, "
         "shrink, retype, add) with confidence and evidence; never alters manifest-verified intervals")
def boundary_solve(args):
    data, delta = _load_image(args.image, args.vram_delta)
    image = bmod.Image(data, delta)
    original = bmod.read_catalogue(args.catalogue)
    rows = bmod.shift_rows(original, -args.catalogue_shift)
    manifest = _manifest_rows(args.manifest, args.manifest_delta if args.manifest_delta is not None else delta, "c")
    verdict_path = getattr(args, "verdicts", None)
    verdicts = own.read_verdicts(verdict_path) if verdict_path else {}
    proven = [row for row in manifest if verdicts.get(row.source) or verdicts.get(own.hx(row.vram))]
    verified = bmod.Verified(own.verified_intervals(proven))
    stats: dict = {}
    ops = bmod.solve(image, rows, _also(args.also), verified, keep_padding=args.keep_padding,
                     name_format=args.name_format, name_shift=args.catalogue_shift, stats=stats)
    in_image = [r for r in rows if image.lo <= r[1] and r[1] + r[2] <= image.hi]
    new, applied, skipped = bmod.apply(in_image, ops, args.min_confidence)
    info = bmod.summary(in_image, ops, new, args.min_confidence)
    info["catalogue_rows_outside_image"] = len(rows) - len(in_image)
    info.update(stats)
    kinds = Counter(op["kind"] + (":" + op["to"] if op.get("to") else "") for op in ops)
    print(f"boundary-solve: {len(in_image)} rows, {len(ops)} operations "
          f"({', '.join(f'{k} {v}' for k, v in sorted(kinds.items()))})")
    print(f"  at >= {args.min_confidence}: " + ", ".join(f"{k} {v}" for k, v in
                                                          info[f"at_or_above_{args.min_confidence}"].items()))
    print(f"  functions {info['rows_before']} -> {info['rows_after']}; catalogued bytes "
          f"{info['code_bytes_before']:,} -> {info['code_bytes_after']:,}; applied {len(applied)}, "
          f"blocked {info['blocked']}")
    print(f"  padding kept inside verified units: {stats['padding_kept_by_verified_unit']}; jal-like words outside "
          f"catalogued code ignored: {stats['call_sites_outside_code']}")
    for op in [o for o in ops if o["status"] == "blocked" and o["confidence"] >= args.min_confidence][:20]:
        print(f"  BLOCKED {op['id']} {op['kind']}{':' + op['to'] if op.get('to') else ''} "
              f"{', '.join(r['name'] for r in op['remove'] or [op.get('target', {'name': '?'})])} by "
              f"{'; '.join(op['blocked_by'][:2])}")
    for op in [o for o in ops if o["confidence"] >= args.min_confidence][:args.show]:
        print(f"  {op['id']} {op['status']} {op['kind']}{':' + op['to'] if op.get('to') else ''} "
              f"{op['confidence']}: {op['evidence'][0]}")
    if args.out:
        out = Path(args.out)
        cat_dir = Path(args.catalogue).resolve().parent
        if (out.resolve() == cat_dir or cat_dir in out.resolve().parents) and not args.force:
            print(f"refusing to write into the catalogue's directory {cat_dir} (use --force)")
            return 2
        out.mkdir(parents=True, exist_ok=True)
        header = {"image": str(args.image), "vram_delta": bmod.hx(delta), "catalogue": str(args.catalogue),
                  "catalogue_shift": args.catalogue_shift, "space": "image (link) addresses",
                  "min_confidence": args.min_confidence, "summary": info}
        bmod.dump_operations(out / "operations.json", ops, **header)
        bmod.dump_operations(out / "inverse.json", bmod.invert(applied), **header)
        outside = [r for r in rows if r not in in_image]
        corrected = bmod.shift_rows(sorted(new + outside, key=lambda r: r[1]), args.catalogue_shift)
        name = Path(args.catalogue).name
        bmod.write_catalogue(out / name, corrected, like=args.catalogue)
        print(f"  wrote {out / 'operations.json'}, {out / 'inverse.json'}, {out / name}")
    return 0


boundary_solve.arguments = _solve_args


# ---------------------------------------------------------------------------------------------

def _build_args(p):
    p.add_argument("image")
    p.add_argument("--name", help="image identity name (default: file name)")
    p.add_argument("--vram-delta", type=_int)
    p.add_argument("--catalogue", required=True)
    p.add_argument("--catalogue-shift", type=_int, default=0)
    p.add_argument("--c-manifest", action="append", default=[])
    p.add_argument("--asm-manifest", action="append", default=[])
    p.add_argument("--data-manifest", action="append", default=[])
    p.add_argument("--manifest-delta", type=_int, help="file-offset base of the manifests (default: --vram-delta)")
    p.add_argument("--verdicts", help="strict verdict file: SOURCE_OR_VRAM VERDICT")
    p.add_argument("--operations", help="operations.json from boundary-solve (image-space addresses)")
    p.add_argument("--min-confidence", type=float, default=0.8)
    p.add_argument("--intervals", action="append", default=[], help="extra TSV: START SIZE CLASS NOTE")
    p.add_argument("--segment", action="append", default=[], metavar="ROM:OFFSET:SIZE:TRANSFORM")
    p.add_argument("--extent", metavar="START:END")
    p.add_argument("--root", help="project root for source-existence checks")
    p.add_argument("--no-nop-padding", action="store_true")
    p.add_argument("--out", required=True)


@command("ledger-build", "Build the per-image byte-ownership ledger (every byte exactly one owner class)")
def ownership_build(args):
    data, delta = _load_image(args.image, args.vram_delta)
    mdelta = args.manifest_delta if args.manifest_delta is not None else delta
    manifests = _manifest_rows(args.c_manifest, mdelta, "c") + _manifest_rows(args.asm_manifest, mdelta, "asm") \
        + _manifest_rows(args.data_manifest, mdelta, "data")
    segments = [tuple(_int(x) if k < 3 else x for k, x in enumerate(s.split(":"))) for s in args.segment]
    if not segments and args.vram_delta is None:
        segments = [(0, 0, len(data), "copy")]          # the image is the ROM itself
    info = own.ImageInfo.of(args.name or Path(args.image).name, data, delta, segments)
    rows = bmod.shift_rows(bmod.read_catalogue(args.catalogue), -args.catalogue_shift)
    rows = [r for r in rows if delta <= r[1] and r[1] + r[2] <= delta + len(data)]
    ops = bmod.load_operations(args.operations)[0] if args.operations else None
    extra = [x for path in args.intervals for x in own.read_intervals(path)]
    extent = tuple(_int(x) for x in args.extent.split(":")) if args.extent else None
    ledger = own.build(info, rows, manifests, data, ops, args.min_confidence, extra,
                       own.read_verdicts(args.verdicts) if args.verdicts else None, extent, args.root,
                       not args.no_nop_padding)
    ledger.to_tsv(args.out)
    totals = ledger.totals()
    violations = Counter(v.kind for v in ledger.check())
    print(f"ledger-build: {info.name} extent {totals['extent']} ({totals['extent_bytes']:,} bytes) -> {args.out}")
    for cls, n in totals["bytes"].items():
        if n:
            print(f"  {cls:20s} {n:>10,}")
    print(f"  functions {totals['functions']}: {totals['functions_by_status']}")
    print(f"  violations: {dict(violations) or 'none'}; double-covered functions: {len(ledger.double_covered())}")
    return 0


ownership_build.arguments = _build_args


def _check_args(p):
    p.add_argument("ledger")
    p.add_argument("--explain", action="store_true")
    p.add_argument("--show", type=int, default=50)


@command("ledger-check", "Check a ledger: overlaps, gaps, outside rows, partial/stale rows, missing sources")
def ownership_check(args):
    ledger = own.Ledger.from_tsv(args.ledger)
    violations = ledger.check()
    totals = ledger.totals()
    print(f"ledger-check: {ledger.image.name}: {len(violations)} violation(s) "
          f"{dict(Counter(v.kind for v in violations))}; sum(bytes by class) == extent: {totals['sum_equals_extent']}")
    if args.explain:
        for v in violations[:args.show]:
            print(f"  {v.kind:14s} {own.hx(v.start)}..{own.hx(v.end)} {v.message}")
    return 1 if violations else 0


ownership_check.arguments = _check_args


def _reconcile_args(p):
    p.add_argument("before")
    p.add_argument("after")


@command("ledger-diff", "Explain every numerator/denominator change between two ownership ledgers")
def progress_reconcile(args):
    report = own.reconcile(own.Ledger.from_tsv(args.before), own.Ledger.from_tsv(args.after))
    for sentence in report["sentences"]:
        print(sentence)
    return 0


progress_reconcile.arguments = _reconcile_args


# ---------------------------------------------------------------------------------------------

def _project_args(p):
    p.add_argument("--project", default=".", help="project directory holding n64dk.toml")


@command("image-registry", "Resolve a logical image name (or alias) from n64dk.toml [images.*]; fails closed")
def image_resolve(args):
    try:
        names = [args.name] if args.name else sorted(imgmod.load_registry(args.project))
        for name in names:
            spec = imgmod.resolve(args.project, name)
            lo, hi = spec.span()
            print(json.dumps({"name": spec.name, "path": str(spec.path), "vram_delta": imgmod.hx(spec.delta),
                              "vram_delta_source": spec.delta_source,
                              "catalogue": str(spec.catalogue) if spec.catalogue else None,
                              "catalogue_shift": spec.catalogue_shift, "catalogue_rows": len(spec.rows()),
                              "manifests": [str(m) for m in spec.manifests], "aliases": spec.aliases,
                              "span": [imgmod.hx(lo), imgmod.hx(hi)], "raw_segments": len(spec.raw_segments)}))
    except imgmod.ImageError as error:
        print(f"error: {error}")
        return 2
    return 0


image_resolve.arguments = lambda p: (_project_args(p), p.add_argument("name", nargs="?"))


def _explain_args(p):
    _project_args(p)
    p.add_argument("--image")
    p.add_argument("--vram", type=_int)
    p.add_argument("--offset", type=_int)
    p.add_argument("--rom", type=_int)
    p.add_argument("--space", choices=("auto", "link", "catalogue"), default="auto")


@command("image-address", "Explain one address in every coordinate system and every image that maps it")
def address_explain(args):
    try:
        result = imgmod.explain(args.project, args.image, args.vram, args.offset, args.rom, args.space)
    except (imgmod.ImageError, ValueError) as error:
        print(f"error: {error}")
        return 2
    print(json.dumps(result, indent=1))
    return 0 if result.get("chosen") else 3


address_explain.arguments = _explain_args
