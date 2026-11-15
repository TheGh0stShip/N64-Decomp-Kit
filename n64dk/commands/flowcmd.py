"""``entry-audit`` and ``abi-solve``: whole-catalogue flow, boundary and prototype evidence."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..analysis import abi as abimod
from ..analysis import flow as flowmod
from ..analysis import values as valuemod
from ..analysis import structures as structuremod
from ..analysis.catalogue import load as load_catalogue
from ..cli import command
from ..match import causes as causemod


def _int(text: str) -> int:
    return int(text, 0)


def _image(args) -> tuple[bytes, int]:
    """(bytes, vram_delta).  A ROM with a header is mapped through its boot segment unless
    ``--vram-delta`` says the file is a linear image."""
    if args.vram_delta is not None:
        return Path(args.image).read_bytes(), args.vram_delta
    from ..match.engine import Target
    from ..rom import Rom
    target = Target.from_rom(Rom.load(args.image), None)
    return target.rom, target.delta


def _functions(args, data: bytes, delta: int) -> list[tuple[str, int, int]]:
    out = []
    for name, vram, size in load_catalogue(Path(args.catalogue)):
        vram -= args.catalogue_shift
        if size >= 4 and 0 <= vram - delta <= len(data) - size:
            out.append((name, vram, size))
    return out


def _common(p):
    p.add_argument("image", help="ROM or linear image")
    p.add_argument("--vram-delta", type=_int, help="VRAM minus file offset (omit for a ROM with a boot segment)")
    p.add_argument("--catalogue", required=True, help="function catalogue TOML or symbol_addrs.txt")
    p.add_argument("--catalogue-shift", type=_int, default=0)
    p.add_argument("--show", type=int, default=30)


@command("entry-audit", "Classify every catalogued range: complete function, fragment, false split, "
         "non-standard ABI, hand-written, embedded data; with compiler family and NOP roles")
def entry_audit(args):
    data, delta = _image(args)
    functions = _functions(args, data, delta)
    starts = {vram for _n, vram, _s in functions}
    verdicts, families, nops, shapes = Counter(), Counter(), Counter(), Counter()
    rows, padding = [], 0
    for name, vram, size in functions:
        flow = flowmod.analyse_in_image(data, delta, vram, size)
        found = [c for c in causemod.target_causes(flow, starts) if c.confidence >= 0.6]
        family = causemod.compiler_family(flow)
        families[family["family"] if family["confidence"] >= 0.6 else "undetermined"] += 1
        shapes[flowmod.shapes(flow)[0]["shape"]] += 1
        for _address, role in flowmod.nop_roles(flow):
            nops[role] += 1
            padding += 4 * (role == "padding")
        top = found[0].id if found else "complete"
        verdicts[top] += 1
        if found:
            rows.append({"name": name, "vram": f"0x{vram:08X}", "size": size, "verdict": top,
                         "confidence": round(found[0].confidence, 2), "evidence": found[0].evidence[:2],
                         "next": found[0].next, "also": [c.id for c in found[1:3]]})
    rows.sort(key=lambda row: (-row["confidence"], row["vram"]))
    return {"functions": len(functions), "verdicts": dict(verdicts.most_common()),
            "compiler_family": dict(families.most_common()), "shapes": dict(shapes.most_common(12)),
            "nop_roles": dict(nops.most_common()), "padding_bytes_inside_ranges": padding,
            "flagged": rows if args.all else rows[:args.show]}


def _entry_args(p):
    _common(p)
    p.add_argument("--all", action="store_true")


entry_audit.arguments = _entry_args


@command("abi-solve", "Infer prototypes for every catalogued function from callee and call-site evidence")
def abi_solve(args):
    data, delta = _image(args)
    functions = _functions(args, data, delta)
    facts, names = {}, {}
    for name, vram, size in functions:
        facts[vram] = valuemod.track(flowmod.analyse_in_image(data, delta, vram, size))
        names[vram] = name
    solved = abimod.solve(facts, names)
    confident = [p for p in solved.values() if p.confidence >= args.min_confidence]
    if args.out:
        lines = ["/* Prototype evidence from machine code (n64dk abi-solve). Review before trusting:",
                 f"   only entries with confidence >= {args.min_confidence} are listed. */"]
        lines += [f"{p.declaration()}  /* {p.confidence:.2f}, {p.call_sites} call site(s) */"
                  for p in sorted(confident, key=lambda p: p.vram)]
        Path(args.out).write_text("\n".join(lines) + "\n")
    conflicts = [p for p in solved.values() if p.conflicts]
    conflicts.sort(key=lambda p: -p.call_sites)
    return {"functions": len(solved), "confident": len(confident),
            "void": sum(1 for p in solved.values() if p.returns == "void"),
            "with_conflicts": len(conflicts), "written": args.out,
            "argument_counts": dict(sorted(Counter(p.args for p in solved.values()).items())),
            "conflicts": [p.as_dict() for p in conflicts[:args.show]]}


def _abi_args(p):
    _common(p)
    p.add_argument("--min-confidence", type=float, default=0.8)
    p.add_argument("--out", help="write confident declarations to this header (m2c context seed)")


abi_solve.arguments = _abi_args


@command("structure-context", "Cluster cross-function pointer layouts and emit an m2c context seed")
def structure_context(args):
    data, delta = _image(args)
    functions = _functions(args, data, delta)
    facts, names = {}, {}
    for name, vram, size in functions:
        facts[vram] = valuemod.track(flowmod.analyse_in_image(data, delta, vram, size))
        names[vram] = name
    result = structuremod.infer(facts, names)
    solved = abimod.solve(facts, names)
    prototypes = [value for value in solved.values() if value.confidence >= args.min_confidence]
    if args.out:
        Path(args.out).write_text(structuremod.context_header(
            result, sorted(prototypes, key=lambda value: value.vram), args.min_members))
    result.update({"functions": len(functions), "prototype_count": len(prototypes),
                   "written": args.out})
    if not args.all:
        result["layouts"] = sorted(result["layouts"],
                                   key=lambda row: (-len(row["members"]), -row["max_extent"]))[:args.show]
    return result


def _structure_args(p):
    _common(p)
    p.add_argument("--min-confidence", type=float, default=0.8)
    p.add_argument("--min-members", type=int, default=1,
                   help="minimum related pointer origins required in emitted layouts")
    p.add_argument("--all", action="store_true")
    p.add_argument("--out", help="write provisional structs and ABI prototypes for m2c")


structure_context.arguments = _structure_args
