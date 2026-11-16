"""Matching engine: build + relocated compare for one unit, manifest batches and sweeps."""
from __future__ import annotations

import hashlib
import itertools
import re
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .. import boot
from ..elf import Elf
from ..rom import Rom
from . import compare as cmp
from . import symbols as symmod
from .manifest import Unit
from .pipeline import BuildError, BuildSpec, build
from .toolchain import Config


@dataclass
class Target:
    """The retail image and its main-segment address mapping."""
    rom: bytes
    delta: int                    # vram - rom
    window: tuple[int, int]       # ROM range searched for constant pools

    @classmethod
    def from_rom(cls, image: Rom, vram_delta: int | None = None) -> "Target":
        info = boot.analyse(image)
        delta = vram_delta if vram_delta is not None else info.main_vram - info.main_rom
        return cls(image.data, delta, (info.main_rom, len(image.data)))

    def vram_to_rom(self, vram: int) -> int:
        return vram - self.delta

    def rom_to_vram(self, rom: int) -> int:
        return rom + self.delta


@dataclass
class Outcome:
    name: str
    vram: int
    size: int
    spec: BuildSpec
    result: cmp.Result | None = None
    error: str | None = None
    digest: str | None = None
    digest_ok: bool | None = None
    proof_required: bool = False
    proof: object | None = None
    defined: dict[str, int] = field(default_factory=dict)   # global symbols the object defines
    ambiguous_addresses: list[int] = field(default_factory=list)

    @property
    def exact(self) -> bool:
        exploratory = (self.error is None and self.result is not None and self.result.exact
                       and self.digest_ok is not False)
        return exploratory and (not self.proof_required or bool(self.proof and self.proof.exact))

    @property
    def exploratory_exact(self) -> bool:
        return (self.error is None and self.result is not None and self.result.exact
                and self.digest_ok is not False)

    def as_dict(self) -> dict:
        out = {"name": self.name, "vram": f"0x{self.vram:08X}", "size": f"0x{self.size:X}",
               "pipeline": self.spec.pipeline, "flags": " ".join(self.spec.flags), "exact": self.exact,
               "exploratory_exact": self.exploratory_exact,
               "proof_required": self.proof_required,
               "proof": self.proof.as_dict() if self.proof is not None else {"verdict": "not-run"}}
        if self.digest is not None:
            out["sha256_text"] = self.digest
            out["digest_ok"] = self.digest_ok if self.digest_ok is not None else self.exact
            out["digest_authority"] = ("expected-manifest-hash" if self.digest_ok is not None
                                       else "exact-target-text-byte-comparison")
        if self.result is not None:
            out.update(self.result.as_dict())
            out["exact"] = self.exact
        if self.ambiguous_addresses:
            out["ambiguous_addresses"] = [f"0x{value:08X}" for value in self.ambiguous_addresses]
        if self.error:
            out["error"] = self.error
        return out


def match_source(source: Path, spec: BuildSpec, cfg: Config, target: Target, vram: int | None,
                 size: int | None, symbols: symmod.SymbolMap, workdir: Path,
                 includes: list[Path] | None = None, infer_externals: bool = True,
                 expected_digest: str | None = None, section_sizes: dict[str, int] | None = None,
                 name: str | None = None, with_diff: bool = True,
                 strict_verification: bool = False,
                 function_starts: set[int] | None = None) -> Outcome:
    out = Outcome(name or str(source), vram or 0, size or 0, spec,
                  proof_required=strict_verification)
    try:
        obj = build(source, spec, cfg, workdir, includes)
    except (BuildError, RuntimeError, OSError) as exc:
        out.error = str(exc)
        return out
    try:
        elf = Elf.load(obj)
    except ValueError as exc:
        out.error = str(exc)
        return out
    candidates = [vram]
    if vram is None:  # no address given: find the compiled code in the ROM
        candidates = cmp.locate_text(elf, target.rom, target.window[0], target.window[1], target.rom_to_vram)
        if not candidates:
            out.error = "compiled .text not found in the ROM"
            return out
    found_exact = []
    searching = vram is None
    for vram in candidates:
        out.vram = vram
        _compare_at(out, elf, source, spec, target, vram, size, symbols, infer_externals,
                    expected_digest, section_sizes, with_diff and len(candidates) == 1,
                    strict_verification and not searching, function_starts)
        if out.exploratory_exact:
            found_exact.append(vram)
        if out.exact and not searching:
            break
    if searching:
        if len(found_exact) != 1:
            out.ambiguous_addresses = sorted(set(found_exact))
            out.error = (("compiled .text is exact at more than one ROM location: " +
                          ", ".join(f"0x{value:08X}" for value in found_exact[:16]) +
                          "; pass --addr to choose one")
                         if found_exact else "compiled .text did not compare exactly at any located position")
            out.result = None
        else:
            out.error = None
            out.vram = found_exact[0]
            _compare_at(out, elf, source, spec, target, found_exact[0], size, symbols,
                        infer_externals, expected_digest, section_sizes, with_diff,
                        strict_verification, function_starts)
    try:
        obj.unlink()
    except OSError:
        pass
    return out


def _compare_at(out: Outcome, elf: Elf, source: Path, spec: BuildSpec, target: Target, vram: int,
                size: int | None, symbols: symmod.SymbolMap, infer_externals: bool,
                expected_digest: str | None, section_sizes: dict[str, int] | None, with_diff: bool,
                strict_verification: bool = False, function_starts: set[int] | None = None) -> None:
    # Keep the proof authority separate from exploration conveniences.  A candidate may
    # contain LDSYM markers or address-bearing aliases to make a draft link, but candidate
    # text is not independent evidence and therefore cannot establish strict exactness.
    declared_syms = symbols.copy()
    declared_syms.update(spec.symbols)
    syms = declared_syms.copy()
    try:
        syms.update(symmod.from_source(Path(source).read_text(errors="replace"), syms))
    except OSError:
        pass
    res = cmp.compare_object(elf, target.rom, target.vram_to_rom, vram, size, syms, spec.section_bases,
                      infer=True, infer_externals=infer_externals, rom_window=target.window,
                      to_vram=target.rom_to_vram, section_sizes=section_sizes, with_diff=with_diff)
    out.result = res
    out.size = res.text.size
    out.defined = {}
    for sym in elf.symbols:
        if sym.bind == 1 and sym.name and 0 < sym.section < len(elf.sections):
            base = res.bases.get(elf.sections[sym.section].name)
            if base is not None:
                out.defined[sym.name] = base + sym.value
    try:
        text = cmp.relocate(elf, ".text", res.bases, _with(syms, res.inferred_symbols))[:out.size]
        out.digest = hashlib.sha256(text).hexdigest()
    except (KeyError, ValueError) as exc:
        out.digest = f"error: {exc}"
    if expected_digest is not None:
        out.digest_ok = out.digest == expected_digest
    if strict_verification and size is not None:
        from .verify import strict_compare
        out.proof = strict_compare(elf, target.rom, target.vram_to_rom, vram, size, declared_syms,
                                   spec.section_bases, section_sizes, function_starts)


def _with(syms: symmod.SymbolMap, extra: dict[str, int]) -> symmod.SymbolMap:
    s = syms.copy()
    s.update(extra)
    return s


def batch(units: list[Unit], cfg: Config, target: Target, symbols: symmod.SymbolMap,
          jobs: int | None = None, infer_externals: bool = False, progress=None) -> list[Outcome]:
    """Rebuild and verify every unit; results keep manifest order."""
    jobs = jobs or os.cpu_count() or 1
    with tempfile.TemporaryDirectory(prefix="n64dk-match-") as tmp:
        work = Path(tmp)
        function_starts = {unit.vram for unit in units}

        def one(unit: Unit) -> Outcome:
            unit_dir = work / f"u{unit.line}"
            unit_dir.mkdir(exist_ok=True)
            o = match_source(unit.source, unit.spec, cfg, target, unit.vram, unit.size, symbols, unit_dir,
                             infer_externals=infer_externals, expected_digest=unit.digest,
                             section_sizes=unit.section_sizes, name=unit.name,
                             strict_verification=True, function_starts=function_starts)
            if progress:
                progress(o)
            return o

        with ThreadPoolExecutor(max_workers=jobs) as pool:
            outs = list(pool.map(one, units))
            # Second pass: text symbols defined by peer units are independent link evidence.
            # Never import data definitions whose section base came from the target bytes.
            retry = [i for i, o in enumerate(outs) if o.exploratory_exact and not o.exact]
            if retry:
                symbols = symbols.copy()
                for o in outs:
                    for k, v in o.defined.items():
                        if o.vram <= v < o.vram + o.size:
                            symbols.setdefault(k, v)
                for i, o in zip(retry, pool.map(one, [units[i] for i in retry])):
                    outs[i] = o
            return outs


# --------------------------------------------------------------------------- sweep
GCC_AXES = {
    "opt": ["-O2", "-O1", "-O3"],
    "g": [[], ["-g"]],
    "isa": [["-mips3", "-mgp32", "-mfp32"], ["-mips2"]],
    "G": ["-G0", "-G8"],
}
IDO_AXES = {
    "opt": ["-O2", "-O1", "-O3"],
    "g": [[], ["-g3"]],
    "isa": [["-mips2"], ["-mips3", "-32"]],
    "G": [["-G", "0"], ["-G", "8"]],
}
IDO_FIXED = ["-non_shared", "-Xcpluscomm", "-Wab,-r4300_mul"]
SN_FIXED = ["-mcpu=vr4300", "-mhard-float", "-meb"]


def non_axis_flags(flags: list[str]) -> list[str]:
    """Flags a sweep keeps fixed: everything except optimisation, debug, ISA and -G settings."""
    out, skip = [], False
    for f in flags:
        if skip:
            skip = False
            continue
        if f == "-G":
            skip = True
            continue
        if re.fullmatch(r"-O\d?|-g\d?|-mips\d|-G\d+|-mgp32|-mfp32|-32", f):
            continue
        out.append(f)
    return out


def _l(x):
    return list(x) if isinstance(x, list) else [x]


def sweep_specs(pipelines: list[str], extended: bool = False) -> list[BuildSpec]:
    """Configurations in preference order: flags vary fastest within each pipeline, with the
    usual retail settings (-O2, no -g, -mips3/-mips2, -G0) first."""
    out = []
    for pipe in pipelines:
        axes = IDO_AXES if pipe.startswith("ido") else GCC_AXES
        for opt, g, isa, G in itertools.product(axes["opt"], axes["g"], axes["isa"], axes["G"]):
            flags = [opt, *_l(g)]
            if pipe.startswith("ido"):
                flags += [*_l(isa), *IDO_FIXED, *_l(G)]
            elif pipe == "sn":
                flags += [*_l(G), *SN_FIXED, *_l(isa)[:1]]
            else:
                flags += [*_l(G), *_l(isa)]
            out.append(BuildSpec(pipe, flags))
        if pipe.startswith("ido"):
            # some titles were built for the first instruction set (seen in published settings of
            # finished decompilations); last, because it is rare
            out += [BuildSpec(pipe, [opt, "-mips1", *IDO_FIXED, "-G", "0"]) for opt in ("-O2", "-O1")]
    if extended:
        additions = []
        for spec in out:
            if spec.pipeline.startswith("ido"):
                continue
            options = ["-fno-schedule-insns2", "-fforce-addr", "-fno-force-mem", "-fvolatile"]
            if "-mips3" in spec.flags:
                options += ["-mcpu=r4600", "-mcpu=r4650"]
            additions += [BuildSpec(spec.pipeline, [*spec.flags, option]) for option in options]
        out += additions
    return out


def default_pipelines(cfg: Config) -> list[str]:
    avail = cfg.available()
    out = []
    if "kmc" in avail:
        if cfg.normalizer:
            out.append("kmc+hook")
        out.append("kmc+builtin")
        if cfg.gnu_as() is not None:
            out.append("kmc+asn64")
        out.append("kmc+as")
    if "ido53" in avail:
        out.append("ido5.3")
    if "ido71" in avail:
        out.append("ido7.1")
    if "sn" in avail:
        out.append("sn")
    return out


@dataclass
class SweepResult:
    tried: list[Outcome] = field(default_factory=list)
    exact: Outcome | None = None

    def best(self) -> Outcome | None:
        if self.exact:
            return self.exact
        scored = [o for o in self.tried if o.result is not None]
        return min(scored, key=lambda o: (o.result.diff.score if o.result.diff else 0), default=None)


def sweep(source: Path, cfg: Config, target: Target, vram: int, size: int | None,
          symbols: symmod.SymbolMap, pipelines: list[str] | None = None, jobs: int | None = None,
          includes: list[Path] | None = None, stop_at_first: bool = True,
          base_spec: BuildSpec | None = None, extended_flags: bool = False) -> SweepResult:
    """Try pipelines x flags (x rodata placement, done inside the compare) and stop at the
    first exact configuration in preference order."""
    specs = sweep_specs(pipelines or default_pipelines(cfg), extended_flags)
    if base_spec is not None:
        extra = non_axis_flags(base_spec.flags)
        for s in specs:
            s.section_bases.update(base_spec.section_bases)
            s.symbols.update(base_spec.symbols)
            s.flags += [f for f in extra if f not in s.flags or f.startswith(("-D", "-I"))]
    jobs = jobs or os.cpu_count() or 1
    res = SweepResult()
    with tempfile.TemporaryDirectory(prefix="n64dk-sweep-") as tmp, ThreadPoolExecutor(jobs) as pool:
        for i in range(0, len(specs), jobs):
            chunk = specs[i:i + jobs]
            outs = list(pool.map(lambda s: match_source(source, s, cfg, target, vram, size, symbols, Path(tmp),
                                                        includes, strict_verification=size is not None), chunk))
            res.tried += outs
            hit = next((o for o in outs if o.exact), None)
            if hit is not None:
                res.exact = hit
                if stop_at_first:
                    break
    return res


def manifest_row(outcome: Outcome, project: Path, source: Path, target: Target, symbols: symmod.SymbolMap) -> str:
    """BattleTanx-style ``ROM_START SIZE SOURCE FLAGS SHA256`` row for an exact outcome."""
    if not outcome.exact:
        raise ValueError("manifest rows require a strictly verified exact outcome")
    spec = BuildSpec(outcome.spec.pipeline, list(outcome.spec.flags), dict(outcome.spec.section_bases),
                     dict(outcome.spec.symbols), list(outcome.spec.normalizer_args))
    res = outcome.result
    for k, v in (res.bases if res else {}).items():
        if k != ".text":
            spec.section_bases.setdefault(k, v)
    if res:
        spec.symbols.update(res.inferred_symbols)
    rom_start = target.vram_to_rom(outcome.vram)
    rom_text = target.rom[rom_start:rom_start + outcome.size]
    try:
        rel = str(Path(source).resolve().relative_to(project))
    except ValueError:
        rel = str(source)
    return "\t".join([f"0x{rom_start:X}", f"0x{outcome.size:X}", rel, spec.manifest_flags(),
                      hashlib.sha256(rom_text).hexdigest()])
