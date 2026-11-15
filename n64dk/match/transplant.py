"""Donor transplant: recover target functions from C already matched in another project.

A function in a target image that is machine-code identical to a function some other local
project has already matched as C (after masking the fields a linker rewrites) is recovered
by compiling the donor's proven source with the donor's proven recipe and verifying it at
the target address.  This is how SDK and library code (libultra, libaudio/libmus, libc
pieces, compiler runtime, shared engine code) is recovered without re-decompiling it.

Stages (each usable on its own):

``build_index``  walk every C row of every donor manifest, cut the retail bytes of the unit
                 into functions (donor catalogue starts), and store per function a
                 relocation-masked signature, the raw bytes, the masked sites with the donor
                 address and donor symbol name at each, and the donor unit recipe.  Persisted
                 as JSON; a unit whose source, manifest row and retail bytes are unchanged is
                 reused without recomputation.
``scan``         exact masked-signature hits (same size) for each target function, plus
                 *near* hits (at most ``near_max`` differing words) that are reported but
                 never transplanted.
``transfer``     align donor and target instruction by instruction and derive the target
                 address of each donor symbol at a masked site; check that every donor symbol
                 maps to one target address across all hits (contradicting hits go to
                 ``needs-review``) and flag different donor symbols landing on one address.
``transplant``   build the donor unit in a scratch workspace (donor include directories,
                 donor flags), relocate it with the transferred symbols and verify it with
                 :func:`n64dk.match.verify.strict_compare`.  Verdicts:
                 ``exact-with-transferred-symbols``, ``mismatch``, ``build-failed``; units
                 only partly present in the target are ``partial-unit``.

Masking rules: the 26-bit target of ``j``/``jal``; the immediate of every ``lui``; the
immediate of each ``%lo`` user found by the same straight-line pairing the m2c bridge uses
(``m2c_bridge._pairs``).  Ordinary immediates (stack offsets, field offsets, small
constants, branch offsets) are kept.  Trailing zero words are not part of a signature, so
alignment padding never prevents a hit.

Nothing here writes into a donor or target project: builds run in a scratch project
directory whose entries are symlinks to the donor's top level, and outputs go to the
caller's directory.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import tempfile
import time
import tomllib
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from ..elf import R_MIPS_26, Elf
from . import compare as cmp
from . import symbols as symmod
from .m2c_bridge import _pairs
from .pipeline import BuildError, BuildSpec, build, split_flags
from .toolchain import Config

INDEX_VERSION = 3
EXACT_VERDICT = "exact-with-transferred-symbols"
NEAR_MIN_WORDS = 6
AUTO_NAME = re.compile(r"^(?:func|D|B|jtbl|L|sym|data)_[0-9A-Fa-f]{6,8}$|^0x[0-9A-Fa-f]+$")
INCLUDE = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.M)
HEX = re.compile(r"^(0x)?[0-9A-Fa-f]+$")


# --------------------------------------------------------------------------- donors

@dataclass
class Manifest:
    path: str                 # relative to the donor root
    pipeline: str             # kmc+builtin, kmc+as, kmc+asn64, ido5.3, ido7.1, sn


@dataclass
class DonorSpec:
    name: str
    root: Path
    image: Path
    manifests: list[Manifest]
    vram_delta: int | None = None
    symbols: list[Path] = field(default_factory=list)
    catalogue: list[Path] = field(default_factory=list)
    include: list[Path] = field(default_factory=list)
    kmc_lane: str = "kmc+builtin"


def _abs(root: Path, value: str) -> Path:
    path = Path(os.path.expanduser(value))
    return path if path.is_absolute() else root / path


def donor_from_dict(name: str, data: dict) -> DonorSpec:
    root = Path(os.path.expanduser(data["root"]))
    manifests = []
    for item in data.get("manifests", []):
        if isinstance(item, str):
            path, _, pipe = item.partition("=")
            manifests.append(Manifest(path, pipe or "kmc+builtin"))
        else:
            manifests.append(Manifest(item["path"], item.get("pipeline", "kmc+builtin")))
    delta = data.get("vram_delta")
    return DonorSpec(name, root, _abs(root, data["image"]), manifests,
                     int(delta, 0) if isinstance(delta, str) else delta,
                     [_abs(root, p) for p in data.get("symbols", [])],
                     [_abs(root, p) for p in data.get("catalogue", [])],
                     [_abs(root, p) for p in data.get("include", [])],
                     data.get("kmc_lane", "kmc+builtin"))


def load_donors(path: str | Path, only: list[str] | None = None, exclude: list[str] | None = None) -> list[DonorSpec]:
    """``[donor.<name>]`` tables (see ``donors.example.toml``)."""
    data = tomllib.loads(Path(path).read_text())
    out = [donor_from_dict(name, table) for name, table in data.get("donor", {}).items()]
    if only:
        out = [d for d in out if d.name in only]
    if exclude:
        out = [d for d in out if d.name not in exclude]
    return out


def load_functions(paths, delta: int | None = None) -> list[tuple[str, int, int]]:
    """(name, vram, size) from recomp/splat catalogues or ``ROM SIZE VRAM NAME`` TSVs."""
    from ..analysis.functions import load_catalogue
    out: dict[int, tuple[str, int, int]] = {}
    for path in paths:
        rows = load_catalogue(path)
        if not rows:
            for line in Path(path).read_text().splitlines():
                cols = line.split("\t") if "\t" in line else line.split()
                if line.startswith("#") or len(cols) < 3 or not all(HEX.match(c) for c in cols[:2]):
                    continue
                size = int(cols[1], 16)
                if len(cols) >= 4 and HEX.match(cols[2]) and cols[2].lower().startswith("0x8"):
                    rows.append((cols[3], int(cols[2], 16), size))
                elif delta is not None:
                    rows.append((cols[2] if len(cols) > 2 else f"func_{int(cols[0], 16) + delta:08X}",
                                 int(cols[0], 16) + delta, size))
        for name, vram, size in rows:
            if size > 0:
                out.setdefault(vram, (name, vram, size))
    return sorted(out.values(), key=lambda r: r[1])


def manifest_intervals(paths, delta: int) -> list[tuple[int, int]]:
    """VRAM intervals of manifest rows (first two hex columns are ROM start and size)."""
    out = []
    for path in paths:
        for line in Path(path).read_text().splitlines():
            if line.startswith("#") or not line.strip():
                continue
            cols = line.split("\t") if "\t" in line else line.split()
            if len(cols) >= 2 and HEX.match(cols[0]) and HEX.match(cols[1]):
                start = int(cols[0], 16) + delta
                out.append((start, start + int(cols[1], 16)))
    return out


# --------------------------------------------------------------------------- masking

def words_of(code: bytes) -> list[int]:
    return [struct.unpack_from(">I", code, i)[0] for i in range(0, len(code) - len(code) % 4, 4)]


def strip_padding(code: bytes) -> bytes:
    end = len(code) - len(code) % 4
    while end >= 4 and code[end - 4:end] == b"\0\0\0\0":
        end -= 4
    return code[:end]


def mask(code: bytes, vram: int) -> tuple[list[int], list[tuple[int, str, int]]]:
    """Masked words and the masked sites ``(word index, kind, full address)``.

    ``kind`` is ``jal``/``j`` (26-bit target), ``hi`` (paired ``lui``), ``lui`` (unpaired
    ``lui``, address ``upper << 16``) or ``lo`` (``%lo`` user)."""
    words = words_of(code)
    pairs = _pairs(words, vram)
    out, sites = [], []
    for i, word in enumerate(words):
        op, site = word >> 26, vram + 4 * i
        if op in (2, 3):
            out.append(word & 0xFC000000)
            sites.append((i, "jal" if op == 3 else "j", ((site + 4) & 0xF0000000) | ((word & 0x3FFFFFF) << 2)))
        elif op == 15:
            out.append(word & 0xFFFF0000)
            if site in pairs:
                sites.append((i, "hi", pairs[site]))
            else:   # unpaired lui: a constant (or an address the tracker lost); masked, never transferred
                sites.append((i, "lui", (word & 0xFFFF) << 16))
        elif site in pairs:
            out.append(word & 0xFFFF0000)
            sites.append((i, "lo", pairs[site]))
        else:
            out.append(word)
    return out, sites


def signature(masked: list[int]) -> str:
    return hashlib.sha1(struct.pack(f">{len(masked)}I", *masked)).hexdigest()


def chunk_keys(masked: list[int], parts: int = 3) -> list[str]:
    """Pigeonhole keys: two masked sequences with at most ``parts - 1`` differing words share
    at least one identical chunk."""
    n = len(masked)
    bounds = [n * k // parts for k in range(parts + 1)]
    return [f"{n}:{k}:" + signature(masked[bounds[k]:bounds[k + 1]]) for k in range(parts)]


# --------------------------------------------------------------------------- index

def _name_at(address: int, by_addr: dict[int, str], sorted_addrs: list[int], sizes: dict[str, int]) -> tuple[str | None, int]:
    """Donor symbol covering ``address``: exact, else the closest lower symbol whose known size covers it."""
    if address in by_addr:
        return by_addr[address], 0
    import bisect
    k = bisect.bisect_right(sorted_addrs, address) - 1
    if k >= 0:
        base = sorted_addrs[k]
        name = by_addr[base]
        if address - base < sizes.get(name, 0):
            return name, address - base
    return None, 0


class DonorContext:
    """Loaded donor: image bytes, address mapping, symbol map and function starts."""

    def __init__(self, spec: DonorSpec):
        from ..rom import Rom
        from .engine import Target
        self.spec = spec
        self.target = Target.from_rom(Rom.load(spec.image), spec.vram_delta)
        self.symbols = symmod.load([p for p in spec.symbols if p.is_file()])
        self.functions = load_functions([p for p in spec.catalogue if p.is_file()], self.target.delta)
        for name, vram, size in self.functions:
            self.symbols.setdefault(name, vram)
            self.symbols.sizes.setdefault(name, size)
        self.by_addr: dict[int, str] = {}
        for name, address in self.symbols.items():   # prefer descriptive names over auto names
            old = self.by_addr.get(address)
            if old is None or (AUTO_NAME.match(old) and not AUTO_NAME.match(name)):
                self.by_addr[address] = name
        self.sorted = sorted(self.by_addr)
        self.starts = sorted(v for _n, v, _s in self.functions)

    def name_at(self, address: int) -> tuple[str | None, int]:
        return _name_at(address, self.by_addr, self.sorted, self.symbols.sizes)


def _unit_rows(donor: DonorSpec, ctx: DonorContext):
    from . import manifest as manmod
    for man in donor.manifests:
        path = donor.root / man.path
        if not path.is_file():
            continue
        lines = path.read_text().splitlines()
        lane = man.pipeline if man.pipeline.startswith("kmc") and man.pipeline != "kmc" else donor.kmc_lane
        pipe = "kmc" if man.pipeline.startswith("kmc") else man.pipeline
        try:
            units = manmod.parse(path, donor.root, ctx.target.rom_to_vram, pipe, lane)
        except Exception:                                   # noqa: BLE001 - foreign manifest layout
            continue
        for unit in units:
            if unit.source.suffix not in (".c",):
                continue
            row = lines[unit.line - 1] if 0 < unit.line <= len(lines) else ""
            yield man, unit, row


def _function_spans(ctx: DonorContext, vram: int, size: int) -> list[tuple[str, int, int]]:
    import bisect
    lo = bisect.bisect_left(ctx.starts, vram)
    hi = bisect.bisect_left(ctx.starts, vram + size)
    starts = [vram] + [s for s in ctx.starts[lo:hi] if s != vram]
    out = []
    for k, start in enumerate(starts):
        end = starts[k + 1] if k + 1 < len(starts) else vram + size
        name = ctx.by_addr.get(start) or f"func_{start:08X}"
        out.append((name, start, end - start))
    return out


def function_record(code: bytes, vram: int, name: str, offset: int, span: int, position: int,
                    name_at=None, unit_range: tuple[int, int] | None = None) -> dict:
    """Index record of one donor function (``code`` already stripped of trailing padding)."""
    masked, sites = mask(code, vram)
    lo, hi = unit_range or (vram, vram + len(code))
    site_rows = []
    for i, kind, address in sites:
        sym, addend = name_at(address) if name_at else (None, 0)
        local = lo <= address < hi and kind in ("j", "jal")
        site_rows.append([i, kind, address, sym, addend, local])
    return {"name": name, "vram": vram, "offset": offset, "size": len(code), "span": span,
            "bytes": code.hex(), "masked": signature(masked),
            "chunks": chunk_keys(masked) if len(masked) >= NEAR_MIN_WORDS else [],
            "sites": site_rows, "position": position}


def index_unit(ctx: DonorContext, man: Manifest, unit, row: str) -> dict:
    target = ctx.target
    offset = target.vram_to_rom(unit.vram)
    raw = target.rom[offset:offset + unit.size]
    spans = _function_spans(ctx, unit.vram, unit.size)
    functions = []
    for k, (name, start, size) in enumerate(spans):
        code = strip_padding(raw[start - unit.vram:start - unit.vram + size])
        if code:
            functions.append(function_record(code, start, name, start - unit.vram, size, k, ctx.name_at,
                                             (unit.vram, unit.vram + unit.size)))
    core = strip_padding(raw)
    unit_masked, _ = mask(core, unit.vram)
    flags = row.split("\t")[3] if row.count("\t") >= 3 else ""
    return {"donor": ctx.spec.name, "source": str(unit.source.relative_to(ctx.spec.root)) if unit.source.is_relative_to(ctx.spec.root) else str(unit.source),
            "manifest": man.path, "line": unit.line, "pipeline": unit.spec.pipeline,
            "flags_text": flags.strip(), "flags": unit.spec.flags, "normalizer_args": unit.spec.normalizer_args,
            "section_bases": unit.spec.section_bases, "symbols": unit.spec.symbols,
            "vram": unit.vram, "size": unit.size, "core_size": len(core), "unit_masked": signature(unit_masked),
            "functions": functions}


def _unit_digest(donor: DonorSpec, unit, row: str, raw: bytes) -> str:
    h = hashlib.sha256()
    h.update(f"{INDEX_VERSION}|{donor.name}|{row}|".encode())
    try:
        h.update(unit.source.read_bytes())
    except OSError:
        h.update(b"missing")
    h.update(raw)
    return h.hexdigest()


class Index:
    """Donor functions keyed by masked signature, with chunk keys for near matches."""

    def __init__(self, units: dict[str, dict] | None = None, donors: dict[str, dict] | None = None):
        self.units = units or {}            # digest -> unit record
        self.donors = donors or {}          # donor name -> spec summary
        self._build()

    def _build(self):
        self.by_sig: dict[tuple[str, int], list[tuple[dict, dict]]] = defaultdict(list)
        self.by_chunk: dict[str, list[tuple[dict, dict]]] = defaultdict(list)
        for unit in self.units.values():
            for fn in unit["functions"]:
                self.by_sig[(fn["masked"], fn["size"])].append((unit, fn))
                for key in fn["chunks"]:
                    self.by_chunk[key].append((unit, fn))

    def stats(self) -> dict:
        per = defaultdict(Counter)
        for unit in self.units.values():
            per[unit["donor"]][unit["pipeline"]] += len(unit["functions"])
            per[unit["donor"]]["units"] += 1
        return {d: dict(c) for d, c in sorted(per.items())}

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": INDEX_VERSION, "donors": self.donors, "units": self.units}))
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str | Path) -> "Index":
        data = json.loads(Path(path).read_text())
        if data.get("version") != INDEX_VERSION:
            return cls()
        return cls(data["units"], data.get("donors", {}))


def build_index(donors: list[DonorSpec], path: str | Path | None = None) -> tuple[Index, dict]:
    """Index every C unit of ``donors``; reuse records from ``path`` whose digest is unchanged."""
    old = Index.load(path) if path and Path(path).is_file() else Index()
    units: dict[str, dict] = {}
    info = {"reused": 0, "indexed": 0, "skipped_missing": 0}
    donor_info = {}
    for donor in donors:
        ctx = DonorContext(donor)
        donor_info[donor.name] = {"root": str(donor.root), "image": str(donor.image), "delta": ctx.target.delta,
                                  "include": [str(p) for p in donor.include]}
        for man, unit, row in _unit_rows(donor, ctx):
            if not unit.source.is_file():
                info["skipped_missing"] += 1
                continue
            offset = ctx.target.vram_to_rom(unit.vram)
            digest = _unit_digest(donor, unit, row, ctx.target.rom[offset:offset + unit.size])
            if digest in old.units:
                units[digest] = old.units[digest]
                info["reused"] += 1
            else:
                units[digest] = index_unit(ctx, man, unit, row)
                info["indexed"] += 1
    index = Index(units, donor_info)
    if path:
        index.save(path)
    return index, info


# --------------------------------------------------------------------------- scan

@dataclass
class Hit:
    name: str
    vram: int
    size: int
    unit: dict
    function: dict
    kind: str                        # exact | near
    diffs: list[int] = field(default_factory=list)       # word indices that differ (near)
    sites: list[dict] = field(default_factory=list)      # aligned masked sites
    status: str = "candidate"        # candidate | needs-review | local-inconsistent | constant-differs | partial-unit
    notes: list[str] = field(default_factory=list)
    template: bool = False           # generic code shape (one donor function hit by several targets)

    @property
    def donor(self) -> str:
        return self.unit["donor"]

    def row(self) -> dict:
        return {"target": self.name, "vram": f"0x{self.vram:08X}", "size": self.size, "kind": self.kind,
                "donor": self.donor, "donor_unit": self.unit["source"], "donor_function": self.function["name"],
                "donor_pipeline": self.unit["pipeline"], "status": self.status, "notes": self.notes,
                **({"differing_words": [f"0x{4 * d:X}" for d in self.diffs]} if self.diffs else {})}


def _align(hit: Hit, target_code: bytes) -> None:
    """Pair each donor masked site with the target address at the same instruction."""
    _masked, tsites = mask(target_code, hit.vram)
    tmap = {i: (kind, address) for i, kind, address in tsites}
    fn = hit.function
    for i, kind, daddr, sym, addend, local in fn["sites"]:
        tk = tmap.get(i)
        if tk is None or tk[0] != kind:
            continue
        taddr = tk[1]
        if kind == "lui":
            # an unpaired lui is usually a constant: a different value is a different function
            if taddr != daddr and not (0x80000000 <= daddr < 0xC0000000 and 0x80000000 <= taddr < 0xC0000000):
                hit.status = "constant-differs"
                hit.notes.append(f"lui constant at +0x{4 * i:X}: donor 0x{daddr >> 16:04X}, target 0x{taddr >> 16:04X}")
            continue
        if local:
            expect = hit.vram + (daddr - fn["vram"])
            if taddr != expect:
                hit.status = "local-inconsistent"
                hit.notes.append(f"local {kind} at +0x{4 * i:X}: donor offset does not carry to the target")
            continue
        hit.sites.append({"offset": 4 * i, "kind": kind, "donor_address": daddr, "target_address": taddr,
                          "donor_symbol": sym, "addend": addend})


def _lost_lo(a: int, b: int) -> bool:
    """Words differing only in imm16 of an addiu/load/store whose base is not $sp."""
    if a >> 16 != b >> 16:
        return False
    op, rs = a >> 26, (a >> 21) & 31
    return rs not in (0, 29) and (op == 9 or 0x20 <= op <= 0x3F)


def scan(image: bytes, vram_delta: int, functions: list[tuple[str, int, int]], index: Index,
         near_max: int = 2) -> list[Hit]:
    """Exact and near masked-signature hits for each target ``(name, vram, size)``."""
    hits: list[Hit] = []
    for name, vram, size in functions:
        offset = vram - vram_delta
        if offset < 0 or offset + size > len(image):
            continue
        code = strip_padding(image[offset:offset + size])
        if not code:
            continue
        masked, _sites = mask(code, vram)
        exact = index.by_sig.get((signature(masked), len(code)), [])
        seen = set()
        for unit, fn in exact:
            hit = Hit(name, vram, len(code), unit, fn, "exact")
            _align(hit, code)
            hits.append(hit)
            seen.add(id(fn))
        if near_max <= 0 or len(masked) < NEAR_MIN_WORDS or exact:
            continue
        candidates = {}
        for key in chunk_keys(masked):
            for unit, fn in index.by_chunk.get(key, []):
                if fn["size"] == len(code) and id(fn) not in seen:
                    candidates[id(fn)] = (unit, fn)
        for unit, fn in candidates.values():
            dmasked, _ = mask(bytes.fromhex(fn["bytes"]), fn["vram"])
            diffs = [i for i, (a, b) in enumerate(zip(dmasked, masked)) if a != b]
            if 0 < len(diffs) <= near_max:
                hit = Hit(name, vram, len(code), unit, fn, "near", diffs, status="near")
                if all(_lost_lo(dmasked[i], masked[i]) for i in diffs):
                    hit.notes.append("only 16-bit immediates of non-stack loads/stores/addiu differ: probably "
                                     "%lo halves the straight-line pair tracker lost (masking too tight)")
                hits.append(hit)
    return hits


# --------------------------------------------------------------------------- symbol transfer

def _key(hit: Hit, site: dict) -> tuple[str, int]:
    """Identity of the donor object a site refers to: (donor, donor base address)."""
    return hit.donor, site["donor_address"] - site["addend"]


def transfer(hits: list[Hit]) -> dict:
    """Derive target addresses of donor symbols and check them across all exact hits.

    Returns ``{"symbols": {(donor, donor_addr): {...}}, "contradictions": [...], "suspicious": [...]}``
    and marks contradicting hits ``needs-review``."""
    targets_per_fn: dict[int, set[int]] = defaultdict(set)
    for hit in hits:
        if hit.kind == "exact":
            targets_per_fn[id(hit.function)].add(hit.vram)
    for hit in hits:
        if hit.kind == "exact" and len(targets_per_fn[id(hit.function)]) > 1 and hit.sites:
            hit.template = True
    votes: dict[tuple[str, int], dict[int, list[Hit]]] = defaultdict(lambda: defaultdict(list))
    names: dict[tuple[str, int], str | None] = {}
    by_name: dict[str, dict[int, set]] = defaultdict(lambda: defaultdict(set))
    for hit in hits:
        if hit.kind != "exact" or hit.template or hit.status != "candidate":
            continue
        for site in hit.sites:
            if site["donor_symbol"] is None and site["donor_address"] == site["target_address"]:
                continue        # constant / hardware address, identical on both sides
            key = _key(hit, site)
            taddr = (site["target_address"] - site["addend"]) & 0xFFFFFFFF
            if hit not in votes[key][taddr]:
                votes[key][taddr].append(hit)
            names[key] = site["donor_symbol"]
    contradictions, bad_hits = [], set()
    for key, choices in list(votes.items()):
        if len(choices) > 1:
            counts = sorted(((len({h.vram for h in hs}), a) for a, hs in choices.items()), reverse=True)
            winner = counts[0][1] if counts[0][0] >= 2 and counts[0][0] >= 3 * counts[1][0] else None
            contradictions.append({"donor": key[0], "donor_symbol": names[key], "donor_address": f"0x{key[1]:08X}",
                                   "target_addresses": {f"0x{a:08X}": sorted({h.name for h in hs})[:6]
                                                        for a, hs in choices.items()},
                                   "resolved_to": None if winner is None else f"0x{winner:08X}"})
            for a, hs in choices.items():
                if a != winner:
                    bad_hits.update(id(h) for h in hs)
            if winner is not None:
                votes[key] = {winner: choices[winner]}
    for key, choices in votes.items():
        if names[key] and not AUTO_NAME.match(names[key]):
            for taddr, hs in choices.items():
                if not all(id(h) in bad_hits for h in hs):
                    by_name[names[key]][taddr].add(key)
    for name, choices in by_name.items():
        if len(choices) > 1:
            contradictions.append({"donor_symbol": name, "cross_donor": True,
                                   "target_addresses": {f"0x{a:08X}": sorted(f"{d}:0x{v:08X}" for d, v in keys)
                                                        for a, keys in choices.items()}})
            for a in choices:
                for key in choices[a]:
                    for hs in votes[key].values():
                        bad_hits.update(id(h) for h in hs)
    for hit in hits:
        if id(hit) in bad_hits and hit.status == "candidate":
            hit.status = "needs-review"
    symbols = {}
    by_target: dict[int, set] = defaultdict(set)
    for key, choices in votes.items():
        if len(choices) != 1:
            continue
        (taddr, hs), = choices.items()
        call = any(s["kind"] in ("jal", "j") for h in hs for s in h.sites if _key(h, s) == key)
        symbols[key] = {"donor": key[0], "donor_address": key[1], "donor_symbol": names[key],
                        "target_address": taddr, "hits": len({h.name for h in hs}), "call": call}
        by_target[taddr].add(key)
    suspicious = []
    for taddr, keys in by_target.items():
        per_donor = defaultdict(set)
        for donor, daddr in keys:
            per_donor[donor].add(daddr)
        for donor, daddrs in per_donor.items():
            if len(daddrs) > 1:
                suspicious.append({"target_address": f"0x{taddr:08X}", "donor": donor,
                                   "donor_symbols": sorted(f"{names[(donor, d)] or '?'}@0x{d:08X}" for d in daddrs)})
    return {"symbols": symbols, "contradictions": contradictions, "suspicious": suspicious}


def symbol_file(transfer_result: dict) -> str:
    """Reviewable ``symbol_addrs``-style text: one line per target address, best-supported name."""
    by_target: dict[int, list[dict]] = defaultdict(list)
    for item in transfer_result["symbols"].values():
        by_target[item["target_address"]].append(item)
    lines = ["// Proposed by n64dk transplant-scan: donor symbol names transferred by instruction alignment.",
             "// Review before use; names are the donor projects' names."]
    for taddr in sorted(by_target):
        items = sorted(by_target[taddr], key=lambda i: (i["donor_symbol"] is None or bool(AUTO_NAME.match(i["donor_symbol"] or "")), -i["hits"]))
        best = items[0]
        if best["donor_symbol"] is None:
            continue
        kind = "func" if best["call"] else "data"
        others = ", ".join(f"{i['donor']}:{i['donor_symbol']}" for i in items[1:] if i["donor_symbol"])
        lines.append(f"{best['donor_symbol']} = 0x{taddr:08X}; // type:{kind} donor:{best['donor']} "
                     f"donor_addr:0x{best['donor_address']:08X} hits:{sum(i['hits'] for i in items)}"
                     + (f" also:{others}" if others else ""))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- transplant

def scratch_project(donor_root: Path, scratch: Path) -> Path:
    """A writable directory mirroring the donor's top level through symlinks (builds and the
    object cache write here, never into the donor)."""
    scratch.mkdir(parents=True, exist_ok=True)
    for entry in donor_root.iterdir():
        if entry.name in (".n64dk", ".git", "build") or entry.name.startswith("."):
            continue
        link = scratch / entry.name
        if not link.exists() and not link.is_symlink():
            try:
                link.symlink_to(entry)
            except OSError:
                pass
    return scratch


def _spec_of(unit: dict) -> BuildSpec:
    return BuildSpec(unit["pipeline"], list(unit["flags"]), {}, {}, list(unit.get("normalizer_args", [])))


def include_closure(source: Path, roots: list[Path], limit: int = 400) -> list[Path]:
    """Headers reachable from ``source`` through ``#include`` (quote: own directory first)."""
    seen, out, todo = set(), [], [source]
    while todo and len(out) < limit:
        path = todo.pop()
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for quote, name in INCLUDE.findall(text):
            for base in ([path.parent] if quote == '"' else []) + roots:
                found = base / name
                if found.is_file():
                    key = found.resolve()
                    if key not in seen:
                        seen.add(key)
                        out.append(found)
                        todo.append(found)
                    break
    return out


@dataclass
class Job:
    hits: list[Hit]                  # hits covered by this unit transplant (unit order)
    unit: dict
    vram: int                        # target address of the unit start
    size: int                        # bytes compared (unit core size)


def plan(hits: list[Hit], image: bytes, vram_delta: int,
         starts: set[int] | None = None) -> tuple[list[Job], list[dict]]:
    """Group candidate hits into unit transplants; units only partly present are reported.

    With ``starts`` (target function starts) a unit must begin at a target function start:
    the bytes before a hit can mimic a donor neighbour (a preceding ``jr ra; nop``)."""
    jobs, partial, done = [], [], set()
    for hit in hits:
        if hit.kind != "exact" or hit.status != "candidate":
            continue
        unit, fn = hit.unit, hit.function
        start = hit.vram - fn["offset"]
        key = (unit["donor"], unit["source"], unit["line"], start)
        if key in done:
            continue
        if starts is not None and start not in starts:
            hit.status = "partial-unit"
            hit.notes.append(f"donor unit would start at 0x{start:08X}, which is not a target function start")
            continue
        if len(unit["functions"]) == 1:
            done.add(key)
            jobs.append(Job([hit], unit, start, unit["core_size"]))
            continue
        offset = start - vram_delta
        code = strip_padding(image[offset:offset + unit["core_size"]]) if offset >= 0 else b""
        if len(code) == unit["core_size"] and signature(mask(code, start)[0]) == unit["unit_masked"]:
            done.add(key)
            jobs.append(Job([hit], unit, start, unit["core_size"]))
            continue
        missing = []
        for other in unit["functions"]:
            o = offset + other["offset"]
            ocode = strip_padding(image[o:o + other["size"]]) if o >= 0 else b""
            if len(ocode) != other["size"] or signature(mask(ocode, start + other["offset"])[0]) != other["masked"]:
                missing.append({"donor_function": other["name"], "expected_target_vram": f"0x{start + other['offset']:08X}",
                                "size": other["size"]})
        hit.status = "partial-unit"
        pkey = (hit.vram, unit["donor"], unit["source"])
        if pkey in done or hit.size < 16:      # tiny stubs hit inside many units: count, do not list
            continue
        done.add(pkey)
        partial.append({"target": hit.name, "vram": f"0x{hit.vram:08X}", "donor": unit["donor"],
                        "donor_unit": unit["source"], "functions_in_unit": len(unit["functions"]),
                        "missing_neighbours": missing})
    # attach the other hits that fall inside a whole-unit job
    by_start = {(j.unit["donor"], j.unit["source"], j.vram): j for j in jobs}
    for hit in hits:
        if hit.kind == "exact" and hit.status == "candidate":
            job = by_start.get((hit.unit["donor"], hit.unit["source"], hit.vram - hit.function["offset"]))
            if job and hit not in job.hits:
                job.hits.append(hit)
    return jobs, partial


def verify_job(job: Job, index: Index, target, transfer_result: dict, function_starts: set[int] | None,
               workroot: Path, toolchain_root: Path | None, data_symbols: dict | None = None) -> dict:
    from .verify import strict_compare
    unit = job.unit
    donor = index.donors[unit["donor"]]
    root = Path(donor["root"])
    project = scratch_project(root, workroot / "projects" / unit["donor"])
    cfg = Config(project=project, toolchain_root=toolchain_root, include=[Path(p) for p in donor["include"]])
    source = project / unit["source"]
    row = {"target_vram": job.vram, "size": job.size, "donor": unit["donor"], "donor_unit": unit["source"],
           "donor_pipeline": unit["pipeline"], "functions": [h.name for h in job.hits],
           "donor_functions": [f["name"] for f in unit["functions"]], "transferred": {}, "derived_sections": {},
           "conflicts": [], "notes": []}
    spec = _spec_of(unit)
    work = workroot / "objects" / hashlib.sha1(f"{unit['donor']}|{unit['source']}|{unit['flags']}|{job.vram}".encode()).hexdigest()[:12]
    try:
        work.mkdir(parents=True, exist_ok=True)
        elf = Elf.load(build(source, spec, cfg, work))
    except (BuildError, RuntimeError, OSError, ValueError) as error:
        row.update(verdict="build-failed", error=str(error)[-400:])
        return row
    donor_offset = unit["vram"] - donor["delta"]
    # donor addresses of every object symbol/section (from the donor's own retail bytes)
    dimage = _donor_image(donor["image"])
    dcode = dimage[donor_offset:donor_offset + unit["core_size"]]
    dbases, dsyms = cmp.infer_from_rom(elf, dcode, unit["vram"], {}, {})
    toff = target.vram_to_rom(job.vram)
    tcode = target.rom[toff:toff + job.size]
    tbases, tsyms = cmp.infer_from_rom(elf, tcode, job.vram, {}, {})
    table = {} if any(h.template for h in job.hits) else transfer_result["symbols"]
    row["template"] = any(h.template for h in job.hits)
    declared = symmod.SymbolMap()
    for name, taddr in tsyms.items():
        daddr = dsyms.get(name)
        item = table.get((unit["donor"], daddr)) if daddr is not None else None
        if item is None:
            # Keep target-derived values as diagnostics only.  Supplying them to strict_compare
            # would make the bytes under test their own authority and could prove a wrong symbol.
            row.setdefault("derived_unchecked", {})[name] = f"0x{taddr:08X}"
            continue
        if item["target_address"] != taddr:
            row["conflicts"].append(f"{name}: transferred 0x{item['target_address']:08X} but this unit needs 0x{taddr:08X}")
            continue
        declared[name] = taddr
        row["transferred"][name] = f"0x{taddr:08X}"
    for name, base in tbases.items():
        # a section of the unit itself: its base follows from the donor base and the aligned sites
        row["derived_sections"][name] = f"0x{base:08X}"
    if row["conflicts"]:
        row["verdict"] = "needs-review"
        return row
    # Target-inferred section bases are likewise useful evidence but never proof.  A later pass
    # may promote independently transferred/project-declared bases; this pass must fail closed.
    verdict = strict_compare(elf, target.rom, target.vram_to_rom, job.vram, job.size, declared, {},
                             None, function_starts)
    row["strict"] = verdict.as_dict()
    unverified = [s["section"] for s in verdict.sections if s.get("status") == "unverified"]
    if verdict.verdict == "mismatch" or not verdict.text_equal:
        row["verdict"] = "mismatch"
        row["first_diff"] = None if verdict.first_diff is None else f"0x{verdict.first_diff:X}"
    elif verdict.assumptions:
        row["verdict"] = "mismatch"
        row["notes"].append("strict oracle still needed retail-derived addresses: "
                            + ", ".join(a.name for a in verdict.assumptions))
    elif unverified:
        row["verdict"] = "needs-review"
        row["notes"].append("strict comparison left owned sections unverified: " + ", ".join(unverified))
    else:
        row["verdict"] = EXACT_VERDICT
    if unverified:
        row["data_unverified"] = unverified
    if row["verdict"] == "mismatch":
        row["donor_self_check"] = _self_check(elf, dimage, donor, unit, dsyms, dbases)
        row["donor_vs_target_first_diff"] = _first_raw_diff(dcode, tcode)
        row["cause"] = _cause(row, elf, dcode, unit["vram"])
    row["_elf_spec"] = (spec, declared, dict(tbases), source)
    return row


def _cause(row: dict, elf: Elf, dcode: bytes, dvram: int) -> str:
    """First-pass classification of a transplant mismatch."""
    if row.get("donor_self_check") != "ok":
        return "donor-recipe-not-reproducible"
    relocated = {r.offset for r in cmp.relocations(elf, ".text")}
    _m, sites = mask(dcode, dvram)
    hard = [4 * i for i, kind, _a in sites if kind in ("jal", "j", "hi", "lo") and 4 * i not in relocated]
    first = row.get("donor_vs_target_first_diff")
    if hard and first is not None and int(first, 16) in hard:
        return "donor-source-hardcodes-address"
    if first is not None and any(int(first, 16) == 4 * i for i, kind, _a in sites if kind == "lui"):
        return "masked-constant-differs"
    if first is None:
        return "data-differs" if row.get("strict", {}).get("text_equal") else "relocation-or-size"
    return "other"


def _first_raw_diff(a: bytes, b: bytes) -> str | None:
    for i in range(0, min(len(a), len(b)) - 3, 4):
        if a[i:i + 4] != b[i:i + 4]:
            return f"0x{i:X}"
    return None


def _self_check(elf: Elf, dimage: bytes, donor: dict, unit: dict, dsyms: dict, dbases: dict) -> str:
    """Does the donor recipe, as indexed, rebuild the donor's own retail bytes?  A ``no``
    means the mismatch is a recipe/lane problem (normalizer, assembler, flags), not the target."""
    from .verify import strict_compare
    syms = symmod.SymbolMap(dsyms)
    result = strict_compare(elf, dimage, lambda v: v - donor["delta"], unit["vram"], unit["core_size"], syms,
                            dict(dbases), None, None)
    return "ok" if result.text_equal else f"fails at 0x{result.first_diff or 0:X}"


_IMAGES: dict[str, bytes] = {}


def _donor_image(path: str) -> bytes:
    if path not in _IMAGES:
        from ..rom import Rom
        _IMAGES[path] = Rom.load(path).data
    return _IMAGES[path]


def _manifest_row(job_row: dict, target, out_source: str, include_flags: list[str]) -> str:
    spec, declared, bases, _source = job_row["_elf_spec"]
    out = BuildSpec(spec.pipeline, spec.flags + [f for f in include_flags if f not in spec.flags], {k: v for k, v in bases.items()}, dict(declared), spec.normalizer_args)
    return f"0x{target.vram_to_rom(job_row['target_vram']):X}\t0x{job_row['size']:X}\t{out_source}\t{out.manifest_flags()}"


def write_outputs(out_dir: Path, rows: list[dict], index: Index, target, report: dict, symtext: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "proposed_symbol_addrs.txt").write_text(symtext)
    manifests: dict[tuple[str, str], list[str]] = defaultdict(list)
    for row in rows:
        if row.get("verdict") != EXACT_VERDICT:
            continue
        donor = index.donors[row["donor"]]
        root = Path(donor["root"])
        src = root / row["donor_unit"]
        rel = Path(row["donor"]) / row["donor_unit"]
        dest = out_dir / "src" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest)
        flag_dirs = [root / f[2:] for f in row["_elf_spec"][0].flags if f.startswith("-I") and len(f) > 2]
        roots = flag_dirs + [Path(p) for p in donor["include"]] + [root / "include", root]
        for header in include_closure(src, roots):
            try:
                hrel = header.resolve().relative_to(root.resolve())
            except ValueError:
                continue
            hdest = out_dir / "src" / row["donor"] / hrel
            if not hdest.exists():
                hdest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(header, hdest)
        includes = []
        for path in donor["include"]:
            try:
                includes.append(f"-I{Path(path).resolve().relative_to(root.resolve())}")
            except ValueError:
                includes.append(f"-I{path}")
        manifests[(row["donor"], row["donor_pipeline"])].append(_manifest_row(row, target, row["donor_unit"], includes))
    for (donor_name, pipe), lines in manifests.items():
        name = donor_name + "_" + pipe.replace("+", "_").replace(".", "")
        (out_dir / f"proposed_{name}.tsv").write_text(
            f"# {pipe} rows proposed by donor transplant from {donor_name}; SOURCE paths are relative to\n"
            f"# src/{donor_name}/ (the source and the headers it includes, in the donor's layout)\n"
            "# ROM_START\tSIZE\tSOURCE\tFLAGS\n" + "\n".join(sorted(lines)) + "\n")
    (out_dir / "report.json").write_text(json.dumps(report, indent=1, default=str))


def select_rows(rows: list[dict]) -> list[dict]:
    """Keep non-overlapping exact rows (largest first); overlapped exact rows become ``superseded``."""
    taken: list[tuple[int, int]] = []
    exact = sorted((r for r in rows if r["verdict"] == EXACT_VERDICT), key=lambda r: (-r["size"], r["target_vram"]))
    for row in exact:
        lo, hi = row["target_vram"], row["target_vram"] + row["size"]
        if any(a < hi and lo < b for a, b in taken):
            row["verdict"] = "superseded"
            row["notes"].append("overlaps a larger exact transplant")
        else:
            taken.append((lo, hi))
    return rows


_STATUS_ORDER = ("candidate", "partial-unit", "needs-review", "local-inconsistent")


def _by_vram(hits: list[Hit]) -> dict[int, list[Hit]]:
    out: dict[int, list[Hit]] = defaultdict(list)
    for hit in hits:
        if hit.kind == "exact":
            out[hit.vram].append(hit)
    return out


def _best_status(hits: list[Hit]) -> str:
    return min((h.status for h in hits), key=lambda s: _STATUS_ORDER.index(s) if s in _STATUS_ORDER else 99)


def manifest_declared_addresses(paths) -> set[int]:
    """Addresses a project declares in manifest flags (``--symbol=``, ``--section-base=``)."""
    out = set()
    for path in paths:
        for m in re.finditer(r"--(?:symbol|section-base)=[^:\s]+:(0x[0-9A-Fa-f]+)", Path(path).read_text()):
            out.add(int(m.group(1), 16))
    return out


def run(target_image: bytes | None, target, functions: list[tuple[str, int, int]], index: Index,
        skip: list[tuple[int, int]] | None = None, out_dir: Path | None = None, jobs: int = 4,
        toolchain_root: Path | None = None, verify: bool = True, near_max: int = 2,
        target_symbols: symmod.SymbolMap | None = None, truth_addresses: set[int] | None = None) -> dict:
    """Scan, transfer, transplant and verify; return the report dict (and write outputs)."""
    t0 = time.time()
    skip = sorted(skip or [])
    def skipped(vram, size):
        return any(a < vram + size and vram < b for a, b in skip)
    todo = [f for f in functions if not skipped(f[1], f[2])]
    hits = scan(target.rom, target.delta, todo, index, near_max)
    xfer = transfer(hits)
    starts = {v for _n, v, _s in functions}
    jobs_list, partial = plan(hits, target.rom, target.delta, starts)
    t_scan = time.time() - t0
    rows: list[dict] = []
    if verify and jobs_list:
        # one job per target unit address: try donors in order until one is exact
        by_addr: dict[int, list[Job]] = defaultdict(list)
        for job in jobs_list:
            by_addr[job.vram].append(job)
        for alts in by_addr.values():
            alts.sort(key=lambda j: (len(j.unit["functions"]) != 1, j.unit["donor"], j.unit["source"]))
        with tempfile.TemporaryDirectory(prefix="n64dk-transplant-") as tmp:
            def attempt(alts):
                tried = []
                for job in alts[:4]:
                    row = verify_job(job, index, target, xfer, starts, Path(tmp), toolchain_root)
                    tried.append(row)
                    if row["verdict"] == EXACT_VERDICT:
                        break
                best = next((r for r in tried if r["verdict"] == EXACT_VERDICT), tried[0])
                best["alternatives_tried"] = len(tried)
                if best["verdict"] != EXACT_VERDICT:
                    best["other_attempts"] = [{"donor": r["donor"], "unit": r["donor_unit"], "verdict": r["verdict"]}
                                              for r in tried[1:]]
                return best
            with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
                rows = list(pool.map(attempt, by_addr.values()))
        rows = select_rows(rows)
    t_verify = time.time() - t0 - t_scan
    # symbol transfer precision against the target catalogue (calls) and symbol file (data)
    precision = {"calls": 0, "calls_at_function_start": 0, "data": 0, "data_at_known_symbol": 0,
                 "confirmed_by_exact_transplant": 0}
    confirmed = {int(a, 16) for r in rows if r["verdict"] == EXACT_VERDICT for a in r["transferred"].values()}
    known = set((target_symbols or {}).values()) | set(truth_addresses or ())
    for item in xfer["symbols"].values():
        precision["confirmed_by_exact_transplant"] += item["target_address"] in confirmed
        if item["call"]:
            precision["calls"] += 1
            precision["calls_at_function_start"] += item["target_address"] in starts
        else:
            precision["data"] += 1
            precision["data_at_known_symbol"] += item["target_address"] in known
    verdicts = Counter(r["verdict"] for r in rows)
    exact_rows = [r for r in rows if r["verdict"] == EXACT_VERDICT]
    sizes = {v: size for _n, v, size in functions}
    new_funcs = set()
    for r in exact_rows:
        lo, hi = r["target_vram"], r["target_vram"] + r["size"]
        inside = [v for v in starts if lo <= v < hi]
        matched = [v for v in inside if skipped(v, sizes[v])]
        if matched:
            r["overlaps_matched"] = [f"0x{v:08X}" for v in sorted(matched)]
            r["notes"].append(f"unit covers {len(matched)} function(s) the target already matched")
        new_funcs.update(v for v in inside if v not in matched)
    report = {
        "functions_considered": len(todo), "functions_skipped": len(functions) - len(todo),
        "exact_hit_functions": len({h.vram for h in hits if h.kind == "exact"}),
        "exact_hit_bytes": sum({h.vram: h.size for h in hits if h.kind == "exact"}.values()),
        "near_hit_functions": len({h.vram for h in hits if h.kind == "near"} - {h.vram for h in hits if h.kind == "exact"}),
        "hit_status_by_function": dict(Counter(_best_status(hs) for hs in _by_vram(hits).values())),
        "unit_transplants": len(rows), "verdicts": dict(verdicts),
        "functions_recovered_new": len(new_funcs),
        "bytes_recovered_new": sum(sizes[v] for v in new_funcs),
        "rows_overlapping_matched": sum(1 for r in exact_rows if r.get("overlaps_matched")),
        "functions_recovered": len({v for r in exact_rows for v in starts if r["target_vram"] <= v < r["target_vram"] + r["size"]}),
        "mismatch_causes": dict(Counter(r.get("cause", "?") for r in rows if r["verdict"] == "mismatch")),
        "template_units_exact": sum(1 for r in exact_rows if r.get("template")),
        "bytes_recovered": sum(r["size"] for r in exact_rows),
        "data_unverified_units": sum(1 for r in exact_rows if r.get("data_unverified")),
        "symbol_transfer": {"symbols": len(xfer["symbols"]), "contradictions": len(xfer["contradictions"]),
                            "suspicious": len(xfer["suspicious"]), "precision": precision},
        "timing_s": {"scan": round(t_scan, 2), "verify": round(t_verify, 2)},
        "rows": [{k: (f"0x{v:08X}" if k == "target_vram" else v) for k, v in r.items() if not k.startswith("_")}
                 for r in sorted(rows, key=lambda r: r["target_vram"])],
        "partial_units": partial,
        "near_hits": [h.row() for h in hits if h.kind == "near"][:500],
        "needs_review": [h.row() for h in hits if h.status in ("needs-review", "local-inconsistent", "constant-differs")],
        "contradictions": xfer["contradictions"], "suspicious": xfer["suspicious"],
    }
    symtext = symbol_file(xfer)
    report["proposed_symbol_count"] = symtext.count("\n") - 2
    if out_dir is not None:
        write_outputs(Path(out_dir), rows, index, target, report, symtext)
    report["_symbol_file"] = symtext
    return report
