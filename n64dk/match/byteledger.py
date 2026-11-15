"""Authoritative byte-ownership ledger for one image.

Every byte of an image's declared extent has exactly one owner class:

``c-verified``          manifest row for compiled C with a strict passing verdict
``c-declared``          manifest row for compiled C without a strict verdict
``asm-proven``          assembly manifest row with provenance (a target-text digest)
``asm-declared``        assembly manifest row without provenance
``data``                data manifests, released data, caller-classified data
``jump-table``          jump tables
``padding``             alignment / trailing padding (never code)
``fragment``            interior piece of another function (carries its owner)
``function-unmatched``  catalogued function with no source
``unknown``             nothing claims it

Inputs are generic: image identity, a catalogue, manifests tagged with a class by the caller,
optional boundary operations, optional extra interval files.  ``Ledger.check`` reports
violations, ``Ledger.totals`` counts bytes and functions per class, ``reconcile`` explains every
numerator/denominator change between two ledgers.
"""
from __future__ import annotations

import bisect
import hashlib
import re
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path

CLASSES = ("c-verified", "c-declared", "asm-proven", "asm-declared", "data", "jump-table", "padding",
           "fragment", "function-unmatched", "unknown")
C_CLASSES = ("c-verified", "c-declared")
ASM_CLASSES = ("asm-proven", "asm-declared")
CODE_CLASSES = C_CLASSES + ASM_CLASSES + ("fragment", "function-unmatched")
_HEX = re.compile(r"^(0x)?[0-9A-Fa-f]+$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
# Only the strict verifier's terminal verdict can create verified ownership.  Legacy/generic
# success words describe workflow state, not byte identity, and therefore remain declarations.
PASSING = {"exact", "exact_current_target", "strict-exact"}


def hx(value: int) -> str:
    return f"0x{value:08X}"


# ---------------------------------------------------------------------------------------------
# manifests


@dataclass
class ManifestRow:
    vram: int
    size: int
    source: str
    cls: str              # c | asm | data (from the caller's tag, refined by the source suffix)
    digest: str = ""
    origin: str = ""      # path:line

    @property
    def end(self) -> int:
        return self.vram + self.size


def read_manifest(path, vram_delta: int, cls: str) -> list[ManifestRow]:
    """Rows of a matching manifest.  Recognised layouts (tab or blank separated):

    * ``OFFSET SIZE SOURCE [FLAGS] [SHA256]`` -- OFFSET is a file offset in the image
      (vram = OFFSET + vram_delta);
    * ``NAME VRAM SIZE [STATUS]`` -- unit rows with explicit addresses;
    * ``GROUP SOURCE .SECTION VRAM SIZE [SHA256] ...`` -- data rows with explicit addresses.

    ``cls`` is the caller's tag (c, asm, data); a ``.s`` source in a C manifest is asm."""
    out = []
    header: dict[str, int] | None = None
    for lineno, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            names = [c.strip() for c in line.lstrip("# ").split("\t" if "\t" in line else None)]
            if all(re.match(r"^[A-Z][A-Z0-9_]*$", n) for n in names) and "SIZE" in names and ("VRAM" in names or "ROM_START" in names):
                header = {n: k for k, n in enumerate(names)}
            continue
        cols = line.split("\t") if "\t" in line else line.split()
        cols = [c.strip() for c in cols]
        row = None
        digest = next((c for c in cols if _DIGEST.match(c)), "")
        if header and len(cols) >= len(header) - 1:
            try:
                size = int(cols[header["SIZE"]], 16)
                vram = int(cols[header["VRAM"]], 16) if "VRAM" in header else int(cols[header["ROM_START"]], 16) + vram_delta
                source = cols[header["SOURCE"]] if "SOURCE" in header else cols[header.get("NAME", 0)]
                row = (vram, size, source)
            except (ValueError, IndexError):
                row = None
        elif len(cols) >= 3 and _HEX.match(cols[0]) and _HEX.match(cols[1]) and not _HEX.match(cols[2]):
            row = (int(cols[0], 16) + vram_delta, int(cols[1], 16), cols[2])
        elif len(cols) >= 5 and cols[2].startswith(".") and _HEX.match(cols[3]) and _HEX.match(cols[4]):
            row = (int(cols[3], 16), int(cols[4], 16), cols[1])
        elif len(cols) >= 3 and not _HEX.match(cols[0]) and _HEX.match(cols[1]) and _HEX.match(cols[2]):
            row = (int(cols[1], 16), int(cols[2], 16), cols[0])
        if row is None or row[1] <= 0:
            continue
        kind = cls
        if cls == "c" and row[2].endswith((".s", ".S")):
            kind = "asm"
        out.append(ManifestRow(row[0] & 0xFFFFFFFF, row[1], row[2], kind, digest, f"{path}:{lineno}"))
    return out


def verified_intervals(rows: list[ManifestRow]) -> list[tuple[int, int, str]]:
    return [(r.vram, r.end, f"{r.source}") for r in rows]


def read_verdicts(path) -> dict[str, bool]:
    """``KEY VERDICT`` lines; KEY is a source path or a hex VRAM."""
    out = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t") if "\t" in line else line.split()
        if len(cols) >= 2:
            key = cols[0]
            if _HEX.match(key):
                key = hx(int(key, 16))
            out[key] = cols[1].strip().lower() in PASSING
    return out


def read_intervals(path) -> list[tuple[int, int, str, str]]:
    """Extra interval file: ``START SIZE CLASS [NOTE]`` (hex start/size)."""
    out = []
    for line in Path(path).read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t") if "\t" in line else line.split(None, 3)
        if len(cols) >= 3 and _HEX.match(cols[0]) and _HEX.match(cols[1]):
            if cols[2] not in CLASSES:
                raise ValueError(f"{path}: unknown class {cols[2]!r}")
            out.append((int(cols[0], 16), int(cols[1], 16), cols[2], cols[3].strip() if len(cols) > 3 else ""))
    return out


# ---------------------------------------------------------------------------------------------
# ledger


@dataclass
class ImageInfo:
    name: str
    digest: str
    size: int
    vram_delta: int
    segments: list[tuple[int, int, int, str]] = field(default_factory=list)   # rom, image offset, size, transform

    @classmethod
    def of(cls, name: str, data: bytes, vram_delta: int, segments=()) -> "ImageInfo":
        return cls(name, hashlib.sha256(data).hexdigest(), len(data), vram_delta, [tuple(s) for s in segments])

    def rom_of(self, vram: int) -> int | str:
        off = vram - self.vram_delta
        for rom, image_off, size, transform in self.segments:
            if image_off <= off < image_off + size:
                return rom + off - image_off if transform == "copy" else f"compressed:{transform}"
        return "-"


@dataclass
class Interval:
    start: int
    end: int
    cls: str
    name: str = "-"
    owner: str = "-"
    source: str = "-"
    note: str = "-"

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class Function:
    name: str
    vram: int
    size: int
    status: str = ""          # c, asm, partial, unmatched, data, other
    note: str = "-"

    @property
    def end(self) -> int:
        return self.vram + self.size


@dataclass
class Violation:
    kind: str
    start: int
    end: int
    message: str


class Ledger:
    def __init__(self, image: ImageInfo, extent: tuple[int, int]):
        self.image = image
        self.extent = extent
        self.intervals: list[Interval] = []
        self.functions: list[Function] = []
        self.manifests: list[ManifestRow] = []
        self.conflicts: list[Violation] = []
        self.root: str = ""

    # -- painting
    def _free(self, start: int, end: int) -> list[tuple[int, int]]:
        starts = [i.start for i in self.intervals]
        k = max(0, bisect.bisect_right(starts, start) - 1)
        out, cursor = [], start
        for item in self.intervals[k:]:
            if item.start >= end:
                break
            if item.end <= cursor:
                continue
            if item.start > cursor:
                out.append((cursor, item.start))
            cursor = max(cursor, item.end)
        if cursor < end:
            out.append((cursor, end))
        return out

    def paint(self, start: int, end: int, cls: str, **kw) -> list[tuple[int, int]]:
        """Claim the unowned bytes of [start, end) clipped to the extent; returns the pieces
        that were already owned (the caller decides whether that is a violation)."""
        lo, hi = max(start, self.extent[0]), min(end, self.extent[1])
        if lo >= hi:
            return []
        free = self._free(lo, hi)
        for a, b in free:
            bisect.insort(self.intervals, Interval(a, b, cls, **kw), key=lambda i: i.start)
        taken, cursor = [], lo
        for a, b in free:
            if a > cursor:
                taken.append((cursor, a))
            cursor = b
        if cursor < hi:
            taken.append((cursor, hi))
        return taken

    def owner_at(self, address: int) -> Interval | None:
        starts = [i.start for i in self.intervals]
        k = bisect.bisect_right(starts, address) - 1
        if k >= 0 and self.intervals[k].start <= address < self.intervals[k].end:
            return self.intervals[k]
        return None

    def classes_in(self, start: int, end: int) -> dict[str, int]:
        out: dict[str, int] = {}
        starts = [i.start for i in self.intervals]
        k = max(0, bisect.bisect_right(starts, start) - 1)
        for item in self.intervals[k:]:
            if item.start >= end:
                break
            overlap = min(end, item.end) - max(start, item.start)
            if overlap > 0:
                out[item.cls] = out.get(item.cls, 0) + overlap
        return out

    # -- reports
    def totals(self) -> dict:
        size = self.extent[1] - self.extent[0]
        by_class = {c: 0 for c in CLASSES}
        for item in self.intervals:
            by_class[item.cls] += item.size
        functions: dict[str, int] = {}
        for f in self.functions:
            functions[f.status] = functions.get(f.status, 0) + 1
        out = {
            "extent": f"{hx(self.extent[0])}..{hx(self.extent[1])}", "extent_bytes": size,
            "bytes": by_class, "sum_equals_extent": sum(by_class.values()) == size,
            "code_bytes": sum(by_class[c] for c in CODE_CLASSES),
            "c_bytes": sum(by_class[c] for c in C_CLASSES), "asm_bytes": sum(by_class[c] for c in ASM_CLASSES),
            "functions": len(self.functions), "functions_by_status": dict(sorted(functions.items())),
            "functions_matched_c": functions.get("c", 0), "functions_asm": functions.get("asm", 0),
        }
        return out

    def check(self) -> list[Violation]:
        out = list(self.conflicts)
        lo, hi = self.extent
        size = hi - lo
        if sum(i.size for i in self.intervals) != size:
            out.append(Violation("invariant", lo, hi, "bytes by class do not sum to the extent size"))
        cursor = lo
        for item in self.intervals:
            if item.start != cursor:
                out.append(Violation("invariant", cursor, item.start, "interval table is not contiguous"))
            cursor = item.end
        run = None
        for item in self.intervals + [Interval(hi, hi, "end")]:
            if item.cls == "unknown" and run and run[1] == item.start:
                run = (run[0], item.end)
                continue
            if run:
                out.append(Violation("gap", run[0], run[1], f"{run[1] - run[0]} byte(s) owned by nothing"))
                run = None
            if item.cls == "unknown":
                run = (item.start, item.end)
        image_lo, image_hi = self.image.vram_delta, self.image.vram_delta + self.image.size
        ends = {f.end for f in self.functions}
        starts = {f.vram: f for f in self.functions}
        for row in self.manifests:
            if row.vram < image_lo or row.end > image_hi:
                out.append(Violation("outside", row.vram, row.end, f"{row.source} ({row.origin}) lies outside "
                                     f"the image {hx(image_lo)}..{hx(image_hi)}"))
            candidates = [row.source] if Path(row.source).suffix else \
                [row.source, f"src/{row.source}.c", f"src/code/{row.source}.c"]     # unit rows (manifest.parse)
            if self.root and row.cls != "data" and not any((Path(self.root) / c).exists() for c in candidates):
                out.append(Violation("missing-source", row.vram, row.end, f"{row.source} does not exist"))
            f = starts.get(row.vram)
            covered_end = max((g.end for g in self.functions if row.vram <= g.vram and g.end <= row.end), default=None)
            aligned = covered_end is not None and 0 <= row.end - covered_end < 16    # aggregate unit + alignment
            if f is not None and f.size != row.size and row.cls != "data" and row.end not in ends and not aligned:
                out.append(Violation("stale", row.vram, row.end, f"{row.source} has size {hx(row.size)} but the "
                                     f"catalogue row {f.name} has size {hx(f.size)} (and {hx(row.end)} is no "
                                     "catalogue boundary)"))
        for f in self.functions:
            if f.status == "partial":
                out.append(Violation("partial", f.vram, f.end, f"{f.name}: {f.note}"))
        return sorted(out, key=lambda v: (v.start, v.kind))

    def double_covered(self) -> list[str]:
        """Catalogue functions overlapped by two or more manifest rows that overlap each other."""
        names = []
        for f in self.functions:
            hits = [r for r in self.manifests if r.vram < f.end and f.vram < r.end and r.cls != "data"]
            if any(a.vram < b.end and b.vram < a.end for k, a in enumerate(hits) for b in hits[k + 1:]):
                names.append(f.name)
        return names

    # -- persistence
    def to_tsv(self, path) -> Path:
        lines = ["# n64dk byte-ownership ledger",
                 f"#! image\t{self.image.name}", f"#! digest\t{self.image.digest}",
                 f"#! size\t{self.image.size}", f"#! vram_delta\t{hx(self.image.vram_delta)}",
                 f"#! extent\t{hx(self.extent[0])}\t{hx(self.extent[1])}", f"#! root\t{self.root or '-'}"]
        for seg in self.image.segments:
            lines.append("#! segment\t" + "\t".join([hx(seg[0]), hx(seg[1]), hx(seg[2]), seg[3]]))
        lines.append("# interval\tSTART\tEND\tSIZE\tCLASS\tNAME\tOWNER\tSOURCE\tNOTE\tIMAGE_OFFSET\tROM")
        for i in self.intervals:
            lines.append("\t".join(["interval", hx(i.start), hx(i.end), hx(i.size), i.cls, i.name, i.owner,
                                    i.source, i.note, hx(i.start - self.image.vram_delta),
                                    (lambda r: hx(r) if isinstance(r, int) else r)(self.image.rom_of(i.start))]))
        lines.append("# function\tVRAM\tSIZE\tNAME\tSTATUS\tNOTE")
        for f in self.functions:
            lines.append("\t".join(["function", hx(f.vram), hx(f.size), f.name, f.status, f.note]))
        lines.append("# manifest\tVRAM\tSIZE\tCLASS\tSOURCE\tDIGEST\tORIGIN")
        for r in self.manifests:
            lines.append("\t".join(["manifest", hx(r.vram), hx(r.size), r.cls, r.source, r.digest or "-", r.origin]))
        for v in self.conflicts:
            lines.append("\t".join(["conflict", hx(v.start), hx(v.end), v.kind, v.message]))
        Path(path).write_text("\n".join(lines) + "\n")
        return Path(path)

    @classmethod
    def from_tsv(cls, path) -> "Ledger":
        meta, segments, intervals, functions, manifests, conflicts = {}, [], [], [], [], []
        for line in Path(path).read_text().splitlines():
            if line.startswith("#! "):
                key, *vals = line[3:].split("\t")
                if key == "segment":
                    segments.append((int(vals[0], 16), int(vals[1], 16), int(vals[2], 16), vals[3]))
                else:
                    meta[key] = vals
                continue
            if not line or line.startswith("#"):
                continue
            c = line.split("\t")
            if c[0] == "interval":
                intervals.append(Interval(int(c[1], 16), int(c[2], 16), c[4], c[5], c[6], c[7], c[8]))
            elif c[0] == "function":
                functions.append(Function(c[3], int(c[1], 16), int(c[2], 16), c[4], c[5]))
            elif c[0] == "manifest":
                manifests.append(ManifestRow(int(c[1], 16), int(c[2], 16), c[4], c[3],
                                             "" if c[5] == "-" else c[5], c[6]))
            elif c[0] == "conflict":
                conflicts.append(Violation(c[3], int(c[1], 16), int(c[2], 16), c[4]))
        image = ImageInfo(meta["image"][0], meta["digest"][0], int(meta["size"][0]), int(meta["vram_delta"][0], 16),
                          segments)
        ledger = cls(image, (int(meta["extent"][0], 16), int(meta["extent"][1], 16)))
        ledger.intervals, ledger.functions, ledger.manifests, ledger.conflicts = intervals, functions, manifests, conflicts
        ledger.root = "" if meta.get("root", ["-"])[0] == "-" else meta["root"][0]
        return ledger


def _trailing_padding(data: bytes | None, delta: int, vram: int, size: int) -> int:
    """Zero words after the final terminator + delay slot (flow.nop_roles 'padding')."""
    if data is None or size < 12:
        return 0
    from ..analysis import flow as flowmod
    fl = flowmod.analyse(data[vram - delta:vram - delta + size], vram)
    pad = 0
    for address, role in reversed(flowmod.nop_roles(fl)):
        if role == "padding" and address == vram + size - 4 - pad:
            pad += 4
        else:
            break
    return pad


def build(image: ImageInfo, catalogue: list[tuple[str, int, int]], manifests: list[ManifestRow],
          data: bytes | None = None, operations: list[dict] | None = None, min_confidence: float = 0.8,
          extra: list[tuple[int, int, str, str]] = (), verdicts: dict[str, bool] | None = None,
          extent: tuple[int, int] | None = None, root: str | Path | None = None,
          padding_from_nops: bool = True, zero_gap_padding: int = 0) -> Ledger:
    """Build the ledger.  ``catalogue`` is in the image's address space.  ``operations`` (from the
    boundary solver) are applied first: absorbed rows become ``fragment`` of their new owner and
    released bytes take their class.  ``verdicts`` (source or hex VRAM -> passed) decide
    ``c-verified`` vs ``c-declared``; without them every C row is ``c-declared``.  Uncovered
    all-zero runs between owned intervals are padding (``zero_gap_padding`` > 0 limits their length)."""
    from ..analysis import boundaries as bmod
    image_lo, image_hi = image.vram_delta, image.vram_delta + image.size
    rows = sorted(set(catalogue), key=lambda r: r[1])
    fragments: list[tuple[int, int, str, str]] = []
    released: list[tuple[int, int, str, str]] = []
    if operations:
        rows, applied, _skipped = bmod.apply(rows, operations, min_confidence)
        for op in applied:
            if op["kind"] == "merge":
                owner = op["insert"][0]["name"]
                for r in op["remove"][1:]:
                    fragments.append((int(r["vram"], 16), int(r["size"], 16), owner, r["name"]))
            for r in op.get("released", []):
                released.append((int(r["vram"], 16), int(r["size"], 16), r["class"], f"{op['id']} {op['kind']}"))
    inside = [r for r in manifests if image_lo <= r.vram and r.end <= image_hi]
    if extent is None:
        spans = [(v, v + s) for _n, v, s in rows] + [(r.vram, r.end) for r in inside]
        extent = (min(a for a, _b in spans), max(b for _a, b in spans)) if spans else (image_lo, image_lo)
    ledger = Ledger(image, extent)
    ledger.root = str(root) if root else ""
    ledger.manifests = list(manifests)
    verdicts = verdicts or {}
    # 1. manifests (ground truth): C, asm, data -- in that order; overlaps are violations
    order = {"c": 0, "asm": 1, "data": 2}
    for row in sorted(manifests, key=lambda r: (order.get(r.cls, 3), r.vram)):
        if row.cls == "c":
            verdict = verdicts.get(row.source, verdicts.get(hx(row.vram)))
            cls = "c-verified" if verdict else "c-declared"
        elif row.cls == "asm":
            cls = "asm-proven" if row.digest else "asm-declared"
        else:
            cls = "data"
        taken = ledger.paint(row.vram, row.end, cls, name=Path(row.source).stem, source=row.source,
                             note=row.origin.rsplit("/", 1)[-1])
        for a, b in taken:
            other = ledger.owner_at(a)
            ledger.conflicts.append(Violation("overlap", a, b, f"{row.source} ({row.origin}) and "
                                              f"{other.source if other else '?'} both own these bytes"))
    # 2. caller-supplied classifications, released bytes, fragments
    for start, size, cls, note in extra:
        ledger.paint(start, start + size, cls, note=note or "extra interval")
    for start, size, cls, note in released:
        ledger.paint(start, start + size, cls, note=note)
    for start, size, owner, name in fragments:
        ledger.paint(start, start + size, "fragment", name=name, owner=owner, note="absorbed by merge")
    # 3. catalogue functions: trailing padding first, then the body
    for name, vram, size in rows:
        pad = _trailing_padding(data, image.vram_delta, vram, size) if padding_from_nops else 0
        if pad:
            ledger.paint(vram + size - pad, vram + size, "padding", owner=name, note="trailing nop padding")
        ledger.paint(vram, vram + size, "function-unmatched", name=name)
    # 4. small zero gaps are alignment padding; everything else is unknown
    for a, b in ledger._free(*extent):
        zero = data is not None and not any(data[a - image.vram_delta:b - image.vram_delta])
        if zero and (zero_gap_padding <= 0 or b - a < zero_gap_padding):
            ledger.paint(a, b, "padding", note="zero alignment gap")
        else:
            ledger.paint(a, b, "unknown")
    # 5. function status from the final ownership
    for name, vram, size in rows:
        classes = ledger.classes_in(vram, vram + size)
        body = {k: v for k, v in classes.items() if k != "padding"}
        if body and set(body) <= set(C_CLASSES):
            status = "c"
        elif body and set(body) <= set(ASM_CLASSES):
            status = "asm"
        elif body and set(body) <= set(C_CLASSES + ASM_CLASSES):
            status = "c+asm"
        elif not body:
            status = "padding"
        elif set(body) <= {"function-unmatched", "fragment"}:
            status = "unmatched"
        elif set(body) & set(C_CLASSES + ASM_CLASSES):
            status = "partial"
        elif set(body) <= {"data", "jump-table"}:
            status = "data"
        else:
            status = "other"
        note = ",".join(f"{k}:{v}" for k, v in sorted(classes.items())) if status in ("partial", "other") else "-"
        ledger.functions.append(Function(name, vram, size, status, note))
    return ledger


# ---------------------------------------------------------------------------------------------
# reconcile


def _n(value: int) -> str:
    return f"{value:,}"


def reconcile(before: Ledger, after: Ledger) -> dict:
    """Explain every numerator/denominator change between two ledgers of the same image."""
    sentences = []
    tb, ta = before.totals(), after.totals()
    if before.image.digest != after.image.digest:
        sentences.append(f"WARNING: different images ({before.image.name} {before.image.digest[:12]} vs "
                         f"{after.image.name} {after.image.digest[:12]})")
    fb = {(f.vram): f for f in before.functions}
    fa = {(f.vram): f for f in after.functions}

    def what_is(ledger: Ledger, vram: int) -> str:
        item = ledger.owner_at(vram)
        if item is None:
            return "outside the extent"
        if item.cls == "fragment":
            return f"reclassified as fragment of {item.owner}"
        containing = [f for f in ledger.functions if f.vram < vram < f.end]
        if containing:
            return f"now inside {containing[0].name} ({hx(containing[0].vram)}+{hx(containing[0].size)})"
        return f"reclassified as {item.cls}"

    byte_delta = {c: ta["bytes"][c] - tb["bytes"][c] for c in CLASSES}
    tail = f"; C bytes {byte_delta['c-verified'] + byte_delta['c-declared']:+,}"
    reasons = []
    for vram, f in sorted(fb.items()):
        if vram not in fa:
            reasons.append(f"{f.name} {what_is(after, vram)}")
        elif fa[vram].size != f.size:
            reasons.append(f"{f.name} size {hx(f.size)} -> {hx(fa[vram].size)}")
    for vram, f in sorted(fa.items()):
        if vram not in fb:
            reasons.append(f"{f.name} added at {hx(vram)}+{hx(f.size)} (" + what_was(before, vram) + ")")
    if tb["functions"] != ta["functions"] or reasons:
        sentences.append(f"denominator {_n(tb['functions'])} -> {_n(ta['functions'])}: "
                         + ("; ".join(reasons[:40]) if reasons else "no row changes") +
                         (f"; ... {len(reasons) - 40} more" if len(reasons) > 40 else "") + tail)
    status_changes = []
    for vram, f in sorted(fa.items()):
        old = fb.get(vram)
        if old is not None and (old.status == "c") != (f.status == "c"):
            status_changes.append(f"{f.name} {old.status} -> {f.status}")
        elif old is None and f.status == "c":
            status_changes.append(f"{f.name} new and matched")
    for vram, f in sorted(fb.items()):
        if vram not in fa and f.status == "c":
            status_changes.append(f"{f.name} was matched and is no longer a row")
    if tb["functions_matched_c"] != ta["functions_matched_c"] or status_changes:
        sentences.append(f"numerator (C-matched functions) {_n(tb['functions_matched_c'])} -> "
                         f"{_n(ta['functions_matched_c'])}: " + ("; ".join(status_changes[:40]) or "no status changes"))
    for c in CLASSES:
        if byte_delta[c]:
            sentences.append(f"{c} bytes {_n(tb['bytes'][c])} -> {_n(ta['bytes'][c])} ({byte_delta[c]:+,})")
    if tb["code_bytes"] != ta["code_bytes"]:
        sentences.append(f"code bytes {_n(tb['code_bytes'])} -> {_n(ta['code_bytes'])} "
                         f"({ta['code_bytes'] - tb['code_bytes']:+,}; padding and data never count as code)")
    if not sentences:
        sentences.append("no change in any numerator, denominator or class total")
    return {"before": tb, "after": ta, "sentences": sentences}


def what_was(ledger: Ledger, vram: int) -> str:
    item = ledger.owner_at(vram)
    if item is None:
        return "previously outside the extent"
    if item.cls == "function-unmatched" and item.name != "-":
        return f"previously inside {item.name}"
    return f"previously {item.cls}" + (f" {item.name}" if item.name != "-" else "")
