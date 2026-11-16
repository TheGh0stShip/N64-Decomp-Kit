"""Code segments outside the boot segment.

IPL3 copies one segment; many titles keep most of their code elsewhere in the ROM and load it
later (a second program segment, overlays).  The survey already knows *which ROM ranges a loader
reads raw*; this module answers the two questions that are left for each such range:

* **is it code?**  A range of compiled MIPS has a recognisable density of stack-frame prologues
  and ``jr $ra`` returns.
* **where does it run?**  The range's own ``jal`` instructions carry absolute targets.  For the
  right load address every internal call lands on a function start, so each (call target,
  prologue offset) pair votes for ``target - offset`` and the address with the most votes wins.
  Calls into already-known segments are set aside first.

Nothing is assumed about the title: no address, name or layout convention.  A range that does not
look like code, or whose calls do not agree on one address, is left alone and reported as such.
"""
from __future__ import annotations

import struct
from collections import Counter
from dataclasses import dataclass, field

MIN_BYTES = 0x800            # smaller ranges are data records, not program segments
MIN_PROLOGUES = 6
MIN_VOTES = 6
MIN_AGREEMENT = 0.25         # share of internal call targets that land on a prologue


@dataclass
class Candidate:
    rom_start: int
    rom_end: int
    vram: int | None = None              # solved load address, or None
    text_bytes: int = 0                  # leading part that decodes as code
    prologues: int = 0
    returns: int = 0
    calls: int = 0                       # distinct jal targets outside the known segments
    votes: int = 0
    agreement: float = 0.0
    runner_up: int = 0                   # votes of the second-best address
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    codec: str = ""                      # set when the range is a compressed stream
    by_density: bool = False             # found by the whole-ROM scan, not through a loader range
    data: bytes | None = field(default=None, repr=False)   # the decoded bytes of such a stream

    @property
    def size(self) -> int:
        return len(self.data) if self.data is not None else self.rom_end - self.rom_start

    def as_dict(self) -> dict:
        return {"rom": f"0x{self.rom_start:X}", "rom_end": f"0x{self.rom_end:X}", "size": self.size,
                "vram": None if self.vram is None else f"0x{self.vram:08X}", "text_bytes": self.text_bytes,
                "prologues": self.prologues, "returns": self.returns, "calls": self.calls, "votes": self.votes,
                "agreement": round(self.agreement, 3), "runner_up": self.runner_up, "reason": self.reason,
                "evidence": self.evidence, **({"codec": self.codec} if self.codec else {})}


def _words(data: bytes) -> list[int]:
    count = len(data) // 4
    return list(struct.unpack(f">{count}I", data[:4 * count]))


def _is_prologue(word: int) -> bool:
    """``addiu $sp, $sp, -N`` with N a positive multiple of 8."""
    if word >> 16 != 0x27BD:
        return False
    imm = word & 0xFFFF
    return imm >= 0x8000 and (0x10000 - imm) % 8 == 0 and (0x10000 - imm) <= 0x4000


def profile(data: bytes) -> dict:
    """Code signals of a byte range: prologue offsets, returns and absolute call targets, and
    how far the leading part keeps looking like code."""
    words = _words(data)
    prologues = [4 * i for i, w in enumerate(words) if _is_prologue(w)]
    returns = [4 * i for i, w in enumerate(words) if w == 0x03E00008]
    calls = Counter()
    for word in words:
        if word >> 26 == 3:                                   # jal: target within the 0x8xxxxxxx region
            calls[0x80000000 | ((word & 0x03FFFFFF) << 2)] += 1
    # the text ends where returns stop coming: the last window of 0x400 bytes holding one
    text_end = 0
    if returns:
        last = returns[0]
        for offset in returns:
            if offset - last > 0x2000:                        # a gap this long is data
                break
            last = offset
        text_end = min(len(data), last + 8)
    return {"prologues": prologues, "returns": returns, "calls": calls, "text_end": text_end}


def solve(data: bytes, known: list[tuple[int, int]] = ()) -> Candidate:
    """Load address of one raw range, or the reason none was found.  ``known`` are the address
    ranges of segments already placed (calls into them say nothing about this range)."""
    out = Candidate(0, len(data))
    if len(data) < MIN_BYTES:
        out.reason = "too small to be a program segment"
        return out
    found = profile(data)
    text = found["text_end"]
    prologues = [p for p in found["prologues"] if p < text]
    out.text_bytes, out.prologues = text, len(prologues)
    out.returns = sum(1 for r in found["returns"] if r < text)
    if out.prologues < MIN_PROLOGUES or out.returns < MIN_PROLOGUES:
        out.reason = "not code: too few stack-frame prologues and returns"
        return out
    density = out.returns / max(1, text // 4)
    if density < 1 / 400:                                     # compiled code returns at least this often
        out.reason = "not code: returns are too sparse"
        return out
    internal = {target: count for target, count in found["calls"].items()
                if not any(lo <= target < hi for lo, hi in known)}
    out.calls = len(internal)
    if len(internal) < MIN_VOTES:
        out.reason = "code, but it makes too few calls outside the known segments to place it"
        return out
    votes: Counter = Counter()
    for target in internal:
        for offset in prologues:
            base = target - offset
            if base & 3 == 0 and 0x80000000 <= base < 0x80800000:
                votes[base] += 1
    if not votes:
        out.reason = "code, but no load address is consistent with its calls"
        return out
    ranked = votes.most_common(2)
    base, best = ranked[0]
    out.votes, out.runner_up = best, ranked[1][1] if len(ranked) > 1 else 0
    landing = sum(1 for target in internal if 0 <= target - base < text)
    out.agreement = best / max(1, landing)
    if best < MIN_VOTES or best < 2 * out.runner_up or out.agreement < MIN_AGREEMENT:
        out.reason = (f"code, but its calls do not agree on one load address (best 0x{base:08X}: {best} votes, "
                      f"next {out.runner_up})")
        return out
    if any(lo < base + len(data) and base < hi for lo, hi in known):
        out.evidence.append("overlaps a known segment's address range: an overlay sharing addresses")
    out.vram = base
    out.evidence.append(f"{best} of {landing} internal call targets land on a stack-frame prologue at 0x{base:08X} "
                        f"(next best address: {out.runner_up})")
    return out


def raw_ranges(ledger) -> list[tuple[int, int]]:
    """ROM ranges a loader reads raw (survey ledger items), adjacent pieces joined."""
    spans = sorted((item.start, item.end) for item in ledger
                   if getattr(item, "category", "") == "loader_range" and getattr(item, "kind", "") == "raw")
    joined: list[list[int]] = []
    for start, end in spans:
        if joined and start <= joined[-1][1] + 16:
            joined[-1][1] = max(joined[-1][1], end)
        else:
            joined.append([start, end])
    return [(a, b) for a, b in joined if b - a >= MIN_BYTES]


def discover(rom_data: bytes, ledger, known: list[tuple[int, int]]) -> list[Candidate]:
    """One :class:`Candidate` per raw loader range, placed where its calls agree.  ``known`` grows
    as segments are placed, so a later range's calls into an earlier one are set aside too."""
    out = []
    placed = list(known)
    for start, end in raw_ranges(ledger):
        candidate = solve(rom_data[start:end], placed)
        candidate.rom_start, candidate.rom_end = start, end
        if candidate.vram is not None:
            placed.append((candidate.vram, candidate.vram + candidate.size))
        out.append(candidate)
    return out


def discover_compressed(rom_data: bytes, known: list[tuple[int, int]], skip: list[tuple[int, int]] = (),
                        min_output: int = MIN_BYTES) -> list[Candidate]:
    """Code kept in compressed streams.  Every stream the codec scan can decode (magic-headed
    formats, zlib, gzip, header-less deflate at word alignment) is profiled like a raw range, and
    one that is code whose calls agree on a load address becomes a candidate carrying its decoded
    bytes.  ``skip`` are ROM ranges that are already placed code.  Streams that are not code are
    dropped silently: most compressed streams in a ROM are assets."""
    from ..assets import compress
    out = []
    placed = list(known)
    try:
        streams = compress.scan(rom_data, lzari_brute=False, deflate_align=4, min_output=min_output, skip=list(skip))
    except Exception:                                        # a scan failure costs reach, never the project
        return out
    for stream in sorted(streams, key=lambda s: s.rom):
        try:
            data = stream.data if stream.data is not None else compress.decode(stream.codec, rom_data, stream.rom).data
        except Exception:
            continue
        candidate = solve(data, placed)
        if not candidate.text_bytes or candidate.prologues < MIN_PROLOGUES:
            continue
        candidate.rom_start, candidate.rom_end = stream.rom, stream.end
        candidate.codec, candidate.data = stream.codec, data
        if candidate.vram is not None:
            placed.append((candidate.vram, candidate.vram + len(data)))
            candidate.evidence.append(f"decoded from a {stream.codec} stream ({stream.consumed} bytes in the ROM)")
        out.append(candidate)
    return out


def _decodes(window) -> bool:
    """Most words of the window are plausible MIPS instructions with common opcodes (data such as
    display lists, textures and tables is not)."""
    common = 0
    for w in window:
        op = w >> 26
        if w == 0 or op in (0x23, 0x2B, 0x09, 0x0F, 0x03, 0x04, 0x05, 0x0D, 0x21, 0x25, 0x24, 0x20, 0x28, 0x29,
                            0x31, 0x39, 0x35, 0x3D, 0x0A, 0x0B, 0x0C, 0x02, 0x06, 0x07, 0x01, 0x11, 0x14, 0x15):
            common += 1
        elif op == 0 and (w & 0x3F) in (0x21, 0x25, 0x08, 0x00, 0x02, 0x03, 0x23, 0x2A, 0x2B, 0x24, 0x18, 0x19, 0x1A,
                                        0x1B, 0x10, 0x12, 0x09, 0x04, 0x06, 0x07, 0x26, 0x27, 0x20, 0x22):
            common += 1
    return common * 10 >= len(window) * 9


WINDOW = 0x400               # density window of the whole-ROM code scan
TOP_DELTAS = 12


def code_regions(rom_data: bytes, skip: list[tuple[int, int]] = ()) -> list[tuple[int, int]]:
    """ROM ranges outside ``skip`` that have the density of compiled code: every window holds at
    least two returns and a stack-frame prologue.  Each range is trimmed to start at its first
    prologue and to end after its last return."""
    words = _words(rom_data)
    hot, warm = [], set()
    for start in range(0x1000, len(rom_data) - WINDOW, WINDOW):
        if any(start < hi and lo < start + WINDOW for lo, hi in skip):
            continue
        window = words[start // 4:(start + WINDOW) // 4]
        returns = sum(1 for w in window if w == 0x03E00008)
        prologue = any(_is_prologue(w) for w in window)
        if returns >= 2 and prologue:
            hot.append(start)
        elif _decodes(window):
            warm.add(start)                                  # long functions: code, but below the seed density
    joined: list[list[int]] = []
    for start in hot:
        if joined and start <= joined[-1][1]:
            joined[-1][1] = start + WINDOW
            continue
        if joined:                                           # bridge windows of long functions between two seeds
            gap = range(joined[-1][1], start, WINDOW)
            if len(gap) <= 64 and all(g in warm for g in gap):
                joined[-1][1] = start + WINDOW
                continue
        joined.append([start, start + WINDOW])
    out = []
    for start, end in joined:
        if end - start < 4 * WINDOW:
            continue
        chunk = words[start // 4:end // 4]
        first = next((i for i, w in enumerate(chunk) if _is_prologue(w)), None)
        last = max((i for i, w in enumerate(chunk) if w == 0x03E00008), default=None)
        if first is None or last is None or last <= first:
            continue
        out.append((start + 4 * first, min(end, start + 4 * last + 8)))
    return out


def _landings(prologues: list[int], top: list[int], target_set: set[int]) -> list[tuple[int, tuple[int, ...]]]:
    """[(prologue ROM offset, distances that turn it into a call target)] for the prologues at
    least one candidate distance accounts for.  The evidence is on the callee's side on purpose: a
    call says where the *called* function lives, whichever program the caller belongs to."""
    out = []
    for offset in prologues:
        landing = tuple(delta for delta in top if (offset + delta) & 0xFFFFFFFF in target_set)
        if landing:
            out.append((offset, landing))
    return out


def _labels(prologues: list[int], top: list[int], target_set: set[int]) -> list[tuple[int, int]]:
    """The prologues exactly one candidate distance accounts for, with that distance."""
    return [(offset, landing[0]) for offset, landing in _landings(prologues, top, target_set) if len(landing) == 1]


def _switches(start: int, prologues: list[int], landings: list[tuple[int, tuple[int, ...]]]) -> list[tuple[int, int]]:
    """[(piece start, distance)] for a region whose called functions support different distances
    in different parts (two programs back to back, such as overlays loaded at one address); one
    entry or none when it is one program.  A new distance is adopted when four prologues in a row
    that only it accounts for carry it; the cut is the first prologue after the last one the
    earlier distance accounts for (alone or not)."""
    labels = [(offset, landing[0]) for offset, landing in landings if len(landing) == 1]
    marks, current = [], None
    for index, (_offset, delta) in enumerate(labels):
        window = labels[index:index + 4]
        if delta != current and len(window) == 4 and all(row[1] == delta for row in window):
            current = delta
            marks.append((index, delta))
    if not marks:
        return []
    cuts = [(start, marks[0][1])]
    for number in range(1, len(marks)):
        index, delta = marks[number]
        earlier, first_new = marks[number - 1][1], labels[index][0]
        last_before = max((offset for offset, landing in landings if offset < first_new and earlier in landing),
                          default=cuts[-1][0])
        cut = next((q for q in prologues if q > last_before), None)
        if cut is not None and cut > cuts[-1][0]:
            cuts.append((min(cut, first_new), delta))
    return cuts


def _trim(words, start: int, end: int, prologues: list[int], delta: int, target_set: set[int],
          prologue_set: set[int], known) -> tuple[int, int]:
    """Cut from a placed region the leading and trailing code that belongs to another program.

    Small programs packed next to a large one (a row of overlays) join it in one density region.
    Between the first and the last prologue the distance accounts for, the region is that program.
    Outside them a call whose target falls inside the region at this distance should land on a
    prologue about as often as elsewhere in the program; where at least four such calls almost
    never do, the code up to the last of them (or from the first of them) is someone else's."""
    labelled = [q for q in prologues if (q + delta) & 0xFFFFFFFF in target_set]
    if not labelled:
        return start, end
    first, last = labelled[0], labelled[-1]

    def verdicts(lo: int, hi: int) -> list[tuple[int, bool]]:
        out = []
        for index in range(lo // 4, hi // 4):
            word = words[index]
            if word >> 26 != 3:
                continue
            target = 0x80000000 | ((word & 0x03FFFFFF) << 2)
            if any(a <= target < b for a, b in known):
                continue
            offset = (target - delta) & 0xFFFFFFFF
            if start <= offset < end:
                out.append((4 * index, offset in prologue_set))
        return out
    head = verdicts(start, first)
    if len(head) >= 4 and 5 * sum(1 for _o, ok in head if ok) < len(head):
        miss = max(o for o, ok in head if not ok)
        start = next((q for q in prologues if q > miss), first)
    tail = verdicts(min(end, last + 4), end)
    if len(tail) >= 4 and 5 * sum(1 for _o, ok in tail if ok) < len(tail):
        miss = min(o for o, ok in tail if not ok)
        cut = max((q for q in prologues if q <= miss and q > last), default=None)
        if cut is not None:
            end = cut
    return start, end


def discover_regions(rom_data: bytes, known: list[tuple[int, int]], skip: list[tuple[int, int]] = ()) -> list[Candidate]:
    """Code that no loader range or stream points at, found by density and placed by one vote over
    the whole ROM.

    A linked program keeps one distance between a function's ROM offset and its address, however
    many code and data sections it is cut into.  Every (call target, prologue ROM offset) pair of
    the unplaced code votes for that distance; a distance many pairs agree on is a program, and a
    region belongs to it when its own calls, or the calls into it, land on prologues at that
    distance.  Overlays that share addresses simply have different distances."""
    regions = code_regions(rom_data, skip)
    if not regions:
        return []
    words = _words(rom_data)
    info = []
    for start, end in regions:
        chunk = words[start // 4:end // 4]
        prologues = [start + 4 * i for i, w in enumerate(chunk) if _is_prologue(w)]
        targets = {0x80000000 | ((w & 0x03FFFFFF) << 2) for w in chunk if w >> 26 == 3}
        targets = {t for t in targets if not any(lo <= t < hi for lo, hi in known)}
        info.append((start, end, prologues, targets))
    all_prologues = sorted({p for row in info for p in row[2]})
    prologue_set = set(all_prologues)
    all_targets = sorted({t for row in info for t in row[3]})
    if len(all_prologues) * len(all_targets) > 40_000_000:           # bound the vote on very large ROMs
        step = len(all_prologues) * len(all_targets) // 40_000_000 + 1
        all_targets = all_targets[::step]
    votes: Counter = Counter()
    for target in all_targets:
        for offset in all_prologues:
            delta = target - offset
            if delta & 3 == 0 and delta >= 0x7F000000:
                votes[delta] += 1
    top = []
    for delta, count in votes.most_common(4 * TOP_DELTAS):
        # a distance a few instructions away from a stronger one is the same program seen through
        # functions whose frame is set up after their first instruction
        if count >= MIN_VOTES and not any(abs(delta - kept) <= 0x40 for kept in top):
            top.append(delta)
    top = top[:TOP_DELTAS]
    target_set = set(all_targets)
    # Two programs can sit back to back in the ROM (overlays loaded at the same address): a region
    # whose called functions switch from one distance to another is cut where they switch.
    forced: dict[int, int] = {}
    pieces = []
    for start, end, prologues, targets in info:
        cuts = _switches(start, prologues, _landings(prologues, top, target_set))
        if len(cuts) < 2:
            pieces.append((start, end, prologues, targets))
            continue
        for number, (piece_start, delta) in enumerate(cuts):
            piece_end = cuts[number + 1][0] if number + 1 < len(cuts) else end
            chunk = words[piece_start // 4:piece_end // 4]
            last = max((i for i, w in enumerate(chunk) if w == 0x03E00008), default=None)
            if last is None:
                continue
            piece_end = min(piece_end, piece_start + 4 * last + 8)
            piece_targets = {0x80000000 | ((w & 0x03FFFFFF) << 2) for w in chunk if w >> 26 == 3}
            piece_targets = {t for t in piece_targets if not any(lo <= t < hi for lo, hi in known)}
            forced[len(pieces)] = delta
            pieces.append((piece_start, piece_end, [q for q in prologues if piece_start <= q < piece_end],
                           piece_targets))
    info = pieces
    out = []
    assigned: dict[int, int] = dict(forced)                          # region index -> delta
    for index, (start, end, prologues, targets) in enumerate(info):
        if index in assigned:
            continue
        counts = Counter(delta for _offset, delta in _labels(prologues, top, target_set))
        ranked = counts.most_common(2)
        if ranked and ranked[0][1] >= 3 and (len(ranked) == 1 or ranked[0][1] >= 2 * ranked[1][1]):
            assigned[index] = ranked[0][0]
    # regions that make few calls of their own: placed by the calls that arrive from placed regions
    for index, (start, end, prologues, targets) in enumerate(info):
        if index in assigned:
            continue
        own = set(prologues)
        incoming = Counter()
        for other, delta in assigned.items():
            incoming[delta] += sum(1 for t in info[other][3] if t - delta in own)
        ranked = incoming.most_common(2)
        if ranked and ranked[0][1] >= 3 and (len(ranked) == 1 or ranked[0][1] >= 2 * ranked[1][1]):
            assigned[index] = ranked[0][0]
    trimmed = []
    for index, (start, end, prologues, targets) in enumerate(list(info)):
        delta = assigned.get(index)
        if delta is None:
            continue
        new_start, new_end = _trim(words, start, end, prologues, delta, target_set, prologue_set, known)
        if (new_start, new_end) == (start, end) or new_end - new_start < MIN_BYTES:
            continue
        for lo, hi in ((start, new_start), (new_end, end)):           # what was cut off stays visible, unplaced
            if hi - lo >= MIN_BYTES:
                trimmed.append((lo, hi, [q for q in prologues if lo <= q < hi], set()))
        chunk = words[new_start // 4:new_end // 4]
        last = max((i for i, w in enumerate(chunk) if w == 0x03E00008), default=len(chunk) - 2)
        info[index] = (new_start, min(new_end, new_start + 4 * last + 8),
                       [q for q in prologues if new_start <= q < new_end],
                       {t for t in targets})
    info = info + trimmed
    for index, (start, end, prologues, targets) in enumerate(info):
        candidate = Candidate(start, end, text_bytes=end - start, prologues=len(prologues), calls=len(targets),
                              by_density=True,
                              returns=sum(1 for w in words[start // 4:end // 4] if w == 0x03E00008))
        delta = assigned.get(index)
        if delta is None:
            candidate.reason = "code by density, but no load address is supported by its calls"
            if (start, end) in {(lo, hi) for lo, hi, _p, _t in trimmed}:
                candidate.reason = "code next to a placed program whose calls contradict that program's address"
        else:
            landing = sum(1 for q in prologues if (q + delta) & 0xFFFFFFFF in target_set)
            candidate.vram, candidate.votes = (start + delta) & 0xFFFFFFFF, landing
            candidate.agreement = landing / max(1, len(prologues))
            candidate.evidence.append(
                f"address = ROM offset + 0x{delta:08X}: {votes[delta]} call-target/prologue pairs across the ROM agree, "
                f"{landing} of this range's {len(prologues)} prologues are call targets at that distance")
            if any(lo < candidate.vram + (end - start) and candidate.vram < hi for lo, hi in known):
                candidate.evidence.append("overlaps a known segment's address range: an overlay sharing addresses")
        out.append(candidate)
    return out
