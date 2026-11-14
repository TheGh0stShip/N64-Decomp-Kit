# Program image and survey

## Program image (`n64dk.image`)

`image.build(rom, mode="auto")` returns a `ProgramImage`: the program's main segment and its
BSS, each with where its bytes come from.

* **static** (default when the entry routine only clears BSS and hands over): the IPL3 copy
  (ROM 0x1000 -> header entry, up to the BSS start) and the BSS from `boot.analyse`.
* **emulated** (when the hand-over leaves the boot image or the entry routine calls anything
  first): `n64dk.emu` runs the loader with read tracking and snapshots RAM at the first
  handoff. The written range holding the hand-over becomes the main segment:
  * `rom` when a PI DMA put it there verbatim;
  * `packed` when the loader wrote it. Its source is the largest RAM range the loader read
    (excluding the code it ran and its own output), mapped back to ROM through the DMAs
    (the whole DMA'd buffer) or the boot copy (256-byte granularity). A codec from
    `n64dk.assets.compress` that reproduces the start of the segment is named. Otherwise
    the game's own routine is identified (below): the source argument it was called with
    gives the exact start of the packed data.
  * The segment end and BSS come from the loader's own BSS loop, else from the same static
    walk run over the unpacked code at the hand-over (`boot.analyse_segment`: the second
    stage's entry routine), else the codec output size, else trailing zeros trimmed.

`ProgramImage.boot_info()` and `main_data(rom)` give the main segment to the analyses
(`functions.discover`, `datamap.analyse`, `sdk.analyse`, all via `program=`) and to loader
tracing (`assets-scan`'s `scan_rom(program=...)`: the code that references assets is the
unpacked program, not the loader). For a packed segment, offsets they report are offsets
into the unpacked segment.

### The game's own codec (`n64dk.gamecodec`)

When no native codec reproduces a packed program, the emulator records the arguments each
routine called by the entry code received on entry (after the delay slot, which often sets
one). The routine whose arguments point at the packed source and at the program is the
game's decompressor: `gamecodec.find` names it, with the argument roles (input, output, and
a size argument when one equals the packed size, e.g. WWF's size minus one), and
`gamecodec.decode` calls it through the emulator (`Machine.call`) on any ROM bytes.
Measured: called directly on the packed sources, the routines reproduce both programs (WWF
War Zone byte for byte; Madden 64 except the 0x40-byte table its loader copies over the start
afterwards).

The survey also tries it on loader-referenced ranges that do not shrink under zlib, within a
time budget, and accepts a range only when the routine consumes the referenced size (two
independent sources agreeing) and the item is at least 4 KiB. Decodes from arbitrary offsets
are not trusted: LZ-style routines also expand random input.

## Survey (`n64dk survey ROM --out DIR`)

Runs the program image, function discovery, the data map and SDK identification on the main
segment, and audio, graphics, compressed-stream and loader-range scans over the whole ROM.
Writes:

* `report.md`: a summary first (program, how much of the ROM is understood, the top next
  steps), then every analysis, cross-checks, ranked **next steps** and timings;
* `report.json`: the same data, including `errors` (a failing analysis is recorded with its
  traceback and the others still run), `unknown_without_graphics` (the same run's ledger
  without the graphics level), `referenced_only_bytes`, `rsp_in_text` and `game_codec`;
* `ledger.tsv`: one interval ledger over the whole ROM. Intervals are placed in priority
  order (ROM header and IPL3; the program: loader code, RSP code blocks inside `.text`,
  data-map sections or the packed program; audio; compressed streams, including ranges the
  game's codec decodes; graphics; loader-referenced ranges). A lower-priority interval that
  overlaps a placed one is dropped and counted, except data-map sections (clipped around RSP
  blocks) and loader ranges (clipped to the bytes nothing else claims). Loader ranges are
  class `referenced`: something points at them, but their content is not understood.
  Unclaimed bytes become `padding` (zero/0xFF fill) or `unknown`;
* `functions.toml`, `symbol_addrs.txt`: the function catalogue;
* `main_segment.bin`: the main segment as loaded in RAM (for a packed program, the unpacked
  bytes a decompilation splits).

Next steps are ordered by bytes affected (failures first). Each unknown range carries a hint
from its entropy and from how much zlib can still shrink samples of it: already-compressed
data (ratio about 1.0) points to an unknown codec, raw media (0.8-0.95) to audio, textures or
animation, structured data (below 0.6) to tables and level data. Calibrated on the BattleTanx
ledger: LZARI streams 1.00, sample tables 0.80-0.88, code and data 0.46, demo recordings 0.25.

`--require-complete` is the zero-unknown gate: the command exits with status 1 while any ROM
byte is `unknown`. `--image static|emulated` forces the program-image method.

### Graphics level

`survey.scan_graphics` scans the whole ROM for display lists (`gbi.find_display_lists`) in
F3DEX, F3DEX2 and F3D, and finds pools of self-relative blobs with `gbi.find_blob_pools`
(no bounds given: a list that walks with segment-0 addresses relative to its own start opens
a pool, which is partitioned forward and extended backwards; candidates whose data overlaps
their own commands are misaligned and rejected). The family is the one whose pools cover the
most bytes, then the one the ROM's microcode names (F3DEX 2.xx = F3DEX2). Each blob is one
`dl_blob` interval (list, vertices, textures, palettes); other lists cover only their
commands (`display_list`), since their data is addressed through runtime segments.

Against the BattleTanx project's ROM ledger (read-only ground truth): 2,143,704 bytes placed
as graphics, byte precision 0.992 and recall 0.9998 against its model and texture payloads;
all 4,756 models (`models.tsv`) and all 561 texture blobs (`textures.tsv`) are exact blob
intervals. The 17,936 disagreeing bytes are ones the project classifies as unused (dead
display-list commands, palette trailers, unreferenced geometry, a pool in the boot-copy
residue).

## Measured results

One `n64dk survey` per fixture ROM (defaults: `--image auto`, LZARI brute force on).

| ROM | Image | Main segment (source) | BSS | Functions / jump tables | SDK named; game compiler | Audio | Graphics | Streams | Unknown | Referenced only | Time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| BattleTanx (NBXE) | static | 0x80071000..0x80147040 (ROM 0x1000..0xD7040) | 0x80147040..0x803C8880 | 1763 / 79 | 258; KMC | 2 banks, 78 samples, 19 MIDI | F3DEX: 5347 blobs in 4 pools | 70 LZARI | 11.4 % (37.0 % without graphics) | 3.8 % | 44 s |
| Global Assault (NBQE) | static | 0x80071000..0x80127E30 (ROM 0x1000..0xB7E30) | 0x80127E30..0x803B17B0 | 1889 / 191 | 282; KMC | 25 banks, 307 samples | F3DEX2: 6526 blobs in 9 pools | 270 LZARI | 3.7 % (41.9 %) | 4.7 % | 50 s |
| Mario Kart 64 (NKTE) | static | 0x80000400..0x800F6910 (ROM 0x1000..0xF7510) | 0x800F6910..0x801978D0 | 2659 / 209 | 151; IDO | 3 banks, 202 samples | F3DEX: 55 blobs, 7 lists (graphics are in MIO0) | 3354 MIO0 | 17.8 % | 1.8 % | 30 s |
| Nagano Winter Olympics '98 (NH5E) | static | 0x80000400..0x80081DE0 (ROM 0x1000..0x829E0) | 0x80081DE0..0x801954A0 | 1469 / 59 | 241; IDO | 3 banks, 93 samples | F3DEX: 1 pool inside the program | none | 82.4 % | 7.4 % | 17 s |
| Madden 64 (N8ME) | emulated | 0x80000400..0x800776C0 (packed, ROM 0x1318..0x46C00, game routine 0x802004DC) | 0x800776C0..0x8008B8E0 (second stage) | 1383 / 31 | 147; KMC | none found | 5 lists, no pools | none | 79.1 % | 18.6 % | 29 s |
| WWF War Zone (NWWE) | emulated | 0x8003C400..0x8012A1C0 (packed, ROM 0xB8E9E0..0xBF5040, game routine 0x80000540) | 0x8012A1C0..0x801A43E0 (loader) | 2873 / 97 | 269; KMC | none found | F3DEX2: 1 small pool | none | 96.2 % | 0.0 % | 70 s |

Unknown percentages in brackets are the same run without the graphics level; the graphics
level resolves 2.14 MB on BattleTanx and 3.21 MB on Global Assault. "Referenced only" is
what loader tables point at without the content being understood. Before the loader
plausibility checks (`docs/compression.md`) it was 24.0 % on Nagano, 81.5 % on Madden 64 and
33.2 % on WWF War Zone, mostly contradictory or size-table ranges; those bytes are now
reported as unknown, which is what they are.

All six report SDK 2.0D-2.0H (`libultra_rom`). Without the program image, Madden 64 and WWF
War Zone get only their loaders (Madden: 5 functions); with it, function discovery and SDK
identification behave as on the standard boots. Neither packed codec is one of
`n64dk.assets.compress`'s; both programs are unpacked by the games' own routines, which the
survey names and can run. Tried on the loader-referenced ranges that look packed (one each),
neither routine decodes any other data with a matching size, so no assets are claimed for it.

### RSP code inside `.text`

libultra links RSP microcode text (rspboot and others) into the CPU `.text` section. The
survey finds it (`sdk.fingerprint.rsp_text_ranges`: RSP-only opcodes with a high share of
vector operations, 64-byte granularity), places it as `rsp_text`, and uses it to explain a
difference between the CPU code's end (`functions`) and the `.text` section's end
(`datamap`): on Mario Kart 64 and Nagano the difference is RSP code. On Madden 64, CPU code
continues after the RSP block; `functions` recovers it (calls from accepted functions past
the text end, from at least two sites, extend the text and the phases run again): 1181 ->
1383 functions, text end 0x80050EFC -> 0x800649FC, the same end as `datamap`.

## Limitations

* Graphics are placed only where they are raw self-relative blobs or raw display lists.
  Graphics inside compressed streams (Mario Kart 64) or game-specific containers (Nagano,
  Madden, WWF) stay inside those intervals or unknown; standalone lists' vertices and
  textures are not placed (runtime segment addresses). What remains unknown on the
  BattleTanx games is mostly game-specific data (demo recordings) and boot-copy residue.
* A packed source's start is exact when the game's routine is identified; its end stays at
  256-byte granularity unless a DMA bounds it (WWF) or a native codec reports what it read.
* Loader-referenced ranges come from heuristics over the program's code and tables
  (`assets.loaders`), filtered for contradictions; on games without a ground truth the rest
  is still unverified, which is why they are reported as `referenced`, not as understood
  content.
* Overlays loaded after start-up (Mario Kart 64's segments) are not part of the image.
