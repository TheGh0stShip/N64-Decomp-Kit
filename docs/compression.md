# Compressed streams and loader evidence

Modules: `n64dk.assets.compress` (codecs, stream scanner), `n64dk.assets.loaders`
(ROM ranges named by code and data), command `n64dk assets-scan`.

## Codecs

| name | header | decode | encode | byte-identical re-encode |
|---|---|---|---|---|
| `mio0` | `MIO0`, size, link offset, literal offset | yes | greedy parser, 1-byte lazy look-ahead, farthest offset on ties, 4096 window, 3..18 byte matches | MK64: 3354 / 3354 streams |
| `yay0` | `Yay0`, size, link offset, chunk offset | yes | same parser, 3..273 byte matches, 32-bit mask words | not measured (no fixture uses it) |
| `yaz0` | `Yaz0`, size, 8 reserved bytes | yes | same parser, 3..273 byte matches | not measured (no fixture uses it) |
| `lzari` | big-endian `u32` expanded size, then Okumura LZARI bits (N=4096, F=60, THRESHOLD=2) | yes | original binary-tree parser | BattleTanx: 70 / 70; Global Assault: every found stream's consumed length equals the re-encoded length (270 / 270) |
| `zlib`, `gzip`, `deflate` | standard library | yes | `zlib` level 9 (`deflate_reencode_identical` searches level/memLevel) | - |

Every decoder returns `Decoded(data, consumed)` where `consumed` is the exact number
of input bytes of the stream (header included), so streams can be placed in an interval
ledger.  For LZARI the decoder reads up to 17 bits ahead of the arithmetic coder; the
exact length is `4 + ceil((bits_read - 15) / 8)` (coder shifts plus the encoder's two
terminating bits).  This matches all 40 BattleTanx level/navigation stream ends recorded by
the game's own table and the re-encoded length of all 70 BattleTanx and 270 Global
Assault streams.  Retail streams rely on reads past the end returning `0xFF` (C `getc`
EOF); the decoder emulates that for at most 32 bits.

LZARI support is adapted from the BattleTanx decompilation's `tools/lzari.py` (GPL-3.0),
itself derived from the BattleTanx: Global Assault decompilation.

New codecs: `compress.register(Codec(name, decode, encode, magic))`.  Codecs with a
`magic` are picked up by the scanner automatically.

## Scanner (`compress.scan`)

1. **Magic formats** (Yay0, Yaz0, MIO0, gzip, zlib `78 xx` with a valid FCHECK): every
   occurrence is fully decoded within the ROM; failures are dropped.
2. **LZARI** has no magic.  A candidate is checked by `lzari_probe`: decode a short output
   prefix (256 then 1024 bytes) and re-encode it with the exact encoder, comparing every
   byte the encoder emits before its look-ahead runs short against the stream.  Arithmetic
   coder bytes are final once emitted and the parser looks only `F` bytes ahead, so a real
   stream agrees while arbitrary bytes diverge within a few bytes.  When the whole stream
   fits in the prefix the full re-encode must equal the stream.  Candidates come from:
   * seeds: starts of loader-evidenced ROM ranges;
   * chains: after each accepted stream, the next 4-aligned non-zero word within 16 bytes;
   * brute force: every 4-aligned word that follows a zero word, holds a size in
     `8..4 MiB`, and passes a quick filter (the first 48 output bytes contain no match
     reaching into the decoder's initial space-filled window).
   Accepted streams must fully decode with at most 8 bits of `0xFF` tail.  A group of
   adjacent streams made only of tiny (< 64 decoded bytes) brute-force finds is
   discarded, because short literal-only streams re-encode exactly from almost any bytes.
3. **Raw deflate** (opt-in, `--deflate-align N`): `zlib.decompressobj(-15)` at every
   N-byte boundary not already covered; accepted only if the stream terminates, consumes
   at least 256 bytes and expands by at least 1.5x.

Overlaps resolve in favour of the earlier, longer stream.

## Loader tracing (`loaders.trace`)

Code of the main segment (ROM 0x1000, mapped at the header entry point) is walked with a
linear constant propagator (`lui`, `addiu`, `ori`, `addu`, `or`, `subu`, outgoing stack
arguments).  State resets at `addiu $sp, $sp, -N` prologues and after `jr $ra`.

| source | evidence |
|---|---|
| `call` | a `jal` whose arguments hold two ROM addresses `start < end` (PI form `0xB0000000+off`), or a start plus `end - start` computed by `subu` |
| `wrapper` | a call to a detected DMA wrapper with a start and a constant size in the wrapper's learned argument slots |
| `size` | a `subu` of two ROM constants (`size = end - start`) |
| `store` | constant ROM addresses stored to adjacent words (tables filled by code) |
| `pairs` | parallel start/end arrays in data (any order; ranges disjoint) |
| `records` | adjacent `start, end` words in data; raw offsets need a repeated stride of three or more disjoint records |
| `table` | ascending runs of ROM addresses (each entry ends where the next begins) |

DMA wrappers are callees that receive a PI-form or computed-size range at two or more
sites.  The loader of a table entry is the function referencing the nearest address at
or below it (within 0x800 bytes).  Outside the main segment the whole ROM is searched for
stride-repeated records whose starts agree with two or more found streams (sites are then
ROM offsets, `site_space: rom`).

When the program is unpacked by a boot loader, `scan_rom(program=...)` traces the unpacked
program (`n64dk.image`) instead of the loader, since that is where asset references are.

### Plausibility (`loaders.plausible`)

The sources above are heuristics; on games without a reference their raw-number forms
read sizes, counts and coordinates as offsets. The final evidence is filtered for
contradictions:

* two loaded items cannot partially overlap (nesting is allowed): of two partially
  overlapping ranges, the one with stronger evidence (code sources over data tables, then
  the smaller) is kept;
* a range over 1 MiB resting on table evidence or raw numbers is dropped;
* a raw range whose start and end are both powers of two is a size table read as offsets;

unless a validated compressed stream starts at the range. The rejections are reported
(`loader.rejected`, reason -> count).

| ROM | ranges before -> after | bytes before -> after | notes |
|---|---|---|---|
| BattleTanx | 129 -> 129 | 2.46 MB, unchanged | all PI form; 128 / 129 match the project's ROM ledger at both ends, the last at its start |
| Global Assault | 270 -> 249 | 3.83 -> 1.73 MB | 20 partial overlaps, one raw 1.4 MiB range; 211 of the kept 249 start on a validated LZARI stream |
| Mario Kart 64 | 65 -> 65 | 3.01 MB, unchanged | the course table; the one range over 1 MiB starts on an MIO0 stream |
| Nagano (no reference) | 174 -> 119 | 7.08 -> 1.96 MB | 53 partial overlaps, 2 ranges over 1 MiB |
| Madden 64 (no reference) | 29 -> 22 | 17.28 -> 3.94 MB | 4 ranges over 1 MiB (one PI-form "record" of 6.9 MB), 3 overlaps |
| WWF War Zone (no reference) | 16 -> 6 | 4.19 MB -> 2.3 KB | 9 power-of-two ranges (a size table) |

## Command

    n64dk assets-scan ROM [--out DIR] [--extract] [--verify] [--deflate-align N] [--no-lzari-brute]
    n64dk --format json assets-scan ROM

Writes `DIR/ledger.tsv` (an `n64dk.ledger` interval list over the whole ROM: header,
IPL3, `payload/compressed` streams, `payload/loader_range` ranges not covered by a
stream, padding and unknown gaps), `DIR/assets_scan.json` (streams with their matching
loader evidence, all loader ranges, detected wrappers) and with `--extract`
`DIR/streams/<rom>.<codec>.bin`.  `--verify` re-encodes every stream and reports
`identical`, `roundtrip` or `differs`.

## Measured results

Run times are for the default command (no `--verify`) on one core.

| ROM | time | streams | ground truth | precision / recall |
|---|---|---|---|---|
| BattleTanx (NBXE) | 65 s | 70 LZARI | 70 LZARI streams in the project's asset layouts (20 resource bundles, 10 strip bundles, 40 level world/navigation streams) | 70 / 70 found, 0 false positives; all consumed lengths exact (28 loader ranges add 1-15 bytes of zero alignment padding) |
| Global Assault (NBQE) | 64 s | 270 LZARI | 271 streams accepted by the project's inventory (195 images, 75 worlds, 1 leftover) | 270 / 271 found, 0 false positives; consumed length equals the re-encoded size for all 270.  Missed: the 0x100000 leftover stream, which follows non-padding bytes and has no loader reference |
| Mario Kart 64 (NKTE) | 29 s | 3354 MIO0 | - | 3354 / 3354 decode; 3354 / 3354 re-encode byte-identically; no LZARI or deflate false positives |

Loader evidence:

* BattleTanx: DMA wrapper `0x80077930` (`rom_dma_read(pi_start, dst, size)`, 35 sites).
  68 / 70 streams carry an exact loader range (the two level bundles at 0x4B4B00 and
  0x4C1930 are addressed through computed indices).  All 40 level world/navigation ranges
  come from `store` evidence in `func_800865E0` with exact (unaligned) ends; the
  10-entry strip-bundle start/end arrays at `0x80134B88` are recovered as `pairs`; the
  sequence offset table at `0x80125714` as a `table`/`records` run.
* Global Assault: wrappers `0x80096810`, `0x800D520C`; 227 / 271 streams start at a
  loader-evidenced address (113 with the exact end), mostly from 208 `records` ranges of the image table.
* MK64: the course table (`gCourseTable`, 20 records of 0x30 bytes at ROM 0x122390,
  outside the IPL3-copied MiB) yields 60 raw start/end ranges plus one more; 41 of the 61
  start at a decoded MIO0 stream.  Code evidence is sparse (3 linker `size` pairs, one
  call) because most MK64 DMA addresses are formed from segment bases at run time.

Re-encode cost (pure Python): MIO0 about 19 KB/s of output (16.2 MB in 867 s), LZARI
about 7 KB/s (4.06 MB in 585 s), which is why `--verify` is opt-in.

Raw deflate trial at 4-byte alignment with the acceptance rule above leaves 6 (BattleTanx),
12 (Global Assault) and 6 (MK64) candidates although none of the games uses deflate, so
`--deflate-align` should only be used on ROMs expected to contain deflate.

## Limitations

* Code tracing covers the main segment only; overlays loaded elsewhere are not walked
  (their tables are still found by the whole-ROM record scan when they agree with streams).
* The constant propagator is linear: values flowing through branches, loads from memory
  or loop indices are not tracked, so indexed table loads only attribute via the nearest
  referenced table address.
* LZARI brute force only starts at words that follow a zero word; streams embedded after
  other non-stream data are found only through seeds or chains.
* Yay0/Yaz0 encoders round-trip but have not been checked against a retail encoder.
