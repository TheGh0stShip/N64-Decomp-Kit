# Graphics: display lists and textures

Modules: `n64dk.assets.gbi` (GBI tables, decoder, walker, scanner, ucode detection) and
`n64dk.assets.texture` (texel codecs, PNG writer, dimension heuristic). CLI: `n64dk gfx`.

## GBI families

| family | source macros | G_VTX | triangles | G_DL / G_ENDDL |
|---|---|---|---|---|
| `f3d` | gbi.h, Fast3D | `04 (n-1)<<4\|v0, len` | `BF`, index x10 | `06` / `B8` |
| `f3dex` | `F3DEX_GBI` (F3DEX/F3DLX/F3DLP 1.x) | `04 v0*2, n<<10\|len-1` | `BF`, `B1` TRI2, index x2 | `06` / `B8`, `B0` BRANCH_Z |
| `f3dex2` | `F3DEX_GBI_2` | `01 n<<12\|(v0+n)<<1` | `05`/`06`/`07` | `DE` / `DF`, `04` BRANCH_Z |
| `s2dex` | gs2dex.h 1.x numbering | - | - | `06` / `B8`, `B0` SELECT_DL |
| `s2dex2` | gs2dex.h 2.x numbering | - | - | `DE` / `DF`, `04` SELECT_DL |

RDP commands (`C0`, `C8..CF`, `E4..FF`) are shared. `gbi.decode(w0, w1, family)` returns a
`Command` with decoded fields, a reference `(kind, segmented address, byte length)` for
DMA-style commands (vertices, sub-lists, matrices, movemem, images, S2DEX objects) and
an `error` when operands are structurally impossible (padding bits set, vertex count and
length disagree, cache overflow, misaligned/non-segmented address, ...). These checks are
what makes scanning raw bytes reliable.

## Walker

`gbi.walk(Memory(data, segments, origin), start, family)` follows G_DL calls and
branches with a return stack, G_BRANCH_Z/G_SELECT_DL targets (from G_RDPHALF_1/0) and
G_MOVEWORD segment writes. It collects vertex loads (address, buffer offset, count),
matrices, sub-lists, palettes and texture images. Texture images are derived from
G_SETTIMG + G_LOADBLOCK/G_LOADTILE, with the render tile (same TMEM address as the load
tile, sized by G_SETTILESIZE) giving format, size and dimensions; CI images get the TLUT
loaded at `256 + palette*16` (CI4) or 256 (CI8) and the TLUT type from othermode
G_MDSFT_TEXTLUT. Errors: unknown opcode, data outside the buffer, misaligned images or
palettes, triangles using vertex slots never loaded.

`Memory` resolves segmented addresses: `physical = segments[seg] + offset` (KSEG0 through
segment 0), buffer offset = `physical - origin`. `Memory(data)` treats segment-0 addresses
as buffer offsets; `Memory.unmapped(data)` resolves nothing (raw ROM scans).

`gbi.partition_blobs` splits a pool of self-relative blobs (list at offset 0, segment-0
addresses relative to the blob, data after the list) into consecutive blobs whose end is
the end of the furthest referenced data. `gbi.find_display_lists` finds lists anywhere:
each aligned G_ENDDL word pair is a terminator candidate, the start is found by stepping
back while commands decode cleanly, and the list is re-walked forwards to validate it.
`gbi.detect_family` scores each family by the validated geometry/control commands of the
lists it finds (sprite families only score lists their 3D sibling cannot decode; ties
prefer f3dex). `gbi.find_blob_pools` finds blob pools without bounds: found lists that walk
self-relative open a pool (a misaligned scan start is corrected by trying offsets up to the
list's first segment-0 reference; candidates whose data overlaps their own commands are
rejected), which is partitioned forward and extended backwards. On BattleTanx it finds the
geometry pool 0x3EA970..0x49C740 (4775 blobs) and the texture pool 0x5A1110..0x6F9C38
(561 blobs) exactly, in under a second; `n64dk survey` uses it (see survey.md).

## Textures

`texture.decode(data, fmt, siz, w, h, palette, tlut)` handles RGBA16/32, CI4/CI8 (RGBA16 or
IA16 TLUT), IA4/8/16, I4/I8 to RGBA8888; `texture.to_png` writes deterministic PNGs with
stdlib zlib. Codecs adapted from the BattleTanx project's `tools/n64_texture.py` (GPL-3.0).
`texture.guess_dimensions(data, siz)` ranks power-of-two shapes for headerless data by
vertical coherence (adjacent rows resemble each other at the true width).

## CLI

```
n64dk gfx ROM [--range START:END] [--ucode auto|f3d|f3dex|f3dex2|s2dex|s2dex2]
              [--mode auto|blobs|scan|walk] [--walk OFF ...] [--segment N=ROMOFF ...]
              [--decompress] [--out DIR --png]
n64dk --format json gfx ...
```

`auto` mode uses `blobs` when the range starts with a valid self-relative list, else
`scan`. `--decompress` also scans every compressed stream (`n64dk.assets.compress`) found in
the range. `--out` writes `display_lists.tsv`; with `--png` every texture whose format,
size and data resolve is exported.

## Measured results

BattleTanx (NBXE), ground truth = level tile index (section 6 of every world stream) as
inventoried in the BattleTanx project:

| pool | ROM | blobs walked | index | exact (start,end) | per-blob fields |
|---|---|---|---|---|---|
| geometry | 0x3EA970..0x49C740 | 4775 | 4756 | 4756/4756 | commands, vertex loads, vertices, triangles: 4756/4756 |
| textures | 0x5A1110..0x6F9C40 | 561 | 561 | 561/561 | image offset, format, dimensions, palette ranges: 561/561 |

The 19 extra geometry blobs lie exactly in the three index gaps (0x42F2E8..0x42F3E8,
0x441540..0x441EF0, 0x467750..0x467860): well-formed models no level references. The
texture pool leaves one 8-byte tail (0x6F9C38..0x6F9C40) as a gap. Detected ucode: f3dex.
Runtime about 0.4 s + 0.2 s for the walks.

Whole-ROM scans (`n64dk gfx ROM`, raw bytes, no segment mapping):

| ROM | ucode | lists | commands | vertex loads | triangles | textures |
|---|---|---|---|---|---|---|
| BattleTanx | f3dex | 5354 | 46165 | 4877 | 18372 | 543 |
| Global Assault | f3dex2 | 6547 | 45998 | 5532 | 21779 | 828 |
| Mario Kart 64 (raw) | f3dex | 60 | 395 | 50 | 24 | 0 |
| Mario Kart 64 `--decompress` | f3dex | 2377 | 65805 | 498 | 4443 | 739 |

Mario Kart 64 keeps most display lists inside MIO0 streams (3354 found; 23 of them hold
2317 lists); its course geometry uses a game-specific packed list format that is not GBI
and is not counted. No list-level ground truth was available for MK64 or Global Assault,
so those numbers are counts, not precision/recall.

## Limitations

* Raw scans cannot resolve segmented references, so textures there carry the load format
  only when the render tile is set in another list (shown without dimensions).
* G_LOADTILE sub-rectangles are recorded as the covered byte span of the source image.
* Line-stride (`line`) padding in TMEM and mip-mapped loads are not unpacked for PNG
  export; YUV is not decoded.
* Lists made only of RDP commands decode identically in every family; detection then
  falls back to f3dex.
* S2DEX object structures (uObjBg, uObjSprite, uObjTxtr) are recorded as references but
  their embedded image pointers are not followed.
