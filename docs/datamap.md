# Data map (`n64dk.analysis.datamap`, `n64dk datamap`)

Maps the initialized main-segment image (ROM 0x1000 -> header entry, up to the BSS start
from `n64dk.boot`) into code and data, cross-references every data address, splits the
data into `.rodata`/`.data`, assigns each object to its consumer function(s), builds an
initialized-data ledger and emits typed C data units.

```
n64dk datamap ROM [--matched TSV ...] [--symbols FILE] [--emit-units DIR]
                  [--ledger TSV] [--objects TSV] [--xrefs TSV] [--bss-start VRAM]
n64dk --format json datamap ROM ...
```

* `--matched` takes rows in the `ROM_START SIZE SOURCE <SECTION|FLAGS> ...` layout
  (comment lines with `#`; zero-size rows ignored; a fourth column starting with `.` is a
  data section, anything else marks code). When both code and data rows are given the
  command also reports ownership and section agreement against them.
* `--symbols` accepts splat `symbol_addrs.txt`, `nm`-style lines or
  `{ name = "...", vram = 0x... }` tables. Words equal to a symbol address are emitted as
  `void *` members initialised with that symbol (relocations), with `extern` declarations.
* `--emit-units DIR` writes `DIR/src/data/{rodata,data}_XXXXXXXX.c` for every unmatched
  data run, split into owner pools (consecutive objects with the same single consumer),
  and `DIR/data_units.tsv` (`ROM_START SIZE SOURCE SECTION SHA256_DATA`).

## Method

1. **Code extent.** `jal` targets anywhere in the image that land on decodable code are
   clustered (gaps must decode at >= 90 %; large clusters also join across mostly-code
   gaps such as embedded hand-written tables). The heaviest cluster is `.text`; it is
   extended backwards over clean prologue-started code, and ends at the last `jr $ra`
   before the first address the code loads or stores. The entry routine (up to its first
   jump or `break`) is a separate code range.
2. **Cross references.** Per function (call targets plus post-return starts) the scanner
   pairs `lui` with `addiu`/`ori`/loads/stores, keeps the `%hi` through `addu` indexing
   (jump and lookup tables), and follows an address held in a register into later
   `off(reg)` accesses (`via=reg`). Access types: `f32` (`lwc1`/`swc1`), `f64`
   (`ldc1`/`sdc1`), `word`, `half`, `byte`, `dword`, `addr` (address taken).
3. **Section split.** Each non-code region gets the single cut (either order) that best
   separates written addresses (`.data`) from read-only evidence (jump tables, `%hi/%lo`
   float literal loads).
4. **Objects.** Regions are cut at each referenced address; type is `jtbl`, `string`,
   `sjis`, `f32`, `f64`, `pointers`, `words` or `unreferenced`; owners are the functions
   containing the reference sites.
5. **Ledger.** Matched rows go in first (overlapping rows are rejected and listed), then
   unmatched `.text`, data objects (`evidence=owner=...;access=...`) and padding fill,
   via `n64dk.ledger.Ledger.complete`.
6. **Typed units.** Explicit-width members: `char[]` for strings, `f32`/`f64` only where
   a floating-point access proves the type and the literal round-trips, `void *` for
   symbol-matched pointer words, `u32` otherwise, `u16`/`u8` for tails and unaligned
   bytes. The member encoding round-trips byte-exactly over the whole GA data image
   (`tests/test_datamap.py`).

## Measured results

| Fixture | image | .text | .rodata | .data | functions | xref sites | objects (single owner / shared) | jump tables | strings |
|---|---|---|---|---|---|---|---|---|---|
| BattleTanx (NBXE) | 0x80071000..0x80147040 | 0xAF58C | 0x4FC4 | 0x21AF0 | 1834 | 4743 | 2573 (2297 / 275) | 82 | 317 |
| Global Assault (NBQE) | 0x80071000..0x80127E30 | 0x9C898 | 0x6C04 | 0x13994 | 1964 | 6034 | 3121 (2602 / 517) | 192 | 190 |
| Mario Kart 64 (NKTE) | 0x80000400..0x800F6910 | 0xDC02C | 0xB4B0 | 0xF034 | 2896 | 5573 | 2224 (1929 / 293) | 209 | 28 |

Runtime is 1-2 s per ROM.

**BattleTanx** against `config/us/matching_*units.tsv` (1419 rows, none rejected):

* `.text` = 0x80076000..0x80125550 and the leading `.rodata` 0x8007103C..0x80076000,
  exactly the project layout.
* Section agreement: 194/194 matched data rows (`.rdata` counted as `.rodata`).
* Ownership: 111 data rows have a source with matched code. At least one predicted
  consumer lies in that source for 110/111 (99.1 %); all predicted consumers do for
  103/111 (92.8 %). The disagreements are libultra globals (`os_vi`, `os_initialize`,
  `al_sl`, ...) that other files also reference, i.e. genuinely shared objects.
* Ledger: code matched 0x4BBD0, unmatched 0x639BC; data matched 0x25944, unmatched
  0x1170 (16 owner-pool units emitted).

**Global Assault** against `config/us/unit_rodata.tsv` + `unit_data.tsv` (548 rows), with
unit code ranges approximated from `config/source_layout.tsv` (each unit spans to the next
listed address):

* `.text` starts at 0x80077C40, matching the project's first C unit.
* Section agreement: 547/548 (the miss is a `.data` row inside the detected `.text` tail).
* Ownership: 493 evaluable rows; any-consumer agreement 383 (77.7 %), exact 372 (75.5 %).
  Most disagreements are rows whose unit name is a data address or whose code is split
  over several layout entries, so the layout-derived ranges understate the true owner.

**Mario Kart 64**: no ground truth wired in; totals above. The layout found is
`.text` 0x80000450..0x800DC444, then `.data`, then `.rodata` from 0x800EB460.

## Limitations

* One `.data`/`.rodata` cut per non-code region; images that interleave several data
  sections between code clusters (or keep data inside `.text`) need `--matched` rows.
* `$gp`-relative accesses are not tracked (the fixtures are built `-G0`).
* Objects are cut at every referenced address, so a `%lo` into the middle of a struct
  splits it; owners are by reference site, so data reached only through pointers in other
  data has no owner.
* Strings are only recognised at referenced addresses or right after another string, to
  avoid false positives inside binary tables.
* Function starts are call targets plus post-return boundaries; an exact boundary list
  (`n64dk.analysis.functions`) can replace them once available.
